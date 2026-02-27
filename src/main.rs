use std::collections::HashSet;
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::process::Command;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use nix::sys::signal::{kill, Signal};
use nix::sys::time::TimeSpec;
use nix::sys::timerfd::{ClockId, Expiration, TimerFd, TimerFlags, TimerSetTimeFlags};
use nix::unistd::Pid;

use time::macros::format_description;
use time::{format_description::FormatItem, OffsetDateTime};

// --- 常量定义 ---
const DEFAULT_OOM_SCORE_THRESHOLD: i32 = 800;
const DEFAULT_INTERVAL: u64 = 60;
const HASH_SIZE: usize = 128; // 扩大哈希桶以减少冲突
const UPDATE_INTERVAL_MS: u64 = 500;
const STABILITY_THRESHOLD: u8 = 6; // 观察阈值：20次 * 500ms = 10秒。10秒没变身才通过。

struct AppConfig {
    interval: u64,
    whitelist: HashSet<String>,
    oom_threshold: i32,
}

// ==========================================
// 核心数据结构：模拟你描述的“默认表”节点
// ==========================================

#[derive(Clone, PartialEq)]
enum NodeStatus {
    Pending,   // 观察期：可能是主进程，也可能是还没改名的子进程
    Monitored, // 已确认为目标子进程：持续监控 OOM
    Ignored,   // 已确认为安全进程（系统进程或稳定主进程）：不再读取 cmdline
}

#[derive(Clone)]
struct ProcessNode {
    pid: i32,
    uid: u32,
    process_name: String,
    oom_score: i32,
    status: NodeStatus,
    retry_counter: u8, // 观察计数器
    is_alive: bool,    // 存活标记，用于清理哈希表
}

struct ProcessTable {
    buckets: [Vec<ProcessNode>; HASH_SIZE],
}

impl ProcessTable {
    fn new() -> Self {
        Self {
            buckets: std::array::from_fn(|_| Vec::new()),
        }
    }

    // 简单的取模哈希，对应步骤3中的哈希计算
    fn hash(pid: i32) -> usize {
        (pid as usize) % HASH_SIZE
    }

    fn check_alive(pid: i32) -> bool {
        match kill(Pid::from_raw(pid), None) {
            Ok(_) => true,
            Err(nix::errno::Errno::ESRCH) => false,
            Err(_) => std::path::Path::new(&format!("/proc/{}", pid)).exists(),
        }
    }

    // 核心逻辑：对应步骤3、4、5的增量维护
    fn update(&mut self, whitelist: &HashSet<String>) {
        let current_pids = get_all_pids();

        // 1. 标记死亡进程 (Bucket 清理)
        for bucket in &mut self.buckets {
            for node in bucket.iter_mut() {
                if node.is_alive && !current_pids.contains(&node.pid) {
                    node.is_alive = false;
                }
            }
            // 物理移除死亡节点
            bucket.retain(|node| node.is_alive);
        }

        // 2. 处理所有 PID (增量处理：表里有的更新，没的新增)
        for pid in current_pids {
            let hash_idx = Self::hash(pid);
            let bucket = &mut self.buckets[hash_idx];

            // 尝试在桶中找到该 PID
            if let Some(node) = bucket.iter_mut().find(|n| n.pid == pid) {
                // --- 旧进程 (表里已有) ---
                // 这里是关键修复：根据状态决定是否重新检查
                match node.status {
                    NodeStatus::Ignored => {
                        // 系统进程或稳定主进程，直接跳过，极速！
                        continue;
                    }
                    NodeStatus::Monitored => {
                        // 目标子进程，只更新 OOM，不读 Cmdline (省IO)
                        node.oom_score = get_oom_score(pid).unwrap_or(node.oom_score);
                    }
                    NodeStatus::Pending => {
                        // 【重点】观察期进程：必须重新读取 Cmdline 检查是否变身
                        Self::recheck_pending_node(node, whitelist);
                    }
                }
            } else {
                // --- 新进程 (表里没有) ---
                // 对应步骤4：新进程专属处理
                if let Some(new_node) = Self::create_node(pid, whitelist) {
                    bucket.push(new_node);
                }
            }
        }
    }

    // 创建新节点（初次筛选）
    fn create_node(pid: i32, whitelist: &HashSet<String>) -> Option<ProcessNode> {
        let uid = get_uid(pid)?; // 读不到 UID 说明进程可能刚死，跳过

        // 1. 系统进程直接忽略
        if uid < 10000 {
            return Some(ProcessNode {
                pid,
                uid,
                process_name: String::new(),
                oom_score: -1000,
                status: NodeStatus::Ignored, // 永久忽略
                retry_counter: 0,
                is_alive: true,
            });
        }

        // 2. 用户进程：读取 Cmdline
        let cmdline = get_cmdline(pid).unwrap_or_default();
        let oom = get_oom_score(pid).unwrap_or(0);

        // 3. 判定初始状态
        let (status, name) = if cmdline.contains(':') {
            // 一出生就带冒号（且不在白名单），直接监控
            if whitelist.contains(&cmdline) {
                (NodeStatus::Ignored, cmdline)
            } else {
                (NodeStatus::Monitored, cmdline)
            }
        } else {
            // 没有冒号，可能是主进程，也可能是还没改名的子进程
            // 标记为 Pending，后续持续观察
            (NodeStatus::Pending, cmdline)
        };

        Some(ProcessNode {
            pid,
            uid,
            process_name: name,
            oom_score: oom,
            status,
            retry_counter: 0,
            is_alive: true,
        })
    }

    // 【核心修复逻辑】重新检查处于观察期的节点
    fn recheck_pending_node(node: &mut ProcessNode, whitelist: &HashSet<String>) {
        // 如果观察次数超过阈值（约10秒），认定为稳定主进程，不再检查
        if node.retry_counter >= STABILITY_THRESHOLD {
            node.status = NodeStatus::Ignored;
            return;
        }

        // 重新读取名字
        if let Some(new_cmdline) = get_cmdline(node.pid) {
            if new_cmdline.contains(':') {
                // ！！！抓到了！它变身了！！！
                node.process_name = new_cmdline.clone();
                if whitelist.contains(&new_cmdline) {
                    node.status = NodeStatus::Ignored;
                } else {
                    node.status = NodeStatus::Monitored;
                    node.oom_score = get_oom_score(node.pid).unwrap_or(0);
                }
            } else {
                // 还是没变身，增加计数器，继续观察
                node.retry_counter += 1;
                // 顺便更新一下 OOM，万一它是主进程但我们想看它数据
                // node.oom_score = get_oom_score(node.pid).unwrap_or(node.oom_score);
            }
        } else {
            // 读不到名字了？可能死了
            node.is_alive = false;
        }
    }

    // 查杀逻辑
    fn query_and_kill(&mut self, threshold: i32, log_path: &Option<String>) {
        let mut killed_list = Vec::new();

        for bucket in &mut self.buckets {
            bucket.retain(|node| {
                if !node.is_alive {
                    return false;
                }

                // 只杀 Monitored 状态的节点
                if node.status == NodeStatus::Monitored && node.oom_score >= threshold {
                    // 杀前做最后一次双重验证
                    if Self::check_alive(node.pid) {
                        // 尝试击杀
                        if kill(Pid::from_raw(node.pid), Signal::SIGKILL).is_ok() {
                            killed_list.push(node.process_name.clone());
                            return false; // 移除节点
                        }
                    }
                }
                true
            });
        }

        if !killed_list.is_empty() {
            if let Some(path) = log_path {
                write_log_to_file(path, &killed_list);
            }
        }
    }
}

// ==========================================
// 主入口
// ==========================================

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <config_path> [log_path]", args[0]);
        std::process::exit(1);
    }

    let config_path = &args[1];
    let log_path = if args.len() > 2 {
        Some(args[2].clone())
    } else {
        None
    };

    let config = load_config(config_path);
    println!("Starting Daemon (Deep Logic Fixed)...");
    println!("Kill Interval: {}s", config.interval);
    println!("OOM Threshold: {}", config.oom_threshold);

    if let Some(ref path) = log_path {
        write_startup_log(path);
    }

    let timer = TimerFd::new(ClockId::CLOCK_BOOTTIME, TimerFlags::empty())
        .expect("Failed to create timerfd");

    // 500ms 唤醒一次进行数据更新
    let interval_spec = TimeSpec::new(0, (UPDATE_INTERVAL_MS * 1_000_000) as i64);
    timer
        .set(
            Expiration::Interval(interval_spec),
            TimerSetTimeFlags::empty(),
        )
        .expect("Failed to set timer");

    let mut table = ProcessTable::new();
    let mut last_kill_time = Instant::now();
    let mut initialized = false;

    loop {
        let _ = timer.wait();

        // 1. 每 500ms 执行一次表更新（增量维护 + 观察期重检）
        // 这一步非常快，因为 Ignored 节点直接跳过，只有 Pending 节点会读文件
        table.update(&config.whitelist);

        if !initialized {
            println!("Process Table Initialized. Monitoring...");
            initialized = true;
        }

        // 2. 到达 Interval 周期才执行查杀
        if last_kill_time.elapsed().as_secs() >= config.interval {
            if !is_device_in_doze() {
                // 只有非 Doze 模式才动刀
                table.query_and_kill(config.oom_threshold, &log_path);
            }
            last_kill_time = Instant::now();
        }
    }
}

// --- 辅助函数 (保持不变) ---

fn load_config(path: &str) -> AppConfig {
    let mut interval = DEFAULT_INTERVAL;
    let mut oom_threshold = DEFAULT_OOM_SCORE_THRESHOLD;
    let mut whitelist = HashSet::new();

    if let Ok(content) = fs::read_to_string(path) {
        let mut in_whitelist_mode = false;
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            if line.starts_with("interval:") {
                if let Some(val) = line.split(':').nth(1) {
                    if let Ok(v) = val.trim().parse() {
                        interval = v;
                    }
                }
                in_whitelist_mode = false;
            } else if line.starts_with("oom_threshold:") {
                if let Some(val) = line.split(':').nth(1) {
                    if let Ok(v) = val.trim().parse() {
                        oom_threshold = v;
                    }
                }
                in_whitelist_mode = false;
            } else if line.starts_with("whitelist:") {
                in_whitelist_mode = true;
                if let Some(val_part) = line.split(':').nth(1) {
                    parse_packages(val_part, &mut whitelist);
                }
            } else if in_whitelist_mode {
                parse_packages(line, &mut whitelist);
            }
        }
    }
    AppConfig {
        interval,
        whitelist,
        oom_threshold,
    }
}

fn parse_packages(line: &str, whitelist: &mut HashSet<String>) {
    for part in line.split(',') {
        let pkg = part.trim();
        if !pkg.is_empty() {
            whitelist.insert(pkg.to_string());
        }
    }
}

fn get_all_pids() -> HashSet<i32> {
    let mut pids = HashSet::with_capacity(1024);
    if let Ok(dir) = fs::read_dir("/proc") {
        for entry in dir.flatten() {
            if let Some(name_str) = entry.file_name().to_str() {
                if let Ok(pid) = name_str.parse::<i32>() {
                    pids.insert(pid);
                }
            }
        }
    }
    pids
}

fn get_uid(pid: i32) -> Option<u32> {
    let path = format!("/proc/{}/status", pid);
    if let Ok(content) = fs::read_to_string(path) {
        for line in content.lines() {
            if line.starts_with("Uid:") {
                return line.split_whitespace().nth(1)?.parse().ok();
            }
        }
    }
    None
}

fn get_oom_score(pid: i32) -> Option<i32> {
    let path = format!("/proc/{}/oom_score_adj", pid);
    let mut buf = String::with_capacity(8);
    if File::open(path)
        .and_then(|mut f| f.read_to_string(&mut buf))
        .is_ok()
    {
        return buf.trim().parse().ok();
    }
    None
}

fn get_cmdline(pid: i32) -> Option<String> {
    let path = format!("/proc/{}/cmdline", pid);
    let mut buf = Vec::with_capacity(128);
    if File::open(path)
        .and_then(|mut f| f.read_to_end(&mut buf))
        .is_ok()
    {
        return buf
            .split(|&c| c == 0)
            .next()
            .and_then(|slice| String::from_utf8(slice.to_vec()).ok());
    }
    None
}

fn is_device_in_doze() -> bool {
    if let Ok(output) = Command::new("cmd")
        .args(&["deviceidle", "get", "deep"])
        .output()
    {
        return String::from_utf8_lossy(&output.stdout)
            .trim()
            .contains("IDLE");
    }
    false
}

static TIME_FMT: &[FormatItem<'static>] =
    format_description!("[year]-[month]-[day] [hour]:[minute]:[second]");

fn now() -> String {
    let dt = OffsetDateTime::now_local().unwrap_or_else(|_| OffsetDateTime::now_utc());
    dt.format(TIME_FMT)
        .unwrap_or_else(|_| "time_err".to_string())
}

fn write_startup_log(path: &str) {
    let time_str = now();
    let today = time_str.split_whitespace().next().unwrap_or("1970-01-01");
    let need_clear = fs::read_to_string(path)
        .map(|c| !c.contains(today))
        .unwrap_or(true);
    if let Ok(mut file) = OpenOptions::new()
        .create(true)
        .write(true)
        .append(!need_clear)
        .truncate(need_clear)
        .open(path)
    {
        let _ = writeln!(file, "=== 启动时间: {} ===", time_str);
        let _ = writeln!(file, "⚡进程压制已启动(深度修复版)⚡");
        let _ = writeln!(file, "");
    }
}

fn write_log_to_file(path: &str, killed_list: &[String]) {
    let time_str = now();
    let today = time_str.split_whitespace().next().unwrap_or("1970-01-01");
    let need_clear = fs::read_to_string(path)
        .map(|c| !c.contains(today))
        .unwrap_or(true);
    if let Ok(mut file) = OpenOptions::new()
        .create(true)
        .write(true)
        .append(!need_clear)
        .truncate(need_clear)
        .open(path)
    {
        let _ = writeln!(file, "=== 清理时间: {} ===", time_str);
        for pkg in killed_list {
            let _ = writeln!(file, "已清理: {}", pkg);
        }
        let _ = writeln!(file, "");
    }
}
