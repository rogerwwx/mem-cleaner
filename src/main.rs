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
const HASH_SIZE: usize = 128;
const UPDATE_INTERVAL_MS: u64 = 500;

struct AppConfig {
    interval: u64,
    whitelist: HashSet<String>,
    oom_threshold: i32,
}

// ==========================================
// 核心数据结构：仅保留 Monitored / Ignored 状态
// ==========================================
#[derive(Clone, PartialEq)]
enum NodeStatus {
    Monitored, // 已确认为目标子进程：持续监控 OOM
    Ignored,   // 已确认为安全进程：不再读取 cmdline
}

#[derive(Clone)]
struct ProcessNode {
    pid: i32,
    uid: u32,
    process_name: String,
    oom_score: i32,
    status: NodeStatus,
    is_alive: bool, // 存活标记，用于清理哈希表
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

    // 原哈希逻辑，未修改
    fn hash(pid: i32) -> usize {
        (pid as usize) % HASH_SIZE
    }

    // 原存活检查逻辑，未修改
    fn check_alive(pid: i32) -> bool {
        match kill(Pid::from_raw(pid), None) {
            Ok(_) => true,
            Err(nix::errno::Errno::ESRCH) => false,
            Err(_) => std::path::Path::new(&format!("/proc/{}", pid)).exists(),
        }
    }

    // 仅删除 Pending 相关逻辑，无其他改动
    fn update(&mut self, whitelist: &HashSet<String>) {
        let current_pids = get_all_pids();

        // 1. 标记并清理死亡进程（原逻辑）
        for bucket in &mut self.buckets {
            for node in bucket.iter_mut() {
                if node.is_alive && !current_pids.contains(&node.pid) {
                    node.is_alive = false;
                }
            }
            bucket.retain(|node| node.is_alive);
        }

        // 2. 处理所有 PID（移除 Pending 分支）
        for pid in current_pids {
            let hash_idx = Self::hash(pid);
            let bucket = &mut self.buckets[hash_idx];

            if let Some(node) = bucket.iter_mut().find(|n| n.pid == pid) {
                // 旧进程：仅更新 Monitored 状态的 OOM，原逻辑
                match node.status {
                    NodeStatus::Ignored => continue,
                    NodeStatus::Monitored => {
                        node.oom_score = get_oom_score(pid).unwrap_or(node.oom_score);
                    }
                }
            } else {
                // 新进程：直接判定状态，无观察期
                if let Some(new_node) = Self::create_node(pid, whitelist) {
                    bucket.push(new_node);
                }
            }
        }
    }

    // 仅删除 Pending 状态判定，无其他逻辑修改
    fn create_node(pid: i32, whitelist: &HashSet<String>) -> Option<ProcessNode> {
        let uid = get_uid(pid)?;

        // 系统进程直接忽略（原逻辑，未修改）
        if uid < 10000 {
            return Some(ProcessNode {
                pid,
                uid,
                process_name: String::new(),
                oom_score: -1000,
                status: NodeStatus::Ignored,
                is_alive: true,
            });
        }

        let cmdline = get_cmdline(pid).unwrap_or_default();
        let oom = get_oom_score(pid).unwrap_or(0);

        // 直接根据 cmdline 判定状态（无 Pending 分支）
        let status = if cmdline.contains(':') && !whitelist.contains(&cmdline) {
            NodeStatus::Monitored
        } else {
            NodeStatus::Ignored
        };

        Some(ProcessNode {
            pid,
            uid,
            process_name: cmdline,
            oom_score: oom,
            status,
            is_alive: true,
        })
    }

    // 原查杀逻辑，未修改
    fn query_and_kill(&mut self, threshold: i32, log_path: &Option<String>) {
        let mut killed_list = Vec::new();

        for bucket in &mut self.buckets {
            bucket.retain(|node| {
                if !node.is_alive {
                    return false;
                }

                if node.status == NodeStatus::Monitored && node.oom_score >= threshold {
                    if Self::check_alive(node.pid) {
                        if kill(Pid::from_raw(pid), Signal::SIGKILL).is_ok() {
                            killed_list.push(node.process_name.clone());
                            return false;
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
// 主入口：仅保留查杀前强制 update（无负收益修改）
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
    println!("Starting Daemon (No Pending State)...");
    println!("Kill Interval: {}s", config.interval);
    println!("OOM Threshold: {}", config.oom_threshold);

    if let Some(ref path) = log_path {
        write_startup_log(path);
    }

    let timer = TimerFd::new(ClockId::CLOCK_BOOTTIME, TimerFlags::empty())
        .expect("Failed to create timerfd");

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

        table.update(&config.whitelist);

        if !initialized {
            println!("Process Table Initialized. Monitoring...");
            initialized = true;
        }

        // 查杀前强制 update：无负收益，仅避免定时器延迟导致的状态过期
        if last_kill_time.elapsed().as_secs() >= config.interval {
            if !is_device_in_doze() {
                table.update(&config.whitelist); 
                table.query_and_kill(config.oom_threshold, &log_path);
            }
            last_kill_time = Instant::now();
        }
    }
}

// --- 辅助函数：完全保留原逻辑，无任何修改 ---
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
        let _ = writeln!(file, "⚡进程压制已启动⚡");
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
