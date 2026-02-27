use std::collections::{HashMap, HashSet};
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::MetadataExt; // 极速获取 UID
use std::time::Instant;

use nix::sys::signal::{kill, Signal};
use nix::sys::time::TimeSpec;
use nix::sys::timerfd::{ClockId, Expiration, TimerFd, TimerFlags, TimerSetTimeFlags};
use nix::unistd::Pid;

use time::macros::format_description;
use time::{format_description::FormatItem, OffsetDateTime};

// --- 配置区域 ---
const DEFAULT_OOM_THRESHOLD: i32 = 800;
const DEFAULT_INTERVAL: u64 = 60;
const UPDATE_INTERVAL_MS: u64 = 500;
const HASH_CAPACITY: usize = 64; // 初始容量64，不够自动扩容

struct AppConfig {
    interval: u64,
    whitelist: HashSet<String>,
    oom_threshold: i32,
}

#[derive(Clone, PartialEq, Debug)]
enum ProcessType {
    /// 猎物：名字带冒号的子进程 (e.g. "com.app:push")
    /// 策略：只读 OOM，不读 Cmdline，超标即杀
    TargetChild,

    /// 疑似主进程：名字不带冒号 (e.g. "com.app")
    /// 策略：每次必须重读 Cmdline，防止它变身
    PotentialMain,

    /// 忽略：系统进程或无关进程
    Ignored,
}

#[derive(Clone)]
struct ProcessNode {
    pid: i32,
    uid: u32,
    name: String,
    oom_score: i32,
    p_type: ProcessType,
    visited: bool, // 用于标记每一轮扫描是否存活
}

struct ProcessManager {
    // 使用 HashMap 替代 Vec，查询 O(1)，自动扩容
    table: HashMap<i32, ProcessNode>,
    // IO 缓冲区复用，避免循环内频繁分配内存
    cmd_buffer: Vec<u8>,
    // 临时存储 OOM 读取结果
    oom_buffer: [u8; 16],
}

impl ProcessManager {
    fn new() -> Self {
        Self {
            table: HashMap::with_capacity(HASH_CAPACITY),
            cmd_buffer: Vec::with_capacity(256),
            oom_buffer: [0u8; 16],
        }
    }

    /// 核心逻辑：全量扫描 + 动态身份修正
    fn update(&mut self, whitelist: &HashSet<String>) {
        // 1. 标记所有节点为未访问（准备清理死进程）
        for node in self.table.values_mut() {
            node.visited = false;
        }

        // 2. 遍历 /proc 目录
        if let Ok(dir) = fs::read_dir("/proc") {
            for entry in dir.flatten() {
                // 极速解析 PID，跳过非数字目录
                let pid = match entry
                    .file_name()
                    .to_str()
                    .and_then(|s| s.parse::<i32>().ok())
                {
                    Some(p) => p,
                    None => continue,
                };

                // 分情况处理：是旧人还是新人？
                if let Some(node) = self.table.get_mut(&pid) {
                    // --- 旧节点 (Update) ---
                    node.visited = true;

                    match node.p_type {
                        ProcessType::Ignored => continue, // 极速跳过
                        ProcessType::TargetChild => {
                            // 已经是子进程了，不需要再看名字，只监控 OOM
                            node.oom_score = self.read_oom_fast(pid).unwrap_or(node.oom_score);
                        }
                        ProcessType::PotentialMain => {
                            // 【关键修复】疑似主进程，必须重读名字！
                            // 也许上次它还没改名，现在可能变成 :push 了
                            self.recheck_potential_main(node, whitelist);
                        }
                    }
                } else {
                    // --- 新节点 (Insert) ---
                    // 只有这里需要分配一次内存创建节点
                    if let Some(mut new_node) = self.create_node(pid, whitelist) {
                        new_node.visited = true;
                        self.table.insert(pid, new_node);
                    }
                }
            }
        }

        // 3. 物理清理死亡进程
        self.table.retain(|_, node| node.visited);
    }

    /// 创建新节点
    fn create_node(&mut self, pid: i32, whitelist: &HashSet<String>) -> Option<ProcessNode> {
        // 优化：直接从文件元数据拿 UID，不读 status 文件
        let uid = get_uid_fast(pid)?;

        // 过滤系统进程 (UID < 10000)
        if uid < 10000 {
            return Some(ProcessNode {
                pid,
                uid,
                name: String::new(),
                oom_score: -1000,
                p_type: ProcessType::Ignored,
                visited: true,
            });
        }

        // 读取名字
        let name = self.read_cmdline(pid).unwrap_or_default();
        let oom = self.read_oom_fast(pid).unwrap_or(0);

        // 初始分类
        let p_type = if name.contains(':') {
            if whitelist.contains(&name) {
                ProcessType::Ignored
            } else {
                ProcessType::TargetChild
            }
        } else {
            // 没冒号，暂时当做主进程，但后续每次 Update 都要查它
            ProcessType::PotentialMain
        };

        Some(ProcessNode {
            pid,
            uid,
            name,
            oom_score: oom,
            p_type,
            visited: true,
        })
    }

    /// 【防止漏杀的核心】重新检查那些“看起来像主进程”的家伙
    fn recheck_potential_main(&mut self, node: &mut ProcessNode, whitelist: &HashSet<String>) {
        // 重新读取 cmdline
        if let Some(new_name) = self.read_cmdline(node.pid) {
            // 如果发现它名字里有冒号了！
            if new_name.contains(':') {
                node.name = new_name; // 更新名字
                if whitelist.contains(&node.name) {
                    node.p_type = ProcessType::Ignored;
                } else {
                    // 抓住你了！变身子进程，锁定为 TargetChild
                    node.p_type = ProcessType::TargetChild;
                    // 顺便更新一下 OOM
                    node.oom_score = self.read_oom_fast(node.pid).unwrap_or(node.oom_score);
                }
            } else {
                // 还是没冒号，可能是真的主进程，也可能还没变身
                // 继续保持 PotentialMain，下次还查
                // 顺便更新 OOM (可选，如果你想监控主进程OOM的话)
                node.oom_score = self.read_oom_fast(node.pid).unwrap_or(node.oom_score);
            }
        }
    }

    /// 查杀逻辑：只杀 TargetChild
    fn scan_and_kill(&mut self, threshold: i32, log_path: &Option<String>) {
        let mut killed_list = Vec::new();

        // 收集要杀的 PID (避免在遍历时修改 HashMap 导致借用冲突)
        // 这里我们只杀 TargetChild，绝对不碰 PotentialMain
        let targets: Vec<(i32, String)> = self
            .table
            .values()
            .filter(|n| n.p_type == ProcessType::TargetChild && n.oom_score >= threshold)
            .map(|n| (n.pid, n.name.clone()))
            .collect();

        for (pid, name) in targets {
            // 杀之前再确认一次存活，防止报错
            if kill(Pid::from_raw(pid), Signal::SIGKILL).is_ok() {
                killed_list.push(format!("{} (PID:{})", name, pid));
                // 杀完立刻从表里移除，防止下次还读到
                self.table.remove(&pid);
            }
        }

        if !killed_list.is_empty() {
            if let Some(path) = log_path {
                write_log_to_file(path, &killed_list);
            }
        }
    }

    // --- IO 辅助 ---

    fn read_cmdline(&mut self, pid: i32) -> Option<String> {
        let path = format!("/proc/{}/cmdline", pid);
        self.cmd_buffer.clear();
        if let Ok(mut f) = File::open(path) {
            if f.read_to_end(&mut self.cmd_buffer).is_ok() {
                // 取第一段，遇 \0 截断
                let slice = self.cmd_buffer.split(|&c| c == 0).next()?;
                return String::from_utf8(slice.to_vec()).ok();
            }
        }
        None
    }

    fn read_oom_fast(&mut self, pid: i32) -> Option<i32> {
        let path = format!("/proc/{}/oom_score_adj", pid);
        if let Ok(mut f) = File::open(path) {
            // 复用 buffer，不分配内存
            if let Ok(n) = f.read(&mut self.oom_buffer) {
                let s = std::str::from_utf8(&self.oom_buffer[..n]).ok()?.trim();
                return s.parse().ok();
            }
        }
        None
    }
}

// 极速获取 UID (元数据法)
fn get_uid_fast(pid: i32) -> Option<u32> {
    fs::metadata(format!("/proc/{}", pid)).ok().map(|m| m.uid())
}

// ==========================================
// 主程序入口
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

    println!("Starting Daemon (No-Pending / Strict Child Kill)...");

    if let Some(ref path) = log_path {
        write_startup_log(path);
    }

    let timer = TimerFd::new(ClockId::CLOCK_BOOTTIME, TimerFlags::empty()).unwrap();
    let interval_spec = TimeSpec::new(0, (UPDATE_INTERVAL_MS * 1_000_000) as i64);
    timer
        .set(
            Expiration::Interval(interval_spec),
            TimerSetTimeFlags::empty(),
        )
        .unwrap();

    let mut manager = ProcessManager::new();
    let mut last_kill_time = Instant::now();

    loop {
        let _ = timer.wait();

        // 1. 高频更新：修正所有进程身份
        manager.update(&config.whitelist);

        // 2. 周期查杀：只杀身份确定的子进程
        if last_kill_time.elapsed().as_secs() >= config.interval {
            if !is_device_idle() {
                manager.scan_and_kill(config.oom_threshold, &log_path);
            }
            last_kill_time = Instant::now();
        }
    }
}

// --- 辅助配置与日志 ---

fn load_config(path: &str) -> AppConfig {
    let mut interval = DEFAULT_INTERVAL;
    let mut oom_threshold = DEFAULT_OOM_THRESHOLD;
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

fn is_device_idle() -> bool {
    // 检查 Doze 模式，避免打断深度睡眠
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
    OffsetDateTime::now_local()
        .unwrap_or_else(|_| OffsetDateTime::now_utc())
        .format(TIME_FMT)
        .unwrap_or_default()
}

fn write_startup_log(path: &str) {
    let _ = OpenOptions::new()
        .create(true)
        .write(true)
        .append(true)
        .open(path)
        .map(|mut f| writeln!(f, "\n=== 启动: {} ===", now()));
}

fn write_log_to_file(path: &str, lines: &[String]) {
    if let Ok(mut file) = OpenOptions::new()
        .create(true)
        .write(true)
        .append(true)
        .open(path)
    {
        let _ = writeln!(file, "--- 清理时间: {} ---", now());
        for line in lines {
            let _ = writeln!(file, "已清理: {}", line);
        }
        let _ = writeln!(file, "");
    }
}
