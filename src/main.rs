use std::collections::{HashMap, HashSet};
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::MetadataExt;
use std::process::Command; // 【修复1】添加缺失的引用
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
const HASH_CAPACITY: usize = 64;

struct AppConfig {
    interval: u64,
    whitelist: HashSet<String>,
    oom_threshold: i32,
}

#[derive(Clone, PartialEq, Debug)]
enum ProcessType {
    /// 猎物：名字带冒号的子进程
    TargetChild,
    /// 疑似主进程：名字不带冒号，需持续监控是否变身
    PotentialMain,
    /// 忽略
    Ignored,
}

#[derive(Clone)]
struct ProcessNode {
    pid: i32,
    uid: u32,
    name: String,
    oom_score: i32,
    p_type: ProcessType,
    visited: bool,
}

struct ProcessManager {
    table: HashMap<i32, ProcessNode>,
    cmd_buffer: Vec<u8>,
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

    // 【修复2】重构 update 逻辑，拆分借用，解决 E0499 报错
    fn update(&mut self, whitelist: &HashSet<String>) {
        // 1. 重置 visited
        for node in self.table.values_mut() {
            node.visited = false;
        }

        // 2. 显式解构 self，让编译器知道 table 和 buffer 是分离的，互不影响
        let table = &mut self.table;
        let cmd_buf = &mut self.cmd_buffer;
        let oom_buf = &mut self.oom_buffer;

        if let Ok(dir) = fs::read_dir("/proc") {
            for entry in dir.flatten() {
                let pid = match entry
                    .file_name()
                    .to_str()
                    .and_then(|s| s.parse::<i32>().ok())
                {
                    Some(p) => p,
                    None => continue,
                };

                // 现在我们可以同时使用 `table` 和 `cmd_buf/oom_buf` 了
                if let Some(node) = table.get_mut(&pid) {
                    // --- 旧节点 ---
                    node.visited = true;

                    match node.p_type {
                        ProcessType::Ignored => continue,
                        ProcessType::TargetChild => {
                            // 只读 OOM
                            node.oom_score =
                                read_oom_helper(pid, oom_buf).unwrap_or(node.oom_score);
                        }
                        ProcessType::PotentialMain => {
                            // 疑似主进程，必须重读名字检查是否变身
                            if let Some(new_name) = read_cmdline_helper(pid, cmd_buf) {
                                if new_name.contains(':') {
                                    // 变身了！
                                    node.name = new_name;
                                    if whitelist.contains(&node.name) {
                                        node.p_type = ProcessType::Ignored;
                                    } else {
                                        node.p_type = ProcessType::TargetChild;
                                        node.oom_score =
                                            read_oom_helper(pid, oom_buf).unwrap_or(node.oom_score);
                                    }
                                } else {
                                    // 还是没变身，顺便更新下 OOM
                                    node.oom_score =
                                        read_oom_helper(pid, oom_buf).unwrap_or(node.oom_score);
                                }
                            }
                        }
                    }
                } else {
                    // --- 新节点 ---
                    // 使用独立函数创建节点，避免借用冲突
                    if let Some(mut new_node) = create_node_helper(pid, whitelist, cmd_buf, oom_buf)
                    {
                        new_node.visited = true;
                        table.insert(pid, new_node);
                    }
                }
            }
        }

        // 3. 清理死亡进程
        table.retain(|_, node| node.visited);
    }

    fn scan_and_kill(&mut self, threshold: i32, log_path: &Option<String>) {
        let mut killed_list = Vec::new();

        // 收集目标，只杀 TargetChild
        let targets: Vec<(i32, String)> = self
            .table
            .values()
            .filter(|n| n.p_type == ProcessType::TargetChild && n.oom_score >= threshold)
            .map(|n| (n.pid, n.name.clone()))
            .collect();

        for (pid, name) in targets {
            if kill(Pid::from_raw(pid), Signal::SIGKILL).is_ok() {
                killed_list.push(format!("{} (PID:{})", name, pid));
                self.table.remove(&pid);
            }
        }

        if !killed_list.is_empty() {
            if let Some(path) = log_path {
                write_log_to_file(path, &killed_list);
            }
        }
    }
}

// ==========================================
// 【核心修改】将 IO 操作改为独立函数 (Standalone Functions)
// 这样就需要显式传递 buffer，不再依赖 &mut self，彻底解决借用冲突
// ==========================================

fn create_node_helper(
    pid: i32,
    whitelist: &HashSet<String>,
    cmd_buf: &mut Vec<u8>,
    oom_buf: &mut [u8],
) -> Option<ProcessNode> {
    let uid = get_uid_fast(pid)?;

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

    let name = read_cmdline_helper(pid, cmd_buf).unwrap_or_default();
    let oom = read_oom_helper(pid, oom_buf).unwrap_or(0);

    let p_type = if name.contains(':') {
        if whitelist.contains(&name) {
            ProcessType::Ignored
        } else {
            ProcessType::TargetChild
        }
    } else {
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

fn read_cmdline_helper(pid: i32, buffer: &mut Vec<u8>) -> Option<String> {
    let path = format!("/proc/{}/cmdline", pid);
    buffer.clear();
    if let Ok(mut f) = File::open(path) {
        if f.read_to_end(buffer).is_ok() {
            let slice = buffer.split(|&c| c == 0).next()?;
            return String::from_utf8(slice.to_vec()).ok();
        }
    }
    None
}

fn read_oom_helper(pid: i32, buffer: &mut [u8]) -> Option<i32> {
    let path = format!("/proc/{}/oom_score_adj", pid);
    if let Ok(mut f) = File::open(path) {
        if let Ok(n) = f.read(buffer) {
            let s = std::str::from_utf8(&buffer[..n]).ok()?.trim();
            return s.parse().ok();
        }
    }
    None
}

fn get_uid_fast(pid: i32) -> Option<u32> {
    fs::metadata(format!("/proc/{}", pid)).ok().map(|m| m.uid())
}

// ==========================================
// 主程序入口 (无变化，仅确保引用正确)
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

    println!("Starting Daemon (Fixed E0499 + E0433)...");

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
        manager.update(&config.whitelist);

        if last_kill_time.elapsed().as_secs() >= config.interval {
            if !is_device_idle() {
                manager.scan_and_kill(config.oom_threshold, &log_path);
            }
            last_kill_time = Instant::now();
        }
    }
}

// --- 辅助函数 ---

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
