use std::collections::HashSet;
use std::env;
use std::fs::{self, File};
use std::io::Read; // 去掉了 unused `self`
// use std::os::fd::AsRawFd; // 去掉了 unused import
use std::process::Command;

use nix::sys::signal::{kill, Signal};
// 引入 TimerSetTimeFlags
use nix::sys::timerfd::{TimerFd, ClockId, TimerFlags, TimerSetTimeFlags, Expiration};
use nix::sys::time::TimeSpec; // 去掉了 unused `TimeValLike`
use nix::unistd::Pid;

// --- 常量定义 ---
// OOM Score 800: 通常对应 CACHED_APP_MIN_ADJ
const OOM_SCORE_THRESHOLD: i32 = 800;
const DEFAULT_INTERVAL: u64 = 60;

// 配置结构体
struct AppConfig {
    interval: u64,
    whitelist: HashSet<String>,
}

fn main() {
    // 1. 获取命令行参数 (配置文件路径)
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <config_path>", args[0]);
        std::process::exit(1);
    }
    let config_path = &args[1];

    println!("Starting Daemon...");
    println!("Config Path: {}", config_path);

    // 2. 加载配置
    let config = load_config(config_path);
    println!("Interval: {}s", config.interval);
    println!("Whitelist loaded: {} entries", config.whitelist.len());

    // 3. 初始化 TimerFD
    // TimerFlags 用于创建 (如 CLOEXEC/NONBLOCK)
    let timer = TimerFd::new(ClockId::CLOCK_BOOTTIME, TimerFlags::empty())
        .expect("Failed to create timerfd");

    loop {
        // --- 循环开始，设置下一次唤醒 ---
        let interval_spec = TimeSpec::new(config.interval as i64, 0);
        
        // 【修复点】：这里使用 TimerSetTimeFlags
        timer.set(
            Expiration::OneShot(interval_spec),
            TimerSetTimeFlags::empty() 
        ).expect("Failed to set timer");

        // --- 挂起进程 ---
        let _ = timer.wait();

        // --- 唤醒后逻辑 ---

        // A. 检测是否在 Doze (深度睡眠) 模式
        if is_device_in_doze() {
            continue; 
        }

        // B. 执行扫描清理
        perform_cleanup(&config.whitelist);
    }
}

/// 解析配置文件
fn load_config(path: &str) -> AppConfig {
    let mut interval = DEFAULT_INTERVAL;
    let mut whitelist = HashSet::new();
    
    // 默认白名单
    whitelist.insert("com.android.systemui".to_string());
    whitelist.insert("android".to_string());
    whitelist.insert("com.android.phone".to_string());

    if let Ok(content) = fs::read_to_string(path) {
        let mut in_whitelist_mode = false;

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') { continue; }

            if line.starts_with("interval:") {
                if let Some(val_part) = line.split(':').nth(1) {
                    if let Ok(val) = val_part.trim().parse::<u64>() {
                        interval = val;
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

    AppConfig { interval, whitelist }
}

/// 辅助函数：处理逗号分隔的包名
fn parse_packages(line: &str, whitelist: &mut HashSet<String>) {
    for part in line.split(',') {
        let pkg = part.trim();
        if !pkg.is_empty() {
            whitelist.insert(pkg.to_string());
        }
    }
}

/// 核心清理逻辑
fn perform_cleanup(whitelist: &HashSet<String>) {
    let proc_dir = match fs::read_dir("/proc") {
        Ok(d) => d,
        Err(_) => return,
    };

    for entry in proc_dir {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };

        let pid_str = entry.file_name();
        let pid_str = pid_str.to_string_lossy();
        let pid: i32 = match pid_str.parse() {
            Ok(p) => p,
            Err(_) => continue,
        };

        // 1. UID 过滤
        let uid = match get_uid(pid) {
            Some(u) => u,
            None => continue,
        };
        if uid < 10000 { continue; }

        // 2. OOM Score 过滤
        let oom_score = match get_oom_score(pid) {
            Some(s) => s,
            None => continue, 
        };
        if oom_score < OOM_SCORE_THRESHOLD {
            continue;
        }

        // 3. 白名单匹配
        let cmdline = match get_cmdline(pid) {
            Some(c) => c,
            None => continue,
        };

        if whitelist.contains(&cmdline) { continue; }

        let package_name = cmdline.split(':').next().unwrap_or(&cmdline);
        if whitelist.contains(package_name) { continue; }

        // 4. 执行压制
        let _ = kill(Pid::from_raw(pid), Signal::SIGKILL);
    }
}

// --- /proc 读取辅助函数 ---

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
    if File::open(path).and_then(|mut f| f.read_to_string(&mut buf)).is_ok() {
        return buf.trim().parse().ok();
    }
    None
}

fn get_cmdline(pid: i32) -> Option<String> {
    let path = format!("/proc/{}/cmdline", pid);
    let mut buf = Vec::with_capacity(128);
    if File::open(path).and_then(|mut f| f.read_to_end(&mut buf)).is_ok() {
        return buf.split(|&c| c == 0)
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
        let s = String::from_utf8_lossy(&output.stdout);
        return s.trim().contains("IDLE");
    }
    false
}