use std::collections::HashSet;
use std::env;
use std::fs::{self, File, OpenOptions}; // 新增 OpenOptions
use std::io::{Read, Write}; // 新增 Write
use std::process::Command;

use nix::sys::signal::{kill, Signal};
use nix::sys::timerfd::{TimerFd, ClockId, TimerFlags, TimerSetTimeFlags, Expiration};
use nix::sys::time::TimeSpec;
use nix::unistd::Pid;

use time::{format_description::FormatItem, macros::format_description, OffsetDateTime};

// --- 常量定义 ---
const OOM_SCORE_THRESHOLD: i32 = 800;
const DEFAULT_INTERVAL: u64 = 60;

// 配置结构体
struct AppConfig {
    interval: u64,
    whitelist: HashSet<String>,
}

fn main() {
    // 1. 获取命令行参数
    // 用法: mem_cleaner <config_path> [log_path]
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <config_path> [log_path]", args[0]);
        std::process::exit(1);
    }
    
    let config_path = &args[1];
    // 获取日志路径 (Option)，如果 service.sh 传了就用，没传就不记
    let log_path = if args.len() > 2 {
        Some(args[2].clone())
    } else {
        None
    };

    println!("Starting Daemon...");
    println!("Config Path: {}", config_path);
    if let Some(ref p) = log_path {
        println!("Log Path: {}", p);
    }

    // 2. 加载配置
    let config = load_config(config_path);
    println!("Interval: {}s", config.interval);
    println!("Whitelist loaded: {} entries", config.whitelist.len());

    if let Some(ref path) = log_path {
        let msg = vec!["进程压制已启动！".to_string()];
        write_log_to_file(path, &msg);
    }

    // 3. 初始化 TimerFD
    let timer = TimerFd::new(ClockId::CLOCK_BOOTTIME, TimerFlags::empty())
        .expect("Failed to create timerfd");

    loop {
        // --- 设置下一次唤醒 ---
        let interval_spec = TimeSpec::new(config.interval as i64, 0);
        
        timer.set(
            Expiration::Interval(interval_spec),
            TimerSetTimeFlags::empty() 
        ).expect("Failed to set timer");

        // --- 挂起等待 ---
        let _ = timer.wait();

        // --- 唤醒后逻辑 ---

        // A. 检测 Doze
        if is_device_in_doze() {
            continue; 
        }

        // B. 执行扫描清理 (传入日志路径)
        perform_cleanup(&config.whitelist, &log_path);
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
fn perform_cleanup(whitelist: &HashSet<String>, log_path: &Option<String>) {
    let proc_dir = match fs::read_dir("/proc") {
        Ok(d) => d,
        Err(_) => return,
    };

    // 用于暂存本次循环被杀掉的进程名
    let mut killed_list: Vec<String> = Vec::new();

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

        // 3. Cmdline 获取
        let cmdline = match get_cmdline(pid) {
            Some(c) => c,
            None => continue,
        };

        // 4. 严格模式逻辑：只杀带冒号的子进程
        if !cmdline.contains(':') {
            continue; 
        }

        // 5. 白名单检查
        if whitelist.contains(&cmdline) {
            continue;
        }

        // 6. 杀进程
        // 尝试杀进程，如果成功（或发送信号成功），则记录
        if kill(Pid::from_raw(pid), Signal::SIGKILL).is_ok() {
            // 将被杀的进程名加入列表
            killed_list.push(cmdline);
        }
    }

    // 循环结束后，如果有进程被杀，且配置了日志路径，则写入文件
    if !killed_list.is_empty() {
        if let Some(path) = log_path {
            write_log_to_file(path, &killed_list);
        }
    }
}

/// 将清理记录写入日志文件
fn write_log_to_file(path: &str, killed_list: &[String]) {
    // 定义日期格式
    let date_format = time::format_description::parse("[year]-[month]-[day]").unwrap();
    let datetime_format = time::format_description::parse("[year]-[month]-[day] [hour]:[minute]:[second]").unwrap();

    // 获取当前日期和时间
    let now = OffsetDateTime::now_utc();
    let today = now.format(&date_format).unwrap();
    let time_str = now.format(&datetime_format).unwrap();

    // 检查文件是否存在
    let need_clear = if let Ok(content) = fs::read_to_string(path) {
        // 如果文件第一行包含的日期不是今天，就清空
        !content.contains(&today)
    } else {
        true
    };

    // 打开文件，必要时清空
    let mut file = match OpenOptions::new()
        .create(true)
        .write(true)
        .append(!need_clear) // 如果需要清空，就不用 append
        .truncate(need_clear) // 清空文件
        .open(path)
    {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Failed to open log file: {}", e);
            return;
        }
    };

    // 写入头部
    let _ = writeln!(file, "=== 清理时间: {} ===", time_str);

    // 写入被杀的进程名
    for pkg in killed_list {
        let _ = writeln!(file, "已清理: {}", pkg);
    }

    let _ = writeln!(file, "");
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