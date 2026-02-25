use std::collections::HashSet;
use std::env;
use std::fs::{self, File};
use std::io::{self, Read};
use std::os::fd::AsRawFd;
use std::process::Command;
// use std::thread; // 如果需要可以引入 sleep，但我们用 timerfd

use nix::sys::signal::{kill, Signal};
use nix::sys::timerfd::{TimerFd, ClockId, TimerFlags, Expiration};
use nix::sys::time::{TimeSpec, TimeValLike};
use nix::unistd::Pid;

// --- 常量定义 ---
// OOM Score 800: 通常对应 CACHED_APP_MIN_ADJ (900是空进程)
// 这是一个非常安全的阈值，绝对不会杀掉服务(500)或前台(0)
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

    // 2. 加载配置 (只执行一次，无热更新，性能最优)
    let config = load_config(config_path);
    println!("Interval: {}s", config.interval);
    println!("Whitelist loaded: {} entries", config.whitelist.len());

    // 3. 初始化 TimerFD (CLOCK_BOOTTIME 包含休眠时间，保证定时准确)
    let timer = TimerFd::new(ClockId::CLOCK_BOOTTIME, TimerFlags::empty())
        .expect("Failed to create timerfd");

    // 设定周期性唤醒时间
    // 注意：TimerFD 可以设置为周期性重复 (SetTimeFlags::TFD_TIMER_ABSTIME)，
    // 但为了逻辑清晰和处理 Doze 后的恢复，我们在循环末尾手动 set 下一次比较灵活。
    
    loop {
        // --- 循环开始，设置下一次唤醒 ---
        let interval_spec = TimeSpec::new(config.interval as i64, 0);
        timer.set(
            Expiration::OneShot(interval_spec),
            TimerFlags::empty()
        ).expect("Failed to set timer");

        // --- 挂起进程 (进入睡眠状态，0% CPU) ---
        // 只有当时间到了，或者收到信号，这里才会返回
        let _ = timer.wait();

        // --- 唤醒后逻辑 ---

        // A. 检测是否在 Doze (深度睡眠) 模式
        if is_device_in_doze() {
            // 如果在 Doze，什么都不做，直接进入下一次 wait
            // 这样既不耗电，也不会打断系统的休眠维护窗口
            continue; 
        }

        // B. 执行扫描清理
        perform_cleanup(&config.whitelist);
    }
}

/// 解析配置文件
/// 支持格式:
/// interval: 60
/// whitelist: com.a, com.b
/// com.c
/// com.d, com.e
fn load_config(path: &str) -> AppConfig {
    let mut interval = DEFAULT_INTERVAL;
    let mut whitelist = HashSet::new();
    
    // 默认白名单 (防止误杀系统核心组件)
    whitelist.insert("com.android.systemui".to_string());
    whitelist.insert("android".to_string());
    whitelist.insert("com.android.phone".to_string());

    if let Ok(content) = fs::read_to_string(path) {
        let mut in_whitelist_mode = false;

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') { continue; }

            if line.starts_with("interval:") {
                // 解析 interval: 60
                if let Some(val_part) = line.split(':').nth(1) {
                    if let Ok(val) = val_part.trim().parse::<u64>() {
                        interval = val;
                    }
                }
                in_whitelist_mode = false;
            } else if line.starts_with("whitelist:") {
                in_whitelist_mode = true;
                // 处理 "whitelist: com.a, com.b" 这种同行的情况
                if let Some(val_part) = line.split(':').nth(1) {
                    parse_packages(val_part, &mut whitelist);
                }
            } else if in_whitelist_mode {
                // 处理换行后的包名
                parse_packages(line, &mut whitelist);
            }
        }
    }

    AppConfig { interval, whitelist }
}

/// 辅助函数：处理逗号分隔的包名并插入 Set
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

        // 1. 获取 PID
        let pid_str = entry.file_name();
        let pid_str = pid_str.to_string_lossy();
        let pid: i32 = match pid_str.parse() {
            Ok(p) => p,
            Err(_) => continue, // 不是 PID 目录
        };

        // 2. UID 过滤 (System < 10000)
        // 这是第一道防线，保护系统稳定
        let uid = match get_uid(pid) {
            Some(u) => u,
            None => continue,
        };
        if uid < 10000 { continue; }

        // 3. OOM Score 过滤 (目标 >= 800)
        // 这是第二道防线，只杀后台缓存
        // 如果读取失败，假设它是活跃进程不杀，以防万一
        let oom_score = match get_oom_score(pid) {
            Some(s) => s,
            None => continue, 
        };
        if oom_score < OOM_SCORE_THRESHOLD {
            // 是前台(0)、服务(500)或可见(200)，跳过
            continue;
        }

        // 4. 白名单匹配 (Cmdline)
        let cmdline = match get_cmdline(pid) {
            Some(c) => c,
            None => continue,
        };

        // 匹配逻辑：
        // A. 完全匹配: "com.pkg.main:push" 在白名单里 -> 跳过
        // B. 主包名匹配: "com.pkg.main" 在白名单里，当前是 "com.pkg.main:push" -> 跳过
        
        // 检查完整 cmdline
        if whitelist.contains(&cmdline) { continue; }

        // 检查主包名 (去除冒号后的部分)
        let package_name = cmdline.split(':').next().unwrap_or(&cmdline);
        if whitelist.contains(package_name) { continue; }

        // 5. 所有的过滤都通过了 -> 杀！
        // println!("Killing: {} (PID: {}, OOM: {})", cmdline, pid, oom_score);
        let _ = kill(Pid::from_raw(pid), Signal::SIGKILL);
    }
}

// --- /proc 读取辅助函数 (保持轻量) ---

fn get_uid(pid: i32) -> Option<u32> {
    // 读取 /proc/pid/status 中的 Uid 行
    // 格式: Uid: 10000 10000 10000 10000
    // 我们手动解析 buffer，比 File::read_to_string 稍微快一点点，
    // 主要是为了避免每次都 String allocation，但这里为了代码简洁还是用 read_to_string
    // 现代 Rust 的 I/O 也是有 buffer 的。
    let path = format!("/proc/{}/status", pid);
    if let Ok(content) = fs::read_to_string(path) {
        for line in content.lines() {
            if line.starts_with("Uid:") {
                // split_whitespace 会自动处理多个空格
                return line.split_whitespace().nth(1)?.parse().ok();
            }
        }
    }
    None
}

fn get_oom_score(pid: i32) -> Option<i32> {
    let path = format!("/proc/{}/oom_score_adj", pid);
    let mut buf = String::with_capacity(8); // 这种文件很短
    if File::open(path).and_then(|mut f| f.read_to_string(&mut buf)).is_ok() {
        return buf.trim().parse().ok();
    }
    None
}

fn get_cmdline(pid: i32) -> Option<String> {
    let path = format!("/proc/{}/cmdline", pid);
    let mut buf = Vec::with_capacity(128);
    if File::open(path).and_then(|mut f| f.read_to_end(&mut buf)).is_ok() {
        // cmdline 以 \0 分隔参数，我们只要 argv[0]
        return buf.split(|&c| c == 0)
            .next()
            .and_then(|slice| String::from_utf8(slice.to_vec()).ok());
    }
    None
}

fn is_device_in_doze() -> bool {
    // 执行 shell 命令是开销最大的部分
    // 但因为每次 sleep 60s+ 才执行一次，且为了通用性，这是必要的妥协
    if let Ok(output) = Command::new("cmd")
        .args(&["deviceidle", "get", "deep"]) 
        .output() 
    {
        // 避免 utf8 检查错误导致 panic，用 lossy
        let s = String::from_utf8_lossy(&output.stdout);
        // IDLE 表示进入 Doze
        return s.trim().contains("IDLE");
    }
    // 如果命令执行失败，默认不在 Doze，继续工作
    false
}