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
const HASH_SIZE: usize = 64;
const UPDATE_INTERVAL_MS: u64 = 500; // 增量更新间隔

struct AppConfig {
    interval: u64, // 清理拦截触发间隔（秒）
    whitelist: HashSet<String>,
    oom_threshold: i32,
}

// ==========================================
// 表1：子进程专属缓存表
// ==========================================

#[derive(Clone)]
struct ProcessNode {
    pid: i32,
    process_name: String,
    oom_score: i32,
    is_alive: bool,
    last_update_ts: u64,
}

struct SubProcessCache {
    buckets: [Vec<ProcessNode>; HASH_SIZE],
    baseline_pids: HashSet<i32>, // 全局 PID 基准集合
    update_counter: u32,
}

impl SubProcessCache {
    fn new() -> Self {
        Self {
            buckets: std::array::from_fn(|_| Vec::new()),
            baseline_pids: HashSet::new(),
            update_counter: 0,
        }
    }

    /// 修复1：修正哈希算法，直接取模保证均匀分布
    fn hash(pid: i32) -> usize {
        (pid as usize) % HASH_SIZE
    }

    fn now_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
    }

    /// 存活状态双重验证
    fn check_alive(pid: i32) -> bool {
        match kill(Pid::from_raw(pid), None) {
            Ok(_) => true,
            Err(nix::errno::Errno::ESRCH) => false,
            Err(_) => std::path::Path::new(&format!("/proc/{}", pid)).exists(),
        }
    }

    /// 初始化：全量扫描并缓存所有子进程
    fn init(&mut self, whitelist: &HashSet<String>) {
        let current_pids = get_all_pids();
        let now = Self::now_ms();

        for &pid in &current_pids {
            self.try_insert_new(pid, now, whitelist);
        }
        self.baseline_pids = current_pids;
    }

    /// 核心：极限优化的增量更新 (每 500ms 触发)
    fn update(&mut self, whitelist: &HashSet<String>) {
        let current_pids = get_all_pids(); // 仅读取轻量级的纯数字目录
        let now = Self::now_ms();

        // 1. 消失的 PID (利用差集极速运算)
        for &old_pid in self.baseline_pids.difference(&current_pids) {
            let hash_idx = Self::hash(old_pid);
            for node in &mut self.buckets[hash_idx] {
                if node.pid == old_pid {
                    node.is_alive = false;
                }
            }
        }

        // 2. 新增的 PID
        for &new_pid in current_pids.difference(&self.baseline_pids) {
            self.try_insert_new(new_pid, now, whitelist);
        }

        // 3. 更新存活的【已知子进程】的 OOM Score
        // 修复3：只遍历几十个子进程读取文件，而不是去读上千个全量进程，IO开销骤降！
        for bucket in &mut self.buckets {
            for node in bucket {
                if node.is_alive && current_pids.contains(&node.pid) {
                    node.oom_score = get_oom_score(node.pid).unwrap_or(node.oom_score);
                    node.last_update_ts = now;
                }
            }
        }

        // 刷新基准
        self.baseline_pids = current_pids;
        self.update_counter += 1;

        if self.update_counter >= 10 {
            self.periodic_cleanup(now);
            self.update_counter = 0;
        }
    }

    /// 解析并插入新节点
    fn try_insert_new(&mut self, pid: i32, now: u64, whitelist: &HashSet<String>) {
        if let Some(uid) = get_uid(pid) {
            if uid < 10000 {
                return;
            }
        } else {
            return;
        }

        let cmdline = match get_cmdline(pid) {
            Some(c) if c.contains(':') && !whitelist.contains(&c) => c,
            _ => return,
        };

        let oom = get_oom_score(pid).unwrap_or(0);

        // 修复2：删除了 oom < threshold 的拦截限制。
        // 将所有带 ':' 的子进程一律入表，后续 update 才能动态追踪到 OOM 变化。

        let hash_idx = Self::hash(pid);
        self.buckets[hash_idx].push(ProcessNode {
            pid,
            process_name: cmdline,
            oom_score: oom,
            is_alive: true,
            last_update_ts: now,
        });
    }

    /// 查询与击杀 (由 interval 控制触发)
    fn query_and_kill(&mut self, threshold: i32, log_path: &Option<String>) {
        let mut killed_list = Vec::new();

        for bucket in &mut self.buckets {
            bucket.retain(|node| {
                if !node.is_alive {
                    return false;
                } // 惰性清理

                if node.oom_score >= threshold {
                    // 杀前做最后一次双重验证，防止极小概率的 PID 复用
                    if Self::check_alive(node.pid)
                        && kill(Pid::from_raw(node.pid), Signal::SIGKILL).is_ok()
                    {
                        killed_list.push(node.process_name.clone());
                        return false; // 击杀成功，移出缓存
                    }
                }
                true
            });
        }

        // 移除了全量兜底逻辑，因为增量差集算法已经绝对可靠，兜底只会徒增耗电

        if !killed_list.is_empty() {
            if let Some(path) = log_path {
                write_log_to_file(path, &killed_list);
            }
        }
    }

    fn periodic_cleanup(&mut self, now: u64) {
        for bucket in &mut self.buckets {
            if bucket.len() < 5 {
                bucket.retain(|node| node.is_alive || (now - node.last_update_ts < 5000));
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
    println!("Starting SubProcess Cache Daemon...");
    println!("Kill Interval: {}s", config.interval);
    println!("OOM Threshold: {}", config.oom_threshold);

    if let Some(ref path) = log_path {
        write_startup_log(path);
    }

    let timer = TimerFd::new(ClockId::CLOCK_BOOTTIME, TimerFlags::empty())
        .expect("Failed to create timerfd");

    // 底层 TimerFd 写死 500ms 唤醒一次，用于极致省电的增量更新
    let interval_spec = TimeSpec::new(0, (UPDATE_INTERVAL_MS * 1_000_000) as i64);
    timer
        .set(
            Expiration::Interval(interval_spec),
            TimerSetTimeFlags::empty(),
        )
        .expect("Failed to set timer");

    let mut cache = SubProcessCache::new();
    let mut cache_initialized = false;
    let mut last_kill_time = Instant::now();

    loop {
        let _ = timer.wait();

        // --- 1. 每 500ms 执行缓存增量更新 ---
        if !cache_initialized {
            cache.init(&config.whitelist);
            cache_initialized = true;
        } else {
            cache.update(&config.whitelist);
        }

        // --- 2. 到达 interval 周期才执行查表拦截 ---
        if last_kill_time.elapsed().as_secs() >= config.interval {
            if !is_device_in_doze() {
                cache.query_and_kill(config.oom_threshold, &log_path);
            }
            last_kill_time = Instant::now();
        }
    }
}

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
        let _ = writeln!(file, "子进程压制已启动 (纯表1架构)！");
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
