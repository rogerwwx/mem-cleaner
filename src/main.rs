use std::collections::HashSet;
use std::env;
use std::fmt::Write as FmtWrite; // 引入 write! 宏用于 String
use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, Read, Write};
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

use nix::sys::signal::{kill, Signal};
use nix::sys::time::TimeSpec;
use nix::sys::timerfd::{ClockId, Expiration, TimerFd, TimerFlags, TimerSetTimeFlags};
use nix::unistd::Pid;

use time::macros::format_description;
use time::{format_description::FormatItem, Date, OffsetDateTime};

// --- 常量配置 ---
const OOM_SCORE_THRESHOLD: i32 = 800; // 只有大于此值的进程才会被检查
const DEFAULT_INTERVAL: u64 = 60;
const DOZE_CACHE_TTL_SECS: u64 = 30; // Doze 状态缓存时间，避免频繁 fork

// --- 结构体定义 ---

struct AppConfig {
    interval: u64,
    whitelist: HashSet<String>,
}

/// 扫描资源复用池
/// 作用：在循环中重复利用内存，避免成千上万次的 String 分配和释放
struct ScannerResources {
    path_buf: String,    // 复用路径字符串 "/proc/12345/..."
    file_buf: Vec<u8>,   // 复用文件读取 buffer
    cmdline_buf: String, // 复用 cmdline 解析 buffer
}

impl ScannerResources {
    fn new() -> Self {
        Self {
            path_buf: String::with_capacity(64),
            file_buf: Vec::with_capacity(128),
            cmdline_buf: String::with_capacity(128),
        }
    }
}

/// 智能日志管理器
struct Logger {
    path: PathBuf,
    /// 缓存上一次写入时的日期
    last_write_date: Option<Date>,
}

impl Logger {
    fn new(path: Option<String>) -> Option<Self> {
        path.map(|p| Self {
            path: PathBuf::from(p),
            last_write_date: None,
        })
    }

    /// 打开日志文件句柄。
    /// 逻辑：
    /// 1. 获取当前日期。
    /// 2. 如果当前日期 != 上次写入日期：
    ///    a. 检查磁盘文件的修改时间 (mtime)。
    ///    b. 如果磁盘文件也是今天的 -> 追加 (Append)。
    ///    c. 如果磁盘文件是昨天的 -> 截断 (Truncate/Overwrite)。
    /// 3. 如果当前日期 == 上次写入日期 -> 追加 (Append)。
    fn open_writer(&mut self) -> Option<BufWriter<File>> {
        let now = OffsetDateTime::now_local().unwrap_or_else(|_| OffsetDateTime::now_utc());
        let today = now.date();

        // 默认为追加模式
        let mut should_truncate = false;

        // 只有当内存记录的日期变了（或者刚启动为 None），才去检查文件系统
        if self.last_write_date != Some(today) {
            // 检查文件实际的修改时间
            if let Ok(meta) = fs::metadata(&self.path) {
                if let Ok(mtime) = meta.modified() {
                    let mtime_dt = OffsetDateTime::from(mtime);
                    let file_date = mtime_dt.date();

                    // 核心逻辑：如果文件日期不是今天，说明是旧日志，需要截断
                    if file_date != today {
                        should_truncate = true;
                    }
                    // else: 文件日期是今天（可能刚才重启过），保持 false (Append)
                } else {
                    // 获取不到时间，稳妥起见，如果文件存在则追加，不轻易删除
                    should_truncate = false;
                }
            } else {
                // 文件不存在，新建，truncate 无所谓
                should_truncate = true;
            }

            // 更新内存缓存
            self.last_write_date = Some(today);
        }

        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .append(!should_truncate)
            .truncate(should_truncate)
            .open(&self.path)
            .ok()?;

        Some(BufWriter::new(file))
    }

    fn write_startup(&mut self) {
        if let Some(mut writer) = self.open_writer() {
            let _ = writeln!(writer, "=== 启动时间: {} ===", now_fmt());
            let _ = writeln!(writer, "进程压制 Daemon 已启动");
            let _ = writeln!(writer);
        }
    }

    fn write_cleanup(&mut self, killed_list: &[String]) {
        if killed_list.is_empty() {
            return;
        }
        // 只有真的有内容要写时，才打开文件
        if let Some(mut writer) = self.open_writer() {
            let _ = writeln!(writer, "=== 清理时间: {} ===", now_fmt());
            for pkg in killed_list {
                let _ = writeln!(writer, "已清理: {}", pkg);
            }
            let _ = writeln!(writer);
        }
    }
}

// --- Doze 缓存 (减少 fork 开销) ---
struct DozeCache {
    last_checked: Option<Instant>,
    is_deep: bool,
    ttl: Duration,
}

impl DozeCache {
    fn new(ttl: Duration) -> Self {
        Self {
            last_checked: None,
            is_deep: false,
            ttl,
        }
    }

    fn is_deep_doze_cached(&mut self) -> bool {
        let now = Instant::now();
        // 检查缓存是否有效
        if let Some(t) = self.last_checked {
            if now.duration_since(t) < self.ttl {
                return self.is_deep;
            }
        }

        // 缓存失效，执行实际检查
        let state = is_device_in_deep_doze();
        self.last_checked = Some(now);
        self.is_deep = state;
        state
    }
}

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

    println!("Starting Daemon...");
    let config = load_config(config_path);
    println!("Interval: {}s", config.interval);

    // 1. 初始化日志
    let mut logger = Logger::new(log_path);
    if let Some(l) = &mut logger {
        l.write_startup();
    }

    // 2. 初始化 TimerFD
    let timer = TimerFd::new(ClockId::CLOCK_BOOTTIME, TimerFlags::empty())
        .expect("Failed to create timerfd");
    let interval_spec = TimeSpec::new(config.interval as i64, 0);
    timer
        .set(
            Expiration::Interval(interval_spec),
            TimerSetTimeFlags::empty(),
        )
        .expect("Failed to set timer");

    // 3. 初始化缓存和资源池
    let mut doze_cache = DozeCache::new(Duration::from_secs(DOZE_CACHE_TTL_SECS));
    let mut resources = ScannerResources::new();

    loop {
        // 阻塞等待定时器
        let _ = timer.wait();

        // 检查 Doze 状态
        if doze_cache.is_deep_doze_cached() {
            continue;
        }

        // 执行清理任务
        perform_cleanup(&config.whitelist, &mut logger, &mut resources);
    }
}

// --- 核心业务逻辑 ---

fn perform_cleanup(
    whitelist: &HashSet<String>,
    logger: &mut Option<Logger>,
    res: &mut ScannerResources,
) {
    let proc_dir = match fs::read_dir("/proc") {
        Ok(d) => d,
        Err(_) => return,
    };

    let mut killed_list: Vec<String> = Vec::new();

    for entry in proc_dir {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };

        // 优化 1: 快速过滤非 PID 目录
        // file_name() 返回 &OsStr, 直接转换 check
        let file_name = entry.file_name();
        let file_name_bytes = file_name.as_encoded_bytes();

        // 简单的 ASCII 数字检查，比 parse::<i32> 更快一点点，且避免 String 分配
        if file_name_bytes.is_empty() || !file_name_bytes.iter().all(|b| b.is_ascii_digit()) {
            continue;
        }

        let pid_str = unsafe { std::str::from_utf8_unchecked(file_name_bytes) };
        let pid: i32 = match pid_str.parse() {
            Ok(p) => p,
            Err(_) => continue,
        };

        // 优化 2: 先查 oom_score_adj (最轻量的文件读取)
        res.path_buf.clear();
        let _ = write!(res.path_buf, "/proc/{}/oom_score_adj", pid);

        if let Some(score) = read_int_from_file(&res.path_buf, &mut res.file_buf) {
            if score < OOM_SCORE_THRESHOLD {
                continue;
            }
        } else {
            continue; // 无法读取，可能进程已消失
        }

        // 优化 3: 查 UID (一次 syscall)
        res.path_buf.clear();
        let _ = write!(res.path_buf, "/proc/{}", pid);

        let metadata = match fs::metadata(&res.path_buf) {
            Ok(m) => m,
            Err(_) => continue,
        };

        if metadata.uid() < 10000 {
            continue;
        }

        // 优化 4: 查 cmdline
        res.path_buf.push_str("/cmdline");
        if !read_string_from_file(&res.path_buf, &mut res.file_buf, &mut res.cmdline_buf) {
            continue;
        }
        let cmdline = &res.cmdline_buf;

        if cmdline.is_empty() {
            continue;
        }

        // 白名单检查
        if whitelist.contains(cmdline) {
            continue;
        }

        // 策略: 只杀子进程 (包含 :)，或者你可以根据需求修改这里
        if !cmdline.contains(':') {
            continue;
        }

        // 执行 Kill
        // 直接发送信号，不需要再 stat 一次
        if kill(Pid::from_raw(pid), Signal::SIGKILL).is_ok() {
            killed_list.push(cmdline.clone());
        }
    }

    // 写入日志
    if !killed_list.is_empty() {
        if let Some(l) = logger {
            l.write_cleanup(&killed_list);
        }
    }
}

// --- 底层 I/O 辅助 ---

#[inline(always)]
fn read_int_from_file(path: &str, buf: &mut Vec<u8>) -> Option<i32> {
    buf.clear();
    // 使用 File::open 也可以，但在某些内核版本上，直接读小文件开销差别不大
    let mut f = File::open(path).ok()?;
    // oom_score_adj 最大也就几字节
    let _ = f.read_to_end(buf).ok()?;
    let s = std::str::from_utf8(buf).ok()?.trim();
    s.parse().ok()
}

#[inline(always)]
fn read_string_from_file(path: &str, buf: &mut Vec<u8>, out_str: &mut String) -> bool {
    buf.clear();
    let mut f = match File::open(path) {
        Ok(f) => f,
        Err(_) => return false,
    };
    if f.read_to_end(buf).is_err() {
        return false;
    }

    // cmdline 格式是 "arg0\0arg1\0..."，我们通常只关心 argv[0] 即包名/进程名
    let slice = buf.split(|&c| c == 0).next().unwrap_or(&[]);

    out_str.clear();
    out_str.push_str(&String::from_utf8_lossy(slice));
    !out_str.is_empty()
}

fn is_device_in_deep_doze() -> bool {
    // 依然使用 cmd deviceidle get deep，因为这是最直接的接口
    // 它的开销主要在 fork，我们通过外层的 DozeCache 限制了调用频率
    if let Ok(output) = Command::new("cmd")
        .args(&["deviceidle", "get", "deep"])
        .output()
    {
        let s = String::from_utf8_lossy(&output.stdout).trim().to_string();
        return s == "IDLE";
    }
    false
}

// --- 配置加载与时间 ---

fn load_config(path: &str) -> AppConfig {
    let mut interval = DEFAULT_INTERVAL;
    let mut whitelist = HashSet::new();

    // 基础白名单
    whitelist.insert("com.android.systemui".to_string());
    whitelist.insert("android".to_string());
    whitelist.insert("com.android.phone".to_string());

    if let Ok(content) = fs::read_to_string(path) {
        let mut in_whitelist_mode = false;
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

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
    AppConfig {
        interval,
        whitelist,
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

static TIME_FMT: &[FormatItem<'static>] =
    format_description!("[year]-[month]-[day] [hour]:[minute]:[second]");

fn now_fmt() -> String {
    let dt = OffsetDateTime::now_local().unwrap_or_else(|_| OffsetDateTime::now_utc());
    dt.format(TIME_FMT)
        .unwrap_or_else(|_| "time_err".to_string())
}
