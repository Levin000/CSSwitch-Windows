#[cfg(test)]
fn science_status_running(out: &Output) -> bool {
    out.status.success() && science_status_value(out) == Some(true)
}

fn science_status_value(out: &Output) -> Option<bool> {
    let stdout = String::from_utf8_lossy(&out.stdout);
    for (idx, ch) in stdout.char_indices() {
        if ch != '{' {
            continue;
        }
        let mut stream =
            serde_json::Deserializer::from_str(&stdout[idx..]).into_iter::<serde_json::Value>();
        if let Some(Ok(value)) = stream.next() {
            if let Some(running) = value.get("running").and_then(|running| running.as_bool()) {
                return Some(running);
            }
        }
    }
    None
}

#[cfg(test)]
fn trusted_science_status(out: &Output) -> Option<bool> {
    match science_status_value(out) {
        Some(false) => Some(false),
        Some(true) if out.status.success() => Some(true),
        _ => None,
    }
}

fn runtime_status_value(out: &Output) -> Option<bool> {
    match science_status_value(out) {
        Some(false) => Some(false),
        Some(true) if out.status.success() => Some(true),
        _ => None,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SandboxScienceState {
    RunningHealthy,
    Stopped,
    Unknown,
}

#[cfg(test)]
fn classify_sandbox_state(
    status: Option<bool>,
    health_ready: bool,
    port_accepts_tcp: bool,
) -> SandboxScienceState {
    match status {
        Some(true) if health_ready => SandboxScienceState::RunningHealthy,
        Some(false) if !port_accepts_tcp => SandboxScienceState::Stopped,
        _ => SandboxScienceState::Unknown,
    }
}

fn classify_known_runtime_state(
    status: Option<bool>,
    health_ready: bool,
    port_accepts_tcp: bool,
    listener_matches_runtime: bool,
) -> SandboxScienceState {
    match status {
        Some(true) if health_ready && listener_matches_runtime => {
            SandboxScienceState::RunningHealthy
        }
        Some(false) if !port_accepts_tcp => SandboxScienceState::Stopped,
        _ => SandboxScienceState::Unknown,
    }
}

fn loopback_port_accepts_tcp(port: u16) -> bool {
    #[cfg(test)]
    if std::env::var_os("CSSWITCH_TEST_PORT_OBSERVATION_TARGET")
        .and_then(|value| value.to_string_lossy().parse::<u16>().ok())
        == Some(port)
    {
        if let Some(sequence_dir) = std::env::var_os("CSSWITCH_TEST_PORT_OBSERVATION_SEQUENCE_DIR")
            .map(PathBuf::from)
            .filter(|path| path.join("armed").is_file())
        {
            let false_marker = sequence_dir.join("observed-false");
            if OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&false_marker)
                .is_ok()
            {
                return false;
            }
            let replaced_marker = sequence_dir.join("receipt-replaced");
            if !replaced_marker.is_file() {
                let replacement =
                    std::env::var_os("CSSWITCH_TEST_PORT_OBSERVATION_REPLACEMENT_RECEIPT")
                        .map(PathBuf::from);
                let target =
                    std::env::var_os("CSSWITCH_TEST_PORT_OBSERVATION_RECEIPT").map(PathBuf::from);
                let replacement_result = (|| -> std::io::Result<()> {
                    let replacement = replacement.ok_or_else(|| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            "replacement receipt path is missing",
                        )
                    })?;
                    let target = target.ok_or_else(|| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            "managed receipt path is missing",
                        )
                    })?;
                    let bytes = fs::read(replacement)?;
                    let temp = sequence_dir.join("concurrent-receipt.tmp");
                    let mut file = OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .mode(0o600)
                        .custom_flags(crate::platform::O_NOFOLLOW | crate::platform::O_CLOEXEC)
                        .open(&temp)?;
                    file.write_all(&bytes)?;
                    file.sync_all()?;
                    fs::rename(&temp, &target)?;
                    File::open(
                        target
                            .parent()
                            .ok_or_else(|| std::io::Error::other("receipt parent is missing"))?,
                    )?
                    .sync_all()?;
                    fs::write(&replaced_marker, b"replaced")
                })();
                if replacement_result.is_err() {
                    let _ = fs::write(sequence_dir.join("receipt-replacement-failed"), b"failed");
                }
            }
            let _ = fs::write(sequence_dir.join("observed-true"), b"true");
            return true;
        }
    }
    let address = std::net::SocketAddr::from(([127, 0, 0, 1], port));
    std::net::TcpStream::connect_timeout(&address, Duration::from_millis(250)).is_ok()
}

fn parse_unique_listener_pid(stdout: &str) -> Option<u32> {
    let mut pids = stdout
        .lines()
        .map(str::trim)
        .filter(|pid| !pid.is_empty())
        .map(str::parse::<u32>);
    let pid = pids.next()?.ok()?;
    if pid <= 1 || pids.any(|other| other.ok() != Some(pid)) {
        return None;
    }
    Some(pid)
}

#[cfg(windows)]
fn unique_listener_pid(port: u16) -> Option<u32> {
    // Windows 移植：无 lsof；解析 netstat -ano 找唯一 LISTEN 进程。
    crate::platform::listener_pid_for_port(port)
}

#[cfg(unix)]
fn unique_listener_pid(port: u16) -> Option<u32> {
    let listener = Command::new("/usr/sbin/lsof")
        .args(["-nP", &format!("-iTCP:{port}"), "-sTCP:LISTEN", "-t"])
        .output()
        .ok()?;
    if !listener.status.success() {
        return None;
    }
    parse_unique_listener_pid(&String::from_utf8(listener.stdout).ok()?)
}

fn managed_launch_path() -> PathBuf {
    config::default_dir().join(MANAGED_LAUNCH_FILE)
}

pub(crate) fn process_start_identity(pid: u32) -> Option<String> {
    if pid <= 1 {
        return None;
    }
    #[cfg(test)]
    if std::env::var_os("CSSWITCH_TEST_PROCESS_START_DRIFT_PID")
        .and_then(|value| value.to_string_lossy().parse::<u32>().ok())
        == Some(pid)
        && std::env::var_os("CSSWITCH_TEST_PROCESS_START_DRIFT_MARKER")
            .is_some_and(|path| PathBuf::from(path).is_file())
    {
        return Some("Mon Jan  1 00:00:00 2001".into());
    }
    #[cfg(windows)]
    {
        // Windows 移植：无 /bin/date；用启动时间戳自洽格式（仅与自身记录
        // 做相等比较，格式无需与 macOS ps lstart 一致）。
        let (start_seconds, start_micros) = process_start_timestamp(pid)?;
        return Some(format!("win-start {start_seconds}.{start_micros:06}"));
    }
    #[cfg(unix)]
    {
    let (start_seconds, _) = process_start_timestamp(pid)?;
    let seconds = libc::time_t::try_from(start_seconds).ok()?;
    let output = Command::new("/bin/date")
        .args(["-r", &seconds.to_string(), "+%a %b %e %T %Y"])
        .env_clear()
        .output()
        .ok()?;
    if !output.status.success() || output.stdout.len() > 128 || !output.stderr.is_empty() {
        return None;
    }
    let identity = String::from_utf8(output.stdout).ok()?;
    let identity = identity.trim();
    if identity.is_empty()
        || identity.len() > 64
        || !identity.is_ascii()
        || identity.lines().count() != 1
    {
        return None;
    }
    // Preserve the trimmed `ps -o lstart=` representation already stored in
    // schema-v1 managed receipts, without spawning the sandbox-blocked `ps`.
    Some(identity.to_string())
    }
}

pub(crate) fn process_start_identity_digest(pid: u32) -> Option<String> {
    let (start_seconds, start_microseconds) = process_start_timestamp(pid)?;
    let mut digest = Sha256::new();
    digest.update(b"csswitch-process-start-identity-v1\0");
    digest.update(pid.to_be_bytes());
    digest.update(start_seconds.to_be_bytes());
    digest.update(start_microseconds.to_be_bytes());
    Some(format!("{:x}", digest.finalize()))
}

#[cfg(target_os = "macos")]
fn process_start_timestamp(pid: u32) -> Option<(u64, u64)> {
    if pid <= 1 {
        return None;
    }
    let mut info = std::mem::MaybeUninit::<libc::proc_bsdinfo>::zeroed();
    let info_size = std::mem::size_of::<libc::proc_bsdinfo>();
    let read = unsafe {
        libc::proc_pidinfo(
            i32::try_from(pid).ok()?,
            libc::PROC_PIDTBSDINFO,
            0,
            info.as_mut_ptr().cast(),
            i32::try_from(info_size).ok()?,
        )
    };
    if usize::try_from(read).ok()? != info_size {
        return None;
    }
    let info = unsafe { info.assume_init() };
    let start_seconds = u64::try_from(info.pbi_start_tvsec).ok()?;
    let start_microseconds = u64::try_from(info.pbi_start_tvusec).ok()?;
    if info.pbi_pid != pid || start_seconds == 0 || start_microseconds >= 1_000_000 {
        return None;
    }
    Some((start_seconds, start_microseconds))
}

#[cfg(windows)]
// Windows 移植：GetProcessTimes 读进程创建时间（FILETIME 100ns → unix 秒/微秒）。
fn process_start_timestamp(pid: u32) -> Option<(u64, u64)> {
    use windows_sys::Win32::Foundation::{CloseHandle, FILETIME};
    use windows_sys::Win32::System::Threading::{
        GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    };
    if pid <= 1 {
        return None;
    }
    unsafe {
        // SAFETY: handle 仅为本次查询而打开，查询后立即关闭。
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if handle.is_null() {
            return None;
        }
        let mut creation = FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        };
        let mut exit_time = FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        };
        let mut kernel = FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        };
        let mut user = FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        };
        let ok = GetProcessTimes(
            handle,
            &mut creation,
            &mut exit_time,
            &mut kernel,
            &mut user,
        );
        CloseHandle(handle);
        if ok == 0 {
            return None;
        }
        let ticks = (u64::from(creation.dwHighDateTime) << 32) | u64::from(creation.dwLowDateTime);
        // FILETIME：自 1601-01-01 起 100ns；换算 unix epoch。
        const EPOCH_DELTA_100NS: u64 = 116_444_736_000_000_000;
        if ticks < EPOCH_DELTA_100NS {
            return None;
        }
        let unix_100ns = ticks - EPOCH_DELTA_100NS;
        Some((unix_100ns / 10_000_000, (unix_100ns % 10_000_000) / 10))
    }
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
// Linux 降级：proc_pidinfo 是 macOS 专属 API；无法观测进程启动时间，
// 返回 None 由上层走无启动时间戳的降级指纹。
fn process_start_timestamp(_pid: u32) -> Option<(u64, u64)> {
    None
}

fn data_dir_identity() -> Option<(PathBuf, u64, u64)> {
    let data_dir = sandbox_data_dir().canonicalize_norm().ok()?;
    let metadata = data_dir.symlink_metadata().ok()?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != unsafe { crate::platform::geteuid() }
        || metadata.permissions().mode() & 0o022 != 0
    {
        return None;
    }
    Some((data_dir, metadata.dev(), metadata.ino()))
}

#[cfg(test)]
pub(crate) fn test_process_start_identity_for_pid(pid: u32) -> Option<String> {
    process_start_identity(pid)
}

#[cfg(test)]
pub(crate) fn test_unique_listener_pid(port: u16) -> Option<u32> {
    unique_listener_pid(port)
}
