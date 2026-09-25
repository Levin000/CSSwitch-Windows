/// A regular-file-backed output sink prevents a descendant that inherited
/// stdout/stderr from keeping the parent blocked on pipe EOF. RLIMIT_FSIZE
/// bounds what the entire private process group can write before it is killed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BoundedControlOutputStream {
    Stdout,
    Stderr,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BoundedControlCommandFailure {
    OutputSetup,
    Spawn,
    Wait,
    Cleanup,
    Reap,
    OutputRead(BoundedControlOutputStream),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BoundedControlCommandError {
    Failed(BoundedControlCommandFailure),
    Timeout,
    OutputLimit(BoundedControlOutputStream),
}

const SCIENCE_CONTROL_CLEANUP_GRACE: Duration = Duration::from_secs(1);
const SCIENCE_CONTROL_SUPERVISOR_GRACE: Duration = Duration::from_secs(2);
#[cfg(test)]
pub(crate) const TEST_FORCE_GROUP_KILL_FAILURE_ENV: &str =
    "CSSWITCH_TEST_FORCE_CONTROL_GROUP_KILL_FAILURE";

struct ScienceControlOutput {
    file: fs::File,
    path: PathBuf,
}

impl ScienceControlOutput {
    fn create(label: &str) -> Option<Self> {
        for _ in 0..8 {
            let nonce = SCIENCE_CONTROL_OUTPUT_NONCE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                ".csswitch-science-control-{label}-{}-{nonce}",
                std::process::id()
            ));
            match OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(crate::platform::O_NOFOLLOW | crate::platform::O_CLOEXEC)
                .open(&path)
            {
                Ok(file) => return Some(Self { file, path }),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(_) => return None,
            }
        }
        None
    }

    fn stdio(&self) -> Option<Stdio> {
        self.file.try_clone().ok().map(Stdio::from)
    }

    fn read_bounded(
        &mut self,
        limit: u64,
        stream: BoundedControlOutputStream,
    ) -> Result<Vec<u8>, BoundedControlCommandError> {
        let metadata = self.file.metadata().map_err(|_| {
            BoundedControlCommandError::Failed(BoundedControlCommandFailure::OutputRead(stream))
        })?;
        if metadata.len() > limit {
            return Err(BoundedControlCommandError::OutputLimit(stream));
        }
        self.file.seek(SeekFrom::Start(0)).map_err(|_| {
            BoundedControlCommandError::Failed(BoundedControlCommandFailure::OutputRead(stream))
        })?;
        let mut bytes = Vec::new();
        std::io::Read::by_ref(&mut self.file)
            .take(limit.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|_| {
                BoundedControlCommandError::Failed(BoundedControlCommandFailure::OutputRead(stream))
            })?;
        if bytes.len() as u64 > limit {
            return Err(BoundedControlCommandError::OutputLimit(stream));
        }
        Ok(bytes)
    }
}

impl Drop for ScienceControlOutput {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

#[cfg(unix)]
fn anchored_science_control_child_exited(pid: u32) -> Result<bool, i32> {
    let mut info = std::mem::MaybeUninit::<libc::siginfo_t>::zeroed();
    loop {
        // SAFETY: info points to writable siginfo_t storage. WNOWAIT observes
        // without reaping, keeping the pid as an anchor for its private group.
        let result = unsafe {
            libc::waitid(
                libc::P_PID,
                pid as libc::id_t,
                info.as_mut_ptr(),
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        };
        if result == 0 {
            // SAFETY: successful waitid initializes siginfo_t; si_pid == 0 is
            // the specified WNOHANG result when no child exit is pending.
            return Ok(unsafe { info.assume_init().si_pid() } != 0);
        }
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        if errno != libc::EINTR {
            return Err(errno);
        }
    }
}

#[cfg(not(unix))]
// Windows 移植：无 waitid(WNOWAIT)。用 OpenProcess + GetExitCodeProcess 观测
// 退出状态：子进程未被 reap 前退出码不再是 STILL_ACTIVE 即视为已退出
// （等价 WNOHANG|WNOWAIT 的观测语义，不做进程组锚定）。
fn anchored_science_control_child_exited(pid: u32) -> Result<bool, i32> {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{
        GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    };
    const STILL_ACTIVE: u32 = 259;
    unsafe {
        // SAFETY: handle 仅为本次查询而打开，查询后立即关闭。
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if handle.is_null() {
            // 打不开：子进程已退出（原 WNOWAIT 锚定随之消失）或权限不足。
            // 返回「已退出」，交给上层 try_wait 复核真实退出码，避免把
            // 正常完成的子进程误判为 Wait 失败。
            return Ok(true);
        }
        let mut exit_code: u32 = 0;
        let ok = GetExitCodeProcess(handle, &mut exit_code);
        CloseHandle(handle);
        if ok == 0 {
            return Err(0);
        }
        Ok(exit_code != STILL_ACTIVE)
    }
}

fn kill_anchored_science_control_group(pid: u32, leader_exited: bool, force_failure: bool) -> bool {
    if force_failure {
        return false;
    }
    let Ok(pgid) = i32::try_from(pid) else {
        return false;
    };
    // SAFETY: the child was spawned with process_group(0), and the live or
    // WNOWAIT-observed leader keeps this exact pid/pgid reserved.
    if unsafe { crate::platform::kill(-pgid, crate::platform::SIGKILL) } == 0 {
        return true;
    }
    let errno = std::io::Error::last_os_error().raw_os_error();
    if errno == Some(libc::ESRCH) {
        return true;
    }
    cfg!(target_os = "macos") && leader_exited && errno == Some(libc::EPERM)
}

fn run_science_control_reaper(
    receiver: std::sync::mpsc::Receiver<Child>,
    force_group_kill_failure: bool,
) {
    let Ok(mut child) = receiver.recv() else {
        return;
    };
    let deadline = Instant::now()
        .checked_add(SCIENCE_CONTROL_CLEANUP_GRACE)
        .unwrap_or_else(Instant::now);
    let mut leader_exited = false;
    loop {
        if let Ok(exited) = anchored_science_control_child_exited(child.id()) {
            leader_exited = exited;
        }
        if kill_anchored_science_control_group(child.id(), leader_exited, force_group_kill_failure)
        {
            break;
        }
        if !leader_exited {
            let _ = child.kill();
        }
        if Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let _ = child.kill();
    let _ = child.wait();
}

fn handoff_science_control_reaper(reaper: &std::sync::mpsc::SyncSender<Child>, child: Child) {
    if let Err(error) = reaper.send(child) {
        let mut child = error.0;
        let _ = child.kill();
        let _ = child.wait();
    }
}

fn terminate_and_reap_science_control_child(
    mut child: Child,
    leader_exited: bool,
    reaper: &std::sync::mpsc::SyncSender<Child>,
    force_group_kill_failure: bool,
) -> Result<ExitStatus, BoundedControlCommandError> {
    let cleanup_deadline = Instant::now()
        .checked_add(SCIENCE_CONTROL_CLEANUP_GRACE)
        .unwrap_or_else(Instant::now);
    let mut leader_exited = leader_exited;
    let group_stopped = loop {
        if kill_anchored_science_control_group(child.id(), leader_exited, force_group_kill_failure)
        {
            break true;
        }
        if !leader_exited {
            let _fallback_stopped = child.kill().is_ok();
            if let Ok(exited) = anchored_science_control_child_exited(child.id()) {
                leader_exited = exited;
            }
        }
        if Instant::now() >= cleanup_deadline {
            break false;
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    if !group_stopped {
        handoff_science_control_reaper(reaper, child);
        return Err(BoundedControlCommandError::Failed(
            BoundedControlCommandFailure::Cleanup,
        ));
    }
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) if Instant::now() < cleanup_deadline => {
                std::thread::sleep(Duration::from_millis(20));
            }
            Ok(None) => {
                handoff_science_control_reaper(reaper, child);
                return Err(BoundedControlCommandError::Failed(
                    BoundedControlCommandFailure::Reap,
                ));
            }
            Err(_) => {
                handoff_science_control_reaper(reaper, child);
                return Err(BoundedControlCommandError::Failed(
                    BoundedControlCommandFailure::Reap,
                ));
            }
        }
    }
}

fn wait_science_control_command(
    child: Child,
    deadline: Instant,
    reaper: &std::sync::mpsc::SyncSender<Child>,
    force_group_kill_failure: bool,
) -> Result<ExitStatus, BoundedControlCommandError> {
    loop {
        match anchored_science_control_child_exited(child.id()) {
            Ok(true) => {
                return terminate_and_reap_science_control_child(
                    child,
                    true,
                    reaper,
                    force_group_kill_failure,
                );
            }
            Ok(false) if Instant::now() < deadline => {
                std::thread::sleep(
                    Duration::from_millis(20)
                        .min(deadline.saturating_duration_since(Instant::now())),
                );
            }
            Ok(false) => {
                terminate_and_reap_science_control_child(
                    child,
                    false,
                    reaper,
                    force_group_kill_failure,
                )?;
                return Err(BoundedControlCommandError::Timeout);
            }
            Err(_) => {
                terminate_and_reap_science_control_child(
                    child,
                    false,
                    reaper,
                    force_group_kill_failure,
                )?;
                return Err(BoundedControlCommandError::Failed(
                    BoundedControlCommandFailure::Wait,
                ));
            }
        }
    }
}

fn run_bounded_control_command_worker(
    mut command: Command,
    deadline: Instant,
    stdout_limit: u64,
    stderr_limit: u64,
    mut stdout: ScienceControlOutput,
    mut stderr: ScienceControlOutput,
    reaper: std::sync::mpsc::SyncSender<Child>,
    force_group_kill_failure: bool,
) -> Result<Output, BoundedControlCommandError> {
    if Instant::now() >= deadline {
        return Err(BoundedControlCommandError::Timeout);
    }
    let child = command
        .spawn()
        .map_err(|_| BoundedControlCommandError::Failed(BoundedControlCommandFailure::Spawn))?;
    let status = wait_science_control_command(child, deadline, &reaper, force_group_kill_failure)?;
    let stdout = stdout.read_bounded(stdout_limit, BoundedControlOutputStream::Stdout)?;
    let stderr = stderr.read_bounded(stderr_limit, BoundedControlOutputStream::Stderr)?;
    Ok(Output {
        status,
        stdout,
        stderr,
    })
}

pub(crate) fn run_bounded_control_command(
    mut command: Command,
    deadline: Instant,
    stdout_limit: u64,
    stderr_limit: u64,
) -> Result<Output, BoundedControlCommandError> {
    if Instant::now() >= deadline {
        return Err(BoundedControlCommandError::Timeout);
    }
    let stdout = ScienceControlOutput::create("stdout").ok_or(
        BoundedControlCommandError::Failed(BoundedControlCommandFailure::OutputSetup),
    )?;
    let stderr = ScienceControlOutput::create("stderr").ok_or(
        BoundedControlCommandError::Failed(BoundedControlCommandFailure::OutputSetup),
    )?;
    let stdout_stdio = stdout.stdio().ok_or(BoundedControlCommandError::Failed(
        BoundedControlCommandFailure::OutputSetup,
    ))?;
    let stderr_stdio = stderr.stdio().ok_or(BoundedControlCommandError::Failed(
        BoundedControlCommandFailure::OutputSetup,
    ))?;
    let file_limit = stdout_limit.max(stderr_limit).saturating_add(1);
    #[cfg(test)]
    let force_group_kill_failure = command.get_envs().any(|(key, value)| {
        key == TEST_FORCE_GROUP_KILL_FAILURE_ENV && value.is_some_and(|value| value == "1")
    });
    #[cfg(test)]
    command.env_remove(TEST_FORCE_GROUP_KILL_FAILURE_ENV);
    #[cfg(not(test))]
    let force_group_kill_failure = false;

    command.stdout(stdout_stdio).stderr(stderr_stdio);
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
        // SAFETY: setrlimit is async-signal-safe and the closure captures only a
        // copyable integer. The limit is inherited by all descendants.
        unsafe {
            command.pre_exec(move || {
                let limit = libc::rlimit {
                    rlim_cur: file_limit as libc::rlim_t,
                    rlim_max: file_limit as libc::rlim_t,
                };
                if libc::setrlimit(libc::RLIMIT_FSIZE, &limit) == 0 {
                    Ok(())
                } else {
                    Err(std::io::Error::last_os_error())
                }
            });
        }
    }
    // Windows 降级：无 process_group/pre_exec(RLIMIT_FSIZE)；子进程输出上限仍由
    // 读取侧 BoundedControlCommand 限额兜底。
    #[cfg(not(unix))]
    let _ = file_limit;
    let completion_deadline = deadline
        .checked_add(SCIENCE_CONTROL_SUPERVISOR_GRACE)
        .unwrap_or(deadline);
    let (reaper_sender, reaper_receiver) = std::sync::mpsc::sync_channel(1);
    std::thread::Builder::new()
        .name("csswitch-control-reaper".into())
        .spawn(move || {
            run_science_control_reaper(reaper_receiver, false);
        })
        .map_err(|_| BoundedControlCommandError::Failed(BoundedControlCommandFailure::Spawn))?;
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    std::thread::Builder::new()
        .name("csswitch-control-supervisor".into())
        .spawn(move || {
            let result = run_bounded_control_command_worker(
                command,
                deadline,
                stdout_limit,
                stderr_limit,
                stdout,
                stderr,
                reaper_sender,
                force_group_kill_failure,
            );
            let _ = sender.send(result);
        })
        .map_err(|_| BoundedControlCommandError::Failed(BoundedControlCommandFailure::Spawn))?;
    match receiver.recv_timeout(completion_deadline.saturating_duration_since(Instant::now())) {
        Ok(result) => result,
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => Err(BoundedControlCommandError::Timeout),
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => Err(
            BoundedControlCommandError::Failed(BoundedControlCommandFailure::Wait),
        ),
    }
}

fn run_science_control_command(
    path: &Path,
    home: &Path,
    timeout: Duration,
    stdout_limit: u64,
    stderr_limit: u64,
    configure: impl FnOnce(&mut Command),
) -> Option<Output> {
    let deadline = Instant::now().checked_add(timeout)?;
    let mut environment = super::launch_env::base_process_env();
    environment.push(("HOME".into(), home.display().to_string()));

    let mut command = Command::new(path);
    super::launch_env::apply_allowlist(&mut command, environment);
    configure(&mut command);
    run_bounded_control_command(command, deadline, stdout_limit, stderr_limit).ok()
}
