#[cfg(windows)]
fn process_text_paths(pid: u32) -> Option<Vec<PathBuf>> {
    // Windows 移植：无 lsof；用进程可执行文件路径做同等身份比较。
    crate::platform::process_image_path(pid).map(|path| vec![path])
}

#[cfg(unix)]
fn process_text_paths(pid: u32) -> Option<Vec<PathBuf>> {
    let pid_text = pid.to_string();
    let text_files = Command::new("/usr/sbin/lsof")
        .args(["-nP", "-a", "-p", &pid_text, "-d", "txt", "-Fn"])
        .output()
        .ok()?;
    if !text_files.status.success() {
        return None;
    }
    Some(
        String::from_utf8_lossy(&text_files.stdout)
            .lines()
            .filter_map(|line| line.strip_prefix('n'))
            .filter_map(|path| Path::new(path).canonicalize_norm().ok())
            .collect(),
    )
}

fn listener_runtime_pid(port: u16, runtime: &ScienceRuntimeIdentity) -> Option<u32> {
    if !runtime.is_current() {
        return None;
    }
    let pid = unique_listener_pid(port)?;
    #[cfg(test)]
    {
        let pid_text = pid.to_string();
        if test_listener_marker_matches(&pid_text, runtime) {
            return Some(pid);
        }
    }
    let expected = runtime.path.canonicalize_norm().ok()?;
    process_text_paths(pid)?
        .into_iter()
        .any(|path| path == expected)
        .then_some(pid)
}

fn listener_uses_runtime(port: u16, runtime: &ScienceRuntimeIdentity) -> bool {
    listener_runtime_pid(port, runtime).is_some()
}

#[cfg(test)]
fn test_listener_marker_matches(pid: &str, runtime: &ScienceRuntimeIdentity) -> bool {
    if std::env::var("CSSWITCH_TEST_FAKE_SCIENCE_IDENTITY")
        .ok()
        .as_deref()
        != Some("1")
    {
        return false;
    }
    let explicit_matches = std::env::var_os("SCIENCE_BIN")
        .map(PathBuf::from)
        .and_then(|configured| configured.canonicalize_norm().ok())
        == runtime.path.canonicalize_norm().ok();
    let updater_snapshot_matches = fake_science_updater_identity_armed_for_current_thread()
        && runtime.source == ScienceRuntimeSource::OfficialUpdated;
    if !explicit_matches && !updater_snapshot_matches {
        return false;
    }
    std::fs::read_to_string(sandbox_data_dir().join("fake-science/pid"))
        .ok()
        .is_some_and(|recorded| recorded.trim() == pid)
}

/// Return the sandbox UI URL, falling back to the plain localhost port.
pub(crate) fn sandbox_url(port: u16, runtime: &ScienceRuntimeIdentity) -> String {
    sandbox_url_with_timeout(port, runtime, SCIENCE_CONTROL_TIMEOUT)
}

fn sandbox_url_with_timeout(
    port: u16,
    runtime: &ScienceRuntimeIdentity,
    timeout: Duration,
) -> String {
    let home = sandbox_home();
    let data_dir = sandbox_data_dir();
    if runtime.is_current() {
        if let Some(out) = run_science_control_command(
            &runtime.path,
            &home,
            timeout,
            MAX_SCIENCE_CONTROL_OUTPUT_BYTES,
            MAX_SCIENCE_CONTROL_OUTPUT_BYTES,
            |command| {
                command.arg("url").arg("--data-dir").arg(&data_dir);
            },
        ) {
            let s = String::from_utf8_lossy(&out.stdout);
            if let Some(url) = first_http_url(&s) {
                return url;
            }
        }
    }
    format!("http://127.0.0.1:{port}")
}

fn runtime_status(runtime: &ScienceRuntimeIdentity) -> Option<bool> {
    runtime_status_with_timeout(runtime, SCIENCE_CONTROL_TIMEOUT)
}

fn runtime_status_with_timeout(
    runtime: &ScienceRuntimeIdentity,
    timeout: Duration,
) -> Option<bool> {
    if !runtime.is_current() {
        return None;
    }
    let data_dir = sandbox_data_dir();
    let out = run_science_control_command(
        &runtime.path,
        &sandbox_home(),
        timeout,
        MAX_SCIENCE_CONTROL_OUTPUT_BYTES,
        MAX_SCIENCE_CONTROL_OUTPUT_BYTES,
        |command| {
            command.arg("status").arg("--data-dir").arg(&data_dir);
        },
    )?;
    // Some Science builds use a non-zero exit to mean "not running" while
    // still returning a valid {"running":false} payload. Accept only that
    // negative result; a non-zero positive or malformed response stays unknown.
    runtime_status_value(&out)
}

pub(crate) fn probe_known_runtime(
    port: u16,
    runtime: &ScienceRuntimeIdentity,
) -> SandboxScienceState {
    let status = runtime_status(runtime);
    let health_ready = proc::http_health(port, None, 400);
    let port_accepts_tcp = health_ready || loopback_port_accepts_tcp(port);
    let listener_matches_runtime = status == Some(true)
        && health_ready
        && listener_uses_runtime(port, runtime)
        && managed_launch_identity_matches(port, runtime);
    classify_known_runtime_state(
        status,
        health_ready,
        port_accepts_tcp,
        listener_matches_runtime,
    )
}

pub(crate) fn probe_sandbox_runtime(
    port: u16,
) -> Result<(SandboxScienceState, Option<ScienceRuntimeIdentity>), String> {
    probe_sandbox_runtime_cached(port, &ScienceVersionCache::default())
}

pub(crate) fn probe_sandbox_runtime_cached(
    port: u16,
    version_cache: &ScienceVersionCache,
) -> Result<(SandboxScienceState, Option<ScienceRuntimeIdentity>), String> {
    let health_ready = proc::http_health(port, None, 400);
    let port_accepts_tcp = health_ready || loopback_port_accepts_tcp(port);
    let candidates = runtime_probe_candidates(port, version_cache)?;
    let no_candidates = candidates.is_empty();
    let mut saw_stopped = false;
    let mut saw_running_unconfirmed = false;
    for mut runtime in candidates {
        match runtime_status(&runtime) {
            Some(true) if health_ready && listener_uses_runtime(port, &runtime) => {
                if let Some(token) = managed_launch_token(port, &runtime) {
                    if hydrate_runtime_adoption_from_managed_launch(&token, &mut runtime).is_ok() {
                        return Ok((SandboxScienceState::RunningHealthy, Some(runtime)));
                    }
                }
                saw_running_unconfirmed = true;
            }
            Some(true) => saw_running_unconfirmed = true,
            Some(false) => saw_stopped = true,
            None => {}
        }
    }
    if saw_running_unconfirmed {
        return Ok((SandboxScienceState::Unknown, None));
    }
    if !port_accepts_tcp && (saw_stopped || !sandbox_data_dir().exists()) {
        return Ok((SandboxScienceState::Stopped, None));
    }
    if !port_accepts_tcp && no_candidates {
        return Ok((SandboxScienceState::Stopped, None));
    }
    Ok((SandboxScienceState::Unknown, None))
}

fn stop_runtime_from_probe(
    state: SandboxScienceState,
    runtime: Option<ScienceRuntimeIdentity>,
) -> Result<Option<ScienceRuntimeIdentity>, String> {
    match (state, runtime) {
        (SandboxScienceState::Stopped, _) => Ok(None),
        (SandboxScienceState::RunningHealthy, Some(runtime)) => Ok(Some(runtime)),
        (SandboxScienceState::RunningHealthy, None) => {
            Err("Science 状态为运行中，但无法确认其 binary 身份；已拒绝按端口停止".into())
        }
        (SandboxScienceState::Unknown, _) => {
            Err("无法确认当前 Science daemon 使用的 binary；已拒绝按端口停止".into())
        }
    }
}

/// Check that the sandbox Science associated with our data-dir is running.
/// A naked `/health` response is not sufficient identity proof.
#[cfg(test)]
pub(crate) fn sandbox_running_ours(port: u16, runtime: &ScienceRuntimeIdentity) -> bool {
    probe_known_runtime(port, runtime) == SandboxScienceState::RunningHealthy
}

/// The caller has just observed a healthy response and only needs to prove the
/// listener executable identity; avoid repeating status and health CLI work.
pub(crate) fn sandbox_listener_matches_runtime(
    port: u16,
    runtime: &ScienceRuntimeIdentity,
) -> bool {
    listener_uses_runtime(port, runtime)
}

/// Stop the sandbox Science process and clear the in-memory sandbox URL.
///
/// Returns `Err` when the stop script is unavailable or the exact managed
/// process cannot be proven stopped. A non-zero Science CLI result may fall
/// back to the already-frozen exact PID only while its full launch token is
/// still current.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SciencePostTermAction {
    Complete,
    KillExact,
    IdentityDrift,
    PreserveCommandFailure,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ScienceStopCommandOutcome {
    Success,
    NonZero,
    Unavailable,
}

fn science_post_term_action(
    command_outcome: ScienceStopCommandOutcome,
    port_accepts_tcp: bool,
    ownership_is_current: bool,
) -> SciencePostTermAction {
    if command_outcome == ScienceStopCommandOutcome::Unavailable {
        return SciencePostTermAction::PreserveCommandFailure;
    }
    match (port_accepts_tcp, ownership_is_current) {
        (false, _) => SciencePostTermAction::Complete,
        (true, true) => SciencePostTermAction::KillExact,
        (true, false) => SciencePostTermAction::IdentityDrift,
    }
}

pub(crate) fn claim_science_stop_request(
    runtime: Option<&ScienceRuntimeIdentity>,
) -> Result<ScienceStopRequest, ScienceStopFailure> {
    if !sandbox_data_dir().exists() {
        let sandbox_port = config::load_from(&config::default_dir())
            .map_err(|error| {
                ScienceStopFailure::request_rejected(format!("读取 Science 端口配置失败：{error}"))
            })?
            .sandbox_port;
        let first_port_observation = loopback_port_accepts_tcp(sandbox_port);
        let second_port_observation = if first_port_observation {
            true
        } else {
            std::thread::sleep(Duration::from_millis(20));
            loopback_port_accepts_tcp(sandbox_port)
        };
        if second_port_observation {
            return Err(ScienceStopFailure::exit_unconfirmed(
                "Science data-dir 已消失，但配置端口仍有监听；未发送信号且未确认停止。",
            ));
        }
        return Ok(ScienceStopRequest::observed_stopped());
    }
    let recovered;
    let runtime = match runtime {
        Some(runtime) => runtime,
        None => {
            let port = config::load_from(&config::default_dir())
                .map_err(|error| {
                    ScienceStopFailure::request_rejected(format!(
                        "读取 Science 端口配置失败：{error}"
                    ))
                })?
                .sandbox_port;
            let (state, runtime) =
                probe_sandbox_runtime(port).map_err(ScienceStopFailure::identity_drift)?;
            let Some(runtime) = stop_runtime_from_probe(state, runtime)
                .map_err(ScienceStopFailure::identity_drift)?
            else {
                return Ok(ScienceStopRequest::observed_stopped());
            };
            recovered = runtime;
            &recovered
        }
    };
    if !runtime.is_current() {
        return Err(ScienceStopFailure::identity_drift(
            "Science binary 在选择后发生变化；已拒绝用不同文件控制现有 daemon",
        ));
    }
    let sandbox_port = config::load_from(&config::default_dir())
        .map_err(|error| {
            ScienceStopFailure::request_rejected(format!("读取 Science 端口配置失败：{error}"))
        })?
        .sandbox_port;
    let stop_token = managed_launch_token(sandbox_port, runtime).ok_or_else(|| {
        ScienceStopFailure::identity_drift(
            "Science managed launch 身份无法确认；已拒绝调用 stop 或发送信号",
        )
    })?;
    if stop_token.record.port != sandbox_port
        || !managed_launch_token_is_current(&stop_token, runtime)
    {
        return Err(ScienceStopFailure::identity_drift(
            "Science managed launch 身份在停止前发生变化；未调用 stop 或发送信号",
        ));
    }
    Ok(ScienceStopRequest::exact(
        runtime,
        ScienceStopOwnershipReceipt::from_managed_launch(&stop_token),
    ))
}

pub(crate) struct ScienceStopExecution {
    outcome: ScienceStopOutcome,
    clear_process_tracking: bool,
}

impl ScienceStopExecution {
    pub(crate) fn into_parts(self) -> (ScienceStopOutcome, bool) {
        (self.outcome, self.clear_process_tracking)
    }
}

pub(crate) fn execute_science_stop<R: Runtime>(
    app: &tauri::AppHandle<R>,
    request: ScienceStopRequest,
) -> ScienceStopExecution {
    execute_science_stop_inner(app, request, None)
}

pub(crate) fn execute_science_stop_with_authority_bypass<R: Runtime>(
    app: &tauri::AppHandle<R>,
    request: ScienceStopRequest,
    bypass: &config::AuthorityWriterBypass<'_>,
) -> ScienceStopExecution {
    execute_science_stop_inner(app, request, Some(bypass))
}

fn execute_science_stop_inner<R: Runtime>(
    app: &tauri::AppHandle<R>,
    request: ScienceStopRequest,
    bypass: Option<&config::AuthorityWriterBypass<'_>>,
) -> ScienceStopExecution {
    let ScienceStopRequest {
        runtime,
        ownership,
        observed_stopped,
    } = request;
    let mut clear_process_tracking = observed_stopped;
    let outcome = (|| -> ScienceStopOutcome {
        if observed_stopped {
            return Ok(VerifiedScienceStop {
                runtime: None,
                ownership_was_proven: false,
            });
        }
        let recovered;
        let runtime = match runtime.as_ref() {
            Some(runtime) => runtime,
            None => {
                let port = config::load_from(&config::default_dir())
                    .map_err(|error| {
                        ScienceStopFailure::request_rejected(format!(
                            "读取 Science 端口配置失败：{error}"
                        ))
                    })?
                    .sandbox_port;
                let (state, runtime) =
                    probe_sandbox_runtime(port).map_err(ScienceStopFailure::identity_drift)?;
                let Some(runtime) = stop_runtime_from_probe(state, runtime)
                    .map_err(ScienceStopFailure::identity_drift)?
                else {
                    clear_process_tracking = true;
                    return Ok(VerifiedScienceStop {
                        runtime: None,
                        ownership_was_proven: false,
                    });
                };
                recovered = runtime;
                &recovered
            }
        };
        if !runtime.is_current() {
            return Err(ScienceStopFailure::identity_drift(
                "Science binary 在选择后发生变化；已拒绝用不同文件控制现有 daemon",
            ));
        }
        let sandbox_port = config::load_from(&config::default_dir())
            .map_err(|error| {
                ScienceStopFailure::request_rejected(format!("读取 Science 端口配置失败：{error}"))
            })?
            .sandbox_port;
        let stop_token = match ownership {
            Some(receipt) => receipt.token,
            None => managed_launch_token(sandbox_port, runtime).ok_or_else(|| {
                ScienceStopFailure::identity_drift(
                    "Science managed launch 身份无法确认；已拒绝调用 stop 或发送信号",
                )
            })?,
        };
        if stop_token.record.port != sandbox_port
            || !managed_launch_token_is_current(&stop_token, runtime)
        {
            return Err(ScienceStopFailure::identity_drift(
                "Science managed launch 身份在停止前发生变化；未调用 stop 或发送信号",
            ));
        }
        let mut failure = None;
        let mut command_outcome = ScienceStopCommandOutcome::Unavailable;
        match asset_root(app) {
            Some(root) => {
                let stop = root.join("scripts/stop-science-sandbox.sh");
                if stop.is_file() {
                    let mut stop_cmd = Command::new(crate::runtime::launch_env::science_script_shell());
                    stop_cmd.arg(crate::platform::bash_path(&stop));
                    crate::runtime::launch_env::configure_science_stop_script_command(
                        &mut stop_cmd,
                        &sandbox_home(),
                        Path::new(&runtime.path),
                    );
                    match stop_cmd
                        .stdout(Stdio::null())
                        .stderr(Stdio::null())
                        .status()
                    {
                        Ok(s) if s.success() => {
                            command_outcome = ScienceStopCommandOutcome::Success;
                        }
                        Ok(s) => {
                            command_outcome = ScienceStopCommandOutcome::NonZero;
                            failure = Some(ScienceStopFailure::stop_command_failed(format!(
                                "停止沙箱脚本非零退出（{:?}）。",
                                s.code()
                            )))
                        }
                        Err(e) => {
                            failure = Some(ScienceStopFailure::stop_command_failed(format!(
                                "调用停止沙箱脚本失败：{e}"
                            )))
                        }
                    }
                } else {
                    failure = Some(ScienceStopFailure::stop_command_failed(
                        "找不到打包的停止脚本，无法确认沙箱已停止（沙箱可能仍在运行）。",
                    ));
                }
            }
            None => {
                failure = Some(ScienceStopFailure::stop_command_failed(
                    "定位不到资源根，取不到停止脚本，无法确认沙箱已停止（沙箱可能仍在运行）。"
                        .to_string(),
                ));
            }
        }
        let port_accepts_tcp = loopback_port_accepts_tcp(sandbox_port);
        let ownership_is_current = managed_launch_token_is_current(&stop_token, runtime);
        match science_post_term_action(command_outcome, port_accepts_tcp, ownership_is_current) {
            SciencePostTermAction::Complete => {
                failure = None;
            }
            SciencePostTermAction::KillExact => {
                let pid = stop_token.record.listener_pid;
                failure = None;
                // Some upstream Science builds return success and remove their
                // lockfile without terminating the daemon; others return
                // non-zero after rejecting their own still-live PID. The user
                // requested stop, so signal only the exact launch token whose
                // listener, process start, receipt, and canonical executable
                // were proved both before and after CLI.
                // SAFETY: kill does not dereference pointers. PID > 1 and exact
                // listener identity were checked immediately above.
                if unsafe { crate::platform::kill(pid as i32, libc::SIGTERM) } != 0 {
                    failure = Some(ScienceStopFailure::signal_failure(
                        "Science CLI 后精确 daemon 无法接收 TERM。",
                    ));
                } else {
                    for _ in 0..50 {
                        if !loopback_port_accepts_tcp(sandbox_port) {
                            break;
                        }
                        std::thread::sleep(Duration::from_millis(100));
                    }
                    match science_post_term_action(
                        command_outcome,
                        loopback_port_accepts_tcp(sandbox_port),
                        managed_launch_token_is_current(&stop_token, runtime),
                    ) {
                        SciencePostTermAction::Complete => {}
                        SciencePostTermAction::KillExact => {
                            // SAFETY: the same launch token, including process-start
                            // identity, is revalidated after the TERM wait.
                            let _ = unsafe { crate::platform::kill(pid as i32, crate::platform::SIGKILL) };
                            for _ in 0..20 {
                                if !loopback_port_accepts_tcp(sandbox_port) {
                                    break;
                                }
                                std::thread::sleep(Duration::from_millis(100));
                            }
                            if loopback_port_accepts_tcp(sandbox_port) {
                                failure = Some(ScienceStopFailure::exit_unconfirmed(
                                    "Science CLI 后端口仍被占用；已拒绝把未知监听者当作停止成功。"
                                        .to_string(),
                                ));
                            }
                        }
                        SciencePostTermAction::IdentityDrift => {
                            // Preserve the existing user-visible text and refusal
                            // to signal a replacement listener, but retain the
                            // ownership reason in the typed outcome.
                            failure = Some(ScienceStopFailure::identity_drift(
                                "Science CLI 后端口仍被占用；已拒绝把未知监听者当作停止成功。",
                            ));
                        }
                        SciencePostTermAction::PreserveCommandFailure => unreachable!(
                            "a completed exact TERM always permits post-TERM classification"
                        ),
                    }
                }
            }
            SciencePostTermAction::IdentityDrift => {
                failure = Some(ScienceStopFailure::identity_drift(
                    "Science stop 后监听身份与启动记录不一致；未发送信号。",
                ));
            }
            SciencePostTermAction::PreserveCommandFailure => {}
        }
        clear_process_tracking = true;
        if failure.is_none() {
            if loopback_port_accepts_tcp(sandbox_port) {
                failure = Some(ScienceStopFailure::exit_unconfirmed(
                    "Science stop 后配置端口重新出现监听；未确认停止且未清理 managed launch 记录。"
                        .to_string(),
                ));
            } else if let Err(error) = match bypass {
                Some(bypass) => clear_managed_launch_identity_with_authority_bypass(
                    &stop_token,
                    runtime,
                    bypass,
                ),
                None => clear_managed_launch_identity(&stop_token, runtime),
            } {
                failure = Some(
                    ScienceStopFailure::receipt_cleanup_failure(error)
                        .with_confirmed_runtime(runtime.clone()),
                );
            }
        }
        #[cfg(test)]
        if failure.is_none()
            && SCIENCE_LIFECYCLE_TEST_SEAMS
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .as_ref()
                .is_some_and(|(thread, config_dir)| {
                    *thread == std::thread::current().id() && *config_dir == config::default_dir()
                })
        {
            failure = Some(
                ScienceStopFailure::outcome_publication_failure(
                    "test-only post-stop failure after exact process and receipt cleanup",
                )
                .with_confirmed_runtime(runtime.clone()),
            );
        }
        match failure {
            Some(error) => Err(error),
            None => Ok(VerifiedScienceStop {
                runtime: Some(runtime.clone()),
                ownership_was_proven: true,
            }),
        }
    })();
    ScienceStopExecution {
        outcome,
        clear_process_tracking,
    }
}

pub(crate) fn stop_sandbox<R: Runtime>(
    app: &tauri::AppHandle<R>,
    sandbox: &mut Option<Child>,
    sandbox_url: &mut Option<String>,
    request: ScienceStopRequest,
) -> ScienceStopOutcome {
    let execution = execute_science_stop(app, request);
    let (outcome, clear_process_tracking) = execution.into_parts();
    if clear_process_tracking {
        kill_child(sandbox);
        *sandbox_url = None;
    }
    outcome
}
