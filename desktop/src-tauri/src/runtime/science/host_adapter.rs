/// Behavior-preserving façade for the process-local Claude Science host.
///
/// This adapter deliberately remains macOS/Rust + shell specific. It owns the
/// launch command encoding, environment-exposure classification, health and
/// listener proof, managed launch receipt publication, and the existing typed
/// stop/probe surface. Coordinators retain operation ordering and compensation
/// policy; they do not interpret shell exit codes or reconstruct host identity.
pub(crate) struct ScienceHostAdapter;

/// Process-local proof that an exact CSSwitch-managed Science runtime was
/// healthy while its managed launch receipt still named the same owner.
///
/// The fields intentionally stay private: callers may carry and revalidate
/// the proof, but cannot synthesize one from a cached executable identity.
#[must_use]
pub(crate) struct ScienceManagedHealthyProof {
    runtime: ScienceRuntimeIdentity,
    port: u16,
    ownership: ScienceManagedLaunchToken,
}

impl ScienceManagedHealthyProof {
    pub(crate) fn runtime(&self) -> &ScienceRuntimeIdentity {
        &self.runtime
    }
}

const SCIENCE_LAUNCH_ENVIRONMENT_EXPOSED_EXIT_CODE: i32 = 70;

#[cfg(test)]
static SCIENCE_HOST_ADAPTER_TEST_SEAMS: std::sync::LazyLock<
    std::sync::Mutex<Option<std::thread::ThreadId>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(None));

#[cfg(test)]
pub(crate) struct ScienceHostAdapterTestSeamGuard;

#[cfg(test)]
impl Drop for ScienceHostAdapterTestSeamGuard {
    fn drop(&mut self) {
        *SCIENCE_HOST_ADAPTER_TEST_SEAMS
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = None;
    }
}

#[cfg(test)]
pub(crate) fn test_arm_science_launch_spawn_failure() -> ScienceHostAdapterTestSeamGuard {
    *SCIENCE_HOST_ADAPTER_TEST_SEAMS
        .lock()
        .unwrap_or_else(|error| error.into_inner()) = Some(std::thread::current().id());
    ScienceHostAdapterTestSeamGuard
}

#[cfg(test)]
fn test_science_launch_spawn_failure_armed() -> bool {
    SCIENCE_HOST_ADAPTER_TEST_SEAMS
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .as_ref()
        .is_some_and(|thread_id| *thread_id == std::thread::current().id())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ScienceEnvironmentExposure {
    NotExposed,
    Exposed,
    Uncertain,
}

impl ScienceEnvironmentExposure {
    pub(crate) fn may_be_exposed(self) -> bool {
        self != Self::NotExposed
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ScienceLaunchFailureKind {
    RuntimeDrift,
    SpawnFailed,
    WaitFailed,
    ScriptFailed,
    HealthTimeout,
    ListenerIdentityMismatch,
    OwnershipUnavailable,
    ReceiptCommitFailed,
    ReceiptIdentityDrift,
}

impl ScienceLaunchFailureKind {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::RuntimeDrift => "runtime_drift",
            Self::SpawnFailed => "spawn_failed",
            Self::WaitFailed => "wait_failed",
            Self::ScriptFailed => "script_failed",
            Self::HealthTimeout => "health_timeout",
            Self::ListenerIdentityMismatch => "listener_identity_mismatch",
            Self::OwnershipUnavailable => "ownership_unavailable",
            Self::ReceiptCommitFailed => "receipt_commit_failed",
            Self::ReceiptIdentityDrift => "receipt_identity_drift",
        }
    }
}

#[derive(Debug)]
pub(crate) struct ScienceLaunchFailure {
    kind: ScienceLaunchFailureKind,
    message: String,
    environment: ScienceEnvironmentExposure,
    ownership: Option<ScienceManagedLaunchToken>,
    exit_code: Option<i32>,
}

impl ScienceLaunchFailure {
    fn new(
        kind: ScienceLaunchFailureKind,
        message: impl Into<String>,
        environment: ScienceEnvironmentExposure,
    ) -> Self {
        Self {
            kind,
            message: message.into(),
            environment,
            ownership: None,
            exit_code: None,
        }
    }

    fn with_ownership(mut self, ownership: Option<ScienceManagedLaunchToken>) -> Self {
        self.ownership = ownership;
        self
    }

    fn with_exit_code(mut self, exit_code: Option<i32>) -> Self {
        self.exit_code = exit_code;
        self
    }

    pub(crate) fn kind(&self) -> ScienceLaunchFailureKind {
        self.kind
    }

    pub(crate) fn message(&self) -> &str {
        &self.message
    }

    pub(crate) fn environment(&self) -> ScienceEnvironmentExposure {
        self.environment
    }

    pub(crate) fn ownership(&self) -> Option<&ScienceManagedLaunchToken> {
        self.ownership.as_ref()
    }

    pub(crate) fn exit_code(&self) -> Option<i32> {
        self.exit_code
    }
}

impl std::fmt::Display for ScienceLaunchFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for ScienceLaunchFailure {}

fn launch_script_failure(
    status: &ExitStatus,
    environment: ScienceEnvironmentExposure,
) -> ScienceLaunchFailure {
    ScienceLaunchFailure::new(
        ScienceLaunchFailureKind::ScriptFailed,
        format!("启动脚本非零退出（{:?}）", status.code()),
        environment,
    )
    .with_exit_code(status.code())
}

#[derive(Clone, Copy, Debug)]
enum ScienceLaunchWaitPolicy {
    Synchronous,
    AbsoluteDeadline,
}

pub(crate) struct ScienceLaunchSpec<'a> {
    launch_script: &'a Path,
    runtime: &'a ScienceRuntimeIdentity,
    port: u16,
    proxy_url: &'a str,
    reuse_system_ssh: bool,
    system_ssh_hosts: &'a str,
    opaque_bindings: Option<&'a str>,
    health_budget: Duration,
    poll_interval: Duration,
    health_probe_timeout_ms: u64,
    wait_policy: ScienceLaunchWaitPolicy,
    recheck_committed_receipt: bool,
}

impl<'a> ScienceLaunchSpec<'a> {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn one_click(
        launch_script: &'a Path,
        runtime: &'a ScienceRuntimeIdentity,
        port: u16,
        proxy_url: &'a str,
        reuse_system_ssh: bool,
        system_ssh_hosts: &'a str,
        opaque_bindings: Option<&'a str>,
        health_budget_ms: u64,
        poll_interval_ms: u64,
        health_probe_timeout_ms: u64,
    ) -> Self {
        Self {
            launch_script,
            runtime,
            port,
            proxy_url,
            reuse_system_ssh,
            system_ssh_hosts,
            opaque_bindings,
            health_budget: Duration::from_millis(health_budget_ms),
            poll_interval: Duration::from_millis(poll_interval_ms),
            health_probe_timeout_ms,
            wait_policy: ScienceLaunchWaitPolicy::Synchronous,
            recheck_committed_receipt: false,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn recovery(
        launch_script: &'a Path,
        runtime: &'a ScienceRuntimeIdentity,
        port: u16,
        proxy_url: &'a str,
        reuse_system_ssh: bool,
        system_ssh_hosts: &'a str,
        health_budget_ms: u64,
        poll_interval_ms: u64,
        health_probe_timeout_ms: u64,
    ) -> Self {
        Self {
            launch_script,
            runtime,
            port,
            proxy_url,
            reuse_system_ssh,
            system_ssh_hosts,
            opaque_bindings: None,
            health_budget: Duration::from_millis(health_budget_ms.max(poll_interval_ms)),
            poll_interval: Duration::from_millis(poll_interval_ms),
            health_probe_timeout_ms,
            wait_policy: ScienceLaunchWaitPolicy::AbsoluteDeadline,
            recheck_committed_receipt: true,
        }
    }
}

pub(crate) struct ScienceLaunchAttempt {
    runtime: ScienceRuntimeIdentity,
    port: u16,
    status: ExitStatus,
    environment: ScienceEnvironmentExposure,
    health_budget: Duration,
    poll_interval: Duration,
    health_probe_timeout_ms: u64,
    deadline: Option<Instant>,
    recheck_committed_receipt: bool,
}

impl ScienceLaunchAttempt {
    pub(crate) fn environment(&self) -> ScienceEnvironmentExposure {
        self.environment
    }
}

pub(crate) struct ScienceVerifiedLaunch {
    runtime: ScienceRuntimeIdentity,
    port: u16,
    ownership: Option<ScienceManagedLaunchToken>,
    recheck_committed_receipt: bool,
}

pub(crate) struct ScienceHealthyLaunch {
    runtime: ScienceRuntimeIdentity,
    port: u16,
    recheck_committed_receipt: bool,
}

impl ScienceVerifiedLaunch {
    pub(crate) fn ownership(&self) -> Option<&ScienceManagedLaunchToken> {
        self.ownership.as_ref()
    }
}

pub(crate) struct ScienceLaunchReceipt {
    ownership: ScienceManagedLaunchToken,
    runtime: ScienceRuntimeIdentity,
}

impl ScienceLaunchReceipt {
    pub(crate) fn ownership(&self) -> &ScienceManagedLaunchToken {
        &self.ownership
    }

    pub(crate) fn runtime(&self) -> &ScienceRuntimeIdentity {
        &self.runtime
    }
}

impl ScienceHostAdapter {
    pub(crate) fn validate_launch_runtime(
        runtime: &ScienceRuntimeIdentity,
    ) -> Result<(), ScienceLaunchFailure> {
        if runtime.is_current() {
            Ok(())
        } else {
            Err(ScienceLaunchFailure::new(
                ScienceLaunchFailureKind::RuntimeDrift,
                "Science runtime 在启动前发生变化",
                ScienceEnvironmentExposure::NotExposed,
            ))
        }
    }

    pub(crate) fn spawn_launch(
        spec: ScienceLaunchSpec<'_>,
        stdout: File,
        stderr: File,
    ) -> Result<ScienceLaunchAttempt, ScienceLaunchFailure> {
        let acceptance_outer_sandbox =
            std::env::var(super::launch_env::ACCEPTANCE_OUTER_SANDBOX_ENV)
                .ok()
                .as_deref()
                == Some("1");
        if acceptance_outer_sandbox && !super::launch_env::current_process_denies_network_outbound()
        {
            return Err(ScienceLaunchFailure::new(
                ScienceLaunchFailureKind::RuntimeDrift,
                "isolated-live outer sandbox does not deny network-outbound",
                ScienceEnvironmentExposure::NotExposed,
            ));
        }
        let deadline = matches!(spec.wait_policy, ScienceLaunchWaitPolicy::AbsoluteDeadline)
            .then(|| Instant::now() + spec.health_budget);
        #[cfg(test)]
        if test_science_launch_spawn_failure_armed() {
            return Err(ScienceLaunchFailure::new(
                ScienceLaunchFailureKind::SpawnFailed,
                "test-only zsh spawn failure",
                ScienceEnvironmentExposure::NotExposed,
            ));
        }
        let mut command = Command::new(crate::runtime::launch_env::science_script_shell());
        command
            .arg(crate::platform::bash_path(spec.launch_script))
            .arg("--port")
            .arg(spec.port.to_string())
            .arg("--skip-oauth-forge");
        super::launch_env::configure_science_launch_script_command(
            &mut command,
            &super::launch_env::ScienceLaunchScriptEnv {
                sandbox_home: &sandbox_home(),
                science_bin: Path::new(&spec.runtime.path),
                proxy_url: spec.proxy_url,
                reuse_system_ssh: spec.reuse_system_ssh,
                system_ssh_hosts: spec.system_ssh_hosts,
                // Windows 降级：不下发 opaque 绑定（dev/inode 锚定在 Windows 上
                // 不可观测，启动脚本侧相应跳过绑定校验），也不声明
                // runtime_version_prechecked（让移植版启动脚本自己做 --version
                // 预检），避免二次启动时 conda/runtime 等目录已存在导致拒绝。
                opaque_bindings: if cfg!(unix) {
                    spec.opaque_bindings
                } else {
                    None
                },
                runtime_version_prechecked: cfg!(unix),
                acceptance_outer_sandbox,
            },
        );
        let mut child = command
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr))
            .spawn()
            .map_err(|error| {
                ScienceLaunchFailure::new(
                    ScienceLaunchFailureKind::SpawnFailed,
                    error.to_string(),
                    ScienceEnvironmentExposure::NotExposed,
                )
            })?;

        let status = match spec.wait_policy {
            ScienceLaunchWaitPolicy::Synchronous => child.wait().map_err(|error| {
                ScienceLaunchFailure::new(
                    ScienceLaunchFailureKind::WaitFailed,
                    error.to_string(),
                    ScienceEnvironmentExposure::Uncertain,
                )
            })?,
            ScienceLaunchWaitPolicy::AbsoluteDeadline => loop {
                match child.try_wait() {
                    Ok(Some(status)) => break status,
                    Ok(None) if deadline.is_some_and(|deadline| Instant::now() < deadline) => {
                        std::thread::sleep(
                            spec.poll_interval.min(
                                deadline
                                    .expect("absolute deadline policy must set deadline")
                                    .saturating_duration_since(Instant::now()),
                            ),
                        );
                    }
                    Ok(None) => {
                        let _ = child.kill();
                        let _ = child.wait();
                        return Err(ScienceLaunchFailure::new(
                            ScienceLaunchFailureKind::WaitFailed,
                            "启动脚本超过 absolute deadline",
                            ScienceEnvironmentExposure::Uncertain,
                        ));
                    }
                    Err(error) => {
                        let _ = child.kill();
                        let _ = child.wait();
                        return Err(ScienceLaunchFailure::new(
                            ScienceLaunchFailureKind::WaitFailed,
                            format!("启动脚本状态未知：{error}"),
                            ScienceEnvironmentExposure::Uncertain,
                        ));
                    }
                }
            },
        };
        let environment = match spec.wait_policy {
            ScienceLaunchWaitPolicy::Synchronous
                if !status.success()
                    && status.code() != Some(SCIENCE_LAUNCH_ENVIRONMENT_EXPOSED_EXIT_CODE)
                    && status.code().is_some() =>
            {
                ScienceEnvironmentExposure::NotExposed
            }
            _ => ScienceEnvironmentExposure::Exposed,
        };
        Ok(ScienceLaunchAttempt {
            runtime: spec.runtime.clone(),
            port: spec.port,
            status,
            environment,
            health_budget: spec.health_budget,
            poll_interval: spec.poll_interval,
            health_probe_timeout_ms: spec.health_probe_timeout_ms,
            deadline,
            recheck_committed_receipt: spec.recheck_committed_receipt,
        })
    }

    pub(crate) fn accept_launch_script(
        attempt: ScienceLaunchAttempt,
    ) -> Result<ScienceLaunchAttempt, ScienceLaunchFailure> {
        if !attempt.status.success() {
            return Err(launch_script_failure(&attempt.status, attempt.environment));
        }
        Ok(attempt)
    }

    pub(crate) fn verify_health(
        attempt: ScienceLaunchAttempt,
    ) -> Result<ScienceHealthyLaunch, ScienceLaunchFailure> {
        let healthy = match attempt.deadline {
            None => {
                let attempts =
                    attempt.health_budget.as_millis() / attempt.poll_interval.as_millis().max(1);
                let mut healthy = false;
                for _ in 0..attempts {
                    std::thread::sleep(attempt.poll_interval);
                    if proc::http_health(attempt.port, None, attempt.health_probe_timeout_ms) {
                        healthy = true;
                        break;
                    }
                }
                healthy
            }
            Some(deadline) => {
                let mut healthy = false;
                while Instant::now() < deadline {
                    std::thread::sleep(
                        attempt
                            .poll_interval
                            .min(deadline.saturating_duration_since(Instant::now())),
                    );
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        break;
                    }
                    let probe_timeout_ms = attempt.health_probe_timeout_ms.min(
                        u64::try_from(remaining.as_millis())
                            .unwrap_or(u64::MAX)
                            .max(1),
                    );
                    if proc::http_health(attempt.port, None, probe_timeout_ms) {
                        healthy = true;
                        break;
                    }
                }
                healthy && Instant::now() <= deadline
            }
        };
        if !healthy {
            return Err(ScienceLaunchFailure::new(
                ScienceLaunchFailureKind::HealthTimeout,
                "Science listener 探活超时",
                attempt.environment,
            ));
        }
        Ok(ScienceHealthyLaunch {
            runtime: attempt.runtime,
            port: attempt.port,
            recheck_committed_receipt: attempt.recheck_committed_receipt,
        })
    }

    pub(crate) fn verify_identity(
        healthy: ScienceHealthyLaunch,
    ) -> Result<ScienceVerifiedLaunch, ScienceLaunchFailure> {
        if !sandbox_listener_matches_runtime(healthy.port, &healthy.runtime) {
            return Err(ScienceLaunchFailure::new(
                ScienceLaunchFailureKind::ListenerIdentityMismatch,
                "Science listener 健康或 runtime 身份不一致",
                ScienceEnvironmentExposure::Exposed,
            ));
        }
        let ownership = if healthy.recheck_committed_receipt {
            Some(
                uncommitted_managed_science_launch_token(healthy.port, &healthy.runtime)
                    .ok_or_else(|| {
                        ScienceLaunchFailure::new(
                            ScienceLaunchFailureKind::OwnershipUnavailable,
                            "无法建立精确的未提交 Science 启动身份",
                            ScienceEnvironmentExposure::Exposed,
                        )
                    })?,
            )
        } else {
            None
        };
        Ok(ScienceVerifiedLaunch {
            runtime: healthy.runtime,
            port: healthy.port,
            ownership,
            recheck_committed_receipt: healthy.recheck_committed_receipt,
        })
    }

    pub(crate) fn commit_launch(
        verified: ScienceVerifiedLaunch,
    ) -> Result<ScienceLaunchReceipt, ScienceLaunchFailure> {
        Self::commit_launch_with_id(verified, None)
    }

    pub(crate) fn commit_launch_with_launch_id(
        verified: ScienceVerifiedLaunch,
        launch_id: &str,
    ) -> Result<ScienceLaunchReceipt, ScienceLaunchFailure> {
        Self::commit_launch_with_id(verified, Some(launch_id))
    }

    pub(crate) fn commit_launch_with_authority_bypass(
        verified: ScienceVerifiedLaunch,
        bypass: &crate::config::AuthorityWriterBypass<'_>,
    ) -> Result<ScienceLaunchReceipt, ScienceLaunchFailure> {
        Self::commit_launch_with_id_and_authority_bypass(verified, None, bypass)
    }

    pub(crate) fn commit_launch_with_launch_id_and_authority_bypass(
        verified: ScienceVerifiedLaunch,
        launch_id: &str,
        bypass: &crate::config::AuthorityWriterBypass<'_>,
    ) -> Result<ScienceLaunchReceipt, ScienceLaunchFailure> {
        Self::commit_launch_with_id_and_authority_bypass(verified, Some(launch_id), bypass)
    }

    fn commit_launch_with_id(
        verified: ScienceVerifiedLaunch,
        launch_id: Option<&str>,
    ) -> Result<ScienceLaunchReceipt, ScienceLaunchFailure> {
        Self::commit_launch_with_id_inner(verified, launch_id, None)
    }

    fn commit_launch_with_id_and_authority_bypass(
        verified: ScienceVerifiedLaunch,
        launch_id: Option<&str>,
        bypass: &crate::config::AuthorityWriterBypass<'_>,
    ) -> Result<ScienceLaunchReceipt, ScienceLaunchFailure> {
        Self::commit_launch_with_id_inner(verified, launch_id, Some(bypass))
    }

    fn commit_launch_with_id_inner(
        verified: ScienceVerifiedLaunch,
        launch_id: Option<&str>,
        bypass: Option<&crate::config::AuthorityWriterBypass<'_>>,
    ) -> Result<ScienceLaunchReceipt, ScienceLaunchFailure> {
        let ownership = match launch_id {
            Some(launch_id) => match bypass {
                Some(bypass) => record_managed_science_launch_with_launch_id_and_authority_bypass(
                    verified.port,
                    &verified.runtime,
                    launch_id,
                    bypass,
                ),
                None => record_managed_science_launch_with_launch_id(
                    verified.port,
                    &verified.runtime,
                    launch_id,
                ),
            },
            None => match bypass {
                Some(bypass) => record_managed_science_launch_with_authority_bypass(
                    verified.port,
                    &verified.runtime,
                    bypass,
                ),
                None => record_managed_science_launch(verified.port, &verified.runtime),
            },
        }
        .map_err(|error| {
            ScienceLaunchFailure::new(
                ScienceLaunchFailureKind::ReceiptCommitFailed,
                error.message().to_string(),
                ScienceEnvironmentExposure::Exposed,
            )
            .with_ownership(error.token().cloned())
        })?;
        let mut runtime = verified.runtime;
        if hydrate_runtime_adoption_from_managed_launch(&ownership, &mut runtime).is_err() {
            return Err(ScienceLaunchFailure::new(
                ScienceLaunchFailureKind::ReceiptIdentityDrift,
                "fresh managed receipt adoption provenance 回读不一致",
                ScienceEnvironmentExposure::Exposed,
            )
            .with_ownership(Some(ownership)));
        }
        if verified.recheck_committed_receipt
            && !managed_launch_token_is_current_for_runtime(&ownership, &runtime)
        {
            return Err(ScienceLaunchFailure::new(
                ScienceLaunchFailureKind::ReceiptIdentityDrift,
                "fresh managed receipt 回读不一致",
                ScienceEnvironmentExposure::Exposed,
            )
            .with_ownership(Some(ownership)));
        }
        Ok(ScienceLaunchReceipt { ownership, runtime })
    }

    pub(crate) fn probe_known(port: u16, runtime: &ScienceRuntimeIdentity) -> SandboxScienceState {
        probe_known_runtime(port, runtime)
    }

    pub(crate) fn prove_managed_healthy(
        port: u16,
        runtime: &ScienceRuntimeIdentity,
    ) -> Option<ScienceManagedHealthyProof> {
        let ownership = Self::managed_receipt(port, runtime)?;
        if !Self::receipt_is_current(&ownership, runtime)
            || Self::probe_known(port, runtime) != SandboxScienceState::RunningHealthy
            || !Self::receipt_is_current(&ownership, runtime)
        {
            return None;
        }
        Some(ScienceManagedHealthyProof {
            runtime: runtime.clone(),
            port,
            ownership,
        })
    }

    pub(crate) fn revalidate_managed_healthy(proof: &ScienceManagedHealthyProof) -> bool {
        proof.runtime.is_current()
            && Self::receipt_is_current(&proof.ownership, &proof.runtime)
            && Self::probe_known(proof.port, &proof.runtime) == SandboxScienceState::RunningHealthy
            && Self::receipt_is_current(&proof.ownership, &proof.runtime)
    }

    pub(crate) fn probe_cached(
        port: u16,
        version_cache: &ScienceVersionCache,
    ) -> Result<(SandboxScienceState, Option<ScienceRuntimeIdentity>), String> {
        probe_sandbox_runtime_cached(port, version_cache)
    }

    pub(crate) fn listener_matches(port: u16, runtime: &ScienceRuntimeIdentity) -> bool {
        sandbox_listener_matches_runtime(port, runtime)
    }

    pub(crate) fn url(port: u16, runtime: &ScienceRuntimeIdentity) -> String {
        sandbox_url(port, runtime)
    }

    pub(crate) fn managed_receipt(
        port: u16,
        runtime: &ScienceRuntimeIdentity,
    ) -> Option<ScienceManagedLaunchToken> {
        managed_launch_token_for_runtime(port, runtime)
    }

    pub(crate) fn receipt_is_current(
        ownership: &ScienceManagedLaunchToken,
        runtime: &ScienceRuntimeIdentity,
    ) -> bool {
        managed_launch_token_is_current_for_runtime(ownership, runtime)
    }

    pub(crate) fn receipt_process_is_alive(ownership: &ScienceManagedLaunchToken) -> bool {
        managed_launch_token_process_is_alive(ownership)
    }

    pub(crate) fn claim_stop(
        runtime: Option<&ScienceRuntimeIdentity>,
    ) -> Result<ScienceStopRequest, ScienceStopFailure> {
        claim_science_stop_request(runtime)
    }

    pub(crate) fn execute_stop<R: Runtime>(
        app: &tauri::AppHandle<R>,
        request: ScienceStopRequest,
    ) -> ScienceStopExecution {
        execute_science_stop(app, request)
    }

    pub(crate) fn execute_stop_with_authority_bypass<R: Runtime>(
        app: &tauri::AppHandle<R>,
        request: ScienceStopRequest,
        bypass: &crate::config::AuthorityWriterBypass<'_>,
    ) -> ScienceStopExecution {
        execute_science_stop_with_authority_bypass(app, request, bypass)
    }

    pub(crate) fn stop<R: Runtime>(
        app: &tauri::AppHandle<R>,
        sandbox: &mut Option<Child>,
        sandbox_url: &mut Option<String>,
        request: ScienceStopRequest,
    ) -> ScienceStopOutcome {
        stop_sandbox(app, sandbox, sandbox_url, request)
    }

    pub(crate) fn stop_with_authority_bypass<R: Runtime>(
        app: &tauri::AppHandle<R>,
        sandbox: &mut Option<Child>,
        sandbox_url: &mut Option<String>,
        request: ScienceStopRequest,
        bypass: &crate::config::AuthorityWriterBypass<'_>,
    ) -> ScienceStopOutcome {
        let execution = execute_science_stop_with_authority_bypass(app, request, bypass);
        let (outcome, clear_process_tracking) = execution.into_parts();
        if clear_process_tracking {
            kill_child(sandbox);
            *sandbox_url = None;
        }
        outcome
    }
}

#[cfg(test)]
mod launch_failure_tests {
    use super::*;

    #[test]
    fn script_failure_preserves_stable_kind_and_exit_code() {
        let status = Command::new("/bin/sh")
            .args(["-c", "exit 70"])
            .status()
            .expect("test shell must run");
        let failure = launch_script_failure(&status, ScienceEnvironmentExposure::Exposed);
        assert_eq!(failure.kind().as_str(), "script_failed");
        assert_eq!(failure.exit_code(), Some(70));
        assert_eq!(failure.environment(), ScienceEnvironmentExposure::Exposed);
        assert!(failure.message().contains("Some(70)"));
    }
}
