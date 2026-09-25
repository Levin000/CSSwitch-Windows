#[cfg(test)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::time::{Duration, Instant};

use csswitch_skill_install_core::{open_science_health_session_before, ScienceHealthSession};
use serde_json::{json, Value};
use tauri::{Manager, Runtime};

use crate::runtime::failure::{OneClickFailureKind, ProjectedRecovery, TypedOneClickFailure};
use crate::runtime::operation::{
    self, OperationKind, OperationStage, OperationTrace, POLL_INTERVAL_MS,
};
use crate::runtime::proxy::ProxyAction;
use crate::runtime::proxy_lifecycle::{
    current_skill_install_bridge_key, skill_install_bridge_dir, GatewayController,
};
use crate::runtime::science::{
    mark_science_runtime_adoption_finalized, reconcile_current_science_runtime_adoption,
    sandbox_home, select_science_runtime_cached, SandboxScienceState, ScienceEnvironmentExposure,
    ScienceHostAdapter, ScienceLaunchFailureKind, ScienceLaunchSpec, ScienceManagedLaunchToken,
    ScienceRuntimeIdentity, ScienceRuntimeSource, ScienceStopFailureKind,
    ScienceStopOwnershipReceipt, ScienceStopRequest,
};
use crate::runtime::skill_install_bridge::{
    inspect_while_science_running, register_before_science_start, RegistrationStatus,
};
use crate::runtime::system::{asset_root, log_path, open_in_browser, open_log, redact, tail_file};
use crate::{
    config, lifecycle, lock, oauth_forge, proc, HistoryRecoveryChoice,
    HistoryRecoveryScienceQuiescence, HistoryRecoverySession, SharedAppState,
};

// Sibling modules are owned by the sandbox_session facade.
#[cfg(test)]
use super::authority_snapshot::SANDBOX_SESSION_TEST_SEAMS;
use super::authority_transaction::AuthorityTransaction;
use super::catalog_verify::*;
use super::pending_cleanup::{
    cleanup_required_error, replay_compensation_snapshot_cleanup,
    replay_finalize_authority_cleanup, retry_pending_authority_cleanup, AuthorityCleanupFailure,
    AuthorityCleanupPhase, PendingCleanupRetryOutcome,
};
use super::recovery::{read_registered_private_manifest, AppAuthoritySnapshot};
use super::route_reconcile::configure_third_party_best_effort;
use super::ssh_preflight::*;
use super::transaction_science_stop::{
    execute_transaction_science_stop_with, TransactionScienceStopBoundary,
    TransactionScienceStopTarget,
};

mod cold;
mod compensation_replay;
mod healthy_reopen;
mod transaction;

use compensation_replay::persist_compensation_replay_manifest;
pub(super) use compensation_replay::replay_interrupted_one_click_compensation;
pub(super) use transaction::{
    admit_healthy_reopen_gateway_rollback, begin_healthy_reopen_gateway_intent,
    begin_one_click_compensation_step, begin_one_click_finalize, begin_prior_stop_intent,
    commit_healthy_reopen_binding, complete_healthy_reopen_gateway_rollback,
    complete_one_click_finalize, finish_one_click_authority_restore_step,
    finish_one_click_compensation, finish_one_click_compensation_step, publish_prior_stop_outcome,
    resolve_gateway_terminal_handoff, write_one_click_checkpoint, OneClickJournalProgress,
    OneClickTransactionIdentity,
};
#[cfg(test)]
pub(super) use transaction::{
    begin_one_click_compensation, clear_one_click_transaction, commit_runtime_binding,
    one_click_phase_exposure,
};
use transaction::{
    begin_one_click_compensation_with_id, clear_prior_stop_transition, config_authority_matches,
};
#[cfg(test)]
pub(super) fn test_replay_prior_restart_effect_without_outcome<R: Runtime>(
    app: &tauri::AppHandle<R>,
    state: &SharedAppState,
    lifecycle: &lifecycle::Lifecycle,
) -> Result<config::RuntimeCompensationStepState, String> {
    compensation_replay::test_replay_prior_restart_effect_without_outcome(app, state, lifecycle)
}

#[cfg(test)]
pub(super) use cold::{
    CompensationCause, CompensationEnvironment, CompensationOutcome, CompensationSkipCause,
    CompensationStepOutcome,
};

use healthy_reopen::healthy_reopen_with_gateway_rollback;

pub(super) fn runtime_environment_fingerprint_changed(
    prior_runtime_fingerprint: Option<&str>,
    launch_runtime_fingerprint: &str,
) -> bool {
    prior_runtime_fingerprint.is_some_and(|fingerprint| fingerprint != launch_runtime_fingerprint)
}

#[derive(Clone, PartialEq)]
struct OneClickGatewayPreflightSnapshot {
    child_pid: u32,
    proxy_port: u16,
    secret: String,
    provider: String,
    gateway_kind: String,
    shim_mode: String,
    launch_id: String,
    key_fp: u64,
    launch_context: crate::runtime::proxy_lifecycle::GatewayLaunchRecipe,
}

impl OneClickGatewayPreflightSnapshot {
    fn capture(state: &SharedAppState) -> Result<Option<Self>, String> {
        let mut current = lock(state);
        let Some(child) = current.proxy.as_mut() else {
            return Ok(None);
        };
        if child
            .try_wait()
            .map_err(|_| {
                "gateway_identity_retry：无法确认先前 Gateway child 状态，请重试。".to_string()
            })?
            .is_some()
        {
            return Err(
                "gateway_identity_retry：先前 Gateway child 已退出，请先恢复运行态后重试。".into(),
            );
        }
        let child_pid = child.id();
        let launch_context = current.gateway_launch_context.clone().ok_or(
            "gateway_identity_retry：先前 Gateway 缺少完整启动上下文，请先恢复运行态后重试。",
        )?;
        Ok(Some(Self {
            child_pid,
            proxy_port: current.proxy_port,
            secret: current.secret.clone(),
            provider: current.provider.clone(),
            gateway_kind: current.gateway_kind.clone(),
            shim_mode: current.shim_mode.clone(),
            launch_id: current.launch_id.clone(),
            key_fp: current.key_fp,
            launch_context,
        }))
    }

    fn needs_codex_proof(&self) -> Result<bool, String> {
        Ok(
            crate::runtime::provider::resolve_launch_plan(&self.launch_context.profile)?.adapter
                == "codex",
        )
    }

    fn verify_unchanged(&self, state: &SharedAppState) -> Result<(), String> {
        let mut current = lock(state);
        let child_matches = match current.proxy.as_mut() {
            Some(child) if child.id() == self.child_pid => child
                .try_wait()
                .map_err(|_| {
                    "gateway_identity_retry：无法复核先前 Gateway child 状态，请重试。".to_string()
                })?
                .is_none(),
            _ => false,
        };
        let exact_context = child_matches
            && current.proxy_port == self.proxy_port
            && current.secret == self.secret
            && current.provider == self.provider
            && current.gateway_kind == self.gateway_kind
            && current.shim_mode == self.shim_mode
            && current.launch_id == self.launch_id
            && current.key_fp == self.key_fp
            && current.gateway_launch_context.as_ref() == Some(&self.launch_context);
        if exact_context {
            Ok(())
        } else {
            Err(
                "gateway_context_changed_retry：先前 Gateway 身份或完整启动上下文在认证检查期间发生变化，请重试。"
                    .into(),
            )
        }
    }
}

/// Immutable command-to-runtime proof used only to keep lock-free auth preflight
/// outside the destructive lease. Runtime entry owns capture and verification.
pub(crate) struct OneClickEntryPreflight {
    config: Option<config::Config>,
    runtime_transaction: Option<config::RuntimeTransactionRecord>,
    runtime_compensation: Option<config::RuntimeCompensationJournal>,
    prior_gateway: Option<OneClickGatewayPreflightSnapshot>,
    auth_adapter: String,
}

fn typed_runtime_effect_admission_error(error: std::io::Error) -> TypedOneClickFailure {
    let detail = error.to_string();
    let kind = if detail.contains("code=codex_disable_operation_in_progress")
        || detail.contains("code=config_mutation_operation_in_progress")
    {
        OneClickFailureKind::Prepare
    } else {
        OneClickFailureKind::ConfigLoad
    };
    typed_one_click_err(kind, detail)
}

impl OneClickEntryPreflight {
    pub(crate) fn capture(state: &SharedAppState) -> Result<Self, TypedOneClickFailure> {
        Self::capture_at(&config::default_dir(), state)
    }

    pub(crate) fn capture_at(
        dir: &Path,
        state: &SharedAppState,
    ) -> Result<Self, TypedOneClickFailure> {
        let cfg = config::load_for_runtime_effect_admission(dir)
            .map_err(typed_runtime_effect_admission_error)?;
        let active = cfg.active_profile().ok_or_else(|| {
            typed_one_click_err(
                OneClickFailureKind::NoActiveProfile,
                "未配置生效 profile，请先在面板选择或新建一条配置。",
            )
        })?;
        let adapter = crate::runtime::provider::resolve_launch_plan(active)
            .map_err(|message| typed_one_click_err(OneClickFailureKind::LaunchPlan, message))?
            .adapter;
        let prior_gateway =
            OneClickGatewayPreflightSnapshot::capture(state).map_err(|message| {
                typed_one_click_err(OneClickFailureKind::PreflightSnapshot, message)
            })?;
        let needs_codex_proof = adapter == "codex"
            || prior_gateway
                .as_ref()
                .map(OneClickGatewayPreflightSnapshot::needs_codex_proof)
                .transpose()
                .map_err(|message| {
                    typed_one_click_err(OneClickFailureKind::PreflightSnapshot, message)
                })?
                .unwrap_or(false);
        Ok(Self {
            runtime_transaction: cfg.runtime_transaction.clone(),
            runtime_compensation: cfg.runtime_compensation.clone(),
            config: (adapter != "codex").then_some(cfg),
            prior_gateway,
            auth_adapter: if needs_codex_proof {
                "codex".into()
            } else {
                adapter
            },
        })
    }

    pub(crate) fn auth_adapter(&self) -> &str {
        &self.auth_adapter
    }

    pub(crate) fn verify_unchanged(
        &self,
        state: &SharedAppState,
    ) -> Result<(), TypedOneClickFailure> {
        self.verify_unchanged_at(&config::default_dir(), state)
    }

    pub(crate) fn verify_unchanged_at(
        &self,
        dir: &Path,
        state: &SharedAppState,
    ) -> Result<(), TypedOneClickFailure> {
        let current =
            config::load_for_runtime_effect_admission(dir).map_err(|error| {
                typed_one_click_err(
                    OneClickFailureKind::PreflightSnapshot,
                    format!(
                        "config_changed_retry：无法复核 P2-A/P2-B runtime mutation admission，请重试：{error}"
                    ),
                )
            })?;
        if let Some(expected) = self.config.as_ref() {
            if &current != expected {
                return Err(typed_one_click_err(
                    OneClickFailureKind::PreflightSnapshot,
                    "config_changed_retry：候选启动配置在认证检查期间发生变化，请重试。",
                ));
            }
        } else {
            if current.runtime_transaction != self.runtime_transaction
                || current.runtime_compensation != self.runtime_compensation
            {
                return Err(typed_one_click_err(
                    OneClickFailureKind::PreflightSnapshot,
                    "config_changed_retry：runtime transaction 在认证检查期间发生变化，请重试。",
                ));
            }
        }
        if let Some(expected) = self.prior_gateway.as_ref() {
            expected.verify_unchanged(state).map_err(|message| {
                typed_one_click_err(OneClickFailureKind::PreflightSnapshot, message)
            })?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum OneClickEntryRecoveryDecision {
    ReplayFinalize,
    ReplayFinalizeCleanup,
    RecoverGateway,
    Route,
}

pub(super) fn decide_one_click_entry_recovery(
    finalize_pending: bool,
    finalize_replayed: bool,
    finalize_cleanup_replayed: bool,
    gateway_recovery_complete: bool,
) -> OneClickEntryRecoveryDecision {
    if finalize_pending {
        OneClickEntryRecoveryDecision::ReplayFinalize
    } else if finalize_replayed && !finalize_cleanup_replayed {
        OneClickEntryRecoveryDecision::ReplayFinalizeCleanup
    } else if !gateway_recovery_complete {
        OneClickEntryRecoveryDecision::RecoverGateway
    } else {
        OneClickEntryRecoveryDecision::Route
    }
}

fn one_click_finalize_pending(cfg: &config::Config) -> bool {
    cfg.runtime_transaction.as_ref().is_some_and(|record| {
        matches!(
            record,
            config::RuntimeTransactionRecord::V2(transaction)
                if transaction.finalize != config::RuntimeFinalizeState::NotStarted
        )
    })
}

fn history_resume_handoff(cfg: &config::Config) -> Option<config::RuntimeTransactionV2> {
    match cfg.runtime_transaction.as_ref() {
        Some(config::RuntimeTransactionRecord::V2(record))
            if record.operation == config::RuntimeTransactionOperation::HistoryRecovery
                && record.phase == config::RuntimeTransactionPhase::ResumeAfterHistoryRestore
                && record.snapshot_ticket.is_none()
                && record.finalize == config::RuntimeFinalizeState::NotStarted
                && record.target_profile_id == cfg.active_id
                && record.previous_binding.as_ref() == cfg.runtime_binding.as_ref() =>
        {
            super::history_recovery::history_config_authority_matches(cfg, record)
                .then(|| record.clone())
        }
        _ => None,
    }
}

pub(super) fn pending_cleanup_requires_recapture(outcome: PendingCleanupRetryOutcome) -> bool {
    outcome == PendingCleanupRetryOutcome::Cleared
}

pub(crate) fn typed_interrupted_gateway_recovery_error(
    error: crate::runtime::proxy_lifecycle::InterruptedGatewayRecoveryError,
) -> TypedOneClickFailure {
    use crate::runtime::proxy_lifecycle::{
        InterruptedGatewayRecoveryDisposition, InterruptedGatewayRecoveryErrorKind,
    };

    let kind = match error.kind() {
        InterruptedGatewayRecoveryErrorKind::AuthoritySnapshot => {
            OneClickFailureKind::AuthoritySnapshot
        }
        InterruptedGatewayRecoveryErrorKind::GatewayStart
        | InterruptedGatewayRecoveryErrorKind::NotManaged
        | InterruptedGatewayRecoveryErrorKind::StopUnknown(_) => OneClickFailureKind::GatewayStart,
    };
    let recovery = match error.recovery() {
        InterruptedGatewayRecoveryDisposition::Degraded => ProjectedRecovery::DEGRADED,
        InterruptedGatewayRecoveryDisposition::ManualRecoveryRequired => {
            ProjectedRecovery::MANUAL_RECOVERY_REQUIRED
        }
    };
    TypedOneClickFailure::new(kind, error.to_string()).with_recovery(recovery)
}

fn open_science_surface<R: Runtime>(
    app: &tauri::AppHandle<R>,
    url: &str,
) -> Result<&'static str, String> {
    if std::env::var("CSSWITCH_SCIENCE_WEBVIEW_SPIKE")
        .ok()
        .as_deref()
        == Some("1")
    {
        if let Some(win) = app.get_webview_window("science") {
            let _ = win.close();
        }
        let parsed = url
            .parse()
            .map_err(|e| format!("Science URL 解析失败：{e}"))?;
        match tauri::WebviewWindowBuilder::new(app, "science", tauri::WebviewUrl::External(parsed))
            .title("Claude Science")
            .inner_size(1100.0, 800.0)
            .build()
        {
            Ok(win) => {
                let _ = win.set_focus();
                return Ok("webview");
            }
            Err(_) => {
                // Spike-only path: construction failure falls through to the existing browser surface.
            }
        }
    }
    open_in_browser(url)?;
    Ok("browser")
}

fn installer_status_json(status: &RegistrationStatus) -> Value {
    match status {
        RegistrationStatus::Warning(message) => {
            json!({"status": status.code(), "message": message})
        }
        _ => json!({"status": status.code()}),
    }
}

fn append_installer_note(mut message: String, status: &RegistrationStatus) -> String {
    if let Some(note) = status.user_note() {
        message.push_str(&format!(" {note}"));
    }
    message
}

/// One-click session startup: active proxy, virtual login, sandbox, browser.
///
/// Callers must hold the command serializer lock.
#[cfg(test)]
pub(crate) fn one_click_login<R: Runtime>(
    app: tauri::AppHandle<R>,
    state: SharedAppState,
    lifecycle: &lifecycle::Lifecycle,
    runtime_choice: Option<&str>,
    auth_proof: Option<&crate::codex_auth_supervisor::CodexAuthReadyProof>,
) -> Result<Value, TypedOneClickFailure> {
    one_click_login_with_options(
        app,
        state,
        lifecycle,
        runtime_choice,
        auth_proof,
        true,
        OneClickEntryProgress::initial(None),
    )
}

fn one_click_login_after_gateway_recovery<R: Runtime>(
    app: tauri::AppHandle<R>,
    state: SharedAppState,
    lifecycle: &lifecycle::Lifecycle,
    runtime_choice: Option<&str>,
    auth_proof: Option<&crate::codex_auth_supervisor::CodexAuthReadyProof>,
    recovery: crate::runtime::proxy_lifecycle::InterruptedGatewayRecoveryOutcome,
) -> Result<Value, TypedOneClickFailure> {
    let terminal = recovery.into_terminal_record();
    one_click_login_with_options(
        app,
        state,
        lifecycle,
        runtime_choice,
        auth_proof,
        true,
        OneClickEntryProgress::initial(terminal.as_ref()),
    )
}

pub(super) fn one_click_login_after_history_handoff<R: Runtime>(
    app: tauri::AppHandle<R>,
    state: SharedAppState,
    lifecycle: &lifecycle::Lifecycle,
    runtime_choice: Option<&str>,
    auth_proof: Option<&crate::codex_auth_supervisor::CodexAuthReadyProof>,
    expected: config::RuntimeTransactionV2,
) -> Result<Value, TypedOneClickFailure> {
    let dir = config::default_dir();
    config::update_result(&dir, |current| {
        if history_resume_handoff(current).as_ref() != Some(&expected)
            || !super::history_recovery::history_config_authority_matches(current, &expected)
            || current.runtime_transaction.as_ref()
                != Some(&config::RuntimeTransactionRecord::V2(expected.clone()))
        {
            return Err(
                "history resume handoff disappeared, drifted, or retargeted; preserved current state"
                    .into(),
            );
        }
        current.runtime_transaction = None;
        Ok(((), true))
    })
    .map_err(|error| {
        TypedOneClickFailure::new(OneClickFailureKind::Prepare, error)
            .with_recovery(ProjectedRecovery::MANUAL_RECOVERY_REQUIRED)
    })?;
    one_click_login_entry(app, state, lifecycle, runtime_choice, auth_proof)
}

pub(crate) fn replay_interrupted_compensation_before_auth<R: Runtime>(
    app: &tauri::AppHandle<R>,
    state: &SharedAppState,
    lifecycle: &lifecycle::Lifecycle,
) -> Result<bool, String> {
    let cfg = config::load_from(&config::default_dir()).map_err(|error| error.to_string())?;
    replay_interrupted_one_click_compensation(app, state, lifecycle, None, &cfg)
}

pub(crate) fn interrupted_compensation_requires_pre_auth_replay() -> Result<bool, String> {
    config::load_from(&config::default_dir())
        .map(|cfg| cfg.runtime_compensation.is_some())
        .map_err(|error| error.to_string())
}

#[cfg(test)]
#[allow(
    clippy::too_many_arguments,
    reason = "test-only fixture exposes each durable compensation input explicitly so crash-replay tests cannot inherit hidden ambient state"
)]
pub(super) fn test_begin_replayable_compensation(
    dir: &Path,
    authority: &AuthorityTransaction,
    state: &SharedAppState,
    identity: &OneClickTransactionIdentity,
    progress: &mut OneClickJournalProgress,
    launch_runtime: ScienceRuntimeIdentity,
    ssh_stub_transaction: Option<crate::runtime::settings::ManagedSshStubTransaction>,
    prior_science_present: bool,
) -> Result<(), String> {
    let rollback = OneClickRollbackContext {
        proxy_action: ProxyAction::Reused,
        sandbox_port: config::load_from(dir)
            .map_err(|error| error.to_string())?
            .sandbox_port,
        launch_runtime,
        launch_token: None,
        launch_environment: ScienceEnvironmentExposure::NotExposed,
        launch_confirmed_stopped: false,
        candidate_stop_proof: ManagedScienceCandidateStopProof::NotRequired,
        ssh_stub_transaction,
        current_kind: OneClickFailureKind::Prepare,
    };
    let (compensation_id, science_adoption_attempt_ids) = persist_compensation_replay_manifest(
        authority,
        state,
        identity,
        &rollback,
        prior_science_present,
        progress,
    )?;
    begin_one_click_compensation_with_id(
        dir,
        identity,
        progress,
        authority.captured_runtime_transaction(),
        compensation_id,
        science_adoption_attempt_ids,
    )
}

/// Sole production one-click runtime entry owner. Recovery is an explicit
/// recapture/decide/effect loop; the affine Gateway handoff is consumed only
/// after the post-effect facts have been recaptured.
pub(crate) fn one_click_login_entry<R: Runtime>(
    app: tauri::AppHandle<R>,
    state: SharedAppState,
    lifecycle: &lifecycle::Lifecycle,
    runtime_choice: Option<&str>,
    auth_proof: Option<&crate::codex_auth_supervisor::CodexAuthReadyProof>,
) -> Result<Value, TypedOneClickFailure> {
    let mut finalize_replayed = false;
    let mut finalize_cleanup_replayed = false;
    let mut gateway_recovery = None;
    loop {
        let facts = config::load_for_runtime_effect_admission(&config::default_dir())
            .map_err(typed_runtime_effect_admission_error)?;
        if replay_interrupted_one_click_compensation(&app, &state, lifecycle, auth_proof, &facts)
            .map_err(|error| {
                TypedOneClickFailure::new(
                    OneClickFailureKind::AuthoritySnapshot,
                    format!(
                        "检测到未完成的 durable compensation，安全重放失败并已保留事务：{error}"
                    ),
                )
                .with_recovery(ProjectedRecovery::MANUAL_RECOVERY_REQUIRED)
            })?
        {
            continue;
        }
        if super::history_recovery::replay_interrupted_history_recovery(&state, &facts).map_err(
            |error| {
                TypedOneClickFailure::new(
                    OneClickFailureKind::AuthoritySnapshot,
                    format!("检测到未完成的 history recovery，安全重放失败并已保留事务：{error}"),
                )
                .with_recovery(ProjectedRecovery::MANUAL_RECOVERY_REQUIRED)
            },
        )? {
            continue;
        }
        if let Some(handoff) = history_resume_handoff(&facts) {
            return one_click_login_after_history_handoff(
                app,
                state,
                lifecycle,
                runtime_choice,
                auth_proof,
                handoff,
            );
        }
        match decide_one_click_entry_recovery(
            one_click_finalize_pending(&facts),
            finalize_replayed,
            finalize_cleanup_replayed,
            gateway_recovery.is_some(),
        ) {
            OneClickEntryRecoveryDecision::ReplayFinalize => {
                replay_interrupted_one_click_finalize(&state).map_err(|error| {
                    TypedOneClickFailure::new(
                        OneClickFailureKind::AuthoritySnapshot,
                        format!(
                            "检测到未完成的 success finalize，安全重放失败并已保留事务：{error}"
                        ),
                    )
                    .with_recovery(ProjectedRecovery::MANUAL_RECOVERY_REQUIRED)
                })?;
                finalize_replayed = true;
            }
            OneClickEntryRecoveryDecision::ReplayFinalizeCleanup => {
                retry_pending_authority_cleanup(&state).map_err(|failure| {
                    typed_authority_cleanup_err(
                        OneClickFailureKind::AuthoritySnapshot,
                        failure,
                        false,
                    )
                })?;
                finalize_cleanup_replayed = true;
            }
            OneClickEntryRecoveryDecision::RecoverGateway => {
                gateway_recovery = Some(
                    crate::runtime::proxy_lifecycle::recover_interrupted_gateway(&app, &state)
                        .map_err(typed_interrupted_gateway_recovery_error)?,
                );
            }
            OneClickEntryRecoveryDecision::Route => {
                let recovery = gateway_recovery.ok_or_else(|| {
                    typed_one_click_err(
                        OneClickFailureKind::GatewayStart,
                        "runtime entry lost the typed Gateway recovery outcome",
                    )
                })?;
                return one_click_login_after_gateway_recovery(
                    app,
                    state,
                    lifecycle,
                    runtime_choice,
                    auth_proof,
                    recovery,
                );
            }
        }
    }
}

fn typed_one_click_err(
    kind: OneClickFailureKind,
    message: impl Into<String>,
) -> TypedOneClickFailure {
    TypedOneClickFailure::new(kind, message)
}

#[derive(Debug)]
pub(super) struct InterruptedScienceRecoveryError {
    safe_detail: &'static str,
    recovery: ProjectedRecovery,
}

impl InterruptedScienceRecoveryError {
    fn new(safe_detail: &'static str, recovery: ProjectedRecovery) -> Self {
        Self {
            safe_detail,
            recovery,
        }
    }

    #[allow(dead_code)]
    pub(super) fn projected_recovery(&self) -> ProjectedRecovery {
        self.recovery
    }
}

impl std::fmt::Display for InterruptedScienceRecoveryError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.safe_detail)
    }
}

fn typed_interrupted_science_err(
    kind: OneClickFailureKind,
    error: InterruptedScienceRecoveryError,
) -> TypedOneClickFailure {
    TypedOneClickFailure::new(kind, error.safe_detail).with_recovery(error.recovery)
}

fn typed_authority_cleanup_err(
    kind: OneClickFailureKind,
    failure: AuthorityCleanupFailure,
    environment_uncertain: bool,
) -> TypedOneClickFailure {
    let cleanup_required = failure.cleanup_requirement().is_some();
    let phase = failure.phase();
    let message = failure.to_string();
    let recovery = if cleanup_required && environment_uncertain {
        ProjectedRecovery::cleanup_required_uncertain()
    } else if cleanup_required {
        ProjectedRecovery::CLEANUP_REQUIRED
    } else if environment_uncertain {
        ProjectedRecovery::ENVIRONMENT_UNCERTAIN
    } else {
        ProjectedRecovery::NOT_NEEDED
    };
    TypedOneClickFailure::new(kind, message)
        .with_recovery(recovery)
        .with_safe_cause(phase.cause_code(), "authority cleanup typed failure")
}

pub(super) fn validate_interrupted_science_transaction_entry(
    environment_state: Option<config::RuntimeTransactionV1EnvironmentState<'_>>,
) -> Result<(), InterruptedScienceRecoveryError> {
    if environment_state
        .is_some_and(config::RuntimeTransactionV1EnvironmentState::is_authority_snapshot_active)
    {
        return Err(InterruptedScienceRecoveryError::new(
            "检测到 authority 快照已登记但受保护状态写入未完成；已保留恢复快照并拒绝把部分写入态作为新基线；recovery_status=manual_recovery_required",
            ProjectedRecovery::MANUAL_RECOVERY_REQUIRED,
        ));
    }
    Ok(())
}

fn validate_interrupted_science_environment_runtime(
    expected_runtime_id: Option<&str>,
    runtime: &ScienceRuntimeIdentity,
) -> Result<(), InterruptedScienceRecoveryError> {
    let Some(expected_runtime_id) = expected_runtime_id else {
        return Ok(());
    };
    if runtime.environment_transaction_id() == expected_runtime_id {
        Ok(())
    } else {
        Err(InterruptedScienceRecoveryError::new(
            "上次启动在 Science 环境暴露边界中断，当前 executable 与中断事务不一致；已拒绝自动启动旧版或其他 runtime；environment_uncertain；newer_runtime_required；recovery_status=manual_recovery_required",
            ProjectedRecovery::environment_uncertain_manual(),
        ))
    }
}

#[derive(Clone)]
struct OneClickRollbackContext {
    proxy_action: ProxyAction,
    sandbox_port: u16,
    launch_runtime: ScienceRuntimeIdentity,
    launch_token: Option<ScienceManagedLaunchToken>,
    launch_environment: ScienceEnvironmentExposure,
    launch_confirmed_stopped: bool,
    candidate_stop_proof: ManagedScienceCandidateStopProof,
    ssh_stub_transaction: Option<crate::runtime::settings::ManagedSshStubTransaction>,
    /// Produce-site failure kind for UI projection; updated at phase boundaries.
    current_kind: OneClickFailureKind,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum ManagedScienceCandidateStopProof {
    #[default]
    NotRequired,
    ConfirmedStopped,
    Unproven,
}

#[derive(Debug)]
pub(super) struct ManagedScienceRestartError {
    message: String,
    candidate_stop_proof: ManagedScienceCandidateStopProof,
    diagnostic: PriorScienceRestartDiagnostic,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PriorScienceRestartDiagnostic {
    Failed,
    #[cfg(test)]
    TestPostSpawnValidationFailed,
}

impl ManagedScienceRestartError {
    fn before_spawn(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            candidate_stop_proof: ManagedScienceCandidateStopProof::NotRequired,
            diagnostic: PriorScienceRestartDiagnostic::Failed,
        }
    }

    fn after_spawn_unproven(message: impl Into<String>) -> Self {
        Self {
            message: format!("{}；code=science_candidate_stop_unproven", message.into()),
            candidate_stop_proof: ManagedScienceCandidateStopProof::Unproven,
            diagnostic: PriorScienceRestartDiagnostic::Failed,
        }
    }

    #[allow(clippy::result_large_err)]
    fn after_exact_cleanup(
        message: impl Into<String>,
        expected_runtime: &ScienceRuntimeIdentity,
        cleanup: crate::runtime::science::ScienceStopOutcome,
    ) -> Self {
        match cleanup.and_then(|verified| verified.require_exact_stop_of(expected_runtime)) {
            Ok(_) => Self {
                message: message.into(),
                candidate_stop_proof: ManagedScienceCandidateStopProof::ConfirmedStopped,
                diagnostic: PriorScienceRestartDiagnostic::Failed,
            },
            Err(error) => {
                Self::after_spawn_unproven(format!("{}；candidate_cleanup={error}", message.into()))
            }
        }
    }

    #[cfg(test)]
    fn test_post_spawn_validation(
        expected_runtime: &ScienceRuntimeIdentity,
        cleanup: crate::runtime::science::ScienceStopOutcome,
    ) -> Self {
        let mut failure = Self::after_exact_cleanup(
            "test-only prior Science post-spawn validation failure",
            expected_runtime,
            cleanup,
        );
        failure.diagnostic = PriorScienceRestartDiagnostic::TestPostSpawnValidationFailed;
        failure
    }
}

impl std::fmt::Display for ManagedScienceRestartError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl From<String> for ManagedScienceRestartError {
    fn from(message: String) -> Self {
        Self::before_spawn(message)
    }
}

impl From<&str> for ManagedScienceRestartError {
    fn from(message: &str) -> Self {
        Self::before_spawn(message)
    }
}

struct OneClickFailure {
    typed: TypedOneClickFailure,
    rollback: OneClickRollbackContext,
}

impl OneClickFailure {
    fn message(&self) -> &str {
        &self.typed.safe_detail
    }
}

// Science 0.1.25 gives boot quick_check a 300s query timeout. Its own warning
// says the subsequently unblocked migration can take about 30 minutes, so the
// recovery restart has a separate finite ceiling instead of the ordinary 8s
// launch budget.
const SCIENCE_DB_REVERIFY_BUDGET_MS: u64 = 305_000;
const SCIENCE_DB_RECOVERY_RESTART_BUDGET_MS: u64 = 30 * 60 * 1_000 + 10_000;
// Windows 移植：守护进程冷启动要恢复 conda/MCP 预热（可达一两分钟），
// 20s 引导预算会耗尽；放宽到 120s。macOS 保持原值。
#[cfg(windows)]
const SCIENCE_HEALTH_BOOTSTRAP_BUDGET_MS: u64 = 120_000;
#[cfg(not(windows))]
const SCIENCE_HEALTH_BOOTSTRAP_BUDGET_MS: u64 = 20_000;

fn science_db_reverify_budget_ms() -> u64 {
    #[cfg(test)]
    if let Ok(value) = std::env::var("CSSWITCH_TEST_DB_REVERIFY_BUDGET_MS") {
        if let Ok(value) = value.parse::<u64>() {
            return value.max(POLL_INTERVAL_MS);
        }
    }
    SCIENCE_DB_REVERIFY_BUDGET_MS
}

fn science_db_recovery_restart_budget_ms() -> u64 {
    #[cfg(test)]
    if let Ok(value) = std::env::var("CSSWITCH_TEST_DB_RECOVERY_RESTART_BUDGET_MS") {
        if let Ok(value) = value.parse::<u64>() {
            return value.max(POLL_INTERVAL_MS);
        }
    }
    SCIENCE_DB_RECOVERY_RESTART_BUDGET_MS
}

fn open_authenticated_science_health_session(
    port: u16,
    runtime: &ScienceRuntimeIdentity,
    token: &ScienceManagedLaunchToken,
    deadline: Instant,
) -> Result<ScienceHealthSession, String> {
    if !ScienceHostAdapter::receipt_is_current(token, runtime) {
        return Err("science_db_listener_identity_changed".into());
    }
    let context = runtime
        .skill_install_host_context(port)
        .map_err(|_| "science_api_health_control_context_invalid".to_string())?;
    let session = open_science_health_session_before(&context, deadline)
        .map_err(science_health_control_error)?;
    if !ScienceHostAdapter::receipt_is_current(token, runtime) {
        return Err("science_db_listener_identity_changed".into());
    }
    Ok(session)
}

pub(super) fn science_health_control_error(
    error: csswitch_skill_install_core::AttachError,
) -> String {
    if error.retryable
        && matches!(
            error.code.as_str(),
            "SCIENCE_HEALTH_UNREACHABLE"
                | "SCIENCE_HEALTH_TIMEOUT"
                | "SCIENCE_CONTROL_TIMEOUT"
                | "SCIENCE_HEALTH_HTTP_STATUS"
        )
    {
        "science_api_health_unreachable".into()
    } else {
        format!(
            "science_api_health_control_failed code={} detail={}",
            error.code, error.message
        )
    }
}

fn authenticated_science_db_health(
    session: &ScienceHealthSession,
    timeout: Duration,
) -> Result<proc::ScienceDbHealth, String> {
    let body = session
        .read_health_with_timeout(timeout)
        .map_err(science_health_control_error)?;
    let body =
        std::str::from_utf8(&body).map_err(|_| "science_api_health_malformed".to_string())?;
    proc::science_db_health_from_body(body)
}

fn wait_for_science_db_reverify(
    port: u16,
    runtime: &ScienceRuntimeIdentity,
    token: &ScienceManagedLaunchToken,
) -> Result<proc::ScienceDbHealth, String> {
    let deadline = Instant::now() + Duration::from_millis(science_db_reverify_budget_ms());
    let bootstrap_deadline =
        deadline.min(Instant::now() + Duration::from_millis(SCIENCE_HEALTH_BOOTSTRAP_BUDGET_MS));
    let session = loop {
        let remaining = bootstrap_deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err("science_api_health_bootstrap_timeout".into());
        }
        match open_authenticated_science_health_session(port, runtime, token, bootstrap_deadline) {
            Ok(session) => break session,
            Err(error)
                if error == "science_api_health_unreachable"
                    && Instant::now() < bootstrap_deadline =>
            {
                std::thread::sleep(
                    Duration::from_millis(POLL_INTERVAL_MS)
                        .min(bootstrap_deadline.saturating_duration_since(Instant::now())),
                );
            }
            Err(error) => return Err(error),
        }
    };
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err("science_db_reverify_timeout".into());
        }
        if !ScienceHostAdapter::receipt_is_current(token, runtime) {
            return Err("science_db_listener_identity_changed".into());
        }
        match authenticated_science_db_health(&session, remaining.min(Duration::from_secs(5))) {
            Ok(state) => {
                if !ScienceHostAdapter::receipt_is_current(token, runtime) {
                    return Err("science_db_listener_identity_changed".into());
                }
                match state {
                    proc::ScienceDbHealth::ReverifyPending if Instant::now() < deadline => {
                        std::thread::sleep(
                            Duration::from_millis(POLL_INTERVAL_MS)
                                .min(deadline.saturating_duration_since(Instant::now())),
                        );
                    }
                    proc::ScienceDbHealth::ReverifyPending => {
                        return Err("science_db_reverify_timeout".into())
                    }
                    other => return Ok(other),
                }
            }
            Err(error)
                if matches!(
                    error.as_str(),
                    "science_api_health_unreachable" | "science_api_health_incomplete"
                ) && Instant::now() < deadline =>
            {
                std::thread::sleep(
                    Duration::from_millis(POLL_INTERVAL_MS)
                        .min(deadline.saturating_duration_since(Instant::now())),
                );
            }
            Err(error)
                if matches!(
                    error.as_str(),
                    "science_api_health_unreachable" | "science_api_health_incomplete"
                ) =>
            {
                return Err("science_db_reverify_timeout".into())
            }
            Err(error) => return Err(error),
        }
    }
}

#[derive(Clone)]
struct PriorScienceContext {
    runtime: ScienceRuntimeIdentity,
    port: u16,
    launch_token: ScienceManagedLaunchToken,
}

enum AuthorityCaptureAfterQuiesceError {
    PriorScienceRestored(String),
    RestartRequired(String),
}

impl OneClickRollbackContext {
    fn failure(&self, message: impl Into<String>) -> OneClickFailure {
        OneClickFailure {
            typed: TypedOneClickFailure::new(self.current_kind, message),
            rollback: self.clone(),
        }
    }

    fn set_kind(&mut self, kind: OneClickFailureKind) {
        self.current_kind = kind;
    }
}

#[allow(clippy::result_large_err)]
fn one_click_step<T, E: std::fmt::Display>(
    result: Result<T, E>,
    rollback: &OneClickRollbackContext,
) -> Result<T, OneClickFailure> {
    result.map_err(|error| rollback.failure(error.to_string()))
}

fn restart_prior_science<R: Runtime>(
    app: &tauri::AppHandle<R>,
    state: &SharedAppState,
    lifecycle: &lifecycle::Lifecycle,
    auth_proof: Option<&crate::codex_auth_supervisor::CodexAuthReadyProof>,
    prior: &PriorScienceContext,
    authority_bypass: Option<&config::AuthorityWriterBypass<'_>>,
) -> Result<(), ManagedScienceRestartError> {
    restart_science_identity_with_budget(
        app,
        state,
        lifecycle,
        auth_proof,
        &prior.runtime,
        prior.port,
        operation::SANDBOX_HEALTH_BUDGET_MS,
        None,
        authority_bypass,
    )
}

#[allow(clippy::too_many_arguments)]
fn restart_science_identity_with_budget<R: Runtime>(
    app: &tauri::AppHandle<R>,
    state: &SharedAppState,
    _lifecycle: &lifecycle::Lifecycle,
    _auth_proof: Option<&crate::codex_auth_supervisor::CodexAuthReadyProof>,
    runtime: &ScienceRuntimeIdentity,
    port: u16,
    health_budget_ms: u64,
    durable_launch_id: Option<&str>,
    authority_bypass: Option<&config::AuthorityWriterBypass<'_>>,
) -> Result<(), ManagedScienceRestartError> {
    let dir = config::default_dir();
    let cfg = config::load_from(&dir).map_err(|error| error.to_string())?;
    if cfg.sandbox_port != port {
        return Err("恢复 prior Science 时沙箱端口已变化".into());
    }
    if ScienceHostAdapter::validate_launch_runtime(runtime).is_err() {
        return Err("恢复 prior Science 时 runtime 身份已变化".into());
    }
    if proc::loopback_port_in_use(port, operation::LOCAL_HEALTH_TIMEOUT_MS) {
        return Err("恢复 prior Science 前端口仍被占用；拒绝接管未知 listener".into());
    }
    let (proxy_port, secret) = {
        let current = lock(state);
        if current.proxy.is_some() {
            (current.proxy_port, current.secret.clone())
        } else {
            (cfg.proxy_port, cfg.secret.clone())
        }
    };
    let ssh_hosts = if cfg.reuse_system_ssh {
        crate::runtime::ssh_bridge::validate_science_ssh_bridge(&sandbox_home())?
    } else {
        Vec::new()
    };
    let root = asset_root(app).ok_or("恢复 prior Science 时找不到打包资源")?;
    let launch = root.join("scripts/launch-virtual-sandbox.sh");
    if !launch.is_file() {
        return Err("恢复 prior Science 时启动脚本缺失".into());
    }
    let logf = open_log("sandbox.log").map_err(|error| error.to_string())?;
    let logf2 = logf.try_clone().map_err(|error| error.to_string())?;
    let proxy_url = format!("http://127.0.0.1:{proxy_port}/{secret}");
    let ssh_hosts = ssh_hosts.join(" ");
    let attempt = ScienceHostAdapter::spawn_launch(
        ScienceLaunchSpec::recovery(
            &launch,
            runtime,
            port,
            &proxy_url,
            cfg.reuse_system_ssh,
            &ssh_hosts,
            health_budget_ms,
            POLL_INTERVAL_MS,
            operation::LOCAL_HEALTH_TIMEOUT_MS,
        ),
        logf,
        logf2,
    )
    .map_err(|error| match error.kind() {
        ScienceLaunchFailureKind::RuntimeDrift | ScienceLaunchFailureKind::SpawnFailed => {
            ManagedScienceRestartError::before_spawn(format!(
                "恢复 prior Science 启动失败：{}",
                error.message()
            ))
        }
        _ => ManagedScienceRestartError::after_spawn_unproven(format!(
            "恢复 prior Science {}",
            error.message()
        )),
    })?;
    let attempt = ScienceHostAdapter::accept_launch_script(attempt).map_err(|error| {
        ManagedScienceRestartError::after_spawn_unproven(format!(
            "恢复 prior Science {}",
            error.message()
        ))
    })?;
    let healthy = ScienceHostAdapter::verify_health(attempt).map_err(|_| {
        ManagedScienceRestartError::after_spawn_unproven(
            "恢复 prior Science 后 listener 健康或 runtime 身份不一致",
        )
    })?;
    let verified =
        ScienceHostAdapter::verify_identity(healthy).map_err(|error| match error.kind() {
            ScienceLaunchFailureKind::OwnershipUnavailable => {
                ManagedScienceRestartError::after_spawn_unproven(
                    "恢复 prior Science 后无法建立精确的未提交启动身份",
                )
            }
            _ => ManagedScienceRestartError::after_spawn_unproven(
                "恢复 prior Science 后 listener 健康或 runtime 身份不一致",
            ),
        })?;
    let _candidate_token = verified
        .ownership()
        .expect("recovery launch must carry uncommitted ownership proof")
        .clone();
    #[cfg(test)]
    {
        let mut seams = SANDBOX_SESSION_TEST_SEAMS
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let post_spawn_failure = seams.prior_restart_post_spawn_failure_port == Some(port);
        let post_spawn_uncertain = seams.prior_restart_post_spawn_uncertain_port == Some(port);
        if post_spawn_failure || post_spawn_uncertain {
            let listener_pid = crate::runtime::science::test_unique_listener_pid(port)
                .ok_or("test-only prior Science listener identity missing after verification")?;
            let process_start =
                crate::runtime::science::test_process_start_identity_for_pid(listener_pid)
                    .ok_or("test-only prior Science process-start identity missing")?;
            seams.prior_restart_post_spawn_identity = Some((listener_pid, process_start));
            drop(seams);
            if post_spawn_uncertain {
                return Err(ManagedScienceRestartError::after_spawn_unproven(
                    "test-only prior Science post-spawn cleanup uncertainty",
                ));
            }
            let mut sandbox = None;
            let mut url = None;
            let request = ScienceStopRequest::exact(
                runtime,
                ScienceStopOwnershipReceipt::from_managed_launch(&_candidate_token),
            );
            let cleanup = match authority_bypass {
                Some(bypass) => ScienceHostAdapter::stop_with_authority_bypass(
                    app,
                    &mut sandbox,
                    &mut url,
                    request,
                    bypass,
                ),
                None => ScienceHostAdapter::stop(app, &mut sandbox, &mut url, request),
            };
            return Err(ManagedScienceRestartError::test_post_spawn_validation(
                runtime, cleanup,
            ));
        }
    }
    let committed_launch = match (durable_launch_id, authority_bypass) {
        (Some(launch_id), Some(bypass)) => {
            ScienceHostAdapter::commit_launch_with_launch_id_and_authority_bypass(
                verified, launch_id, bypass,
            )
        }
        (None, Some(bypass)) => {
            ScienceHostAdapter::commit_launch_with_authority_bypass(verified, bypass)
        }
        (Some(launch_id), None) => {
            ScienceHostAdapter::commit_launch_with_launch_id(verified, launch_id)
        }
        (None, None) => ScienceHostAdapter::commit_launch(verified),
    };
    let committed_runtime = match committed_launch {
        Ok(receipt) => receipt.runtime().clone(),
        Err(error) => {
            let mut sandbox = None;
            let mut url = None;
            let token_present = error.ownership().is_some();
            let request = error
                .ownership()
                .map(|token| {
                    ScienceStopRequest::exact(
                        runtime,
                        ScienceStopOwnershipReceipt::from_managed_launch(token),
                    )
                })
                .unwrap_or_else(|| ScienceStopRequest::recover(Some(runtime)));
            let cleanup = match authority_bypass {
                Some(bypass) => ScienceHostAdapter::stop_with_authority_bypass(
                    app,
                    &mut sandbox,
                    &mut url,
                    request,
                    bypass,
                ),
                None => ScienceHostAdapter::stop(app, &mut sandbox, &mut url, request),
            };
            let message = match error.kind() {
                ScienceLaunchFailureKind::ReceiptIdentityDrift => {
                    "恢复 prior Science 后 fresh managed receipt 回读不一致".to_string()
                }
                _ => format!(
                    "恢复 prior Science 时 fresh managed receipt 提交失败：{}",
                    error.message()
                ),
            };
            return Err(if token_present {
                ManagedScienceRestartError::after_exact_cleanup(message, runtime, cleanup)
            } else {
                ManagedScienceRestartError::after_spawn_unproven(message)
            });
        }
    };
    let url = ScienceHostAdapter::url(port, &committed_runtime);
    let mut current = lock(state);
    current.sandbox_port = port;
    current.sandbox_url = Some(url);
    current.science_runtime = Some(committed_runtime);
    current.science_confirmed_stopped = None;
    Ok(())
}

/// Shared managed-restart effect for the dedicated Codex-disable receipt.
/// This does not read or write a one-click/history journal; it only reuses the
/// existing ScienceHostAdapter launch/health/identity/managed-receipt phases.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DurableScienceRestoreError {
    Failed,
    Uncertain,
}

pub(crate) fn restore_science_from_durable_recipe<R: Runtime>(
    app: &tauri::AppHandle<R>,
    state: &SharedAppState,
    lifecycle: &lifecycle::Lifecycle,
    auth_proof: Option<&crate::codex_auth_supervisor::CodexAuthReadyProof>,
    recipe: &config::RuntimePriorScienceRecipe,
    durable_launch_id: &str,
) -> Result<(), DurableScienceRestoreError> {
    let mut runtime = crate::runtime::science::runtime_identity_from_prior_recipe(recipe)
        .map_err(|_| DurableScienceRestoreError::Failed)?;
    {
        let current = lock(state);
        if current.sandbox.is_some()
            || current
                .science_runtime
                .as_ref()
                .is_some_and(|candidate| candidate != &runtime)
            || current
                .science_confirmed_stopped
                .as_ref()
                .is_some_and(|candidate| candidate != &runtime)
        {
            return Err(DurableScienceRestoreError::Uncertain);
        }
    }
    if crate::runtime::science::hydrate_runtime_from_v2_managed_launch(
        recipe.port,
        &mut runtime,
        durable_launch_id,
    )
    .is_ok()
        && ScienceHostAdapter::probe_known(recipe.port, &runtime)
            == SandboxScienceState::RunningHealthy
    {
        let mut current = lock(state);
        if current.sandbox.is_some()
            || current
                .science_runtime
                .as_ref()
                .is_some_and(|candidate| candidate != &runtime)
        {
            return Err(DurableScienceRestoreError::Uncertain);
        }
        current.sandbox_port = recipe.port;
        current.sandbox_url = Some(ScienceHostAdapter::url(recipe.port, &runtime));
        current.science_runtime = Some(runtime);
        current.science_confirmed_stopped = None;
        return Ok(());
    }
    if proc::loopback_port_in_use(recipe.port, operation::LOCAL_HEALTH_TIMEOUT_MS)
        || !crate::runtime::science::prior_restart_receipt_is_absent(recipe, &runtime)
    {
        return Err(DurableScienceRestoreError::Uncertain);
    }
    restart_science_identity_with_budget(
        app,
        state,
        lifecycle,
        auth_proof,
        &runtime,
        recipe.port,
        operation::SANDBOX_HEALTH_BUDGET_MS,
        Some(durable_launch_id),
        None,
    )
    .map_err(|error| {
        if error.candidate_stop_proof == ManagedScienceCandidateStopProof::Unproven {
            DurableScienceRestoreError::Uncertain
        } else {
            DurableScienceRestoreError::Failed
        }
    })
}

#[allow(clippy::too_many_arguments)]
fn capture_authority_after_science_quiesce<R: Runtime>(
    app: &tauri::AppHandle<R>,
    state: &SharedAppState,
    lifecycle: &lifecycle::Lifecycle,
    auth_proof: Option<&crate::codex_auth_supervisor::CodexAuthReadyProof>,
    config_dir: &Path,
    sandbox_home: &Path,
    auth_dir: &Path,
    config: &config::Config,
    prior_science: Option<&PriorScienceContext>,
) -> Result<AuthorityTransaction, AuthorityCaptureAfterQuiesceError> {
    match AuthorityTransaction::capture(config_dir, sandbox_home, auth_dir, config, state) {
        Ok(snapshot) => Ok(snapshot),
        Err(capture_error) => {
            if let Some(prior) = prior_science {
                match restart_prior_science(app, state, lifecycle, auth_proof, prior, None) {
                    Ok(()) => Err(AuthorityCaptureAfterQuiesceError::PriorScienceRestored(
                        capture_error,
                    )),
                    Err(restart_error) => Err(AuthorityCaptureAfterQuiesceError::RestartRequired(
                        format!("{capture_error}；prior_science_restart={restart_error}"),
                    )),
                }
            } else {
                Err(AuthorityCaptureAfterQuiesceError::RestartRequired(
                    capture_error,
                ))
            }
        }
    }
}

fn preserve_interrupted_success_finalize(
    authority_transaction: &mut AuthorityTransaction,
    value: &mut Value,
) {
    authority_transaction.preserve_recovery();
    if let Some(object) = value.as_object_mut() {
        object.insert("status".into(), Value::String("degraded".into()));
        object.insert(
            "recovery_status".into(),
            Value::String("manual_recovery_required".into()),
        );
        object.insert(
            "cleanup_message".into(),
            Value::String(
                "启动已完成，但 success finalize 尚未持久化；下次一键操作会先安全重放。".into(),
            ),
        );
    }
}

struct OneClickEntryFacts {
    science_state: SandboxScienceState,
    running_runtime: Option<ScienceRuntimeIdentity>,
    selected_runtime: Option<ScienceRuntimeIdentity>,
    login_intact: bool,
    binding_matches: bool,
    remembered_runtime_was_present: bool,
}

enum OneClickEntryDecision {
    HealthyReopen {
        runtime: ScienceRuntimeIdentity,
    },
    Mutating {
        launch_runtime: ScienceRuntimeIdentity,
        running_runtime_to_stop: Option<ScienceRuntimeIdentity>,
        science_state: SandboxScienceState,
        remembered_runtime_was_present: bool,
    },
}

#[derive(Clone, Copy)]
struct OneClickEntryProgress<'a> {
    gateway_terminal_handoff: Option<&'a config::RuntimeTransactionV2>,
    cleanup_replayed: bool,
}

impl<'a> OneClickEntryProgress<'a> {
    fn initial(gateway_terminal_handoff: Option<&'a config::RuntimeTransactionV2>) -> Self {
        Self {
            gateway_terminal_handoff,
            cleanup_replayed: false,
        }
    }

    fn after_cleanup(self) -> Self {
        Self {
            cleanup_replayed: true,
            ..self
        }
    }
}

fn capture_one_click_entry_facts(
    state: &SharedAppState,
    cfg: &config::Config,
    active_profile: &config::Profile,
    auth_dir: &Path,
    runtime_choice: Option<&str>,
    interrupted_environment_runtime_id: Option<&str>,
) -> Result<OneClickEntryFacts, TypedOneClickFailure> {
    let version_cache = { lock(state).science_version_cache.clone() };
    let (remembered_runtime, confirmed_stopped) = {
        let current = lock(state);
        (
            current.science_runtime.clone(),
            current.science_confirmed_stopped.clone(),
        )
    };
    let remembered_runtime_was_present = remembered_runtime.is_some();
    let (science_state, running_runtime) = match remembered_runtime {
        Some(runtime) => {
            let observed = ScienceHostAdapter::probe_known(cfg.sandbox_port, &runtime);
            let running = (observed == SandboxScienceState::RunningHealthy).then_some(runtime);
            (observed, running)
        }
        None if confirmed_stopped
            .as_ref()
            .is_some_and(|runtime| runtime.source != ScienceRuntimeSource::CachedOnce)
            && !proc::loopback_port_in_use(cfg.sandbox_port, 100) =>
        {
            (SandboxScienceState::Stopped, None)
        }
        None => ScienceHostAdapter::probe_cached(cfg.sandbox_port, &version_cache)
            .map_err(|message| typed_one_click_err(OneClickFailureKind::ScienceStart, message))?,
    };

    let mut selected_runtime = None;
    let mut login_intact = false;
    let mut binding_matches = false;
    match science_state {
        SandboxScienceState::RunningHealthy => {
            let running = running_runtime.as_ref().ok_or_else(|| {
                typed_one_click_err(
                    OneClickFailureKind::ScienceStart,
                    "Science 状态为运行中，但无法确认其 binary 身份",
                )
            })?;
            validate_interrupted_science_environment_runtime(
                interrupted_environment_runtime_id,
                running,
            )
            .map_err(|error| typed_interrupted_science_err(OneClickFailureKind::Prepare, error))?;
            let desired_binding =
                crate::runtime::provider::desired_runtime_binding(cfg, active_profile, running)
                    .map_err(|message| {
                        typed_one_click_err(OneClickFailureKind::Prepare, message)
                    })?;
            binding_matches = !crate::runtime::provider::science_restart_required(
                cfg.runtime_binding.as_ref(),
                &desired_binding,
            );
            login_intact =
                oauth_forge::login_intact(auth_dir, "virtual@localhost.invalid", &sandbox_home());
            if !login_intact {
                selected_runtime = Some(
                    select_science_runtime_cached(runtime_choice, &version_cache).map_err(
                        |message| typed_one_click_err(OneClickFailureKind::ScienceStart, message),
                    )?,
                );
            }
        }
        SandboxScienceState::Stopped => {
            selected_runtime = Some(
                select_science_runtime_cached(runtime_choice, &version_cache).map_err(
                    |message| typed_one_click_err(OneClickFailureKind::ScienceStart, message),
                )?,
            );
        }
        SandboxScienceState::Unknown => {
            if interrupted_environment_runtime_id.is_some() {
                return Err(TypedOneClickFailure::new(
                    OneClickFailureKind::ScienceStart,
                    "上次启动在 Science 环境暴露边界中断，且当前 listener/runtime 身份无法确认；已拒绝自动恢复；environment_uncertain；recovery_status=manual_recovery_required",
                )
                .with_recovery(ProjectedRecovery::environment_uncertain_manual()));
            }
            let sandbox_port = cfg.sandbox_port;
            return Err(typed_one_click_err(
                OneClickFailureKind::ScienceStart,
                format!(
                    "无法确认隔离 Science 状态（端口 {sandbox_port} 或 data-dir 状态不一致）。请先停止占用该端口的进程后重试。"
                ),
            ));
        }
    }
    Ok(OneClickEntryFacts {
        science_state,
        running_runtime,
        selected_runtime,
        login_intact,
        binding_matches,
        remembered_runtime_was_present,
    })
}

fn decide_one_click_entry(
    facts: OneClickEntryFacts,
) -> Result<OneClickEntryDecision, TypedOneClickFailure> {
    if facts.science_state == SandboxScienceState::RunningHealthy
        && facts.login_intact
        && facts.binding_matches
    {
        let runtime = facts.running_runtime.ok_or_else(|| {
            typed_one_click_err(
                OneClickFailureKind::ScienceStart,
                "healthy entry facts lost the observed Science runtime",
            )
        })?;
        return Ok(OneClickEntryDecision::HealthyReopen { runtime });
    }
    let running_runtime_to_stop = facts.running_runtime.clone();
    let launch_runtime =
        if facts.science_state == SandboxScienceState::RunningHealthy && facts.login_intact {
            facts.running_runtime.ok_or_else(|| {
                typed_one_click_err(
                    OneClickFailureKind::ScienceStart,
                    "mutating entry facts lost the observed Science runtime",
                )
            })?
        } else {
            facts.selected_runtime.ok_or_else(|| {
                typed_one_click_err(
                    OneClickFailureKind::ScienceStart,
                    "mutating entry facts lost the selected Science runtime",
                )
            })?
        };
    Ok(OneClickEntryDecision::Mutating {
        launch_runtime,
        running_runtime_to_stop,
        science_state: facts.science_state,
        remembered_runtime_was_present: facts.remembered_runtime_was_present,
    })
}

pub(crate) fn replay_interrupted_one_click_finalize(state: &SharedAppState) -> Result<(), String> {
    let dir = config::default_dir();
    let cfg = config::load_from(&dir).map_err(|error| error.to_string())?;
    let Some(config::RuntimeTransactionRecord::V2(expected)) = cfg.runtime_transaction.as_ref()
    else {
        return Ok(());
    };
    let action = match &expected.finalize {
        config::RuntimeFinalizeState::NotStarted => return Ok(()),
        config::RuntimeFinalizeState::Intent { action } => action.clone(),
    };
    let replay_adoption_proof = if let config::RuntimeFinalizeAction::CommitBinding {
        binding,
        science_adoption_attempt_id,
    } = &action
    {
        if binding.science_adoption_attempt_id.as_deref() != science_adoption_attempt_id.as_deref()
        {
            return Err(
                "interrupted finalize binding/adoption provenance mismatch; preserved current state"
                    .into(),
            );
        }
        science_adoption_attempt_id
            .as_deref()
            .map(|attempt_id| prove_finalize_science_adoption_runtime(state, &cfg, attempt_id))
            .transpose()?
    } else {
        None
    };
    let initial_authority_matches =
        if expected.operation == config::RuntimeTransactionOperation::HistoryRecovery {
            super::history_recovery::history_config_authority_matches(&cfg, expected)
        } else {
            config_authority_matches(
                &cfg,
                &expected.target_profile_id,
                expected.previous_binding.as_ref(),
            )
        };
    if !initial_authority_matches {
        return Err("interrupted finalize intent no longer targets the active profile".into());
    }
    match (&expected.operation, &action) {
        (
            config::RuntimeTransactionOperation::OneClick,
            config::RuntimeFinalizeAction::CommitBinding { binding, .. },
        ) if binding.profile_id != expected.target_profile_id => {
            return Err("interrupted finalize binding no longer matches its target profile".into())
        }
        (
            config::RuntimeTransactionOperation::OneClick,
            config::RuntimeFinalizeAction::ClearJournal
            | config::RuntimeFinalizeAction::CommitBinding { .. },
        )
        | (
            config::RuntimeTransactionOperation::HistoryRecovery,
            config::RuntimeFinalizeAction::ClearJournal
            | config::RuntimeFinalizeAction::ResumeOneClick,
        ) => {}
        _ => return Err("interrupted finalize action has invalid operation ownership".into()),
    }
    let ticket = expected
        .snapshot_ticket
        .as_ref()
        .ok_or("interrupted finalize intent has no authority snapshot ticket")?;
    let cleanup = replay_finalize_authority_cleanup(state, ticket).map_err(String::from)?;
    if replay_adoption_proof
        .as_ref()
        .is_some_and(|(runtime, receipt)| !ScienceHostAdapter::receipt_is_current(receipt, runtime))
    {
        return Err(
            "interrupted finalize Science adoption receipt drifted before config commit; preserved current state"
                .into(),
        );
    }
    config::update_result(&dir, |current| {
        let authority_matches =
            if expected.operation == config::RuntimeTransactionOperation::HistoryRecovery {
                super::history_recovery::history_config_authority_matches(current, expected)
            } else {
                config_authority_matches(
                    current,
                    &expected.target_profile_id,
                    expected.previous_binding.as_ref(),
                )
            };
        if !authority_matches
            || current.runtime_transaction.as_ref()
                != Some(&config::RuntimeTransactionRecord::V2(expected.clone()))
        {
            return Err(
                "interrupted finalize record drifted during authority replay; preserved current state"
                    .into(),
            );
        }
        match &action {
            config::RuntimeFinalizeAction::CommitBinding { binding, .. } => {
                current.runtime_binding = Some(binding.clone());
                current.runtime_transaction = None;
            }
            config::RuntimeFinalizeAction::ClearJournal => {
                current.runtime_transaction = None;
            }
            config::RuntimeFinalizeAction::ResumeOneClick => {
                let mut terminal = expected.clone();
                terminal.phase = config::RuntimeTransactionPhase::ResumeAfterHistoryRestore;
                terminal.snapshot_ticket = None;
                terminal.finalize = config::RuntimeFinalizeState::NotStarted;
                current.runtime_transaction = Some(config::RuntimeTransactionRecord::V2(terminal));
            }
        }
        Ok(((), true))
    })?;
    if let Some((runtime, _)) = replay_adoption_proof {
        let _ = mark_science_runtime_adoption_finalized(&runtime);
    }
    let _ = cleanup;
    Ok(())
}

fn prove_finalize_science_adoption_runtime(
    state: &SharedAppState,
    cfg: &config::Config,
    expected_attempt_id: &str,
) -> Result<(ScienceRuntimeIdentity, ScienceManagedLaunchToken), String> {
    let version_cache = { lock(state).science_version_cache.clone() };
    let (science_state, runtime) =
        ScienceHostAdapter::probe_cached(cfg.sandbox_port, &version_cache).map_err(|error| {
            format!(
                "interrupted finalize could not prove current Science adoption runtime: {error}"
            )
        })?;
    if science_state != SandboxScienceState::RunningHealthy {
        return Err(
            "interrupted finalize requires a healthy current Science runtime with an exact V2 receipt; preserved current state"
                .into(),
        );
    }
    let runtime = runtime.ok_or(
        "interrupted finalize lost the current Science runtime identity; preserved current state",
    )?;
    if runtime.adoption_attempt_id() != Some(expected_attempt_id) {
        return Err(
            "interrupted finalize Science runtime/receipt adoption provenance mismatch; preserved current state"
                .into(),
        );
    }
    let receipt = ScienceHostAdapter::managed_receipt(cfg.sandbox_port, &runtime).ok_or(
        "interrupted finalize could not recover the exact current Science V2 receipt; preserved current state",
    )?;
    if !ScienceHostAdapter::receipt_is_current(&receipt, &runtime) {
        return Err(
            "interrupted finalize Science V2 receipt changed during proof; preserved current state"
                .into(),
        );
    }
    Ok((runtime, receipt))
}

fn history_recovery_choices(
    candidates: Vec<oauth_forge::HistoryOrgCandidate>,
) -> Result<(Vec<HistoryRecoveryChoice>, Vec<Value>), String> {
    if candidates.len() > 64 {
        return Err("历史记录候选超过安全上限（64），已拒绝生成恢复会话".into());
    }
    let choices = candidates
        .into_iter()
        .map(|candidate| HistoryRecoveryChoice {
            reference: config::new_id(),
            candidate,
        })
        .collect::<Vec<_>>();
    let visible = choices
        .iter()
        .enumerate()
        .map(|(index, choice)| {
            let label = if index < 26 {
                format!("历史记录 {}", (b'A' + index as u8) as char)
            } else {
                format!("历史记录 {}", index + 1)
            };
            json!({
                "reference": choice.reference,
                "label": label
            })
        })
        .collect();
    Ok((choices, visible))
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(super) fn test_compensate_one_click_failure<R: Runtime>(
    app: &tauri::AppHandle<R>,
    state: &SharedAppState,
    lifecycle: &lifecycle::Lifecycle,
    dir: &Path,
    authority_transaction: &mut AuthorityTransaction,
    transaction_identity: &OneClickTransactionIdentity,
    journal_progress: &mut OneClickJournalProgress,
    launch_runtime: ScienceRuntimeIdentity,
) -> Result<Value, TypedOneClickFailure> {
    let trace = OperationTrace::start(
        OperationKind::OneClickLogin,
        "test=one_click_journal_drift_compensation",
    );
    let failure = OneClickRollbackContext {
        proxy_action: ProxyAction::Reused,
        sandbox_port: 0,
        launch_runtime,
        launch_token: None,
        launch_environment: ScienceEnvironmentExposure::NotExposed,
        launch_confirmed_stopped: false,
        candidate_stop_proof: ManagedScienceCandidateStopProof::NotRequired,
        ssh_stub_transaction: None,
        current_kind: OneClickFailureKind::Prepare,
    }
    .failure("test-only one-click complete-record CAS rejection");
    cold::compensate_one_click_failure(
        app,
        state,
        lifecycle,
        None,
        dir,
        &trace,
        authority_transaction,
        transaction_identity,
        journal_progress,
        None,
        failure,
    )
}

#[allow(clippy::result_large_err, clippy::too_many_arguments)]
fn one_click_login_with_options<R: Runtime>(
    app: tauri::AppHandle<R>,
    state: SharedAppState,
    lifecycle: &lifecycle::Lifecycle,
    runtime_choice: Option<&str>,
    auth_proof: Option<&crate::codex_auth_supervisor::CodexAuthReadyProof>,
    open_surface: bool,
    entry_progress: OneClickEntryProgress<'_>,
) -> Result<Value, TypedOneClickFailure> {
    let trace = OperationTrace::start(OperationKind::OneClickLogin, "command=one_click_login");
    let dir = config::default_dir();
    let cfg = config::load_for_runtime_effect_admission(&dir)
        .map_err(typed_runtime_effect_admission_error)?;
    if cfg.runtime_compensation.is_some() {
        return Err(TypedOneClickFailure::new(
            OneClickFailureKind::Prepare,
            "durable compensation 尚未由 production entry owner 收敛；已保留 exact journal 与恢复快照。",
        )
        .with_recovery(ProjectedRecovery::MANUAL_RECOVERY_REQUIRED));
    }
    let gateway_terminal_handoff = resolve_gateway_terminal_handoff(
        cfg.runtime_transaction.as_ref(),
        entry_progress.gateway_terminal_handoff,
        &cfg.active_id,
        cfg.runtime_binding.as_ref(),
    )
    .map_err(|detail| {
        TypedOneClickFailure::new(
            OneClickFailureKind::Prepare,
            format!(
                "检测到无法接管的 runtime journal；已保留当前事务并要求人工恢复：{detail}；recovery_status=manual_recovery_required"
            ),
        )
        .with_recovery(ProjectedRecovery::MANUAL_RECOVERY_REQUIRED)
    })?;
    if gateway_terminal_handoff.is_none()
        && cfg
            .runtime_transaction
            .as_ref()
            .is_some_and(config::RuntimeTransactionRecord::is_v2)
    {
        return Err(TypedOneClickFailure::new(
            OneClickFailureKind::Prepare,
            "检测到无法接管的 typed runtime journal；已保留当前事务并要求人工恢复；recovery_status=manual_recovery_required",
        )
        .with_recovery(ProjectedRecovery::MANUAL_RECOVERY_REQUIRED));
    }
    let interrupted_environment_state = cfg
        .runtime_transaction
        .as_ref()
        .and_then(config::RuntimeTransactionRecord::v1_environment_state);
    let interrupted_environment_runtime_id = interrupted_environment_state
        .map(config::RuntimeTransactionV1EnvironmentState::runtime_fingerprint);
    validate_interrupted_science_transaction_entry(interrupted_environment_state)
        .map_err(|error| typed_interrupted_science_err(OneClickFailureKind::Prepare, error))?;
    let active_profile = cfg.active_profile().ok_or_else(|| {
        typed_one_click_err(
            OneClickFailureKind::NoActiveProfile,
            "未配置生效 profile，请先在面板选择或新建一条配置。",
        )
    })?;
    config::require_template_enabled(&cfg, &active_profile.template_id)
        .map_err(|message| typed_one_click_err(OneClickFailureKind::Prepare, message))?;
    let active_launch = crate::runtime::provider::resolve_launch_plan(active_profile)
        .map_err(|message| typed_one_click_err(OneClickFailureKind::LaunchPlan, message))?;
    crate::commands::codex::require_provider_auth_proof(&active_launch.adapter, auth_proof)
        .map_err(|message| typed_one_click_err(OneClickFailureKind::AuthPreflight, message))?;
    crate::runtime::settings::validate_runtime_ports(cfg.proxy_port, cfg.sandbox_port)
        .map_err(|message| typed_one_click_err(OneClickFailureKind::Prepare, message))?;
    let sport = cfg.sandbox_port;

    let sbx_home = sandbox_home();
    let auth_dir = sbx_home.join(".claude-science");
    let entry_facts = capture_one_click_entry_facts(
        &state,
        &cfg,
        active_profile,
        &auth_dir,
        runtime_choice,
        interrupted_environment_runtime_id,
    )?;
    let (launch_runtime, running_runtime_to_stop, science_state, remembered_runtime_was_present) =
        match decide_one_click_entry(entry_facts)? {
            OneClickEntryDecision::HealthyReopen {
                runtime: running_runtime,
            } => {
                let gateway_intent = begin_healthy_reopen_gateway_intent(
                    &dir,
                    &cfg,
                    gateway_terminal_handoff.as_ref(),
                )
                .map_err(|error| typed_one_click_err(OneClickFailureKind::Prepare, error))?;
                let mut reopened = healthy_reopen_with_gateway_rollback(
                    &app,
                    &state,
                    lifecycle,
                    auth_proof,
                    &trace,
                    &dir,
                    &cfg,
                    active_profile,
                    &auth_dir,
                    sport,
                    &running_runtime,
                    open_surface,
                    &gateway_intent,
                )?;
                if interrupted_environment_runtime_id.is_some() {
                    reopened["recovery_status"] = json!("environment_uncertain");
                    reopened["environment_status"] = json!("uncertain");
                }
                return Ok(reopened);
            }
            OneClickEntryDecision::Mutating {
                launch_runtime,
                running_runtime_to_stop,
                science_state,
                remembered_runtime_was_present,
            } => {
                if !entry_progress.cleanup_replayed {
                    let cleanup = retry_pending_authority_cleanup(&state).map_err(|failure| {
                        typed_authority_cleanup_err(
                            OneClickFailureKind::AuthoritySnapshot,
                            failure,
                            false,
                        )
                    })?;
                    if pending_cleanup_requires_recapture(cleanup) {
                        return one_click_login_with_options(
                            app,
                            state,
                            lifecycle,
                            runtime_choice,
                            auth_proof,
                            open_surface,
                            entry_progress.after_cleanup(),
                        );
                    }
                }
                (
                    launch_runtime,
                    running_runtime_to_stop,
                    science_state,
                    remembered_runtime_was_present,
                )
            }
        };
    cold::run_cold_one_click(
        app,
        state,
        lifecycle,
        auth_proof,
        open_surface,
        trace,
        dir,
        &cfg,
        active_profile,
        sbx_home,
        auth_dir,
        sport,
        launch_runtime,
        running_runtime_to_stop,
        science_state,
        remembered_runtime_was_present,
        gateway_terminal_handoff,
        interrupted_environment_runtime_id,
    )
}
