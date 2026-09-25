fn static_gateway_catalog_fp(launch: &FormalGatewayPlan) -> Option<String> {
    launch
        .static_model_catalog
        .as_deref()
        .and_then(|payload| serde_json::from_str::<serde_json::Value>(payload).ok())
        .and_then(|value| {
            value
                .get("catalog_fp")
                .and_then(|fp| fp.as_str())
                .map(str::to_string)
        })
}

fn interrupted_health_matches(
    health: &proc::GatewayHealth,
    target_provider: &str,
    target_shim: &str,
    target_contract_id: &str,
    target_contract_digest: &str,
    target_catalog_fp: Option<&str>,
    previous: Option<&config::GatewayRuntimeJournalIdentity>,
) -> bool {
    let managed_identity = health.gateway == "rust"
        && health.intent == "formal"
        && (24..=128).contains(&health.launch_id.len())
        && health
            .launch_id
            .chars()
            .all(|value| value.is_ascii_hexdigit());
    let target_matches = health.provider == target_provider
        && health.shim == target_shim
        && !target_contract_id.is_empty()
        && !target_contract_digest.is_empty()
        && health.provider_contract_id == target_contract_id
        && health.provider_contract_digest == target_contract_digest
        && target_catalog_fp
            .map(|expected| health.catalog_fp == expected)
            .unwrap_or(health.catalog_fp.is_empty());
    let previous_matches = previous.is_some_and(|expected| {
        health.provider == expected.provider
            && health.shim == expected.shim
            && health.launch_id == expected.launch_id
            && !expected.provider_contract_id.is_empty()
            && !expected.provider_contract_digest.is_empty()
            && health.provider_contract_id == expected.provider_contract_id
            && health.provider_contract_digest == expected.provider_contract_digest
            && health.catalog_fp == expected.catalog_fp
    });
    managed_identity && (target_matches || previous_matches)
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct InterruptedGatewayTerminalHandoff {
    record: config::RuntimeTransactionV2,
}

impl InterruptedGatewayTerminalHandoff {
    fn into_record(self) -> config::RuntimeTransactionV2 {
        self.record
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum InterruptedGatewayRecoveryOutcome {
    NotNeeded,
    Terminal(InterruptedGatewayTerminalHandoff),
    Stopped(u32, InterruptedGatewayTerminalHandoff),
}

impl InterruptedGatewayRecoveryOutcome {
    pub(crate) fn into_terminal_record(self) -> Option<config::RuntimeTransactionV2> {
        match self {
            Self::NotNeeded => None,
            Self::Terminal(handoff) | Self::Stopped(_, handoff) => Some(handoff.into_record()),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InterruptedGatewayStopUnknownKind {
    SignalFailed,
    ExitUnconfirmed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InterruptedGatewayRecoveryErrorKind {
    GatewayStart,
    AuthoritySnapshot,
    NotManaged,
    StopUnknown(InterruptedGatewayStopUnknownKind),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InterruptedGatewayRecoveryDisposition {
    Degraded,
    ManualRecoveryRequired,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct InterruptedGatewayRecoveryError {
    kind: InterruptedGatewayRecoveryErrorKind,
    recovery: InterruptedGatewayRecoveryDisposition,
    safe_detail: String,
}

impl InterruptedGatewayRecoveryError {
    pub(crate) fn new(
        kind: InterruptedGatewayRecoveryErrorKind,
        safe_detail: impl Into<String>,
    ) -> Self {
        let recovery = match kind {
            InterruptedGatewayRecoveryErrorKind::AuthoritySnapshot => {
                InterruptedGatewayRecoveryDisposition::ManualRecoveryRequired
            }
            InterruptedGatewayRecoveryErrorKind::GatewayStart
            | InterruptedGatewayRecoveryErrorKind::NotManaged
            | InterruptedGatewayRecoveryErrorKind::StopUnknown(_) => {
                InterruptedGatewayRecoveryDisposition::Degraded
            }
        };
        Self {
            kind,
            recovery,
            safe_detail: safe_detail.into(),
        }
    }

    pub(crate) fn kind(&self) -> InterruptedGatewayRecoveryErrorKind {
        self.kind
    }

    pub(crate) fn recovery(&self) -> InterruptedGatewayRecoveryDisposition {
        self.recovery
    }
}

impl std::fmt::Display for InterruptedGatewayRecoveryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.safe_detail)
    }
}

impl std::error::Error for InterruptedGatewayRecoveryError {}

fn interrupted_gateway_recovery_error(
    kind: InterruptedGatewayRecoveryErrorKind,
    safe_detail: impl Into<String>,
) -> InterruptedGatewayRecoveryError {
    InterruptedGatewayRecoveryError::new(kind, safe_detail)
}

fn interrupted_gateway_recovery_record(
    journal: &config::RuntimeTransactionRecord,
    gateway_stop_outcome: config::RuntimeGatewayStopOutcome,
) -> Result<config::RuntimeTransactionV2, String> {
    let mut typed = match journal {
        config::RuntimeTransactionRecord::V1(legacy)
            if matches!(
                legacy.stage.as_str(),
                "start_formal_gateway" | "recover_interrupted_gateway"
            ) =>
        {
            config::RuntimeTransactionV2 {
                schema_version: config::RUNTIME_TRANSACTION_SCHEMA_VERSION_V2,
                transaction_id: journal.transaction_id().to_string(),
                operation: config::RuntimeTransactionOperation::ProfileSwitch,
                target_profile_id: journal.target_profile_id().to_string(),
                phase: config::RuntimeTransactionPhase::RecoverInterruptedGateway,
                runtime_fingerprint: None,
                environment_exposure: config::RuntimeEnvironmentExposure::NotExposed,
                snapshot_ticket: None,
                previous_binding: legacy.previous_binding.clone(),
                previous_gateway: legacy.previous_gateway.clone(),
                compensation: config::RuntimeCompensationState::NotStarted,
                gateway_stop_outcome,
                prior_stop: config::RuntimePriorStopState::NotRequired,
                finalize: config::RuntimeFinalizeState::NotStarted,
            }
        }
        config::RuntimeTransactionRecord::V1(_) => {
            return Err(
                "compatibility runtime journal is not an interrupted profile-switch Gateway transaction"
                    .into(),
            );
        }
        config::RuntimeTransactionRecord::V2(typed)
            if typed.operation == config::RuntimeTransactionOperation::ProfileSwitch
                && matches!(
                    typed.phase,
                    config::RuntimeTransactionPhase::StartFormalGateway
                        | config::RuntimeTransactionPhase::RecoverInterruptedGateway
                )
                && typed.compensation == config::RuntimeCompensationState::NotStarted =>
        {
            typed.clone()
        }
        config::RuntimeTransactionRecord::V2(_) => {
            return Err(
                "typed runtime journal is not an interrupted profile-switch Gateway transaction"
                    .into(),
            );
        }
    };
    typed.phase = config::RuntimeTransactionPhase::RecoverInterruptedGateway;
    typed.gateway_stop_outcome = gateway_stop_outcome;
    Ok(typed)
}

fn publish_interrupted_gateway_recovery_record(
    dir: &Path,
    expected: &config::RuntimeTransactionRecord,
    gateway_stop_outcome: config::RuntimeGatewayStopOutcome,
) -> Result<config::RuntimeTransactionRecord, InterruptedGatewayRecoveryError> {
    let next = config::RuntimeTransactionRecord::V2(
        interrupted_gateway_recovery_record(expected, gateway_stop_outcome).map_err(|error| {
            interrupted_gateway_recovery_error(
                InterruptedGatewayRecoveryErrorKind::AuthoritySnapshot,
                format!(
                    "无法证明未完成事务属于可恢复的 profile-switch Gateway；已保留 listener 和事务 journal，拒绝自动恢复：{error}；recovery_status=manual_recovery_required"
                ),
            )
        })?,
    );
    config::update_result(dir, |current| {
        if current.runtime_transaction.as_ref() != Some(expected) {
            return Err(
                "runtime transaction retargeted before Gateway recovery journal publication; preserved the current transaction"
                    .into(),
            );
        }
        current.runtime_transaction = Some(next.clone());
        Ok(((), true))
    })
    .map_err(|error| {
        interrupted_gateway_recovery_error(
            InterruptedGatewayRecoveryErrorKind::GatewayStart,
            error.to_string(),
        )
    })?;
    Ok(next)
}

fn should_record_absent_after_attempt(journal: &config::RuntimeTransactionRecord) -> bool {
    match journal {
        config::RuntimeTransactionRecord::V1(legacy) => {
            legacy.stage == "recover_interrupted_gateway"
        }
        config::RuntimeTransactionRecord::V2(typed) => {
            typed.operation == config::RuntimeTransactionOperation::ProfileSwitch
                && matches!(
                    typed.phase,
                    config::RuntimeTransactionPhase::StartFormalGateway
                        | config::RuntimeTransactionPhase::RecoverInterruptedGateway
                )
                && !matches!(
                    typed.gateway_stop_outcome,
                    config::RuntimeGatewayStopOutcome::Stopped
                        | config::RuntimeGatewayStopOutcome::AbsentAfterAttempt
                )
        }
    }
}

fn interrupted_gateway_recovery_is_complete(journal: &config::RuntimeTransactionRecord) -> bool {
    journal.as_v2().is_some_and(|typed| {
        typed.operation == config::RuntimeTransactionOperation::ProfileSwitch
            && typed.phase == config::RuntimeTransactionPhase::RecoverInterruptedGateway
            && matches!(
                typed.gateway_stop_outcome,
                config::RuntimeGatewayStopOutcome::Stopped
                    | config::RuntimeGatewayStopOutcome::AbsentAfterAttempt
            )
    })
}

/// Consume an interrupted profile-switch journal after an app restart. An
/// orphan is never adopted. It is stopped only when the persisted path secret
/// authenticates a formal Rust Gateway, its public launch/catalog identity
/// matches either the committed target or the journaled previous Gateway, and
/// the listener executes this exact packaged sidecar. The normal one-click
/// path then starts the committed config from a newly tracked child.
pub(crate) fn recover_interrupted_gateway<R: Runtime>(
    app: &tauri::AppHandle<R>,
    state: &SharedAppState,
) -> Result<InterruptedGatewayRecoveryOutcome, InterruptedGatewayRecoveryError> {
    let dir = config::default_dir();
    recover_interrupted_gateway_from_dir(app, state, &dir)
}

fn recover_interrupted_gateway_from_dir<R: Runtime>(
    app: &tauri::AppHandle<R>,
    state: &SharedAppState,
    dir: &Path,
) -> Result<InterruptedGatewayRecoveryOutcome, InterruptedGatewayRecoveryError> {
    let cfg = config::load_from(dir).map_err(|error| {
        interrupted_gateway_recovery_error(
            InterruptedGatewayRecoveryErrorKind::GatewayStart,
            error.to_string(),
        )
    })?;
    #[cfg(not(unix))]
    {
        // Windows 移植降级：中断事务的身份证明与安全接管依赖 fd/dev/ino
        // 锚定，本平台不可用。改为直接终止全部 Gateway 进程并清空事务与
        // 补偿 journal，让一键流程从干净状态重建（单用户桌面场景；macOS
        // 保留原有保守语义）。
        if cfg.runtime_transaction.is_some() || cfg.runtime_compensation.is_some() {
            use crate::platform::CreationFlagsExt;
            let _ = std::process::Command::new("taskkill")
                .args(["/IM", "csswitch-gateway.exe", "/F"])
                .creation_flags(0x0800_0000) // CREATE_NO_WINDOW
                .status();
            config::update(dir, |current| {
                current.runtime_transaction = None;
                current.runtime_compensation = None;
            })
            .map_err(|error| {
                interrupted_gateway_recovery_error(
                    InterruptedGatewayRecoveryErrorKind::GatewayStart,
                    format!("清空中断事务 journal 失败：{error}"),
                )
            })?;
        }
        return Ok(InterruptedGatewayRecoveryOutcome::NotNeeded);
    }
    // Windows 已在上面的降级分支提前返回；此处起仅 Unix 可达，但保持
    // 无 cfg 编译以复用后续主体。
    let Some(journal) = cfg.runtime_transaction.as_ref() else {
        return Ok(InterruptedGatewayRecoveryOutcome::NotNeeded);
    };
    if journal.target_profile_id() != cfg.active_id {
        return Err(interrupted_gateway_recovery_error(
            InterruptedGatewayRecoveryErrorKind::GatewayStart,
            "未完成运行事务的 target profile 与当前 active profile 不一致；已保留 listener 和事务 journal，拒绝自动恢复，等待人工或后续恢复。",
        ));
    }
    if journal.requires_snapshot_preservation() {
        return Err(interrupted_gateway_recovery_error(
            InterruptedGatewayRecoveryErrorKind::AuthoritySnapshot,
            "检测到中断的 Science authority/environment 事务；已保留 Gateway、事务 journal 与恢复快照，拒绝自动探测、停止或改写其身份；recovery_status=manual_recovery_required",
        ));
    }
    interrupted_gateway_recovery_record(
        journal,
        config::RuntimeGatewayStopOutcome::Pending,
    )
    .map_err(|error| {
        interrupted_gateway_recovery_error(
            InterruptedGatewayRecoveryErrorKind::AuthoritySnapshot,
            format!(
                "无法证明未完成事务属于可恢复的 profile-switch Gateway；已保留 listener 和事务 journal，拒绝自动恢复：{error}；recovery_status=manual_recovery_required"
            ),
        )
    })?;
    if interrupted_gateway_recovery_is_complete(journal) {
        let record = journal
            .as_v2()
            .expect("terminal interrupted Gateway recovery is typed")
            .clone();
        return Ok(InterruptedGatewayRecoveryOutcome::Terminal(
            InterruptedGatewayTerminalHandoff { record },
        ));
    }
    {
        let st = lock(state);
        if st.proxy.is_some()
            || !st.launch_id.is_empty()
            || !st.provider.is_empty()
            || !st.gateway_kind.is_empty()
        {
            // Same-process profile switching owns its Child and recovery.
            return Ok(InterruptedGatewayRecoveryOutcome::NotNeeded);
        }
    }
    if !proc::loopback_port_in_use(cfg.proxy_port, operation::LOCAL_HEALTH_TIMEOUT_MS) {
        if should_record_absent_after_attempt(journal) {
            let terminal = publish_interrupted_gateway_recovery_record(
                dir,
                journal,
                config::RuntimeGatewayStopOutcome::AbsentAfterAttempt,
            )?;
            let record = terminal
                .as_v2()
                .expect("published interrupted Gateway terminal is typed")
                .clone();
            return Ok(InterruptedGatewayRecoveryOutcome::Terminal(
                InterruptedGatewayTerminalHandoff { record },
            ));
        }
        return Ok(InterruptedGatewayRecoveryOutcome::NotNeeded);
    }
    if cfg.secret.is_empty() {
        return Err(interrupted_gateway_recovery_error(
            InterruptedGatewayRecoveryErrorKind::GatewayStart,
            "检测到未完成的运行事务，但正式端口被占用且配置没有 path secret；已拒绝接管。",
        ));
    }
    let active = cfg.active_profile().ok_or_else(|| {
        interrupted_gateway_recovery_error(
            InterruptedGatewayRecoveryErrorKind::GatewayStart,
            "未完成的运行事务指向不存在的 active profile",
        )
    })?;
    let formal = crate::runtime::provider::resolve_launch_plan(active)
        .map_err(|error| {
            interrupted_gateway_recovery_error(
                InterruptedGatewayRecoveryErrorKind::GatewayStart,
                error,
            )
        })?
        .formal();
    let target_shim = current_shim_mode_for_adapter(&formal.adapter);
    let target_catalog_fp = static_gateway_catalog_fp(&formal);
    let initial = proc::http_gateway_health(
        cfg.proxy_port,
        Some(&cfg.secret),
        operation::LOCAL_HEALTH_TIMEOUT_MS,
    )
    .ok_or_else(|| {
        interrupted_gateway_recovery_error(
            InterruptedGatewayRecoveryErrorKind::GatewayStart,
            "检测到未完成的运行事务，但端口 listener 不接受已提交 path secret；已拒绝接管。",
        )
    })?;
    if !interrupted_health_matches(
        &initial,
        &formal.adapter,
        target_shim,
        &formal.contract_id,
        &formal.contract_digest,
        target_catalog_fp.as_deref(),
        journal.previous_gateway(),
    ) || !proc::http_health_gateway(
        cfg.proxy_port,
        Some(&cfg.secret),
        operation::LOCAL_HEALTH_TIMEOUT_MS,
        proc::GatewayHealthExpectation {
            gateway: "rust",
            provider: Some(&initial.provider),
            shim: Some(&initial.shim),
            launch_id: Some(&initial.launch_id),
            provider_contract_id: Some(&initial.provider_contract_id),
            provider_contract_digest: Some(&initial.provider_contract_digest),
        },
    ) {
        return Err(interrupted_gateway_recovery_error(
            InterruptedGatewayRecoveryErrorKind::GatewayStart,
            "未完成事务的端口 listener 与已提交/上一受管 Gateway 身份不一致；已拒绝结束未知进程。",
        ));
    }
    let binary = gateway_bin_path(app).ok_or_else(|| {
        interrupted_gateway_recovery_error(
            InterruptedGatewayRecoveryErrorKind::GatewayStart,
            "未找到本次应用打包的 Gateway，无法安全恢复事务",
        )
    })?;
    finish_interrupted_gateway_recovery(dir, journal, || {
        let initial_for_probe = initial.clone();
        stop_managed_gateway_on_port(cfg.proxy_port, &binary, || {
            let Some(current) = proc::http_gateway_health(
                cfg.proxy_port,
                Some(&cfg.secret),
                operation::LOCAL_HEALTH_TIMEOUT_MS,
            ) else {
                return false;
            };
            current == initial_for_probe
                && proc::http_health_gateway(
                    cfg.proxy_port,
                    Some(&cfg.secret),
                    operation::LOCAL_HEALTH_TIMEOUT_MS,
                    proc::GatewayHealthExpectation {
                        gateway: "rust",
                        provider: Some(&initial_for_probe.provider),
                        shim: Some(&initial_for_probe.shim),
                        launch_id: Some(&initial_for_probe.launch_id),
                        provider_contract_id: Some(&initial_for_probe.provider_contract_id),
                        provider_contract_digest: Some(&initial_for_probe.provider_contract_digest),
                    },
                )
        })
    })
}

fn finish_interrupted_gateway_recovery<F>(
    dir: &Path,
    journal: &config::RuntimeTransactionRecord,
    cleanup: F,
) -> Result<InterruptedGatewayRecoveryOutcome, InterruptedGatewayRecoveryError>
where
    F: FnOnce() -> ManagedGatewayCleanup,
{
    let pending = publish_interrupted_gateway_recovery_record(
        dir,
        journal,
        config::RuntimeGatewayStopOutcome::Pending,
    )?;
    let cleanup = cleanup();
    let outcome = match cleanup {
        ManagedGatewayCleanup::Stopped(_) => config::RuntimeGatewayStopOutcome::Stopped,
        ManagedGatewayCleanup::NotManaged => config::RuntimeGatewayStopOutcome::NotManaged,
        ManagedGatewayCleanup::StopUnknown {
            kind: ManagedGatewayStopUnknownKind::SignalFailed,
            ..
        } => config::RuntimeGatewayStopOutcome::SignalFailed,
        ManagedGatewayCleanup::StopUnknown {
            kind: ManagedGatewayStopUnknownKind::ExitUnconfirmed,
            ..
        } => config::RuntimeGatewayStopOutcome::ExitUnconfirmed,
    };
    let terminal = publish_interrupted_gateway_recovery_record(dir, &pending, outcome)?;
    let handoff = InterruptedGatewayTerminalHandoff {
        record: terminal
            .as_v2()
            .expect("published interrupted Gateway terminal is typed")
            .clone(),
    };
    match cleanup {
        ManagedGatewayCleanup::Stopped(pid) => {
            Ok(InterruptedGatewayRecoveryOutcome::Stopped(pid, handoff))
        }
        ManagedGatewayCleanup::NotManaged => Err(interrupted_gateway_recovery_error(
            InterruptedGatewayRecoveryErrorKind::NotManaged,
            "未完成事务的 listener 未通过精确 Gateway binary/uid/PID 复核；已拒绝结束进程。",
        )),
        ManagedGatewayCleanup::StopUnknown { kind, .. } => {
            let kind = match kind {
                ManagedGatewayStopUnknownKind::SignalFailed => {
                    InterruptedGatewayStopUnknownKind::SignalFailed
                }
                ManagedGatewayStopUnknownKind::ExitUnconfirmed => {
                    InterruptedGatewayStopUnknownKind::ExitUnconfirmed
                }
            };
            Err(interrupted_gateway_recovery_error(
                InterruptedGatewayRecoveryErrorKind::StopUnknown(kind),
                "已确认未完成事务遗留的受管 Gateway，但安全停止失败。",
            ))
        }
    }
}
