use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use tauri::Runtime;

use super::*;
use crate::runtime::sandbox_session::recovery::OneClickAuthoritySnapshot;

const COMPENSATION_REPLAY_MANIFEST: &str = "compensation-replay.v1.json";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct DurableRuntimeIdentity {
    path: PathBuf,
    source: String,
    version: Option<String>,
    fingerprint: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    adoption_attempt_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
enum DurableGatewayCleanup {
    Absent {
        port: u16,
    },
    Managed {
        port: u16,
        secret: String,
        provider: String,
        shim: String,
        launch_id: String,
        provider_contract_id: String,
        provider_contract_digest: String,
        catalog_fp: String,
    },
}

impl DurableRuntimeIdentity {
    fn capture(runtime: &ScienceRuntimeIdentity) -> Self {
        Self {
            path: runtime.path.clone(),
            source: runtime.source.code().to_string(),
            version: runtime.version.clone(),
            fingerprint: runtime.environment_transaction_id(),
            adoption_attempt_id: runtime.adoption_attempt_id().map(str::to_string),
        }
    }

    fn resolve(&self) -> Result<ScienceRuntimeIdentity, String> {
        crate::runtime::science::runtime_identity_from_durable_parts(
            &self.path,
            &self.source,
            self.version.clone(),
            &self.fingerprint,
            self.adoption_attempt_id.clone(),
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum DurableLaunchEnvironment {
    NotExposed,
    Exposed,
    Uncertain,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum DurableCandidateStopProof {
    NotRequired,
    ConfirmedStopped,
    Unproven,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct CompensationReplayManifest {
    schema_version: u32,
    compensation_id: String,
    target_profile_id: String,
    runtime_fingerprint: String,
    snapshot_ticket: config::RuntimeSnapshotTicket,
    active_runtime_transaction: Option<config::RuntimeTransactionRecord>,
    proxy_restarted: bool,
    gateway_cleanup: Option<DurableGatewayCleanup>,
    sandbox_port: u16,
    launch_runtime: DurableRuntimeIdentity,
    launch_token_was_present: bool,
    launch_environment: DurableLaunchEnvironment,
    launch_confirmed_stopped: bool,
    candidate_stop_proof: DurableCandidateStopProof,
    ssh_stub_transaction: Option<crate::runtime::settings::ManagedSshStubTransaction>,
    cross_runtime_environment: bool,
    prior_science: Option<config::RuntimePriorScienceRecipe>,
    prior_restart_launch_id: Option<String>,
}

pub(super) fn persist_compensation_replay_manifest(
    authority: &AuthorityTransaction,
    state: &SharedAppState,
    identity: &OneClickTransactionIdentity,
    rollback: &OneClickRollbackContext,
    prior_science_present: bool,
    journal_progress: &OneClickJournalProgress,
) -> Result<(String, Vec<String>), String> {
    let compensation_id = config::new_id();
    let prior_science = match &identity.prior_stop {
        config::RuntimePriorStopState::Intent { recipe }
        | config::RuntimePriorStopState::Outcome { recipe, .. } => Some(recipe.clone()),
        config::RuntimePriorStopState::NotRequired => {
            if prior_science_present {
                return Err("durable compensation replay lost the prior Science recipe".into());
            }
            None
        }
    };
    let gateway_cleanup = if rollback.proxy_action == ProxyAction::Restarted {
        let (port, secret, provider, shim, launch_id, tracked_running) = {
            let mut current = lock(state);
            let tracked_running = current
                .proxy
                .as_mut()
                .and_then(|child| child.try_wait().ok())
                .is_some_and(|status| status.is_none());
            (
                current.proxy_port,
                current.secret.clone(),
                current.provider.clone(),
                current.shim_mode.clone(),
                current.launch_id.clone(),
                tracked_running,
            )
        };
        if proc::loopback_port_in_use(port, operation::LOCAL_HEALTH_TIMEOUT_MS) {
            let health =
                proc::http_gateway_health(port, Some(&secret), operation::LOCAL_HEALTH_TIMEOUT_MS)
                    .ok_or("compensation replay could not authenticate the candidate Gateway")?;
            if !tracked_running
                || health.gateway != "rust"
                || health.intent != "formal"
                || health.provider != provider
                || health.shim != shim
                || health.launch_id != launch_id
            {
                return Err(
                    "compensation replay candidate Gateway identity does not match its process-local owner"
                        .into(),
                );
            }
            Some(DurableGatewayCleanup::Managed {
                port,
                secret,
                provider: health.provider,
                shim: health.shim,
                launch_id: health.launch_id,
                provider_contract_id: health.provider_contract_id,
                provider_contract_digest: health.provider_contract_digest,
                catalog_fp: health.catalog_fp,
            })
        } else {
            Some(DurableGatewayCleanup::Absent { port })
        }
    } else {
        None
    };
    let manifest = CompensationReplayManifest {
        schema_version: 1,
        compensation_id: compensation_id.clone(),
        target_profile_id: identity.target_profile_id.clone(),
        runtime_fingerprint: identity.runtime_fingerprint.clone(),
        snapshot_ticket: identity.snapshot_ticket.clone(),
        active_runtime_transaction: match journal_progress {
            OneClickJournalProgress::PreJournalAbort {
                runtime_transaction,
                ..
            } => runtime_transaction.as_ref().clone(),
            OneClickJournalProgress::Journaled { record, .. } => {
                Some(config::RuntimeTransactionRecord::V2(record.clone()))
            }
            _ => return Err("durable compensation replay was prepared after intent".into()),
        },
        proxy_restarted: rollback.proxy_action == ProxyAction::Restarted,
        gateway_cleanup,
        sandbox_port: rollback.sandbox_port,
        launch_runtime: DurableRuntimeIdentity::capture(&rollback.launch_runtime),
        launch_token_was_present: rollback.launch_token.is_some(),
        launch_environment: match rollback.launch_environment {
            ScienceEnvironmentExposure::NotExposed => DurableLaunchEnvironment::NotExposed,
            ScienceEnvironmentExposure::Exposed => DurableLaunchEnvironment::Exposed,
            ScienceEnvironmentExposure::Uncertain => DurableLaunchEnvironment::Uncertain,
        },
        launch_confirmed_stopped: rollback.launch_confirmed_stopped,
        candidate_stop_proof: match rollback.candidate_stop_proof {
            ManagedScienceCandidateStopProof::NotRequired => DurableCandidateStopProof::NotRequired,
            ManagedScienceCandidateStopProof::ConfirmedStopped => {
                DurableCandidateStopProof::ConfirmedStopped
            }
            ManagedScienceCandidateStopProof::Unproven => DurableCandidateStopProof::Unproven,
        },
        ssh_stub_transaction: rollback.ssh_stub_transaction.clone(),
        cross_runtime_environment: rollback.launch_environment.may_be_exposed()
            && prior_science.as_ref().is_some_and(|recipe| {
                runtime_environment_fingerprint_changed(
                    Some(&recipe.runtime_fingerprint),
                    &rollback.launch_runtime.environment_transaction_id(),
                )
            }),
        prior_restart_launch_id: prior_science.as_ref().map(|_| config::new_id()),
        prior_science,
    };
    let bytes = serde_json::to_vec(&manifest)
        .map_err(|error| format!("compensation replay manifest encode failed: {error}"))?;
    let science_adoption_attempt_ids = compensation_manifest_adoption_attempt_ids(&manifest);
    authority.persist_private_manifest(COMPENSATION_REPLAY_MANIFEST, &bytes)?;
    Ok((compensation_id, science_adoption_attempt_ids))
}

fn compensation_manifest_adoption_attempt_ids(
    manifest: &CompensationReplayManifest,
) -> Vec<String> {
    let mut attempt_ids = std::collections::BTreeSet::new();
    if let Some(attempt_id) = manifest.launch_runtime.adoption_attempt_id.as_ref() {
        attempt_ids.insert(attempt_id.clone());
    }
    if let Some(attempt_id) = manifest
        .prior_science
        .as_ref()
        .and_then(|recipe| recipe.runtime_adoption_attempt_id.as_ref())
    {
        attempt_ids.insert(attempt_id.clone());
    }
    attempt_ids.into_iter().collect()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CompensationReplayDecision {
    ReplayStep(config::RuntimeCompensationStep),
    Finish,
    RejectLegacy,
    RejectIncomplete,
}

pub(super) fn decide_compensation_replay(
    journal: &config::RuntimeCompensationJournal,
) -> CompensationReplayDecision {
    if journal.schema_version != config::RUNTIME_COMPENSATION_SCHEMA_VERSION_V2 {
        return CompensationReplayDecision::RejectLegacy;
    }
    if matches!(
        journal.state,
        config::RuntimeCompensationState::Incomplete { .. }
    ) {
        return CompensationReplayDecision::RejectIncomplete;
    }
    journal
        .steps
        .iter()
        .find(|progress| !progress.outcome.is_terminal())
        .map(|progress| CompensationReplayDecision::ReplayStep(progress.step))
        .unwrap_or(CompensationReplayDecision::Finish)
}

pub(in super::super) fn replay_interrupted_one_click_compensation<R: Runtime>(
    app: &tauri::AppHandle<R>,
    state: &SharedAppState,
    lifecycle: &lifecycle::Lifecycle,
    auth_proof: Option<&crate::codex_auth_supervisor::CodexAuthReadyProof>,
    _cfg: &config::Config,
) -> Result<bool, String> {
    let dir = config::default_dir();
    let _replay_lease = config::acquire_runtime_compensation_replay_lease(&dir)
        .map_err(|error| format!("durable compensation replay lease failed: {error}"))?;
    let authority_bypass = _replay_lease.authority_writer_bypass();
    let cfg = config::load_from(&dir).map_err(|error| error.to_string())?;
    let Some(journal) = cfg.runtime_compensation.as_ref() else {
        return Ok(false);
    };
    match decide_compensation_replay(journal) {
        CompensationReplayDecision::RejectLegacy => Err(
            "legacy durable compensation journal has no replayable step plan; preserved for manual recovery"
                .into(),
        ),
        CompensationReplayDecision::RejectIncomplete => {
            #[cfg(not(unix))]
            {
                // Windows 移植降级：Incomplete 日志待重放的步骤（authority
                // restore / ssh cleanup / science cleanup）在本平台均为 no-op
                // 降级实现，重放无实际效果；直接清账，避免每次一键被旧失败
                // 日志永久卡死（macOS 保留原语义：人工恢复）。
                config::update(&dir, |current| {
                    current.runtime_compensation = None;
                })
                .map_err(|error| {
                    format!("clearing incomplete compensation journal failed: {error}")
                })?;
                Ok(false)
            }
            #[cfg(unix)]
            Err(
                "incomplete durable compensation requires an explicit retry decision; preserved for manual recovery"
                    .into(),
            )
        }
        CompensationReplayDecision::Finish => {
            let mut progress = replay_progress(&cfg, journal, None, None)?;
            finish_one_click_compensation(&dir, &mut progress)?;
            Ok(true)
        }
        CompensationReplayDecision::ReplayStep(step) => {
            let needs_private_manifest = step != config::RuntimeCompensationStep::SnapshotCleanup;
            let manifest = needs_private_manifest
                .then(|| {
                    read_registered_private_manifest(
                        state,
                        &journal.snapshot_ticket,
                        COMPENSATION_REPLAY_MANIFEST,
                    )
                    .and_then(|bytes| {
                        serde_json::from_slice::<CompensationReplayManifest>(&bytes).map_err(|_| {
                            "compensation replay manifest format is invalid".to_string()
                        })
                    })
                })
                .transpose()?;
            if let Some(manifest) = manifest.as_ref() {
                validate_replay_manifest(journal, manifest)?;
            }
            let mut durable_authority = if step == config::RuntimeCompensationStep::AuthorityRestore
            {
                Some(OneClickAuthoritySnapshot::load_durable(
                    state,
                    &journal.snapshot_ticket,
                )?)
            } else {
                None
            };
            if step == config::RuntimeCompensationStep::AuthorityRestore {
                let manifest = manifest
                    .as_ref()
                    .expect("authority replay requires its private manifest");
                let authority = durable_authority
                    .as_ref()
                    .expect("authority replay requires its durable snapshot");
                let inputs = crate::runtime::sandbox_session::recovery::AuthorityRestoreReplayInputs {
                    sandbox_port: manifest.sandbox_port,
                    compensation_id: manifest.compensation_id.clone(),
                    snapshot_ticket: manifest.snapshot_ticket.clone(),
                };
                authority.preflight_durable_authority_restore(
                    &dir,
                    &cfg.runtime_transaction,
                    journal,
                    &inputs,
                )?;
                authority.prepare_durable_authority_restore(state, &inputs)?;
            }
            let restored_runtime_transaction = durable_authority
                .as_ref()
                .map(|authority| authority.config.runtime_transaction.clone());
            let mut progress = replay_progress(
                &cfg,
                journal,
                manifest.as_ref(),
                restored_runtime_transaction,
            )?;
            let current_outcome = journal
                .steps
                .iter()
                .find(|candidate| candidate.step == step)
                .ok_or("compensation replay step is missing from the fixed plan")?
                .outcome;
            if current_outcome == config::RuntimeCompensationStepState::Pending {
                begin_one_click_compensation_step(&dir, &mut progress, step)?;
            } else if current_outcome != config::RuntimeCompensationStepState::InProgress {
                return Err("compensation replay selected a terminal step".into());
            }
            let outcome = replay_dependency_outcome(journal, step).unwrap_or_else(|| match step {
                config::RuntimeCompensationStep::ScienceCleanup => replay_science_cleanup(
                    app,
                    state,
                    lifecycle,
                    manifest
                        .as_ref()
                        .expect("Science replay requires its private manifest"),
                    &authority_bypass,
                ),
                config::RuntimeCompensationStep::SshCleanup => {
                    replay_ssh_cleanup(
                        manifest.as_ref().expect("SSH replay requires manifest"),
                        &authority_bypass,
                    )
                }
                config::RuntimeCompensationStep::AuthorityRestore => {
                    let manifest = manifest
                        .as_ref()
                        .expect("authority replay requires its private manifest");
                    let authority = durable_authority
                        .as_mut()
                        .expect("authority replay requires its durable snapshot");
                    replay_authority_restore(app, state, authority, manifest, &progress)
                }
                config::RuntimeCompensationStep::PriorScienceRestart => replay_prior_restart(
                    app,
                    state,
                    lifecycle,
                    auth_proof,
                    journal,
                    manifest
                        .as_ref()
                        .expect("prior Science replay requires its private manifest"),
                    Some(&authority_bypass),
                ),
                config::RuntimeCompensationStep::SnapshotCleanup => {
                    replay_snapshot_cleanup(state, journal)
                }
                _ => config::RuntimeCompensationStepState::Failed,
            });
            if step == config::RuntimeCompensationStep::AuthorityRestore {
                finish_one_click_authority_restore_step(
                    &dir,
                    &mut progress,
                    outcome,
                )?;
            } else {
                finish_one_click_compensation_step(
                    &dir,
                    &mut progress,
                    step,
                    outcome,
                )?;
            }
            Ok(true)
        }
    }
}

fn validate_replay_manifest(
    journal: &config::RuntimeCompensationJournal,
    manifest: &CompensationReplayManifest,
) -> Result<(), String> {
    let active_prior_recipe = manifest
        .active_runtime_transaction
        .as_ref()
        .and_then(config::RuntimeTransactionRecord::as_v2)
        .and_then(|record| match &record.prior_stop {
            config::RuntimePriorStopState::Intent { recipe }
            | config::RuntimePriorStopState::Outcome { recipe, .. } => Some(recipe),
            config::RuntimePriorStopState::NotRequired => None,
        });
    let restart_identity_valid = match (
        manifest.prior_science.as_ref(),
        manifest.prior_restart_launch_id.as_deref(),
    ) {
        (None, None) => true,
        (Some(_), Some(launch_id)) => {
            (16..=128).contains(&launch_id.len())
                && launch_id
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        }
        _ => false,
    };
    if manifest.schema_version != 1
        || manifest.compensation_id != journal.compensation_id
        || manifest.target_profile_id != journal.target_profile_id
        || manifest.runtime_fingerprint != journal.runtime_fingerprint
        || manifest.snapshot_ticket != journal.snapshot_ticket
        || manifest.launch_runtime.fingerprint != journal.runtime_fingerprint
        || manifest.proxy_restarted != manifest.gateway_cleanup.is_some()
        || manifest.prior_science.as_ref() != active_prior_recipe
        || journal.science_adoption_attempt_ids
            != compensation_manifest_adoption_attempt_ids(manifest)
        || !restart_identity_valid
    {
        return Err("compensation replay manifest identity drifted or retargeted".into());
    }
    Ok(())
}

fn replay_progress(
    cfg: &config::Config,
    journal: &config::RuntimeCompensationJournal,
    manifest: Option<&CompensationReplayManifest>,
    restored_runtime_transaction: Option<Option<config::RuntimeTransactionRecord>>,
) -> Result<OneClickJournalProgress, String> {
    let active = manifest
        .map(|manifest| manifest.active_runtime_transaction.clone())
        .unwrap_or_else(|| cfg.runtime_transaction.clone());
    let restored = restored_runtime_transaction.unwrap_or_else(|| cfg.runtime_transaction.clone());
    if cfg.runtime_transaction != active && cfg.runtime_transaction != restored {
        return Err("compensation replay business transaction drifted".into());
    }
    let authority_in_progress = journal.steps.iter().any(|progress| {
        progress.step == config::RuntimeCompensationStep::AuthorityRestore
            && progress.outcome == config::RuntimeCompensationStepState::InProgress
    });
    Ok(OneClickJournalProgress::Compensating {
        active_runtime_transaction: Box::new(active.clone()),
        restored_runtime_transaction: Box::new(restored),
        expected_runtime_transaction: Box::new(if authority_in_progress {
            active
        } else {
            cfg.runtime_transaction.clone()
        }),
        compensation: Box::new(journal.clone()),
        registered_ticket: journal.snapshot_ticket.clone(),
    })
}

fn step_outcome(
    journal: &config::RuntimeCompensationJournal,
    step: config::RuntimeCompensationStep,
) -> Option<config::RuntimeCompensationStepState> {
    journal
        .steps
        .iter()
        .find(|progress| progress.step == step)
        .map(|progress| progress.outcome)
}

fn replay_dependency_outcome(
    journal: &config::RuntimeCompensationJournal,
    step: config::RuntimeCompensationStep,
) -> Option<config::RuntimeCompensationStepState> {
    let science = step_outcome(journal, config::RuntimeCompensationStep::ScienceCleanup)?;
    if science == config::RuntimeCompensationStepState::Failed {
        return Some(config::RuntimeCompensationStepState::Skipped {
            cause: if step == config::RuntimeCompensationStep::SnapshotCleanup {
                config::RuntimeCompensationSkipCause::SnapshotPreserved
            } else {
                config::RuntimeCompensationSkipCause::BlockedByScienceCleanup
            },
        });
    }
    if step == config::RuntimeCompensationStep::PriorScienceRestart
        && step_outcome(journal, config::RuntimeCompensationStep::AuthorityRestore)?
            != config::RuntimeCompensationStepState::Succeeded
    {
        return Some(config::RuntimeCompensationStepState::Skipped {
            cause: config::RuntimeCompensationSkipCause::BlockedByAuthorityRestore,
        });
    }
    if step == config::RuntimeCompensationStep::SnapshotCleanup {
        let ssh = step_outcome(journal, config::RuntimeCompensationStep::SshCleanup)?;
        let authority = step_outcome(journal, config::RuntimeCompensationStep::AuthorityRestore)?;
        let prior = step_outcome(
            journal,
            config::RuntimeCompensationStep::PriorScienceRestart,
        )?;
        let prior_complete = matches!(
            prior,
            config::RuntimeCompensationStepState::Succeeded
                | config::RuntimeCompensationStepState::Skipped {
                    cause: config::RuntimeCompensationSkipCause::NoPriorScience
                        | config::RuntimeCompensationSkipCause::CrossRuntimeEnvironment
                }
        );
        if ssh != config::RuntimeCompensationStepState::Succeeded
            || authority != config::RuntimeCompensationStepState::Succeeded
            || !prior_complete
        {
            return Some(config::RuntimeCompensationStepState::Skipped {
                cause: config::RuntimeCompensationSkipCause::SnapshotPreserved,
            });
        }
    }
    None
}

fn replay_science_cleanup<R: Runtime>(
    app: &tauri::AppHandle<R>,
    state: &SharedAppState,
    lifecycle: &lifecycle::Lifecycle,
    manifest: &CompensationReplayManifest,
    bypass: &config::AuthorityWriterBypass<'_>,
) -> config::RuntimeCompensationStepState {
    if manifest.candidate_stop_proof == DurableCandidateStopProof::Unproven {
        return config::RuntimeCompensationStepState::Failed;
    }
    let required = manifest.launch_token_was_present
        || manifest.launch_environment != DurableLaunchEnvironment::NotExposed;
    if !required {
        return config::RuntimeCompensationStepState::Skipped {
            cause: config::RuntimeCompensationSkipCause::NoScienceCandidate,
        };
    }
    let Ok(runtime) = manifest.launch_runtime.resolve() else {
        return config::RuntimeCompensationStepState::Failed;
    };
    let port_in_use =
        proc::loopback_port_in_use(manifest.sandbox_port, operation::LOCAL_HEALTH_TIMEOUT_MS);
    let receipt = ScienceHostAdapter::managed_receipt(manifest.sandbox_port, &runtime);
    if manifest.launch_confirmed_stopped && !port_in_use && receipt.is_none() {
        return config::RuntimeCompensationStepState::Succeeded;
    }
    if port_in_use && receipt.is_none() {
        return config::RuntimeCompensationStepState::Failed;
    }
    let result = execute_transaction_science_stop_with(
        state,
        lifecycle,
        TransactionScienceStopTarget::new(
            TransactionScienceStopBoundary::CompensationReplayCleanup,
            &runtime,
            manifest.sandbox_port,
        ),
        || {
            let receipt = ScienceHostAdapter::managed_receipt(manifest.sandbox_port, &runtime)
                .ok_or_else(|| {
                    crate::runtime::science::ScienceStopFailure::request_rejected(
                        "compensation replay 无法冻结候选 Science 的 exact managed receipt",
                    )
                })?;
            Ok(ScienceStopRequest::exact(
                &runtime,
                ScienceStopOwnershipReceipt::from_managed_launch(&receipt),
            ))
        },
        |request| {
            ScienceHostAdapter::execute_stop_with_authority_bypass(app, request, bypass)
                .into_parts()
        },
        |_state, _confirmed_runtime| {},
    );
    match result {
        Ok(_) => config::RuntimeCompensationStepState::Succeeded,
        _ => config::RuntimeCompensationStepState::Failed,
    }
}

fn replay_ssh_cleanup(
    manifest: &CompensationReplayManifest,
    bypass: &config::AuthorityWriterBypass<'_>,
) -> config::RuntimeCompensationStepState {
    let result = match manifest.ssh_stub_transaction.as_ref() {
        Some(transaction) => {
            transaction.compensate_durable_with_authority_bypass(&sandbox_home(), bypass)
        }
        None => crate::runtime::settings::remove_managed_sandbox_ssh_stub_with_authority_bypass(
            &sandbox_home(),
            bypass,
        ),
    };
    match result {
        Ok(_) => config::RuntimeCompensationStepState::Succeeded,
        Err(_) => config::RuntimeCompensationStepState::Failed,
    }
}

fn replay_authority_restore<R: Runtime>(
    app: &tauri::AppHandle<R>,
    state: &SharedAppState,
    authority: &mut OneClickAuthoritySnapshot,
    manifest: &CompensationReplayManifest,
    progress: &OneClickJournalProgress,
) -> config::RuntimeCompensationStepState {
    let OneClickJournalProgress::Compensating {
        active_runtime_transaction,
        compensation,
        ..
    } = progress
    else {
        return config::RuntimeCompensationStepState::Failed;
    };
    let inputs = crate::runtime::sandbox_session::recovery::AuthorityRestoreReplayInputs {
        sandbox_port: manifest.sandbox_port,
        compensation_id: manifest.compensation_id.clone(),
        snapshot_ticket: manifest.snapshot_ticket.clone(),
    };
    if replay_candidate_gateway_cleanup(app, state, manifest).is_err() {
        return config::RuntimeCompensationStepState::Failed;
    }
    match authority.restore_durable_authority(
        &config::default_dir(),
        state,
        active_runtime_transaction.as_ref(),
        compensation,
        &inputs,
    ) {
        Ok(()) => config::RuntimeCompensationStepState::Succeeded,
        Err(_) => config::RuntimeCompensationStepState::Failed,
    }
}

fn replay_candidate_gateway_cleanup<R: Runtime>(
    app: &tauri::AppHandle<R>,
    state: &SharedAppState,
    manifest: &CompensationReplayManifest,
) -> Result<(), String> {
    let Some(cleanup) = manifest.gateway_cleanup.as_ref() else {
        return Ok(());
    };
    let port = match cleanup {
        DurableGatewayCleanup::Absent { port } | DurableGatewayCleanup::Managed { port, .. } => {
            *port
        }
    };
    if !proc::loopback_port_in_use(port, operation::LOCAL_HEALTH_TIMEOUT_MS) {
        let mut current = lock(state);
        if current
            .proxy
            .as_mut()
            .and_then(|child| child.try_wait().ok())
            .is_some_and(|status| status.is_some())
        {
            current.proxy = None;
        } else if current.proxy.is_some() {
            return Err(
                "process-local Gateway owner no longer matches the durable candidate port".into(),
            );
        }
        return Ok(());
    }
    let DurableGatewayCleanup::Managed {
        secret,
        provider,
        shim,
        launch_id,
        provider_contract_id,
        provider_contract_digest,
        catalog_fp,
        ..
    } = cleanup
    else {
        return Err("candidate Gateway appeared after durable absence proof".into());
    };
    let health_matches = || {
        proc::http_gateway_health(port, Some(secret), operation::LOCAL_HEALTH_TIMEOUT_MS)
            .is_some_and(|health| {
                health.gateway == "rust"
                    && health.intent == "formal"
                    && health.provider == *provider
                    && health.shim == *shim
                    && health.launch_id == *launch_id
                    && health.provider_contract_id == *provider_contract_id
                    && health.provider_contract_digest == *provider_contract_digest
                    && health.catalog_fp == *catalog_fp
            })
    };
    if !health_matches() {
        return Err("candidate Gateway durable health identity changed".into());
    }
    let binary = crate::runtime::proxy_lifecycle::gateway_bin_path(app)
        .ok_or("candidate Gateway binary is unavailable")?;
    match crate::runtime::legacy_proxy::stop_managed_gateway_on_port(port, &binary, health_matches)
    {
        crate::runtime::legacy_proxy::ManagedGatewayCleanup::Stopped(pid) => {
            let mut current = lock(state);
            if current
                .proxy
                .as_ref()
                .is_some_and(|child| child.id() != pid)
            {
                return Err(
                    "process-local Gateway owner changed during exact candidate cleanup".into(),
                );
            }
            if current.proxy.is_some() {
                current.stop_proxy().require_stopped(
                    "补偿重放停止已由外部确认退出的 Gateway 时仍无法确认 process-local child 退出",
                )?;
            }
            Ok(())
        }
        crate::runtime::legacy_proxy::ManagedGatewayCleanup::NotManaged => {
            Err("candidate Gateway listener is not the packaged managed process".into())
        }
        crate::runtime::legacy_proxy::ManagedGatewayCleanup::StopUnknown { .. } => {
            Err("candidate Gateway exact stop could not be confirmed".into())
        }
    }
}

fn replay_prior_restart<R: Runtime>(
    app: &tauri::AppHandle<R>,
    state: &SharedAppState,
    lifecycle: &lifecycle::Lifecycle,
    auth_proof: Option<&crate::codex_auth_supervisor::CodexAuthReadyProof>,
    journal: &config::RuntimeCompensationJournal,
    manifest: &CompensationReplayManifest,
    bypass: Option<&config::AuthorityWriterBypass<'_>>,
) -> config::RuntimeCompensationStepState {
    if step_outcome(journal, config::RuntimeCompensationStep::AuthorityRestore)
        != Some(config::RuntimeCompensationStepState::Succeeded)
    {
        return config::RuntimeCompensationStepState::Skipped {
            cause: config::RuntimeCompensationSkipCause::BlockedByAuthorityRestore,
        };
    }
    if manifest.cross_runtime_environment {
        return config::RuntimeCompensationStepState::Skipped {
            cause: config::RuntimeCompensationSkipCause::CrossRuntimeEnvironment,
        };
    }
    let Some(recipe) = manifest.prior_science.as_ref() else {
        return config::RuntimeCompensationStepState::Skipped {
            cause: config::RuntimeCompensationSkipCause::NoPriorScience,
        };
    };
    let Some(restart_launch_id) = manifest.prior_restart_launch_id.as_deref() else {
        return config::RuntimeCompensationStepState::Failed;
    };
    let Ok(mut runtime) = crate::runtime::science::runtime_identity_from_prior_recipe(recipe)
    else {
        return config::RuntimeCompensationStepState::Failed;
    };
    let already_restarted = crate::runtime::science::hydrate_runtime_from_v2_managed_launch(
        recipe.port,
        &mut runtime,
        restart_launch_id,
    )
    .is_ok()
        && ScienceHostAdapter::probe_known(recipe.port, &runtime)
            == SandboxScienceState::RunningHealthy;
    if already_restarted {
        let mut current = lock(state);
        current.sandbox_port = recipe.port;
        current.sandbox_url = Some(ScienceHostAdapter::url(recipe.port, &runtime));
        current.science_runtime = Some(runtime);
        return config::RuntimeCompensationStepState::Succeeded;
    }
    if proc::loopback_port_in_use(recipe.port, operation::LOCAL_HEALTH_TIMEOUT_MS)
        || !crate::runtime::science::prior_restart_receipt_is_absent(recipe, &runtime)
    {
        return config::RuntimeCompensationStepState::Failed;
    }
    match restart_science_identity_with_budget(
        app,
        state,
        lifecycle,
        auth_proof,
        &runtime,
        recipe.port,
        operation::SANDBOX_HEALTH_BUDGET_MS,
        Some(restart_launch_id),
        bypass,
    ) {
        Ok(()) => config::RuntimeCompensationStepState::Succeeded,
        Err(_) => config::RuntimeCompensationStepState::Failed,
    }
}

#[cfg(test)]
pub(super) fn test_replay_prior_restart_effect_without_outcome<R: Runtime>(
    app: &tauri::AppHandle<R>,
    state: &SharedAppState,
    lifecycle: &lifecycle::Lifecycle,
) -> Result<config::RuntimeCompensationStepState, String> {
    let cfg = config::load_from(&config::default_dir()).map_err(|error| error.to_string())?;
    let journal = cfg
        .runtime_compensation
        .as_ref()
        .ok_or("test prior restart requires a durable compensation journal")?;
    if step_outcome(
        journal,
        config::RuntimeCompensationStep::PriorScienceRestart,
    ) != Some(config::RuntimeCompensationStepState::InProgress)
    {
        return Err("test prior restart requires an in-progress durable step".into());
    }
    let manifest =
        serde_json::from_slice::<CompensationReplayManifest>(&read_registered_private_manifest(
            state,
            &journal.snapshot_ticket,
            COMPENSATION_REPLAY_MANIFEST,
        )?)
        .map_err(|_| "test prior restart manifest format is invalid".to_string())?;
    validate_replay_manifest(journal, &manifest)?;
    Ok(replay_prior_restart(
        app, state, lifecycle, None, journal, &manifest, None,
    ))
}

fn replay_snapshot_cleanup(
    state: &SharedAppState,
    journal: &config::RuntimeCompensationJournal,
) -> config::RuntimeCompensationStepState {
    match replay_compensation_snapshot_cleanup(state, &journal.snapshot_ticket) {
        Ok(()) => config::RuntimeCompensationStepState::Succeeded,
        Err(_) => config::RuntimeCompensationStepState::Failed,
    }
}
