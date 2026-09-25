#[cfg(not(unix))]
use crate::platform::UnixCompatExt;

use std::io::Read;
#[cfg(unix)]
use std::os::fd::AsRawFd;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, PermissionsExt};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::Digest;
use tauri::Runtime;

use crate::config;
use crate::runtime::failure::TypedOneClickFailure;
use crate::runtime::proxy::ProxyAction;
use crate::runtime::science::{
    SandboxScienceState, ScienceHostAdapter, ScienceStopFailureKind, ScienceStopOwnershipReceipt,
    ScienceStopRequest,
};
use crate::{lifecycle, lock, oauth_forge, SharedAppState};

use super::authority_snapshot::{AuthoritySnapshotScope, AuthorityTreeSnapshot};
use super::authority_transaction::AuthorityTransaction;
use super::one_click::one_click_login_after_history_handoff;
use super::pending_cleanup::{
    open_history_snapshot_root, prepare_history_snapshot_cleanup_only,
    retry_pending_authority_cleanup,
};
use super::recovery::RuntimeTransactionRestoreExpectation;
use super::transaction_science_stop::{
    execute_transaction_science_stop_with, TransactionScienceStopBoundary,
    TransactionScienceStopTarget,
};

const HISTORY_RECOVERY_MANIFEST_FILE: &str = ".csswitch-history-recovery.v1.json";
const MAX_HISTORY_RECOVERY_MANIFEST_BYTES: u64 = 16 * 1024;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum HistoryRecoveryAuthorityEntryKind {
    EncryptionKey,
    OauthTokens,
    ActiveOrg,
    VirtualOrgMarker,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct HistoryRecoveryAuthorityEntry {
    kind: HistoryRecoveryAuthorityEntryKind,
    existed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    backup_device: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    backup_inode: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    backup_kind: Option<u32>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct HistoryRecoveryAuthorityManifest {
    schema_version: u32,
    transaction_id: String,
    snapshot_managed_id: String,
    entries: Vec<HistoryRecoveryAuthorityEntry>,
}

#[cfg(test)]
static HISTORY_RESTORE_POST_STOP_CONFIG_DRIFT: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);
#[cfg(test)]
static HISTORY_RESTORE_POST_SNAPSHOT_CONFIG_DRIFT: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);
#[cfg(test)]
static HISTORY_RESTORE_INTERRUPT_AFTER_CREDENTIAL_WRITE: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);
#[cfg(test)]
static HISTORY_FINALIZE_COMPLETION_FAILURE: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);
#[cfg(test)]
static HISTORY_REPLAY_SIBLING_CONFIG_WRITER: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);
#[cfg(test)]
static HISTORY_REPLAY_INTERRUPT_AFTER_FIRST_RESTORE: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

#[cfg(test)]
pub(crate) struct HistoryRestorePostStopConfigDriftGuard;

#[cfg(test)]
impl Drop for HistoryRestorePostStopConfigDriftGuard {
    fn drop(&mut self) {
        HISTORY_RESTORE_POST_STOP_CONFIG_DRIFT.store(false, std::sync::atomic::Ordering::SeqCst);
    }
}

#[cfg(test)]
pub(crate) struct HistoryRestorePostSnapshotConfigDriftGuard;

#[cfg(test)]
impl Drop for HistoryRestorePostSnapshotConfigDriftGuard {
    fn drop(&mut self) {
        HISTORY_RESTORE_POST_SNAPSHOT_CONFIG_DRIFT
            .store(false, std::sync::atomic::Ordering::SeqCst);
    }
}

#[cfg(test)]
pub(crate) struct HistoryRestoreCredentialInterruptGuard;
#[cfg(test)]
pub(crate) struct HistoryFinalizeCompletionFailureGuard;
#[cfg(test)]
pub(crate) struct HistoryReplaySiblingConfigWriterGuard;
#[cfg(test)]
pub(crate) struct HistoryReplayInterruptAfterFirstRestoreGuard;

#[cfg(test)]
impl Drop for HistoryRestoreCredentialInterruptGuard {
    fn drop(&mut self) {
        HISTORY_RESTORE_INTERRUPT_AFTER_CREDENTIAL_WRITE
            .store(false, std::sync::atomic::Ordering::SeqCst);
    }
}

#[cfg(test)]
impl Drop for HistoryFinalizeCompletionFailureGuard {
    fn drop(&mut self) {
        HISTORY_FINALIZE_COMPLETION_FAILURE.store(false, std::sync::atomic::Ordering::SeqCst);
    }
}

#[cfg(test)]
impl Drop for HistoryReplaySiblingConfigWriterGuard {
    fn drop(&mut self) {
        HISTORY_REPLAY_SIBLING_CONFIG_WRITER.store(false, std::sync::atomic::Ordering::SeqCst);
    }
}

#[cfg(test)]
impl Drop for HistoryReplayInterruptAfterFirstRestoreGuard {
    fn drop(&mut self) {
        HISTORY_REPLAY_INTERRUPT_AFTER_FIRST_RESTORE
            .store(false, std::sync::atomic::Ordering::SeqCst);
    }
}

#[cfg(test)]
pub(crate) fn test_arm_history_restore_post_stop_config_drift(
) -> HistoryRestorePostStopConfigDriftGuard {
    HISTORY_RESTORE_POST_STOP_CONFIG_DRIFT.store(true, std::sync::atomic::Ordering::SeqCst);
    HistoryRestorePostStopConfigDriftGuard
}

#[cfg(test)]
pub(crate) fn test_arm_history_restore_post_snapshot_config_drift(
) -> HistoryRestorePostSnapshotConfigDriftGuard {
    HISTORY_RESTORE_POST_SNAPSHOT_CONFIG_DRIFT.store(true, std::sync::atomic::Ordering::SeqCst);
    HistoryRestorePostSnapshotConfigDriftGuard
}

#[cfg(test)]
pub(crate) fn test_arm_history_restore_credential_interrupt(
) -> HistoryRestoreCredentialInterruptGuard {
    HISTORY_RESTORE_INTERRUPT_AFTER_CREDENTIAL_WRITE
        .store(true, std::sync::atomic::Ordering::SeqCst);
    HistoryRestoreCredentialInterruptGuard
}

#[cfg(test)]
pub(crate) fn test_arm_history_finalize_completion_failure() -> HistoryFinalizeCompletionFailureGuard
{
    HISTORY_FINALIZE_COMPLETION_FAILURE.store(true, std::sync::atomic::Ordering::SeqCst);
    HistoryFinalizeCompletionFailureGuard
}

#[cfg(test)]
pub(crate) fn test_arm_history_replay_sibling_config_writer(
) -> HistoryReplaySiblingConfigWriterGuard {
    HISTORY_REPLAY_SIBLING_CONFIG_WRITER.store(true, std::sync::atomic::Ordering::SeqCst);
    HistoryReplaySiblingConfigWriterGuard
}

#[cfg(test)]
pub(crate) fn test_arm_history_replay_interrupt_after_first_restore(
) -> HistoryReplayInterruptAfterFirstRestoreGuard {
    HISTORY_REPLAY_INTERRUPT_AFTER_FIRST_RESTORE.store(true, std::sync::atomic::Ordering::SeqCst);
    HistoryReplayInterruptAfterFirstRestoreGuard
}

#[cfg(test)]
fn apply_history_restore_post_stop_config_drift(expected_port: u16) -> Result<(), String> {
    if !HISTORY_RESTORE_POST_STOP_CONFIG_DRIFT.swap(false, std::sync::atomic::Ordering::SeqCst) {
        return Ok(());
    }
    let dir = config::default_dir();
    let mut current = config::load_from(&dir).map_err(|error| error.to_string())?;
    current.sandbox_port = expected_port
        .checked_add(1)
        .filter(|port| *port != 8765)
        .unwrap_or(expected_port.saturating_sub(1));
    config::test_save_to_without_history_authority_guard(&dir, &current)
        .map_err(|error| error.to_string())
}

#[cfg(test)]
fn apply_history_restore_post_snapshot_config_drift() -> Result<(), String> {
    if !HISTORY_RESTORE_POST_SNAPSHOT_CONFIG_DRIFT.swap(false, std::sync::atomic::Ordering::SeqCst)
    {
        return Ok(());
    }
    let dir = config::default_dir();
    let mut current = config::load_from(&dir).map_err(|error| error.to_string())?;
    current.reuse_system_ssh = !current.reuse_system_ssh;
    config::test_save_to_without_history_authority_guard(&dir, &current)
        .map_err(|error| error.to_string())?;
    Err("test-only credential failure after concurrent config writer".into())
}

#[cfg(test)]
fn apply_history_replay_sibling_config_writer(expected_port: u16) -> Result<(), String> {
    if !HISTORY_REPLAY_SIBLING_CONFIG_WRITER.swap(false, std::sync::atomic::Ordering::SeqCst) {
        return Ok(());
    }
    match config::update(&config::default_dir(), |current| {
        current.sandbox_port = expected_port
            .checked_add(1)
            .filter(|port| *port != 8765)
            .unwrap_or(expected_port.saturating_sub(1));
    }) {
        Err(error) if error.to_string().contains("拒绝 sibling config writer") => Ok(()),
        Err(error) => Err(format!(
            "test-only replay sibling writer returned the wrong rejection: {error}"
        )),
        Ok(_) => Err("test-only replay sibling writer bypassed Config authority".into()),
    }
}

fn history_config_authority_fingerprint(current: &config::Config) -> Result<String, String> {
    let mut authority = current.clone();
    authority.runtime_transaction = None;
    let bytes = serde_json::to_vec(&authority)
        .map_err(|error| format!("history config authority serialization failed: {error}"))?;
    Ok(format!("{:x}", sha2::Sha256::digest(bytes)))
}

pub(super) fn history_config_authority_matches(
    current: &config::Config,
    expected: &config::RuntimeTransactionV2,
) -> bool {
    expected
        .runtime_fingerprint
        .as_deref()
        .is_some_and(|fingerprint| {
            history_config_authority_fingerprint(current).as_deref() == Ok(fingerprint)
        })
}

fn history_authority_paths(
    kind: HistoryRecoveryAuthorityEntryKind,
    snapshot_root: &std::path::Path,
    sandbox_root: &std::path::Path,
    auth_dir: &std::path::Path,
) -> Result<
    (
        AuthoritySnapshotScope,
        std::path::PathBuf,
        std::path::PathBuf,
    ),
    String,
> {
    Ok(match kind {
        HistoryRecoveryAuthorityEntryKind::EncryptionKey => (
            AuthoritySnapshotScope::ScienceData,
            auth_dir.join("encryption.key"),
            snapshot_root.join("0").join("encryption.key"),
        ),
        HistoryRecoveryAuthorityEntryKind::OauthTokens => (
            AuthoritySnapshotScope::ScienceData,
            auth_dir.join(".oauth-tokens"),
            snapshot_root.join("0").join(".oauth-tokens"),
        ),
        HistoryRecoveryAuthorityEntryKind::ActiveOrg => (
            AuthoritySnapshotScope::ScienceData,
            auth_dir.join("active-org.json"),
            snapshot_root.join("0").join("active-org.json"),
        ),
        HistoryRecoveryAuthorityEntryKind::VirtualOrgMarker => (
            AuthoritySnapshotScope::SandboxState,
            oauth_forge::marker_path(sandbox_root)?,
            snapshot_root.join("1").join("virtual-org.v1.json"),
        ),
    })
}

fn captured_history_authority_entry(
    kind: HistoryRecoveryAuthorityEntryKind,
    snapshot_root: &std::path::Path,
    sandbox_root: &std::path::Path,
    auth_dir: &std::path::Path,
) -> Result<HistoryRecoveryAuthorityEntry, String> {
    let (_, _, backup) = history_authority_paths(kind, snapshot_root, sandbox_root, auth_dir)?;
    match std::fs::symlink_metadata(&backup) {
        Ok(metadata) => {
            let file_type = metadata.mode() & u32::from(crate::platform::S_IFMT);
            if metadata.file_type().is_symlink()
                || (file_type != u32::from(crate::platform::S_IFREG) && file_type != u32::from(crate::platform::S_IFDIR))
                || metadata.uid() != unsafe { crate::platform::geteuid() }
            {
                return Err("history recovery backup entry identity is unsafe".into());
            }
            Ok(HistoryRecoveryAuthorityEntry {
                kind,
                existed: true,
                backup_device: Some(metadata.dev()),
                backup_inode: Some(metadata.ino()),
                backup_kind: Some(file_type),
            })
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Ok(HistoryRecoveryAuthorityEntry {
                kind,
                existed: false,
                backup_device: None,
                backup_inode: None,
                backup_kind: None,
            })
        }
        Err(error) => Err(format!(
            "history recovery backup entry metadata failed: {error}"
        )),
    }
}

fn persist_history_authority_manifest(
    authority: &AuthorityTransaction,
    record: &config::RuntimeTransactionV2,
    ticket: &config::RuntimeSnapshotTicket,
    sandbox_root: &std::path::Path,
    auth_dir: &std::path::Path,
) -> Result<(), String> {
    let kinds = [
        HistoryRecoveryAuthorityEntryKind::EncryptionKey,
        HistoryRecoveryAuthorityEntryKind::OauthTokens,
        HistoryRecoveryAuthorityEntryKind::ActiveOrg,
        HistoryRecoveryAuthorityEntryKind::VirtualOrgMarker,
    ];
    let entries = kinds
        .into_iter()
        .map(|kind| {
            captured_history_authority_entry(
                kind,
                authority.recovery_path(),
                sandbox_root,
                auth_dir,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let bytes = serde_json::to_vec(&HistoryRecoveryAuthorityManifest {
        schema_version: 1,
        transaction_id: record.transaction_id.clone(),
        snapshot_managed_id: ticket.managed_id.clone(),
        entries,
    })
    .map_err(|error| format!("history recovery manifest encode failed: {error}"))?;
    authority.persist_private_manifest(HISTORY_RECOVERY_MANIFEST_FILE, &bytes)
}

fn read_history_authority_manifest(
    root: &std::fs::File,
    expected: &config::RuntimeTransactionV2,
    ticket: &config::RuntimeSnapshotTicket,
) -> Result<HistoryRecoveryAuthorityManifest, String> {
    let name = std::ffi::CString::new(HISTORY_RECOVERY_MANIFEST_FILE).unwrap();
    let file =
        AuthorityTreeSnapshot::open_destination_at(root.as_raw_fd(), &name, crate::platform::O_RDONLY, 0)
            .map_err(|error| format!("history recovery manifest open failed: {error}"))?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("history recovery manifest metadata failed: {error}"))?;
    if !metadata.is_file()
        || metadata.uid() != unsafe { crate::platform::geteuid() }
        || metadata.permissions().mode() & 0o777 != 0o600
        || metadata.nlink() != 1
        || metadata.len() == 0
        || metadata.len() > MAX_HISTORY_RECOVERY_MANIFEST_BYTES
    {
        return Err("history recovery manifest identity is unsafe".into());
    }
    let mut bytes = Vec::new();
    file.take(MAX_HISTORY_RECOVERY_MANIFEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("history recovery manifest read failed: {error}"))?;
    if bytes.len() as u64 > MAX_HISTORY_RECOVERY_MANIFEST_BYTES {
        return Err("history recovery manifest is too large".into());
    }
    let manifest: HistoryRecoveryAuthorityManifest = serde_json::from_slice(&bytes)
        .map_err(|error| format!("history recovery manifest decode failed: {error}"))?;
    if manifest.schema_version != 1
        || manifest.transaction_id != expected.transaction_id
        || manifest.snapshot_managed_id != ticket.managed_id
        || manifest.entries.len() != 4
    {
        return Err("history recovery manifest causal identity is invalid".into());
    }
    let kinds = [
        HistoryRecoveryAuthorityEntryKind::EncryptionKey,
        HistoryRecoveryAuthorityEntryKind::OauthTokens,
        HistoryRecoveryAuthorityEntryKind::ActiveOrg,
        HistoryRecoveryAuthorityEntryKind::VirtualOrgMarker,
    ];
    for kind in kinds {
        let matches = manifest
            .entries
            .iter()
            .filter(|entry| entry.kind == kind)
            .collect::<Vec<_>>();
        if matches.len() != 1 {
            return Err("history recovery manifest entry set is invalid".into());
        }
        let entry = matches[0];
        let identity_present = entry.backup_device.is_some()
            && entry.backup_inode.is_some()
            && entry.backup_kind.is_some();
        if entry.existed != identity_present {
            return Err("history recovery manifest entry identity is incomplete".into());
        }
    }
    Ok(manifest)
}

fn reopen_history_authority_entry(
    root: &std::fs::File,
    entry: &HistoryRecoveryAuthorityEntry,
    snapshot_root: &std::path::Path,
    sandbox_root: &std::path::Path,
    auth_dir: &std::path::Path,
) -> Result<AuthorityTreeSnapshot, String> {
    let (scope, source, backup) =
        history_authority_paths(entry.kind, snapshot_root, sandbox_root, auth_dir)?;
    let source_parent_path = source
        .parent()
        .ok_or("history recovery source parent is missing")?;
    let source_parent = match AuthorityTreeSnapshot::open_absolute_directory(source_parent_path) {
        Ok(parent) => Some(parent),
        Err(error) if !entry.existed && error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => {
            return Err(format!(
                "history recovery source parent open failed: {error}"
            ))
        }
    };
    let source_name = source_parent
        .as_ref()
        .map(|_| AuthorityTreeSnapshot::destination_name(&source))
        .transpose()?;
    let group_name = match entry.kind {
        HistoryRecoveryAuthorityEntryKind::VirtualOrgMarker => "1",
        _ => "0",
    };
    let group_name = std::ffi::CString::new(group_name).unwrap();
    let backup_group = match AuthorityTreeSnapshot::open_directory_at(root.as_raw_fd(), &group_name)
    {
        Ok(group) => Some(group),
        Err(error) if !entry.existed && error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => {
            return Err(format!(
                "history recovery backup group open failed: {error}"
            ))
        }
    };
    let backup_name = AuthorityTreeSnapshot::destination_name(&backup)?;
    let expected_identity = match (entry.backup_device, entry.backup_inode, entry.backup_kind) {
        (Some(device), Some(inode), Some(kind)) => Some((device, inode, kind as crate::platform::ModeT)),
        (None, None, None) => None,
        _ => return Err("history recovery manifest entry identity is incomplete".into()),
    };
    match (&backup_group, expected_identity) {
        (Some(group), Some(expected)) => {
            let actual = AuthorityTreeSnapshot::stat_destination_at(group, &backup_name)
                .map_err(|error| format!("history recovery backup stat failed: {error}"))?;
            let actual_identity = (
                u64::try_from(actual.st_dev).ok(),
                super::authority_snapshot::inode_u64(actual.st_ino),
                actual.st_mode & crate::platform::S_IFMT,
            );
            if actual_identity != (Some(expected.0), Some(expected.1), expected.2) {
                return Err("history recovery backup identity changed".into());
            }
        }
        (Some(group), None) => {
            match AuthorityTreeSnapshot::stat_destination_at(group, &backup_name) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Ok(_) => return Err("history recovery found an unexpected backup entry".into()),
                Err(error) => {
                    return Err(format!(
                        "history recovery absent backup validation failed: {error}"
                    ))
                }
            }
        }
        (None, None) => {}
        (None, Some(_)) => return Err("history recovery backup group is missing".into()),
    }
    Ok(AuthorityTreeSnapshot {
        scope,
        source,
        backup,
        existed: entry.existed,
        source_parent,
        source_name,
        backup_identity: expected_identity,
        backup_parent: expected_identity.and(backup_group),
        backup_name: expected_identity.map(|_| backup_name),
    })
}

fn restore_history_authority_from_manifest(
    expected: &config::RuntimeTransactionV2,
    state: &SharedAppState,
) -> Result<(), String> {
    let ticket = expected
        .snapshot_ticket
        .as_ref()
        .ok_or("history recovery replay has no snapshot ticket")?;
    let opened = open_history_snapshot_root(state, ticket).map_err(String::from)?;
    if !opened.active_recovery {
        return Ok(());
    }
    let manifest = read_history_authority_manifest(&opened.root, expected, ticket)?;
    let sandbox_root = crate::runtime::science::sandbox_home();
    let auth_dir = sandbox_root.join(".claude-science");
    let snapshot_root = sandbox_root
        .parent()
        .ok_or("history recovery sandbox root has no parent")?
        .join(&ticket.managed_id);
    #[cfg(test)]
    let mut restored_entries = 0usize;
    for entry in manifest.entries {
        reopen_history_authority_entry(
            &opened.root,
            &entry,
            &snapshot_root,
            &sandbox_root,
            &auth_dir,
        )?
        .restore()?;
        #[cfg(test)]
        {
            restored_entries += 1;
            if restored_entries == 1
                && HISTORY_REPLAY_INTERRUPT_AFTER_FIRST_RESTORE
                    .swap(false, std::sync::atomic::Ordering::SeqCst)
            {
                return Err("test-only interrupted history authority restore".into());
            }
        }
    }
    Ok(())
}

fn begin_history_authority_restore(
    dir: &std::path::Path,
    expected: &config::RuntimeTransactionV2,
) -> Result<config::RuntimeTransactionV2, String> {
    update_history_record(dir, expected, |next| {
        if next.phase != config::RuntimeTransactionPhase::HistoryCredentialWritePending {
            return Err("history authority restore intent has an invalid predecessor".into());
        }
        next.phase = config::RuntimeTransactionPhase::HistoryAuthorityRestorePending;
        Ok(())
    })
}

fn finish_history_authority_restore(
    dir: &std::path::Path,
    expected: &config::RuntimeTransactionV2,
) -> Result<config::RuntimeTransactionV2, String> {
    update_history_record(dir, expected, |next| {
        if next.phase != config::RuntimeTransactionPhase::HistoryAuthorityRestorePending {
            return Err("history authority restore outcome has no durable intent".into());
        }
        next.phase = config::RuntimeTransactionPhase::HistoryAuthorityRestoreSucceeded;
        Ok(())
    })
}

fn replay_history_authority_restore(
    state: &SharedAppState,
    cfg: &config::Config,
    record: &config::RuntimeTransactionV2,
) -> Result<config::RuntimeTransactionV2, String> {
    require_current_science_quiescence(state, cfg.sandbox_port)?;
    let pending = match record.phase {
        config::RuntimeTransactionPhase::HistoryCredentialWritePending => {
            begin_history_authority_restore(&config::default_dir(), record)?
        }
        config::RuntimeTransactionPhase::HistoryAuthorityRestorePending => record.clone(),
        _ => return Err("history authority restore replay has an invalid phase".into()),
    };
    restore_history_authority_from_manifest(&pending, state)?;
    finish_history_authority_restore(&config::default_dir(), &pending)
}

fn finish_history_authority_restore_replay(
    state: &SharedAppState,
    record: &config::RuntimeTransactionV2,
) -> Result<(), String> {
    if record.phase != config::RuntimeTransactionPhase::HistoryAuthorityRestoreSucceeded {
        return Err("history authority restore cleanup has no durable outcome".into());
    }
    let ticket = record
        .snapshot_ticket
        .as_ref()
        .ok_or("history authority restore has no snapshot ticket")?;
    prepare_history_snapshot_cleanup_only(state, ticket).map_err(String::from)?;
    clear_history_record_with_authority(&config::default_dir(), record)?;
    retry_pending_authority_cleanup(state).map_err(String::from)?;
    Ok(())
}

fn begin_history_transaction(
    dir: &std::path::Path,
    config: &config::Config,
    prior_stop: config::RuntimePriorStopState,
) -> Result<config::RuntimeTransactionV2, String> {
    let config_authority_fingerprint = history_config_authority_fingerprint(config)?;
    config::update_result(dir, |current| {
        if current != config || current.has_open_runtime_journal() {
            return Err("history recovery config authority drifted before durable intent".into());
        }
        let record = config::RuntimeTransactionV2 {
            schema_version: config::RUNTIME_TRANSACTION_SCHEMA_VERSION_V2,
            transaction_id: config::new_id(),
            operation: config::RuntimeTransactionOperation::HistoryRecovery,
            target_profile_id: config.active_id.clone(),
            phase: config::RuntimeTransactionPhase::StopOldScience,
            runtime_fingerprint: Some(config_authority_fingerprint.clone()),
            environment_exposure: config::RuntimeEnvironmentExposure::NotExposed,
            snapshot_ticket: None,
            previous_binding: config.runtime_binding.clone(),
            previous_gateway: None,
            compensation: config::RuntimeCompensationState::NotStarted,
            gateway_stop_outcome: config::RuntimeGatewayStopOutcome::NotAttempted,
            prior_stop,
            finalize: config::RuntimeFinalizeState::NotStarted,
        };
        current.runtime_transaction = Some(config::RuntimeTransactionRecord::V2(record.clone()));
        Ok((record, true))
    })
}

fn update_history_record(
    dir: &std::path::Path,
    expected: &config::RuntimeTransactionV2,
    update: impl FnOnce(&mut config::RuntimeTransactionV2) -> Result<(), String>,
) -> Result<config::RuntimeTransactionV2, String> {
    config::update_result(dir, |current| {
        if !history_config_authority_matches(current, expected)
            || current.runtime_transaction.as_ref()
                != Some(&config::RuntimeTransactionRecord::V2(expected.clone()))
        {
            return Err(
                "history recovery complete-record identity drifted; preserved current state".into(),
            );
        }
        let mut next = expected.clone();
        update(&mut next)?;
        current.runtime_transaction = Some(config::RuntimeTransactionRecord::V2(next.clone()));
        Ok((next, true))
    })
}

fn publish_stop_outcome(
    dir: &std::path::Path,
    expected: &config::RuntimeTransactionV2,
    outcome: config::RuntimePriorStopOutcome,
) -> Result<config::RuntimeTransactionV2, String> {
    let recipe = match &expected.prior_stop {
        config::RuntimePriorStopState::Intent { recipe } => recipe.clone(),
        _ => return Err("history recovery stop outcome has no durable intent".into()),
    };
    update_history_record(dir, expected, |next| {
        next.prior_stop = config::RuntimePriorStopState::Outcome { recipe, outcome };
        Ok(())
    })
}

fn clear_history_record(
    dir: &std::path::Path,
    expected: &config::RuntimeTransactionV2,
) -> Result<(), String> {
    config::update_result(dir, |current| {
        if current.runtime_transaction.as_ref()
            != Some(&config::RuntimeTransactionRecord::V2(expected.clone()))
        {
            return Err("history recovery record drifted; preserved current state".into());
        }
        current.runtime_transaction = None;
        Ok(((), true))
    })
}

fn clear_history_record_with_authority(
    dir: &std::path::Path,
    expected: &config::RuntimeTransactionV2,
) -> Result<(), String> {
    config::update_result(dir, |current| {
        if !history_config_authority_matches(current, expected)
            || current.runtime_transaction.as_ref()
                != Some(&config::RuntimeTransactionRecord::V2(expected.clone()))
        {
            return Err(
                "history recovery replay authority drifted; preserved current state".into(),
            );
        }
        current.runtime_transaction = None;
        Ok(((), true))
    })
}

fn complete_history_finalize(
    dir: &std::path::Path,
    expected: &config::RuntimeTransactionV2,
) -> Result<Option<config::RuntimeTransactionV2>, String> {
    #[cfg(test)]
    if HISTORY_FINALIZE_COMPLETION_FAILURE.swap(false, std::sync::atomic::Ordering::SeqCst) {
        return Err("test-only history finalize completion failure".into());
    }
    let action = match &expected.finalize {
        config::RuntimeFinalizeState::Intent { action } => action.clone(),
        config::RuntimeFinalizeState::NotStarted => {
            return Err("history recovery finalize has no durable intent".into())
        }
    };
    config::update_result(dir, |current| {
        if !history_config_authority_matches(current, expected)
            || current.runtime_transaction.as_ref()
                != Some(&config::RuntimeTransactionRecord::V2(expected.clone()))
        {
            return Err("history recovery finalize record drifted; preserved current state".into());
        }
        match action {
            config::RuntimeFinalizeAction::ClearJournal => {
                current.runtime_transaction = None;
                Ok((None, true))
            }
            config::RuntimeFinalizeAction::ResumeOneClick => {
                let mut terminal = expected.clone();
                terminal.phase = config::RuntimeTransactionPhase::ResumeAfterHistoryRestore;
                terminal.snapshot_ticket = None;
                terminal.finalize = config::RuntimeFinalizeState::NotStarted;
                current.runtime_transaction =
                    Some(config::RuntimeTransactionRecord::V2(terminal.clone()));
                Ok((Some(terminal), true))
            }
            config::RuntimeFinalizeAction::CommitBinding { .. } => {
                Err("history recovery cannot finalize a runtime binding".into())
            }
        }
    })
}

fn compensate_history_failure<R: Runtime>(
    app: &tauri::AppHandle<R>,
    state: &SharedAppState,
    lifecycle: &lifecycle::Lifecycle,
    authority: &mut AuthorityTransaction,
    config_before: &config::Config,
    expected: &config::RuntimeTransactionV2,
) -> Result<(), String> {
    if matches!(
        expected.phase,
        config::RuntimeTransactionPhase::HistoryCredentialWritePending
            | config::RuntimeTransactionPhase::HistoryAuthorityRestorePending
    ) {
        let current =
            config::load_from(&config::default_dir()).map_err(|error| error.to_string())?;
        if !history_config_authority_matches(&current, expected)
            || current.runtime_transaction.as_ref()
                != Some(&config::RuntimeTransactionRecord::V2(expected.clone()))
        {
            authority.preserve_recovery();
            return Err(
                "history authority restore found drifted config authority; preserved current state"
                    .into(),
            );
        }
        let restored = replay_history_authority_restore(state, &current, expected)?;
        finish_history_authority_restore_replay(state, &restored)?;
        authority.commit();
        return Ok(());
    }
    let _effect_lease = config::acquire_runtime_history_effect_lease(&config::default_dir())
        .map_err(|error| format!("history compensation effect lease failed: {error}"))?;
    let mut expected_config = config_before.clone();
    expected_config.runtime_transaction =
        Some(config::RuntimeTransactionRecord::V2(expected.clone()));
    authority.restore(
        app,
        &config::default_dir(),
        state,
        lifecycle,
        None,
        ProxyAction::Reused,
        &RuntimeTransactionRestoreExpectation::ExactConfig(Box::new(expected_config)),
    )?;
    authority
        .cleanup_when_expendable()
        .map(|_| ())
        .map_err(String::from)
}

fn project_resume_failure(failure: TypedOneClickFailure) -> Value {
    let journal_open = config::load_from(&config::default_dir())
        .ok()
        .is_some_and(|cfg| cfg.has_open_runtime_journal());
    failure
        .apply_open_journal_degraded(journal_open)
        .project_dto()
}

fn require_current_science_quiescence(
    state: &SharedAppState,
    expected_port: u16,
) -> Result<(), String> {
    let version_cache = {
        let app_state = lock(state);
        if app_state.science_runtime.is_some() {
            return Err(
                "interrupted history recovery found a live managed Science runtime; preserved the exact journal"
                    .into(),
            );
        }
        app_state.science_version_cache.clone()
    };
    let (observed, runtime) = ScienceHostAdapter::probe_cached(expected_port, &version_cache)
        .map_err(|error| error.to_string())?;
    if observed != SandboxScienceState::Stopped || runtime.is_some() {
        return Err(
            "interrupted history recovery could not re-prove current Science quiescence; preserved the exact journal"
                .into(),
        );
    }
    Ok(())
}

pub(crate) fn replay_interrupted_history_recovery_before_auth(
    state: &SharedAppState,
) -> Result<bool, String> {
    let cfg = config::load_from(&config::default_dir()).map_err(|error| error.to_string())?;
    replay_interrupted_history_recovery(state, &cfg)
}

pub(crate) fn interrupted_history_recovery_requires_pre_auth_replay() -> Result<bool, String> {
    let cfg = config::load_from(&config::default_dir()).map_err(|error| error.to_string())?;
    Ok(matches!(
        cfg.runtime_transaction.as_ref(),
        Some(config::RuntimeTransactionRecord::V2(record))
            if record.operation == config::RuntimeTransactionOperation::HistoryRecovery
                && matches!(
                    record.phase,
                    config::RuntimeTransactionPhase::StopOldScience
                        | config::RuntimeTransactionPhase::AuthoritySnapshotActive
                        | config::RuntimeTransactionPhase::HistoryCredentialWritePending
                        | config::RuntimeTransactionPhase::HistoryAuthorityRestorePending
                        | config::RuntimeTransactionPhase::HistoryAuthorityRestoreSucceeded
                )
    ))
}

pub(crate) fn replay_interrupted_history_recovery(
    state: &SharedAppState,
    _cfg: &config::Config,
) -> Result<bool, String> {
    let _effect_lease = config::acquire_runtime_history_effect_lease(&config::default_dir())
        .map_err(|error| format!("history recovery effect lease failed: {error}"))?;
    let cfg = config::load_from(&config::default_dir()).map_err(|error| error.to_string())?;
    let Some(config::RuntimeTransactionRecord::V2(record)) = cfg.runtime_transaction.as_ref()
    else {
        return Ok(false);
    };
    if record.operation != config::RuntimeTransactionOperation::HistoryRecovery {
        return Ok(false);
    }
    if !history_config_authority_matches(&cfg, record) {
        return Err(
            "interrupted history recovery config authority drifted; preserved the exact journal"
                .into(),
        );
    }
    #[cfg(test)]
    apply_history_replay_sibling_config_writer(cfg.sandbox_port)?;
    match record.phase {
        config::RuntimeTransactionPhase::StopOldScience => {
            let safely_stopped = matches!(
                record.prior_stop,
                config::RuntimePriorStopState::NotRequired
                    | config::RuntimePriorStopState::Outcome {
                        outcome: config::RuntimePriorStopOutcome::ExactStopped
                            | config::RuntimePriorStopOutcome::NotStopped,
                        ..
                    }
            );
            if !safely_stopped {
                return Err("interrupted history stop outcome is uncertain; preserved the exact journal for manual recovery".into());
            }
            clear_history_record_with_authority(&config::default_dir(), record)?;
            Ok(true)
        }
        config::RuntimeTransactionPhase::AuthoritySnapshotActive => {
            let ticket = record
                .snapshot_ticket
                .as_ref()
                .ok_or("interrupted history snapshot phase has no ticket")?;
            prepare_history_snapshot_cleanup_only(state, ticket).map_err(String::from)?;
            clear_history_record_with_authority(&config::default_dir(), record)?;
            retry_pending_authority_cleanup(state).map_err(String::from)?;
            Ok(true)
        }
        config::RuntimeTransactionPhase::HistoryCredentialWritePending => {
            let restored = replay_history_authority_restore(state, &cfg, record)?;
            finish_history_authority_restore_replay(state, &restored)?;
            Ok(true)
        }
        config::RuntimeTransactionPhase::HistoryAuthorityRestorePending => {
            let restored = replay_history_authority_restore(state, &cfg, record)?;
            finish_history_authority_restore_replay(state, &restored)?;
            Ok(true)
        }
        config::RuntimeTransactionPhase::HistoryAuthorityRestoreSucceeded => {
            finish_history_authority_restore_replay(state, record)?;
            Ok(true)
        }
        config::RuntimeTransactionPhase::HistoryCredentialPublished
        | config::RuntimeTransactionPhase::ResumeAfterHistoryRestore => Ok(false),
        _ => Err("interrupted history transaction has an invalid phase".into()),
    }
}

#[allow(clippy::result_large_err)]
pub(crate) fn restore_history_choice_entry<R: Runtime>(
    app: tauri::AppHandle<R>,
    state: SharedAppState,
    lifecycle: &lifecycle::Lifecycle,
    reference: &str,
    resume: bool,
    auth_proof: Option<&crate::codex_auth_supervisor::CodexAuthReadyProof>,
) -> Result<Value, String> {
    let dir = config::default_dir();
    let cfg = config::load_from(&dir).map_err(|error| error.to_string())?;
    if cfg.mode != "proxy" {
        return Err("当前已不是第三方模型模式，本次历史恢复选择已作废".into());
    }
    if cfg.has_open_runtime_journal() {
        return Err("当前有新的运行事务尚未完成，已拒绝覆盖其历史身份".into());
    }
    let active_profile_id = cfg
        .active_profile()
        .map(|profile| profile.id.clone())
        .ok_or("当前选择已变化，本次历史恢复选择已作废")?;
    let (auth_dir, sandbox_root, candidate, expected_port, science_quiescence) = {
        let app_state = lock(&state);
        let session = app_state
            .history_recovery
            .as_ref()
            .ok_or("历史恢复选择已过期，请重新点击一键开始")?;
        if session.active_profile_id != active_profile_id
            || session.sandbox_port != cfg.sandbox_port
        {
            return Err("当前配置或端口已变化，本次历史恢复选择已作废".into());
        }
        let choice = session
            .choices
            .iter()
            .find(|choice| choice.reference == reference)
            .ok_or("历史恢复引用无效或已过期")?;
        (
            session.auth_dir.clone(),
            session.sandbox_root.clone(),
            choice.candidate.clone(),
            session.sandbox_port,
            session.science_quiescence.clone(),
        )
    };

    let running = {
        let app_state = lock(&state);
        app_state
            .science_runtime
            .clone()
            .map(|runtime| {
                let receipt = ScienceHostAdapter::managed_receipt(expected_port, &runtime)
                    .ok_or("历史恢复前无法取得 Science 的精确受管启动身份")?;
                let recipe = receipt.durable_prior_stop_recipe(&runtime, expected_port)?;
                Ok::<_, String>((runtime, receipt, recipe))
            })
            .transpose()?
    };
    let prior_stop = running
        .as_ref()
        .map(|(_, _, recipe)| config::RuntimePriorStopState::Intent {
            recipe: recipe.clone(),
        })
        .unwrap_or(config::RuntimePriorStopState::NotRequired);
    let mut record = begin_history_transaction(&dir, &cfg, prior_stop)?;

    if let Some((runtime, receipt, _)) = running.as_ref() {
        let stop_result = execute_transaction_science_stop_with(
            &state,
            lifecycle,
            TransactionScienceStopTarget::new(
                TransactionScienceStopBoundary::HistoryRecoveryPriorStop,
                runtime,
                expected_port,
            ),
            || {
                Ok(ScienceStopRequest::exact(
                    runtime,
                    ScienceStopOwnershipReceipt::from_managed_launch(receipt),
                ))
            },
            |request| ScienceHostAdapter::execute_stop(&app, request).into_parts(),
            |app_state, confirmed_runtime| {
                if confirmed_runtime == Some(runtime) {
                    if let Some(session) = app_state.history_recovery.as_mut() {
                        session.science_quiescence =
                            crate::HistoryRecoveryScienceQuiescence::ExactStopped(runtime.clone());
                    }
                }
            },
        );
        let durable_outcome = match &stop_result {
            Ok(_) => config::RuntimePriorStopOutcome::ExactStopped,
            Err(error) if error.confirmed_runtime() == Some(runtime) => {
                config::RuntimePriorStopOutcome::ExactStopped
            }
            Err(error) if error.kind() == ScienceStopFailureKind::RequestRejected => {
                config::RuntimePriorStopOutcome::NotStopped
            }
            Err(_) => config::RuntimePriorStopOutcome::Unknown,
        };
        record = publish_stop_outcome(&dir, &record, durable_outcome)?;
        if let Err(error) = stop_result {
            if durable_outcome == config::RuntimePriorStopOutcome::NotStopped {
                clear_history_record(&dir, &record)?;
            }
            return Err(error.to_string());
        }
    } else {
        let app_state = lock(&state);
        let version_cache = app_state.science_version_cache.clone();
        drop(app_state);
        let (observed, observed_runtime) =
            match ScienceHostAdapter::probe_cached(expected_port, &version_cache) {
                Ok(observed) => observed,
                Err(error) => {
                    clear_history_record(&dir, &record)?;
                    return Err(error.to_string());
                }
            };
        if observed != SandboxScienceState::Stopped || observed_runtime.is_some() {
            clear_history_record(&dir, &record)?;
            return Err("历史恢复前 Science typed quiescence 复核失败；已拒绝改写历史身份".into());
        }
        let app_state = lock(&state);
        match science_quiescence {
            crate::HistoryRecoveryScienceQuiescence::ExactStopped(expected)
                if app_state.science_confirmed_stopped.as_ref() == Some(&expected) => {}
            crate::HistoryRecoveryScienceQuiescence::NoManagedRuntimeObserved
                if app_state.science_confirmed_stopped.is_none() => {}
            _ => {
                drop(app_state);
                clear_history_record(&dir, &record)?;
                return Err("历史恢复的 Science quiescence 状态已变化，本次选择已作废".into());
            }
        }
    }

    #[cfg(test)]
    apply_history_restore_post_stop_config_drift(expected_port)?;
    let current_cfg = config::load_from(&dir).map_err(|error| error.to_string())?;
    if current_cfg.mode != "proxy"
        || current_cfg.sandbox_port != expected_port
        || current_cfg.active_id != active_profile_id
        || current_cfg.runtime_binding != cfg.runtime_binding
        || current_cfg.runtime_transaction.as_ref()
            != Some(&config::RuntimeTransactionRecord::V2(record.clone()))
    {
        if current_cfg.runtime_transaction.as_ref()
            == Some(&config::RuntimeTransactionRecord::V2(record.clone()))
        {
            let _ = clear_history_record(&dir, &record);
        }
        return Err("运行配置或事务在恢复前已变化，本次选择已作废".into());
    }

    let mut authority =
        match AuthorityTransaction::capture(&dir, &sandbox_root, &auth_dir, &cfg, &state) {
            Ok(authority) => authority,
            Err(error) => {
                let _ = clear_history_record(&dir, &record);
                return Err(if error.contains("symlink") {
                    format!("历史恢复快照拒绝符号链接：{error}")
                } else {
                    error
                });
            }
        };
    let ticket = match authority.registered_snapshot_ticket() {
        Ok(ticket) => ticket,
        Err(error) => {
            return match compensate_history_failure(
                &app,
                &state,
                lifecycle,
                &mut authority,
                &cfg,
                &record,
            ) {
                Ok(()) => Err(error),
                Err(compensation) => {
                    authority.preserve_recovery();
                    Err(format!(
                        "{error}；history snapshot ticket compensation incomplete: {compensation}"
                    ))
                }
            };
        }
    };
    record = match update_history_record(&dir, &record, |next| {
        next.phase = config::RuntimeTransactionPhase::AuthoritySnapshotActive;
        next.snapshot_ticket = Some(ticket.clone());
        Ok(())
    }) {
        Ok(next) => next,
        Err(error) => {
            return match compensate_history_failure(
                &app,
                &state,
                lifecycle,
                &mut authority,
                &cfg,
                &record,
            ) {
                Ok(()) => Err(error),
                Err(compensation) => {
                    authority.preserve_recovery();
                    Err(format!(
                        "{error}；history snapshot registration compensation incomplete: {compensation}"
                    ))
                }
            };
        }
    };

    if let Err(error) =
        persist_history_authority_manifest(&authority, &record, &ticket, &sandbox_root, &auth_dir)
    {
        return match compensate_history_failure(
            &app,
            &state,
            lifecycle,
            &mut authority,
            &cfg,
            &record,
        ) {
            Ok(()) => Err(error),
            Err(compensation) => {
                authority.preserve_recovery();
                Err(format!(
                    "{error}；history recovery manifest compensation incomplete: {compensation}"
                ))
            }
        };
    }
    record = match update_history_record(&dir, &record, |next| {
        next.phase = config::RuntimeTransactionPhase::HistoryCredentialWritePending;
        Ok(())
    }) {
        Ok(next) => next,
        Err(error) => {
            return match compensate_history_failure(
                &app,
                &state,
                lifecycle,
                &mut authority,
                &cfg,
                &record,
            ) {
                Ok(()) => Err(error),
                Err(compensation) => {
                    authority.preserve_recovery();
                    Err(format!(
                        "{error}；history credential intent compensation incomplete: {compensation}"
                    ))
                }
            };
        }
    };

    let history_effect_lease = config::acquire_runtime_history_effect_lease(&dir)
        .map_err(|error| format!("history credential effect lease failed: {error}"))?;
    let owned_cfg = config::load_from(&dir).map_err(|error| error.to_string())?;
    if !history_config_authority_matches(&owned_cfg, &record)
        || owned_cfg.runtime_transaction.as_ref()
            != Some(&config::RuntimeTransactionRecord::V2(record.clone()))
    {
        authority.preserve_recovery();
        return Err(
            "history credential effect owner found a drifted transaction; preserved current state"
                .into(),
        );
    }

    #[cfg(test)]
    if let Err(error) = apply_history_restore_post_snapshot_config_drift() {
        return match compensate_history_failure(
            &app,
            &state,
            lifecycle,
            &mut authority,
            &cfg,
            &record,
        ) {
            Ok(()) => Err(error),
            Err(compensation) => {
                authority.preserve_recovery();
                Err(format!(
                    "{error}；history concurrent-config compensation incomplete: {compensation}"
                ))
            }
        };
    }

    let authority_bypass = history_effect_lease.authority_writer_bypass();
    if let Err(error) = oauth_forge::restore_history_choice_with_authority_bypass(
        &auth_dir,
        "virtual@localhost.invalid",
        &sandbox_root,
        &candidate,
        &authority_bypass,
    ) {
        return match compensate_history_failure(
            &app,
            &state,
            lifecycle,
            &mut authority,
            &cfg,
            &record,
        ) {
            Ok(()) => Err(error),
            Err(compensation) => {
                authority.preserve_recovery();
                Err(format!(
                    "{error}；history recovery compensation incomplete: {compensation}"
                ))
            }
        };
    }

    #[cfg(test)]
    if HISTORY_RESTORE_INTERRUPT_AFTER_CREDENTIAL_WRITE
        .swap(false, std::sync::atomic::Ordering::SeqCst)
    {
        authority.preserve_recovery();
        return Err("test-only interrupted history credential publication".into());
    }

    let action = if resume {
        config::RuntimeFinalizeAction::ResumeOneClick
    } else {
        config::RuntimeFinalizeAction::ClearJournal
    };
    record = match update_history_record(&dir, &record, |next| {
        next.phase = config::RuntimeTransactionPhase::HistoryCredentialPublished;
        next.finalize = config::RuntimeFinalizeState::Intent { action };
        Ok(())
    }) {
        Ok(next) => next,
        Err(error) => {
            return match compensate_history_failure(
                &app,
                &state,
                lifecycle,
                &mut authority,
                &cfg,
                &record,
            ) {
                Ok(()) => Err(error),
                Err(compensation) => {
                    authority.preserve_recovery();
                    Err(format!(
                        "{error}；history credential publication compensation incomplete: {compensation}"
                    ))
                }
            };
        }
    };
    crate::clear_boot_attention(&app);
    let refreshed_choices = {
        let mut app_state = lock(&state);
        let session = app_state
            .history_recovery
            .as_mut()
            .ok_or("历史恢复会话已过期")?;
        session
            .choices
            .iter_mut()
            .enumerate()
            .map(|(index, choice)| {
                choice.reference = config::new_id();
                let label = if index < 26 {
                    format!("历史记录 {}", (b'A' + index as u8) as char)
                } else {
                    format!("历史记录 {}", index + 1)
                };
                json!({"reference": choice.reference, "label": label})
            })
            .collect::<Vec<_>>()
    };
    let mut value = json!({
        "status": "ok",
        "recovery_status": "not_needed",
        "action": "history_choice_restored",
        "message": "已恢复所选历史记录；其他历史记录未被删除。",
        "choices": refreshed_choices
    });
    value["history_recovery"] = json!({
        "status": "restored",
        "choices": value["choices"].clone()
    });
    if let Err(error) = authority.prepare_success(&mut value) {
        authority.preserve_recovery();
        value["status"] = json!("degraded");
        value["recovery_status"] = json!("manual_recovery_required");
        value["message"] = json!(format!(
            "历史记录已恢复，但 snapshot cleanup 准备失败：{error}"
        ));
        return Ok(value);
    }
    let terminal = match complete_history_finalize(&dir, &record) {
        Ok(terminal) => terminal,
        Err(error) => {
            value["status"] = json!("degraded");
            value["recovery_status"] = json!("manual_recovery_required");
            value["message"] = json!(format!(
                "历史记录已恢复，但 durable finalize 尚未完成：{error}"
            ));
            return Ok(value);
        }
    };
    authority.commit();
    drop(history_effect_lease);
    let Some(handoff) = terminal else {
        return Ok(value);
    };
    match one_click_login_after_history_handoff(app, state, lifecycle, None, auth_proof, handoff) {
        Ok(mut resumed) => {
            resumed["history_recovery"] = json!({
                "status": "restored",
                "choices": value["choices"].clone()
            });
            Ok(resumed)
        }
        Err(failure) => {
            let mut projected = project_resume_failure(failure);
            projected["history_recovery"] = json!({
                "status": "restored",
                "choices": value["choices"].clone()
            });
            Ok(projected)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> config::Config {
        let (model_catalog, default_model_route_id, role_bindings) =
            crate::model_catalog::new_profile_catalog(
                "deepseek",
                "anthropic",
                Some("deepseek-v4-flash"),
            )
            .unwrap();
        config::Config {
            profiles: vec![config::Profile {
                id: "history-target".into(),
                template_id: "deepseek".into(),
                api_format: "anthropic".into(),
                model: "deepseek-v4-flash".into(),
                model_catalog,
                default_model_route_id,
                role_bindings,
                model_policy: crate::provider_contracts::ModelPolicy::SavedCatalog,
                ..Default::default()
            }],
            active_id: "history-target".into(),
            ..Default::default()
        }
    }

    #[test]
    fn history_resume_handoff_advances_only_by_complete_record_cas() {
        let dir = std::env::temp_dir().join(format!(
            "csswitch-history-journal-{}-{}",
            std::process::id(),
            config::new_id()
        ));
        let cfg = test_config();
        config::save_to(&dir, &cfg).unwrap();
        let mut record =
            begin_history_transaction(&dir, &cfg, config::RuntimePriorStopState::NotRequired)
                .unwrap();
        let ticket = config::RuntimeSnapshotTicket::verified(
            ".one-click-rollback-0123456789abcdef0123456789abcdef".into(),
        )
        .unwrap();
        record = update_history_record(&dir, &record, |next| {
            next.phase = config::RuntimeTransactionPhase::AuthoritySnapshotActive;
            next.snapshot_ticket = Some(ticket.clone());
            Ok(())
        })
        .unwrap();
        let sibling_write = config::update(&dir, |current| {
            current.reuse_system_ssh = !current.reuse_system_ssh
        })
        .unwrap_err();
        assert!(sibling_write
            .to_string()
            .contains("拒绝 sibling config writer"));
        let mut drifted_config = config::load_from(&dir).unwrap();
        drifted_config.reuse_system_ssh = !drifted_config.reuse_system_ssh;
        config::test_save_to_without_history_authority_guard(&dir, &drifted_config).unwrap();
        assert!(update_history_record(&dir, &record, |next| {
            next.phase = config::RuntimeTransactionPhase::HistoryCredentialPublished;
            next.finalize = config::RuntimeFinalizeState::Intent {
                action: config::RuntimeFinalizeAction::ResumeOneClick,
            };
            Ok(())
        })
        .is_err());
        let mut restored_config = config::load_from(&dir).unwrap();
        restored_config.reuse_system_ssh = cfg.reuse_system_ssh;
        config::test_save_to_without_history_authority_guard(&dir, &restored_config).unwrap();
        record = update_history_record(&dir, &record, |next| {
            next.phase = config::RuntimeTransactionPhase::HistoryCredentialPublished;
            next.finalize = config::RuntimeFinalizeState::Intent {
                action: config::RuntimeFinalizeAction::ResumeOneClick,
            };
            Ok(())
        })
        .unwrap();
        let mut drifted_config = config::load_from(&dir).unwrap();
        drifted_config.mode = "official".into();
        config::test_save_to_without_history_authority_guard(&dir, &drifted_config).unwrap();
        assert!(complete_history_finalize(&dir, &record).is_err());
        assert_eq!(
            config::load_from(&dir).unwrap().runtime_transaction,
            Some(config::RuntimeTransactionRecord::V2(record.clone()))
        );
        let mut restored_config = config::load_from(&dir).unwrap();
        restored_config.mode = cfg.mode.clone();
        config::test_save_to_without_history_authority_guard(&dir, &restored_config).unwrap();
        let terminal = complete_history_finalize(&dir, &record)
            .unwrap()
            .expect("resume finalize must publish a terminal handoff");
        assert_eq!(
            terminal.phase,
            config::RuntimeTransactionPhase::ResumeAfterHistoryRestore
        );
        assert!(terminal.snapshot_ticket.is_none());
        assert_eq!(terminal.finalize, config::RuntimeFinalizeState::NotStarted);
        assert_eq!(
            config::load_from(&dir).unwrap().runtime_transaction,
            Some(config::RuntimeTransactionRecord::V2(terminal.clone()))
        );

        let mut drifted = terminal.clone();
        drifted.transaction_id = "replacement".into();
        assert!(clear_history_record(&dir, &drifted).is_err());
        assert_eq!(
            config::load_from(&dir).unwrap().runtime_transaction,
            Some(config::RuntimeTransactionRecord::V2(terminal))
        );
        std::fs::remove_dir_all(dir).unwrap();
    }
}
