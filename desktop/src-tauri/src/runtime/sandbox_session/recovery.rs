//! Recovery projection orchestration: app/config snapshots and one-click authority capture/restore.
//! Coordinates `authority_snapshot` primitives with `pending_cleanup` registration.

#[cfg(not(unix))]
use crate::platform::UnixCompatExt;

use std::io::Read;
#[cfg(unix)]
use std::os::fd::AsRawFd;
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tauri::Runtime;

use crate::config;
#[cfg(test)]
use crate::proc;
#[cfg(test)]
use crate::runtime::operation;
use crate::runtime::proxy::ProxyAction;
use crate::runtime::proxy_lifecycle::GatewayController;
use crate::runtime::science::ScienceRuntimeIdentity;
use crate::{lifecycle, lock, HistoryRecoverySession, SharedAppState};

#[cfg(test)]
use super::authority_snapshot::SANDBOX_SESSION_TEST_SEAMS;
use super::authority_snapshot::{
    inode_u64, AuthorityCopyBudget, AuthoritySnapshotCategory, AuthoritySnapshotScope,
    AuthorityTreeSnapshot, SCIENCE_OWNED_OPAQUE_ROOTS, SCIENCE_PROTECTED_AUTHORITY_ENTRIES,
};
use super::pending_cleanup::{
    finalize_failed_authority_snapshot, finalize_registered_authority_cleanup,
    prepare_registered_authority_cleanup, register_authority_cleanup,
    registered_authority_snapshot_for_ticket, AuthorityCleanupContext, AuthorityCleanupFailure,
    AuthorityCleanupOutcome, AuthorityCleanupPhase, PendingCleanupDisposition,
    RegisteredAuthorityCleanup,
};

pub(super) const DURABLE_AUTHORITY_REPLAY_MANIFEST: &str = "authority-replay.v2.json";
const DURABLE_AUTHORITY_RESTORE_RESERVATION: &str = "authority-restore-reservation.v1.json";
const DURABLE_AUTHORITY_RESERVATION_SCHEMA_VERSION: u32 = 2;
const DURABLE_AUTHORITY_RESTORE_EFFECT_PREFIX: &str = "authority-restore-effect.v1";
const MAX_DURABLE_PRIVATE_MANIFEST_BYTES: u64 = config::MAX_CONFIG_FILE_BYTES + 1024 * 1024;

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DurableAuthorityTreeV2 {
    scope: AuthoritySnapshotScope,
    source: PathBuf,
    backup_relative: PathBuf,
    existed: bool,
    source_parent_identity: Option<(u64, u64)>,
    backup_identity: Option<(u64, u64, crate::platform::ModeT)>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DurableAuthorityReplayManifestV2 {
    schema_version: u32,
    managed_id: String,
    config: config::Config,
    trees: Vec<DurableAuthorityTreeV2>,
    science_root_path: PathBuf,
    science_root_identity: Option<(u64, u64)>,
    science_opaque_bindings: [Option<(u64, u64)>; SCIENCE_OWNED_OPAQUE_ROOTS.len()],
}

#[derive(Clone)]
pub(super) struct AuthorityRestoreReplayInputs {
    pub(super) sandbox_port: u16,
    pub(super) compensation_id: String,
    pub(super) snapshot_ticket: config::RuntimeSnapshotTicket,
}

/// A durable, deliberately small description of a name that the authority
/// replay is allowed to move.  It is not a pathname CAS: the compensation EX
/// lease serializes cooperating writers; a same-UID non-cooperating pathname
/// attacker remains an explicit fail-closed case.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
enum DurableAuthorityTargetIdentity {
    Absent,
    Entry {
        device: u64,
        inode: u64,
        kind: crate::platform::ModeT,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct DurableScienceQuiescenceReservation {
    schema_version: u32,
    compensation_id: String,
    snapshot_ticket: config::RuntimeSnapshotTicket,
    sandbox_port: u16,
    targets: Vec<DurableAuthorityTargetIdentity>,
    target_content_digests: Vec<Option<String>>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum DurableAuthorityEffectPhase {
    StageIntent,
    Staged,
    TombstoneIntent,
    Tombstoned,
    OutcomeIntent,
    Outcome,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct DurableAuthorityEffectMarker {
    schema_version: u32,
    compensation_id: String,
    snapshot_ticket: config::RuntimeSnapshotTicket,
    target: usize,
    phase: DurableAuthorityEffectPhase,
    identity: DurableAuthorityTargetIdentity,
}

pub(super) fn read_registered_private_manifest(
    state: &SharedAppState,
    ticket: &config::RuntimeSnapshotTicket,
    name: &str,
) -> Result<Vec<u8>, String> {
    let (pending, _, _, root) =
        registered_authority_snapshot_for_ticket(state, ticket).map_err(String::from)?;
    if !matches!(
        pending.disposition,
        Some(PendingCleanupDisposition::ActiveRecovery | PendingCleanupDisposition::CleanupOnly)
    ) {
        return Err("private replay manifest requires a registered snapshot".into());
    }
    let name =
        std::ffi::CString::new(name).map_err(|_| "private replay manifest name is invalid")?;
    let mut file =
        AuthorityTreeSnapshot::open_destination_at(root.as_raw_fd(), &name, crate::platform::O_RDONLY, 0)
            .map_err(|error| format!("private replay manifest open failed: {error}"))?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("private replay manifest metadata failed: {error}"))?;
    if !metadata.is_file()
        || metadata.uid() != unsafe { crate::platform::geteuid() }
        || metadata.permissions().mode() & 0o777 != 0o600
        || metadata.nlink() != 1
        || metadata.len() == 0
        || metadata.len() > MAX_DURABLE_PRIVATE_MANIFEST_BYTES
    {
        return Err("private replay manifest identity is unsafe".into());
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    (&mut file)
        .take(MAX_DURABLE_PRIVATE_MANIFEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("private replay manifest read failed: {error}"))?;
    let after = file
        .metadata()
        .map_err(|error| format!("private replay manifest recheck failed: {error}"))?;
    if after.dev() != metadata.dev()
        || after.ino() != metadata.ino()
        || after.len() != metadata.len()
        || bytes.len() as u64 != metadata.len()
    {
        return Err("private replay manifest changed while reading".into());
    }
    Ok(bytes)
}

#[allow(clippy::large_enum_variant)]
pub(super) enum RuntimeTransactionRestoreExpectation {
    Exact(Option<config::RuntimeTransactionRecord>),
    ExactPreservingCompensation {
        runtime_transaction: Option<config::RuntimeTransactionRecord>,
        compensation: config::RuntimeCompensationJournal,
    },
    ExactConfig(Box<config::Config>),
}

pub(super) struct AppAuthoritySnapshot {
    pub(super) proxy_present: bool,
    pub(super) proxy_port: u16,
    pub(super) secret: String,
    pub(super) provider: String,
    pub(super) gateway_kind: String,
    pub(super) shim_mode: String,
    pub(super) launch_id: String,
    pub(super) key_fp: u64,
    pub(super) gateway_launch_context: Option<crate::runtime::proxy_lifecycle::GatewayLaunchRecipe>,
    pub(super) sandbox_present: bool,
    pub(super) sandbox_port: u16,
    pub(super) sandbox_url: Option<String>,
    pub(super) science_runtime: Option<ScienceRuntimeIdentity>,
    pub(super) science_confirmed_stopped: Option<ScienceRuntimeIdentity>,
    pub(super) history_recovery: Option<HistoryRecoverySession>,
    pub(super) pending_authority_cleanup: Vec<PathBuf>,
}

impl AppAuthoritySnapshot {
    pub(super) fn capture(state: &SharedAppState) -> Self {
        let state = lock(state);
        Self {
            proxy_present: state.proxy.is_some(),
            proxy_port: state.proxy_port,
            secret: state.secret.clone(),
            provider: state.provider.clone(),
            gateway_kind: state.gateway_kind.clone(),
            shim_mode: state.shim_mode.clone(),
            launch_id: state.launch_id.clone(),
            key_fp: state.key_fp,
            gateway_launch_context: state.gateway_launch_context.clone(),
            sandbox_present: state.sandbox.is_some(),
            sandbox_port: state.sandbox_port,
            sandbox_url: state.sandbox_url.clone(),
            science_runtime: state.science_runtime.clone(),
            science_confirmed_stopped: state.science_confirmed_stopped.clone(),
            history_recovery: state.history_recovery.clone(),
            pending_authority_cleanup: state.pending_authority_cleanup.clone(),
        }
    }

    #[cfg(test)]
    pub(super) fn restore(
        &self,
        state: &SharedAppState,
        proxy_action: ProxyAction,
    ) -> Result<(), String> {
        let mut current = lock(state);
        if proxy_action == ProxyAction::Restarted {
            current
                .stop_proxy()
                .require_stopped("测试补偿恢复前无法安全停止 Gateway")?;
        }
        if current.sandbox.is_some() && !self.sandbox_present {
            return Err("late-failure 补偿发现未预期的 Science child，拒绝伪造恢复状态".into());
        }
        if self.proxy_present != current.proxy.is_some() {
            return Err("late-failure 补偿无法恢复先前 Gateway child 所有权".into());
        }
        current.proxy_port = self.proxy_port;
        current.secret = self.secret.clone();
        current.provider = self.provider.clone();
        current.gateway_kind = self.gateway_kind.clone();
        current.shim_mode = self.shim_mode.clone();
        current.launch_id = self.launch_id.clone();
        current.key_fp = self.key_fp;
        current.gateway_launch_context = self.gateway_launch_context.clone();
        current.sandbox_port = self.sandbox_port;
        current.sandbox_url = self.sandbox_url.clone();
        current.science_runtime = self.science_runtime.clone();
        current.science_confirmed_stopped = self.science_confirmed_stopped.clone();
        current.history_recovery = self.history_recovery.clone();
        current.pending_authority_cleanup = self.pending_authority_cleanup.clone();
        Ok(())
    }

    pub(super) fn restore_with_gateway<R: Runtime>(
        &self,
        app: &tauri::AppHandle<R>,
        state: &SharedAppState,
        lifecycle: &lifecycle::Lifecycle,
        auth_proof: Option<&crate::codex_auth_supervisor::CodexAuthReadyProof>,
        proxy_action: ProxyAction,
    ) -> Result<(), String> {
        if proxy_action == ProxyAction::Restarted {
            lock(state)
                .stop_proxy()
                .require_stopped("late-failure 补偿恢复前无法安全停止 Gateway")?;
        }
        if self.proxy_present {
            let context = self
                .gateway_launch_context
                .as_ref()
                .ok_or("late-failure 补偿缺少先前 Gateway 内存启动上下文")?;
            GatewayController::start_for(
                app,
                state,
                lifecycle,
                &context.profile,
                context.science_runtime.as_ref(),
                None,
                auth_proof,
            )
            .map_err(|error| format!("late-failure 补偿无法重启先前 Gateway：{error}"))?;
            if lock(state).proxy.is_none() {
                return Err("late-failure 补偿未恢复先前 Gateway child 所有权".into());
            }
        } else {
            let mut current = lock(state);
            if current.proxy.is_some() {
                return Err("late-failure 补偿发现未预期的 Gateway child".into());
            }
            current.proxy_port = self.proxy_port;
            current.secret = self.secret.clone();
            current.provider = self.provider.clone();
            current.gateway_kind = self.gateway_kind.clone();
            current.shim_mode = self.shim_mode.clone();
            current.launch_id = self.launch_id.clone();
            current.key_fp = self.key_fp;
            current.gateway_launch_context = self.gateway_launch_context.clone();
        }
        let mut current = lock(state);
        if current.sandbox.is_some() && !self.sandbox_present {
            return Err("late-failure 补偿发现未预期的 Science child，拒绝伪造恢复状态".into());
        }
        current.sandbox_port = self.sandbox_port;
        current.sandbox_url = self.sandbox_url.clone();
        current.science_runtime = self.science_runtime.clone();
        current.science_confirmed_stopped = self.science_confirmed_stopped.clone();
        current.history_recovery = self.history_recovery.clone();
        current.pending_authority_cleanup = self.pending_authority_cleanup.clone();
        Ok(())
    }
}

pub(super) struct OneClickAuthoritySnapshot {
    pub(super) backup_root: PathBuf,
    pub(super) cleanup_context: AuthorityCleanupContext,
    pub(super) cleanup_ticket: Option<RegisteredAuthorityCleanup>,
    pub(super) trees: Vec<AuthorityTreeSnapshot>,
    pub(super) science_root_path: PathBuf,
    pub(super) science_root: Option<std::fs::File>,
    pub(super) science_opaque_bindings: [Option<(u64, u64)>; SCIENCE_OWNED_OPAQUE_ROOTS.len()],
    pub(super) config: config::Config,
    pub(super) app: AppAuthoritySnapshot,
    pub(super) preserve_recovery: bool,
    pub(super) cleanup_prepared: bool,
}

impl OneClickAuthoritySnapshot {
    pub(super) fn load_durable(
        state: &SharedAppState,
        ticket: &config::RuntimeSnapshotTicket,
    ) -> Result<Self, String> {
        let (pending, cleanup_context, cleanup_ticket, root) =
            registered_authority_snapshot_for_ticket(state, ticket).map_err(String::from)?;
        if pending.disposition != Some(PendingCleanupDisposition::ActiveRecovery) {
            return Err("durable authority replay requires an ActiveRecovery snapshot".into());
        }
        let name = std::ffi::CString::new(DURABLE_AUTHORITY_REPLAY_MANIFEST).unwrap();
        let mut file =
            AuthorityTreeSnapshot::open_destination_at(root.as_raw_fd(), &name, crate::platform::O_RDONLY, 0)
                .map_err(|error| {
                    format!("durable authority replay manifest open failed: {error}")
                })?;
        let metadata = file.metadata().map_err(|error| {
            format!("durable authority replay manifest metadata failed: {error}")
        })?;
        if !metadata.is_file()
            || metadata.uid() != unsafe { crate::platform::geteuid() }
            || metadata.permissions().mode() & 0o777 != 0o600
            || metadata.nlink() != 1
            || metadata.len() == 0
            || metadata.len() > MAX_DURABLE_PRIVATE_MANIFEST_BYTES
        {
            return Err("durable authority replay manifest identity is unsafe".into());
        }
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        (&mut file)
            .take(MAX_DURABLE_PRIVATE_MANIFEST_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| format!("durable authority replay manifest read failed: {error}"))?;
        let after = file.metadata().map_err(|error| {
            format!("durable authority replay manifest recheck failed: {error}")
        })?;
        if after.dev() != metadata.dev()
            || after.ino() != metadata.ino()
            || after.len() != metadata.len()
            || bytes.len() as u64 != metadata.len()
        {
            return Err("durable authority replay manifest changed while reading".into());
        }
        let manifest: DurableAuthorityReplayManifestV2 = serde_json::from_slice(&bytes)
            .map_err(|_| "durable authority replay manifest format is invalid")?;
        if manifest.schema_version != 2
            || manifest.managed_id != ticket.managed_id
            || manifest.managed_id != cleanup_context.managed_id
        {
            return Err("durable authority replay manifest identity mismatch".into());
        }
        let config_dir = config::default_dir();
        let sandbox_home = crate::runtime::science::sandbox_home();
        let expected_science_root = sandbox_home.join(".claude-science");
        if manifest.science_root_path != expected_science_root {
            return Err("durable authority replay Science root retargeted".into());
        }
        let mut expected_trees = SCIENCE_PROTECTED_AUTHORITY_ENTRIES
            .into_iter()
            .map(|entry| {
                (
                    AuthoritySnapshotScope::ScienceData,
                    expected_science_root.join(entry),
                    PathBuf::from("0").join(entry),
                )
            })
            .collect::<Vec<_>>();
        expected_trees.extend([
            (
                AuthoritySnapshotScope::SandboxState,
                sandbox_home
                    .parent()
                    .ok_or("sandbox HOME has no parent")?
                    .join("state"),
                PathBuf::from("1"),
            ),
            (
                AuthoritySnapshotScope::CsswitchRuntime,
                config_dir.join("runtime"),
                PathBuf::from("2"),
            ),
            (
                AuthoritySnapshotScope::ManagedReceipt,
                config_dir.join("science-managed-launch.v1.json"),
                PathBuf::from("3"),
            ),
        ]);
        if manifest.trees.len() != expected_trees.len() {
            return Err("durable authority replay tree plan length mismatch".into());
        }
        let mut trees = Vec::with_capacity(manifest.trees.len());
        for (tree, (scope, source, backup_relative)) in
            manifest.trees.into_iter().zip(expected_trees)
        {
            if tree.scope != scope
                || tree.source != source
                || tree.backup_relative != backup_relative
                || tree.backup_relative.is_absolute()
                || tree
                    .backup_relative
                    .components()
                    .any(|component| !matches!(component, std::path::Component::Normal(_)))
                || tree.existed != tree.backup_identity.is_some()
            {
                return Err("durable authority replay tree plan retargeted".into());
            }
            let source_parent = match tree.source_parent_identity {
                Some(expected) => {
                    let parent_path = tree
                        .source
                        .parent()
                        .ok_or("durable authority replay source parent missing")?;
                    let parent = AuthorityTreeSnapshot::open_absolute_directory(parent_path)
                        .map_err(|error| {
                            format!("durable authority replay source parent open failed: {error}")
                        })?;
                    let metadata = parent.metadata().map_err(|error| {
                        format!("durable authority replay source parent metadata failed: {error}")
                    })?;
                    if (metadata.dev(), metadata.ino()) != expected {
                        return Err(
                            "durable authority replay source parent identity changed".into()
                        );
                    }
                    Some(parent)
                }
                None => None,
            };
            let source_name = source_parent
                .as_ref()
                .map(|_| AuthorityTreeSnapshot::destination_name(&tree.source))
                .transpose()?;
            let backup = cleanup_context.root.join(&tree.backup_relative);
            let (backup_parent, backup_name) = if tree.existed {
                let parent_path = backup
                    .parent()
                    .ok_or("durable authority replay backup parent missing")?;
                let parent = AuthorityTreeSnapshot::open_absolute_directory(parent_path).map_err(
                    |error| format!("durable authority replay backup parent open failed: {error}"),
                )?;
                let name = AuthorityTreeSnapshot::destination_name(&backup)?;
                (Some(parent), Some(name))
            } else {
                (None, None)
            };
            trees.push(AuthorityTreeSnapshot {
                scope: tree.scope,
                source: tree.source,
                backup,
                existed: tree.existed,
                source_parent,
                source_name,
                backup_identity: tree.backup_identity,
                backup_parent,
                backup_name,
            });
        }
        let science_root = match manifest.science_root_identity {
            Some(expected) => {
                let root = AuthorityTreeSnapshot::open_absolute_directory(&expected_science_root)
                    .map_err(|error| {
                    format!("durable authority replay Science root open failed: {error}")
                })?;
                let metadata = root.metadata().map_err(|error| {
                    format!("durable authority replay Science root metadata failed: {error}")
                })?;
                if (metadata.dev(), metadata.ino()) != expected {
                    return Err("durable authority replay Science root identity changed".into());
                }
                Some(root)
            }
            None => match AuthorityTreeSnapshot::open_absolute_directory(&expected_science_root) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                Ok(_) => return Err("durable authority replay Science root appeared".into()),
                Err(error) => {
                    return Err(format!(
                        "durable authority replay Science root check failed: {error}"
                    ))
                }
            },
        };
        if Self::science_opaque_root_bindings(science_root.as_ref())?
            != manifest.science_opaque_bindings
        {
            return Err("durable authority replay Science opaque binding changed".into());
        }
        Ok(Self {
            backup_root: cleanup_context.root.clone(),
            cleanup_context,
            cleanup_ticket: Some(cleanup_ticket),
            trees,
            science_root_path: expected_science_root,
            science_root,
            science_opaque_bindings: manifest.science_opaque_bindings,
            config: manifest.config,
            app: AppAuthoritySnapshot::capture(state),
            preserve_recovery: true,
            cleanup_prepared: false,
        })
    }

    fn durable_replay_manifest_bytes(&self) -> Result<Vec<u8>, String> {
        let trees = self
            .trees
            .iter()
            .map(|tree| {
                let backup_relative = tree
                    .backup
                    .strip_prefix(&self.backup_root)
                    .map_err(|_| "durable authority backup escaped the registered snapshot")?
                    .to_path_buf();
                if backup_relative.as_os_str().is_empty()
                    || backup_relative.is_absolute()
                    || backup_relative
                        .components()
                        .any(|component| !matches!(component, std::path::Component::Normal(_)))
                {
                    return Err("durable authority backup relative path is invalid".into());
                }
                let source_parent_identity = tree
                    .source_parent
                    .as_ref()
                    .map(|parent| {
                        let metadata = parent.metadata().map_err(|error| {
                            format!("durable authority source parent metadata failed: {error}")
                        })?;
                        Ok::<_, String>((metadata.dev(), metadata.ino()))
                    })
                    .transpose()?;
                Ok(DurableAuthorityTreeV2 {
                    scope: tree.scope,
                    source: tree.source.clone(),
                    backup_relative,
                    existed: tree.existed,
                    source_parent_identity,
                    backup_identity: tree.backup_identity,
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        let science_root_identity = self
            .science_root
            .as_ref()
            .map(|root| {
                let metadata = root
                    .metadata()
                    .map_err(|error| format!("durable Science root metadata failed: {error}"))?;
                Ok::<_, String>((metadata.dev(), metadata.ino()))
            })
            .transpose()?;
        let manifest = DurableAuthorityReplayManifestV2 {
            schema_version: 2,
            managed_id: self.cleanup_context.managed_id.clone(),
            config: self.config.clone(),
            trees,
            science_root_path: self.science_root_path.clone(),
            science_root_identity,
            science_opaque_bindings: self.science_opaque_bindings,
        };
        let bytes = serde_json::to_vec(&manifest)
            .map_err(|error| format!("durable authority replay manifest encode failed: {error}"))?;
        if bytes.is_empty() || bytes.len() as u64 > MAX_DURABLE_PRIVATE_MANIFEST_BYTES {
            return Err("durable authority replay manifest size is invalid".into());
        }
        Ok(bytes)
    }

    // Windows 降级分支在函数体内提前返回，Unix 主体保持原样；
    // unreachable_code 仅在 Windows 上命中。
    #[allow(unreachable_code)]
    pub(super) fn registered_snapshot_ticket(
        &self,
    ) -> Result<config::RuntimeSnapshotTicket, String> {
        // Windows 降级票据：降级 capture 未注册磁盘快照票据，这里直接以
        // managed_id 构造已验证票据，维持 one-click journal 所需的
        // snapshot_ticket 字段一致（managed_id 仍由 AuthorityCleanupContext
        // 生成并通过格式校验）。
        #[cfg(not(unix))]
        {
            return config::RuntimeSnapshotTicket::verified(
                self.cleanup_context.managed_id.clone(),
            );
        }
        let ticket = self
            .cleanup_ticket
            .as_ref()
            .ok_or("registered authority snapshot ticket is missing")?;
        if ticket.entry.managed_id != self.cleanup_context.managed_id
            || ticket.entry.path != self.backup_root
            || ticket.entry.marker != ticket.entry.managed_id
        {
            return Err("registered authority snapshot ticket identity changed".into());
        }
        config::RuntimeSnapshotTicket::verified(ticket.entry.managed_id.clone())
    }

    #[allow(unreachable_code)]
    pub(super) fn persist_private_manifest(&self, name: &str, bytes: &[u8]) -> Result<(), String> {
        if bytes.is_empty() || bytes.len() as u64 > MAX_DURABLE_PRIVATE_MANIFEST_BYTES {
            return Err("private recovery manifest size is invalid".into());
        }
        // Windows 降级持久化：私有恢复 manifest 需要 fd 相对打开与
        // 0600/nlink/dev/inode 身份校验，且降级 capture 没有磁盘快照载体；
        // 这里降级为 no-op（补偿重放 manifest 同样跳过），durable 跨进程
        // 重放链路在 Windows 上整体不可用（load 侧因缺少注册清单而 fail-closed）。
        #[cfg(not(unix))]
        {
            let _ = (name, bytes);
            return Ok(());
        }
        let parent = AuthorityTreeSnapshot::open_absolute_directory(
            &self.cleanup_context.expected_snapshot_parent,
        )
        .map_err(|error| format!("private recovery parent open failed: {error}"))?;
        let root_name = AuthorityTreeSnapshot::destination_name(&self.backup_root)?;
        let root = AuthorityTreeSnapshot::open_directory_at(parent.as_raw_fd(), &root_name)
            .map_err(|error| format!("private recovery root open failed: {error}"))?;
        let metadata = root
            .metadata()
            .map_err(|error| format!("private recovery root metadata failed: {error}"))?;
        let expected = self
            .cleanup_context
            .expected_root_identity
            .ok_or("private recovery root identity is missing")?;
        if !metadata.is_dir()
            || metadata.uid() != unsafe { crate::platform::geteuid() }
            || !crate::platform::dir_mode_is_0700(&metadata)
            || (metadata.dev(), metadata.ino()) != expected
        {
            return Err("private recovery root identity changed".into());
        }
        let manifest_name = std::ffi::CString::new(name)
            .map_err(|_| "private recovery manifest name is invalid")?;
        let mut manifest = AuthorityTreeSnapshot::open_destination_at(
            root.as_raw_fd(),
            &manifest_name,
            crate::platform::O_WRONLY | crate::platform::O_CREAT | crate::platform::O_EXCL,
            0o600,
        )
        .map_err(|error| format!("private recovery manifest create failed: {error}"))?;
        std::io::Write::write_all(&mut manifest, bytes)
            .and_then(|_| manifest.set_permissions(crate::platform::permissions_from_mode(0o600)))
            .and_then(|_| manifest.sync_all())
            .map_err(|error| format!("private recovery manifest sync failed: {error}"))?;
        let manifest_metadata = manifest
            .metadata()
            .map_err(|error| format!("private recovery manifest metadata failed: {error}"))?;
        if !manifest_metadata.is_file()
            || manifest_metadata.uid() != unsafe { crate::platform::geteuid() }
            || manifest_metadata.permissions().mode() & 0o777 != 0o600
            || manifest_metadata.nlink() != 1
            || manifest_metadata.len() != bytes.len() as u64
        {
            return Err("private recovery manifest identity is unsafe".into());
        }
        root.sync_all()
            .and_then(|_| parent.sync_all())
            .map_err(|error| format!("private recovery directory sync failed: {error}"))
    }

    #[allow(unreachable_code)]
    pub(super) fn science_opaque_root_bindings(
        root: Option<&std::fs::File>,
    ) -> Result<[Option<(u64, u64)>; SCIENCE_OWNED_OPAQUE_ROOTS.len()], String> {
        // Windows 降级：opaque 绑定以 dev/inode 锚定（fstatat），Windows 上不可
        // 观测；一律返回「全部 absent」，即不做任何绑定校验。
        #[cfg(not(unix))]
        {
            let _ = root;
            return Ok([None; SCIENCE_OWNED_OPAQUE_ROOTS.len()]);
        }
        let mut bindings = [None; SCIENCE_OWNED_OPAQUE_ROOTS.len()];
        let Some(root) = root else {
            return Ok(bindings);
        };
        for (index, entry) in SCIENCE_OWNED_OPAQUE_ROOTS.iter().enumerate() {
            let name = std::ffi::CString::new(*entry)
                .map_err(|_| "code=science_environment_root_name_invalid")?;
            match AuthorityTreeSnapshot::stat_destination_at(root, &name) {
                Ok(identity)
                    if identity.st_mode & crate::platform::S_IFMT == crate::platform::S_IFDIR
                        && identity.st_uid == unsafe { crate::platform::geteuid() }
                        && identity.st_mode & 0o022 == 0 =>
                {
                    let device = u64::try_from(identity.st_dev)
                        .map_err(|_| "code=science_environment_root_device_invalid")?;
                    let inode = inode_u64(identity.st_ino)
                        .ok_or("code=science_environment_root_inode_invalid")?;
                    bindings[index] = Some((device, inode));
                }
                Ok(_) => {
                    return Err(
                        "code=science_environment_root_identity_failed category=science_runtime"
                            .into(),
                    )
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(format!(
                        "code=science_environment_root_validate_failed category=science_runtime os_error={}",
                        AuthorityTreeSnapshot::os_error_code(&error)
                    ))
                }
            }
        }
        Ok(bindings)
    }

    #[allow(unreachable_code)]
    pub(super) fn pin_science_root_and_validate_opaque_entries(
        auth_dir: &Path,
    ) -> Result<Option<std::fs::File>, String> {
        // Windows 降级：science root pin 依赖 fd 锚定的目录身份与 mode/uid 校验；
        // 返回 None 表示「未锚定」，后续绑定校验随之降级为空绑定。
        #[cfg(not(unix))]
        {
            let _ = auth_dir;
            return Ok(None);
        }
        let root = match AuthorityTreeSnapshot::open_absolute_directory(auth_dir) {
            Ok(root) => root,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(format!(
                    "code=science_authority_root_open_failed os_error={}",
                    AuthorityTreeSnapshot::os_error_code(&error)
                ))
            }
        };
        let metadata = root.metadata().map_err(|error| {
            format!(
                "code=science_authority_root_validate_failed os_error={}",
                AuthorityTreeSnapshot::os_error_code(&error)
            )
        })?;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || metadata.uid() != unsafe { crate::platform::geteuid() }
            || metadata.permissions().mode() & 0o022 != 0
        {
            return Err("code=science_authority_root_identity_failed".into());
        }
        Self::science_opaque_root_bindings(Some(&root))?;
        Ok(Some(root))
    }

    #[allow(unreachable_code)]
    pub(super) fn revalidate_science_root_binding(
        auth_dir: &Path,
        pinned: &Option<std::fs::File>,
    ) -> Result<(), String> {
        // Windows 降级：没有可复核的 fd/目录绑定，直接视为未漂移。
        #[cfg(not(unix))]
        {
            let _ = (auth_dir, pinned);
            return Ok(());
        }
        let Some(pinned) = pinned.as_ref() else {
            return match AuthorityTreeSnapshot::open_absolute_directory(auth_dir) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Ok(_) => Err("code=science_authority_root_created_during_capture".into()),
                Err(error) => Err(format!(
                    "code=science_authority_root_revalidate_failed os_error={}",
                    AuthorityTreeSnapshot::os_error_code(&error)
                )),
            };
        };
        let matches = AuthorityTreeSnapshot::absolute_directory_binding_matches(auth_dir, pinned)
            .map_err(|error| {
            format!(
                "code=science_authority_root_revalidate_failed os_error={}",
                AuthorityTreeSnapshot::os_error_code(&error)
            )
        })?;
        if matches {
            Ok(())
        } else {
            Err("code=science_authority_root_rebound".into())
        }
    }

    #[allow(unreachable_code)]
    pub(super) fn validate_science_restore_root(&self) -> Result<(), String> {
        // Windows 降级：恢复前校验依赖 fd 锚定的 science root 与 opaque 绑定；
        // 降级语义为「允许恢复且不校验身份漂移」（trees 为空，实际 effect 为空）。
        #[cfg(not(unix))]
        {
            return Ok(());
        }
        let current = Self::pin_science_root_and_validate_opaque_entries(&self.science_root_path)?;
        if Self::science_opaque_root_bindings(current.as_ref())? != self.science_opaque_bindings {
            return Err("code=science_environment_root_rebound category=science_runtime".into());
        }
        match (self.science_root.as_ref(), current.as_ref()) {
            (Some(pinned), Some(_)) => {
                let matches = AuthorityTreeSnapshot::absolute_directory_binding_matches(
                    &self.science_root_path,
                    pinned,
                )
                .map_err(|error| {
                    format!(
                        "code=science_authority_restore_root_revalidate_failed os_error={}",
                        AuthorityTreeSnapshot::os_error_code(&error)
                    )
                })?;
                if matches {
                    Ok(())
                } else {
                    Err("code=science_authority_restore_root_rebound".into())
                }
            }
            (Some(_), None) => Err("code=science_authority_restore_root_missing".into()),
            (None, _) => Ok(()),
        }
    }

    pub(super) fn science_opaque_bindings_env(&self) -> String {
        SCIENCE_OWNED_OPAQUE_ROOTS
            .iter()
            .zip(self.science_opaque_bindings)
            .map(|(name, binding)| match binding {
                Some((device, inode)) => format!("{name}={device}:{inode}"),
                None => format!("{name}=absent"),
            })
            .collect::<Vec<_>>()
            .join(";")
    }

    #[allow(unreachable_code)]
    pub(super) fn capture(
        config_dir: &Path,
        sandbox_home: &Path,
        auth_dir: &Path,
        config: &config::Config,
        state: &SharedAppState,
    ) -> Result<Self, String> {
        #[cfg(test)]
        {
            let capture_seam = SANDBOX_SESSION_TEST_SEAMS
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .one_click_capture
                .as_ref()
                .filter(|(target_dir, _, _, _, _)| target_dir == config_dir)
                .cloned();
            if let Some((_, observation, _, expected_prior_pid, expected_receipt)) =
                capture_seam.as_ref()
            {
                let listener_state = if proc::loopback_port_in_use(
                    config.sandbox_port,
                    operation::LOCAL_HEALTH_TIMEOUT_MS,
                ) {
                    "running"
                } else {
                    "stopped"
                };
                let prior_process = if crate::runtime::science::test_process_start_identity_for_pid(
                    *expected_prior_pid,
                )
                .is_some()
                {
                    "alive"
                } else {
                    "absent"
                };
                let prior_receipt = if expected_receipt.exists() {
                    "present"
                } else {
                    "absent"
                };
                std::fs::write(
                    observation,
                    format!(
                        "expected_prior_pid={expected_prior_pid}\nexpected_receipt={}\nlistener={listener_state}\nprior_process={prior_process}\nprior_receipt={prior_receipt}\n",
                        expected_receipt.display()
                    ),
                )
                .map_err(|error| {
                        format!("test-only authority snapshot observation failed: {error}")
                    })?;
            }
            if capture_seam.is_some_and(|(_, _, fail, _, _)| fail) {
                return Err("test-only one-click authority snapshot capture failure".into());
            }
        }
        // Windows 降级 capture：权威快照引擎基于 POSIX fd 相对操作
        // （openat/fstatat/fdopendir/renameat）与 dev/inode 身份锚定，Windows 上
        // 无忠实等价物（文件系统助手一律返回 Unsupported）。降级策略：只保留
        // 纯路径/纯内存部分——cleanup_context（纯路径构造）、config 克隆与
        // app 内存快照；跳过 trees 磁盘备份、cleanup 注册票据、science root
        // pin 与 opaque 绑定、以及 durable manifest 持久化。
        // 语义损失：事务中途失败时没有磁盘快照可自动回滚（restore 时 trees
        // 为空，仅回滚 config/app 状态；durable 补偿重放不可用），残留清理由
        // 「停止全部」手动兜底；success finalize 走降级 cleanup（无快照可清，
        // 直接 Cleared）。
        #[cfg(not(unix))]
        {
            let cleanup_context = AuthorityCleanupContext::new(config_dir, sandbox_home, state)?;
            let backup_root = cleanup_context.root.clone();
            return Ok(Self {
                backup_root,
                cleanup_context,
                cleanup_ticket: None,
                trees: Vec::new(),
                science_root_path: auth_dir.to_path_buf(),
                science_root: None,
                science_opaque_bindings: [None; SCIENCE_OWNED_OPAQUE_ROOTS.len()],
                config: config.clone(),
                app: AppAuthoritySnapshot::capture(state),
                preserve_recovery: false,
                cleanup_prepared: false,
            });
        }
        let sandbox_dir = sandbox_home
            .parent()
            .ok_or("沙箱 HOME 无父目录，无法建立事务快照")?;
        let mut cleanup_context = AuthorityCleanupContext::new(config_dir, sandbox_home, state)?;
        let backup_root = cleanup_context.root.clone();
        let snapshot_parent = AuthorityTreeSnapshot::open_or_create_authority_snapshot_parent(
            config_dir,
            sandbox_home,
        )?;
        let backup_root_name = AuthorityTreeSnapshot::destination_name(&backup_root)?;
        AuthorityTreeSnapshot::mkdir_destination_at(
            snapshot_parent.as_raw_fd(),
            &backup_root_name,
            0o700,
        )
        .map_err(|error| {
            format!(
                "code=authority_snapshot_root_create_failed os_error={}",
                AuthorityTreeSnapshot::os_error_code(&error)
            )
        })?;
        let created_root_entry =
            AuthorityTreeSnapshot::stat_destination_at(&snapshot_parent, &backup_root_name)
                .map_err(|error| {
                    finalize_failed_authority_snapshot(
                        &cleanup_context,
                        format!(
                            "code=authority_snapshot_root_entry_validate_failed os_error={}",
                            AuthorityTreeSnapshot::os_error_code(&error)
                        ),
                    )
                })?;
        cleanup_context.bind_root_identity(&created_root_entry)?;
        let backup_root_file = match (|| -> Result<std::fs::File, String> {
            let root = AuthorityTreeSnapshot::open_directory_at(
                snapshot_parent.as_raw_fd(),
                &backup_root_name,
            )
            .map_err(|error| {
                format!(
                    "code=authority_snapshot_root_open_failed os_error={}",
                    AuthorityTreeSnapshot::os_error_code(&error)
                )
            })?;
            root.set_permissions(crate::platform::permissions_from_mode(0o700))
                .map_err(|error| {
                    format!(
                        "code=authority_snapshot_root_chmod_failed os_error={}",
                        AuthorityTreeSnapshot::os_error_code(&error)
                    )
                })?;
            let metadata = root.metadata().map_err(|error| {
                format!(
                    "code=authority_snapshot_root_validate_failed os_error={}",
                    AuthorityTreeSnapshot::os_error_code(&error)
                )
            })?;
            if !metadata.is_dir()
                || metadata.file_type().is_symlink()
                || metadata.uid() != unsafe { crate::platform::geteuid() }
                || !crate::platform::dir_mode_is_0700(&metadata)
                || !AuthorityTreeSnapshot::destination_entry_matches_file(
                    &created_root_entry,
                    &metadata,
                    crate::platform::S_IFDIR,
                )
            {
                return Err("code=authority_snapshot_root_identity_failed".into());
            }
            root.sync_all().map_err(|error| {
                format!(
                    "code=authority_snapshot_root_sync_failed os_error={}",
                    AuthorityTreeSnapshot::os_error_code(&error)
                )
            })?;
            snapshot_parent.sync_all().map_err(|error| {
                format!(
                    "code=authority_snapshot_root_parent_sync_failed os_error={}",
                    AuthorityTreeSnapshot::os_error_code(&error)
                )
            })?;
            Ok(root)
        })() {
            Ok(root) => root,
            Err(error) => {
                return Err(finalize_failed_authority_snapshot(
                    &cleanup_context,
                    error.to_string(),
                ))
            }
        };
        let cleanup_ticket = match register_authority_cleanup(&cleanup_context) {
            Ok(ticket) => ticket,
            Err(error) => {
                return Err(finalize_failed_authority_snapshot(
                    &cleanup_context,
                    error.to_string(),
                ))
            }
        };
        let science_root = match Self::pin_science_root_and_validate_opaque_entries(auth_dir) {
            Ok(root) => root,
            Err(error) => return Err(finalize_failed_authority_snapshot(&cleanup_context, error)),
        };
        let science_opaque_bindings =
            match Self::science_opaque_root_bindings(science_root.as_ref()) {
                Ok(bindings) => bindings,
                Err(error) => {
                    return Err(finalize_failed_authority_snapshot(&cleanup_context, error))
                }
            };
        let science_backup = backup_root.join("0");
        let science_backup_name = AuthorityTreeSnapshot::destination_name(&science_backup)?;
        AuthorityTreeSnapshot::mkdir_destination_at(
            backup_root_file.as_raw_fd(),
            &science_backup_name,
            0o700,
        )
        .map_err(|error| {
            finalize_failed_authority_snapshot(
                &cleanup_context,
                format!(
                    "code=science_authority_projection_create_failed os_error={}",
                    AuthorityTreeSnapshot::os_error_code(&error)
                ),
            )
        })?;
        let science_backup_file = AuthorityTreeSnapshot::open_directory_at(
            backup_root_file.as_raw_fd(),
            &science_backup_name,
        )
        .map_err(|error| {
            finalize_failed_authority_snapshot(
                &cleanup_context,
                format!(
                    "code=science_authority_projection_open_failed os_error={}",
                    AuthorityTreeSnapshot::os_error_code(&error)
                ),
            )
        })?;
        let mut trees = Vec::with_capacity(SCIENCE_PROTECTED_AUTHORITY_ENTRIES.len() + 3);
        let mut science_budget = AuthorityCopyBudget::default();
        for entry in SCIENCE_PROTECTED_AUTHORITY_ENTRIES {
            let source = auth_dir.join(entry);
            let backup = science_backup.join(entry);
            let source_name = AuthorityTreeSnapshot::destination_name(&source)?;
            let backup_name = AuthorityTreeSnapshot::destination_name(&backup)?;
            let capture = match science_root.as_ref() {
                Some(science_root) => {
                    AuthorityTreeSnapshot::capture_scoped_from_parent_with_budget(
                        AuthoritySnapshotScope::ScienceData,
                        source,
                        backup,
                        science_root,
                        &source_name,
                        &science_backup_file,
                        &backup_name,
                        &mut science_budget,
                    )
                }
                None => AuthorityTreeSnapshot::capture_scoped_at_with_budget(
                    AuthoritySnapshotScope::ScienceData,
                    source,
                    backup,
                    &science_backup_file,
                    &backup_name,
                    &mut science_budget,
                ),
            };
            match capture {
                Ok(snapshot) => trees.push(snapshot),
                Err(error) => {
                    let durability = science_backup_file
                        .sync_all()
                        .and_then(|_| backup_root_file.sync_all())
                        .and_then(|_| snapshot_parent.sync_all());
                    let primary = match durability {
                        Ok(()) => error,
                        Err(sync_error) => format!(
                            "{error}; code=authority_snapshot_failure_sync_failed os_error={}",
                            AuthorityTreeSnapshot::os_error_code(&sync_error)
                        ),
                    };
                    return Err(finalize_failed_authority_snapshot(
                        &cleanup_context,
                        primary,
                    ));
                }
            }
        }
        if let Err(error) = Self::revalidate_science_root_binding(auth_dir, &science_root) {
            return Err(finalize_failed_authority_snapshot(&cleanup_context, error));
        }
        science_backup_file
            .sync_all()
            .and_then(|_| backup_root_file.sync_all())
            .map_err(|error| {
                finalize_failed_authority_snapshot(
                    &cleanup_context,
                    format!(
                        "code=science_authority_projection_sync_failed os_error={}",
                        AuthorityTreeSnapshot::os_error_code(&error)
                    ),
                )
            })?;
        let sources = [
            (
                AuthoritySnapshotScope::SandboxState,
                sandbox_dir.join("state"),
            ),
            (
                AuthoritySnapshotScope::CsswitchRuntime,
                config_dir.join("runtime"),
            ),
            (
                AuthoritySnapshotScope::ManagedReceipt,
                config_dir.join("science-managed-launch.v1.json"),
            ),
        ];
        for (index, (scope, source)) in sources.into_iter().enumerate() {
            let index = index + 1;
            let backup = backup_root.join(index.to_string());
            let backup_name = AuthorityTreeSnapshot::destination_name(&backup)?;
            match AuthorityTreeSnapshot::capture_scoped_at(
                scope,
                source,
                backup,
                &backup_root_file,
                &backup_name,
            ) {
                Ok(snapshot) => trees.push(snapshot),
                Err(error) => {
                    let durability = backup_root_file
                        .sync_all()
                        .and_then(|_| snapshot_parent.sync_all());
                    let primary = match durability {
                        Ok(()) => error,
                        Err(sync_error) => format!(
                            "{error}; code=authority_snapshot_failure_sync_failed os_error={}",
                            AuthorityTreeSnapshot::os_error_code(&sync_error)
                        ),
                    };
                    return Err(finalize_failed_authority_snapshot(
                        &cleanup_context,
                        primary,
                    ));
                }
            }
        }
        if !AuthorityTreeSnapshot::absolute_directory_binding_matches(
            &cleanup_context.expected_snapshot_parent,
            &snapshot_parent,
        )
        .map_err(|error| {
            finalize_failed_authority_snapshot(
                &cleanup_context,
                format!(
                    "code=authority_snapshot_root_parent_revalidate_failed os_error={}",
                    AuthorityTreeSnapshot::os_error_code(&error)
                ),
            )
        })? {
            return Err(finalize_failed_authority_snapshot(
                &cleanup_context,
                "code=authority_snapshot_root_parent_rebound".into(),
            ));
        }
        let final_root_metadata = backup_root_file.metadata().map_err(|error| {
            finalize_failed_authority_snapshot(
                &cleanup_context,
                format!(
                    "code=authority_snapshot_root_validate_failed os_error={}",
                    AuthorityTreeSnapshot::os_error_code(&error)
                ),
            )
        })?;
        let final_root_entry =
            AuthorityTreeSnapshot::stat_destination_at(&snapshot_parent, &backup_root_name)
                .map_err(|error| {
                    finalize_failed_authority_snapshot(
                        &cleanup_context,
                        format!(
                            "code=authority_snapshot_root_entry_revalidate_failed os_error={}",
                            AuthorityTreeSnapshot::os_error_code(&error)
                        ),
                    )
                })?;
        if !AuthorityTreeSnapshot::destination_entry_matches_file(
            &final_root_entry,
            &final_root_metadata,
            crate::platform::S_IFDIR,
        ) {
            return Err(finalize_failed_authority_snapshot(
                &cleanup_context,
                "code=authority_snapshot_root_rebound".into(),
            ));
        }
        AuthorityTreeSnapshot::sync_snapshot_completion(&backup_root_file, &snapshot_parent)
            .map_err(|error| {
                finalize_failed_authority_snapshot(
                    &cleanup_context,
                    format!(
                        "code=authority_snapshot_completion_sync_failed os_error={}",
                        AuthorityTreeSnapshot::os_error_code(&error)
                    ),
                )
            })?;
        let snapshot = Self {
            backup_root,
            cleanup_context,
            cleanup_ticket: Some(cleanup_ticket),
            trees,
            science_root_path: auth_dir.to_path_buf(),
            science_root,
            science_opaque_bindings,
            config: config.clone(),
            app: AppAuthoritySnapshot::capture(state),
            preserve_recovery: false,
            cleanup_prepared: false,
        };
        let replay_manifest = snapshot.durable_replay_manifest_bytes().map_err(|error| {
            finalize_failed_authority_snapshot(&snapshot.cleanup_context, error)
        })?;
        snapshot
            .persist_private_manifest(DURABLE_AUTHORITY_REPLAY_MANIFEST, &replay_manifest)
            .map_err(|error| {
                finalize_failed_authority_snapshot(&snapshot.cleanup_context, error)
            })?;
        #[cfg(test)]
        if SANDBOX_SESSION_TEST_SEAMS
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .one_click_exit_after_capture
            .as_ref()
            == Some(&config_dir.to_path_buf())
        {
            std::process::exit(86);
        }
        Ok(snapshot)
    }

    #[cfg(test)]
    pub(super) fn restore(
        &mut self,
        config_dir: &Path,
        state: &SharedAppState,
        proxy_action: ProxyAction,
    ) -> Result<(), String> {
        let mut errors = Vec::new();
        let science_restore_allowed = match self.validate_science_restore_root() {
            Ok(()) => true,
            Err(error) => {
                errors.push(error);
                false
            }
        };
        for tree in &mut self.trees {
            if tree.scope == AuthoritySnapshotScope::ScienceData && !science_restore_allowed {
                continue;
            }
            if let Err(error) = tree.restore() {
                errors.push(error);
            }
        }
        if let Err(error) =
            config::save_to(config_dir, &self.config).map_err(|error| error.to_string())
        {
            errors.push(error);
        }
        if let Err(error) = self.app.restore(state, proxy_action) {
            errors.push(error);
        }
        if errors.is_empty() {
            return self
                .cleanup_when_expendable()
                .map(|_| ())
                .map_err(String::from);
        }
        self.preserve_recovery = true;
        Err(errors.join("; "))
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn restore_with_gateway<R: Runtime>(
        &mut self,
        app: &tauri::AppHandle<R>,
        config_dir: &Path,
        state: &SharedAppState,
        lifecycle: &lifecycle::Lifecycle,
        auth_proof: Option<&crate::codex_auth_supervisor::CodexAuthReadyProof>,
        proxy_action: ProxyAction,
        runtime_transaction: &RuntimeTransactionRestoreExpectation,
    ) -> Result<(), String> {
        let current = config::load_from(config_dir).map_err(|error| error.to_string())?;
        let authority_matches = match runtime_transaction {
            RuntimeTransactionRestoreExpectation::Exact(expected) => {
                current.runtime_transaction.as_ref() == expected.as_ref()
            }
            RuntimeTransactionRestoreExpectation::ExactPreservingCompensation {
                runtime_transaction,
                compensation,
            } => {
                current.runtime_transaction == *runtime_transaction
                    && current.runtime_compensation.as_ref() == Some(compensation)
            }
            RuntimeTransactionRestoreExpectation::ExactConfig(expected) => current == **expected,
        };
        if !authority_matches {
            self.preserve_recovery = true;
            return Err("one-click compensation found drifted config authority; preserved the current config, authority, runtime state, and recovery snapshot".into());
        }
        if proxy_action == ProxyAction::Restarted {
            if let Err(error) = lock(state)
                .stop_proxy()
                .require_stopped("one-click compensation 恢复前无法安全停止 Gateway")
            {
                self.preserve_recovery = true;
                return Err(error);
            }
        }
        let mut errors = Vec::new();
        let science_restore_allowed = match self.validate_science_restore_root() {
            Ok(()) => true,
            Err(error) => {
                errors.push(error);
                false
            }
        };
        for tree in &mut self.trees {
            if tree.scope == AuthoritySnapshotScope::ScienceData && !science_restore_allowed {
                continue;
            }
            if let Err(error) = tree.restore() {
                errors.push(error);
            }
        }
        let config_restore = match runtime_transaction {
            RuntimeTransactionRestoreExpectation::Exact(expected) => {
                config::update_result(config_dir, |current| {
                    if current.runtime_transaction.as_ref() != expected.as_ref() {
                        return Err("one-click compensation found a retargeted runtime journal; preserved the current config and recovery snapshot".into());
                    }
                    *current = self.config.clone();
                    Ok(((), true))
                })
            }
            RuntimeTransactionRestoreExpectation::ExactPreservingCompensation {
                runtime_transaction,
                compensation,
            } => config::update_result(config_dir, |current| {
                if current.runtime_transaction != *runtime_transaction
                    || current.runtime_compensation.as_ref() != Some(compensation)
                {
                    return Err("one-click compensation found a retargeted durable compensation journal; preserved the current config and recovery snapshot".into());
                }
                *current = self.config.clone();
                current.runtime_compensation = Some(compensation.clone());
                Ok(((), true))
            }),
            RuntimeTransactionRestoreExpectation::ExactConfig(expected) => {
                config::update_result(config_dir, |current| {
                    if current != expected.as_ref() {
                        return Err("one-click compensation found drifted config authority; preserved the current config and recovery snapshot".into());
                    }
                    *current = self.config.clone();
                    Ok(((), true))
                })
            }
        };
        if let Err(error) = config_restore {
            errors.push(error);
        }
        if let Err(error) =
            self.app
                .restore_with_gateway(app, state, lifecycle, auth_proof, proxy_action)
        {
            errors.push(error);
        }
        #[cfg(test)]
        {
            let mut seams = SANDBOX_SESSION_TEST_SEAMS
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            if let Some(canary) = seams.rollback_diagnostic_canary.clone() {
                seams.rollback_diagnostic_snapshot = Some(self.backup_root.clone());
                errors.push(format!("test-only rollback diagnostic {canary}"));
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            self.preserve_recovery = true;
            Err(errors.join("; "))
        }
    }

    pub(super) fn preflight_durable_authority_restore(
        &self,
        config_dir: &Path,
        expected_runtime_transaction: &Option<config::RuntimeTransactionRecord>,
        expected_compensation: &config::RuntimeCompensationJournal,
        inputs: &AuthorityRestoreReplayInputs,
    ) -> Result<(), String> {
        let current = config::load_from(config_dir).map_err(|error| error.to_string())?;
        if current.runtime_compensation.as_ref() != Some(expected_compensation)
            || current.runtime_transaction != *expected_runtime_transaction
        {
            return Err(
                "durable compensation replay found drifted config authority; preserved current state"
                    .into(),
            );
        }
        let ticket = self.registered_snapshot_ticket()?;
        if inputs.snapshot_ticket != ticket
            || inputs.compensation_id != expected_compensation.compensation_id
            || inputs.sandbox_port != self.config.sandbox_port
        {
            return Err(
                "durable authority replay identity mismatch; preserved current state".into(),
            );
        }
        config::validate_runtime_ports(self.config.proxy_port, inputs.sandbox_port)
            .map_err(|_| "durable authority replay ports are invalid; preserved current state")?;
        Ok(())
    }

    /// Publish (or exactly re-open) the reservation before the AuthorityRestore
    /// journal step is allowed to advance.  The reservation binds the observed
    /// quiescent Science boundary and every target's pre-effect identity.
    pub(super) fn prepare_durable_authority_restore(
        &self,
        state: &SharedAppState,
        inputs: &AuthorityRestoreReplayInputs,
    ) -> Result<(), String> {
        self.require_durable_science_quiescence(state, inputs.sandbox_port)?;
        match read_registered_private_manifest(
            state,
            &inputs.snapshot_ticket,
            DURABLE_AUTHORITY_RESTORE_RESERVATION,
        ) {
            Ok(bytes) => {
                let reservation = decode_durable_authority_reservation(&bytes)?;
                if reservation.compensation_id != inputs.compensation_id
                    || reservation.snapshot_ticket != inputs.snapshot_ticket
                    || reservation.sandbox_port != inputs.sandbox_port
                    || reservation.targets.len() != self.trees.len()
                    || reservation.target_content_digests.len() != self.trees.len()
                {
                    return Err(
                        "durable authority reservation identity drifted; preserved ActiveRecovery"
                            .into(),
                    );
                }
                return self.require_durable_science_quiescence(state, inputs.sandbox_port);
            }
            Err(error) if !error.contains("manifest open failed") => return Err(error),
            Err(_) => {}
        }
        let targets = self
            .trees
            .iter()
            .map(Self::durable_tree_identity)
            .collect::<Result<Vec<_>, _>>()?;
        let target_content_digests = self
            .trees
            .iter()
            .map(durable_authority_tree_digest)
            .collect::<Result<Vec<_>, _>>()?;
        let reservation = DurableScienceQuiescenceReservation {
            schema_version: DURABLE_AUTHORITY_RESERVATION_SCHEMA_VERSION,
            compensation_id: inputs.compensation_id.clone(),
            snapshot_ticket: inputs.snapshot_ticket.clone(),
            sandbox_port: inputs.sandbox_port,
            targets,
            target_content_digests,
        };
        self.persist_or_validate_durable_marker(
            state,
            &inputs.snapshot_ticket,
            DURABLE_AUTHORITY_RESTORE_RESERVATION,
            &reservation,
        )?;
        // A reservation is not an assertion that the port remains closed.  A
        // second proof makes the interval between durable intent and the first
        // target effect fail closed for cooperating lifecycle writers.
        self.require_durable_science_quiescence(state, inputs.sandbox_port)
    }

    fn require_durable_science_quiescence(
        &self,
        state: &SharedAppState,
        sandbox_port: u16,
    ) -> Result<(), String> {
        let app = lock(state);
        let fresh_unowned = app.sandbox_port == 0
            && app.sandbox.is_none()
            && app.science_runtime.is_none()
            && app.science_confirmed_stopped.is_none()
            && app.sandbox_url.is_none();
        if app.sandbox.is_some()
            || app.science_runtime.is_some()
            || app.science_confirmed_stopped.is_some()
            || app.sandbox_url.is_some()
            || (!fresh_unowned && app.sandbox_port != sandbox_port)
        {
            return Err("durable authority restore Science ownership is not quiescent; preserved ActiveRecovery".into());
        }
        drop(app);
        if crate::proc::loopback_port_in_use(
            sandbox_port,
            crate::runtime::operation::LOCAL_HEALTH_TIMEOUT_MS,
        ) {
            return Err(
                "durable authority restore Science port is not quiescent; preserved ActiveRecovery"
                    .into(),
            );
        }
        match std::fs::symlink_metadata(config::default_dir().join("science-managed-launch.v1.json")) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Ok(_) => Err("durable authority restore managed Science receipt is present; preserved ActiveRecovery".into()),
            Err(_) => Err("durable authority restore managed Science receipt identity is unknown; preserved ActiveRecovery".into()),
        }
    }

    fn durable_tree_identity(
        tree: &AuthorityTreeSnapshot,
    ) -> Result<DurableAuthorityTargetIdentity, String> {
        let parent = tree
            .source_parent
            .as_ref()
            .ok_or("durable authority target parent identity is unknown")?;
        let name = tree
            .source_name
            .as_deref()
            .ok_or("durable authority target name identity is unknown")?;
        durable_authority_entry_identity(parent, name)
    }

    fn persist_or_validate_durable_marker<T: Serialize + for<'de> Deserialize<'de> + Eq>(
        &self,
        state: &SharedAppState,
        ticket: &config::RuntimeSnapshotTicket,
        name: &str,
        value: &T,
    ) -> Result<(), String> {
        let bytes = serde_json::to_vec(value)
            .map_err(|error| format!("durable authority marker encode failed: {error}"))?;
        match self.persist_private_manifest(name, &bytes) {
            Ok(()) => Ok(()),
            Err(_) => {
                let existing = read_registered_private_manifest(state, ticket, name)?;
                let parsed = serde_json::from_slice::<T>(&existing)
                    .map_err(|_| "durable authority marker format is invalid")?;
                if parsed == *value {
                    Ok(())
                } else {
                    Err(
                        "durable authority marker identity drifted; preserved ActiveRecovery"
                            .into(),
                    )
                }
            }
        }
    }

    fn read_durable_effect_marker(
        state: &SharedAppState,
        ticket: &config::RuntimeSnapshotTicket,
        target: usize,
        phase: DurableAuthorityEffectPhase,
    ) -> Result<Option<DurableAuthorityEffectMarker>, String> {
        let name = durable_authority_effect_marker_name(target, phase);
        match read_registered_private_manifest(state, ticket, &name) {
            Ok(bytes) => {
                let marker = serde_json::from_slice::<DurableAuthorityEffectMarker>(&bytes)
                    .map_err(|_| "durable authority effect marker format is invalid")?;
                if marker.schema_version != 1 || marker.target != target || marker.phase != phase {
                    return Err(
                        "durable authority effect marker retargeted; preserved ActiveRecovery"
                            .into(),
                    );
                }
                Ok(Some(marker))
            }
            Err(error) if error.contains("manifest open failed") => Ok(None),
            Err(error) => Err(error),
        }
    }

    fn durable_effect_marker(
        inputs: &AuthorityRestoreReplayInputs,
        target: usize,
        phase: DurableAuthorityEffectPhase,
        identity: DurableAuthorityTargetIdentity,
    ) -> DurableAuthorityEffectMarker {
        DurableAuthorityEffectMarker {
            schema_version: 1,
            compensation_id: inputs.compensation_id.clone(),
            snapshot_ticket: inputs.snapshot_ticket.clone(),
            target,
            phase,
            identity,
        }
    }

    pub(super) fn restore_durable_authority(
        &mut self,
        config_dir: &Path,
        state: &SharedAppState,
        expected_runtime_transaction: &Option<config::RuntimeTransactionRecord>,
        expected_compensation: &config::RuntimeCompensationJournal,
        inputs: &AuthorityRestoreReplayInputs,
    ) -> Result<(), String> {
        self.require_durable_science_quiescence(state, inputs.sandbox_port)?;
        let reservation = read_registered_private_manifest(
            state,
            &inputs.snapshot_ticket,
            DURABLE_AUTHORITY_RESTORE_RESERVATION,
        )?;
        let reservation = decode_durable_authority_reservation(&reservation)?;
        if reservation.compensation_id != inputs.compensation_id
            || reservation.snapshot_ticket != inputs.snapshot_ticket
            || reservation.sandbox_port != inputs.sandbox_port
            || reservation.targets.len() != self.trees.len()
            || reservation.target_content_digests.len() != self.trees.len()
        {
            return Err(
                "durable authority reservation identity drifted; preserved ActiveRecovery".into(),
            );
        }
        let current = config::load_from(config_dir).map_err(|error| error.to_string())?;
        let mut restored_config = self.config.clone();
        restored_config.runtime_compensation = Some(expected_compensation.clone());
        let already_restored = current == restored_config;
        if current.runtime_compensation.as_ref() != Some(expected_compensation)
            || (!already_restored && current.runtime_transaction != *expected_runtime_transaction)
        {
            return Err("durable compensation replay found drifted config authority; preserved current state".into());
        }
        self.validate_science_restore_root()?;
        for (index, tree) in self.trees.iter().enumerate() {
            let source_parent = tree
                .source_parent
                .as_ref()
                .ok_or("durable authority target parent identity is unknown")?;
            let source_name = tree
                .source_name
                .as_deref()
                .ok_or("durable authority target name identity is unknown")?;
            if durable_authority_entry_identity(source_parent, source_name)?
                == reservation.targets[index]
                && durable_authority_tree_digest(tree)? != reservation.target_content_digests[index]
            {
                return Err(
                    "durable authority target content drifted; preserved ActiveRecovery".into(),
                );
            }
            self.replay_durable_authority_tree(
                state,
                tree,
                index,
                &reservation.targets[index],
                inputs,
            )?;
        }
        if !already_restored {
            let before = self.config.clone();
            config::update_result(config_dir, |current| {
                if current.runtime_transaction != *expected_runtime_transaction
                    || current.runtime_compensation.as_ref() != Some(expected_compensation)
                {
                    return Err("durable compensation replay authority changed during restore; preserved current config".into());
                }
                *current = before.clone();
                current.runtime_compensation = Some(expected_compensation.clone());
                Ok(((), true))
            })?;
        }
        Ok(())
    }

    fn replay_durable_authority_tree(
        &self,
        state: &SharedAppState,
        tree: &AuthorityTreeSnapshot,
        index: usize,
        expected: &DurableAuthorityTargetIdentity,
        inputs: &AuthorityRestoreReplayInputs,
    ) -> Result<(), String> {
        let parent = tree
            .source_parent
            .as_ref()
            .ok_or("durable authority target parent identity is unknown")?;
        let source = tree
            .source_name
            .as_deref()
            .ok_or("durable authority target name identity is unknown")?;
        let stage_path = durable_authority_side_path(tree, inputs, index, "stage")?;
        let tombstone_path = durable_authority_side_path(tree, inputs, index, "tombstone")?;
        let stage = AuthorityTreeSnapshot::destination_name(&stage_path)?;
        let tombstone = AuthorityTreeSnapshot::destination_name(&tombstone_path)?;
        let staged = Self::read_durable_effect_marker(
            state,
            &inputs.snapshot_ticket,
            index,
            DurableAuthorityEffectPhase::Staged,
        )?;
        let staged_identity = match staged {
            Some(marker) => {
                validate_durable_effect_marker(&marker, inputs, index)?;
                marker.identity
            }
            None => {
                let stage_intent = Self::read_durable_effect_marker(
                    state,
                    &inputs.snapshot_ticket,
                    index,
                    DurableAuthorityEffectPhase::StageIntent,
                )?;
                match stage_intent {
                    Some(marker) => {
                        validate_durable_effect_marker(&marker, inputs, index)?;
                        if marker.identity != *expected {
                            return Err("durable authority stage intent identity drifted; preserved ActiveRecovery".into());
                        }
                    }
                    None => {
                        if durable_authority_entry_identity(parent, source)? != *expected
                            || durable_authority_entry_identity(parent, &stage)?
                                != DurableAuthorityTargetIdentity::Absent
                        {
                            return Err("durable authority target drifted before stage intent; preserved ActiveRecovery".into());
                        }
                        let marker = Self::durable_effect_marker(
                            inputs,
                            index,
                            DurableAuthorityEffectPhase::StageIntent,
                            expected.clone(),
                        );
                        self.persist_or_validate_durable_marker(
                            state,
                            &inputs.snapshot_ticket,
                            &durable_authority_effect_marker_name(
                                index,
                                DurableAuthorityEffectPhase::StageIntent,
                            ),
                            &marker,
                        )?;
                        #[cfg(test)]
                        if test_durable_authority_crash_after_boundary(index, "stage-intent") {
                            test_durable_authority_exit_after_boundary();
                        }
                    }
                }
                if durable_authority_entry_identity(parent, source)? != *expected {
                    return Err(
                        "durable authority target drifted before staging; preserved ActiveRecovery"
                            .into(),
                    );
                }
                let identity = if tree.existed {
                    tree.validate_backup_identity()?;
                    let backup_parent = tree
                        .backup_parent
                        .as_ref()
                        .ok_or("durable authority backup parent is unknown")?;
                    let backup_name = tree
                        .backup_name
                        .as_deref()
                        .ok_or("durable authority backup name is unknown")?;
                    match durable_authority_entry_identity(parent, &stage)? {
                        DurableAuthorityTargetIdentity::Absent => {
                            let mut budget = AuthorityCopyBudget::default();
                            AuthorityTreeSnapshot::copy_tree_from_at(
                                &tree.backup,
                                backup_parent,
                                backup_name,
                                parent,
                                &stage,
                                &mut budget,
                                false,
                                tree.scope,
                                &tree.backup,
                            )?;
                            #[cfg(test)]
                            if test_durable_authority_crash_after_boundary(index, "stage-copy") {
                                test_durable_authority_exit_after_boundary();
                            }
                            #[cfg(test)]
                            if test_durable_authority_stage_crash_after_copy(index) {
                                return Err("test-only durable authority crash after stage effect".into());
                            }
                        }
                        _ if durable_authority_tree_matches(&tree.backup, &stage_path)? => {}
                        _ => return Err("durable authority staged target identity is unknown; preserved ActiveRecovery".into()),
                    }
                    durable_authority_entry_identity(parent, &stage)?
                } else {
                    DurableAuthorityTargetIdentity::Absent
                };
                let marker = Self::durable_effect_marker(
                    inputs,
                    index,
                    DurableAuthorityEffectPhase::Staged,
                    identity.clone(),
                );
                self.persist_or_validate_durable_marker(
                    state,
                    &inputs.snapshot_ticket,
                    &durable_authority_effect_marker_name(
                        index,
                        DurableAuthorityEffectPhase::Staged,
                    ),
                    &marker,
                )?;
                #[cfg(test)]
                if test_durable_authority_crash_after_boundary(index, "staged") {
                    test_durable_authority_exit_after_boundary();
                }
                identity
            }
        };
        if staged_identity != DurableAuthorityTargetIdentity::Absent
            && durable_authority_entry_identity(parent, &stage)? != staged_identity
            && durable_authority_entry_identity(parent, source)? != staged_identity
        {
            return Err(
                "durable authority staged target identity drifted; preserved ActiveRecovery".into(),
            );
        }
        let tombstoned = Self::read_durable_effect_marker(
            state,
            &inputs.snapshot_ticket,
            index,
            DurableAuthorityEffectPhase::Tombstoned,
        )?;
        if let Some(marker) = tombstoned.as_ref() {
            validate_durable_effect_marker(marker, inputs, index)?;
            if marker.identity != *expected {
                return Err(
                    "durable authority tombstone marker identity drifted; preserved ActiveRecovery"
                        .into(),
                );
            }
        } else {
            let tombstone_intent = Self::read_durable_effect_marker(
                state,
                &inputs.snapshot_ticket,
                index,
                DurableAuthorityEffectPhase::TombstoneIntent,
            )?;
            match tombstone_intent {
                Some(marker) => {
                    validate_durable_effect_marker(&marker, inputs, index)?;
                    if marker.identity != *expected {
                        return Err("durable authority tombstone intent identity drifted; preserved ActiveRecovery".into());
                    }
                }
                None => {
                    if durable_authority_entry_identity(parent, source)? != *expected
                        || durable_authority_entry_identity(parent, &tombstone)?
                            != DurableAuthorityTargetIdentity::Absent
                    {
                        return Err("durable authority target drifted before tombstone intent; preserved ActiveRecovery".into());
                    }
                    let marker = Self::durable_effect_marker(
                        inputs,
                        index,
                        DurableAuthorityEffectPhase::TombstoneIntent,
                        expected.clone(),
                    );
                    self.persist_or_validate_durable_marker(
                        state,
                        &inputs.snapshot_ticket,
                        &durable_authority_effect_marker_name(
                            index,
                            DurableAuthorityEffectPhase::TombstoneIntent,
                        ),
                        &marker,
                    )?;
                    #[cfg(test)]
                    if test_durable_authority_crash_after_boundary(index, "tombstone-intent") {
                        test_durable_authority_exit_after_boundary();
                    }
                }
            }
            let current = durable_authority_entry_identity(parent, source)?;
            let tombstone_current = durable_authority_entry_identity(parent, &tombstone)?;
            if current == *expected && tombstone_current == DurableAuthorityTargetIdentity::Absent {
                if current != DurableAuthorityTargetIdentity::Absent {
                    durable_authority_rename(parent, source, &tombstone)?;
                    if durable_authority_entry_identity(parent, &tombstone)? != *expected {
                        return Err("durable authority tombstone identity changed; preserved ActiveRecovery".into());
                    }
                    #[cfg(test)]
                    if test_durable_authority_crash_after_boundary(index, "tombstone-rename") {
                        test_durable_authority_exit_after_boundary();
                    }
                    #[cfg(test)]
                    if test_durable_authority_tombstone_crash_after_rename(index) {
                        return Err(
                            "test-only durable authority crash after tombstone rename".into()
                        );
                    }
                }
            } else if current != DurableAuthorityTargetIdentity::Absent
                || tombstone_current != *expected
            {
                return Err(
                    "durable authority target drifted before tombstone; preserved ActiveRecovery"
                        .into(),
                );
            }
            let marker = Self::durable_effect_marker(
                inputs,
                index,
                DurableAuthorityEffectPhase::Tombstoned,
                expected.clone(),
            );
            self.persist_or_validate_durable_marker(
                state,
                &inputs.snapshot_ticket,
                &durable_authority_effect_marker_name(
                    index,
                    DurableAuthorityEffectPhase::Tombstoned,
                ),
                &marker,
            )?;
            #[cfg(test)]
            if test_durable_authority_crash_after_boundary(index, "tombstoned") {
                test_durable_authority_exit_after_boundary();
            }
        }
        let outcome = Self::read_durable_effect_marker(
            state,
            &inputs.snapshot_ticket,
            index,
            DurableAuthorityEffectPhase::Outcome,
        )?;
        if let Some(marker) = outcome.as_ref() {
            validate_durable_effect_marker(marker, inputs, index)?;
            if marker.identity != staged_identity {
                return Err(
                    "durable authority outcome marker identity drifted; preserved ActiveRecovery"
                        .into(),
                );
            }
        } else {
            // Tombstoned proves the rename happened, not that the quarantined
            // pre-effect entry is still present. Before durable Outcome there
            // is no legitimate cleanup state: a missing or replaced tombstone
            // is unknown drift and must not authorize promotion.
            if expected != &DurableAuthorityTargetIdentity::Absent
                && durable_authority_entry_identity(parent, &tombstone)? != *expected
            {
                return Err(
                    "durable authority tombstone drifted before outcome; preserved ActiveRecovery"
                        .into(),
                );
            }
            let outcome_intent = Self::read_durable_effect_marker(
                state,
                &inputs.snapshot_ticket,
                index,
                DurableAuthorityEffectPhase::OutcomeIntent,
            )?;
            match outcome_intent {
                Some(marker) => {
                    validate_durable_effect_marker(&marker, inputs, index)?;
                    if marker.identity != staged_identity {
                        return Err("durable authority outcome intent identity drifted; preserved ActiveRecovery".into());
                    }
                }
                None => {
                    if durable_authority_entry_identity(parent, source)?
                        != DurableAuthorityTargetIdentity::Absent
                        || (staged_identity != DurableAuthorityTargetIdentity::Absent
                            && durable_authority_entry_identity(parent, &stage)? != staged_identity)
                    {
                        return Err("durable authority target drifted before outcome intent; preserved ActiveRecovery".into());
                    }
                    let marker = Self::durable_effect_marker(
                        inputs,
                        index,
                        DurableAuthorityEffectPhase::OutcomeIntent,
                        staged_identity.clone(),
                    );
                    self.persist_or_validate_durable_marker(
                        state,
                        &inputs.snapshot_ticket,
                        &durable_authority_effect_marker_name(
                            index,
                            DurableAuthorityEffectPhase::OutcomeIntent,
                        ),
                        &marker,
                    )?;
                    #[cfg(test)]
                    if test_durable_authority_crash_after_boundary(index, "outcome-intent") {
                        test_durable_authority_exit_after_boundary();
                    }
                }
            }
            let current = durable_authority_entry_identity(parent, source)?;
            if current == DurableAuthorityTargetIdentity::Absent {
                if staged_identity != DurableAuthorityTargetIdentity::Absent {
                    if durable_authority_entry_identity(parent, &stage)? != staged_identity {
                        return Err(
                            "durable authority staged target is missing; preserved ActiveRecovery"
                                .into(),
                        );
                    }
                    durable_authority_rename(parent, &stage, source)?;
                    #[cfg(test)]
                    if test_durable_authority_outcome_crash_after_promotion(index) {
                        return Err(
                            "test-only durable authority crash after outcome promotion".into()
                        );
                    }
                    #[cfg(test)]
                    if test_durable_authority_crash_after_boundary(index, "promotion") {
                        test_durable_authority_exit_after_boundary();
                    }
                }
            } else if current != staged_identity {
                return Err(
                    "durable authority target drifted before promotion; preserved ActiveRecovery"
                        .into(),
                );
            }
            if durable_authority_entry_identity(parent, source)? != staged_identity {
                return Err(
                    "durable authority promotion identity changed; preserved ActiveRecovery".into(),
                );
            }
            let marker = Self::durable_effect_marker(
                inputs,
                index,
                DurableAuthorityEffectPhase::Outcome,
                staged_identity.clone(),
            );
            self.persist_or_validate_durable_marker(
                state,
                &inputs.snapshot_ticket,
                &durable_authority_effect_marker_name(index, DurableAuthorityEffectPhase::Outcome),
                &marker,
            )?;
            #[cfg(test)]
            if test_durable_authority_crash_after_boundary(index, "outcome") {
                test_durable_authority_exit_after_boundary();
            }
        }
        if durable_authority_entry_identity(parent, source)? != staged_identity {
            return Err(
                "durable authority completed target identity drifted; preserved ActiveRecovery"
                    .into(),
            );
        }
        if expected != &DurableAuthorityTargetIdentity::Absent {
            let tombstone_identity = durable_authority_entry_identity(parent, &tombstone)?;
            if tombstone_identity == DurableAuthorityTargetIdentity::Absent {
                // Outcome is durable before tombstone cleanup. A crash after
                // cleanup must resume as completed, not as foreign drift.
                return Ok(());
            }
            if tombstone_identity != *expected {
                return Err(
                    "durable authority tombstone identity drifted; preserved ActiveRecovery".into(),
                );
            }
            AuthorityTreeSnapshot::remove_current_at(tree.scope, parent, &tombstone)?;
            #[cfg(test)]
            if test_durable_authority_crash_after_boundary(index, "cleanup") {
                test_durable_authority_exit_after_boundary();
            }
        }
        Ok(())
    }

    pub(super) fn cleanup_when_expendable(
        &mut self,
    ) -> Result<AuthorityCleanupOutcome, AuthorityCleanupFailure> {
        self.preserve_recovery = true;
        if self.cleanup_ticket.is_none() {
            self.cleanup_ticket = Some(register_authority_cleanup(&self.cleanup_context)?);
        }
        let ticket = self.cleanup_ticket.as_ref().ok_or_else(|| {
            AuthorityCleanupFailure::new(
                AuthorityCleanupPhase::SnapshotRegistration,
                "cleanup_register_failed：事务快照清理票据缺失。",
            )
        })?;
        let cleanup_ticket = prepare_registered_authority_cleanup(&self.cleanup_context, ticket)?;
        self.cleanup_ticket = Some(cleanup_ticket);
        self.cleanup_prepared = true;
        let ticket = self.cleanup_ticket.as_ref().ok_or_else(|| {
            AuthorityCleanupFailure::new(
                AuthorityCleanupPhase::SnapshotRegistration,
                "cleanup_register_failed：cleanup-only 票据缺失。",
            )
        })?;
        match finalize_registered_authority_cleanup(&self.cleanup_context, ticket) {
            Ok(outcome) => {
                self.preserve_recovery = false;
                self.cleanup_prepared = true;
                Ok(outcome)
            }
            Err(error) => Err(error),
        }
    }

    pub(super) fn prepare_success(
        &mut self,
        value: &mut Value,
    ) -> Result<(), AuthorityCleanupFailure> {
        match self.cleanup_when_expendable() {
            Ok(AuthorityCleanupOutcome::Cleared) => Ok(()),
            Err(error) if self.cleanup_prepared && error.cleanup_requirement().is_some() => {
                self.preserve_recovery = true;
                if let Some(object) = value.as_object_mut() {
                    object.insert("status".into(), Value::String("degraded".into()));
                    object.insert(
                        "recovery_status".into(),
                        Value::String("cleanup_required".into()),
                    );
                    object.insert(
                        "cleanup_message".into(),
                        Value::String("运行事务已完成，但私有事务快照需要稍后安全清理。".into()),
                    );
                }
                Ok(())
            }
            Err(error) => {
                self.preserve_recovery = true;
                Err(error)
            }
        }
    }

    pub(super) fn commit(&mut self) {
        if !self.cleanup_prepared {
            let _ = self.cleanup_when_expendable();
        }
    }
}

fn durable_authority_effect_marker_name(
    target: usize,
    phase: DurableAuthorityEffectPhase,
) -> String {
    let phase = match phase {
        DurableAuthorityEffectPhase::StageIntent => "stage-intent",
        DurableAuthorityEffectPhase::Staged => "staged",
        DurableAuthorityEffectPhase::TombstoneIntent => "tombstone-intent",
        DurableAuthorityEffectPhase::Tombstoned => "tombstoned",
        DurableAuthorityEffectPhase::OutcomeIntent => "outcome-intent",
        DurableAuthorityEffectPhase::Outcome => "outcome",
    };
    format!("{DURABLE_AUTHORITY_RESTORE_EFFECT_PREFIX}.{target}.{phase}.json")
}

fn durable_authority_side_path(
    tree: &AuthorityTreeSnapshot,
    inputs: &AuthorityRestoreReplayInputs,
    target: usize,
    kind: &str,
) -> Result<PathBuf, String> {
    let parent = tree
        .source
        .parent()
        .ok_or("durable authority target has no parent")?;
    if !inputs
        .snapshot_ticket
        .managed_id
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.'))
    {
        return Err("durable authority snapshot ticket name is invalid".into());
    }
    Ok(parent.join(format!(
        ".csswitch-authority-{}-{target}-{kind}",
        inputs.snapshot_ticket.managed_id
    )))
}

fn durable_authority_entry_identity(
    parent: &std::fs::File,
    name: &std::ffi::CStr,
) -> Result<DurableAuthorityTargetIdentity, String> {
    match AuthorityTreeSnapshot::stat_destination_at(parent, name) {
        Ok(metadata) => {
            let kind = metadata.st_mode & crate::platform::S_IFMT;
            if !matches!(kind, crate::platform::S_IFDIR | crate::platform::S_IFREG) {
                return Err(
                    "durable authority target identity is unknown; preserved ActiveRecovery".into(),
                );
            }
            Ok(DurableAuthorityTargetIdentity::Entry {
                device: u64::try_from(metadata.st_dev)
                    .map_err(|_| "durable authority target device is invalid")?,
                inode: inode_u64(metadata.st_ino)
                    .ok_or("durable authority target inode is invalid")?,
                kind,
            })
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Ok(DurableAuthorityTargetIdentity::Absent)
        }
        Err(_) => {
            Err("durable authority target identity is unknown; preserved ActiveRecovery".into())
        }
    }
}

fn decode_durable_authority_reservation(
    bytes: &[u8],
) -> Result<DurableScienceQuiescenceReservation, String> {
    let value: Value = serde_json::from_slice(bytes)
        .map_err(|_| "durable authority reservation format is invalid")?;
    if value["schema_version"].as_u64()
        != Some(u64::from(DURABLE_AUTHORITY_RESERVATION_SCHEMA_VERSION))
    {
        return Err(
            "durable authority reservation version is unsupported; preserved ActiveRecovery for manual recovery"
                .into(),
        );
    }
    serde_json::from_value(value)
        .map_err(|_| "durable authority reservation format is invalid".into())
}

/// The descriptor/inode check anchors the parent name, while this bounded
/// content digest catches in-place writes that keep the target inode. It is
/// still not a pathname CAS claim against a same-UID non-cooperating writer.
fn durable_authority_tree_digest(tree: &AuthorityTreeSnapshot) -> Result<Option<String>, String> {
    let Some(parent) = tree.source_parent.as_ref() else {
        return Ok(None);
    };
    let name = tree
        .source_name
        .as_deref()
        .ok_or("durable authority target name identity is unknown")?;
    match AuthorityTreeSnapshot::stat_destination_at(parent, name) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => {
            return Err(
                "durable authority target content identity is unknown; preserved ActiveRecovery"
                    .into(),
            )
        }
    }
    let mut budget = AuthorityCopyBudget::default();
    let mut digest = Sha256::new();
    durable_authority_digest_bytes(&mut digest, b"format", b"csswitch-authority-content-v1");
    durable_authority_digest_entry(parent, name, &mut budget, &mut digest)?;
    Ok(Some(format!("{:x}", digest.finalize())))
}

fn durable_authority_digest_entry(
    parent: &std::fs::File,
    name: &std::ffi::CStr,
    budget: &mut AuthorityCopyBudget,
    digest: &mut Sha256,
) -> Result<(), String> {
    let before = AuthorityTreeSnapshot::stat_destination_at(parent, name).map_err(|_| {
        "durable authority target content identity is unknown; preserved ActiveRecovery"
    })?;
    let kind = before.st_mode & crate::platform::S_IFMT;
    durable_authority_digest_bytes(digest, b"entry-name", name.to_bytes());
    durable_authority_digest_u64(digest, b"mode", u64::from(before.st_mode & 0o777));
    match kind {
        crate::platform::S_IFREG => {
            let bytes = u64::try_from(before.st_size).map_err(|_| {
                "durable authority target content identity is unknown; preserved ActiveRecovery"
            })?;
            AuthorityTreeSnapshot::charge_entry(
                budget,
                bytes,
                AuthoritySnapshotScope::Test,
                AuthoritySnapshotCategory::Other,
            )?;
            durable_authority_digest_bytes(digest, b"entry-kind", b"regular");
            durable_authority_digest_u64(digest, b"file-length", bytes);
            let mut file = AuthorityTreeSnapshot::open_destination_at(
                parent.as_raw_fd(),
                name,
                crate::platform::O_RDONLY,
                0,
            )
            .map_err(|_| {
                "durable authority target content identity is unknown; preserved ActiveRecovery"
            })?;
            let opened = file.metadata().map_err(|_| {
                "durable authority target content identity is unknown; preserved ActiveRecovery"
            })?;
            if !AuthorityTreeSnapshot::destination_entry_matches_file(
                &before,
                &opened,
                crate::platform::S_IFREG,
            ) {
                return Err(
                    "durable authority target content identity changed; preserved ActiveRecovery"
                        .into(),
                );
            }
            durable_authority_digest_header(digest, b"file-contents", bytes);
            let copied = std::io::copy(&mut file, digest).map_err(|_| {
                "durable authority target content identity is unknown; preserved ActiveRecovery"
            })?;
            if copied != bytes {
                return Err(
                    "durable authority target content identity changed; preserved ActiveRecovery"
                        .into(),
                );
            }
        }
        crate::platform::S_IFDIR => {
            AuthorityTreeSnapshot::charge_entry(
                budget,
                0,
                AuthoritySnapshotScope::Test,
                AuthoritySnapshotCategory::Other,
            )?;
            durable_authority_digest_bytes(digest, b"entry-kind", b"directory");
            let directory = AuthorityTreeSnapshot::open_directory_at(parent.as_raw_fd(), name)
                .map_err(|_| {
                    "durable authority target content identity is unknown; preserved ActiveRecovery"
                })?;
            let metadata = directory.metadata().map_err(|_| {
                "durable authority target content identity is unknown; preserved ActiveRecovery"
            })?;
            if !AuthorityTreeSnapshot::destination_entry_matches_file(
                &before,
                &metadata,
                crate::platform::S_IFDIR,
            ) {
                return Err(
                    "durable authority target content identity changed; preserved ActiveRecovery"
                        .into(),
                );
            }
            let children =
                AuthorityTreeSnapshot::read_directory_names(&directory).map_err(|_| {
                    "durable authority target content identity is unknown; preserved ActiveRecovery"
                })?;
            durable_authority_digest_u64(digest, b"directory-child-count", children.len() as u64);
            for child in children {
                let child = std::ffi::CString::new(child.as_encoded_bytes()).map_err(|_| {
                    "durable authority target content identity is unknown; preserved ActiveRecovery"
                })?;
                durable_authority_digest_entry(&directory, &child, budget, digest)?;
            }
            durable_authority_digest_bytes(digest, b"directory-end", b"");
        }
        crate::platform::S_IFLNK => {
            AuthorityTreeSnapshot::charge_entry(
                budget,
                0,
                AuthoritySnapshotScope::Test,
                AuthoritySnapshotCategory::Other,
            )?;
            durable_authority_digest_bytes(digest, b"entry-kind", b"symlink");
            let size = usize::try_from(before.st_size).map_err(|_| {
                "durable authority target content identity is unknown; preserved ActiveRecovery"
            })?;
            let target = AuthorityTreeSnapshot::readlink_destination_at(parent, name, size)
                .map_err(|_| {
                    "durable authority target content identity is unknown; preserved ActiveRecovery"
                })?;
            durable_authority_digest_bytes(digest, b"symlink-target", &target);
        }
        _ => {
            return Err(
                "durable authority target content identity is unsafe; preserved ActiveRecovery"
                    .into(),
            )
        }
    }
    let after = AuthorityTreeSnapshot::stat_destination_at(parent, name).map_err(|_| {
        "durable authority target content identity changed; preserved ActiveRecovery"
    })?;
    if !AuthorityTreeSnapshot::stat_entry_stable(&before, &after) {
        return Err(
            "durable authority target content identity changed; preserved ActiveRecovery".into(),
        );
    }
    Ok(())
}

fn durable_authority_digest_u64(digest: &mut Sha256, label: &[u8], value: u64) {
    durable_authority_digest_bytes(digest, label, &value.to_be_bytes());
}

fn durable_authority_digest_bytes(digest: &mut Sha256, label: &[u8], bytes: &[u8]) {
    durable_authority_digest_header(digest, label, bytes.len() as u64);
    digest.update(bytes);
}

fn durable_authority_digest_header(digest: &mut Sha256, label: &[u8], value_len: u64) {
    digest.update((label.len() as u64).to_be_bytes());
    digest.update(label);
    digest.update(value_len.to_be_bytes());
}

fn durable_authority_rename(
    parent: &std::fs::File,
    from: &std::ffi::CStr,
    to: &std::ffi::CStr,
) -> Result<(), String> {
    #[cfg(unix)]
    let result = unsafe {
        libc::renameat(
            parent.as_raw_fd(),
            from.as_ptr(),
            parent.as_raw_fd(),
            to.as_ptr(),
        )
    };
    // Windows 降级：renameat 无等价物；返回失败由上层显式报错。
    #[cfg(not(unix))]
    let result: i32 = -1;
    if result == 0 {
        parent.sync_all().map_err(|_| {
            "durable authority rename sync failed; preserved ActiveRecovery".to_string()
        })
    } else {
        Err("durable authority rename failed; preserved ActiveRecovery".into())
    }
}

fn validate_durable_effect_marker(
    marker: &DurableAuthorityEffectMarker,
    inputs: &AuthorityRestoreReplayInputs,
    target: usize,
) -> Result<(), String> {
    if marker.compensation_id != inputs.compensation_id
        || marker.snapshot_ticket != inputs.snapshot_ticket
        || marker.target != target
    {
        return Err(
            "durable authority effect marker identity drifted; preserved ActiveRecovery".into(),
        );
    }
    Ok(())
}

/// Re-open an interrupted stage only when it is byte-for-byte the captured
/// backup tree. This is a recovery validation, not a pathname CAS claim: a
/// same-UID non-cooperating writer can still race pathname operations and is
/// intentionally handled by fail-closed identity checks at every boundary.
fn durable_authority_tree_matches(backup: &Path, stage: &Path) -> Result<bool, String> {
    let left = std::fs::symlink_metadata(backup)
        .map_err(|_| "durable authority backup identity is unknown")?;
    let right = match std::fs::symlink_metadata(stage) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(_) => return Err("durable authority staged target identity is unknown".into()),
    };
    if left.file_type().is_symlink() != right.file_type().is_symlink()
        || left.is_dir() != right.is_dir()
        || left.is_file() != right.is_file()
        || left.permissions().mode() & 0o777 != right.permissions().mode() & 0o777
    {
        return Ok(false);
    }
    if left.file_type().is_symlink() {
        return std::fs::read_link(backup)
            .map_err(|_| "durable authority backup symlink is unreadable".to_string())
            .and_then(|target| {
                std::fs::read_link(stage)
                    .map(|candidate| candidate == target)
                    .map_err(|_| "durable authority staged symlink is unreadable".into())
            });
    }
    if left.is_file() {
        if left.len() != right.len() {
            return Ok(false);
        }
        return std::fs::read(backup)
            .map_err(|_| "durable authority backup file is unreadable".to_string())
            .and_then(|expected| {
                std::fs::read(stage)
                    .map(|candidate| candidate == expected)
                    .map_err(|_| "durable authority staged file is unreadable".into())
            });
    }
    if !left.is_dir() {
        return Ok(false);
    }
    let names = |path: &Path| -> Result<std::collections::BTreeSet<std::ffi::OsString>, String> {
        std::fs::read_dir(path)
            .map_err(|_| "durable authority tree is unreadable".to_string())?
            .map(|entry| {
                entry
                    .map(|entry| entry.file_name())
                    .map_err(|_| "durable authority tree entry is unreadable".to_string())
            })
            .collect()
    };
    let left_names = names(backup)?;
    if left_names != names(stage)? {
        return Ok(false);
    }
    left_names.into_iter().try_fold(true, |matches, name| {
        if !matches {
            return Ok(false);
        }
        durable_authority_tree_matches(&backup.join(&name), &stage.join(name))
    })
}

#[cfg(test)]
fn test_durable_authority_stage_crash_after_copy(target: usize) -> bool {
    let seam = super::authority_snapshot::SANDBOX_SESSION_TEST_SEAMS
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .durable_authority_stage_crash_after_copy
        .clone();
    let Some((configured_target, observation)) = seam else {
        return false;
    };
    if configured_target != target {
        return false;
    }
    let observed = config::load_from(&config::default_dir())
        .ok()
        .and_then(|cfg| cfg.runtime_compensation)
        .and_then(|journal| {
            journal
                .steps
                .into_iter()
                .find(|step| step.step == config::RuntimeCompensationStep::AuthorityRestore)
        })
        .is_some_and(|step| step.outcome == config::RuntimeCompensationStepState::InProgress);
    let _ = std::fs::write(
        observation,
        if observed {
            &b"in_progress"[..]
        } else {
            &b"other"[..]
        },
    );
    true
}

#[cfg(test)]
fn test_durable_authority_tombstone_crash_after_rename(target: usize) -> bool {
    super::authority_snapshot::SANDBOX_SESSION_TEST_SEAMS
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .durable_authority_tombstone_crash_after_rename
        == Some(target)
}

#[cfg(test)]
fn test_durable_authority_outcome_crash_after_promotion(target: usize) -> bool {
    super::authority_snapshot::SANDBOX_SESSION_TEST_SEAMS
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .durable_authority_outcome_crash_after_promotion
        == Some(target)
}

#[cfg(test)]
fn test_durable_authority_crash_after_boundary(target: usize, boundary: &str) -> bool {
    super::authority_snapshot::SANDBOX_SESSION_TEST_SEAMS
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .durable_authority_crash_after_boundary
        .as_ref()
        .is_some_and(|(configured_target, configured_boundary)| {
            *configured_target == target && configured_boundary == boundary
        })
}

#[cfg(test)]
fn test_durable_authority_exit_after_boundary() -> ! {
    // The matrix only arms this seam in a dedicated subprocess.  Exit avoids
    // unwinding/destructors, matching the durable state a crash leaves behind.
    std::process::exit(86)
}

impl Drop for OneClickAuthoritySnapshot {
    fn drop(&mut self) {
        // Drop can run during panic unwinding after protected state changed.
        // Only explicit success or fully successful compensation may publish
        // ActiveRecovery -> CleanupOnly and remove the recovery snapshot.
        self.preserve_recovery = true;
    }
}

#[cfg(test)]
mod durable_authority_digest_tests {
    use super::*;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn canonical_tree_digest_separates_legacy_concatenation_collision() {
        let requested_root = std::env::temp_dir().join(format!(
            "csswitch-authority-digest-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&requested_root).unwrap();
        // macOS commonly exposes the temporary directory through `/var`, a
        // symlink. The descriptor-anchored opener correctly rejects that path,
        // so canonicalize the fixture before building its parent descriptor.
        let root = requested_root.canonicalize().unwrap();
        let source = root.join("authority");
        std::fs::create_dir(&source).unwrap();
        let mode = crate::platform::ModeT::try_from(0o600).unwrap().to_le_bytes();
        // The old raw stream had no child count/end framing. One child whose
        // bytes embed a second child record collides with two child records.
        let mut embedded = b"Xb".to_vec();
        embedded.extend(mode);
        embedded.extend(b"fileY");
        let mut legacy_one = b"a".to_vec();
        legacy_one.extend(mode);
        legacy_one.extend(b"file");
        legacy_one.extend(&embedded);
        let mut legacy_two = b"a".to_vec();
        legacy_two.extend(mode);
        legacy_two.extend(b"fileXb");
        legacy_two.extend(mode);
        legacy_two.extend(b"fileY");
        assert_eq!(
            legacy_one, legacy_two,
            "fixture must collide under the old raw concatenation"
        );
        std::fs::write(source.join("a"), &embedded).unwrap();
        std::fs::set_permissions(source.join("a"), crate::platform::permissions_from_mode(0o600)).unwrap();
        let snapshot = AuthorityTreeSnapshot {
            scope: AuthoritySnapshotScope::Test,
            source: source.clone(),
            backup: root.join("unused-backup"),
            existed: true,
            source_parent: Some(AuthorityTreeSnapshot::open_absolute_directory(&root).unwrap()),
            source_name: Some(AuthorityTreeSnapshot::destination_name(&source).unwrap()),
            backup_identity: None,
            backup_parent: None,
            backup_name: None,
        };
        let source_inode = std::fs::metadata(&source).unwrap().ino();
        let first = durable_authority_tree_digest(&snapshot).unwrap();
        std::fs::remove_file(source.join("a")).unwrap();
        std::fs::write(source.join("a"), b"X").unwrap();
        std::fs::write(source.join("b"), b"Y").unwrap();
        for name in ["a", "b"] {
            std::fs::set_permissions(source.join(name), crate::platform::permissions_from_mode(0o600))
                .unwrap();
        }
        assert_eq!(
            std::fs::metadata(&source).unwrap().ino(),
            source_inode,
            "the collision counterexample must retain the authority root identity"
        );
        let second = durable_authority_tree_digest(&snapshot).unwrap();
        assert_ne!(
            first, second,
            "canonical node/count/end framing must reject the old ambiguous tree stream"
        );
        let _ = std::fs::remove_dir_all(root);
    }
}
