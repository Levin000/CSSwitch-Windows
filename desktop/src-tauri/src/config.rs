//! 本地配置读写：正式构建使用 `~/.csswitch/config.json`，Acceptance 构建使用
//! `~/.csswitch-acceptance/config.json`。多 profile + 多模型目录形态（schema v4）。
//!
//! 安全要求（对齐 spec §3 / §5.1，参考 CC Switch 的明文本地存储但加严文件安全）：
//!   - 目录 0700，文件 0600。
//!   - 读/写前 `lstat`（symlink_metadata）拒绝符号链接，绝不跟随写到别处或读到别处。
//!   - 写用「临时文件（O_CREAT|O_EXCL, 0600）+ 原子 rename」，避免半写与竞态。
//!   - profile key 明文存盘（用户已知悉），但**绝不进日志**；回显给前端只给掩码（末 4 位）。
//!
//! 存储升级：schema_version 探测 + v1（旧固定槽）→ canonical v2 → v3 → v4，
//! 迁移留不可覆盖的版本备份，普通覆盖前留滚动 `config.json.bak`，
//! 清 key / 删 profile 后净化滚动备份（旧明文 key 不可从 .bak 恢复）。
//!
//! 所有函数以显式 `dir` 参数工作，便于用临时目录做无副作用的单元测试；
//! 生产代码用 [`default_dir`]；目录名由编译期构建变体固定，不能由运行时输入改写。

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::CString;
use std::fs;
use std::io::{self, Read, Write};
use std::marker::PhantomData;
#[cfg(unix)]
use std::os::fd::{AsRawFd, FromRawFd};
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::rc::Rc;

use crate::model_catalog::{ModelRoute, RoleBindings};
use crate::provider_contracts::{CredentialSource, ModelPolicy};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use crate::platform::CanonicalizeExt;

struct ConfigAccessState {
    downgrade_terminal: bool,
}

static CONFIG_ACCESS: std::sync::Mutex<ConfigAccessState> =
    std::sync::Mutex::new(ConfigAccessState {
        downgrade_terminal: false,
    });

const CONFIG_WRITER_LOCK_FILE: &str = ".config.writer.lock";
const RUNTIME_COMPENSATION_AUTH_LOCK_FILE: &str = ".runtime-compensation.auth.lock";
const CODEX_DISABLE_OPERATION_RECEIPT_FILE: &str = "codex-disable-operation.v1.json";
const CODEX_DISABLE_OPERATION_RECEIPT_CLEARING_FILE: &str = ".codex-disable-operation.v1.clearing";
const CODEX_DISABLE_OPERATION_FENCE_KEY: &str = "codex_disable_operation";
const CODEX_DISABLE_OPERATION_FENCE_SCHEMA_VERSION: u32 = 1;
pub(crate) const CONFIG_MUTATION_OPERATION_RECEIPT_FILE: &str = "config-mutation-operation.v1.json";
pub(crate) const CONFIG_MUTATION_OPERATION_CLEARING_FILE: &str =
    ".config-mutation-operation.v1.clearing";
pub(crate) const CONFIG_MUTATION_OPERATION_FENCE_KEY: &str = "config_mutation_operation";
const CONFIG_MUTATION_OPERATION_FENCE_SCHEMA_VERSION: u32 = 1;
pub(crate) const MAX_CONFIG_MUTATION_RECEIPT_BYTES: usize = 64 * 1024;

#[cfg(test)]
pub(crate) const PENDING_AUTHORITY_CLEANUP_MANIFEST_FILE: &str =
    "pending-authority-cleanup.v1.json";

#[cfg(test)]
#[derive(Clone, Debug)]
pub(crate) struct AtomicWritePreRenameObservation {
    pub(crate) temp_path: PathBuf,
    pub(crate) target_path: PathBuf,
    pub(crate) temp_device: u64,
    pub(crate) temp_inode: u64,
    pub(crate) config_access_held: bool,
}

#[cfg(test)]
struct AtomicWritePreRenameFailpoint {
    id: u64,
    directory_device: u64,
    directory_inode: u64,
    observation: std::sync::Arc<std::sync::Mutex<Option<AtomicWritePreRenameObservation>>>,
}

#[cfg(test)]
static ATOMIC_WRITE_PRE_RENAME_FAILPOINT: std::sync::LazyLock<
    std::sync::Mutex<Option<AtomicWritePreRenameFailpoint>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(None));

#[cfg(test)]
static ATOMIC_WRITE_PRE_RENAME_FAILPOINT_ID: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(1);

#[cfg(test)]
pub(crate) struct AtomicWritePreRenameFailpointGuard {
    id: u64,
}

#[cfg(test)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PendingCleanupIdentity {
    pub(crate) managed_id: String,
    pub(crate) path: PathBuf,
    pub(crate) device: u64,
    pub(crate) inode: u64,
    pub(crate) marker: String,
}

#[cfg(test)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum PendingCleanupLifecycleEvent {
    Register(PendingCleanupIdentity),
    Remove {
        identity: PendingCleanupIdentity,
        not_found: bool,
    },
    Clear,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PendingCleanupPublishFault {
    Register,
    Prepare,
    Clear,
}

#[cfg(test)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum PendingCleanupInitialTicket {
    Present(PendingCleanupIdentity),
    Missing(PendingCleanupIdentity),
}

#[cfg(test)]
impl PendingCleanupInitialTicket {
    fn identity(&self) -> &PendingCleanupIdentity {
        match self {
            Self::Present(identity) | Self::Missing(identity) => identity,
        }
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PendingCleanupRemovalOutcome {
    Removed,
    AlreadyAbsent,
    Error,
}

#[cfg(test)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum PendingCleanupFinalState {
    NotFound,
    Present(PendingCleanupIdentity),
    Error,
}

#[cfg(test)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum PendingCleanupRaceAction {
    Recreate { path: PathBuf, marker: String },
    Delete { path: PathBuf },
}

#[cfg(test)]
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct PendingCleanupLifecycleObservation {
    pub(crate) events: Vec<PendingCleanupLifecycleEvent>,
    pub(crate) attempted_register: Option<PendingCleanupIdentity>,
    pub(crate) validated_loader_count: usize,
    pub(crate) initial_ticket_count: usize,
    pub(crate) race_hook_count: usize,
    pub(crate) delete_attempt_count: usize,
    pub(crate) completion_count: usize,
    pub(crate) causal_mismatch_count: usize,
    pub(crate) race_identity: Option<PendingCleanupIdentity>,
}

#[cfg(test)]
#[derive(Default)]
#[allow(dead_code)]
struct PendingCleanupLifecycleSeam {
    registered_identity: Option<PendingCleanupIdentity>,
    initial_ticket: Option<PendingCleanupInitialTicket>,
    race_action: Option<PendingCleanupRaceAction>,
    observation: PendingCleanupLifecycleObservation,
    publish_fault: Option<PendingCleanupPublishFault>,
}

#[cfg(test)]
static PENDING_CLEANUP_LIFECYCLE_SEAM: std::sync::LazyLock<
    std::sync::Mutex<Option<PendingCleanupLifecycleSeam>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(None));

#[cfg(test)]
static CONFIG_UPDATE_COMMIT_FAILURE: std::sync::LazyLock<
    std::sync::Mutex<Option<(std::thread::ThreadId, PathBuf)>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(None));

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DropRollingBackupFault {
    Unlink,
    DirectorySync,
}

#[cfg(test)]
static DROP_ROLLING_BACKUP_FAILURE: std::sync::LazyLock<
    std::sync::Mutex<Option<(std::thread::ThreadId, PathBuf, DropRollingBackupFault)>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(None));

#[cfg(test)]
static DOWNGRADE_COMMIT_FAILURE: std::sync::LazyLock<
    std::sync::Mutex<Option<(std::thread::ThreadId, PathBuf, bool)>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(None));

#[cfg(test)]
static MIGRATION_COMMIT_FAILURE: std::sync::LazyLock<
    std::sync::Mutex<Option<(std::thread::ThreadId, PathBuf)>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(None));

#[cfg(test)]
pub(crate) struct ConfigUpdateCommitFailureGuard;

#[cfg(test)]
impl Drop for ConfigUpdateCommitFailureGuard {
    fn drop(&mut self) {
        *CONFIG_UPDATE_COMMIT_FAILURE
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = None;
    }
}

#[cfg(test)]
pub(crate) fn test_arm_update_commit_failure(dir: PathBuf) -> ConfigUpdateCommitFailureGuard {
    *CONFIG_UPDATE_COMMIT_FAILURE
        .lock()
        .unwrap_or_else(|error| error.into_inner()) = Some((std::thread::current().id(), dir));
    ConfigUpdateCommitFailureGuard
}

#[cfg(test)]
pub(crate) struct DropRollingBackupFailureGuard;

#[cfg(test)]
impl Drop for DropRollingBackupFailureGuard {
    fn drop(&mut self) {
        *DROP_ROLLING_BACKUP_FAILURE
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = None;
    }
}

#[cfg(test)]
pub(crate) fn test_arm_drop_rolling_backup_failure(
    dir: PathBuf,
    fault: DropRollingBackupFault,
) -> DropRollingBackupFailureGuard {
    *DROP_ROLLING_BACKUP_FAILURE
        .lock()
        .unwrap_or_else(|error| error.into_inner()) =
        Some((std::thread::current().id(), dir, fault));
    DropRollingBackupFailureGuard
}

#[cfg(test)]
pub(crate) struct DowngradeCommitFailureGuard;

#[cfg(test)]
impl Drop for DowngradeCommitFailureGuard {
    fn drop(&mut self) {
        *DOWNGRADE_COMMIT_FAILURE
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = None;
    }
}

#[cfg(test)]
pub(crate) fn test_arm_downgrade_commit_failure(
    dir: PathBuf,
    exit_required: bool,
) -> DowngradeCommitFailureGuard {
    *DOWNGRADE_COMMIT_FAILURE
        .lock()
        .unwrap_or_else(|error| error.into_inner()) =
        Some((std::thread::current().id(), dir, exit_required));
    DowngradeCommitFailureGuard
}

#[cfg(test)]
struct MigrationCommitFailureGuard;

#[cfg(test)]
impl Drop for MigrationCommitFailureGuard {
    fn drop(&mut self) {
        *MIGRATION_COMMIT_FAILURE
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = None;
    }
}

#[cfg(test)]
fn test_arm_migration_commit_failure(dir: PathBuf) -> MigrationCommitFailureGuard {
    *MIGRATION_COMMIT_FAILURE
        .lock()
        .unwrap_or_else(|error| error.into_inner()) = Some((std::thread::current().id(), dir));
    MigrationCommitFailureGuard
}

#[cfg(test)]
pub(crate) struct PendingCleanupLifecycleGuard;

#[cfg(test)]
impl Drop for PendingCleanupLifecycleGuard {
    fn drop(&mut self) {
        *PENDING_CLEANUP_LIFECYCLE_SEAM
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = None;
    }
}

#[cfg(test)]
pub(crate) fn test_arm_pending_cleanup_lifecycle(
    publish_fault: Option<PendingCleanupPublishFault>,
) -> PendingCleanupLifecycleGuard {
    *PENDING_CLEANUP_LIFECYCLE_SEAM
        .lock()
        .unwrap_or_else(|error| error.into_inner()) = Some(PendingCleanupLifecycleSeam {
        publish_fault,
        ..Default::default()
    });
    PendingCleanupLifecycleGuard
}

#[cfg(test)]
pub(crate) fn test_pending_cleanup_lifecycle_observation() -> PendingCleanupLifecycleObservation {
    let seam = PENDING_CLEANUP_LIFECYCLE_SEAM
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    seam.as_ref()
        .map(|seam| seam.observation.clone())
        .unwrap_or_default()
}

#[cfg(test)]
#[allow(dead_code)]
pub(crate) fn test_pending_cleanup_register_publish_attempt(
    identity: PendingCleanupIdentity,
) -> io::Result<()> {
    let mut seam = PENDING_CLEANUP_LIFECYCLE_SEAM
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let Some(seam) = seam.as_mut() else {
        return Ok(());
    };
    seam.observation.attempted_register = Some(identity);
    if seam.publish_fault == Some(PendingCleanupPublishFault::Register) {
        return Err(io::Error::other(
            "test-only pending cleanup REGISTER publish failure",
        ));
    }
    Ok(())
}

#[cfg(test)]
#[allow(dead_code)]
pub(crate) fn test_pending_cleanup_clear_publish_attempt() -> io::Result<()> {
    let seam = PENDING_CLEANUP_LIFECYCLE_SEAM
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    if seam
        .as_ref()
        .is_some_and(|seam| seam.publish_fault == Some(PendingCleanupPublishFault::Clear))
    {
        return Err(io::Error::other(
            "test-only pending cleanup CLEAR publish failure",
        ));
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn test_pending_cleanup_prepare_publish_attempt() -> io::Result<()> {
    let seam = PENDING_CLEANUP_LIFECYCLE_SEAM
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    if seam
        .as_ref()
        .is_some_and(|seam| seam.publish_fault == Some(PendingCleanupPublishFault::Prepare))
    {
        return Err(io::Error::other(
            "test-only pending cleanup PREPARE publish failure",
        ));
    }
    Ok(())
}

#[cfg(test)]
#[allow(dead_code)]
pub(crate) fn test_observe_pending_cleanup_register_published(identity: PendingCleanupIdentity) {
    let mut seam = PENDING_CLEANUP_LIFECYCLE_SEAM
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    if let Some(seam) = seam.as_mut() {
        seam.registered_identity = Some(identity.clone());
        seam.observation
            .events
            .push(PendingCleanupLifecycleEvent::Register(identity));
    }
}

#[cfg(test)]
pub(crate) fn test_observe_pending_cleanup_manifest_validated(identity: PendingCleanupIdentity) {
    let mut seam = PENDING_CLEANUP_LIFECYCLE_SEAM
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    if let Some(seam) = seam.as_mut() {
        seam.registered_identity = Some(identity.clone());
        seam.observation.validated_loader_count += 1;
        seam.observation
            .events
            .push(PendingCleanupLifecycleEvent::Register(identity));
    }
}

#[cfg(test)]
pub(crate) fn test_observe_pending_cleanup_initial_ticket(ticket: PendingCleanupInitialTicket) {
    let mut seam = PENDING_CLEANUP_LIFECYCLE_SEAM
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let Some(seam) = seam.as_mut() else {
        return;
    };
    seam.observation.initial_ticket_count += 1;
    if seam.registered_identity.as_ref() != Some(ticket.identity()) {
        seam.observation.causal_mismatch_count += 1;
        return;
    }
    seam.initial_ticket = Some(ticket);
}

#[cfg(test)]
pub(crate) fn test_configure_pending_cleanup_race(action: PendingCleanupRaceAction) {
    let mut seam = PENDING_CLEANUP_LIFECYCLE_SEAM
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    if let Some(seam) = seam.as_mut() {
        seam.race_action = Some(action);
    }
}

#[cfg(test)]
#[allow(dead_code)]
pub(crate) fn test_pending_cleanup_race_hook() -> io::Result<()> {
    let action = {
        let mut seam = PENDING_CLEANUP_LIFECYCLE_SEAM
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let Some(seam) = seam.as_mut() else {
            return Ok(());
        };
        seam.observation.race_hook_count += 1;
        seam.race_action.clone()
    };
    let race_identity = match action {
        Some(PendingCleanupRaceAction::Recreate { path, marker }) => {
            fs::create_dir(&path)?;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
            let marker_path = path.join(".csswitch-one-click-rollback.marker");
            fs::write(&marker_path, format!("{marker}\n"))?;
            fs::set_permissions(&marker_path, fs::Permissions::from_mode(0o600))?;
            let metadata = path.symlink_metadata()?;
            Some(PendingCleanupIdentity {
                managed_id: path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or_default()
                    .to_string(),
                path,
                device: metadata.dev(),
                inode: metadata.ino(),
                marker,
            })
        }
        Some(PendingCleanupRaceAction::Delete { path }) => {
            fs::remove_dir_all(path)?;
            None
        }
        None => None,
    };
    let mut seam = PENDING_CLEANUP_LIFECYCLE_SEAM
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    if let Some(seam) = seam.as_mut() {
        seam.observation.race_identity = race_identity;
    }
    Ok(())
}

#[cfg(test)]
#[allow(dead_code)]
pub(crate) fn test_observe_pending_cleanup_delete_attempt() {
    let mut seam = PENDING_CLEANUP_LIFECYCLE_SEAM
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    if let Some(seam) = seam.as_mut() {
        seam.observation.delete_attempt_count += 1;
    }
}

#[cfg(test)]
pub(crate) fn test_observe_pending_cleanup_completion(
    outcome: PendingCleanupRemovalOutcome,
    final_state: PendingCleanupFinalState,
) {
    let mut seam = PENDING_CLEANUP_LIFECYCLE_SEAM
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let Some(seam) = seam.as_mut() else {
        return;
    };
    seam.observation.completion_count += 1;
    let Some(ticket) = seam.initial_ticket.take() else {
        seam.observation.causal_mismatch_count += 1;
        return;
    };
    let event = match (ticket, outcome, final_state) {
        (
            PendingCleanupInitialTicket::Present(identity),
            PendingCleanupRemovalOutcome::Removed,
            PendingCleanupFinalState::NotFound,
        ) => Some(PendingCleanupLifecycleEvent::Remove {
            identity,
            not_found: false,
        }),
        (
            PendingCleanupInitialTicket::Missing(identity),
            PendingCleanupRemovalOutcome::AlreadyAbsent,
            PendingCleanupFinalState::NotFound,
        ) => Some(PendingCleanupLifecycleEvent::Remove {
            identity,
            not_found: true,
        }),
        _ => None,
    };
    if let Some(event) = event {
        seam.observation.events.push(event);
    } else {
        seam.observation.causal_mismatch_count += 1;
    }
}

#[cfg(test)]
#[allow(dead_code)]
pub(crate) fn test_observe_pending_cleanup_clear_published() {
    let mut seam = PENDING_CLEANUP_LIFECYCLE_SEAM
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    if let Some(seam) = seam.as_mut() {
        seam.observation
            .events
            .push(PendingCleanupLifecycleEvent::Clear);
    }
}

#[cfg(test)]
impl Drop for AtomicWritePreRenameFailpointGuard {
    fn drop(&mut self) {
        let mut failpoint = ATOMIC_WRITE_PRE_RENAME_FAILPOINT
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if failpoint.as_ref().is_some_and(|armed| armed.id == self.id) {
            *failpoint = None;
        }
    }
}

#[cfg(test)]
pub(crate) fn test_arm_pending_manifest_pre_rename_failure(
    directory: &Path,
) -> io::Result<(
    AtomicWritePreRenameFailpointGuard,
    std::sync::Arc<std::sync::Mutex<Option<AtomicWritePreRenameObservation>>>,
)> {
    let expected = default_dir().canonicalize_norm()?;
    let actual = directory.canonicalize_norm()?;
    if actual != expected {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "test-only manifest failpoint requires the exact config directory",
        ));
    }
    let metadata = actual.symlink_metadata()?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "test-only manifest failpoint requires a regular config directory",
        ));
    }
    let id = ATOMIC_WRITE_PRE_RENAME_FAILPOINT_ID.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let observation = std::sync::Arc::new(std::sync::Mutex::new(None));
    let armed = AtomicWritePreRenameFailpoint {
        id,
        directory_device: metadata.dev(),
        directory_inode: metadata.ino(),
        observation: observation.clone(),
    };
    *ATOMIC_WRITE_PRE_RENAME_FAILPOINT
        .lock()
        .unwrap_or_else(|error| error.into_inner()) = Some(armed);
    Ok((AtomicWritePreRenameFailpointGuard { id }, observation))
}

fn config_access() -> std::sync::MutexGuard<'static, ConfigAccessState> {
    CONFIG_ACCESS
        .lock()
        .unwrap_or_else(|error| error.into_inner())
}

#[cfg(test)]
fn atomic_write_pre_rename_failure(
    secure: &SecureDir,
    target: &str,
    temp: &str,
    _bytes: &[u8],
) -> io::Result<()> {
    let failpoint = ATOMIC_WRITE_PRE_RENAME_FAILPOINT
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let Some(armed) = failpoint.as_ref() else {
        return Ok(());
    };
    if target != PENDING_AUTHORITY_CLEANUP_MANIFEST_FILE {
        return Ok(());
    }
    let directory = secure.file.metadata()?;
    if directory.dev() != armed.directory_device || directory.ino() != armed.directory_inode {
        return Ok(());
    }
    let temp_path = secure.path.join(temp);
    let target_path = secure.path.join(target);
    let metadata = temp_path.symlink_metadata()?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.permissions().mode() & 0o777 != 0o600
    {
        return Err(io::Error::other(
            "test-only pre-rename observation rejected an unsafe temp",
        ));
    }
    *armed
        .observation
        .lock()
        .unwrap_or_else(|error| error.into_inner()) = Some(AtomicWritePreRenameObservation {
        temp_path,
        target_path,
        temp_device: metadata.dev(),
        temp_inode: metadata.ino(),
        config_access_held: CONFIG_ACCESS.try_lock().is_err(),
    });
    Err(io::Error::other(
        "test-only pending manifest failure after temp sync before rename",
    ))
}

fn ensure_config_access_open(access: &ConfigAccessState) -> io::Result<()> {
    if access.downgrade_terminal {
        Err(io::Error::other(
            "配置已降为 v2，CSSwitch 正在终态退出；拒绝再次读取或写入，避免自动迁回当前 schema v4。",
        ))
    } else {
        Ok(())
    }
}

pub(crate) fn default_proxy_port() -> u16 {
    18991
}
pub(crate) fn default_sandbox_port() -> u16 {
    8990
}
pub(crate) fn default_mode() -> String {
    "proxy".to_string()
}

pub(crate) fn validate_runtime_ports(proxy_port: u16, sandbox_port: u16) -> Result<(), String> {
    if proxy_port == 8765 || sandbox_port == 8765 {
        return Err("端口 8765 是真实 Science 实例保留端口，不能用。".into());
    }
    if proxy_port == 0 || sandbox_port == 0 {
        return Err("端口不能为 0。".into());
    }
    if proxy_port == sandbox_port {
        return Err("代理端口与沙箱端口不能相同。".into());
    }
    Ok(())
}

/// 当前配置 schema 版本。>4 的文件由更新版本 app 写入，本版本拒绝启动（不误改）。
pub const CURRENT_SCHEMA_VERSION: u32 = 4;

#[derive(Serialize, Deserialize, Clone, Default, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeBindingCommit {
    pub profile_id: String,
    pub route_fp: String,
    pub catalog_fp: String,
    pub binding_fp: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub science_adoption_attempt_id: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Default, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GatewayRuntimeJournalIdentity {
    pub provider: String,
    pub shim: String,
    pub launch_id: String,
    #[serde(default)]
    pub provider_contract_id: String,
    #[serde(default)]
    pub provider_contract_digest: String,
    pub catalog_fp: String,
}

#[derive(Serialize, Deserialize, Clone, Default, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeTransactionV1 {
    pub transaction_id: String,
    pub target_profile_id: String,
    pub stage: String,
    pub previous_binding: Option<RuntimeBindingCommit>,
    #[serde(default)]
    pub previous_gateway: Option<GatewayRuntimeJournalIdentity>,
}

/// Source-compatible name for the unversioned journal written before R2.
/// New code should store it through [`RuntimeTransactionRecord::V1`].
#[allow(dead_code)]
pub type RuntimeTransactionJournal = RuntimeTransactionV1;

pub const RUNTIME_TRANSACTION_SCHEMA_VERSION_V2: u32 = 2;

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeTransactionOperation {
    OneClick,
    ProfileSwitch,
    HistoryRecovery,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeTransactionPhase {
    StopOldScience,
    StartGateway,
    AuthoritySnapshotActive,
    StartScienceEnvironmentPending,
    WaitScienceDbReverify,
    RestartScienceAfterDbHeal,
    VerifyScienceDbAfterRestart,
    VerifyScienceCatalog,
    StartFormalGateway,
    RecoverInterruptedGateway,
    HistoryCredentialWritePending,
    HistoryAuthorityRestorePending,
    HistoryAuthorityRestoreSucceeded,
    HistoryCredentialPublished,
    ResumeAfterHistoryRestore,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeEnvironmentExposure {
    NotExposed,
    Possible,
    Exposed,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeSnapshotTicket {
    pub managed_id: String,
}

impl RuntimeSnapshotTicket {
    pub(crate) fn verified(managed_id: String) -> Result<Self, String> {
        if !valid_runtime_snapshot_ticket(&managed_id) {
            return Err("runtime_transaction V2 snapshot ticket is invalid".into());
        }
        Ok(Self { managed_id })
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeCompensationStep {
    ScienceCleanup,
    SshCleanup,
    AuthorityRestore,
    ConfigRestore,
    AppStateRestore,
    GatewayRestore,
    PriorScienceRestart,
    SnapshotCleanup,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeCompensationSkipCause {
    NoScienceCandidate,
    NoPriorScience,
    CrossRuntimeEnvironment,
    BlockedByScienceCleanup,
    BlockedByAuthorityRestore,
    SnapshotPreserved,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum RuntimeCompensationStepState {
    Pending,
    InProgress,
    Succeeded,
    Failed,
    Skipped { cause: RuntimeCompensationSkipCause },
}

impl RuntimeCompensationStepState {
    pub(crate) fn is_terminal(self) -> bool {
        matches!(self, Self::Succeeded | Self::Failed | Self::Skipped { .. })
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeCompensationStepProgress {
    pub step: RuntimeCompensationStep,
    pub outcome: RuntimeCompensationStepState,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum RuntimeCompensationState {
    NotStarted,
    InProgress,
    Incomplete {
        failed_steps: Vec<RuntimeCompensationStep>,
    },
}

pub const RUNTIME_COMPENSATION_SCHEMA_VERSION_V1: u32 = 1;
pub const RUNTIME_COMPENSATION_SCHEMA_VERSION_V2: u32 = 2;

pub(crate) const ONE_CLICK_COMPENSATION_STEPS: [RuntimeCompensationStep; 5] = [
    RuntimeCompensationStep::ScienceCleanup,
    RuntimeCompensationStep::SshCleanup,
    RuntimeCompensationStep::AuthorityRestore,
    RuntimeCompensationStep::PriorScienceRestart,
    RuntimeCompensationStep::SnapshotCleanup,
];

pub(crate) fn pending_one_click_compensation_steps() -> Vec<RuntimeCompensationStepProgress> {
    ONE_CLICK_COMPENSATION_STEPS
        .into_iter()
        .map(|step| RuntimeCompensationStepProgress {
            step,
            outcome: RuntimeCompensationStepState::Pending,
        })
        .collect()
}

/// Credential- and path-free durable owner for one-click compensation.
/// Business transaction details stay in `runtime_transaction`; V1 records only
/// aggregate progress, while V2 also records the fixed top-level step states.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeCompensationJournal {
    pub schema_version: u32,
    pub compensation_id: String,
    pub target_profile_id: String,
    pub runtime_fingerprint: String,
    pub snapshot_ticket: RuntimeSnapshotTicket,
    pub state: RuntimeCompensationState,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub steps: Vec<RuntimeCompensationStepProgress>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub science_adoption_attempt_ids: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeGatewayStopOutcome {
    NotAttempted,
    Pending,
    Stopped,
    NotManaged,
    SignalFailed,
    ExitUnconfirmed,
    AbsentAfterAttempt,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RuntimePriorScienceRecipe {
    pub port: u16,
    pub runtime_path: PathBuf,
    pub runtime_source: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_version: Option<String>,
    pub runtime_fingerprint: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_adoption_attempt_id: Option<String>,
    pub launch_receipt_digest: String,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuntimePriorStopOutcome {
    ExactStopped,
    NotStopped,
    Unknown,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum RuntimePriorStopState {
    #[default]
    NotRequired,
    Intent {
        recipe: RuntimePriorScienceRecipe,
    },
    Outcome {
        recipe: RuntimePriorScienceRecipe,
        outcome: RuntimePriorStopOutcome,
    },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum RuntimeFinalizeAction {
    ClearJournal,
    CommitBinding {
        binding: RuntimeBindingCommit,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        science_adoption_attempt_id: Option<String>,
    },
    ResumeOneClick,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum RuntimeFinalizeState {
    #[default]
    NotStarted,
    Intent {
        action: RuntimeFinalizeAction,
    },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeTransactionV2 {
    pub schema_version: u32,
    pub transaction_id: String,
    pub operation: RuntimeTransactionOperation,
    pub target_profile_id: String,
    pub phase: RuntimeTransactionPhase,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_fingerprint: Option<String>,
    pub environment_exposure: RuntimeEnvironmentExposure,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot_ticket: Option<RuntimeSnapshotTicket>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_binding: Option<RuntimeBindingCommit>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_gateway: Option<GatewayRuntimeJournalIdentity>,
    pub compensation: RuntimeCompensationState,
    pub gateway_stop_outcome: RuntimeGatewayStopOutcome,
    #[serde(default)]
    pub prior_stop: RuntimePriorStopState,
    #[serde(default)]
    pub finalize: RuntimeFinalizeState,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum RuntimeTransactionRecord {
    V1(RuntimeTransactionV1),
    V2(RuntimeTransactionV2),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeTransactionV1EnvironmentState<'a> {
    Pending { runtime_fingerprint: &'a str },
    AuthoritySnapshotActive { runtime_fingerprint: &'a str },
}

impl<'a> RuntimeTransactionV1EnvironmentState<'a> {
    pub fn runtime_fingerprint(self) -> &'a str {
        match self {
            Self::Pending {
                runtime_fingerprint,
            }
            | Self::AuthoritySnapshotActive {
                runtime_fingerprint,
            } => runtime_fingerprint,
        }
    }

    pub fn is_authority_snapshot_active(self) -> bool {
        matches!(self, Self::AuthoritySnapshotActive { .. })
    }
}

impl From<RuntimeTransactionV1> for RuntimeTransactionRecord {
    fn from(journal: RuntimeTransactionV1) -> Self {
        Self::V1(journal)
    }
}

impl Serialize for RuntimeTransactionRecord {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::V1(journal) => journal.serialize(serializer),
            Self::V2(journal) => journal.serialize(serializer),
        }
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
#[allow(clippy::large_enum_variant)]
enum RuntimeTransactionWire {
    V2(RuntimeTransactionV2),
    V1(RuntimeTransactionV1),
}

impl<'de> Deserialize<'de> for RuntimeTransactionRecord {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        match RuntimeTransactionWire::deserialize(deserializer)? {
            RuntimeTransactionWire::V1(journal) => {
                validate_runtime_transaction_v1(&journal).map_err(serde::de::Error::custom)?;
                Ok(Self::V1(journal))
            }
            RuntimeTransactionWire::V2(journal) => {
                validate_runtime_transaction_v2(&journal).map_err(serde::de::Error::custom)?;
                Ok(Self::V2(journal))
            }
        }
    }
}

impl RuntimeTransactionRecord {
    pub fn is_v2(&self) -> bool {
        matches!(self, Self::V2(_))
    }

    pub fn transaction_id(&self) -> &str {
        match self {
            Self::V1(journal) => &journal.transaction_id,
            Self::V2(journal) => &journal.transaction_id,
        }
    }

    pub fn target_profile_id(&self) -> &str {
        match self {
            Self::V1(journal) => &journal.target_profile_id,
            Self::V2(journal) => &journal.target_profile_id,
        }
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn previous_binding(&self) -> Option<&RuntimeBindingCommit> {
        match self {
            Self::V1(journal) => journal.previous_binding.as_ref(),
            Self::V2(journal) => journal.previous_binding.as_ref(),
        }
    }

    pub fn previous_gateway(&self) -> Option<&GatewayRuntimeJournalIdentity> {
        match self {
            Self::V1(journal) => journal.previous_gateway.as_ref(),
            Self::V2(journal) => journal.previous_gateway.as_ref(),
        }
    }

    #[allow(dead_code)]
    pub fn as_v1(&self) -> Option<&RuntimeTransactionV1> {
        match self {
            Self::V1(journal) => Some(journal),
            Self::V2(_) => None,
        }
    }

    #[allow(dead_code)]
    pub fn as_v1_mut(&mut self) -> Option<&mut RuntimeTransactionV1> {
        match self {
            Self::V1(journal) => Some(journal),
            Self::V2(_) => None,
        }
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn as_v2(&self) -> Option<&RuntimeTransactionV2> {
        match self {
            Self::V1(_) => None,
            Self::V2(journal) => Some(journal),
        }
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn as_v2_mut(&mut self) -> Option<&mut RuntimeTransactionV2> {
        match self {
            Self::V1(_) => None,
            Self::V2(journal) => Some(journal),
        }
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub fn legacy_stage(&self) -> Option<&str> {
        self.as_v1().map(|journal| journal.stage.as_str())
    }

    pub fn v1_environment_state(&self) -> Option<RuntimeTransactionV1EnvironmentState<'_>> {
        match self {
            Self::V1(journal) => legacy_environment_state(&journal.stage),
            Self::V2(_) => None,
        }
    }

    #[allow(dead_code)]
    pub fn runtime_fingerprint(&self) -> Option<&str> {
        match self {
            Self::V1(journal) => legacy_environment_state(&journal.stage)
                .map(RuntimeTransactionV1EnvironmentState::runtime_fingerprint),
            Self::V2(journal) => journal.runtime_fingerprint.as_deref(),
        }
    }

    pub fn requires_snapshot_preservation(&self) -> bool {
        match self {
            Self::V1(journal) => legacy_environment_state(&journal.stage).is_some(),
            Self::V2(journal) => journal.snapshot_ticket.is_some(),
        }
    }
}

fn valid_runtime_fingerprint(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn valid_runtime_snapshot_ticket(value: &str) -> bool {
    let Some(suffix) = value.strip_prefix(".one-click-rollback-") else {
        return false;
    };
    suffix.len() == 32
        && suffix
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn valid_hex_digest(value: &str) -> bool {
    valid_runtime_fingerprint(value)
}

fn valid_prior_science_recipe(recipe: &RuntimePriorScienceRecipe) -> bool {
    recipe.port != 0
        && recipe.port != 8765
        && recipe.runtime_path.is_absolute()
        && !recipe.runtime_source.is_empty()
        && valid_runtime_fingerprint(&recipe.runtime_fingerprint)
        && recipe
            .runtime_adoption_attempt_id
            .as_deref()
            .is_none_or(|value| {
                value.len() == 32
                    && value
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
            })
        && valid_hex_digest(&recipe.launch_receipt_digest)
}

fn valid_runtime_binding(binding: &RuntimeBindingCommit) -> bool {
    !binding.profile_id.is_empty()
        && !binding.route_fp.is_empty()
        && !binding.catalog_fp.is_empty()
        && !binding.binding_fp.is_empty()
        && binding
            .science_adoption_attempt_id
            .as_deref()
            .is_none_or(|value| {
                value.len() == 32
                    && value
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
            })
}

const LEGACY_SCIENCE_ENVIRONMENT_PENDING_STAGE_PREFIX: &str = "start_science_environment_pending:";
const LEGACY_AUTHORITY_SNAPSHOT_ACTIVE_STAGE_PREFIX: &str = "authority_snapshot_active:";

fn legacy_environment_state(stage: &str) -> Option<RuntimeTransactionV1EnvironmentState<'_>> {
    if let Some(runtime_fingerprint) =
        stage.strip_prefix(LEGACY_SCIENCE_ENVIRONMENT_PENDING_STAGE_PREFIX)
    {
        return valid_runtime_fingerprint(runtime_fingerprint).then_some(
            RuntimeTransactionV1EnvironmentState::Pending {
                runtime_fingerprint,
            },
        );
    }
    let runtime_fingerprint = stage.strip_prefix(LEGACY_AUTHORITY_SNAPSHOT_ACTIVE_STAGE_PREFIX)?;
    valid_runtime_fingerprint(runtime_fingerprint).then_some(
        RuntimeTransactionV1EnvironmentState::AuthoritySnapshotActive {
            runtime_fingerprint,
        },
    )
}

fn validate_runtime_transaction_v1(journal: &RuntimeTransactionV1) -> Result<(), String> {
    if journal.transaction_id.is_empty() || journal.target_profile_id.is_empty() {
        return Err("runtime_transaction V1 identity must be non-empty".into());
    }
    let known_plain = matches!(
        journal.stage.as_str(),
        "stop_old_science"
            | "start_gateway"
            | "wait_science_db_reverify"
            | "restart_science_after_db_heal"
            | "verify_science_db_after_restart"
            | "verify_science_catalog"
            | "start_formal_gateway"
            | "recover_interrupted_gateway"
    );
    if known_plain || legacy_environment_state(&journal.stage).is_some() {
        Ok(())
    } else {
        Err("unknown or malformed V1 runtime_transaction stage".into())
    }
}

fn valid_runtime_compensation_steps(journal: &RuntimeCompensationJournal) -> bool {
    if journal.steps.len() != ONE_CLICK_COMPENSATION_STEPS.len()
        || journal
            .steps
            .iter()
            .zip(ONE_CLICK_COMPENSATION_STEPS)
            .any(|(progress, expected)| progress.step != expected)
    {
        return false;
    }
    let mut open_or_pending_seen = false;
    for progress in &journal.steps {
        match progress.outcome {
            RuntimeCompensationStepState::Pending => open_or_pending_seen = true,
            RuntimeCompensationStepState::InProgress => {
                if open_or_pending_seen {
                    return false;
                }
                open_or_pending_seen = true;
            }
            terminal if terminal.is_terminal() => {
                if open_or_pending_seen {
                    return false;
                }
            }
            _ => return false,
        }
    }
    match &journal.state {
        RuntimeCompensationState::InProgress => true,
        RuntimeCompensationState::Incomplete { failed_steps } => {
            !journal
                .steps
                .iter()
                .any(|progress| progress.outcome == RuntimeCompensationStepState::InProgress)
                && journal
                    .steps
                    .iter()
                    .filter_map(|progress| {
                        (progress.outcome == RuntimeCompensationStepState::Failed)
                            .then_some(progress.step)
                    })
                    .eq(failed_steps.iter().copied())
        }
        RuntimeCompensationState::NotStarted => false,
    }
}

fn validate_runtime_transaction_v2(journal: &RuntimeTransactionV2) -> Result<(), String> {
    if journal.schema_version != RUNTIME_TRANSACTION_SCHEMA_VERSION_V2 {
        return Err("runtime_transaction V2 schema_version mismatch".into());
    }
    if journal.transaction_id.is_empty() || journal.target_profile_id.is_empty() {
        return Err("runtime_transaction V2 identity must be non-empty".into());
    }
    if let Some(fingerprint) = journal.runtime_fingerprint.as_deref() {
        if !valid_runtime_fingerprint(fingerprint) {
            return Err("runtime_transaction V2 fingerprint is invalid".into());
        }
    }
    if journal
        .snapshot_ticket
        .as_ref()
        .is_some_and(|ticket| !valid_runtime_snapshot_ticket(&ticket.managed_id))
    {
        return Err("runtime_transaction V2 snapshot ticket is invalid".into());
    }
    if matches!(
        &journal.compensation,
        RuntimeCompensationState::Incomplete { failed_steps } if failed_steps.is_empty()
    ) {
        return Err("runtime_transaction V2 incomplete compensation has no failed step".into());
    }
    if let RuntimeCompensationState::Incomplete { failed_steps } = &journal.compensation {
        for (index, step) in failed_steps.iter().enumerate() {
            if failed_steps[..index].contains(step) {
                return Err(
                    "runtime_transaction V2 incomplete compensation repeats a failed step".into(),
                );
            }
        }
    }

    let prior_stop_valid = match &journal.prior_stop {
        RuntimePriorStopState::NotRequired => true,
        RuntimePriorStopState::Intent { recipe }
        | RuntimePriorStopState::Outcome { recipe, .. } => valid_prior_science_recipe(recipe),
    };
    if !prior_stop_valid {
        return Err("runtime_transaction V2 prior Science recipe is invalid".into());
    }
    let finalize_valid = match &journal.finalize {
        RuntimeFinalizeState::NotStarted => true,
        RuntimeFinalizeState::Intent {
            action: RuntimeFinalizeAction::ClearJournal,
        } => true,
        RuntimeFinalizeState::Intent {
            action:
                RuntimeFinalizeAction::CommitBinding {
                    binding,
                    science_adoption_attempt_id,
                },
        } => {
            let matching_adoption_provenance = match (
                binding.science_adoption_attempt_id.as_deref(),
                science_adoption_attempt_id.as_deref(),
            ) {
                (None, None) => true,
                (Some(binding_id), Some(action_id)) => binding_id == action_id,
                _ => false,
            };
            valid_runtime_binding(binding)
                && science_adoption_attempt_id.as_deref().is_none_or(|value| {
                    value.len() == 32
                        && value
                            .bytes()
                            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
                })
                && matching_adoption_provenance
        }
        RuntimeFinalizeState::Intent {
            action: RuntimeFinalizeAction::ResumeOneClick,
        } => true,
    };
    if !finalize_valid {
        return Err("runtime_transaction V2 finalize action is invalid".into());
    }

    let one_click_identity = journal.runtime_fingerprint.is_some();
    let pre_snapshot_prior_stop = journal.snapshot_ticket.is_none()
        && journal.phase == RuntimeTransactionPhase::StopOldScience
        && matches!(
            journal.prior_stop,
            RuntimePriorStopState::Intent { .. } | RuntimePriorStopState::Outcome { .. }
        )
        && journal.finalize == RuntimeFinalizeState::NotStarted;
    let registered_one_click = journal.snapshot_ticket.is_some()
        && !matches!(journal.prior_stop, RuntimePriorStopState::Intent { .. })
        && !matches!(
            journal.prior_stop,
            RuntimePriorStopState::Outcome {
                outcome: RuntimePriorStopOutcome::NotStopped | RuntimePriorStopOutcome::Unknown,
                ..
            }
        );
    if journal.operation == RuntimeTransactionOperation::HistoryRecovery
        && (journal.compensation != RuntimeCompensationState::NotStarted
            || journal.previous_gateway.is_some())
    {
        return Err("runtime_transaction V2 history recovery has sibling-owned state".into());
    }
    let valid_phase = match (journal.operation, journal.phase) {
        (
            RuntimeTransactionOperation::OneClick,
            RuntimeTransactionPhase::StopOldScience
            | RuntimeTransactionPhase::StartGateway
            | RuntimeTransactionPhase::AuthoritySnapshotActive
            | RuntimeTransactionPhase::StartScienceEnvironmentPending
            | RuntimeTransactionPhase::WaitScienceDbReverify
            | RuntimeTransactionPhase::RestartScienceAfterDbHeal
            | RuntimeTransactionPhase::VerifyScienceDbAfterRestart
            | RuntimeTransactionPhase::VerifyScienceCatalog,
        ) => one_click_identity && (pre_snapshot_prior_stop || registered_one_click),
        (RuntimeTransactionOperation::OneClick, _) => false,
        (
            RuntimeTransactionOperation::ProfileSwitch,
            RuntimeTransactionPhase::StartFormalGateway
            | RuntimeTransactionPhase::RecoverInterruptedGateway,
        ) => {
            journal.runtime_fingerprint.is_none()
                && journal.snapshot_ticket.is_none()
                && journal.environment_exposure == RuntimeEnvironmentExposure::NotExposed
                && journal.prior_stop == RuntimePriorStopState::NotRequired
                && journal.finalize == RuntimeFinalizeState::NotStarted
        }
        (RuntimeTransactionOperation::ProfileSwitch, _) => false,
        (RuntimeTransactionOperation::HistoryRecovery, RuntimeTransactionPhase::StopOldScience) => {
            journal.runtime_fingerprint.is_some()
                && journal.snapshot_ticket.is_none()
                && journal.finalize == RuntimeFinalizeState::NotStarted
        }
        (
            RuntimeTransactionOperation::HistoryRecovery,
            RuntimeTransactionPhase::AuthoritySnapshotActive,
        ) => {
            journal.runtime_fingerprint.is_some()
                && journal.snapshot_ticket.is_some()
                && journal.finalize == RuntimeFinalizeState::NotStarted
                && !matches!(journal.prior_stop, RuntimePriorStopState::Intent { .. })
                && !matches!(
                    journal.prior_stop,
                    RuntimePriorStopState::Outcome {
                        outcome: RuntimePriorStopOutcome::NotStopped
                            | RuntimePriorStopOutcome::Unknown,
                        ..
                    }
                )
        }
        (
            RuntimeTransactionOperation::HistoryRecovery,
            RuntimeTransactionPhase::HistoryCredentialWritePending
            | RuntimeTransactionPhase::HistoryAuthorityRestorePending
            | RuntimeTransactionPhase::HistoryAuthorityRestoreSucceeded,
        ) => {
            journal.runtime_fingerprint.is_some()
                && journal.snapshot_ticket.is_some()
                && journal.finalize == RuntimeFinalizeState::NotStarted
                && !matches!(journal.prior_stop, RuntimePriorStopState::Intent { .. })
                && !matches!(
                    journal.prior_stop,
                    RuntimePriorStopState::Outcome {
                        outcome: RuntimePriorStopOutcome::NotStopped
                            | RuntimePriorStopOutcome::Unknown,
                        ..
                    }
                )
        }
        (
            RuntimeTransactionOperation::HistoryRecovery,
            RuntimeTransactionPhase::HistoryCredentialPublished,
        ) => {
            journal.runtime_fingerprint.is_some()
                && journal.snapshot_ticket.is_some()
                && matches!(
                    journal.finalize,
                    RuntimeFinalizeState::Intent {
                        action: RuntimeFinalizeAction::ClearJournal
                            | RuntimeFinalizeAction::ResumeOneClick,
                    }
                )
                && !matches!(journal.prior_stop, RuntimePriorStopState::Intent { .. })
                && !matches!(
                    journal.prior_stop,
                    RuntimePriorStopState::Outcome {
                        outcome: RuntimePriorStopOutcome::NotStopped
                            | RuntimePriorStopOutcome::Unknown,
                        ..
                    }
                )
        }
        (
            RuntimeTransactionOperation::HistoryRecovery,
            RuntimeTransactionPhase::ResumeAfterHistoryRestore,
        ) => {
            journal.runtime_fingerprint.is_some()
                && journal.snapshot_ticket.is_none()
                && !matches!(journal.prior_stop, RuntimePriorStopState::Intent { .. })
                && !matches!(
                    journal.prior_stop,
                    RuntimePriorStopState::Outcome {
                        outcome: RuntimePriorStopOutcome::NotStopped
                            | RuntimePriorStopOutcome::Unknown,
                        ..
                    }
                )
                && journal.finalize == RuntimeFinalizeState::NotStarted
        }
        (RuntimeTransactionOperation::HistoryRecovery, _) => false,
    };
    if !valid_phase {
        return Err("runtime_transaction V2 operation/phase identity is invalid".into());
    }

    let exposure_valid = match journal.phase {
        RuntimeTransactionPhase::StopOldScience
        | RuntimeTransactionPhase::StartGateway
        | RuntimeTransactionPhase::AuthoritySnapshotActive
        | RuntimeTransactionPhase::StartFormalGateway
        | RuntimeTransactionPhase::HistoryCredentialWritePending
        | RuntimeTransactionPhase::HistoryAuthorityRestorePending
        | RuntimeTransactionPhase::HistoryAuthorityRestoreSucceeded
        | RuntimeTransactionPhase::HistoryCredentialPublished
        | RuntimeTransactionPhase::ResumeAfterHistoryRestore => {
            journal.environment_exposure == RuntimeEnvironmentExposure::NotExposed
        }
        RuntimeTransactionPhase::StartScienceEnvironmentPending => {
            journal.environment_exposure == RuntimeEnvironmentExposure::Possible
        }
        RuntimeTransactionPhase::WaitScienceDbReverify
        | RuntimeTransactionPhase::RestartScienceAfterDbHeal
        | RuntimeTransactionPhase::VerifyScienceDbAfterRestart
        | RuntimeTransactionPhase::VerifyScienceCatalog => {
            journal.environment_exposure == RuntimeEnvironmentExposure::Exposed
        }
        RuntimeTransactionPhase::RecoverInterruptedGateway => true,
    };
    if !exposure_valid {
        return Err("runtime_transaction V2 phase/exposure is invalid".into());
    }

    let gateway_outcome_valid =
        if journal.phase == RuntimeTransactionPhase::RecoverInterruptedGateway {
            journal.gateway_stop_outcome != RuntimeGatewayStopOutcome::NotAttempted
        } else {
            journal.gateway_stop_outcome == RuntimeGatewayStopOutcome::NotAttempted
        };
    if !gateway_outcome_valid {
        return Err("runtime_transaction V2 gateway outcome is invalid for phase".into());
    }
    if journal.finalize != RuntimeFinalizeState::NotStarted {
        let finalize_owner_valid = journal.snapshot_ticket.is_some()
            && journal.compensation == RuntimeCompensationState::NotStarted
            && matches!(
                (&journal.operation, &journal.phase, &journal.finalize),
                (
                    RuntimeTransactionOperation::OneClick,
                    _,
                    RuntimeFinalizeState::Intent {
                        action: RuntimeFinalizeAction::ClearJournal
                            | RuntimeFinalizeAction::CommitBinding { .. },
                    },
                ) | (
                    RuntimeTransactionOperation::HistoryRecovery,
                    RuntimeTransactionPhase::HistoryCredentialPublished,
                    RuntimeFinalizeState::Intent {
                        action: RuntimeFinalizeAction::ClearJournal
                            | RuntimeFinalizeAction::ResumeOneClick,
                    },
                )
            );
        if !finalize_owner_valid {
            return Err("runtime_transaction V2 finalize intent has invalid ownership".into());
        }
    }
    Ok(())
}

fn default_schema_version() -> u32 {
    CURRENT_SCHEMA_VERSION
}

/// 一条命名配置。API key profile 的 key 明文存盘、只回掩码；OAuth profile 只存固定 opaque ref。
/// 运行行为由 `template_id + api_format` 经 provider-contract catalog 派生，不靠展示字段猜身份。
#[derive(Serialize, Deserialize, Clone, Default, Debug, PartialEq)]
pub struct Profile {
    pub id: String,
    pub name: String,
    pub template_id: String,
    pub category: String,
    pub api_format: String,
    pub base_url: String,
    #[serde(default)]
    pub api_key: String,
    /// v3 单模型的进程内兼容影子。v4 canonical 配置不再序列化该字段；
    /// load/normalize 从 default_model_route_id 回填，旧调用点在分模块迁移期间仍可读。
    #[serde(default, skip_serializing)]
    pub model: String,
    #[serde(default)]
    pub model_catalog: Vec<ModelRoute>,
    #[serde(default)]
    pub default_model_route_id: String,
    #[serde(default)]
    pub role_bindings: RoleBindings,
    #[serde(default)]
    pub credential_source: CredentialSource,
    #[serde(default)]
    pub credential_ref: Option<String>,
    #[serde(default)]
    pub model_policy: ModelPolicy,
    #[serde(default)]
    pub website_url: Option<String>,
    #[serde(default)]
    pub icon: Option<String>,
    #[serde(default)]
    pub icon_color: Option<String>,
    #[serde(default)]
    pub sort_index: Option<i64>,
    #[serde(default)]
    pub created_at: Option<i64>,
    #[serde(default)]
    pub notes: Option<String>,
    #[serde(flatten, default)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

/// 顶层配置。字段都有默认值，缺字段的旧文件也能读。
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Config {
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,
    #[serde(default)]
    pub profiles: Vec<Profile>,
    /// 生效 profile 的 id；空=无生效配置（运行时据此停代理、要求用户选）。
    #[serde(default)]
    pub active_id: String,
    #[serde(default = "default_proxy_port")]
    pub proxy_port: u16,
    #[serde(default = "default_sandbox_port")]
    pub sandbox_port: u16,
    /// 用户显式授权隔离 Science 通过系统 OpenSSH 读取 `~/.ssh/config`。
    /// 默认关闭；不复制或链接 `.ssh`，只在启动时注入受控 PATH wrapper。
    #[serde(default)]
    pub reuse_system_ssh: bool,
    /// 非官方 Codex → Science 桥接实验开关。默认关闭；关闭不删除 profile 或本地 OAuth。
    #[serde(default)]
    pub experimental_codex_enabled: bool,
    /// Codex 专用网络路由。v3 已发布前追加为 serde(default)，旧 v3 文件自动采用 auto。
    #[serde(default)]
    pub codex_network: csswitch_codex_network::CodexNetworkSettings,
    /// 代理的 path-secret。**持久化**并跨代理重启/切 profile/重开 app 复用，
    /// 这样已在跑的沙箱（其 ANTHROPIC_BASE_URL 里嵌了该 secret）不会因代理换 secret 而 403。
    /// 首次为空，由后端生成一次后写回。
    #[serde(default)]
    pub secret: String,
    /// 运行模式："proxy"（第三方）| "official"（真实 Claude Science）。
    #[serde(default = "default_mode")]
    pub mode: String,
    /// 一次性迁移提示（#9 甲：回填默认模型后告知用户）。get_config 读后清空。
    #[serde(default)]
    pub pending_notice: Option<String>,
    /// Last fully healthy gateway + isolated Science binding. Contains hashes
    /// and public identities only; never credentials, endpoints, URLs or prompts.
    #[serde(default)]
    pub runtime_binding: Option<RuntimeBindingCommit>,
    #[serde(default)]
    pub runtime_transaction: Option<RuntimeTransactionRecord>,
    /// Durable one-click compensation progress. Kept separate so rollback can
    /// restore the exact pre-operation runtime transaction without erasing the
    /// crash marker for the compensation that is currently executing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_compensation: Option<RuntimeCompensationJournal>,
    #[serde(flatten, default)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

/// Minimal Config-authority fence for the dedicated `op.codex-enable` disable
/// receipt.  The detailed plan and phase remain in the independent sidecar;
/// this credential-free reference only prevents sibling Config writers from
/// racing a destructive effect and binds terminal cleanup to the exact
/// before/after Config images even if receipt unlink has already completed.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct CodexDisableOperationFence {
    pub(crate) schema_version: u32,
    pub(crate) operation_id: String,
    pub(crate) intent_digest: String,
    pub(crate) before_config_fingerprint: String,
    pub(crate) after_config_fingerprint: String,
}

impl CodexDisableOperationFence {
    pub(crate) fn new(
        operation_id: String,
        intent_digest: String,
        before_config_fingerprint: String,
        after_config_fingerprint: String,
    ) -> Self {
        Self {
            schema_version: CODEX_DISABLE_OPERATION_FENCE_SCHEMA_VERSION,
            operation_id,
            intent_digest,
            before_config_fingerprint,
            after_config_fingerprint,
        }
    }

    fn validate(&self) -> io::Result<()> {
        let valid_lower_hex = |value: &str, len: usize| {
            value.len() == len
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        };
        if self.schema_version != CODEX_DISABLE_OPERATION_FENCE_SCHEMA_VERSION
            || !valid_lower_hex(&self.operation_id, 32)
            || !valid_lower_hex(&self.intent_digest, 64)
            || !valid_lower_hex(&self.before_config_fingerprint, 64)
            || !valid_lower_hex(&self.after_config_fingerprint, 64)
            || self.before_config_fingerprint == self.after_config_fingerprint
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Codex disable operation fence identity/schema 非法",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CodexDisableTerminalConfigImage {
    Before,
    After,
}

impl CodexDisableTerminalConfigImage {
    fn fingerprint<'a>(self, fence: &'a CodexDisableOperationFence) -> &'a str {
        match self {
            Self::Before => &fence.before_config_fingerprint,
            Self::After => &fence.after_config_fingerprint,
        }
    }
}

/// The small Config projection for the ordinary non-one-click mutation
/// protocol.  The detailed receipt remains in the credential-free sidecar;
/// this reference only fences cooperating Config writers and binds terminal
/// cleanup to exact Config/receipt identities.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct ConfigMutationOperationFence {
    pub(crate) schema_version: u32,
    pub(crate) operation_id: String,
    pub(crate) operation: String,
    pub(crate) phase: String,
    pub(crate) intent_digest: String,
    pub(crate) before_config_fingerprint: String,
    pub(crate) after_config_fingerprint: Option<String>,
    pub(crate) terminal_receipt_digest: Option<String>,
    pub(crate) config_state: Option<String>,
    pub(crate) runtime_state: Option<String>,
    pub(crate) auth_epoch: Option<String>,
    pub(crate) auth_generation: Option<u64>,
    pub(crate) auth_account_hash: Option<String>,
}

impl ConfigMutationOperationFence {
    pub(crate) fn begin(
        operation_id: String,
        operation: String,
        intent_digest: String,
        before_config_fingerprint: String,
        after_config_fingerprint: Option<String>,
    ) -> Self {
        Self {
            schema_version: CONFIG_MUTATION_OPERATION_FENCE_SCHEMA_VERSION,
            operation_id,
            operation,
            phase: "begin".into(),
            intent_digest,
            before_config_fingerprint,
            after_config_fingerprint,
            terminal_receipt_digest: None,
            config_state: None,
            runtime_state: None,
            auth_epoch: None,
            auth_generation: None,
            auth_account_hash: None,
        }
    }

    pub(crate) fn terminal(
        &self,
        receipt_digest: String,
        config_state: &str,
        runtime_state: &str,
        auth_epoch: Option<String>,
        auth_generation: Option<u64>,
        auth_account_hash: Option<String>,
    ) -> Self {
        let mut terminal = self.clone();
        terminal.phase = "terminal".into();
        terminal.terminal_receipt_digest = Some(receipt_digest);
        terminal.config_state = Some(config_state.into());
        terminal.runtime_state = Some(runtime_state.into());
        terminal.auth_epoch = auth_epoch;
        terminal.auth_generation = auth_generation;
        terminal.auth_account_hash = auth_account_hash;
        terminal
    }

    fn valid_lower_hex(value: &str, length: usize) -> bool {
        value.len() == length
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    }

    pub(crate) fn validate(&self) -> io::Result<()> {
        const OPERATIONS: &[&str] = &[
            "set_mode_official",
            "set_settings_destructive",
            "codex_auth_start",
            "codex_auth_logout",
            "set_codex_network",
            "clear_applied_profile_key",
            "delete_applied_profile",
        ];
        let valid_state = |value: Option<&String>, allowed: &[&str]| {
            value.is_none_or(|value| allowed.contains(&value.as_str()))
        };
        let base_valid = self.schema_version == CONFIG_MUTATION_OPERATION_FENCE_SCHEMA_VERSION
            && Self::valid_lower_hex(&self.operation_id, 32)
            && OPERATIONS.contains(&self.operation.as_str())
            && matches!(self.phase.as_str(), "begin" | "terminal")
            && Self::valid_lower_hex(&self.intent_digest, 64)
            && Self::valid_lower_hex(&self.before_config_fingerprint, 64)
            && self
                .after_config_fingerprint
                .as_deref()
                .is_none_or(|value| Self::valid_lower_hex(value, 64))
            && self.auth_epoch.as_deref().is_none_or(|value| {
                value.len() <= 128
                    && !value.is_empty()
                    && value
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            })
            && self
                .auth_account_hash
                .as_deref()
                .is_none_or(|value| Self::valid_lower_hex(value, 64))
            && valid_state(self.config_state.as_ref(), &["before", "after", "unknown"])
            && valid_state(
                self.runtime_state.as_ref(),
                &["preserved", "stopped", "restored", "unknown"],
            );
        if !base_valid {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Config mutation operation fence identity/schema 非法",
            ));
        }
        match self.phase.as_str() {
            "begin"
                if self.terminal_receipt_digest.is_none()
                    && self.config_state.is_none()
                    && self.runtime_state.is_none() =>
            {
                Ok(())
            }
            "terminal"
                if self
                    .terminal_receipt_digest
                    .as_deref()
                    .is_some_and(|value| Self::valid_lower_hex(value, 64))
                    && self.config_state.is_some()
                    && self.runtime_state.is_some() =>
            {
                Ok(())
            }
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Config mutation operation fence phase/terminal fields 非法",
            )),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ConfigMutationTerminalConfigImage {
    Before,
    After,
}

impl ConfigMutationTerminalConfigImage {
    fn fingerprint<'a>(self, fence: &'a ConfigMutationOperationFence) -> Option<&'a str> {
        match self {
            Self::Before => Some(&fence.before_config_fingerprint),
            Self::After => fence.after_config_fingerprint.as_deref(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ConfigMutationOrphanFenceRecovery {
    None,
    Cleared,
    ActiveReceipt,
    ConfigDrift,
    Attention,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CodexDisableOrphanFenceRecovery {
    None,
    Cleared,
    ConfigDrift,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            schema_version: CURRENT_SCHEMA_VERSION,
            profiles: Vec::new(),
            active_id: String::new(),
            proxy_port: default_proxy_port(),
            sandbox_port: default_sandbox_port(),
            reuse_system_ssh: false,
            experimental_codex_enabled: false,
            codex_network: csswitch_codex_network::CodexNetworkSettings::default(),
            secret: String::new(),
            mode: default_mode(),
            pending_notice: None,
            runtime_binding: None,
            runtime_transaction: None,
            runtime_compensation: None,
            extra: BTreeMap::new(),
        }
    }
}

pub(crate) fn require_template_enabled(cfg: &Config, template_id: &str) -> Result<(), String> {
    if template_id == "codex" && !cfg.experimental_codex_enabled {
        return Err(
            "Codex 桥接是实验功能，当前未启用。请先在“设置 > Codex 账号与连接”中显式开启。".into(),
        );
    }
    Ok(())
}

pub(crate) fn require_no_runtime_transaction(cfg: &Config) -> Result<(), String> {
    if cfg
        .codex_disable_operation_fence()
        .map_err(|error| error.to_string())?
        .is_some()
    {
        Err(
            "code=codex_disable_operation_in_progress Codex disable operation 尚未结束；请先完成恢复或处理 attention。"
                .into(),
        )
    } else if cfg
        .config_mutation_operation_fence()
        .map_err(|error| error.to_string())?
        .is_some()
    {
        Err(
            "code=config_mutation_operation_in_progress 普通配置变更尚未结束；请先完成恢复或处理 attention。"
                .into(),
        )
    } else if cfg.has_open_runtime_journal() {
        Err(
            "code=runtime_transaction_in_progress 运行时事务尚未结束；请先完成恢复或重试一键开始。"
                .into(),
        )
    } else {
        Ok(())
    }
}

/// Admission helper for a P2-B owner that already holds the dedicated
/// Config-mutation fence.  Ordinary writers must continue using
/// `require_no_runtime_transaction`, which rejects every open sibling fence;
/// only the exact owner may pass its own fence through the shared runtime
/// admission check.
pub(crate) fn require_no_runtime_transaction_for_mutation(
    cfg: &Config,
    expected: &ConfigMutationOperationFence,
) -> Result<(), String> {
    if cfg
        .codex_disable_operation_fence()
        .map_err(|error| error.to_string())?
        .is_some()
    {
        return Err(
            "code=codex_disable_operation_in_progress Codex disable operation 尚未结束；请先完成恢复或处理 attention."
                .into(),
        );
    }
    if cfg
        .config_mutation_operation_fence()
        .map_err(|error| error.to_string())?
        .as_ref()
        != Some(expected)
    {
        return Err(
            "code=config_mutation_operation_in_progress Config mutation operation fence 已变化或缺失。"
                .into(),
        );
    }
    if cfg.has_open_runtime_journal() {
        return Err(
            "code=runtime_transaction_in_progress 运行时事务尚未结束；请先完成恢复或重试一键开始。"
                .into(),
        );
    }
    Ok(())
}

impl Config {
    pub(crate) fn codex_disable_operation_fence(
        &self,
    ) -> io::Result<Option<CodexDisableOperationFence>> {
        self.extra
            .get(CODEX_DISABLE_OPERATION_FENCE_KEY)
            .map(|value| {
                let fence: CodexDisableOperationFence = serde_json::from_value(value.clone())
                    .map_err(|error| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("Codex disable operation fence 无法解析：{error}"),
                        )
                    })?;
                fence.validate()?;
                Ok(fence)
            })
            .transpose()
    }

    pub(crate) fn without_codex_disable_operation_fence(&self) -> Self {
        let mut normalized = self.clone();
        normalized.extra.remove(CODEX_DISABLE_OPERATION_FENCE_KEY);
        normalized
    }

    fn set_codex_disable_operation_fence(&mut self, fence: &CodexDisableOperationFence) {
        self.extra.insert(
            CODEX_DISABLE_OPERATION_FENCE_KEY.into(),
            serde_json::to_value(fence).expect("Codex disable operation fence is serializable"),
        );
    }

    fn clear_codex_disable_operation_fence(&mut self) {
        self.extra.remove(CODEX_DISABLE_OPERATION_FENCE_KEY);
    }

    pub(crate) fn config_mutation_operation_fence(
        &self,
    ) -> io::Result<Option<ConfigMutationOperationFence>> {
        self.extra
            .get(CONFIG_MUTATION_OPERATION_FENCE_KEY)
            .map(|value| {
                let fence: ConfigMutationOperationFence = serde_json::from_value(value.clone())
                    .map_err(|error| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("Config mutation operation fence 无法解析：{error}"),
                        )
                    })?;
                fence.validate()?;
                Ok(fence)
            })
            .transpose()
    }

    pub(crate) fn without_config_mutation_operation_fence(&self) -> Self {
        let mut normalized = self.clone();
        normalized.extra.remove(CONFIG_MUTATION_OPERATION_FENCE_KEY);
        normalized
    }

    fn set_config_mutation_operation_fence(&mut self, fence: &ConfigMutationOperationFence) {
        self.extra.insert(
            CONFIG_MUTATION_OPERATION_FENCE_KEY.into(),
            serde_json::to_value(fence).expect("Config mutation operation fence is serializable"),
        );
    }

    fn clear_config_mutation_operation_fence(&mut self) {
        self.extra.remove(CONFIG_MUTATION_OPERATION_FENCE_KEY);
    }

    pub fn has_open_runtime_journal(&self) -> bool {
        self.runtime_transaction.is_some() || self.runtime_compensation.is_some()
    }

    /// 当前选择 profile（active_id 空或悬空 → None）。
    pub fn active_profile(&self) -> Option<&Profile> {
        if self.active_id.is_empty() {
            return None;
        }
        self.profile_by_id(&self.active_id)
    }
    pub fn profile_by_id(&self, id: &str) -> Option<&Profile> {
        self.profiles.iter().find(|p| p.id == id)
    }
    pub fn profile_by_id_mut(&mut self, id: &str) -> Option<&mut Profile> {
        self.profiles.iter_mut().find(|p| p.id == id)
    }
}

/// Stable credential-free Config identity for the dedicated Codex-disable
/// protocol.  The operation fence itself is excluded so the same before/after
/// images remain comparable while the cross-process writer fence is held.
pub(crate) fn codex_disable_config_fingerprint(config: &Config) -> io::Result<String> {
    let normalized = config.without_codex_disable_operation_fence();
    let bytes = serde_json::to_vec(&normalized).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("无法编码 Codex disable config fingerprint：{error}"),
        )
    })?;
    let mut digest = Sha256::new();
    digest.update(b"csswitch-codex-disable-config-v1\0");
    digest.update(bytes);
    Ok(format!("{:x}", digest.finalize()))
}

/// Stable credential-free identity for P2-B ordinary mutation admission.
/// The persistent P2-B fence is excluded so before/after images remain
/// comparable while the fence is held; all secret-bearing profile/config
/// fields are still covered by the digest and never copied into the receipt.
pub(crate) fn config_mutation_config_fingerprint(config: &Config) -> io::Result<String> {
    let normalized = config.without_config_mutation_operation_fence();
    let bytes = serde_json::to_vec(&normalized).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("无法编码 Config mutation config fingerprint：{error}"),
        )
    })?;
    let mut digest = Sha256::new();
    digest.update(b"csswitch-config-mutation-config-v1\0");
    digest.update(bytes);
    Ok(format!("{:x}", digest.finalize()))
}

/// 16 字节随机 → 32 hex 字符。/dev/urandom（unix）；不可用时退回时间纳秒。
pub fn new_id() -> String {
    use std::io::Read;
    let mut buf = [0u8; 16];
    if let Ok(mut f) = fs::File::open("/dev/urandom") {
        if f.read_exact(&mut buf).is_ok() {
            return buf.iter().map(|b| format!("{b:02x}")).collect();
        }
    }
    let n = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{n:032x}")
}

/// epoch 毫秒（用作 created_at / sort_index 初值）。
pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

// ---------- 版本探测 ----------
#[derive(Debug, Clone, PartialEq)]
pub enum VersionKind {
    Legacy,
    V2,
    V3,
    V4,
    TooNew(u32),
}

#[derive(Deserialize)]
struct VersionProbe {
    #[serde(default)]
    schema_version: u32,
}

/// 先只解析 schema_version 判版本，避免用「必填字段缺失」误判旧文件。
/// <2（含缺失=0）→ Legacy；==2 → V2；==3 → V3；==4 → V4；>4 → TooNew。
pub fn detect_version(data: &[u8]) -> io::Result<VersionKind> {
    let probe: VersionProbe = serde_json::from_slice(data).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("config.json 解析失败：{e}"),
        )
    })?;
    Ok(match probe.schema_version {
        v if v < 2 => VersionKind::Legacy,
        2 => VersionKind::V2,
        3 => VersionKind::V3,
        v if v == CURRENT_SCHEMA_VERSION => VersionKind::V4,
        v => VersionKind::TooNew(v),
    })
}

/// 旧固定槽 → 新 profile 列表。空槽（key/base_url/model 全空）跳过；
/// 旧 provider 指针命中已迁 profile → active_id 指它，否则 ""（不静默选第一条）。
pub fn migrate_v1_to_v2(
    mut legacy: crate::config_legacy::ConfigV1,
) -> crate::config_legacy::ConfigV2 {
    // 先把遗留裸 relay 槽归位到 relay-<preset>。
    crate::templates::migrate_legacy_relay(&mut legacy.providers, &mut legacy.provider);
    let ts = now_ms();
    let mut profiles = Vec::new();
    let mut active_id = String::new();
    for (i, (slot, pc)) in legacy.providers.iter().enumerate() {
        if pc.key.is_empty() && pc.base_url.is_empty() && pc.model.is_empty() {
            continue;
        }
        let tid = crate::templates::template_id_for_legacy_slot(slot);
        let tpl = crate::templates::by_id(tid);
        let id = new_id();
        let base_url = if pc.base_url.is_empty() {
            tpl.map(|t| t.base_url.to_string()).unwrap_or_default()
        } else {
            pc.base_url.clone()
        };
        profiles.push(crate::config_legacy::ProfileV2 {
            id: id.clone(),
            name: tpl
                .map(|t| t.name.to_string())
                .unwrap_or_else(|| slot.clone()),
            template_id: tid.to_string(),
            category: tpl
                .map(|t| t.category.to_string())
                .unwrap_or_else(|| "custom".into()),
            api_format: tpl
                .map(|t| t.api_format.to_string())
                .unwrap_or_else(|| "anthropic".into()),
            base_url,
            api_key: pc.key.clone(),
            model: pc.model.clone(),
            website_url: tpl.map(|t| t.website_url.to_string()),
            icon: tpl.map(|t| t.icon.to_string()),
            icon_color: tpl.map(|t| t.icon_color.to_string()),
            sort_index: Some(i as i64),
            created_at: Some(ts),
            notes: None,
        });
        if *slot == legacy.provider {
            active_id = id;
        }
    }
    crate::config_legacy::ConfigV2 {
        schema_version: 2,
        profiles,
        active_id,
        proxy_port: legacy.proxy_port,
        sandbox_port: legacy.sandbox_port,
        reuse_system_ssh: false,
        secret: legacy.secret,
        mode: legacy.mode,
        pending_notice: None,
    }
}

pub fn migrate_v2_to_v3(
    v2: crate::config_legacy::ConfigV2,
) -> io::Result<crate::config_legacy::ConfigV3> {
    let mut profiles = Vec::with_capacity(v2.profiles.len());
    for p in v2.profiles {
        let template_id = if crate::templates::by_id(&p.template_id).is_some() {
            p.template_id
        } else {
            "custom".to_string()
        };
        let api_format = if p.api_format.trim().is_empty() {
            crate::templates::by_id(&template_id)
                .map(|template| template.api_format.to_string())
                .unwrap_or_else(|| "anthropic".to_string())
        } else {
            p.api_format
        };
        let contract = crate::provider_contracts::contract_for(&template_id, &api_format)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        let model_policy = if contract.default_model_policy == ModelPolicy::DynamicCatalog {
            crate::config_legacy::ModelPolicyV3::DynamicCatalog
        } else if matches!(template_id.as_str(), "deepseek" | "qwen") {
            crate::config_legacy::ModelPolicyV3::OptionalFixed
        } else {
            crate::config_legacy::ModelPolicyV3::RequiredFixed
        };
        profiles.push(crate::config_legacy::ProfileV3 {
            id: p.id,
            name: p.name,
            template_id,
            category: p.category,
            api_format,
            base_url: p.base_url,
            api_key: p.api_key,
            model: p.model,
            credential_source: contract.default_credential_source,
            credential_ref: None,
            model_policy,
            website_url: p.website_url,
            icon: p.icon,
            icon_color: p.icon_color,
            sort_index: p.sort_index,
            created_at: p.created_at,
            notes: p.notes,
            extra: BTreeMap::new(),
        });
    }
    Ok(crate::config_legacy::ConfigV3 {
        schema_version: 3,
        profiles,
        active_id: v2.active_id,
        proxy_port: v2.proxy_port,
        sandbox_port: v2.sandbox_port,
        reuse_system_ssh: v2.reuse_system_ssh,
        experimental_codex_enabled: false,
        codex_network: csswitch_codex_network::CodexNetworkSettings::default(),
        secret: v2.secret,
        mode: v2.mode,
        pending_notice: v2.pending_notice,
        extra: BTreeMap::new(),
    })
}

fn legacy_native_model<'a>(template_id: &str, model: &'a str) -> Option<&'a str> {
    match (template_id, model.trim()) {
        ("deepseek", "claude-opus-4-8") => Some("deepseek-v4-pro"),
        ("deepseek", "claude-sonnet-5" | "claude-sonnet-4-6" | "claude-haiku-4-5") => {
            Some("deepseek-v4-flash")
        }
        ("qwen", "claude-opus-4-8") => Some("qwen3.7-max"),
        ("qwen", "claude-sonnet-5" | "claude-sonnet-4-6") => Some("qwen-plus-latest"),
        ("qwen", "claude-haiku-4-5") => Some("qwen-turbo"),
        (_, "") => None,
        (_, value) => Some(value),
    }
}

fn set_catalog_default(
    routes: &mut [ModelRoute],
    default_selector: &mut String,
    upstream_model: &str,
) -> bool {
    if let Some(index) = routes
        .iter()
        .position(|route| route.upstream_model == upstream_model)
    {
        routes.swap(0, index);
        *default_selector = routes[0].selector_id.clone();
        true
    } else {
        false
    }
}

fn append_notice(existing: Option<String>, next: String) -> Option<String> {
    Some(match existing {
        Some(existing) if !existing.trim().is_empty() => format!("{existing}\n{next}"),
        _ => next,
    })
}

pub fn migrate_v3_to_v4(v3: crate::config_legacy::ConfigV3) -> io::Result<Config> {
    let mut profiles = Vec::with_capacity(v3.profiles.len());
    let mut incomplete_ids = BTreeSet::new();
    for mut p in v3.profiles {
        if crate::templates::by_id(&p.template_id).is_none() {
            p.template_id = "custom".into();
        }
        if p.api_format.trim().is_empty() {
            p.api_format = crate::templates::by_id(&p.template_id)
                .map(|template| template.api_format.to_string())
                .unwrap_or_else(|| "anthropic".into());
        }
        let contract = crate::provider_contracts::contract_for(&p.template_id, &p.api_format)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        let dynamic = contract.default_model_policy == ModelPolicy::DynamicCatalog;
        if (p.model_policy == crate::config_legacy::ModelPolicyV3::DynamicCatalog) != dynamic {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "profile `{}` 的 v3 model_policy 与 provider contract 不一致",
                    p.id
                ),
            ));
        }
        let (mut model_catalog, mut default_model_route_id, role_bindings) = if dynamic {
            (Vec::new(), String::new(), RoleBindings::default())
        } else if matches!(p.template_id.as_str(), "deepseek" | "qwen") {
            let (mut routes, mut default, bindings) =
                crate::model_catalog::preset_catalog(&p.template_id)
                    .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
            let raw = p.model.trim();
            if let Some(index) = routes
                .iter()
                .position(|route| !raw.is_empty() && route.selector_id == raw)
            {
                routes.swap(0, index);
                default = routes[0].selector_id.clone();
            } else if let Some(legacy) = legacy_native_model(&p.template_id, &p.model) {
                if !set_catalog_default(&mut routes, &mut default, legacy) {
                    let (manual, manual_default, _) = crate::model_catalog::single_route_catalog(
                        &crate::model_catalog::namespace_for(&p.template_id, &p.api_format),
                        legacy,
                        None,
                        None,
                    )
                    .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
                    routes.insert(0, manual.into_iter().next().expect("single route"));
                    default = manual_default;
                }
            }
            let mut bindings = bindings;
            // A v3 profile had only one model field, so its migrated Sonnet
            // route must follow that selected default. The remaining role
            // bindings retain the preset's quality/fast choices.
            bindings.sonnet = default.clone();
            (routes, default, bindings)
        } else {
            if let Some(model) = legacy_native_model(&p.template_id, &p.model) {
                crate::model_catalog::single_route_catalog(
                    &crate::model_catalog::namespace_for(&p.template_id, &p.api_format),
                    model,
                    None,
                    None,
                )
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?
            } else {
                incomplete_ids.insert(p.id.clone());
                (Vec::new(), String::new(), RoleBindings::default())
            }
        };
        let model = model_catalog
            .iter()
            .find(|route| route.selector_id == default_model_route_id)
            .map(|route| route.upstream_model.clone())
            .unwrap_or_default();
        profiles.push(Profile {
            id: p.id,
            name: p.name,
            template_id: p.template_id,
            category: p.category,
            api_format: p.api_format,
            base_url: p.base_url,
            api_key: p.api_key,
            model,
            model_catalog: std::mem::take(&mut model_catalog),
            default_model_route_id: std::mem::take(&mut default_model_route_id),
            role_bindings,
            credential_source: p.credential_source,
            credential_ref: p.credential_ref,
            model_policy: if dynamic {
                ModelPolicy::DynamicCatalog
            } else {
                ModelPolicy::SavedCatalog
            },
            website_url: p.website_url,
            icon: p.icon,
            icon_color: p.icon_color,
            sort_index: p.sort_index,
            created_at: p.created_at,
            notes: p.notes,
            extra: p.extra,
        });
    }
    let incomplete_active = incomplete_ids.contains(&v3.active_id);
    let pending_notice = if incomplete_ids.is_empty() {
        v3.pending_notice
    } else {
        append_notice(
            v3.pending_notice,
            format!(
                "{} 个旧静态配置缺少模型目录，已保留为未完成配置{}。",
                incomplete_ids.len(),
                if incomplete_active {
                    "；原生效配置已安全取消激活"
                } else {
                    ""
                }
            ),
        )
    };
    Ok(Config {
        schema_version: CURRENT_SCHEMA_VERSION,
        profiles,
        active_id: if incomplete_active {
            String::new()
        } else {
            v3.active_id
        },
        proxy_port: v3.proxy_port,
        sandbox_port: v3.sandbox_port,
        reuse_system_ssh: v3.reuse_system_ssh,
        experimental_codex_enabled: v3.experimental_codex_enabled,
        codex_network: v3.codex_network,
        secret: v3.secret,
        mode: v3.mode,
        pending_notice,
        runtime_binding: None,
        runtime_transaction: None,
        runtime_compensation: None,
        extra: v3.extra,
    })
}

#[cfg(not(feature = "acceptance-build"))]
pub(crate) const CONFIG_DIR_NAME: &str = ".csswitch";
#[cfg(feature = "acceptance-build")]
pub(crate) const CONFIG_DIR_NAME: &str = ".csswitch-acceptance";

fn default_dir_from_home(home: &Path) -> PathBuf {
    home.join(CONFIG_DIR_NAME)
}

/// 构建变体固定的配置目录。正式构建为 `$HOME/.csswitch`，Acceptance 为
/// `$HOME/.csswitch-acceptance`；两者不会因 Finder 使用同一个 HOME 而互相迁移配置。
pub fn default_dir() -> PathBuf {
    // Windows 双击启动的进程通常没有 HOME，回退 USERPROFILE；最后才退到 "."。
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    default_dir_from_home(&home)
}

pub(crate) fn read_pending_authority_cleanup_manifest(dir: &Path) -> io::Result<Option<Vec<u8>>> {
    let access = config_access();
    ensure_config_access_open(&access)?;
    let secure = match SecureDir::open(dir, false) {
        Ok(secure) => secure,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    secure.read_regular("pending-authority-cleanup.v1.json")
}

pub(crate) fn write_pending_authority_cleanup_manifest(
    dir: &Path,
    bytes: &[u8],
    expected_before: Option<&[u8]>,
) -> io::Result<()> {
    let access = config_access();
    ensure_config_access_open(&access)?;
    let secure = SecureDir::open(dir, true)?;
    atomic_write_named_bytes_in(
        &secure,
        "pending-authority-cleanup.v1.json",
        bytes,
        expected_before,
        |secure| secure.sync(),
    )
}

pub(crate) fn write_pending_authority_cleanup_manifest_if_absent(
    dir: &Path,
    bytes: &[u8],
) -> io::Result<()> {
    let access = config_access();
    ensure_config_access_open(&access)?;
    let secure = SecureDir::open(dir, true)?;
    atomic_write_named_bytes_if_absent_in(
        &secure,
        "pending-authority-cleanup.v1.json",
        bytes,
        |secure| secure.sync(),
    )
}

/// Read the dedicated, credential-free receipt for `op.codex-enable` disable.
///
/// The receipt deliberately lives beside `config.json` instead of inside the
/// one-click/history journals.  All access is anchored to the already-audited
/// config directory descriptor and shares the process-local config serializer.
pub(crate) fn read_codex_disable_operation_receipt(dir: &Path) -> io::Result<Option<Vec<u8>>> {
    let access = config_access();
    ensure_config_access_open(&access)?;
    let (secure, _fence) = match open_config_writer(dir, false) {
        Ok(writer) => writer,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    read_codex_disable_operation_receipt_in(&secure)
}

fn read_codex_disable_operation_receipt_in(secure: &SecureDir) -> io::Result<Option<Vec<u8>>> {
    let active = secure.read_regular(CODEX_DISABLE_OPERATION_RECEIPT_FILE)?;
    let clearing = secure.read_regular(CODEX_DISABLE_OPERATION_RECEIPT_CLEARING_FILE)?;
    match (active, clearing) {
        (active, None) => Ok(active),
        (None, Some(bytes)) => {
            // `clear` first makes the private clearing name durable, then
            // unlinks it.  If a process dies in between, resurrect the exact
            // terminal receipt so boot replay can adjudicate and clear it
            // again instead of treating an invisible tombstone as success.
            secure.rename(
                CODEX_DISABLE_OPERATION_RECEIPT_CLEARING_FILE,
                CODEX_DISABLE_OPERATION_RECEIPT_FILE,
            )?;
            secure.sync()?;
            if secure
                .read_regular(CODEX_DISABLE_OPERATION_RECEIPT_FILE)?
                .as_deref()
                != Some(bytes.as_slice())
            {
                return Err(io::Error::other(
                    "Codex disable receipt 清理恢复后身份不确定；已停止 mutation",
                ));
            }
            Ok(Some(bytes))
        }
        (Some(_), Some(_)) => Err(io::Error::other(
            "Codex disable receipt 与清理记录同时存在；已保留并停止 mutation",
        )),
    }
}

fn require_no_sidecar_mutation_receipts_in(secure: &SecureDir) -> io::Result<()> {
    if read_codex_disable_operation_receipt_in(secure)?.is_some() {
        return Err(io::Error::other(
            "code=codex_disable_operation_in_progress Codex disable operation receipt 尚未结束；拒绝普通 Config writer。",
        ));
    }
    if read_config_mutation_operation_receipt_in(secure)?.is_some() {
        return Err(io::Error::other(
            "code=config_mutation_operation_in_progress Config mutation receipt 尚未结束；拒绝普通 Config writer。",
        ));
    }
    Ok(())
}

/// Snapshot an exact Config-authority proof immediately before one frozen
/// destructive effect.  The writer flock serializes proof acquisition; the
/// durable Config field remains after it is released and makes every normal
/// cross-process writer fail closed for the whole effect window.
pub(crate) struct CodexDisableEffectLease {
    config: Config,
}

impl CodexDisableEffectLease {
    pub(crate) fn config(&self) -> &Config {
        &self.config
    }
}

pub(crate) fn acquire_codex_disable_effect_lease(
    dir: &Path,
    expected_fence: &CodexDisableOperationFence,
) -> io::Result<CodexDisableEffectLease> {
    let access = config_access();
    ensure_config_access_open(&access)?;
    let (secure, _writer) = open_config_writer(dir, false)?;
    let config = load_from_secure(&secure)?;
    if config.codex_disable_operation_fence()?.as_ref() != Some(expected_fence) {
        return Err(io::Error::other(
            "Codex disable operation fence 在 effect 前发生变化",
        ));
    }
    Ok(CodexDisableEffectLease { config })
}

/// Atomically establish the Config authority fence and then publish the
/// sidecar intent before any destructive effect may begin.  A crash after the
/// first durable write leaves a harmless orphan fence for boot recovery; an
/// ordinary write failure attempts an exact rollback while the writer flock is
/// still held.
pub(crate) fn begin_codex_disable_operation(
    dir: &Path,
    expected_config: &Config,
    fence: &CodexDisableOperationFence,
    receipt_bytes: &[u8],
) -> io::Result<()> {
    fence.validate()?;
    if expected_config.codex_disable_operation_fence()?.is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Codex disable begin before-image 已含 operation fence",
        ));
    }
    if codex_disable_config_fingerprint(expected_config)? != fence.before_config_fingerprint {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Codex disable begin before-image fingerprint 不匹配",
        ));
    }
    let mut expected_after = expected_config.clone();
    expected_after.experimental_codex_enabled = false;
    if codex_disable_config_fingerprint(&expected_after)? != fence.after_config_fingerprint {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Codex disable begin after-image fingerprint 不匹配",
        ));
    }
    let access = config_access();
    ensure_config_access_open(&access)?;
    let (secure, _writer) = open_config_writer(dir, true)?;
    let mut current = load_from_secure(&secure)?;
    if &current != expected_config {
        return Err(io::Error::other(
            "Codex disable begin config before-image 已变化",
        ));
    }
    require_no_runtime_transaction(&current).map_err(io::Error::other)?;
    if read_codex_disable_operation_receipt_in(&secure)?.is_some()
        || read_config_mutation_operation_receipt_in(&secure)?.is_some()
    {
        return Err(io::Error::other("Codex disable receipt 已存在"));
    }
    current.set_codex_disable_operation_fence(fence);
    save_to_secure(&secure, &current)?;
    let publish = atomic_write_named_bytes_if_absent_in(
        &secure,
        CODEX_DISABLE_OPERATION_RECEIPT_FILE,
        receipt_bytes,
        |secure| secure.sync(),
    );
    if let Err(error) = publish {
        current.clear_codex_disable_operation_fence();
        let _ = save_to_secure(&secure, &current);
        return Err(error);
    }
    if secure
        .read_regular(CODEX_DISABLE_OPERATION_RECEIPT_FILE)?
        .as_deref()
        != Some(receipt_bytes)
    {
        return Err(io::Error::other("Codex disable intent 持久化后回读不一致"));
    }
    Ok(())
}

/// Exact-fence bypass used only by this operation's Config commit.  The
/// closure may change the flag but cannot replace or remove the fence.
pub(crate) fn update_codex_disable_operation<T, F>(
    dir: &Path,
    expected_fence: &CodexDisableOperationFence,
    f: F,
) -> Result<T, String>
where
    F: FnOnce(&mut Config) -> Result<(T, bool), String>,
{
    let access = config_access();
    ensure_config_access_open(&access).map_err(|error| error.to_string())?;
    let (secure, _writer) = open_config_writer(dir, false).map_err(|error| error.to_string())?;
    let mut config = load_from_secure(&secure).map_err(|error| error.to_string())?;
    if config
        .codex_disable_operation_fence()
        .map_err(|error| error.to_string())?
        .as_ref()
        != Some(expected_fence)
    {
        return Err("Codex disable operation fence 已变化".into());
    }
    let (result, changed) = f(&mut config)?;
    if config
        .codex_disable_operation_fence()
        .map_err(|error| error.to_string())?
        .as_ref()
        != Some(expected_fence)
    {
        return Err("Codex disable operation closure 不得改变 fence".into());
    }
    if changed
        && codex_disable_config_fingerprint(&config).map_err(|error| error.to_string())?
            != expected_fence.after_config_fingerprint
    {
        return Err("Codex disable operation closure 未生成 exact after-image".into());
    }
    if changed {
        #[cfg(test)]
        if CONFIG_UPDATE_COMMIT_FAILURE
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .as_ref()
            .is_some_and(|(thread, armed_dir)| {
                *thread == std::thread::current().id() && armed_dir == dir
            })
        {
            return Err("test-only config update commit failure".into());
        }
        save_to_secure(&secure, &config).map_err(|error| error.to_string())?;
    }
    Ok(result)
}

pub(crate) fn clear_codex_disable_operation_fence(
    dir: &Path,
    expected_fence: &CodexDisableOperationFence,
    terminal_image: CodexDisableTerminalConfigImage,
) -> io::Result<()> {
    let access = config_access();
    ensure_config_access_open(&access)?;
    let (secure, _writer) = open_config_writer(dir, false)?;
    if read_codex_disable_operation_receipt_in(&secure)?.is_some() {
        return Err(io::Error::other(
            "Codex disable receipt 尚未清理；拒绝释放 Config fence",
        ));
    }
    let mut config = load_from_secure(&secure)?;
    if config.codex_disable_operation_fence()?.as_ref() != Some(expected_fence) {
        return Err(io::Error::other(
            "Codex disable Config fence 在清理前发生变化",
        ));
    }
    if codex_disable_config_fingerprint(&config)? != terminal_image.fingerprint(expected_fence) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Codex disable Config terminal image 在 fence 清理前发生变化",
        ));
    }
    config.clear_codex_disable_operation_fence();
    save_to_secure(&secure, &config)
}

/// Boot-only convergence for the two safe receipt-free protocol points: a
/// crash after fence publication but before intent publication, or a crash
/// after exact terminal receipt clear but before fence clear.
pub(crate) fn recover_orphan_codex_disable_operation_fence(
    dir: &Path,
) -> io::Result<CodexDisableOrphanFenceRecovery> {
    let access = config_access();
    ensure_config_access_open(&access)?;
    let (secure, _writer) = match open_config_writer(dir, false) {
        Ok(writer) => writer,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(CodexDisableOrphanFenceRecovery::None)
        }
        Err(error) => return Err(error),
    };
    if read_codex_disable_operation_receipt_in(&secure)?.is_some() {
        return Ok(CodexDisableOrphanFenceRecovery::None);
    }
    let mut config = load_from_secure(&secure)?;
    let Some(fence) = config.codex_disable_operation_fence()? else {
        return Ok(CodexDisableOrphanFenceRecovery::None);
    };
    let fingerprint = codex_disable_config_fingerprint(&config)?;
    if fingerprint != fence.before_config_fingerprint
        && fingerprint != fence.after_config_fingerprint
    {
        return Ok(CodexDisableOrphanFenceRecovery::ConfigDrift);
    }
    config.clear_codex_disable_operation_fence();
    save_to_secure(&secure, &config)?;
    Ok(CodexDisableOrphanFenceRecovery::Cleared)
}

/// Publish the first disable intent without replacing another open operation.
#[cfg(test)]
pub(crate) fn write_codex_disable_operation_receipt_if_absent(
    dir: &Path,
    bytes: &[u8],
) -> io::Result<()> {
    let access = config_access();
    ensure_config_access_open(&access)?;
    let (secure, _fence) = open_config_writer(dir, true)?;
    if secure.regular_exists_allow_hardlinks(CODEX_DISABLE_OPERATION_RECEIPT_CLEARING_FILE)? {
        return Err(io::Error::other(
            "Codex disable receipt 尚有未裁决的清理记录",
        ));
    }
    atomic_write_named_bytes_if_absent_in(
        &secure,
        CODEX_DISABLE_OPERATION_RECEIPT_FILE,
        bytes,
        |secure| secure.sync(),
    )
}

/// Advance one receipt phase by exact-byte CAS.  A stale writer can therefore
/// neither overwrite a replacement operation nor silently retarget recovery.
pub(crate) fn write_codex_disable_operation_receipt(
    dir: &Path,
    bytes: &[u8],
    expected_before: &[u8],
) -> io::Result<()> {
    let access = config_access();
    ensure_config_access_open(&access)?;
    let (secure, _fence) = open_config_writer(dir, false)?;
    if secure.regular_exists_allow_hardlinks(CODEX_DISABLE_OPERATION_RECEIPT_CLEARING_FILE)? {
        return Err(io::Error::other(
            "Codex disable receipt 尚有未裁决的清理记录",
        ));
    }
    atomic_write_named_bytes_in(
        &secure,
        CODEX_DISABLE_OPERATION_RECEIPT_FILE,
        bytes,
        Some(expected_before),
        |secure| secure.sync(),
    )
}

/// Clear only the exact terminal receipt.  The fixed private clearing name is
/// part of the protocol: an interrupted clear is discoverable and resurrected
/// by `read_codex_disable_operation_receipt`, while a stale clear can never
/// unlink a replacement.
pub(crate) fn clear_codex_disable_operation_receipt(
    dir: &Path,
    expected: &[u8],
    expected_fence: &CodexDisableOperationFence,
    terminal_image: CodexDisableTerminalConfigImage,
) -> io::Result<()> {
    let operation_id = &expected_fence.operation_id;
    if operation_id.len() != 32
        || !operation_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Codex disable operation id 非法",
        ));
    }
    let access = config_access();
    ensure_config_access_open(&access)?;
    let (secure, _fence) = open_config_writer(dir, false)?;
    if secure.regular_exists_allow_hardlinks(CODEX_DISABLE_OPERATION_RECEIPT_CLEARING_FILE)? {
        return Err(io::Error::other(
            "Codex disable receipt 尚有未裁决的清理记录",
        ));
    }
    let config = load_from_secure(&secure)?;
    if config.codex_disable_operation_fence()?.as_ref() != Some(expected_fence) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Codex disable Config fence 在 receipt 清理前发生变化",
        ));
    }
    if codex_disable_config_fingerprint(&config)? != terminal_image.fingerprint(expected_fence) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Codex disable Config terminal image 在 receipt 清理前发生变化",
        ));
    }
    if secure
        .read_regular(CODEX_DISABLE_OPERATION_RECEIPT_FILE)?
        .as_deref()
        != Some(expected)
    {
        return Err(io::Error::other(
            "Codex disable receipt 在清理前发生变化；已保留当前记录",
        ));
    }
    secure.rename(
        CODEX_DISABLE_OPERATION_RECEIPT_FILE,
        CODEX_DISABLE_OPERATION_RECEIPT_CLEARING_FILE,
    )?;
    // Persist the discoverable intermediate name before removing it.  Every
    // crash point therefore leaves either the active receipt, the recoverable
    // clearing receipt, or a durably empty state.
    secure.sync()?;
    if secure
        .read_regular(CODEX_DISABLE_OPERATION_RECEIPT_CLEARING_FILE)?
        .as_deref()
        != Some(expected)
    {
        return Err(io::Error::other(
            "Codex disable receipt 在清理期间变化；清理记录已保留",
        ));
    }
    secure.unlink(CODEX_DISABLE_OPERATION_RECEIPT_CLEARING_FILE)?;
    secure.sync()
}

fn validate_config_mutation_receipt_size(bytes: &[u8]) -> io::Result<()> {
    if bytes.is_empty() || bytes.len() > MAX_CONFIG_MUTATION_RECEIPT_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Config mutation receipt 为空或超过 64 KiB 上限",
        ));
    }
    Ok(())
}

fn read_config_mutation_operation_receipt_in(secure: &SecureDir) -> io::Result<Option<Vec<u8>>> {
    let active = secure.read_regular(CONFIG_MUTATION_OPERATION_RECEIPT_FILE)?;
    let clearing = secure.read_regular(CONFIG_MUTATION_OPERATION_CLEARING_FILE)?;
    if let Some(bytes) = active.as_deref() {
        validate_config_mutation_receipt_size(bytes)?;
    }
    if let Some(bytes) = clearing.as_deref() {
        validate_config_mutation_receipt_size(bytes)?;
    }
    match (active, clearing) {
        (active, None) => Ok(active),
        (None, Some(bytes)) => {
            secure.rename(
                CONFIG_MUTATION_OPERATION_CLEARING_FILE,
                CONFIG_MUTATION_OPERATION_RECEIPT_FILE,
            )?;
            secure.sync()?;
            if secure
                .read_regular(CONFIG_MUTATION_OPERATION_RECEIPT_FILE)?
                .as_deref()
                != Some(bytes.as_slice())
            {
                return Err(io::Error::other(
                    "Config mutation receipt 清理恢复后身份不确定；已停止 mutation",
                ));
            }
            Ok(Some(bytes))
        }
        (Some(_), Some(_)) => Err(io::Error::other(
            "Config mutation receipt 与 clearing 记录同时存在；已保留并停止 mutation",
        )),
    }
}

/// Read the independent P2-B receipt through the secure Config directory.
/// A recoverable clearing tombstone is resurrected before the bytes are
/// returned, preserving the exact terminal record across a crash.
pub(crate) fn read_config_mutation_operation_receipt(dir: &Path) -> io::Result<Option<Vec<u8>>> {
    let access = config_access();
    ensure_config_access_open(&access)?;
    let (secure, _fence) = match open_config_writer(dir, false) {
        Ok(writer) => writer,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    read_config_mutation_operation_receipt_in(&secure)
}

/// Fence-first P2-B admission.  The caller has already validated the typed
/// receipt and effect graph; this function owns the secure Config/fence and
/// sidecar publication seam.
pub(crate) fn begin_config_mutation_operation(
    dir: &Path,
    expected_config: &Config,
    fence: &ConfigMutationOperationFence,
    receipt_bytes: &[u8],
) -> io::Result<()> {
    fence.validate()?;
    if fence.phase != "begin" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Config mutation begin 必须使用 begin fence",
        ));
    }
    validate_config_mutation_receipt_size(receipt_bytes)?;
    if expected_config.codex_disable_operation_fence()?.is_some()
        || expected_config.config_mutation_operation_fence()?.is_some()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "P2-B begin 前已有互斥 operation fence",
        ));
    }
    if config_mutation_config_fingerprint(expected_config)? != fence.before_config_fingerprint {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Config mutation begin before-image fingerprint 不匹配",
        ));
    }
    let access = config_access();
    ensure_config_access_open(&access)?;
    let (secure, _writer) = open_config_writer(dir, true)?;
    let mut current = load_from_secure(&secure)?;
    if &current != expected_config {
        return Err(io::Error::other(
            "Config mutation begin config before-image 已变化",
        ));
    }
    if current.codex_disable_operation_fence()?.is_some()
        || current.config_mutation_operation_fence()?.is_some()
    {
        return Err(io::Error::other(
            "Config mutation begin 发现互斥 operation fence",
        ));
    }
    require_no_runtime_transaction(&current).map_err(io::Error::other)?;
    if read_codex_disable_operation_receipt_in(&secure)?.is_some()
        || read_config_mutation_operation_receipt_in(&secure)?.is_some()
    {
        return Err(io::Error::other(
            "Config mutation begin 发现已有 receipt；拒绝覆盖",
        ));
    }
    current.set_config_mutation_operation_fence(fence);
    save_to_secure(&secure, &current)?;
    let publish = atomic_write_named_bytes_if_absent_in(
        &secure,
        CONFIG_MUTATION_OPERATION_RECEIPT_FILE,
        receipt_bytes,
        |secure| secure.sync(),
    );
    if let Err(error) = publish {
        let rollback = (|| {
            let fenced = load_from_secure(&secure)?;
            if fenced.config_mutation_operation_fence()?.as_ref() != Some(fence)
                || config_mutation_config_fingerprint(&fenced)? != fence.before_config_fingerprint
                || read_config_mutation_operation_receipt_in(&secure)?.is_some()
            {
                return Err(io::Error::other(
                    "Config mutation receipt publish 失败后无法证明零 effect；保留 attention",
                ));
            }
            let mut before = fenced;
            before.clear_config_mutation_operation_fence();
            save_to_secure(&secure, &before)
        })();
        return match rollback {
            Ok(()) => Err(error),
            Err(rollback_error) => Err(io::Error::other(format!(
                "Config mutation receipt publish 失败且 fence rollback 失败：{error}；{rollback_error}"
            ))),
        };
    }
    let reread = load_from_secure(&secure)?;
    if reread.config_mutation_operation_fence()?.as_ref() != Some(fence)
        || secure
            .read_regular(CONFIG_MUTATION_OPERATION_RECEIPT_FILE)?
            .as_deref()
            != Some(receipt_bytes)
    {
        return Err(io::Error::other(
            "Config mutation fence/receipt 发布后 exact reread 不一致；保留 attention",
        ));
    }
    Ok(())
}

/// The only P2-B Config write bypass.  It requires both the exact fence and
/// exact current receipt bytes and cannot replace or remove the fence.
pub(crate) fn update_config_mutation_operation<T, F>(
    dir: &Path,
    expected_fence: &ConfigMutationOperationFence,
    expected_receipt: &[u8],
    f: F,
) -> Result<T, String>
where
    F: FnOnce(&mut Config) -> Result<(T, bool), String>,
{
    update_config_mutation_operation_with_after_fingerprint(
        dir,
        expected_fence,
        expected_receipt,
        f,
    )
    .map(|(result, _after_fingerprint)| result)
}

/// The dynamic-after variant returns the exact Config image observed while
/// the Config writer lock is still held. Callers must checkpoint that digest
/// into their durable receipt before claiming an `after` terminal image.
pub(crate) fn update_config_mutation_operation_with_after_fingerprint<T, F>(
    dir: &Path,
    expected_fence: &ConfigMutationOperationFence,
    expected_receipt: &[u8],
    f: F,
) -> Result<(T, String), String>
where
    F: FnOnce(&mut Config) -> Result<(T, bool), String>,
{
    expected_fence
        .validate()
        .map_err(|error| error.to_string())?;
    let access = config_access();
    ensure_config_access_open(&access).map_err(|error| error.to_string())?;
    let (secure, _writer) = open_config_writer(dir, false).map_err(|error| error.to_string())?;
    let mut current = load_from_secure(&secure).map_err(|error| error.to_string())?;
    if current
        .config_mutation_operation_fence()
        .map_err(|error| error.to_string())?
        .as_ref()
        != Some(expected_fence)
    {
        return Err("Config mutation operation fence 已变化".into());
    }
    if secure
        .regular_exists_allow_hardlinks(CONFIG_MUTATION_OPERATION_CLEARING_FILE)
        .map_err(|error| error.to_string())?
    {
        return Err("Config mutation receipt 尚有未裁决的 clearing 记录".into());
    }
    if secure
        .read_regular(CONFIG_MUTATION_OPERATION_RECEIPT_FILE)
        .map_err(|error| error.to_string())?
        .as_deref()
        != Some(expected_receipt)
    {
        return Err("Config mutation receipt 已变化".into());
    }
    let (result, changed) = f(&mut current)?;
    if current
        .config_mutation_operation_fence()
        .map_err(|error| error.to_string())?
        .as_ref()
        != Some(expected_fence)
    {
        return Err("Config mutation closure 不得改变 operation fence".into());
    }
    if changed {
        #[cfg(test)]
        if CONFIG_UPDATE_COMMIT_FAILURE
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .as_ref()
            .is_some_and(|(thread, armed_dir)| {
                *thread == std::thread::current().id() && armed_dir == dir
            })
        {
            return Err("test-only config update commit failure".into());
        }
        save_to_secure(&secure, &current).map_err(|error| error.to_string())?;
    }
    let committed = load_from_secure(&secure).map_err(|error| error.to_string())?;
    if committed
        .config_mutation_operation_fence()
        .map_err(|error| error.to_string())?
        .as_ref()
        != Some(expected_fence)
        || secure
            .read_regular(CONFIG_MUTATION_OPERATION_RECEIPT_FILE)
            .map_err(|error| error.to_string())?
            .as_deref()
            != Some(expected_receipt)
    {
        return Err("Config mutation dynamic after-image 回读身份不匹配".into());
    }
    let after_fingerprint =
        config_mutation_config_fingerprint(&committed).map_err(|error| error.to_string())?;
    Ok((result, after_fingerprint))
}

/// Exact-byte checkpoint for the durable receipt. It cannot create a
/// replacement and cannot run while a clearing tombstone is unresolved.
pub(crate) fn write_config_mutation_operation(
    dir: &Path,
    expected_fence: &ConfigMutationOperationFence,
    bytes: &[u8],
    expected_before: &[u8],
) -> io::Result<()> {
    expected_fence.validate()?;
    validate_config_mutation_receipt_size(bytes)?;
    let access = config_access();
    ensure_config_access_open(&access)?;
    let (secure, _writer) = open_config_writer(dir, false)?;
    if secure.regular_exists_allow_hardlinks(CONFIG_MUTATION_OPERATION_CLEARING_FILE)? {
        return Err(io::Error::other(
            "Config mutation receipt 尚有未裁决的 clearing 记录",
        ));
    }
    if load_from_secure(&secure)?
        .config_mutation_operation_fence()?
        .as_ref()
        != Some(expected_fence)
    {
        return Err(io::Error::other("Config mutation operation fence 已变化"));
    }
    atomic_write_named_bytes_in(
        &secure,
        CONFIG_MUTATION_OPERATION_RECEIPT_FILE,
        bytes,
        Some(expected_before),
        |secure| secure.sync(),
    )
}

pub(crate) fn publish_config_mutation_terminal_fence(
    dir: &Path,
    expected_begin_fence: &ConfigMutationOperationFence,
    terminal_fence: &ConfigMutationOperationFence,
    terminal_receipt: &[u8],
    terminal_image: ConfigMutationTerminalConfigImage,
) -> io::Result<()> {
    expected_begin_fence.validate()?;
    terminal_fence.validate()?;
    if expected_begin_fence.phase != "begin"
        || terminal_fence.phase != "terminal"
        || terminal_fence.operation_id != expected_begin_fence.operation_id
        || terminal_fence.operation != expected_begin_fence.operation
        || terminal_fence.intent_digest != expected_begin_fence.intent_digest
        || (expected_begin_fence.after_config_fingerprint.is_some()
            && terminal_fence.after_config_fingerprint
                != expected_begin_fence.after_config_fingerprint)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Config mutation terminal fence identity 不匹配",
        ));
    }
    validate_config_mutation_receipt_size(terminal_receipt)?;
    let access = config_access();
    ensure_config_access_open(&access)?;
    let (secure, _writer) = open_config_writer(dir, false)?;
    if secure
        .read_regular(CONFIG_MUTATION_OPERATION_RECEIPT_FILE)?
        .as_deref()
        != Some(terminal_receipt)
    {
        return Err(io::Error::other(
            "Config mutation terminal receipt 在 fence checkpoint 前变化",
        ));
    }
    let mut current = load_from_secure(&secure)?;
    if current.config_mutation_operation_fence()?.as_ref() != Some(expected_begin_fence) {
        return Err(io::Error::other(
            "Config mutation begin fence 在 terminal checkpoint 前变化",
        ));
    }
    let expected_fingerprint = terminal_image.fingerprint(terminal_fence);
    if expected_fingerprint.is_some_and(|expected| {
        config_mutation_config_fingerprint(&current)
            .map(|actual| actual != expected)
            .unwrap_or(true)
    }) {
        return Err(io::Error::other(
            "Config mutation terminal Config image 不匹配",
        ));
    }
    current.set_config_mutation_operation_fence(terminal_fence);
    save_to_secure(&secure, &current)?;
    if load_from_secure(&secure)?
        .config_mutation_operation_fence()?
        .as_ref()
        != Some(terminal_fence)
    {
        return Err(io::Error::other(
            "Config mutation terminal fence exact reread 不一致",
        ));
    }
    Ok(())
}

/// Ordered terminal cleanup: receipt -> terminal fence -> clearing -> unlink
/// -> final exact terminal fence clear. A crash at any intermediate seam is
/// left discoverable for the next boot and never clears a replacement.
pub(crate) fn clear_config_mutation_operation(
    dir: &Path,
    expected_terminal_fence: &ConfigMutationOperationFence,
    expected_terminal_receipt: &[u8],
    terminal_image: ConfigMutationTerminalConfigImage,
) -> io::Result<()> {
    expected_terminal_fence.validate()?;
    if expected_terminal_fence.phase != "terminal" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Config mutation cleanup 需要 terminal fence",
        ));
    }
    let access = config_access();
    ensure_config_access_open(&access)?;
    let (secure, _writer) = open_config_writer(dir, false)?;
    let _ = read_config_mutation_operation_receipt_in(&secure)?;
    let mut current = load_from_secure(&secure)?;
    if current.config_mutation_operation_fence()?.as_ref() != Some(expected_terminal_fence) {
        return Err(io::Error::other(
            "Config mutation terminal fence 在 cleanup 前变化",
        ));
    }
    if terminal_image
        .fingerprint(expected_terminal_fence)
        .is_some_and(|expected| {
            config_mutation_config_fingerprint(&current)
                .map(|actual| actual != expected)
                .unwrap_or(true)
        })
    {
        return Err(io::Error::other(
            "Config mutation terminal Config image 在 cleanup 前变化",
        ));
    }
    if secure
        .read_regular(CONFIG_MUTATION_OPERATION_RECEIPT_FILE)?
        .as_deref()
        != Some(expected_terminal_receipt)
    {
        return Err(io::Error::other(
            "Config mutation receipt 在 cleanup 前变化；已保留当前记录",
        ));
    }
    secure.rename(
        CONFIG_MUTATION_OPERATION_RECEIPT_FILE,
        CONFIG_MUTATION_OPERATION_CLEARING_FILE,
    )?;
    secure.sync()?;
    if secure
        .read_regular(CONFIG_MUTATION_OPERATION_CLEARING_FILE)?
        .as_deref()
        != Some(expected_terminal_receipt)
    {
        return Err(io::Error::other(
            "Config mutation clearing 期间身份变化；保留 clearing 记录",
        ));
    }
    secure.unlink(CONFIG_MUTATION_OPERATION_CLEARING_FILE)?;
    secure.sync()?;

    current = load_from_secure(&secure)?;
    if current.config_mutation_operation_fence()?.as_ref() != Some(expected_terminal_fence)
        || read_config_mutation_operation_receipt_in(&secure)?.is_some()
    {
        return Err(io::Error::other(
            "Config mutation receipt 清理后 terminal fence 身份变化；保留 attention",
        ));
    }
    current.clear_config_mutation_operation_fence();
    save_to_secure(&secure, &current)
}

/// Boot-only convergence for a fence left without an active receipt. A begin
/// fence is cleared only when the exact before-image proves that no effect
/// could have started; a terminal fence is cleared only when its bounded
/// terminal image still matches. All other states remain attention.
pub(crate) fn recover_orphan_config_mutation_operation_fence(
    dir: &Path,
) -> io::Result<ConfigMutationOrphanFenceRecovery> {
    let access = config_access();
    ensure_config_access_open(&access)?;
    let (secure, _writer) = match open_config_writer(dir, false) {
        Ok(writer) => writer,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(ConfigMutationOrphanFenceRecovery::None)
        }
        Err(error) => return Err(error),
    };
    let receipt = read_config_mutation_operation_receipt_in(&secure)?;
    let mut current = load_from_secure(&secure)?;
    let Some(fence) = current.config_mutation_operation_fence()? else {
        return Ok(if receipt.is_some() {
            ConfigMutationOrphanFenceRecovery::Attention
        } else {
            ConfigMutationOrphanFenceRecovery::None
        });
    };
    if receipt.is_some() {
        return Ok(ConfigMutationOrphanFenceRecovery::ActiveReceipt);
    }
    if fence.phase == "begin" {
        if config_mutation_config_fingerprint(&current)? != fence.before_config_fingerprint {
            return Ok(ConfigMutationOrphanFenceRecovery::Attention);
        }
    } else {
        let Some(state) = fence.config_state.as_deref() else {
            return Ok(ConfigMutationOrphanFenceRecovery::Attention);
        };
        let expected = match state {
            "before" => fence.before_config_fingerprint.as_str(),
            "after" => match fence.after_config_fingerprint.as_deref() {
                Some(value) => value,
                None => return Ok(ConfigMutationOrphanFenceRecovery::Attention),
            },
            _ => return Ok(ConfigMutationOrphanFenceRecovery::Attention),
        };
        if config_mutation_config_fingerprint(&current)? != expected {
            return Ok(ConfigMutationOrphanFenceRecovery::ConfigDrift);
        }
    }
    current.clear_config_mutation_operation_fence();
    save_to_secure(&secure, &current)?;
    Ok(ConfigMutationOrphanFenceRecovery::Cleared)
}

fn config_path(dir: &Path) -> PathBuf {
    dir.join("config.json")
}

pub(crate) const MAX_CONFIG_FILE_BYTES: u64 = 64 * 1024 * 1024;

/// 若 path 存在且是符号链接则报错（不跟随）。path 不存在返回 Ok。
pub(crate) fn assert_not_symlink(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(md) if md.file_type().is_symlink() => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("拒绝符号链接（防跟随写/读到别处）：{}", path.display()),
        )),
        Ok(_) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// 确保配置目录存在且是普通目录、权限 0700。目录是符号链接则拒绝。
fn ensure_dir(dir: &Path) -> io::Result<()> {
    assert_not_symlink(dir)?;
    if !dir.exists() {
        fs::create_dir_all(dir)?;
    }
    Ok(())
}

/// 配置文件的所有关键操作都锚定到同一个已打开目录描述符。即使路径名随后被
/// rename/替换，openat/renameat/linkat 仍只作用于最初审计过的目录。
/// Windows 降级：无法把目录作为句柄锚定（std 不支持），只保留路径 + lstat
/// 拒绝符号链接；目录被整目录替换的极端竞态在 Windows 上不设防（注释降级）。
#[cfg(unix)]
const FLOCK_SH: i32 = libc::LOCK_SH;
#[cfg(unix)]
const FLOCK_EX: i32 = libc::LOCK_EX;
#[cfg(not(unix))]
// Windows 降级：无 flock；常量仅作占位参数。
const FLOCK_SH: i32 = 0;
#[cfg(not(unix))]
const FLOCK_EX: i32 = 1;

struct SecureDir {
    #[cfg(unix)]
    file: fs::File,
    path: PathBuf,
    normalize_file_permissions: bool,
}

struct ConfigWriterFence {
    #[cfg(unix)]
    file: fs::File,
}

struct RuntimeCompensationFence {
    #[cfg(unix)]
    file: fs::File,
}

pub(crate) struct RuntimeCompensationAuthLease {
    _secure: SecureDir,
    _fence: RuntimeCompensationFence,
}

pub(crate) struct RuntimeCompensationPublicationLease {
    _secure: SecureDir,
    _fence: RuntimeCompensationFence,
}

pub(crate) struct RuntimeCompensationReplayLease {
    _secure: SecureDir,
    _fence: RuntimeCompensationFence,
}

pub(crate) struct RuntimeHistoryEffectLease {
    _secure: SecureDir,
    _fence: RuntimeCompensationFence,
}

/// A scoped proof that the caller already owns the authority fence exclusively.
/// It deliberately cannot cross threads and is only constructible from an EX
/// lease, so an EX owner can call an authority writer without attempting its
/// own incompatible SH flock.
pub(crate) struct AuthorityWriterBypass<'owner> {
    _owner: PhantomData<&'owner RuntimeCompensationFence>,
    _not_send_or_sync: PhantomData<Rc<()>>,
}

/// Keeps a normal authority filesystem mutation inside the shared authority
/// fence, or records the scoped EX-owner bypass that made SH unnecessary.
pub(crate) struct AuthorityWriterGuard<'owner> {
    _kind: AuthorityWriterGuardKind<'owner>,
}

enum AuthorityWriterGuardKind<'owner> {
    Shared {
        _secure: SecureDir,
        _fence: RuntimeCompensationFence,
    },
    Bypass(PhantomData<&'owner AuthorityWriterBypass<'owner>>),
}

/// A single inherited descriptor for the Skill-install host.  It identifies
/// the existing compensation fence without handing a path to the child; the
/// receiver must still check the frozen device/inode before taking SH.
pub(crate) struct AuthorityFenceCapability {
    directory: fs::File,
    directory_device: u64,
    directory_inode: u64,
    lock_device: u64,
    lock_inode: u64,
}

impl AuthorityFenceCapability {
    pub(crate) fn fd(&self) -> i32 {
        #[cfg(unix)]
        {
            self.directory.as_raw_fd()
        }
        #[cfg(not(unix))]
        {
            // Windows 降级：不存在可继承 fd 的概念；Gateway 侧 Windows 分支
            // 已不再消费该 env，恒返回 0。
            0
        }
    }

    pub(crate) fn directory_device(&self) -> u64 {
        self.directory_device
    }

    pub(crate) fn directory_inode(&self) -> u64 {
        self.directory_inode
    }

    pub(crate) fn lock_device(&self) -> u64 {
        self.lock_device
    }

    pub(crate) fn lock_inode(&self) -> u64 {
        self.lock_inode
    }
}

impl Drop for ConfigWriterFence {
    fn drop(&mut self) {
        #[cfg(unix)]
        unsafe {
            libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

impl Drop for RuntimeCompensationFence {
    fn drop(&mut self) {
        #[cfg(unix)]
        unsafe {
            libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

impl SecureDir {
    fn open(path: &Path, create: bool) -> io::Result<Self> {
        Self::open_with_policy(path, create, true)
    }

    /// Consumer projections may inspect canonical state, but must not repair
    /// directory or file permissions as a side effect of that inspection.
    fn open_read_only(path: &Path) -> io::Result<Self> {
        Self::open_with_policy(path, false, false)
    }

    /// 用户自己选择的 export 父目录必须已存在，且 CSSwitch 不得擅自 chmod 它。
    fn open_unmanaged(path: &Path) -> io::Result<Self> {
        Self::open_with_policy(path, false, false)
    }

    fn open_with_policy(
        path: &Path,
        create: bool,
        normalize_permissions: bool,
    ) -> io::Result<Self> {
        assert_not_symlink(path)?;
        if create {
            ensure_dir(path)?;
        }
        #[cfg(unix)]
        {
            let mut options = fs::OpenOptions::new();
            options
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC);
            let file = options.open(path)?;
            if !file.metadata()?.is_dir() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("配置目录不是目录：{}", path.display()),
                ));
            }
            if normalize_permissions {
                file.set_permissions(fs::Permissions::from_mode(0o700))?;
            }
            Ok(Self {
                file,
                path: path.to_path_buf(),
                normalize_file_permissions: normalize_permissions,
            })
        }
        #[cfg(not(unix))]
        {
            // Windows 降级：目录无法作为 File 打开锚定；仅 lstat 拒绝符号链接
            // 并按需收紧目录 mode（实际是 no-op，权限由 NTACL 决定）。
            let metadata = fs::metadata(path)?;
            if !metadata.is_dir() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("配置目录不是目录：{}", path.display()),
                ));
            }
            if normalize_permissions {
                crate::platform::set_path_mode(path, 0o700)?;
            }
            Ok(Self {
                path: path.to_path_buf(),
                normalize_file_permissions: normalize_permissions,
            })
        }
    }

    fn name(name: &str) -> io::Result<CString> {
        if name.is_empty() || name.as_bytes().contains(&b'/') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "配置目录内部文件名非法",
            ));
        }
        CString::new(name.as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "配置目录内部文件名包含 NUL"))
    }

    fn read_regular_snapshot(&self, name: &str) -> io::Result<Option<(Vec<u8>, u32)>> {
        #[cfg(unix)]
        {
            let name = Self::name(name)?;
            let fd = unsafe {
                libc::openat(
                    self.file.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::NotFound {
                    return Ok(None);
                }
                if error.raw_os_error() == Some(libc::ELOOP) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "拒绝配置目录内的符号链接",
                    ));
                }
                return Err(error);
            }
            let file = unsafe { fs::File::from_raw_fd(fd) };
            let metadata = file.metadata()?;
            if !metadata.is_file() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "拒绝配置目录内的非普通文件",
                ));
            }
            if self.normalize_file_permissions && metadata.nlink() != 1 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "拒绝配置目录内具有多个 hard link 的文件",
                ));
            }
            if metadata.len() > MAX_CONFIG_FILE_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "配置或备份文件过大",
                ));
            }
            let mut mode = metadata.permissions().mode() & 0o777;
            if self.normalize_file_permissions {
                file.set_permissions(fs::Permissions::from_mode(0o600))?;
                mode = 0o600;
            }
            let mut bytes = Vec::with_capacity(metadata.len() as usize);
            file.take(MAX_CONFIG_FILE_BYTES + 1)
                .read_to_end(&mut bytes)?;
            if bytes.len() as u64 > MAX_CONFIG_FILE_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "配置或备份文件过大",
                ));
            }
            Ok(Some((bytes, mode)))
        }
        #[cfg(not(unix))]
        {
            // Windows 降级：无 openat/no-follow，先用 symlink_metadata 拒绝符号
            // 链接再打开；hard link 检查与 POSIX mode 观测不可用（恒 0o600）。
            Self::validate_name(name)?;
            let path = self.path.join(name);
            let link = match fs::symlink_metadata(&path) {
                // 与 Unix 分支对齐：目标不存在视为「无内容」而不是错误。
                Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
                Err(error) => return Err(error),
                Ok(link) => link,
            };
            if link.file_type().is_symlink() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "拒绝配置目录内的符号链接",
                ));
            }
            if !link.is_file() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "拒绝配置目录内的非普通文件",
                ));
            }
            if link.len() > MAX_CONFIG_FILE_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "配置或备份文件过大",
                ));
            }
            let mut file = fs::File::open(&path)?;
            let mode = 0o600;
            if self.normalize_file_permissions {
                crate::platform::set_file_mode(&file, 0o600)?;
            }
            let mut bytes = Vec::with_capacity(link.len() as usize);
            file.take(MAX_CONFIG_FILE_BYTES + 1)
                .read_to_end(&mut bytes)?;
            if bytes.len() as u64 > MAX_CONFIG_FILE_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "配置或备份文件过大",
                ));
            }
            Ok(Some((bytes, mode)))
        }
    }

    /// 只确认模块自有 pending 名是否为普通文件；不 chmod、不要求单 hard link。
    fn regular_exists_allow_hardlinks(&self, name: &str) -> io::Result<bool> {
        #[cfg(unix)]
        {
            let name = Self::name(name)?;
            let fd = unsafe {
                libc::openat(
                    self.file.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::NotFound {
                    return Ok(false);
                }
                if error.raw_os_error() == Some(libc::ELOOP) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "拒绝版本备份 pending 符号链接",
                    ));
                }
                return Err(error);
            }
            let file = unsafe { fs::File::from_raw_fd(fd) };
            let metadata = file.metadata()?;
            if !metadata.is_file() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "拒绝非普通版本备份 pending 文件",
                ));
            }
            Ok(true)
        }
        #[cfg(not(unix))]
        {
            // Windows 降级：lstat 拒绝符号链接后按存在性判断。
            Self::validate_name(name)?;
            let path = self.path.join(name);
            let link = match fs::symlink_metadata(&path) {
                Ok(link) => link,
                Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
                Err(error) => return Err(error),
            };
            if link.file_type().is_symlink() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "拒绝版本备份 pending 符号链接",
                ));
            }
            if !link.is_file() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "拒绝非普通版本备份 pending 文件",
                ));
            }
            Ok(true)
        }
    }

    fn read_regular(&self, name: &str) -> io::Result<Option<Vec<u8>>> {
        self.read_regular_snapshot(name)
            .map(|snapshot| snapshot.map(|(bytes, _)| bytes))
    }

    fn create_new(&self, name: &str) -> io::Result<fs::File> {
        #[cfg(unix)]
        {
            let name = Self::name(name)?;
            let fd = unsafe {
                libc::openat(
                    self.file.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_WRONLY
                        | libc::O_CREAT
                        | libc::O_EXCL
                        | libc::O_NOFOLLOW
                        | libc::O_CLOEXEC,
                    0o600,
                )
            };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(unsafe { fs::File::from_raw_fd(fd) })
        }
        #[cfg(not(unix))]
        {
            // Windows 降级：create_new 本身具有 O_EXCL 语义；先 lstat 拒绝同名
            // 符号链接，mode 收紧交由 NTACL（no-op）。
            Self::validate_name(name)?;
            let path = self.path.join(name);
            if let Ok(link) = fs::symlink_metadata(&path) {
                if link.file_type().is_symlink() {
                    return Err(io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        "拒绝覆盖符号链接",
                    ));
                }
            }
            fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
        }
    }

    fn acquire_config_writer_fence(&self) -> io::Result<ConfigWriterFence> {
        #[cfg(unix)]
        {
            let name = Self::name(CONFIG_WRITER_LOCK_FILE)?;
            let fd = unsafe {
                libc::openat(
                    self.file.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDWR
                        | libc::O_CREAT
                        | libc::O_NOFOLLOW
                        | libc::O_CLOEXEC
                        | libc::O_NONBLOCK,
                    0o600,
                )
            };
            if fd < 0 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::ELOOP) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "拒绝 config writer lock 符号链接",
                    ));
                }
                return Err(error);
            }
            let file = unsafe { fs::File::from_raw_fd(fd) };
            let metadata = file.metadata()?;
            if !metadata.is_file() || metadata.nlink() != 1 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "config writer lock 必须是单链接普通文件",
                ));
            }
            file.set_permissions(fs::Permissions::from_mode(0o600))?;

            #[cfg(test)]
            if let Some(marker) = std::env::var_os("CSSWITCH_C1A_EXPECT_LOCK_CONTENTION_MARKER") {
                let result =
                    unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
                if result == 0 {
                    unsafe {
                        libc::flock(file.as_raw_fd(), libc::LOCK_UN);
                    }
                    return Err(io::Error::other(
                        "test-only expected an already-held config writer fence",
                    ));
                }
                let error = io::Error::last_os_error();
                let raw_error = error.raw_os_error();
                if raw_error != Some(libc::EWOULDBLOCK) && raw_error != Some(libc::EAGAIN) {
                    return Err(error);
                }
                fs::write(marker, b"contended")?;
            }

            loop {
                if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } == 0 {
                    break;
                }
                let error = io::Error::last_os_error();
                if error.kind() != io::ErrorKind::Interrupted {
                    return Err(error);
                }
            }

            // A cooperating writer must keep one stable, persistent lock inode.
            // Re-open the directory entry after acquisition and reject replacement
            // instead of letting two writer populations proceed on different inodes.
            let verify_fd = unsafe {
                libc::openat(
                    self.file.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
                )
            };
            if verify_fd < 0 {
                return Err(io::Error::last_os_error());
            }
            let verify = unsafe { fs::File::from_raw_fd(verify_fd) };
            let verified = verify.metadata()?;
            if !verified.is_file()
                || verified.nlink() != 1
                || verified.dev() != metadata.dev()
                || verified.ino() != metadata.ino()
            {
                return Err(io::Error::other("config writer lock 在获取期间被替换"));
            }
            Ok(ConfigWriterFence { file })
        }
        #[cfg(not(unix))]
        {
            // Windows 降级：无 flock/no-follow。打开（或创建）锁文件并 lstat 拒绝
            // 符号链接；跨进程互斥退化为「持有一个共享冲突句柄」不可用，单实例
            // 桌面应用下由 CONFIG_ACCESS 进程内互斥兜底（注释降级）。
            let _file = self.open_lock_file_degraded(CONFIG_WRITER_LOCK_FILE)?;
            Ok(ConfigWriterFence {})
        }
    }

    fn acquire_runtime_compensation_fence(&self, operation: i32) -> io::Result<RuntimeCompensationFence> {
        #[cfg(unix)]
        {
            let name = Self::name(RUNTIME_COMPENSATION_AUTH_LOCK_FILE)?;
            let fd = unsafe {
                libc::openat(
                    self.file.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDWR
                        | libc::O_CREAT
                        | libc::O_NOFOLLOW
                        | libc::O_CLOEXEC
                        | libc::O_NONBLOCK,
                    0o600,
                )
            };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            let file = unsafe { fs::File::from_raw_fd(fd) };
            let metadata = file.metadata()?;
            if !metadata.is_file()
                || metadata.nlink() != 1
                || metadata.uid() != unsafe { libc::geteuid() }
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "runtime compensation auth fence 必须是当前用户的单链接普通文件",
                ));
            }
            file.set_permissions(fs::Permissions::from_mode(0o600))?;
            loop {
                if unsafe { libc::flock(file.as_raw_fd(), operation as libc::c_int) } == 0 {
                    break;
                }
                let error = io::Error::last_os_error();
                if error.kind() != io::ErrorKind::Interrupted {
                    return Err(error);
                }
            }
            let verify_fd = unsafe {
                libc::openat(
                    self.file.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
                )
            };
            if verify_fd < 0 {
                return Err(io::Error::last_os_error());
            }
            let verified = unsafe { fs::File::from_raw_fd(verify_fd) }.metadata()?;
            if !verified.is_file()
                || verified.nlink() != 1
                || verified.dev() != metadata.dev()
                || verified.ino() != metadata.ino()
            {
                return Err(io::Error::other(
                    "runtime compensation auth fence 在获取期间被替换",
                ));
            }
            Ok(RuntimeCompensationFence { file })
        }
        #[cfg(not(unix))]
        {
            // Windows 降级：无 flock/uid。打开（或创建）锁文件并 lstat 拒绝符号
            // 链接；跨进程 SH/EX 互斥不可用，注释降级（单实例桌面进程内互斥兜底）。
            let _ = operation;
            let _file = self.open_lock_file_degraded(RUNTIME_COMPENSATION_AUTH_LOCK_FILE)?;
            Ok(RuntimeCompensationFence {})
        }
    }

    #[cfg(not(unix))]
    /// Windows 降级助手：打开（或创建）目录内锁文件；符号链接一律拒绝，
    /// 保持「绝不跟随链接写」的语义。无 no-follow 原子性，注释降级。
    fn open_lock_file_degraded(&self, name: &str) -> io::Result<fs::File> {
        Self::validate_name(name)?;
        let path = self.path.join(name);
        if let Ok(link) = fs::symlink_metadata(&path) {
            if link.file_type().is_symlink() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("拒绝锁文件符号链接：{name}"),
                ));
            }
        }
        fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
    }

    #[cfg(not(unix))]
    /// Windows 降级助手：等价 Unix `Self::name` 的名字校验（CString 版）。
    fn validate_name(name: &str) -> io::Result<()> {
        if name.is_empty()
            || name.as_bytes().contains(&b'/')
            || name.as_bytes().contains(&b'\\')
            || name.as_bytes().contains(&0)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "配置目录内部文件名非法",
            ));
        }
        Ok(())
    }

    fn authority_fence_capability(&self) -> io::Result<AuthorityFenceCapability> {
        #[cfg(unix)]
        {
            let name = Self::name(RUNTIME_COMPENSATION_AUTH_LOCK_FILE)?;
            let fd = unsafe {
                libc::openat(
                    self.file.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDWR
                        | libc::O_CREAT
                        | libc::O_NOFOLLOW
                        | libc::O_CLOEXEC
                        | libc::O_NONBLOCK,
                    0o600,
                )
            };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            let file = unsafe { fs::File::from_raw_fd(fd) };
            let metadata = file.metadata()?;
            if !metadata.is_file()
                || metadata.nlink() != 1
                || metadata.uid() != unsafe { libc::geteuid() }
                || metadata.permissions().mode() & 0o077 != 0
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "runtime compensation auth fence 必须是当前用户的单链接私有普通文件",
                ));
            }
            let inherited_fd = unsafe { libc::fcntl(self.file.as_raw_fd(), libc::F_DUPFD, 64) };
            if inherited_fd < 0 {
                return Err(io::Error::last_os_error());
            }
            let inherited = unsafe { fs::File::from_raw_fd(inherited_fd) };
            let flags = unsafe { libc::fcntl(inherited.as_raw_fd(), libc::F_GETFD) };
            if flags < 0
                || unsafe {
                    libc::fcntl(
                        inherited.as_raw_fd(),
                        libc::F_SETFD,
                        flags & !libc::FD_CLOEXEC,
                    )
                } < 0
            {
                return Err(io::Error::last_os_error());
            }
            let verified = inherited.metadata()?;
            let directory = self.file.metadata()?;
            if !verified.is_dir()
                || verified.uid() != unsafe { libc::geteuid() }
                || verified.permissions().mode() & 0o077 != 0
                || verified.dev() != directory.dev()
                || verified.ino() != directory.ino()
            {
                return Err(io::Error::other(
                    "runtime compensation auth fence capability identity changed",
                ));
            }
            Ok(AuthorityFenceCapability {
                directory: inherited,
                directory_device: directory.dev(),
                directory_inode: directory.ino(),
                lock_device: metadata.dev(),
                lock_inode: metadata.ino(),
            })
        }
        #[cfg(not(unix))]
        {
            // Windows 降级：无法继承/绑定目录 fd 与 device/inode 身份。Gateway 的
            // Windows 分支不再消费该 capability（skill bridge 整体禁用），这里仅
            // 打开锁文件占位并返回全零身份，保持调用方流程可继续。
            let file = self.open_lock_file_degraded(RUNTIME_COMPENSATION_AUTH_LOCK_FILE)?;
            Ok(AuthorityFenceCapability {
                directory: file,
                directory_device: 0,
                directory_inode: 0,
                lock_device: 0,
                lock_inode: 0,
            })
        }
    }

    fn rename(&self, from: &str, to: &str) -> io::Result<()> {
        #[cfg(unix)]
        {
            let from = Self::name(from)?;
            let to = Self::name(to)?;
            let result = unsafe {
                libc::renameat(
                    self.file.as_raw_fd(),
                    from.as_ptr(),
                    self.file.as_raw_fd(),
                    to.as_ptr(),
                )
            };
            if result == 0 {
                Ok(())
            } else {
                Err(io::Error::last_os_error())
            }
        }
        #[cfg(not(unix))]
        {
            // Windows 降级：路径版 rename（同目录内），等价原子性由 NTFS 提供。
            Self::validate_name(from)?;
            Self::validate_name(to)?;
            fs::rename(self.path.join(from), self.path.join(to))
        }
    }

    fn link(&self, from: &str, to: &str) -> io::Result<()> {
        #[cfg(unix)]
        {
            let from = Self::name(from)?;
            let to = Self::name(to)?;
            let result = unsafe {
                libc::linkat(
                    self.file.as_raw_fd(),
                    from.as_ptr(),
                    self.file.as_raw_fd(),
                    to.as_ptr(),
                    0,
                )
            };
            if result == 0 {
                Ok(())
            } else {
                Err(io::Error::last_os_error())
            }
        }
        #[cfg(not(unix))]
        {
            // Windows 降级：NTFS 支持硬链接，std::fs::hard_link 具备目标存在即
            // 失败的 O_EXCL 语义；先 lstat 拒绝符号链接。
            Self::validate_name(from)?;
            Self::validate_name(to)?;
            let from_path = self.path.join(from);
            if let Ok(link) = fs::symlink_metadata(&from_path) {
                if link.file_type().is_symlink() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "拒绝为符号链接创建硬链接",
                    ));
                }
            }
            fs::hard_link(from_path, self.path.join(to))
        }
    }

    fn unlink(&self, name: &str) -> io::Result<()> {
        #[cfg(unix)]
        {
            let name = Self::name(name)?;
            let result = unsafe { libc::unlinkat(self.file.as_raw_fd(), name.as_ptr(), 0) };
            if result == 0 {
                Ok(())
            } else {
                Err(io::Error::last_os_error())
            }
        }
        #[cfg(not(unix))]
        {
            // Windows 降级：先 lstat 拒绝符号链接，再按普通文件删除。
            Self::validate_name(name)?;
            let path = self.path.join(name);
            if let Ok(link) = fs::symlink_metadata(&path) {
                if link.file_type().is_symlink() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "拒绝删除符号链接",
                    ));
                }
            }
            fs::remove_file(&path)
        }
    }

    fn sync(&self) -> io::Result<()> {
        #[cfg(unix)]
        {
            self.file.sync_all()
        }
        #[cfg(not(unix))]
        {
            // Windows 降级：无法以句柄形式 fsync 目录；跳过目录级持久化，
            // 文件级 sync_all 仍由各写入点自行执行（注释降级）。
            Ok(())
        }
    }

    fn display_path(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }

    fn same_directory(&self, other: &Self) -> io::Result<bool> {
        #[cfg(unix)]
        {
            let left = self.file.metadata()?;
            let right = other.file.metadata()?;
            Ok(left.dev() == right.dev() && left.ino() == right.ino())
        }
        #[cfg(not(unix))]
        {
            // Windows 降级：无 device/inode，等价近似为 canonical 路径相等。
            let left = self.path.canonicalize_norm()?;
            let right = other.path.canonicalize_norm()?;
            Ok(left == right)
        }
    }
}

fn open_config_writer(dir: &Path, create: bool) -> io::Result<(SecureDir, ConfigWriterFence)> {
    let secure = SecureDir::open(dir, create)?;
    let fence = secure.acquire_config_writer_fence()?;
    Ok((secure, fence))
}

pub(crate) fn acquire_runtime_compensation_auth_lease(
    dir: &Path,
) -> io::Result<RuntimeCompensationAuthLease> {
    let secure = SecureDir::open(dir, false)?;
    let fence = secure.acquire_runtime_compensation_fence(FLOCK_SH)?;
    Ok(RuntimeCompensationAuthLease {
        _secure: secure,
        _fence: fence,
    })
}

/// Serialize one ordinary authority filesystem mutation with durable replay
/// and live/history authority restoration.  This is intentionally narrower
/// than the config writer fence: only authority writers call it.
pub(crate) fn acquire_authority_writer_guard() -> io::Result<AuthorityWriterGuard<'static>> {
    acquire_authority_writer_guard_at(&default_dir())
}

fn acquire_authority_writer_guard_at(dir: &Path) -> io::Result<AuthorityWriterGuard<'static>> {
    let secure = SecureDir::open(dir, true)?;
    #[cfg(all(test, unix))]
    if let Some(marker) = std::env::var_os("CSSWITCH_TEST_AUTHORITY_WRITER_SH_PROBE_MARKER") {
        // A test-only nonblocking probe records that this precise normal
        // writer reached the SH flock and observed an EX owner. The real
        // blocking acquisition immediately below remains the production path.
        let probe = secure.acquire_runtime_compensation_fence(FLOCK_SH | libc::LOCK_NB);
        match probe {
            Ok(fence) => {
                drop(fence);
                fs::write(marker, b"uncontended")?;
            }
            Err(error)
                if error.raw_os_error() == Some(libc::EWOULDBLOCK)
                    || error.raw_os_error() == Some(libc::EAGAIN) =>
            {
                fs::write(marker, b"blocked")?;
            }
            Err(error) => return Err(error),
        }
    }
    let fence = secure.acquire_runtime_compensation_fence(FLOCK_SH)?;
    Ok(AuthorityWriterGuard {
        _kind: AuthorityWriterGuardKind::Shared {
            _secure: secure,
            _fence: fence,
        },
    })
}

/// Consume a scoped EX proof for a single nested writer call.  The guard has
/// no unlock effect because the owner lease remains responsible for the EX
/// flock's lifetime.
pub(crate) fn authority_writer_guard_from_bypass<'owner>(
    _bypass: &'owner AuthorityWriterBypass<'owner>,
) -> AuthorityWriterGuard<'owner> {
    AuthorityWriterGuard {
        _kind: AuthorityWriterGuardKind::Bypass(PhantomData),
    }
}

macro_rules! authority_writer_bypass {
    ($lease:ty) => {
        impl $lease {
            pub(crate) fn authority_writer_bypass(&self) -> AuthorityWriterBypass<'_> {
                AuthorityWriterBypass {
                    _owner: PhantomData,
                    _not_send_or_sync: PhantomData,
                }
            }
        }
    };
}

authority_writer_bypass!(RuntimeCompensationReplayLease);
authority_writer_bypass!(RuntimeHistoryEffectLease);

/// Prepare the one descriptor that the Desktop-spawned Gateway may inherit for
/// its Skill mutation host.  The descriptor is not a lock grant: the child
/// revalidates this exact identity and takes SH for each mutation.
pub(crate) fn prepare_authority_fence_capability(
    dir: &Path,
) -> io::Result<AuthorityFenceCapability> {
    SecureDir::open(dir, false)?.authority_fence_capability()
}

pub(crate) fn acquire_runtime_compensation_publication_lease(
    dir: &Path,
) -> io::Result<RuntimeCompensationPublicationLease> {
    let secure = SecureDir::open(dir, false)?;
    let fence = secure.acquire_runtime_compensation_fence(FLOCK_EX)?;
    Ok(RuntimeCompensationPublicationLease {
        _secure: secure,
        _fence: fence,
    })
}

pub(crate) fn acquire_runtime_compensation_replay_lease(
    dir: &Path,
) -> io::Result<RuntimeCompensationReplayLease> {
    let secure = SecureDir::open(dir, false)?;
    let fence = secure.acquire_runtime_compensation_fence(FLOCK_EX)?;
    Ok(RuntimeCompensationReplayLease {
        _secure: secure,
        _fence: fence,
    })
}

pub(crate) fn acquire_runtime_history_effect_lease(
    dir: &Path,
) -> io::Result<RuntimeHistoryEffectLease> {
    let secure = SecureDir::open(dir, false)?;
    let fence = secure.acquire_runtime_compensation_fence(FLOCK_EX)?;
    Ok(RuntimeHistoryEffectLease {
        _secure: secure,
        _fence: fence,
    })
}

// ---------- 备份 ----------
/// 迁移前备份旧 config.json → config.json.v1.bak。源不存在 / 备份失败 → Err（中止迁移）。
#[cfg(test)]
pub fn write_migration_backup(dir: &Path) -> io::Result<()> {
    let secure = SecureDir::open(dir, false)?;
    let data = secure
        .read_regular("config.json")?
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "config.json 不存在"))?;
    write_versioned_backup_bytes_in(&secure, 1, &data).map(|_| ())
}

fn backup_suffix() -> String {
    let millis = now_ms();
    let id = new_id();
    format!("{millis}-{}", &id[..8])
}

fn backup_content_suffix(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// 版本迁移备份：固定名存在且内容相同就复用；内容不同时写唯一后缀，永不覆盖。
/// temp 在同目录完整 fsync 后用 hard_link 原子发布，link 本身具有 O_EXCL 语义。
#[cfg(test)]
fn write_versioned_backup_bytes(dir: &Path, version: u32, bytes: &[u8]) -> io::Result<PathBuf> {
    let secure = SecureDir::open(dir, true)?;
    write_versioned_backup_bytes_in(&secure, version, bytes)
}

fn write_versioned_backup_bytes_in(
    secure: &SecureDir,
    version: u32,
    bytes: &[u8],
) -> io::Result<PathBuf> {
    let primary = format!("config.json.v{version}.bak");
    let content_suffix = backup_content_suffix(bytes);
    let alternate = format!("config.json.v{version}.bak.{content_suffix}");
    let pending = format!(".config.json.v{version}.bak.pending-{content_suffix}");

    // link+dir-fsync 后若进程崩溃，pending hard link 可能在重启后重新出现。
    // 当前迁移输入在 backup 成功前不会改变，因此内容哈希能稳定定位并清理残留。
    if secure.regular_exists_allow_hardlinks(&pending)? {
        secure.unlink(&pending)?;
        secure.sync()?;
    }
    let target = match secure.read_regular(&primary)? {
        Some(existing) if existing == bytes => return Ok(secure.display_path(&primary)),
        Some(_) => alternate,
        None => primary.clone(),
    };
    if let Some(existing) = secure.read_regular(&target)? {
        if existing == bytes {
            return Ok(secure.display_path(&target));
        }
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "版本备份哈希目标冲突",
        ));
    }
    let result = (|| -> io::Result<()> {
        let mut file = secure.create_new(&pending)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        secure.link(&pending, &target)?;
        if let Err(error) = secure.sync() {
            let _ = secure.unlink(&target);
            let _ = secure.unlink(&pending);
            let _ = secure.sync();
            return Err(error);
        }
        secure.unlink(&pending)?;
        secure.sync()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = secure.unlink(&pending);
    }
    result?;
    Ok(secure.display_path(&target))
}

/// 普通保存前的单份滚动备份 → config.json.bak。best-effort（调用方可忽略 Err），但写法仍原子/0600。
#[cfg(test)]
pub fn write_rolling_backup(dir: &Path) -> io::Result<()> {
    let access = config_access();
    ensure_config_access_open(&access)?;
    let (secure, _fence) = open_config_writer(dir, false)?;
    write_rolling_backup_in(&secure)
}

fn write_rolling_backup_in(secure: &SecureDir) -> io::Result<()> {
    let data = secure
        .read_regular("config.json")?
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "config.json 不存在"))?;
    atomic_write_named_bytes_in(secure, "config.json.bak", &data, None, |secure| {
        secure.sync()
    })
}

/// 清 key / 删 profile 后净化滚动备份。调用方只有在 unlink、目录 fsync 与
/// exact absence 回读都成功后，才能把 credential/profile revocation 记为完成。
pub fn drop_rolling_backup(dir: &Path) -> io::Result<()> {
    let access = config_access();
    ensure_config_access_open(&access)?;
    let (secure, _fence) = match open_config_writer(dir, false) {
        Ok(writer) => writer,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    if secure.read_regular("config.json.bak")?.is_none() {
        return Ok(());
    }
    #[cfg(test)]
    if DROP_ROLLING_BACKUP_FAILURE
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .as_ref()
        .is_some_and(|(thread, armed_dir, fault)| {
            *thread == std::thread::current().id()
                && armed_dir == dir
                && *fault == DropRollingBackupFault::Unlink
        })
    {
        return Err(io::Error::other("test-only rolling backup unlink failure"));
    }
    secure.unlink("config.json.bak")?;
    #[cfg(test)]
    if DROP_ROLLING_BACKUP_FAILURE
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .as_ref()
        .is_some_and(|(thread, armed_dir, fault)| {
            *thread == std::thread::current().id()
                && armed_dir == dir
                && *fault == DropRollingBackupFault::DirectorySync
        })
    {
        return Err(io::Error::other(
            "test-only rolling backup directory sync failure",
        ));
    }
    secure.sync()?;
    if secure.read_regular("config.json.bak")?.is_some() {
        return Err(io::Error::other("滚动备份删除后的 exact absence 回读失败"));
    }
    Ok(())
}

/// 从 `dir/config.json` 读配置。文件不存在返回 [`Config::default`]。
/// v1/v2/v3 先完整解析、迁移、校验，再写不可覆盖的版本备份，最后只原子提交一次 v4。
/// v4 悬空 active_id 归一化为空。文件/目录是符号链接则报错（不跟随读）。
pub fn load_from(dir: &Path) -> io::Result<Config> {
    let access = config_access();
    ensure_config_access_open(&access)?;
    assert_not_symlink(dir)?;
    let (secure, _fence) = match open_config_writer(dir, false) {
        Ok(writer) => writer,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Config::default()),
        Err(error) => return Err(error),
    };
    load_from_secure(&secure)
}

/// One-click and other effect owners use this immediately before any external
/// effect. It snapshots Config and all P2-A/P2-B sidecar admission state under
/// the same writer lock, including resurrection of an interrupted clearing
/// receipt. One-click's own runtime journal is intentionally allowed here so
/// its dedicated replay owner can converge it.
pub(crate) fn load_for_runtime_effect_admission(dir: &Path) -> io::Result<Config> {
    let access = config_access();
    ensure_config_access_open(&access)?;
    assert_not_symlink(dir)?;
    let (secure, _fence) = match open_config_writer(dir, false) {
        Ok(writer) => writer,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Config::default()),
        Err(error) => return Err(error),
    };
    require_no_sidecar_mutation_receipts_in(&secure)?;
    let cfg = load_from_secure(&secure)?;
    if cfg.codex_disable_operation_fence()?.is_some() {
        return Err(io::Error::other(
            "code=codex_disable_operation_in_progress Codex disable operation 尚未结束；拒绝 runtime effect。",
        ));
    }
    if cfg.config_mutation_operation_fence()?.is_some() {
        return Err(io::Error::other(
            "code=config_mutation_operation_in_progress Config mutation operation 尚未结束；拒绝 runtime effect。",
        ));
    }
    Ok(cfg)
}

/// Read the already-canonical config without migration, normalization writes, or
/// notice clearing. Consumer status projections must never become mutation
/// owners, so older schemas are rejected instead of upgraded here.
pub(crate) fn load_current_from_read_only(dir: &Path) -> io::Result<Config> {
    let access = config_access();
    ensure_config_access_open(&access)?;
    assert_not_symlink(dir)?;
    let secure = match SecureDir::open_read_only(dir) {
        Ok(secure) => secure,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Config::default()),
        Err(error) => return Err(error),
    };
    let Some(data) = secure.read_regular("config.json")? else {
        return Ok(Config::default());
    };
    if !matches!(detect_version(&data)?, VersionKind::V4) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "read-only consumer requires canonical schema v4",
        ));
    }
    let cfg: Config = serde_json::from_slice(&data).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("v4 config.json 解析失败：{error}"),
        )
    })?;
    let cfg = normalize_active(cfg);
    validate_loaded_ports(&cfg)?;
    validate_profile_contracts(&cfg)?;
    Ok(cfg)
}

fn load_from_secure(secure: &SecureDir) -> io::Result<Config> {
    let data = match secure.read_regular("config.json")? {
        Some(data) => data,
        None => return Ok(Config::default()),
    };
    match detect_version(&data)? {
        VersionKind::TooNew(v) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("config.json 由更新版本（schema {v}）写入，请升级 CSSwitch 后再打开。"),
        )),
        VersionKind::Legacy => {
            let legacy: crate::config_legacy::ConfigV1 =
                serde_json::from_slice(&data).map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("旧 config 解析失败：{e}"),
                    )
                })?;
            let v2 = migrate_v1_to_v2(legacy);
            let canonical_v2 = serde_json::to_vec_pretty(&v2).map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("v2 备份序列化失败：{error}"),
                )
            })?;
            let cfg = normalize_active(migrate_v3_to_v4(migrate_v2_to_v3(v2)?)?);
            validate_loaded_ports(&cfg)?;
            validate_profile_contracts(&cfg)?;
            write_versioned_backup_bytes_in(secure, 1, &data)?;
            write_versioned_backup_bytes_in(secure, 2, &canonical_v2)?;
            commit_migrated_config(secure, &data, &cfg)?;
            Ok(cfg)
        }
        VersionKind::V2 => {
            let v2: crate::config_legacy::ConfigV2 =
                serde_json::from_slice(&data).map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("v2 config.json 解析失败：{e}"),
                    )
                })?;
            let canonical_v2 = serde_json::to_vec_pretty(&v2).map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("v2 备份序列化失败：{error}"),
                )
            })?;
            let cfg = normalize_active(migrate_v3_to_v4(migrate_v2_to_v3(v2)?)?);
            validate_loaded_ports(&cfg)?;
            validate_profile_contracts(&cfg)?;
            write_versioned_backup_bytes_in(secure, 2, &canonical_v2)?;
            commit_migrated_config(secure, &data, &cfg)?;
            Ok(cfg)
        }
        VersionKind::V3 => {
            let v3: crate::config_legacy::ConfigV3 =
                serde_json::from_slice(&data).map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("v3 config.json 解析失败：{e}"),
                    )
                })?;
            let cfg = normalize_active(migrate_v3_to_v4(v3)?);
            validate_loaded_ports(&cfg)?;
            validate_profile_contracts(&cfg)?;
            write_versioned_backup_bytes_in(secure, 3, &data)?;
            commit_migrated_config(secure, &data, &cfg)?;
            Ok(cfg)
        }
        VersionKind::V4 => {
            let cfg: Config = serde_json::from_slice(&data).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("v4 config.json 解析失败：{e}"),
                )
            })?;
            let cfg = normalize_active(cfg);
            validate_loaded_ports(&cfg)?;
            validate_profile_contracts(&cfg)?;
            Ok(cfg)
        }
    }
}

fn commit_migrated_config(secure: &SecureDir, original: &[u8], cfg: &Config) -> io::Result<()> {
    #[cfg(test)]
    {
        let failure = MIGRATION_COMMIT_FAILURE
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if failure.as_ref().is_some_and(|(thread, dir)| {
            *thread == std::thread::current().id() && dir == &secure.path
        }) {
            return Err(io::Error::other(
                "test-only migration failure after backup before v4 commit",
            ));
        }
    }
    let json = serde_json::to_vec_pretty(cfg).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("v4 配置序列化失败：{error}"),
        )
    })?;
    let decoded: Config = serde_json::from_slice(&json).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("v4 配置回读验证失败：{error}"),
        )
    })?;
    let decoded = normalize_active(decoded);
    validate_loaded_ports(&decoded)?;
    validate_profile_contracts(&decoded)?;
    atomic_write_named_bytes_in(secure, "config.json", &json, Some(original), |secure| {
        secure.sync()
    })?;

    let published = secure
        .read_regular("config.json")?
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "v4 配置提交后消失"));
    let post_check = published.and_then(|published| {
        if published != json {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "v4 配置提交后字节校验不一致",
            ));
        }
        let reread: Config = serde_json::from_slice(&published).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("v4 配置提交后解析失败：{error}"),
            )
        })?;
        let reread = normalize_active(reread);
        validate_loaded_ports(&reread)?;
        validate_profile_contracts(&reread)
    });
    if let Err(post_error) = post_check {
        return match atomic_write_named_bytes_in(
            secure,
            "config.json",
            original,
            Some(&json),
            |secure| secure.sync(),
        ) {
            Ok(()) => Err(post_error),
            Err(rollback_error) => Err(io::Error::other(format!(
                "v4 配置提交后验证失败：{post_error}；恢复原配置也失败：{rollback_error}"
            ))),
        };
    }
    Ok(())
}

fn validate_loaded_ports(cfg: &Config) -> io::Result<()> {
    validate_runtime_ports(cfg.proxy_port, cfg.sandbox_port).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("config.json 端口无效：{e}"),
        )
    })
}

/// 加载后归一化两个不变式（spec §4）：
/// - `template_id` 未命中注册表 → 归一化为 `custom`（保留连接字段；据它派生 adapter/UI 能力）；
/// - `active_id` 指向不存在的 profile → 归一化为空（运行时据此停代理、要求用户选）。
fn normalize_active(mut cfg: Config) -> Config {
    for p in cfg.profiles.iter_mut() {
        if p.api_format.trim().is_empty() {
            p.api_format = crate::templates::by_id(&p.template_id)
                .map(|template| template.api_format.to_string())
                .unwrap_or_else(|| "anthropic".to_string());
        }
        let known_contract =
            crate::provider_contracts::contract_for(&p.template_id, &p.api_format).is_ok();
        if crate::templates::by_id(&p.template_id).is_none() && !known_contract {
            p.template_id = "custom".to_string();
        }
        p.model = p
            .model_catalog
            .iter()
            .find(|route| route.selector_id == p.default_model_route_id)
            .map(|route| route.upstream_model.clone())
            .unwrap_or_default();
    }
    if !cfg.active_id.is_empty() && cfg.profile_by_id(&cfg.active_id).is_none() {
        cfg.active_id.clear();
    }
    cfg
}

fn validate_profile_contracts(cfg: &Config) -> io::Result<()> {
    if cfg.schema_version != CURRENT_SCHEMA_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("只接受 canonical schema v{CURRENT_SCHEMA_VERSION}"),
        ));
    }
    let codex_disable_fence = cfg.codex_disable_operation_fence()?;
    let config_mutation_fence = cfg.config_mutation_operation_fence()?;
    if codex_disable_fence.is_some() && config_mutation_fence.is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "P2-A 与 P2-B Config fence 不能同时存在",
        ));
    }
    let mut ids = BTreeSet::new();
    for reserved in [
        "schema_version",
        "profiles",
        "active_id",
        "proxy_port",
        "sandbox_port",
        "reuse_system_ssh",
        "experimental_codex_enabled",
        "codex_network",
        "secret",
        "mode",
        "pending_notice",
        "runtime_binding",
        "runtime_transaction",
        "runtime_compensation",
    ] {
        if cfg.extra.contains_key(reserved) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("config extension 与 canonical 字段冲突：{reserved}"),
            ));
        }
    }
    if let Some(compensation) = cfg.runtime_compensation.as_ref() {
        let state_valid = matches!(
            compensation.state,
            RuntimeCompensationState::InProgress | RuntimeCompensationState::Incomplete { .. }
        );
        let failed_steps_valid = match &compensation.state {
            RuntimeCompensationState::Incomplete { failed_steps } => {
                !failed_steps.is_empty()
                    && failed_steps
                        .iter()
                        .enumerate()
                        .all(|(index, step)| !failed_steps[..index].contains(step))
            }
            RuntimeCompensationState::InProgress => true,
            RuntimeCompensationState::NotStarted => false,
        };
        let schema_valid = match compensation.schema_version {
            RUNTIME_COMPENSATION_SCHEMA_VERSION_V1 => {
                compensation.steps.is_empty()
                    && compensation.science_adoption_attempt_ids.is_empty()
            }
            RUNTIME_COMPENSATION_SCHEMA_VERSION_V2 => {
                valid_runtime_compensation_steps(compensation)
                    && compensation.science_adoption_attempt_ids.len() <= 2
                    && compensation
                        .science_adoption_attempt_ids
                        .iter()
                        .enumerate()
                        .all(|(index, value)| {
                            value.len() == 32
                                && value.bytes().all(|byte| {
                                    byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')
                                })
                                && !compensation.science_adoption_attempt_ids[..index]
                                    .contains(value)
                        })
            }
            _ => false,
        };
        if !schema_valid
            || compensation.compensation_id.is_empty()
            || compensation.target_profile_id.is_empty()
            || !valid_runtime_fingerprint(&compensation.runtime_fingerprint)
            || !valid_runtime_snapshot_ticket(&compensation.snapshot_ticket.managed_id)
            || !state_valid
            || !failed_steps_valid
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "runtime_compensation must be a path-free registered step progress record",
            ));
        }
    }
    if cfg
        .runtime_binding
        .as_ref()
        .and_then(|binding| binding.science_adoption_attempt_id.as_deref())
        .is_some_and(|value| {
            value.len() != 32
                || !value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        })
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "runtime_binding Science adoption attempt id is invalid",
        ));
    }
    for reserved in ["mode", "proxy_url"] {
        if cfg.codex_network.extra.contains_key(reserved) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("codex_network extension 与 canonical 字段冲突：{reserved}"),
            ));
        }
    }
    for profile in &cfg.profiles {
        for reserved in [
            "id",
            "name",
            "template_id",
            "category",
            "api_format",
            "base_url",
            "api_key",
            "model",
            "model_catalog",
            "default_model_route_id",
            "role_bindings",
            "credential_source",
            "credential_ref",
            "model_policy",
            "website_url",
            "icon",
            "icon_color",
            "sort_index",
            "created_at",
            "notes",
        ] {
            if profile.extra.contains_key(reserved) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "profile `{}` extension 与 canonical 字段冲突：{reserved}",
                        profile.id
                    ),
                ));
            }
        }
        if profile.id.trim().is_empty() || profile.id.len() > 256 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "profile id 不能为空且不得超过 256 字节",
            ));
        }
        if !ids.insert(profile.id.clone()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("profile id 重复：{}", profile.id),
            ));
        }
        let contract =
            crate::provider_contracts::contract_for(&profile.template_id, &profile.api_format)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        if !contract
            .credential_sources
            .contains(&profile.credential_source)
            || !contract.model_policies.contains(&profile.model_policy)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "profile `{}` 的 credential/model policy 不符合 provider contract",
                    profile.id
                ),
            ));
        }
        match profile.model_policy {
            ModelPolicy::DynamicCatalog => {
                if profile.template_id != "codex"
                    || !profile.model_catalog.is_empty()
                    || !profile.default_model_route_id.is_empty()
                    || !profile.role_bindings.all_empty()
                {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("动态目录 profile `{}` 含静态目录或不是 Codex", profile.id),
                    ));
                }
            }
            ModelPolicy::SavedCatalog if profile.model_catalog.is_empty() => {
                if cfg.active_id == profile.id
                    || !profile.default_model_route_id.is_empty()
                    || !profile.role_bindings.all_empty()
                {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("未完成静态 profile `{}` 不得激活或保存悬空绑定", profile.id),
                    ));
                }
            }
            ModelPolicy::SavedCatalog => {
                crate::model_catalog::validate_saved_catalog(
                    &profile.model_catalog,
                    &profile.default_model_route_id,
                    &profile.role_bindings,
                )
                .map_err(|error| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("profile `{}` 模型目录无效：{error}", profile.id),
                    )
                })?;
            }
        }
        match profile.credential_source {
            CredentialSource::ApiKey if profile.credential_ref.is_some() => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("API-key profile `{}` 不得保存 credential_ref", profile.id),
                ));
            }
            CredentialSource::CsswitchOauth => {
                if profile.credential_ref.as_deref() != Some("csswitch:codex:default")
                    || !profile.api_key.is_empty()
                {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "OAuth profile `{}` 的 credential_ref 或 api_key 非法",
                            profile.id
                        ),
                    ));
                }
            }
            CredentialSource::None
                if profile.credential_ref.is_some() || !profile.api_key.is_empty() =>
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("无凭据 profile `{}` 不得保存 credential 数据", profile.id),
                ));
            }
            _ => {}
        }
    }
    if !cfg.active_id.is_empty() && !ids.contains(&cfg.active_id) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("active_id 指向不存在的 profile：{}", cfg.active_id),
        ));
    }
    Ok(())
}

/// 原子写 `dir/config.json`（0600）。目录/目标文件是符号链接则拒绝。
#[allow(dead_code)]
pub fn save_to(dir: &Path, cfg: &Config) -> io::Result<()> {
    let access = config_access();
    ensure_config_access_open(&access)?;
    let (secure, _fence) = open_config_writer(dir, true)?;
    require_no_sidecar_mutation_receipts_in(&secure)?;
    // `save_to` is also the explicit repair primitive for malformed legacy
    // bytes. Preserve that overwrite contract, but enforce the HistoryRecovery
    // fence whenever a valid current Config can be identified.
    if let Ok(current) = load_from_secure(&secure) {
        ensure_history_recovery_sibling_authority_unchanged(&current, cfg)?;
        ensure_codex_disable_sibling_authority_unchanged(&current, cfg)?;
        ensure_config_mutation_sibling_authority_unchanged(&current, cfg)?;
    }
    save_to_secure(&secure, cfg)
}

#[cfg(test)]
pub(crate) fn test_save_to_without_history_authority_guard(
    dir: &Path,
    cfg: &Config,
) -> io::Result<()> {
    let access = config_access();
    ensure_config_access_open(&access)?;
    let (secure, _fence) = open_config_writer(dir, true)?;
    save_to_secure(&secure, cfg)
}

fn ensure_history_recovery_sibling_authority_unchanged(
    current: &Config,
    next: &Config,
) -> io::Result<()> {
    let history_open = matches!(
        current.runtime_transaction.as_ref(),
        Some(RuntimeTransactionRecord::V2(record))
            if record.operation == RuntimeTransactionOperation::HistoryRecovery
    );
    if !history_open {
        return Ok(());
    }
    let mut current_authority = current.clone();
    current_authority.runtime_transaction = None;
    let mut next_authority = next.clone();
    next_authority.runtime_transaction = None;
    if current_authority != next_authority {
        return Err(io::Error::other(
            "history recovery 正在持有完整 Config authority；拒绝 sibling config writer",
        ));
    }
    Ok(())
}

fn ensure_codex_disable_sibling_authority_unchanged(
    current: &Config,
    next: &Config,
) -> io::Result<()> {
    if current.codex_disable_operation_fence()?.is_some() && current != next {
        return Err(io::Error::other(
            "Codex disable operation 正在持有完整 Config authority；拒绝 sibling config writer",
        ));
    }
    Ok(())
}

fn ensure_config_mutation_sibling_authority_unchanged(
    current: &Config,
    next: &Config,
) -> io::Result<()> {
    if current.config_mutation_operation_fence()?.is_some() && current != next {
        return Err(io::Error::other(
            "Config mutation operation 正在持有 Config authority；拒绝 sibling config writer",
        ));
    }
    Ok(())
}

fn save_to_secure(secure: &SecureDir, cfg: &Config) -> io::Result<()> {
    if cfg.schema_version != CURRENT_SCHEMA_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("只能保存 schema v{CURRENT_SCHEMA_VERSION} 配置"),
        ));
    }
    validate_loaded_ports(cfg)?;
    validate_profile_contracts(cfg)?;
    let json = serde_json::to_vec_pretty(cfg).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("config 序列化失败：{e}"),
        )
    })?;

    atomic_write_named_bytes_in(secure, "config.json", &json, None, |secure| secure.sync())
}

fn atomic_write_config_bytes_in(secure: &SecureDir, json: &[u8]) -> io::Result<()> {
    atomic_write_named_bytes_in(secure, "config.json", json, None, |secure| secure.sync())
}

#[derive(Debug)]
struct AtomicRollbackUncertain {
    commit: String,
    rollback: String,
}

impl std::fmt::Display for AtomicRollbackUncertain {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "配置提交同步失败，且回滚失败：commit={}; rollback={}",
            self.commit, self.rollback
        )
    }
}

impl std::error::Error for AtomicRollbackUncertain {}

fn atomic_rollback_is_uncertain(error: &io::Error) -> bool {
    error
        .get_ref()
        .is_some_and(|source| source.is::<AtomicRollbackUncertain>())
}

/// 先发布临时文件，再持久化目录项。若发布后的同步失败，恢复发布前字节并再次
/// 同步，保证 `Err` 的可观察语义是目标文件未改变。测试可注入 commit sync 失败。
enum AtomicWriteExpectedBefore<'a> {
    Any,
    Exact(&'a [u8]),
    Absent,
}

fn atomic_write_named_bytes_in<F>(
    secure: &SecureDir,
    target: &str,
    bytes: &[u8],
    expected_before: Option<&[u8]>,
    commit_sync: F,
) -> io::Result<()>
where
    F: FnOnce(&SecureDir) -> io::Result<()>,
{
    atomic_write_named_bytes_with_expectation_in(
        secure,
        target,
        bytes,
        expected_before
            .map(AtomicWriteExpectedBefore::Exact)
            .unwrap_or(AtomicWriteExpectedBefore::Any),
        commit_sync,
    )
}

fn atomic_write_named_bytes_if_absent_in<F>(
    secure: &SecureDir,
    target: &str,
    bytes: &[u8],
    commit_sync: F,
) -> io::Result<()>
where
    F: FnOnce(&SecureDir) -> io::Result<()>,
{
    atomic_write_named_bytes_with_expectation_in(
        secure,
        target,
        bytes,
        AtomicWriteExpectedBefore::Absent,
        commit_sync,
    )
}

fn atomic_write_named_bytes_with_expectation_in<F>(
    secure: &SecureDir,
    target: &str,
    bytes: &[u8],
    expected_before: AtomicWriteExpectedBefore<'_>,
    commit_sync: F,
) -> io::Result<()>
where
    F: FnOnce(&SecureDir) -> io::Result<()>,
{
    let before = secure.read_regular_snapshot(target)?;
    match expected_before {
        AtomicWriteExpectedBefore::Any => {}
        AtomicWriteExpectedBefore::Exact(expected)
            if before.as_ref().map(|(bytes, _)| bytes.as_slice()) == Some(expected) => {}
        AtomicWriteExpectedBefore::Absent if before.is_none() => {}
        _ => {
            return Err(io::Error::other("配置在迁移提交前被外部进程修改"));
        }
    }
    let suffix = backup_suffix();
    let tmp = format!(".{target}.tmp-{}-{suffix}", std::process::id());

    let mut file = secure.create_new(&tmp)?;
    if let Err(error) = file.write_all(bytes).and_then(|_| file.sync_all()) {
        let _ = secure.unlink(&tmp);
        return Err(error);
    }
    drop(file);

    #[cfg(test)]
    if let Err(error) = atomic_write_pre_rename_failure(secure, target, &tmp, bytes) {
        let _ = secure.unlink(&tmp);
        return Err(error);
    }

    match (before.as_ref(), secure.read_regular(target)) {
        (Some((expected, _)), Ok(Some(actual))) if expected == &actual => {}
        (None, Ok(None)) => {}
        (_, Ok(_)) => {
            let _ = secure.unlink(&tmp);
            return Err(io::Error::other("配置在提交前被并发修改"));
        }
        (_, Err(error)) => {
            let _ = secure.unlink(&tmp);
            return Err(error);
        }
    }

    if let Err(error) = secure.rename(&tmp, target) {
        let _ = secure.unlink(&tmp);
        return Err(error);
    }

    if let Err(commit_error) = commit_sync(secure) {
        let restore = if let Some((old_bytes, old_mode)) = before {
            let restore_tmp = format!(".{target}.restore-{}-{suffix}", std::process::id());
            let restore_result = (|| -> io::Result<()> {
                let mut restore_file = secure.create_new(&restore_tmp)?;
                restore_file.write_all(&old_bytes)?;
                crate::platform::set_file_mode(&restore_file, old_mode)?;
                restore_file.sync_all()?;
                drop(restore_file);
                secure.rename(&restore_tmp, target)?;
                secure.sync()
            })();
            if restore_result.is_err() {
                let _ = secure.unlink(&restore_tmp);
            }
            restore_result
        } else {
            secure.unlink(target).and_then(|_| secure.sync())
        };
        if let Err(restore_error) = restore {
            return Err(io::Error::other(AtomicRollbackUncertain {
                commit: commit_error.to_string(),
                rollback: restore_error.to_string(),
            }));
        }
        return Err(commit_error);
    }
    Ok(())
}

#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CodexDowngradeAction {
    ExportThenRemove,
    Remove,
}

#[allow(dead_code)]
#[derive(Debug)]
pub(crate) struct DowngradePreview {
    pub(crate) v2: crate::config_legacy::ConfigV2,
    pub(crate) exports: Vec<serde_json::Value>,
    pub(crate) fingerprint: String,
}

#[derive(Debug)]
pub(crate) struct DowngradeError {
    pub(crate) message: String,
    pub(crate) exit_required: bool,
}

impl DowngradeError {
    fn safe(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            exit_required: false,
        }
    }

    fn commit(error: io::Error) -> Self {
        Self {
            exit_required: atomic_rollback_is_uncertain(&error),
            message: format!("v2 配置原子提交失败：{error}"),
        }
    }
}

impl From<String> for DowngradeError {
    fn from(message: String) -> Self {
        Self::safe(message)
    }
}

impl From<&str> for DowngradeError {
    fn from(message: &str) -> Self {
        Self::safe(message)
    }
}

fn latch_terminal_downgrade_outcome(
    access: &mut ConfigAccessState,
    result: &Result<Option<PathBuf>, DowngradeError>,
) {
    if result.is_ok() || result.as_ref().is_err_and(|error| error.exit_required) {
        access.downgrade_terminal = true;
    }
}

#[allow(dead_code)]
pub(crate) fn prepare_downgrade_to_v2(
    cfg: &Config,
    actions: &BTreeMap<String, CodexDowngradeAction>,
) -> Result<DowngradePreview, String> {
    require_no_runtime_transaction(cfg)?;
    validate_profile_contracts(cfg).map_err(|error| error.to_string())?;
    if !cfg.extra.is_empty()
        || !cfg.codex_network.extra.is_empty()
        || cfg.profiles.iter().any(|profile| {
            !profile.extra.is_empty()
                || !profile.role_bindings.extra.is_empty()
                || profile
                    .model_catalog
                    .iter()
                    .any(|route| !route.extra.is_empty())
        })
    {
        return Err("配置含当前版本不理解的扩展字段；为避免静默丢失，拒绝降级到 v2。".into());
    }
    let codex_ids: BTreeSet<String> = cfg
        .profiles
        .iter()
        .filter(|profile| profile.credential_source == CredentialSource::CsswitchOauth)
        .map(|profile| profile.id.clone())
        .collect();
    let action_ids: BTreeSet<String> = actions.keys().cloned().collect();
    if codex_ids != action_ids {
        return Err(
            "降级前必须为每个且仅每个 Codex profile 选择 export_then_remove 或 remove".into(),
        );
    }
    let mut profiles = Vec::new();
    let mut exports = Vec::new();
    for profile in &cfg.profiles {
        if profile.credential_source == CredentialSource::CsswitchOauth {
            if actions.get(&profile.id) == Some(&CodexDowngradeAction::ExportThenRemove) {
                exports.push(serde_json::json!({
                    "schema_version": 1,
                    "profile": {
                        "id": profile.id,
                        "name": profile.name,
                        "template_id": profile.template_id,
                        "category": profile.category,
                        "api_format": profile.api_format,
                        "model": profile.model,
                        "model_policy": profile.model_policy,
                        "website_url": profile.website_url,
                        "icon": profile.icon,
                        "icon_color": profile.icon_color,
                        "sort_index": profile.sort_index,
                        "created_at": profile.created_at,
                        "notes": profile.notes
                    }
                }));
            }
            continue;
        }
        let default_upstream = profile
            .model_catalog
            .iter()
            .find(|route| route.selector_id == profile.default_model_route_id)
            .map(|route| route.upstream_model.clone())
            .unwrap_or_default();
        if !profile.model_catalog.is_empty() {
            exports.push(serde_json::json!({
                "schema_version": 1,
                "kind": "saved_model_catalog",
                "profile": {
                    "id": profile.id,
                    "name": profile.name,
                    "template_id": profile.template_id,
                    "category": profile.category,
                    "api_format": profile.api_format,
                    "model_policy": profile.model_policy,
                    "default_model_route_id": profile.default_model_route_id,
                    "default_upstream_model": default_upstream,
                    "model_catalog": profile.model_catalog.iter().map(|route| serde_json::json!({
                        "selector_id": route.selector_id,
                        "display_name": route.display_name,
                        "upstream_model": route.upstream_model,
                        "supports_tools": route.supports_tools,
                    })).collect::<Vec<_>>(),
                    "role_bindings": {
                        "sonnet": profile.role_bindings.sonnet,
                        "opus": profile.role_bindings.opus,
                        "haiku": profile.role_bindings.haiku,
                        "fable": profile.role_bindings.fable,
                    },
                    "website_url": profile.website_url,
                    "icon": profile.icon,
                    "icon_color": profile.icon_color,
                    "sort_index": profile.sort_index,
                    "created_at": profile.created_at,
                    "notes": profile.notes,
                }
            }));
        }
        profiles.push(crate::config_legacy::ProfileV2 {
            id: profile.id.clone(),
            name: profile.name.clone(),
            template_id: profile.template_id.clone(),
            category: profile.category.clone(),
            api_format: profile.api_format.clone(),
            base_url: profile.base_url.clone(),
            api_key: profile.api_key.clone(),
            model: default_upstream,
            website_url: profile.website_url.clone(),
            icon: profile.icon.clone(),
            icon_color: profile.icon_color.clone(),
            sort_index: profile.sort_index,
            created_at: profile.created_at,
            notes: profile.notes.clone(),
        });
    }
    let active_id = if codex_ids.contains(&cfg.active_id) {
        String::new()
    } else {
        cfg.active_id.clone()
    };
    let fingerprint_bytes = serde_json::to_vec(cfg).map_err(|error| error.to_string())?;
    let mut fingerprint_hasher = Sha256::new();
    fingerprint_hasher.update(b"csswitch-v2-downgrade-preview-v1\0");
    fingerprint_hasher.update(&fingerprint_bytes);
    let fingerprint = format!("{:x}", fingerprint_hasher.finalize());
    Ok(DowngradePreview {
        v2: crate::config_legacy::ConfigV2 {
            schema_version: 2,
            profiles,
            active_id,
            proxy_port: cfg.proxy_port,
            sandbox_port: cfg.sandbox_port,
            reuse_system_ssh: cfg.reuse_system_ssh,
            secret: cfg.secret.clone(),
            mode: cfg.mode.clone(),
            pending_notice: cfg.pending_notice.clone(),
        },
        exports,
        fingerprint,
    })
}

/// 把当前 v4 原子降为 v2。调用方必须先停止受管 Codex 链路；本函数从不读取、
/// 删除或修改 CSSwitch 私有认证文件。若 action 要求 export，先把 bundle 原子持久化到调用方明确
/// 给出的目标，再提交 v2。两次提交之间崩溃只会留下“原配置 + 已完成 export”，不会
/// 出现 profile 已移除但 export 尚未落盘的数据丢失窗口。
#[allow(dead_code)]
pub(crate) fn downgrade_to_v2(
    dir: &Path,
    actions: &BTreeMap<String, CodexDowngradeAction>,
    export_destination: Option<&Path>,
) -> Result<Option<PathBuf>, String> {
    let access = config_access();
    ensure_config_access_open(&access).map_err(|error| error.to_string())?;
    downgrade_to_v2_unlocked(dir, actions, export_destination, None).map_err(|error| error.message)
}

/// Production terminal variant. It serializes against every config read/write,
/// commits v2, then latches the process closed before releasing the lock. Any
/// in-flight or later status/config command therefore finishes before commit or
/// fails without observing v2; none can trigger the normal migration chain from v2 back to the
/// current schema v4.
pub(crate) fn downgrade_to_v2_and_latch(
    dir: &Path,
    actions: &BTreeMap<String, CodexDowngradeAction>,
    export_destination: Option<&Path>,
    expected_fingerprint: &str,
) -> Result<Option<PathBuf>, DowngradeError> {
    let mut access = config_access();
    ensure_config_access_open(&access).map_err(|error| DowngradeError::safe(error.to_string()))?;
    let result =
        downgrade_to_v2_unlocked(dir, actions, export_destination, Some(expected_fingerprint));
    latch_terminal_downgrade_outcome(&mut access, &result);
    result
}

fn downgrade_to_v2_unlocked(
    dir: &Path,
    actions: &BTreeMap<String, CodexDowngradeAction>,
    export_destination: Option<&Path>,
    expected_fingerprint: Option<&str>,
) -> Result<Option<PathBuf>, DowngradeError> {
    let (secure, _fence) =
        open_config_writer(dir, true).map_err(|error| DowngradeError::safe(error.to_string()))?;
    require_no_sidecar_mutation_receipts_in(&secure)
        .map_err(|error| DowngradeError::safe(error.to_string()))?;
    let cfg = load_from_secure(&secure).map_err(|error| DowngradeError::safe(error.to_string()))?;
    require_no_runtime_transaction(&cfg).map_err(DowngradeError::safe)?;
    let preview = prepare_downgrade_to_v2(&cfg, actions)?;
    if expected_fingerprint
        .is_some_and(|expected| expected.is_empty() || expected != preview.fingerprint)
    {
        return Err("配置在确认后发生变化；未导出、未降级，请重新预览并确认。".into());
    }
    let v2_bytes = serde_json::to_vec_pretty(&preview.v2)
        .map_err(|error| format!("v2 配置序列化失败：{error}"))?;
    let export_bytes = if preview.exports.is_empty() {
        None
    } else {
        Some(
            serde_json::to_vec_pretty(&serde_json::json!({
                "schema_version": 2,
                "profiles": preview.exports
            }))
            .map_err(|error| format!("兼容性元数据导出序列化失败：{error}"))?,
        )
    };

    let export_path = match (export_bytes, export_destination) {
        (Some(bytes), Some(path)) => {
            if path == config_path(dir) {
                return Err("兼容性导出目标不得覆盖 config.json".into());
            }
            let parent = path
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .ok_or("兼容性导出目标缺少父目录")?;
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or("兼容性导出文件名必须是有效 UTF-8")?;
            let config_dir = SecureDir::open(dir, false)
                .map_err(|error| format!("打开 CSSwitch 配置目录失败：{error}"))?;
            let export_dir = SecureDir::open_unmanaged(parent)
                .map_err(|error| format!("打开兼容性导出父目录失败：{error}"))?;
            if config_dir
                .same_directory(&export_dir)
                .map_err(|error| format!("比较 export 目录失败：{error}"))?
            {
                return Err("兼容性导出不得写入 CSSwitch 配置目录或其路径别名".into());
            }
            atomic_write_named_bytes_in(&export_dir, name, &bytes, None, |secure| secure.sync())
                .map_err(|error| format!("Codex profile export 写入失败：{error}"))?;
            Some(path.to_path_buf())
        }
        (Some(_), None) => return Err("export_then_remove 必须提供 export 目标".into()),
        (None, Some(_)) => return Err("没有需要 export 的 Codex profile".into()),
        (None, None) => None,
    };

    // 所有 action、序列化与必需 export 先完整完成；之后才允许写 v2 config。
    write_rolling_backup_in(&secure).map_err(|error| format!("降级滚动备份失败：{error}"))?;
    #[cfg(test)]
    {
        let failure = DOWNGRADE_COMMIT_FAILURE
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .as_ref()
            .filter(|(thread, target, _)| *thread == std::thread::current().id() && target == dir)
            .map(|(_, _, exit_required)| *exit_required);
        if let Some(exit_required) = failure {
            return Err(DowngradeError {
                message: "test-only downgrade commit failure".into(),
                exit_required,
            });
        }
    }
    atomic_write_config_bytes_in(&secure, &v2_bytes).map_err(DowngradeError::commit)?;
    Ok(export_path)
}

/// 序列化的「读-改-写」：进程内全局写锁下 load → apply → save，避免并发命令
/// 各读一份旧 config、各改一个字段、互相覆盖。
pub fn update<F: FnOnce(&mut Config)>(dir: &Path, f: F) -> io::Result<Config> {
    let access = config_access();
    ensure_config_access_open(&access)?;
    let (secure, _fence) = open_config_writer(dir, true)?;
    require_no_sidecar_mutation_receipts_in(&secure)?;
    let mut cfg = load_from_secure(&secure)?;
    let current = cfg.clone();
    f(&mut cfg);
    ensure_history_recovery_sibling_authority_unchanged(&current, &cfg)?;
    ensure_codex_disable_sibling_authority_unchanged(&current, &cfg)?;
    ensure_config_mutation_sibling_authority_unchanged(&current, &cfg)?;
    #[cfg(test)]
    if CONFIG_UPDATE_COMMIT_FAILURE
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .as_ref()
        .is_some_and(|(thread, armed_dir)| {
            *thread == std::thread::current().id() && armed_dir == dir
        })
    {
        return Err(io::Error::other("test-only config update commit failure"));
    }
    save_to_secure(&secure, &cfg)?;
    Ok(cfg)
}

/// Serialized fallible read-modify-write. If the caller rejects the in-memory
/// mutation, no config or rolling backup is written.
pub fn update_result<T, F>(dir: &Path, f: F) -> Result<T, String>
where
    F: FnOnce(&mut Config) -> Result<(T, bool), String>,
{
    let access = config_access();
    ensure_config_access_open(&access).map_err(|error| error.to_string())?;
    let (secure, _fence) = open_config_writer(dir, true).map_err(|error| error.to_string())?;
    require_no_sidecar_mutation_receipts_in(&secure).map_err(|error| error.to_string())?;
    let mut cfg = load_from_secure(&secure).map_err(|error| error.to_string())?;
    let current = cfg.clone();
    let (result, changed) = f(&mut cfg)?;
    if changed {
        ensure_history_recovery_sibling_authority_unchanged(&current, &cfg)
            .map_err(|error| error.to_string())?;
        ensure_codex_disable_sibling_authority_unchanged(&current, &cfg)
            .map_err(|error| error.to_string())?;
        ensure_config_mutation_sibling_authority_unchanged(&current, &cfg)
            .map_err(|error| error.to_string())?;
        #[cfg(test)]
        if CONFIG_UPDATE_COMMIT_FAILURE
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .as_ref()
            .is_some_and(|(thread, armed_dir)| {
                *thread == std::thread::current().id() && armed_dir == dir
            })
        {
            return Err("test-only config update commit failure".into());
        }
        save_to_secure(&secure, &cfg).map_err(|error| error.to_string())?;
    }
    Ok(result)
}

/// Fallible serialized update whose rolling backup is created only after the
/// closure accepts the mutation. Backup remains best-effort, matching existing
/// profile-save behavior, while a guard error leaves both files untouched.
pub fn update_result_with_rolling_backup<T, F>(dir: &Path, f: F) -> Result<T, String>
where
    F: FnOnce(&mut Config) -> Result<(T, bool), String>,
{
    let access = config_access();
    ensure_config_access_open(&access).map_err(|error| error.to_string())?;
    let (secure, _fence) = open_config_writer(dir, true).map_err(|error| error.to_string())?;
    require_no_sidecar_mutation_receipts_in(&secure).map_err(|error| error.to_string())?;
    let mut cfg = load_from_secure(&secure).map_err(|error| error.to_string())?;
    let current = cfg.clone();
    let (result, changed) = f(&mut cfg)?;
    if changed {
        ensure_history_recovery_sibling_authority_unchanged(&current, &cfg)
            .map_err(|error| error.to_string())?;
        ensure_codex_disable_sibling_authority_unchanged(&current, &cfg)
            .map_err(|error| error.to_string())?;
        ensure_config_mutation_sibling_authority_unchanged(&current, &cfg)
            .map_err(|error| error.to_string())?;
        let _ = write_rolling_backup_in(&secure);
        save_to_secure(&secure, &cfg).map_err(|error| error.to_string())?;
    }
    Ok(result)
}

/// 掩码：固定 4 个圆点 + 末 4 位（`••••tail`）。空 key 返回空串；≤4 位全遮。
/// 定长而非随 key 长度增长：长 key 的掩码不会在列表里撑出横向溢出（WKWebView 不给连续
/// 圆点断行，`word-break` 拦不住），且不泄漏 key 长度。绝不返回完整 key，是回显前端的唯一形式。
pub fn mask(key: &str) -> String {
    let n = key.chars().count();
    if n == 0 {
        String::new()
    } else if n <= 4 {
        "•".repeat(n)
    } else {
        let last4: String = key.chars().skip(n - 4).collect();
        format!("••••{last4}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{symlink, FileTypeExt};

    fn tmpdir() -> PathBuf {
        // 每个测试用「进程 id + 线程 id」独立子目录，避免并行测试相互踩。
        let base = std::env::temp_dir().join(format!("csswitch-cfg-test-{}", std::process::id()));
        let d = base.join(format!("{:?}", std::thread::current().id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn mode_of(p: &Path) -> u32 {
        fs::metadata(p).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn p2a_codex_disable_receipt_cas_clear_preserves_replacement() {
        let dir = tmpdir().join(".csswitch-p2a-receipt");
        let cfg = Config {
            experimental_codex_enabled: true,
            proxy_port: 18000,
            sandbox_port: 18765,
            ..Default::default()
        };
        save_to(&dir, &cfg).unwrap();
        let mut after = cfg.clone();
        after.experimental_codex_enabled = false;
        let fence = CodexDisableOperationFence::new(
            "11".repeat(16),
            "22".repeat(32),
            codex_disable_config_fingerprint(&cfg).unwrap(),
            codex_disable_config_fingerprint(&after).unwrap(),
        );
        let first = br#"{"phase":"intent"}"#;
        let second = br#"{"phase":"effects_applied"}"#;
        let replacement = br#"{"phase":"attention"}"#;
        begin_codex_disable_operation(&dir, &cfg, &fence, first).unwrap();
        assert_eq!(
            read_codex_disable_operation_receipt(&dir).unwrap(),
            Some(first.to_vec())
        );
        assert_eq!(
            mode_of(&dir.join(CODEX_DISABLE_OPERATION_RECEIPT_FILE)),
            0o600
        );
        assert!(write_codex_disable_operation_receipt_if_absent(&dir, second).is_err());

        write_codex_disable_operation_receipt(&dir, second, first).unwrap();
        write_codex_disable_operation_receipt(&dir, replacement, second).unwrap();
        assert!(clear_codex_disable_operation_receipt(
            &dir,
            second,
            &fence,
            CodexDisableTerminalConfigImage::Before,
        )
        .is_err());
        assert_eq!(
            read_codex_disable_operation_receipt(&dir).unwrap(),
            Some(replacement.to_vec()),
            "stale clear must preserve replacement bytes"
        );

        {
            let (secure, _fence) = open_config_writer(&dir, false).unwrap();
            secure
                .rename(
                    CODEX_DISABLE_OPERATION_RECEIPT_FILE,
                    CODEX_DISABLE_OPERATION_RECEIPT_CLEARING_FILE,
                )
                .unwrap();
            secure.sync().unwrap();
        }
        assert!(!dir.join(CODEX_DISABLE_OPERATION_RECEIPT_FILE).exists());
        assert!(dir
            .join(CODEX_DISABLE_OPERATION_RECEIPT_CLEARING_FILE)
            .exists());
        assert_eq!(
            read_codex_disable_operation_receipt(&dir).unwrap(),
            Some(replacement.to_vec()),
            "an interrupted clear must resurrect the exact receipt"
        );
        assert!(dir.join(CODEX_DISABLE_OPERATION_RECEIPT_FILE).exists());
        assert!(!dir
            .join(CODEX_DISABLE_OPERATION_RECEIPT_CLEARING_FILE)
            .exists());

        clear_codex_disable_operation_receipt(
            &dir,
            replacement,
            &fence,
            CodexDisableTerminalConfigImage::Before,
        )
        .unwrap();
        assert!(read_codex_disable_operation_receipt(&dir)
            .unwrap()
            .is_none());
        assert!(!fs::read_dir(&dir).unwrap().flatten().any(|entry| entry
            .file_name()
            .to_string_lossy()
            .contains(CODEX_DISABLE_OPERATION_RECEIPT_FILE)));
        clear_codex_disable_operation_fence(&dir, &fence, CodexDisableTerminalConfigImage::Before)
            .unwrap();
    }

    #[test]
    fn p2a_codex_disable_config_fence_blocks_siblings_and_recovers_orphans() {
        let dir = tmpdir().join(".csswitch-p2a-fence");
        let cfg = Config {
            experimental_codex_enabled: true,
            proxy_port: 18000,
            sandbox_port: 18765,
            ..Default::default()
        };
        save_to(&dir, &cfg).unwrap();
        let mut after = cfg.clone();
        after.experimental_codex_enabled = false;
        let fence = CodexDisableOperationFence::new(
            "11".repeat(16),
            "22".repeat(32),
            codex_disable_config_fingerprint(&cfg).unwrap(),
            codex_disable_config_fingerprint(&after).unwrap(),
        );

        let mut fence_only = cfg.clone();
        fence_only.set_codex_disable_operation_fence(&fence);
        save_to(&dir, &fence_only).unwrap();
        assert_eq!(
            recover_orphan_codex_disable_operation_fence(&dir).unwrap(),
            CodexDisableOrphanFenceRecovery::Cleared
        );
        assert_eq!(
            recover_orphan_codex_disable_operation_fence(&dir).unwrap(),
            CodexDisableOrphanFenceRecovery::None
        );
        assert_eq!(load_from(&dir).unwrap(), cfg);

        let receipt = br#"{"schema_version":1,"phase":"intent"}"#;
        begin_codex_disable_operation(&dir, &cfg, &fence, receipt).unwrap();
        let fenced = load_from(&dir).unwrap();
        assert_eq!(
            fenced.codex_disable_operation_fence().unwrap(),
            Some(fence.clone())
        );
        assert!(require_no_runtime_transaction(&fenced)
            .unwrap_err()
            .contains("codex_disable_operation_in_progress"));
        assert!(update(&dir, |current| current.mode = "official".into()).is_err());
        assert_eq!(load_from(&dir).unwrap(), fenced);

        clear_codex_disable_operation_receipt(
            &dir,
            receipt,
            &fence,
            CodexDisableTerminalConfigImage::Before,
        )
        .unwrap();
        let mut drifted = load_from(&dir).unwrap();
        drifted.reuse_system_ssh = true;
        test_save_to_without_history_authority_guard(&dir, &drifted).unwrap();
        for _ in 0..2 {
            assert_eq!(
                recover_orphan_codex_disable_operation_fence(&dir).unwrap(),
                CodexDisableOrphanFenceRecovery::ConfigDrift,
                "receipt-free terminal drift must retain the self-describing fence"
            );
            assert_eq!(
                load_from(&dir)
                    .unwrap()
                    .codex_disable_operation_fence()
                    .unwrap(),
                Some(fence.clone())
            );
        }
        let mut exact = load_from(&dir).unwrap();
        exact.reuse_system_ssh = false;
        test_save_to_without_history_authority_guard(&dir, &exact).unwrap();
        assert_eq!(
            recover_orphan_codex_disable_operation_fence(&dir).unwrap(),
            CodexDisableOrphanFenceRecovery::Cleared
        );
        assert_eq!(
            recover_orphan_codex_disable_operation_fence(&dir).unwrap(),
            CodexDisableOrphanFenceRecovery::None
        );
        assert_eq!(load_from(&dir).unwrap(), cfg);
        assert!(read_codex_disable_operation_receipt(&dir)
            .unwrap()
            .is_none());

        begin_codex_disable_operation(&dir, &cfg, &fence, receipt).unwrap();
        update_codex_disable_operation(&dir, &fence, |current| {
            current.experimental_codex_enabled = false;
            Ok(((), true))
        })
        .unwrap();
        clear_codex_disable_operation_receipt(
            &dir,
            receipt,
            &fence,
            CodexDisableTerminalConfigImage::After,
        )
        .unwrap();
        assert_eq!(
            recover_orphan_codex_disable_operation_fence(&dir).unwrap(),
            CodexDisableOrphanFenceRecovery::Cleared
        );
        assert_eq!(load_from(&dir).unwrap(), after);
    }

    fn wait_for_test_path(path: &Path) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while !path.exists() {
            assert!(
                std::time::Instant::now() < deadline,
                "timed out waiting for {}",
                path.display()
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }

    fn assert_exact_child_passed(output: std::process::Output, label: &str) {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success()
                && stdout.lines().any(|line| line == "running 1 test")
                && stdout.contains("config::tests::c1_a_config_writer_child ... ok")
                && stdout.contains("1 passed"),
            "{label} did not execute the exact config writer child:\nstdout={stdout}\nstderr={stderr}"
        );
    }

    fn assert_o1_e3_replay_child_passed(output: std::process::Output, label: &str) {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success()
                && stdout.lines().any(|line| line == "running 1 test")
                && stdout.contains("config::tests::o1_e3_replay_fence_child ... ok")
                && stdout.contains("1 passed"),
            "{label} did not execute the exact replay-fence child:\nstdout={stdout}\nstderr={stderr}"
        );
    }

    fn saved_profile(id: &str, template_id: &str, api_format: &str, upstream: &str) -> Profile {
        let (model_catalog, default_model_route_id, role_bindings) =
            crate::model_catalog::new_profile_catalog(template_id, api_format, Some(upstream))
                .unwrap();
        Profile {
            id: id.into(),
            template_id: template_id.into(),
            api_format: api_format.into(),
            model: upstream.into(),
            model_catalog,
            default_model_route_id,
            role_bindings,
            model_policy: ModelPolicy::SavedCatalog,
            ..Default::default()
        }
    }

    // ---------- A1: 结构 + 访问器 + new_id/now_ms ----------
    #[test]
    fn config_default_is_v4_empty() {
        let c = Config::default();
        assert_eq!(c.schema_version, CURRENT_SCHEMA_VERSION);
        assert_eq!(c.schema_version, 4);
        assert!(c.profiles.is_empty());
        assert_eq!(c.active_id, "");
        assert_eq!(c.proxy_port, 18991);
        assert!(!c.reuse_system_ssh);
        assert!(!c.experimental_codex_enabled);
        assert_eq!(
            c.codex_network.mode,
            csswitch_codex_network::CodexNetworkMode::Auto
        );
        assert!(c.codex_network.proxy_url.is_empty());
        assert_eq!(c.mode, "proxy");
    }

    fn valid_one_click_v2(phase: RuntimeTransactionPhase) -> RuntimeTransactionV2 {
        let environment_exposure = match phase {
            RuntimeTransactionPhase::StartScienceEnvironmentPending => {
                RuntimeEnvironmentExposure::Possible
            }
            RuntimeTransactionPhase::WaitScienceDbReverify
            | RuntimeTransactionPhase::RestartScienceAfterDbHeal
            | RuntimeTransactionPhase::VerifyScienceDbAfterRestart
            | RuntimeTransactionPhase::VerifyScienceCatalog => RuntimeEnvironmentExposure::Exposed,
            _ => RuntimeEnvironmentExposure::NotExposed,
        };
        RuntimeTransactionV2 {
            schema_version: RUNTIME_TRANSACTION_SCHEMA_VERSION_V2,
            transaction_id: "tx-v2".into(),
            operation: RuntimeTransactionOperation::OneClick,
            target_profile_id: "target-profile".into(),
            phase,
            runtime_fingerprint: Some("a".repeat(64)),
            environment_exposure,
            snapshot_ticket: Some(RuntimeSnapshotTicket {
                managed_id: ".one-click-rollback-0123456789abcdef0123456789abcdef".into(),
            }),
            previous_binding: Some(RuntimeBindingCommit {
                profile_id: "prior-profile".into(),
                route_fp: "route-fp".into(),
                catalog_fp: "catalog-fp".into(),
                binding_fp: "binding-fp".into(),
                science_adoption_attempt_id: None,
            }),
            previous_gateway: Some(GatewayRuntimeJournalIdentity {
                provider: "deepseek".into(),
                shim: "anthropic".into(),
                launch_id: "launch-id".into(),
                provider_contract_id: "deepseek-native".into(),
                provider_contract_digest: "contract-digest".into(),
                catalog_fp: "catalog-fp".into(),
            }),
            compensation: RuntimeCompensationState::NotStarted,
            gateway_stop_outcome: RuntimeGatewayStopOutcome::NotAttempted,
            prior_stop: RuntimePriorStopState::NotRequired,
            finalize: RuntimeFinalizeState::NotStarted,
        }
    }

    fn valid_history_v2(phase: RuntimeTransactionPhase) -> RuntimeTransactionV2 {
        let snapshot_ticket = matches!(
            phase,
            RuntimeTransactionPhase::AuthoritySnapshotActive
                | RuntimeTransactionPhase::HistoryCredentialWritePending
                | RuntimeTransactionPhase::HistoryAuthorityRestorePending
                | RuntimeTransactionPhase::HistoryAuthorityRestoreSucceeded
                | RuntimeTransactionPhase::HistoryCredentialPublished
        )
        .then(|| RuntimeSnapshotTicket {
            managed_id: ".one-click-rollback-fedcba9876543210fedcba9876543210".into(),
        });
        let finalize = if phase == RuntimeTransactionPhase::HistoryCredentialPublished {
            RuntimeFinalizeState::Intent {
                action: RuntimeFinalizeAction::ClearJournal,
            }
        } else {
            RuntimeFinalizeState::NotStarted
        };
        RuntimeTransactionV2 {
            schema_version: RUNTIME_TRANSACTION_SCHEMA_VERSION_V2,
            transaction_id: "history-v2".into(),
            operation: RuntimeTransactionOperation::HistoryRecovery,
            target_profile_id: "target-profile".into(),
            phase,
            runtime_fingerprint: Some("a".repeat(64)),
            environment_exposure: RuntimeEnvironmentExposure::NotExposed,
            snapshot_ticket,
            previous_binding: None,
            previous_gateway: None,
            compensation: RuntimeCompensationState::NotStarted,
            gateway_stop_outcome: RuntimeGatewayStopOutcome::NotAttempted,
            prior_stop: RuntimePriorStopState::NotRequired,
            finalize,
        }
    }

    #[test]
    fn runtime_transaction_v1_round_trip_does_not_upgrade_wire() {
        let dir = tmpdir();
        let stages = [
            "stop_old_science".to_string(),
            "start_gateway".to_string(),
            "wait_science_db_reverify".to_string(),
            "restart_science_after_db_heal".to_string(),
            "verify_science_db_after_restart".to_string(),
            "verify_science_catalog".to_string(),
            "start_formal_gateway".to_string(),
            "recover_interrupted_gateway".to_string(),
            format!(
                "{LEGACY_SCIENCE_ENVIRONMENT_PENDING_STAGE_PREFIX}{}",
                "a".repeat(64)
            ),
            format!(
                "{LEGACY_AUTHORITY_SNAPSHOT_ACTIVE_STAGE_PREFIX}{}",
                "b".repeat(64)
            ),
        ];
        for (index, stage) in stages.into_iter().enumerate() {
            let journal = RuntimeTransactionJournal {
                transaction_id: format!("legacy-tx-{index}"),
                target_profile_id: "legacy-target".into(),
                stage: stage.clone(),
                previous_binding: None,
                previous_gateway: None,
            };
            save_to(
                &dir,
                &Config {
                    runtime_transaction: Some(journal.clone().into()),
                    ..Default::default()
                },
            )
            .unwrap();
            let first: serde_json::Value =
                serde_json::from_slice(&fs::read(config_path(&dir)).unwrap()).unwrap();
            assert_eq!(first["schema_version"], CURRENT_SCHEMA_VERSION);
            assert!(first["runtime_transaction"]["schema_version"].is_null());
            assert_eq!(first["runtime_transaction"]["stage"], stage);

            let loaded = load_from(&dir).unwrap();
            assert_eq!(loaded.runtime_transaction, Some(journal.clone().into()));
            save_to(&dir, &loaded).unwrap();
            let second: serde_json::Value =
                serde_json::from_slice(&fs::read(config_path(&dir)).unwrap()).unwrap();
            assert!(second["runtime_transaction"]["schema_version"].is_null());
            assert_eq!(second["runtime_transaction"]["stage"], stage);
        }
    }

    #[test]
    fn runtime_transaction_reader_rejects_unknown_v1_and_future_v2() {
        let unknown_v1 = serde_json::json!({
            "transaction_id": "legacy-tx",
            "target_profile_id": "target",
            "stage": "unknown-stage",
            "previous_binding": null
        });
        assert!(serde_json::from_value::<RuntimeTransactionRecord>(unknown_v1).is_err());

        let malformed_environment = serde_json::json!({
            "transaction_id": "legacy-tx",
            "target_profile_id": "target",
            "stage": "start_science_environment_pending:not-a-fingerprint",
            "previous_binding": null
        });
        assert!(serde_json::from_value::<RuntimeTransactionRecord>(malformed_environment).is_err());

        for legacy_environment_stage in ["start_science", "start_science_environment_pending"] {
            let legacy_environment = serde_json::json!({
                "transaction_id": "legacy-tx",
                "target_profile_id": "target",
                "stage": legacy_environment_stage,
                "previous_binding": null
            });
            assert!(
                serde_json::from_value::<RuntimeTransactionRecord>(legacy_environment).is_err(),
                "legacy environment stage without a fingerprint must fail closed"
            );
        }

        let future = serde_json::json!({
            "schema_version": 3,
            "transaction_id": "future-tx"
        });
        assert!(serde_json::from_value::<RuntimeTransactionRecord>(future).is_err());

        let duplicate_stage = r#"{
            "transaction_id":"legacy-tx",
            "target_profile_id":"target",
            "stage":"start_gateway",
            "stage":"verify_science_catalog",
            "previous_binding":null
        }"#;
        assert!(serde_json::from_str::<RuntimeTransactionRecord>(duplicate_stage).is_err());
    }

    #[test]
    fn runtime_transaction_v2_round_trip_is_typed_and_secret_free() {
        let mut journal = RuntimeTransactionRecord::V2(valid_one_click_v2(
            RuntimeTransactionPhase::StartScienceEnvironmentPending,
        ));
        assert_eq!(
            journal.as_v2_mut().unwrap().operation,
            RuntimeTransactionOperation::OneClick
        );
        let encoded = serde_json::to_value(&journal).unwrap();
        assert_eq!(encoded["schema_version"], 2);
        assert_eq!(encoded["operation"], "one_click");
        assert_eq!(encoded["phase"], "start_science_environment_pending");
        assert_eq!(encoded["environment_exposure"], "possible");
        assert!(journal.requires_snapshot_preservation());
        assert_eq!(
            journal
                .as_v2()
                .unwrap()
                .snapshot_ticket
                .as_ref()
                .unwrap()
                .managed_id,
            ".one-click-rollback-0123456789abcdef0123456789abcdef"
        );
        let text = serde_json::to_string(&encoded).unwrap();
        for forbidden in ["api_key", "base_url", "secret", "credential", "/Users/"] {
            assert!(!text.contains(forbidden), "journal leaked `{forbidden}`");
        }
        assert_eq!(
            serde_json::from_value::<RuntimeTransactionRecord>(encoded).unwrap(),
            journal
        );

        let dir = tmpdir();
        let one_click_phases = [
            RuntimeTransactionPhase::StopOldScience,
            RuntimeTransactionPhase::StartGateway,
            RuntimeTransactionPhase::AuthoritySnapshotActive,
            RuntimeTransactionPhase::StartScienceEnvironmentPending,
            RuntimeTransactionPhase::WaitScienceDbReverify,
            RuntimeTransactionPhase::RestartScienceAfterDbHeal,
            RuntimeTransactionPhase::VerifyScienceDbAfterRestart,
            RuntimeTransactionPhase::VerifyScienceCatalog,
        ];
        let mut production_records = one_click_phases
            .into_iter()
            .map(valid_one_click_v2)
            .collect::<Vec<_>>();
        production_records.push(RuntimeTransactionV2 {
            schema_version: RUNTIME_TRANSACTION_SCHEMA_VERSION_V2,
            transaction_id: "profile-switch-start".into(),
            operation: RuntimeTransactionOperation::ProfileSwitch,
            target_profile_id: "target-profile".into(),
            phase: RuntimeTransactionPhase::StartFormalGateway,
            runtime_fingerprint: None,
            environment_exposure: RuntimeEnvironmentExposure::NotExposed,
            snapshot_ticket: None,
            previous_binding: None,
            previous_gateway: None,
            compensation: RuntimeCompensationState::NotStarted,
            gateway_stop_outcome: RuntimeGatewayStopOutcome::NotAttempted,
            prior_stop: RuntimePriorStopState::NotRequired,
            finalize: RuntimeFinalizeState::NotStarted,
        });
        for phase in [
            RuntimeTransactionPhase::StopOldScience,
            RuntimeTransactionPhase::AuthoritySnapshotActive,
            RuntimeTransactionPhase::HistoryCredentialWritePending,
            RuntimeTransactionPhase::HistoryAuthorityRestorePending,
            RuntimeTransactionPhase::HistoryAuthorityRestoreSucceeded,
            RuntimeTransactionPhase::HistoryCredentialPublished,
            RuntimeTransactionPhase::ResumeAfterHistoryRestore,
        ] {
            production_records.push(valid_history_v2(phase));
        }
        for outcome in [
            RuntimeGatewayStopOutcome::Pending,
            RuntimeGatewayStopOutcome::Stopped,
            RuntimeGatewayStopOutcome::NotManaged,
            RuntimeGatewayStopOutcome::SignalFailed,
            RuntimeGatewayStopOutcome::ExitUnconfirmed,
            RuntimeGatewayStopOutcome::AbsentAfterAttempt,
        ] {
            production_records.push(RuntimeTransactionV2 {
                schema_version: RUNTIME_TRANSACTION_SCHEMA_VERSION_V2,
                transaction_id: format!("profile-switch-recovery-{outcome:?}"),
                operation: RuntimeTransactionOperation::ProfileSwitch,
                target_profile_id: "target-profile".into(),
                phase: RuntimeTransactionPhase::RecoverInterruptedGateway,
                runtime_fingerprint: None,
                environment_exposure: RuntimeEnvironmentExposure::NotExposed,
                snapshot_ticket: None,
                previous_binding: None,
                previous_gateway: None,
                compensation: RuntimeCompensationState::NotStarted,
                gateway_stop_outcome: outcome,
                prior_stop: RuntimePriorStopState::NotRequired,
                finalize: RuntimeFinalizeState::NotStarted,
            });
        }
        for record in production_records {
            let expected = RuntimeTransactionRecord::V2(record);
            save_to(
                &dir,
                &Config {
                    runtime_transaction: Some(expected.clone()),
                    ..Default::default()
                },
            )
            .unwrap();
            let loaded = load_from(&dir).unwrap();
            assert_eq!(loaded.runtime_transaction.as_ref(), Some(&expected));
            save_to(&dir, &loaded).unwrap();
            assert_eq!(
                load_from(&dir).unwrap().runtime_transaction.as_ref(),
                Some(&expected)
            );
        }

        let legacy_compensation = RuntimeCompensationJournal {
            schema_version: RUNTIME_COMPENSATION_SCHEMA_VERSION_V1,
            compensation_id: "compensation-id".into(),
            target_profile_id: "target-profile".into(),
            runtime_fingerprint: "a".repeat(64),
            snapshot_ticket: RuntimeSnapshotTicket::verified(
                ".one-click-rollback-0123456789abcdef0123456789abcdef".into(),
            )
            .unwrap(),
            state: RuntimeCompensationState::InProgress,
            steps: Vec::new(),
            science_adoption_attempt_ids: Vec::new(),
        };
        let mut prior_business = valid_one_click_v2(RuntimeTransactionPhase::StartGateway);
        prior_business.prior_stop = RuntimePriorStopState::Outcome {
            recipe: RuntimePriorScienceRecipe {
                port: 8766,
                runtime_path: PathBuf::from("/Users/private/Claude Science"),
                runtime_source: "managed".into(),
                runtime_version: Some("1.0".into()),
                runtime_fingerprint: "b".repeat(64),
                runtime_adoption_attempt_id: None,
                launch_receipt_digest: "c".repeat(64),
            },
            outcome: RuntimePriorStopOutcome::ExactStopped,
        };
        let prior_transaction = RuntimeTransactionRecord::V2(prior_business);
        let legacy_config = Config {
            runtime_transaction: Some(prior_transaction.clone()),
            runtime_compensation: Some(legacy_compensation.clone()),
            ..Default::default()
        };
        save_to(&dir, &legacy_config).unwrap();
        assert_eq!(
            load_from(&dir).unwrap().runtime_compensation.as_ref(),
            Some(&legacy_compensation)
        );
        let compensation = RuntimeCompensationJournal {
            schema_version: RUNTIME_COMPENSATION_SCHEMA_VERSION_V2,
            compensation_id: "stepwise-compensation-id".into(),
            target_profile_id: "target-profile".into(),
            runtime_fingerprint: "a".repeat(64),
            snapshot_ticket: RuntimeSnapshotTicket::verified(
                ".one-click-rollback-0123456789abcdef0123456789abcdef".into(),
            )
            .unwrap(),
            state: RuntimeCompensationState::InProgress,
            steps: pending_one_click_compensation_steps(),
            science_adoption_attempt_ids: Vec::new(),
        };
        let config_with_compensation = Config {
            runtime_transaction: Some(prior_transaction.clone()),
            runtime_compensation: Some(compensation.clone()),
            ..Default::default()
        };
        save_to(&dir, &config_with_compensation).unwrap();
        let loaded = load_from(&dir).unwrap();
        assert_eq!(
            loaded.runtime_transaction.as_ref(),
            Some(&prior_transaction)
        );
        assert_eq!(loaded.runtime_compensation.as_ref(), Some(&compensation));
        assert!(loaded.has_open_runtime_journal());
        let compensation_only = Config {
            runtime_transaction: None,
            ..loaded.clone()
        };
        assert!(compensation_only.has_open_runtime_journal());
        assert!(require_no_runtime_transaction(&compensation_only).is_err());
        let wire = fs::read_to_string(config_path(&dir)).unwrap();
        assert!(wire.contains("\"runtime_compensation\""));
        let compensation_wire = serde_json::to_string(
            serde_json::from_str::<serde_json::Value>(&wire).unwrap()["runtime_compensation"]
                .as_object()
                .unwrap(),
        )
        .unwrap();
        for forbidden in [
            "api_key",
            "base_url",
            "credential",
            "runtime_path",
            "prior_stop",
            "message",
            "/Users/",
        ] {
            assert!(
                !compensation_wire.contains(forbidden),
                "compensation journal leaked `{forbidden}`: {compensation_wire}"
            );
        }
    }

    #[test]
    fn runtime_transaction_v2_rejects_illegal_state_and_unknown_fields() {
        let mut wrong_exposure = serde_json::to_value(RuntimeTransactionRecord::V2(
            valid_one_click_v2(RuntimeTransactionPhase::VerifyScienceCatalog),
        ))
        .unwrap();
        wrong_exposure["environment_exposure"] = serde_json::json!("not_exposed");
        assert!(serde_json::from_value::<RuntimeTransactionRecord>(wrong_exposure).is_err());

        let mut missing_ticket = serde_json::to_value(RuntimeTransactionRecord::V2(
            valid_one_click_v2(RuntimeTransactionPhase::StartGateway),
        ))
        .unwrap();
        missing_ticket
            .as_object_mut()
            .unwrap()
            .remove("snapshot_ticket");
        assert!(serde_json::from_value::<RuntimeTransactionRecord>(missing_ticket).is_err());

        let mut path_ticket = serde_json::to_value(RuntimeTransactionRecord::V2(
            valid_one_click_v2(RuntimeTransactionPhase::StartGateway),
        ))
        .unwrap();
        path_ticket["snapshot_ticket"]["managed_id"] =
            serde_json::json!("/Users/example/private-snapshot");
        assert!(serde_json::from_value::<RuntimeTransactionRecord>(path_ticket).is_err());

        let mut unknown_field = serde_json::to_value(RuntimeTransactionRecord::V2(
            valid_one_click_v2(RuntimeTransactionPhase::StartGateway),
        ))
        .unwrap();
        unknown_field["message"] = serde_json::json!("must not be persisted");
        assert!(serde_json::from_value::<RuntimeTransactionRecord>(unknown_field).is_err());

        let one_click_gateway_recovery = RuntimeTransactionRecord::V2(valid_one_click_v2(
            RuntimeTransactionPhase::RecoverInterruptedGateway,
        ));
        assert!(serde_json::from_value::<RuntimeTransactionRecord>(
            serde_json::to_value(one_click_gateway_recovery).unwrap()
        )
        .is_err());

        for history_only_phase in [
            RuntimeTransactionPhase::HistoryCredentialWritePending,
            RuntimeTransactionPhase::HistoryAuthorityRestorePending,
            RuntimeTransactionPhase::HistoryAuthorityRestoreSucceeded,
            RuntimeTransactionPhase::HistoryCredentialPublished,
            RuntimeTransactionPhase::ResumeAfterHistoryRestore,
        ] {
            let illegal = RuntimeTransactionRecord::V2(valid_one_click_v2(history_only_phase));
            assert!(
                serde_json::from_value::<RuntimeTransactionRecord>(
                    serde_json::to_value(illegal).unwrap()
                )
                .is_err(),
                "one-click must reject history-only phase {history_only_phase:?}"
            );
        }

        let mut one_click_resume =
            valid_one_click_v2(RuntimeTransactionPhase::VerifyScienceCatalog);
        one_click_resume.finalize = RuntimeFinalizeState::Intent {
            action: RuntimeFinalizeAction::ResumeOneClick,
        };
        assert!(serde_json::from_value::<RuntimeTransactionRecord>(
            serde_json::to_value(RuntimeTransactionRecord::V2(one_click_resume)).unwrap()
        )
        .is_err());

        let mut mismatched_adoption =
            valid_one_click_v2(RuntimeTransactionPhase::VerifyScienceCatalog);
        mismatched_adoption.finalize = RuntimeFinalizeState::Intent {
            action: RuntimeFinalizeAction::CommitBinding {
                binding: RuntimeBindingCommit {
                    profile_id: mismatched_adoption.target_profile_id.clone(),
                    route_fp: "route-fp".into(),
                    catalog_fp: "catalog-fp".into(),
                    binding_fp: "binding-fp".into(),
                    science_adoption_attempt_id: None,
                },
                science_adoption_attempt_id: Some("a".repeat(32)),
            },
        };
        assert!(serde_json::from_value::<RuntimeTransactionRecord>(
            serde_json::to_value(RuntimeTransactionRecord::V2(mismatched_adoption)).unwrap()
        )
        .is_err());

        for failed_steps in [
            serde_json::json!([]),
            serde_json::json!(["ssh_cleanup", "ssh_cleanup"]),
        ] {
            let mut illegal_compensation = serde_json::to_value(RuntimeTransactionRecord::V2(
                valid_one_click_v2(RuntimeTransactionPhase::AuthoritySnapshotActive),
            ))
            .unwrap();
            illegal_compensation["compensation"] = serde_json::json!({
                "state": "incomplete",
                "failed_steps": failed_steps
            });
            assert!(
                serde_json::from_value::<RuntimeTransactionRecord>(illegal_compensation).is_err(),
                "incomplete compensation must have unique failed steps"
            );
        }

        let mut history_resume_with_snapshot = serde_json::to_value(RuntimeTransactionRecord::V2(
            valid_history_v2(RuntimeTransactionPhase::ResumeAfterHistoryRestore),
        ))
        .unwrap();
        history_resume_with_snapshot["snapshot_ticket"] = serde_json::json!({
            "managed_id": ".one-click-rollback-fedcba9876543210fedcba9876543210"
        });
        assert!(
            serde_json::from_value::<RuntimeTransactionRecord>(history_resume_with_snapshot)
                .is_err()
        );

        let mut history_without_config_authority =
            serde_json::to_value(RuntimeTransactionRecord::V2(valid_history_v2(
                RuntimeTransactionPhase::HistoryCredentialPublished,
            )))
            .unwrap();
        history_without_config_authority
            .as_object_mut()
            .unwrap()
            .remove("runtime_fingerprint");
        assert!(serde_json::from_value::<RuntimeTransactionRecord>(
            history_without_config_authority
        )
        .is_err());

        let dir = tmpdir();
        let invalid_compensation_owner = Config {
            runtime_compensation: Some(RuntimeCompensationJournal {
                schema_version: RUNTIME_COMPENSATION_SCHEMA_VERSION_V1,
                compensation_id: "invalid".into(),
                target_profile_id: "target-profile".into(),
                runtime_fingerprint: "a".repeat(64),
                snapshot_ticket: RuntimeSnapshotTicket::verified(
                    ".one-click-rollback-0123456789abcdef0123456789abcdef".into(),
                )
                .unwrap(),
                state: RuntimeCompensationState::NotStarted,
                steps: Vec::new(),
                science_adoption_attempt_ids: Vec::new(),
            }),
            ..Default::default()
        };
        assert!(save_to(&dir, &invalid_compensation_owner).is_err());

        let mut invalid_step_order = pending_one_click_compensation_steps();
        invalid_step_order.swap(0, 1);
        let invalid_stepwise_compensation = Config {
            runtime_compensation: Some(RuntimeCompensationJournal {
                schema_version: RUNTIME_COMPENSATION_SCHEMA_VERSION_V2,
                compensation_id: "invalid-step-order".into(),
                target_profile_id: "target-profile".into(),
                runtime_fingerprint: "a".repeat(64),
                snapshot_ticket: RuntimeSnapshotTicket::verified(
                    ".one-click-rollback-0123456789abcdef0123456789abcdef".into(),
                )
                .unwrap(),
                state: RuntimeCompensationState::InProgress,
                steps: invalid_step_order,
                science_adoption_attempt_ids: Vec::new(),
            }),
            ..Default::default()
        };
        assert!(save_to(&dir, &invalid_stepwise_compensation).is_err());

        for (field, value) in [
            (
                "compensation",
                serde_json::json!({"state": "in_progress", "step": "stop_gateway"}),
            ),
            (
                "previous_gateway",
                serde_json::json!({
                    "provider": "deepseek",
                    "shim": "anthropic",
                    "launch_id": "launch-id",
                    "provider_contract_id": "deepseek-native",
                    "provider_contract_digest": "contract-digest",
                    "catalog_fp": "catalog-fp"
                }),
            ),
        ] {
            let mut illegal_terminal = serde_json::to_value(RuntimeTransactionRecord::V2(
                valid_history_v2(RuntimeTransactionPhase::ResumeAfterHistoryRestore),
            ))
            .unwrap();
            illegal_terminal[field] = value;
            assert!(
                serde_json::from_value::<RuntimeTransactionRecord>(illegal_terminal).is_err(),
                "history terminal must reject sibling-owned {field}"
            );
        }

        let mut history_commit_without_finalize =
            serde_json::to_value(RuntimeTransactionRecord::V2(valid_history_v2(
                RuntimeTransactionPhase::HistoryCredentialPublished,
            )))
            .unwrap();
        history_commit_without_finalize["finalize"] = serde_json::json!({"state": "not_started"});
        assert!(serde_json::from_value::<RuntimeTransactionRecord>(
            history_commit_without_finalize
        )
        .is_err());
    }

    #[test]
    fn default_dir_is_compile_time_isolated_by_build_variant() {
        let home = Path::new("/tmp/csswitch-home-contract");
        let got = default_dir_from_home(home);
        #[cfg(feature = "acceptance-build")]
        assert_eq!(got, home.join(".csswitch-acceptance"));
        #[cfg(not(feature = "acceptance-build"))]
        assert_eq!(got, home.join(".csswitch"));
    }

    #[test]
    fn experimental_codex_gate_is_default_off_and_provider_scoped() {
        let mut cfg = Config::default();
        assert!(super::require_template_enabled(&cfg, "codex").is_err());
        assert!(super::require_template_enabled(&cfg, "deepseek").is_ok());
        cfg.experimental_codex_enabled = true;
        assert!(super::require_template_enabled(&cfg, "codex").is_ok());
    }

    #[test]
    fn existing_v3_without_experimental_codex_flag_loads_disabled() {
        let d = tmpdir();
        fs::write(
            d.join("config.json"),
            br#"{"schema_version":3,"profiles":[],"active_id":"","proxy_port":18991,"sandbox_port":18765,"reuse_system_ssh":false,"secret":"","mode":"proxy","pending_notice":null}"#,
        )
        .unwrap();
        fs::set_permissions(d.join("config.json"), fs::Permissions::from_mode(0o600)).unwrap();

        let cfg = load_from(&d).unwrap();
        assert_eq!(cfg.schema_version, CURRENT_SCHEMA_VERSION);
        assert!(!cfg.experimental_codex_enabled);
        assert_eq!(
            cfg.codex_network,
            csswitch_codex_network::CodexNetworkSettings::default()
        );
    }

    #[test]
    fn profile_accessors_by_id_and_active() {
        let p = Profile {
            id: "abc".into(),
            name: "DS".into(),
            template_id: "deepseek".into(),
            category: "cn_official".into(),
            api_format: "anthropic".into(),
            base_url: "https://api.deepseek.com/anthropic".into(),
            api_key: "sk-1".into(),
            model: String::new(),
            ..Default::default()
        };
        let c = Config {
            profiles: vec![p.clone()],
            active_id: "abc".into(),
            ..Default::default()
        };
        assert_eq!(c.profile_by_id("abc").unwrap().name, "DS");
        assert!(c.profile_by_id("nope").is_none());
        assert_eq!(c.active_profile().unwrap().id, "abc");
        let c2 = Config {
            active_id: "".into(),
            ..c.clone()
        };
        assert!(c2.active_profile().is_none());
    }

    #[test]
    fn v3_empty_static_profile_is_preserved_incomplete_and_deactivated() {
        let v3 = crate::config_legacy::ConfigV3 {
            profiles: vec![crate::config_legacy::ProfileV3 {
                id: "p1".into(),
                name: "我的 GLM".into(),
                template_id: "glm".into(),
                category: "cn_official".into(),
                api_format: "anthropic".into(),
                model_policy: crate::config_legacy::ModelPolicyV3::RequiredFixed,
                ..Default::default()
            }],
            active_id: "p1".into(),
            schema_version: 3,
            ..crate::config_legacy::ConfigV3::default()
        };
        let cfg = migrate_v3_to_v4(v3).unwrap();
        assert!(cfg.profiles[0].model_catalog.is_empty());
        assert!(cfg.active_id.is_empty());
        assert!(cfg.pending_notice.unwrap().contains("取消激活"));
    }

    #[test]
    fn new_id_is_unique_hex_and_now_ms_positive() {
        let a = new_id();
        let b = new_id();
        assert_ne!(a, b);
        assert_eq!(a.len(), 32);
        assert!(a.chars().all(|ch| ch.is_ascii_hexdigit()));
        assert!(now_ms() > 0);
    }

    #[test]
    fn save_then_load_roundtrips() {
        let d = tmpdir().join(".csswitch");
        let p = Profile {
            name: "DeepSeek".into(),
            category: "cn_official".into(),
            base_url: "https://api.deepseek.com/anthropic".into(),
            api_key: "sk-abcdef1234".into(),
            ..saved_profile("id1", "deepseek", "anthropic", "deepseek-v4-pro")
        };
        let cfg = Config {
            profiles: vec![p],
            active_id: "id1".into(),
            proxy_port: 12345,
            runtime_binding: Some(RuntimeBindingCommit {
                profile_id: "id1".into(),
                route_fp: "route-fp".into(),
                catalog_fp: "catalog-fp".into(),
                binding_fp: "binding-fp".into(),
                science_adoption_attempt_id: Some("a".repeat(32)),
            }),
            ..Default::default()
        };
        save_to(&d, &cfg).unwrap();
        let got = load_from(&d).unwrap();
        assert_eq!(got, cfg);
        assert_eq!(got.active_profile().unwrap().api_key, "sk-abcdef1234");
        let mut invalid = cfg.clone();
        invalid
            .runtime_binding
            .as_mut()
            .unwrap()
            .science_adoption_attempt_id = Some("A".repeat(32));
        assert!(save_to(&d, &invalid).is_err());
        assert_eq!(load_from(&d).unwrap(), cfg);
    }

    #[test]
    fn load_rejects_invalid_runtime_ports() {
        let cases = [
            ("proxy_8765", 8765, 8990),
            ("sandbox_8765", 18991, 8765),
            ("proxy_zero", 0, 8990),
            ("sandbox_zero", 18991, 0),
            ("same_ports", 18991, 18991),
        ];
        for (name, proxy_port, sandbox_port) in cases {
            let d = tmpdir().join(format!(".csswitch-{name}"));
            fs::create_dir_all(&d).unwrap();
            fs::write(
                config_path(&d),
                format!(
                    r#"{{"schema_version":2,"profiles":[],"active_id":"","proxy_port":{proxy_port},"sandbox_port":{sandbox_port}}}"#
                ),
            )
            .unwrap();
            let err = load_from(&d).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidData, "{name}");
            assert!(
                err.to_string().contains("config.json 端口无效"),
                "error should identify invalid config ports for {name}: {err}"
            );
        }
    }

    #[test]
    fn load_rejects_legacy_invalid_ports_before_v2_save() {
        let d = tmpdir().join(".csswitch-legacy-bad-port");
        fs::create_dir_all(&d).unwrap();
        let legacy = r#"{
            "provider":"deepseek",
            "proxy_port":18991,
            "sandbox_port":8765,
            "secret":"sec",
            "mode":"proxy",
            "providers":{"deepseek":{"key":"sk-ds","base_url":"","model":""}}
        }"#;
        fs::write(config_path(&d), legacy).unwrap();
        let err = load_from(&d).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        let after = fs::read_to_string(config_path(&d)).unwrap();
        assert!(
            !after.contains("\"schema_version\""),
            "invalid legacy config should not be saved as v2: {after}"
        );
        assert!(
            !d.join("config.json.v1.bak").exists(),
            "旧配置未通过完整校验时不得发布迁移备份"
        );
    }

    // ---------- A2: 版本探测 ----------
    #[test]
    fn detect_version_missing_field_is_legacy() {
        let d = br#"{"provider":"deepseek","providers":{}}"#;
        assert!(matches!(detect_version(d).unwrap(), VersionKind::Legacy));
    }
    #[test]
    fn detect_version_two_is_v2() {
        let d = br#"{"schema_version":2,"profiles":[],"active_id":""}"#;
        assert!(matches!(detect_version(d).unwrap(), VersionKind::V2));
    }
    #[test]
    fn detect_version_three_is_v3() {
        let d = br#"{"schema_version":3}"#;
        assert!(matches!(detect_version(d).unwrap(), VersionKind::V3));
    }
    #[test]
    fn detect_version_four_is_v4() {
        let d = br#"{"schema_version":4}"#;
        assert!(matches!(detect_version(d).unwrap(), VersionKind::V4));
    }
    #[test]
    fn detect_version_garbage_errors() {
        assert!(detect_version(b"not json").is_err());
    }

    // ---------- A4: 迁移 v1 → v2 ----------
    #[test]
    fn migrate_maps_slots_to_profiles_and_active() {
        use crate::config_legacy::{ConfigV1, ProviderCfgV1};
        let mut providers = std::collections::BTreeMap::new();
        providers.insert(
            "deepseek".to_string(),
            ProviderCfgV1 {
                key: "sk-ds".into(),
                base_url: "".into(),
                model: "".into(),
            },
        );
        providers.insert(
            "relay-glm".to_string(),
            ProviderCfgV1 {
                key: "glmk".into(),
                base_url: "https://open.bigmodel.cn/api/anthropic".into(),
                model: "glm-5".into(),
            },
        );
        providers.insert(
            "qwen".to_string(),
            ProviderCfgV1 {
                key: "".into(),
                base_url: "".into(),
                model: "".into(),
            },
        ); // 空槽
        let legacy = ConfigV1 {
            provider: "relay-glm".into(),
            proxy_port: 18991,
            sandbox_port: 8990,
            secret: "sec".into(),
            mode: "proxy".into(),
            providers,
        };
        let cfg = migrate_v1_to_v2(legacy);
        assert_eq!(cfg.schema_version, 2);
        assert_eq!(cfg.profiles.len(), 2, "空 qwen 槽跳过");
        let glm = cfg
            .profiles
            .iter()
            .find(|p| p.template_id == "glm")
            .unwrap();
        assert_eq!(glm.api_key, "glmk");
        assert_eq!(glm.base_url, "https://open.bigmodel.cn/api/anthropic");
        assert_eq!(glm.model, "glm-5");
        assert_eq!(glm.api_format, "anthropic");
        assert_eq!(
            cfg.active_id, glm.id,
            "旧 provider=relay-glm → 生效指该 profile"
        );
        assert_eq!(cfg.secret, "sec");
    }

    #[test]
    fn migrate_invalid_active_yields_empty() {
        use crate::config_legacy::{ConfigV1, ProviderCfgV1};
        let mut providers = std::collections::BTreeMap::new();
        providers.insert(
            "deepseek".to_string(),
            ProviderCfgV1 {
                key: "k".into(),
                base_url: "".into(),
                model: "".into(),
            },
        );
        // 旧 provider 指向空/不存在的槽 → active_id 必须为空（不静默选第一条）。
        let legacy = ConfigV1 {
            provider: "qwen".into(),
            proxy_port: 18991,
            sandbox_port: 8990,
            secret: "".into(),
            mode: "proxy".into(),
            providers,
        };
        let cfg = migrate_v1_to_v2(legacy);
        assert_eq!(cfg.profiles.len(), 1);
        assert_eq!(cfg.active_id, "", "非法 active → 空，等用户选");
    }

    #[test]
    fn migrate_legacy_bare_relay_slot() {
        use crate::config_legacy::{ConfigV1, ProviderCfgV1};
        let mut providers = std::collections::BTreeMap::new();
        providers.insert(
            "relay".to_string(),
            ProviderCfgV1 {
                key: "rk".into(),
                base_url: "https://open.bigmodel.cn/api/anthropic".into(),
                model: "".into(),
            },
        );
        let legacy = ConfigV1 {
            provider: "relay".into(),
            proxy_port: 18991,
            sandbox_port: 8990,
            secret: "".into(),
            mode: "proxy".into(),
            providers,
        };
        let cfg = migrate_v1_to_v2(legacy);
        let glm = cfg
            .profiles
            .iter()
            .find(|p| p.template_id == "glm")
            .unwrap();
        assert_eq!(glm.api_key, "rk");
        assert_eq!(cfg.active_id, glm.id);
    }

    // ---------- A5: 备份基础设施 ----------
    #[test]
    fn migration_backup_copies_and_is_0600() {
        let d = tmpdir().join(".csswitch");
        fs::create_dir_all(&d).unwrap();
        fs::write(config_path(&d), b"OLD-V1-BYTES").unwrap();
        write_migration_backup(&d).unwrap();
        let bak = d.join("config.json.v1.bak");
        assert_eq!(fs::read(&bak).unwrap(), b"OLD-V1-BYTES");
        assert_eq!(mode_of(&bak), 0o600);
    }
    #[test]
    fn migration_backup_missing_source_errors() {
        let d = tmpdir().join(".csswitch");
        fs::create_dir_all(&d).unwrap();
        assert!(write_migration_backup(&d).is_err());
    }
    #[test]
    fn rolling_backup_then_drop_removes_key_recoverability() {
        let d = tmpdir().join(".csswitch");
        fs::create_dir_all(&d).unwrap();
        fs::write(config_path(&d), br#"{"api_key":"sk-SECRET-TAIL"}"#).unwrap();
        write_rolling_backup(&d).unwrap();
        let bak = d.join("config.json.bak");
        assert!(fs::read_to_string(&bak).unwrap().contains("sk-SECRET-TAIL"));
        drop_rolling_backup(&d).unwrap();
        assert!(
            !bak.exists(),
            "净化后滚动备份应删除，清了的 key 不可从 .bak 恢复"
        );
    }
    #[test]
    fn backup_rejects_symlinked_target() {
        let base = tmpdir();
        let d = base.join(".csswitch");
        fs::create_dir_all(&d).unwrap();
        fs::write(config_path(&d), b"X").unwrap();
        let elsewhere = base.join("elsewhere");
        fs::write(&elsewhere, b"ORIG").unwrap();
        symlink(&elsewhere, d.join("config.json.v1.bak")).unwrap();
        assert!(write_migration_backup(&d).is_err());
        assert_eq!(fs::read(&elsewhere).unwrap(), b"ORIG");
    }

    // ---------- A6: load_from 整合 ----------
    #[test]
    fn load_migrates_old_file_and_writes_v1_bak() {
        let d = tmpdir().join(".csswitch");
        fs::create_dir_all(&d).unwrap();
        fs::write(
            config_path(&d),
            br#"{"provider":"deepseek","providers":{"deepseek":{"key":"sk-x"}}}"#,
        )
        .unwrap();
        let cfg = load_from(&d).unwrap();
        assert_eq!(cfg.schema_version, 4);
        assert_eq!(cfg.profiles.len(), 1);
        assert_eq!(cfg.active_profile().unwrap().api_key, "sk-x");
        assert!(d.join("config.json.v1.bak").exists(), "迁移必须留 v1 备份");
        assert!(
            d.join("config.json.v2.bak").exists(),
            "迁移必须留 canonical v2 备份"
        );
        // 落盘后再读是 v4（幂等，不再迁移）。
        let again = load_from(&d).unwrap();
        assert_eq!(again, cfg);
        assert_eq!(again.schema_version, 4);
    }

    #[test]
    fn r0_startup_migration_is_single_commit_with_backup() {
        let d = tmpdir().join(".csswitch-r0-g-migration");
        fs::create_dir_all(&d).unwrap();
        let original = br#"{"schema_version":2,"profiles":[],"active_id":"","proxy_port":18991,"sandbox_port":8990,"reuse_system_ssh":false,"secret":"","mode":"proxy","pending_notice":null}"#;
        fs::write(config_path(&d), original).unwrap();

        let guard = test_arm_migration_commit_failure(d.clone());
        let error = load_from(&d).unwrap_err();
        assert!(error.to_string().contains("after backup before v4 commit"));
        assert_eq!(fs::read(config_path(&d)).unwrap(), original);
        let backup = fs::read(d.join("config.json.v2.bak")).unwrap();
        assert!(!backup.is_empty());
        assert!(!fs::read_dir(&d).unwrap().flatten().any(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .starts_with(".config.json.tmp-")
        }));

        drop(guard);
        let migrated = load_from(&d).unwrap();
        assert_eq!(migrated.schema_version, 4);
        assert_eq!(fs::read(d.join("config.json.v2.bak")).unwrap(), backup);
        let published: serde_json::Value =
            serde_json::from_slice(&fs::read(config_path(&d)).unwrap()).unwrap();
        assert_eq!(published["schema_version"], 4);
        assert_eq!(load_from(&d).unwrap(), migrated);
    }
    #[test]
    fn load_too_new_errors() {
        let d = tmpdir().join(".csswitch");
        fs::create_dir_all(&d).unwrap();
        fs::write(config_path(&d), br#"{"schema_version":9,"profiles":[]}"#).unwrap();
        let e = load_from(&d).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidData);
        assert!(e.to_string().contains("更新版本"));
    }
    #[test]
    fn load_normalizes_dangling_active() {
        let d = tmpdir().join(".csswitch");
        let cfg = Config {
            active_id: "ghost".into(),
            profiles: vec![Profile {
                id: "real".into(),
                template_id: "deepseek".into(),
                api_format: "anthropic".into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        fs::create_dir_all(&d).unwrap();
        fs::write(config_path(&d), serde_json::to_vec_pretty(&cfg).unwrap()).unwrap();
        let got = load_from(&d).unwrap();
        assert_eq!(got.active_id, "", "悬空 active → 归一化为空");
    }

    // ---------- MP-2 Minor [2]: template_id 未命中 → 归一 custom ----------
    #[test]
    fn load_normalizes_unknown_template_id_to_custom() {
        let d = tmpdir().join(".csswitch");
        let (model_catalog, default_model_route_id, role_bindings) =
            crate::model_catalog::single_route_catalog(
                "custom-anthropic",
                "relay-model-v1",
                None,
                None,
            )
            .unwrap();
        // 造一条 template_id 未命中注册表的 v2 profile（连接字段保留）。
        let cfg = Config {
            active_id: "p1".into(),
            profiles: vec![Profile {
                id: "p1".into(),
                name: "野模板".into(),
                template_id: "totally-unknown-xyz".into(),
                api_format: "anthropic".into(),
                base_url: "https://relay.example/claude".into(),
                api_key: "sk-x".into(),
                model: "relay-model-v1".into(),
                model_catalog,
                default_model_route_id,
                role_bindings,
                model_policy: ModelPolicy::SavedCatalog,
                ..Default::default()
            }],
            ..Default::default()
        };
        fs::create_dir_all(&d).unwrap();
        fs::write(config_path(&d), serde_json::to_vec_pretty(&cfg).unwrap()).unwrap();
        let got = load_from(&d).unwrap();
        let p = got.profile_by_id("p1").unwrap();
        assert_eq!(p.template_id, "custom", "未命中 template_id → 归一 custom");
        assert_eq!(p.base_url, "https://relay.example/claude", "连接字段保留");
        assert_eq!(p.api_key, "sk-x");
        assert_eq!(got.active_id, "p1", "active 仍有效，不被清空");
    }

    // ---------- 既有安全/权限不变量（保留） ----------
    #[test]
    fn load_missing_returns_default() {
        let d = tmpdir().join(".csswitch");
        let cfg = load_from(&d).unwrap();
        assert_eq!(cfg, Config::default());
        assert_eq!(cfg.schema_version, 4);
        assert_eq!(cfg.proxy_port, 18991);
    }

    #[test]
    fn save_sets_dir_0700_and_file_0600() {
        let d = tmpdir().join(".csswitch");
        save_to(&d, &Config::default()).unwrap();
        assert_eq!(mode_of(&d), 0o700, "dir must be 0700");
        assert_eq!(mode_of(&config_path(&d)), 0o600, "file must be 0600");
        assert_eq!(
            mode_of(&d.join(CONFIG_WRITER_LOCK_FILE)),
            0o600,
            "writer fence must be private"
        );
    }

    #[test]
    fn c1_a_config_writer_child() {
        let Some(role) = std::env::var_os("CSSWITCH_C1A_WRITER_ROLE") else {
            return;
        };
        let root = PathBuf::from(std::env::var_os("CSSWITCH_C1A_WRITER_ROOT").unwrap());
        let dir = root.join("config");
        match role.to_string_lossy().as_ref() {
            "a" => {
                update(&dir, |cfg| {
                    cfg.secret = "writer-a".into();
                    fs::write(root.join("a-loaded"), b"ready").unwrap();
                    wait_for_test_path(&root.join("release-a"));
                })
                .unwrap();
                fs::write(root.join("a-committed"), b"done").unwrap();
            }
            "b" => {
                update(&dir, |cfg| {
                    fs::write(root.join("b-entered-update"), b"entered").unwrap();
                    cfg.reuse_system_ssh = true;
                })
                .unwrap();
                fs::write(root.join("b-committed"), b"done").unwrap();
            }
            "replace-b" => {
                let error = update(&dir, |cfg| cfg.reuse_system_ssh = true).unwrap_err();
                assert!(error
                    .to_string()
                    .contains("config writer lock 在获取期间被替换"));
                fs::write(root.join("b-rejected-replacement"), b"rejected").unwrap();
            }
            other => panic!("unexpected writer role {other}"),
        }
    }

    #[test]
    fn c1_a_cross_process_writer_fence_prevents_lost_update() {
        let root = tmpdir().join("c1-a-cross-process-writers");
        let dir = root.join("config");
        fs::create_dir_all(&root).unwrap();
        save_to(&dir, &Config::default()).unwrap();

        let spawn = |role: &str| {
            let mut command = std::process::Command::new(std::env::current_exe().unwrap());
            command
                .arg("--exact")
                .arg("config::tests::c1_a_config_writer_child")
                .arg("--nocapture")
                .arg("--test-threads=1")
                .env("CSSWITCH_C1A_WRITER_ROLE", role)
                .env("CSSWITCH_C1A_WRITER_ROOT", &root)
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped());
            if role != "a" {
                command.env(
                    "CSSWITCH_C1A_EXPECT_LOCK_CONTENTION_MARKER",
                    root.join("b-contended"),
                );
            }
            command.spawn().unwrap()
        };

        let writer_a = spawn("a");
        wait_for_test_path(&root.join("a-loaded"));
        let writer_b = spawn("b");
        wait_for_test_path(&root.join("b-contended"));
        let writer_b_entered_early = root.join("b-entered-update").exists();
        fs::write(root.join("release-a"), b"release").unwrap();

        assert_exact_child_passed(writer_a.wait_with_output().unwrap(), "writer A");
        assert_exact_child_passed(writer_b.wait_with_output().unwrap(), "writer B");
        assert!(root.join("a-committed").is_file());
        assert!(root.join("b-committed").is_file());
        assert!(
            !writer_b_entered_early,
            "writer B entered its read-modify-write closure while writer A held the cross-process fence"
        );

        let final_config = load_from(&dir).unwrap();
        assert_eq!(final_config.secret, "writer-a");
        assert!(
            final_config.reuse_system_ssh,
            "the second writer must load writer A's commit instead of overwriting it from a stale snapshot"
        );
    }

    #[test]
    fn o1_e3_auth_fence_blocks_only_compensation_publication() {
        let dir = tmpdir().join("o1-e3-compensation-auth-fence");
        save_to(&dir, &Config::default()).unwrap();
        let auth = acquire_runtime_compensation_auth_lease(&dir).unwrap();
        let (sent, received) = std::sync::mpsc::channel();
        let publication_dir = dir.clone();
        let publication = std::thread::spawn(move || {
            let _lease = acquire_runtime_compensation_publication_lease(&publication_dir).unwrap();
            sent.send(()).unwrap();
        });
        assert!(
            received
                .recv_timeout(std::time::Duration::from_millis(100))
                .is_err(),
            "compensation publication must wait while provider auth owns the absence proof"
        );
        update(&dir, |current| current.secret = "unrelated-writer".into()).unwrap();
        assert_eq!(load_from(&dir).unwrap().secret, "unrelated-writer");
        drop(auth);
        received
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap();
        publication.join().unwrap();
    }

    #[test]
    fn authority_writer_guard_waits_for_ex_owner_and_bypass_never_relocks() {
        let dir = tmpdir().join("authority-writer-guard");
        save_to(&dir, &Config::default()).unwrap();
        let replay = acquire_runtime_compensation_replay_lease(&dir).unwrap();
        let (entered, received) = std::sync::mpsc::channel();
        let waiting_dir = dir.clone();
        let writer = std::thread::spawn(move || {
            let _guard = acquire_authority_writer_guard_at(&waiting_dir).unwrap();
            entered.send(()).unwrap();
        });
        assert!(
            received
                .recv_timeout(std::time::Duration::from_millis(100))
                .is_err(),
            "ordinary authority writer must wait for an EX effect owner"
        );
        {
            let bypass = replay.authority_writer_bypass();
            let _guard = authority_writer_guard_from_bypass(&bypass);
        }
        drop(replay);
        received
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap();
        writer.join().unwrap();
    }

    #[test]
    fn authority_writer_guard_rebind_after_ex_window_fails_closed() {
        let dir = tmpdir().join("authority-writer-rebind-after-ex");
        save_to(&dir, &Config::default()).unwrap();
        let replay = acquire_runtime_compensation_replay_lease(&dir).unwrap();
        let (entered, received) = std::sync::mpsc::channel();
        let waiting_dir = dir.clone();
        let writer = std::thread::spawn(move || {
            entered.send(()).unwrap();
            acquire_authority_writer_guard_at(&waiting_dir)
                .map(|_| ())
                .map_err(|error| error.to_string())
        });
        received
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(100));
        let lock_path = dir.join(RUNTIME_COMPENSATION_AUTH_LOCK_FILE);
        let replacement = dir.join("replacement-authority-fence");
        fs::write(&replacement, b"replacement\n").unwrap();
        fs::rename(&replacement, &lock_path).unwrap();
        drop(replay);
        let error = match writer.join().unwrap() {
            Ok(()) => panic!("writer must reject a lock entry rebound during the EX window"),
            Err(error) => error,
        };
        assert!(error.contains("被替换"));
    }

    #[test]
    fn authority_writer_guard_early_return_releases_sh() {
        fn early_return(dir: &Path) -> io::Result<()> {
            let _guard = acquire_authority_writer_guard_at(dir)?;
            Ok(())
        }

        let dir = tmpdir().join("authority-writer-early-return");
        save_to(&dir, &Config::default()).unwrap();
        early_return(&dir).unwrap();
        let replay = acquire_runtime_compensation_replay_lease(&dir).unwrap();
        drop(replay);
    }

    #[test]
    fn authority_writer_guard_ssh_leaf_child() {
        let Some(root) = std::env::var_os("CSSWITCH_AUTHORITY_WRITER_SSH_CHILD_ROOT") else {
            return;
        };
        let root = PathBuf::from(root);
        fs::write(root.join("about-to-write"), b"ready").unwrap();
        let _ = crate::runtime::ssh_bridge::revoke_science_ssh_bridge(&root.join("sandbox"));
        fs::write(root.join("write-returned"), b"done").unwrap();
    }

    #[test]
    fn authority_writer_guard_blocks_actual_ssh_leaf_until_ex_releases() {
        let root = tmpdir().join("authority-writer-ssh-leaf");
        let dir = root.join("home/.csswitch");
        fs::create_dir_all(&root).unwrap();
        save_to(&dir, &Config::default()).unwrap();
        let replay = acquire_runtime_compensation_replay_lease(&dir).unwrap();
        let child = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("config::tests::authority_writer_guard_ssh_leaf_child")
            .arg("--nocapture")
            .arg("--test-threads=1")
            .env("CSSWITCH_AUTHORITY_WRITER_SSH_CHILD_ROOT", &root)
            .env("HOME", root.join("home"))
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        wait_for_test_path(&root.join("about-to-write"));
        assert!(
            !root.join("write-returned").exists(),
            "actual SSH authority writer entered while an EX owner still held the fence"
        );
        drop(replay);
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "authority SSH writer failed:\nstdout={}\nstderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
        assert!(root.join("write-returned").is_file());
    }

    #[test]
    fn authority_writer_leaf_contracts_use_fence_or_scoped_bypass() {
        let oauth = include_str!("oauth_forge.rs");
        let settings = include_str!("runtime/settings.rs");
        let ssh_bridge = include_str!("runtime/ssh_bridge.rs");
        let route = include_str!("runtime/skill_install_bridge.rs");
        let skill_key = include_str!("runtime/proxy_lifecycle/skill_bridge.rs");
        let history = include_str!("runtime/sandbox_session/history_recovery.rs");
        let live = include_str!("runtime/sandbox_session/one_click/cold/compensation.rs");
        let replay = include_str!("runtime/sandbox_session/one_click/compensation_replay.rs");

        assert!(
            oauth.contains("pub fn ensure_virtual_login")
                && oauth.contains("acquire_authority_writer_guard")
        );
        assert!(oauth.contains("restore_history_choice_with_authority_bypass"));
        assert!(
            settings.contains("compensate_with_authority_bypass")
                && settings.contains("compensate_durable_with_authority_bypass")
                && settings.contains("remove_managed_sandbox_ssh_stub_with_authority_bypass")
        );
        assert!(
            ssh_bridge.contains("pub(crate) fn prepare_science_ssh_bridge")
                && ssh_bridge.contains("pub(crate) fn revoke_science_ssh_bridge")
                && ssh_bridge.matches("acquire_authority_writer_guard").count() >= 2
        );
        assert!(
            route.contains("fn register_before_science_start")
                && route.contains("fn invalidate_route_configuration")
                && route.contains("fn mark_route_configuration_current")
                && route.matches("acquire_authority_writer_guard").count() >= 3
        );
        assert!(
            skill_key.contains("fn publish_canonical_key")
                && skill_key.contains("acquire_authority_writer_guard")
        );
        assert!(
            history.contains("restore_history_choice_with_authority_bypass")
                && history.contains("history_effect_lease.authority_writer_bypass")
        );
        assert!(
            live.contains("_live_replay_lease.authority_writer_bypass")
                && live.contains("compensate_with_authority_bypass")
        );
        assert!(
            replay.contains("_replay_lease.authority_writer_bypass")
                && replay.contains("compensate_durable_with_authority_bypass")
        );
    }

    #[test]
    fn o1_e3_replay_fence_child() {
        let Some(role) = std::env::var_os("CSSWITCH_O1_E3_REPLAY_ROLE") else {
            return;
        };
        let root = PathBuf::from(std::env::var_os("CSSWITCH_O1_E3_REPLAY_ROOT").unwrap());
        let _lease = acquire_runtime_compensation_replay_lease(&root.join("config")).unwrap();
        let role = role.to_string_lossy().to_string();
        let mut effects = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(root.join("effects"))
            .unwrap();
        writeln!(effects, "{role}").unwrap();
        effects.sync_all().unwrap();
        fs::write(root.join(format!("{role}-entered")), b"entered").unwrap();
        if role == "a" {
            wait_for_test_path(&root.join("release-a"));
        }
    }

    #[test]
    fn o1_e3_replay_fence_serializes_two_process_effect_owners() {
        let root = tmpdir().join("o1-e3-cross-process-replay");
        let dir = root.join("config");
        fs::create_dir_all(&root).unwrap();
        save_to(&dir, &Config::default()).unwrap();
        let spawn = |role: &str| {
            std::process::Command::new(std::env::current_exe().unwrap())
                .arg("--exact")
                .arg("config::tests::o1_e3_replay_fence_child")
                .arg("--nocapture")
                .arg("--test-threads=1")
                .env("CSSWITCH_O1_E3_REPLAY_ROLE", role)
                .env("CSSWITCH_O1_E3_REPLAY_ROOT", &root)
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .unwrap()
        };
        let owner_a = spawn("a");
        wait_for_test_path(&root.join("a-entered"));
        let owner_b = spawn("b");
        std::thread::sleep(std::time::Duration::from_millis(150));
        assert_eq!(fs::read_to_string(root.join("effects")).unwrap(), "a\n");
        assert!(!root.join("b-entered").exists());
        fs::write(root.join("release-a"), b"release").unwrap();
        assert_o1_e3_replay_child_passed(owner_a.wait_with_output().unwrap(), "replay owner A");
        assert_o1_e3_replay_child_passed(owner_b.wait_with_output().unwrap(), "replay owner B");
        assert_eq!(fs::read_to_string(root.join("effects")).unwrap(), "a\nb\n");
    }

    #[test]
    fn o1_e4_history_effect_owner_joins_cross_process_replay_fence() {
        let root = tmpdir().join("o1-e4-history-effect-owner");
        let dir = root.join("config");
        fs::create_dir_all(&root).unwrap();
        save_to(&dir, &Config::default()).unwrap();
        let owner = acquire_runtime_history_effect_lease(&dir).unwrap();
        let contender = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("config::tests::o1_e3_replay_fence_child")
            .arg("--nocapture")
            .arg("--test-threads=1")
            .env("CSSWITCH_O1_E3_REPLAY_ROLE", "b")
            .env("CSSWITCH_O1_E3_REPLAY_ROOT", &root)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(150));
        assert!(!root.join("b-entered").exists());
        assert!(!root.join("effects").exists());
        drop(owner);
        assert_o1_e3_replay_child_passed(
            contender.wait_with_output().unwrap(),
            "history effect contender",
        );
        assert_eq!(fs::read_to_string(root.join("effects")).unwrap(), "b\n");
    }

    #[test]
    fn config_writer_fence_rejects_symlink_without_touching_target() {
        let root = tmpdir().join("c1-a-writer-lock-symlink");
        let dir = root.join("config");
        fs::create_dir_all(&dir).unwrap();
        let target = root.join("elsewhere");
        fs::write(&target, b"user-owned").unwrap();
        symlink(&target, dir.join(CONFIG_WRITER_LOCK_FILE)).unwrap();

        let error = save_to(&dir, &Config::default()).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(fs::read(&target).unwrap(), b"user-owned");
        assert!(!config_path(&dir).exists());
    }

    #[test]
    fn config_writer_fence_rejects_hardlink_without_touching_target() {
        let root = tmpdir().join("c1-a-writer-lock-hardlink");
        let dir = root.join("config");
        fs::create_dir_all(&dir).unwrap();
        let target = root.join("elsewhere");
        fs::write(&target, b"user-owned").unwrap();
        fs::hard_link(&target, dir.join(CONFIG_WRITER_LOCK_FILE)).unwrap();

        let error = save_to(&dir, &Config::default()).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(fs::read(&target).unwrap(), b"user-owned");
        assert_eq!(fs::metadata(&target).unwrap().nlink(), 2);
        assert!(!config_path(&dir).exists());
    }

    #[test]
    fn config_writer_fence_rejects_replacement_while_waiting() {
        let root = tmpdir().join("c1-a-writer-lock-replacement");
        let dir = root.join("config");
        fs::create_dir_all(&root).unwrap();
        save_to(&dir, &Config::default()).unwrap();

        let spawn = |role: &str| {
            let mut command = std::process::Command::new(std::env::current_exe().unwrap());
            command
                .arg("--exact")
                .arg("config::tests::c1_a_config_writer_child")
                .arg("--nocapture")
                .arg("--test-threads=1")
                .env("CSSWITCH_C1A_WRITER_ROLE", role)
                .env("CSSWITCH_C1A_WRITER_ROOT", &root)
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped());
            if role != "a" {
                command.env(
                    "CSSWITCH_C1A_EXPECT_LOCK_CONTENTION_MARKER",
                    root.join("b-contended"),
                );
            }
            command.spawn().unwrap()
        };

        let writer_a = spawn("a");
        wait_for_test_path(&root.join("a-loaded"));
        let writer_b = spawn("replace-b");
        wait_for_test_path(&root.join("b-contended"));

        fs::remove_file(dir.join(CONFIG_WRITER_LOCK_FILE)).unwrap();
        fs::write(dir.join(CONFIG_WRITER_LOCK_FILE), b"").unwrap();
        fs::set_permissions(
            dir.join(CONFIG_WRITER_LOCK_FILE),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        fs::write(root.join("release-a"), b"release").unwrap();

        assert_exact_child_passed(writer_a.wait_with_output().unwrap(), "writer A");
        assert_exact_child_passed(writer_b.wait_with_output().unwrap(), "writer B");
        assert!(root.join("b-rejected-replacement").is_file());
        let final_config = load_from(&dir).unwrap();
        assert_eq!(final_config.secret, "writer-a");
        assert!(!final_config.reuse_system_ssh);
    }

    #[test]
    fn read_only_current_config_does_not_create_writer_fence() {
        let dir = tmpdir().join("c1-a-read-only-no-writer-lock");
        fs::create_dir_all(&dir).unwrap();
        let bytes = serde_json::to_vec_pretty(&Config::default()).unwrap();
        fs::write(config_path(&dir), &bytes).unwrap();
        fs::set_permissions(config_path(&dir), fs::Permissions::from_mode(0o600)).unwrap();

        assert_eq!(
            load_current_from_read_only(&dir).unwrap(),
            Config::default()
        );
        assert_eq!(fs::read(config_path(&dir)).unwrap(), bytes);
        assert!(
            !dir.join(CONFIG_WRITER_LOCK_FILE).exists(),
            "a read-only consumer must not create or acquire the writer fence"
        );
    }

    #[test]
    fn load_resets_widened_perms_to_0600() {
        let d = tmpdir().join(".csswitch");
        save_to(&d, &Config::default()).unwrap();
        let p = config_path(&d);
        fs::set_permissions(&p, fs::Permissions::from_mode(0o644)).unwrap();
        load_from(&d).unwrap();
        assert_eq!(mode_of(&p), 0o600, "load must reset perms to 0600");
    }

    #[test]
    fn save_rejects_symlinked_file_and_leaves_target_untouched() {
        let base = tmpdir();
        let d = base.join(".csswitch");
        fs::create_dir_all(&d).unwrap();
        let target = base.join("real-elsewhere.txt");
        fs::write(&target, b"ORIGINAL").unwrap();
        symlink(&target, config_path(&d)).unwrap();
        let err = save_to(&d, &Config::default()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(fs::read(&target).unwrap(), b"ORIGINAL");
    }

    #[test]
    fn load_rejects_symlinked_file() {
        let base = tmpdir();
        let d = base.join(".csswitch");
        fs::create_dir_all(&d).unwrap();
        let target = base.join("secret.txt");
        fs::write(&target, b"{\"schema_version\":2}").unwrap();
        symlink(&target, config_path(&d)).unwrap();
        let err = load_from(&d).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn load_rejects_fifo_without_blocking() {
        let d = tmpdir().join(".csswitch-fifo");
        fs::create_dir_all(&d).unwrap();
        let path = config_path(&d);
        let c_path = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);
        let error = load_from(&d).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn versioned_backup_rejects_fifo_target_without_overwrite() {
        let d = tmpdir().join(".csswitch-backup-fifo");
        fs::create_dir_all(&d).unwrap();
        let target = d.join("config.json.v2.bak");
        let c_path = std::ffi::CString::new(target.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);
        assert!(write_versioned_backup_bytes(&d, 2, b"safe-bytes").is_err());
        assert!(fs::symlink_metadata(target).unwrap().file_type().is_fifo());
    }

    #[test]
    fn versioned_backup_recovers_published_pending_hardlink_after_crash() {
        let d = tmpdir().join(".csswitch-backup-recovery");
        fs::create_dir_all(&d).unwrap();
        let bytes = b"migration-source-bytes";
        let suffix = backup_content_suffix(bytes);
        let pending = d.join(format!(".config.json.v2.bak.pending-{suffix}"));
        let target = d.join("config.json.v2.bak");
        fs::write(&pending, bytes).unwrap();
        fs::hard_link(&pending, &target).unwrap();
        assert_eq!(fs::metadata(&target).unwrap().nlink(), 2);

        let published = write_versioned_backup_bytes(&d, 2, bytes).unwrap();
        assert_eq!(published, target);
        assert!(!pending.exists());
        assert_eq!(fs::read(&target).unwrap(), bytes);
        assert_eq!(fs::metadata(&target).unwrap().nlink(), 1);
    }

    #[test]
    fn load_rejects_symlinked_dir() {
        let base = tmpdir();
        let realdir = base.join("realdir");
        fs::create_dir_all(&realdir).unwrap();
        fs::write(realdir.join("config.json"), b"{\"schema_version\":2}").unwrap();
        let link = base.join(".csswitch");
        symlink(&realdir, &link).unwrap();
        let err = load_from(&link).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn ensure_dir_rejects_symlinked_dir() {
        let base = tmpdir();
        let realdir = base.join("realdir");
        fs::create_dir_all(&realdir).unwrap();
        let link = base.join(".csswitch");
        symlink(&realdir, &link).unwrap();
        let err = save_to(&link, &Config::default()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn no_tmp_file_left_after_save() {
        let d = tmpdir().join(".csswitch");
        save_to(&d, &Config::default()).unwrap();
        let leftovers: Vec<_> = fs::read_dir(&d)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.file_name()
                    .to_string_lossy()
                    .starts_with(".config.json.tmp")
            })
            .collect();
        assert!(leftovers.is_empty(), "临时文件应已 rename 掉");
    }

    #[test]
    fn update_applies_and_persists() {
        let d = tmpdir().join(".csswitch");
        save_to(&d, &Config::default()).unwrap();
        update(&d, |c| {
            c.profiles.push(Profile {
                name: "Q".into(),
                ..saved_profile("id1", "qwen", "openai_chat", "qwen-plus-latest")
            });
            c.active_id = "id1".into();
        })
        .unwrap();
        let got = load_from(&d).unwrap();
        assert_eq!(got.active_id, "id1");
        assert_eq!(got.active_profile().unwrap().name, "Q");
    }

    #[test]
    fn secret_persists_and_survives_reload() {
        // path-secret 一旦生成必须持久化，代理重启/重开 app 仍是同一个值。
        let d = tmpdir().join(".csswitch");
        save_to(&d, &Config::default()).unwrap();
        assert!(load_from(&d).unwrap().secret.is_empty(), "初始应为空");
        update(&d, |c| c.secret = "deadbeef00112233".into()).unwrap();
        assert_eq!(load_from(&d).unwrap().secret, "deadbeef00112233");
        // 再改别的字段，secret 不受影响。
        update(&d, |c| c.proxy_port = 20000).unwrap();
        assert_eq!(load_from(&d).unwrap().secret, "deadbeef00112233");
    }

    #[test]
    fn v2_migration_preserves_api_key_profile_and_settings() {
        let d = tmpdir().join(".csswitch-v2-migration");
        fs::create_dir_all(&d).unwrap();
        let v2 = crate::config_legacy::ConfigV2 {
            schema_version: 2,
            profiles: vec![crate::config_legacy::ProfileV2 {
                id: "api-1".into(),
                name: "GLM".into(),
                template_id: "glm".into(),
                category: "cn_official".into(),
                api_format: "anthropic".into(),
                base_url: "https://open.bigmodel.cn/api/anthropic".into(),
                api_key: "sk-existing".into(),
                model: "glm-5.2".into(),
                ..Default::default()
            }],
            active_id: "api-1".into(),
            proxy_port: 19001,
            sandbox_port: 19002,
            reuse_system_ssh: true,
            secret: "persistent-secret".into(),
            mode: "proxy".into(),
            pending_notice: Some("keep-me".into()),
        };
        let canonical = serde_json::to_vec_pretty(&v2).unwrap();
        fs::write(config_path(&d), &canonical).unwrap();

        let migrated = load_from(&d).unwrap();
        assert_eq!(migrated.schema_version, 4);
        assert_eq!(migrated.active_id, "api-1");
        assert_eq!(migrated.proxy_port, 19001);
        assert_eq!(migrated.sandbox_port, 19002);
        assert!(migrated.reuse_system_ssh);
        assert_eq!(migrated.secret, "persistent-secret");
        assert_eq!(
            migrated.codex_network,
            csswitch_codex_network::CodexNetworkSettings::default()
        );
        let profile = migrated.active_profile().unwrap();
        assert_eq!(profile.api_key, "sk-existing");
        assert_eq!(profile.model, "glm-5.2");
        assert_eq!(profile.credential_source, CredentialSource::ApiKey);
        assert_eq!(profile.model_policy, ModelPolicy::SavedCatalog);
        assert_eq!(fs::read(d.join("config.json.v2.bak")).unwrap(), canonical);
    }

    #[test]
    fn v3_to_v4_preserves_unknown_fields_and_raw_backup_byte_for_byte() {
        let d = tmpdir().join(".csswitch-v3-extensions");
        fs::create_dir_all(&d).unwrap();
        let raw = br#"{
  "schema_version": 3,
  "profiles": [{
    "id": "qwen-legacy",
    "name": "Qwen",
    "template_id": "qwen",
    "category": "cn_official",
    "api_format": "openai_chat",
    "base_url": "https://dashscope.aliyuncs.com/compatible-mode/v1",
    "api_key": "test-only",
    "model": "claude-sonnet-5",
    "credential_source": "api_key",
    "model_policy": "optional_fixed",
    "future_profile": {"keep": 2}
  }],
  "active_id": "qwen-legacy",
  "proxy_port": 19031,
  "sandbox_port": 19032,
  "codex_network": {"mode": "auto", "proxy_url": "", "future_network": 3},
  "mode": "proxy",
  "future_top": [1, 2, 3]
}"#;
        fs::write(config_path(&d), raw).unwrap();
        let migrated = load_from(&d).unwrap();
        assert_eq!(migrated.extra["future_top"], serde_json::json!([1, 2, 3]));
        assert_eq!(migrated.profiles[0].extra["future_profile"]["keep"], 2);
        assert_eq!(migrated.codex_network.extra["future_network"], 3);
        assert_eq!(migrated.profiles[0].model, "qwen-plus-latest");
        assert_eq!(fs::read(d.join("config.json.v3.bak")).unwrap(), raw);
        let canonical: serde_json::Value =
            serde_json::from_slice(&fs::read(config_path(&d)).unwrap()).unwrap();
        assert_eq!(canonical["schema_version"], 4);
        assert!(canonical["profiles"][0].get("model").is_none());

        update(&d, |cfg| cfg.pending_notice = Some("unrelated".into())).unwrap();
        let again = load_from(&d).unwrap();
        assert_eq!(again.extra["future_top"], serde_json::json!([1, 2, 3]));
        assert_eq!(again.profiles[0].extra["future_profile"]["keep"], 2);
        assert_eq!(again.codex_network.extra["future_network"], 3);
        assert_eq!(fs::read(d.join("config.json.v3.bak")).unwrap(), raw);
    }

    #[test]
    fn v4_route_and_role_extensions_survive_unrelated_update() {
        let d = tmpdir().join(".csswitch-v4-route-extensions");
        let mut profile = saved_profile("p1", "qwen", "openai_chat", "qwen-plus-latest");
        profile.model_catalog[0]
            .extra
            .insert("future_route".into(), serde_json::json!({"keep": true}));
        profile
            .role_bindings
            .extra
            .insert("future_role".into(), serde_json::json!(7));
        let cfg = Config {
            profiles: vec![profile],
            active_id: "p1".into(),
            ..Default::default()
        };
        save_to(&d, &cfg).unwrap();
        update(&d, |cfg| cfg.proxy_port = 19041).unwrap();
        let got = load_from(&d).unwrap();
        assert_eq!(
            got.profiles[0].model_catalog[0].extra["future_route"]["keep"],
            true
        );
        assert_eq!(got.profiles[0].role_bindings.extra["future_role"], 7);
    }

    #[test]
    fn native_v3_model_variants_preserve_the_selected_upstream() {
        for (template_id, api_format, old_model, expected, expected_len) in [
            ("deepseek", "anthropic", "", "deepseek-v4-flash", 2),
            (
                "deepseek",
                "anthropic",
                "claude-haiku-4-5",
                "deepseek-v4-flash",
                2,
            ),
            (
                "deepseek",
                "anthropic",
                "deepseek-v4-pro",
                "deepseek-v4-pro",
                2,
            ),
            ("qwen", "openai_chat", "claude-opus-4-8", "qwen3.7-max", 3),
            ("qwen", "openai_chat", "qwen-turbo", "qwen-turbo", 3),
            (
                "qwen",
                "openai_chat",
                "future-qwen-exact",
                "future-qwen-exact",
                4,
            ),
        ] {
            let v3 = crate::config_legacy::ConfigV3 {
                schema_version: 3,
                profiles: vec![crate::config_legacy::ProfileV3 {
                    id: "p".into(),
                    name: "legacy".into(),
                    template_id: template_id.into(),
                    api_format: api_format.into(),
                    model: old_model.into(),
                    model_policy: crate::config_legacy::ModelPolicyV3::OptionalFixed,
                    credential_source: CredentialSource::ApiKey,
                    ..Default::default()
                }],
                ..Default::default()
            };
            let migrated = migrate_v3_to_v4(v3).unwrap();
            assert_eq!(
                migrated.profiles[0].model, expected,
                "{template_id}:{old_model}"
            );
            assert_eq!(migrated.profiles[0].model_catalog.len(), expected_len);
            assert_eq!(
                migrated.profiles[0].role_bindings.sonnet,
                migrated.profiles[0].default_model_route_id,
                "{template_id}:{old_model} must keep migrated default/Sonnet aligned"
            );
        }

        let selector = crate::model_catalog::selector_id_v1("qwen", "qwen-turbo");
        let v3 = crate::config_legacy::ConfigV3 {
            schema_version: 3,
            profiles: vec![crate::config_legacy::ProfileV3 {
                id: "p".into(),
                template_id: "qwen".into(),
                api_format: "openai_chat".into(),
                model: selector,
                model_policy: crate::config_legacy::ModelPolicyV3::OptionalFixed,
                credential_source: CredentialSource::ApiKey,
                ..Default::default()
            }],
            ..Default::default()
        };
        assert_eq!(
            migrate_v3_to_v4(v3).unwrap().profiles[0].model,
            "qwen-turbo"
        );
    }

    #[test]
    fn v2_backup_collision_never_overwrites_existing_bytes() {
        let d = tmpdir().join(".csswitch-v2-collision");
        fs::create_dir_all(&d).unwrap();
        fs::write(d.join("config.json.v2.bak"), b"OLD-UNRELATED-BYTES").unwrap();
        fs::write(
            config_path(&d),
            br#"{"schema_version":2,"profiles":[],"active_id":"","proxy_port":18991,"sandbox_port":8990,"reuse_system_ssh":false,"secret":"","mode":"proxy","pending_notice":null}"#,
        )
        .unwrap();
        load_from(&d).unwrap();
        assert_eq!(
            fs::read(d.join("config.json.v2.bak")).unwrap(),
            b"OLD-UNRELATED-BYTES"
        );
        let alternates: Vec<_> = fs::read_dir(&d)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with("config.json.v2.bak.")
            })
            .collect();
        assert_eq!(alternates.len(), 1);
    }

    fn codex_profile(id: &str) -> Profile {
        Profile {
            id: id.into(),
            name: "Codex account".into(),
            template_id: "codex".into(),
            category: "official".into(),
            api_format: "openai_responses".into(),
            credential_source: CredentialSource::CsswitchOauth,
            credential_ref: Some("csswitch:codex:default".into()),
            model_policy: ModelPolicy::DynamicCatalog,
            model: "gpt-test".into(),
            ..Default::default()
        }
    }

    #[test]
    fn downgrade_requires_an_action_for_every_codex_profile() {
        let cfg = Config {
            profiles: vec![codex_profile("c1"), codex_profile("c2")],
            active_id: "c1".into(),
            ..Default::default()
        };
        let actions = BTreeMap::from([("c1".into(), CodexDowngradeAction::Remove)]);
        assert!(prepare_downgrade_to_v2(&cfg, &actions).is_err());
    }

    #[test]
    fn downgrade_rejects_every_history_phase_before_export_backup_or_config_write() {
        for phase in [
            RuntimeTransactionPhase::StopOldScience,
            RuntimeTransactionPhase::AuthoritySnapshotActive,
            RuntimeTransactionPhase::HistoryCredentialWritePending,
            RuntimeTransactionPhase::HistoryAuthorityRestorePending,
            RuntimeTransactionPhase::HistoryAuthorityRestoreSucceeded,
            RuntimeTransactionPhase::HistoryCredentialPublished,
            RuntimeTransactionPhase::ResumeAfterHistoryRestore,
        ] {
            let root = tmpdir();
            let dir = root.join(format!("history-downgrade-{phase:?}"));
            let export = root.join(format!("history-export-{phase:?}.json"));
            let mut record = valid_history_v2(phase);
            record.target_profile_id = "codex-history".into();
            let cfg = Config {
                profiles: vec![codex_profile("codex-history")],
                active_id: "codex-history".into(),
                runtime_transaction: Some(RuntimeTransactionRecord::V2(record.clone())),
                ..Default::default()
            };
            save_to(&dir, &cfg).unwrap();
            let before = fs::read(config_path(&dir)).unwrap();
            let manifest = br#"{"schema_version":2,"sentinel":"history-owned"}"#;
            fs::write(dir.join(PENDING_AUTHORITY_CLEANUP_MANIFEST_FILE), manifest).unwrap();
            let actions = BTreeMap::from([(
                "codex-history".into(),
                CodexDowngradeAction::ExportThenRemove,
            )]);

            let preview_error = prepare_downgrade_to_v2(&cfg, &actions).unwrap_err();
            assert!(preview_error.contains("runtime_transaction_in_progress"));
            let commit_error = downgrade_to_v2(&dir, &actions, Some(&export)).unwrap_err();
            assert!(commit_error.contains("runtime_transaction_in_progress"));
            assert_eq!(fs::read(config_path(&dir)).unwrap(), before);
            assert_eq!(
                load_from(&dir).unwrap().runtime_transaction,
                Some(RuntimeTransactionRecord::V2(record))
            );
            assert_eq!(
                fs::read(dir.join(PENDING_AUTHORITY_CLEANUP_MANIFEST_FILE)).unwrap(),
                manifest
            );
            assert!(!export.exists());
            assert!(!dir.join("config.json.bak").exists());
        }
    }

    #[test]
    fn downgrade_exports_only_metadata_and_preserves_api_key_profiles() {
        let root = tmpdir();
        let d = root.join(".csswitch-downgrade");
        let export_destination = root.join("codex-profiles-export.v1.json");
        let api = Profile {
            name: "DeepSeek".into(),
            category: "cn_official".into(),
            base_url: "https://api.deepseek.test/anthropic".into(),
            api_key: "sk-preserve".into(),
            ..saved_profile("api-1", "deepseek", "anthropic", "deepseek-v4-pro")
        };
        let cfg = Config {
            profiles: vec![api, codex_profile("codex-1")],
            active_id: "codex-1".into(),
            proxy_port: 19011,
            sandbox_port: 19012,
            reuse_system_ssh: true,
            secret: "keep-secret".into(),
            codex_network: csswitch_codex_network::CodexNetworkSettings {
                mode: csswitch_codex_network::CodexNetworkMode::Custom,
                proxy_url: "socks5h://127.0.0.1:7890".into(),
                ..Default::default()
            },
            ..Default::default()
        };
        save_to(&d, &cfg).unwrap();
        let actions = BTreeMap::from([("codex-1".into(), CodexDowngradeAction::ExportThenRemove)]);
        let export_path = downgrade_to_v2(&d, &actions, Some(&export_destination))
            .unwrap()
            .unwrap();

        let raw = fs::read(config_path(&d)).unwrap();
        let v2: crate::config_legacy::ConfigV2 = serde_json::from_slice(&raw).unwrap();
        assert_eq!(v2.schema_version, 2);
        assert_eq!(v2.active_id, "");
        assert_eq!(v2.profiles.len(), 1);
        assert_eq!(v2.profiles[0].id, "api-1");
        assert_eq!(v2.profiles[0].api_key, "sk-preserve");
        assert_eq!(v2.proxy_port, 19011);
        assert_eq!(v2.sandbox_port, 19012);
        assert!(v2.reuse_system_ssh);
        assert_eq!(v2.secret, "keep-secret");
        let raw_value: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        assert!(raw_value.get("codex_network").is_none());

        let export = fs::read_to_string(export_path).unwrap();
        assert!(export.contains("Codex account"));
        assert!(export.contains("saved_model_catalog"));
        assert!(!export.contains("csswitch:codex:default"));
        assert!(!export.contains("credential_ref"));
        assert!(!export.contains("api_key"));
        assert!(!export.contains("sk-preserve"));
        assert!(!export.contains("api.deepseek.test"));
        assert!(!export.contains("keep-secret"));
    }

    #[test]
    fn downgrade_terminal_latch_is_verified_in_an_isolated_test_process() {
        if std::env::var_os("CSSWITCH_DOWNGRADE_LATCH_CHILD").is_some() {
            return;
        }
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("config::tests::downgrade_terminal_latch_child")
            .arg("--nocapture")
            .env("CSSWITCH_DOWNGRADE_LATCH_CHILD", "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "terminal latch child failed:\nstdout={}\nstderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn downgrade_terminal_latch_child() {
        if std::env::var_os("CSSWITCH_DOWNGRADE_LATCH_CHILD").is_none() {
            return;
        }
        let root = tmpdir();
        let dir = root.join(".csswitch-terminal-latch");
        let destination = root.join("codex-export.json");
        let cfg = Config {
            profiles: vec![codex_profile("codex-terminal")],
            active_id: "codex-terminal".into(),
            ..Default::default()
        };
        save_to(&dir, &cfg).unwrap();
        let actions = BTreeMap::from([(
            "codex-terminal".into(),
            CodexDowngradeAction::ExportThenRemove,
        )]);
        let fingerprint = prepare_downgrade_to_v2(&cfg, &actions).unwrap().fingerprint;
        downgrade_to_v2_and_latch(&dir, &actions, Some(&destination), &fingerprint).unwrap();

        let raw: serde_json::Value =
            serde_json::from_slice(&fs::read(config_path(&dir)).unwrap()).unwrap();
        assert_eq!(raw["schema_version"], 2);
        let backup_before = fs::read(dir.join("config.json.bak")).unwrap();
        for error in [
            load_from(&dir).unwrap_err(),
            update(&dir, |_| {}).unwrap_err(),
            save_to(&dir, &Config::default()).unwrap_err(),
            write_rolling_backup(&dir).unwrap_err(),
        ] {
            assert!(error.to_string().contains("终态退出"));
        }
        assert!(drop_rolling_backup(&dir).is_err());
        assert_eq!(
            fs::read(dir.join("config.json.bak")).unwrap(),
            backup_before
        );
        let raw_after: serde_json::Value =
            serde_json::from_slice(&fs::read(config_path(&dir)).unwrap()).unwrap();
        assert_eq!(raw_after["schema_version"], 2);
    }

    #[test]
    fn downgrade_export_failure_leaves_current_config_byte_identical() {
        let base = tmpdir();
        let d = base.join(".csswitch-downgrade-fail");
        let cfg = Config {
            profiles: vec![codex_profile("codex-1")],
            active_id: "codex-1".into(),
            ..Default::default()
        };
        save_to(&d, &cfg).unwrap();
        let before = fs::read(config_path(&d)).unwrap();
        let elsewhere = base.join("export-target");
        fs::write(&elsewhere, b"UNCHANGED").unwrap();
        let export_destination = base.join("codex-profiles-export.v1.json");
        symlink(&elsewhere, &export_destination).unwrap();
        let actions = BTreeMap::from([("codex-1".into(), CodexDowngradeAction::ExportThenRemove)]);
        assert!(downgrade_to_v2(&d, &actions, Some(&export_destination)).is_err());
        assert_eq!(fs::read(config_path(&d)).unwrap(), before);
        assert_eq!(fs::read(&elsewhere).unwrap(), b"UNCHANGED");
    }

    #[test]
    fn duplicate_or_empty_profile_ids_fail_before_downgrade_actions_are_folded() {
        let duplicate = Config {
            profiles: vec![codex_profile("same"), codex_profile("same")],
            active_id: "same".into(),
            ..Default::default()
        };
        let actions = BTreeMap::from([("same".into(), CodexDowngradeAction::Remove)]);
        assert!(prepare_downgrade_to_v2(&duplicate, &actions).is_err());

        let mut empty = codex_profile("");
        empty.name = "empty id".into();
        let cfg = Config {
            profiles: vec![empty],
            ..Default::default()
        };
        assert!(save_to(&tmpdir().join(".csswitch-empty-id"), &cfg).is_err());
    }

    #[test]
    fn commit_sync_failure_restores_byte_identical_config_without_residue() {
        let d = tmpdir().join(".csswitch-sync-rollback");
        save_to(&d, &Config::default()).unwrap();
        let before = fs::read(config_path(&d)).unwrap();
        let secure = SecureDir::open(&d, false).unwrap();
        let error = atomic_write_named_bytes_in(
            &secure,
            "config.json",
            br#"{"schema_version":3,"changed":true}"#,
            None,
            |_| Err(io::Error::other("injected fsync failure")),
        )
        .unwrap_err();
        assert!(error.to_string().contains("injected fsync failure"));
        assert_eq!(fs::read(config_path(&d)).unwrap(), before);
        let leftovers: Vec<_> = fs::read_dir(&d)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                name.contains(".tmp-") || name.contains(".restore-") || name.contains(".rollback-")
            })
            .collect();
        assert!(leftovers.is_empty());
    }

    #[test]
    fn commit_and_rollback_double_failure_is_terminal_uncertain() {
        let d = tmpdir().join(".csswitch-sync-rollback-double-fail");
        save_to(&d, &Config::default()).unwrap();
        let secure = SecureDir::open(&d, false).unwrap();
        let error = atomic_write_named_bytes_in(
            &secure,
            "config.json",
            br#"{"schema_version":3,"changed":true}"#,
            None,
            |secure| {
                fs::set_permissions(&secure.path, fs::Permissions::from_mode(0o500))?;
                Err(io::Error::other("injected commit sync failure"))
            },
        )
        .unwrap_err();
        fs::set_permissions(&d, fs::Permissions::from_mode(0o700)).unwrap();

        assert!(atomic_rollback_is_uncertain(&error));
        assert!(error.to_string().contains("回滚失败"));
        let uncertain_bytes = fs::read(config_path(&d)).unwrap();
        let projection = crate::runtime::finalize_consumer::project_finalize_consumer_state(
            &d,
            &serde_json::json!({
                "status": "degraded",
                "recovery_status": "manual_recovery_required",
                "action": "started"
            }),
        );
        assert!(
            projection.is_err(),
            "an unreadable atomic outcome must stay manual instead of guessing applied/Ready"
        );
        assert_eq!(
            fs::read(config_path(&d)).unwrap(),
            uncertain_bytes,
            "finalize projection must not repair or rewrite an uncertain atomic outcome"
        );
        let failure = DowngradeError::commit(error);
        assert!(failure.exit_required);
        let outcome = Err(failure);
        let mut access = ConfigAccessState {
            downgrade_terminal: false,
        };
        latch_terminal_downgrade_outcome(&mut access, &outcome);
        assert!(access.downgrade_terminal);
    }

    #[test]
    fn safe_precommit_downgrade_failure_does_not_latch_terminal_state() {
        let outcome = Err(DowngradeError::safe("injected precommit failure"));
        let mut access = ConfigAccessState {
            downgrade_terminal: false,
        };
        latch_terminal_downgrade_outcome(&mut access, &outcome);
        assert!(!access.downgrade_terminal);
    }

    #[test]
    fn clearing_key_removes_old_secret_from_every_regular_config_file() {
        let d = tmpdir().join(".csswitch-clear-key");
        let mut cfg = Config {
            profiles: vec![Profile {
                api_key: "sk-must-not-survive".into(),
                ..saved_profile("api-1", "deepseek", "anthropic", "deepseek-v4-pro")
            }],
            active_id: "api-1".into(),
            ..Default::default()
        };
        save_to(&d, &cfg).unwrap();
        write_rolling_backup(&d).unwrap();
        cfg.profiles[0].api_key.clear();
        save_to(&d, &cfg).unwrap();
        drop_rolling_backup(&d).unwrap();
        for entry in fs::read_dir(&d).unwrap().filter_map(Result::ok) {
            if entry.file_type().unwrap().is_file() {
                let bytes = fs::read(entry.path()).unwrap();
                assert!(!bytes
                    .windows(b"sk-must-not-survive".len())
                    .any(|window| { window == b"sk-must-not-survive" }));
            }
        }
    }

    #[test]
    fn export_must_leave_app_owned_dir_and_preserves_user_parent_mode() {
        let root = tmpdir();
        let d = root.join(".csswitch-export-boundary");
        let cfg = Config {
            profiles: vec![codex_profile("codex-1")],
            active_id: "codex-1".into(),
            ..Default::default()
        };
        save_to(&d, &cfg).unwrap();
        let actions = BTreeMap::from([("codex-1".into(), CodexDowngradeAction::ExportThenRemove)]);
        for reserved in [
            "config.json",
            "config.json.bak",
            "config.json.v1.bak",
            "config.json.v2.bak",
        ] {
            assert!(downgrade_to_v2(&d, &actions, Some(&d.join(reserved))).is_err());
        }

        let export_dir = root.join("Documents");
        fs::create_dir(&export_dir).unwrap();
        fs::set_permissions(&export_dir, fs::Permissions::from_mode(0o755)).unwrap();
        let destination = export_dir.join("codex-export.json");
        downgrade_to_v2(&d, &actions, Some(&destination)).unwrap();
        assert_eq!(mode_of(&export_dir), 0o755);
        assert_eq!(mode_of(&destination), 0o600);
    }

    #[test]
    fn failed_export_commit_preserves_existing_user_file_bytes_and_mode() {
        let root = tmpdir();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
        let destination = root.join("existing-export.json");
        fs::write(&destination, b"user-owned-before").unwrap();
        fs::set_permissions(&destination, fs::Permissions::from_mode(0o644)).unwrap();
        let export_dir = SecureDir::open_unmanaged(&root).unwrap();
        assert!(atomic_write_named_bytes_in(
            &export_dir,
            "existing-export.json",
            b"replacement",
            None,
            |_| Err(io::Error::other("injected export dir fsync failure")),
        )
        .is_err());
        assert_eq!(fs::read(&destination).unwrap(), b"user-owned-before");
        assert_eq!(mode_of(&destination), 0o644);
        assert_eq!(mode_of(&root), 0o755);
    }

    #[test]
    fn completed_export_survives_later_config_precommit_failure() {
        let root = tmpdir();
        let d = root.join(".csswitch-downgrade-crash-boundary");
        let cfg = Config {
            profiles: vec![codex_profile("codex-1")],
            active_id: "codex-1".into(),
            ..Default::default()
        };
        save_to(&d, &cfg).unwrap();
        let before = fs::read(config_path(&d)).unwrap();
        let fifo = d.join("config.json.bak");
        let c_path = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);
        let destination = root.join("codex-export.json");
        let actions = BTreeMap::from([("codex-1".into(), CodexDowngradeAction::ExportThenRemove)]);
        assert!(downgrade_to_v2(&d, &actions, Some(&destination)).is_err());
        assert_eq!(fs::read(config_path(&d)).unwrap(), before);
        let export = fs::read_to_string(destination).unwrap();
        assert!(export.contains("Codex account"));
        assert!(!export.contains("credential_ref"));
    }

    #[test]
    fn mask_hides_all_but_last4() {
        assert_eq!(mask("sk-1234567890ab"), "••••90ab"); // 定长 4 点 + 末4
        assert_eq!(mask(""), "");
        assert_eq!(mask("abc"), "•••");
        assert_eq!(mask("abcd"), "••••");
        assert_eq!(mask("abcde"), "••••bcde"); // 定长 4 点 + 末4
        let full = "sk-secret-tail9999";
        assert!(!mask(full).contains("secret"));
        // 定长：掩码总长恒为 8（4 点 + 末4），不随 key 长度变长、不泄漏长度
        assert_eq!(
            mask("sk-aaaaaaaaaaaaaaaaaaaaaaaaaaaa1234").chars().count(),
            8
        );
    }

    fn p2b_test_fence(cfg: &Config) -> ConfigMutationOperationFence {
        ConfigMutationOperationFence::begin(
            new_id(),
            "set_mode_official".into(),
            "a".repeat(64),
            config_mutation_config_fingerprint(cfg).unwrap(),
            None,
        )
    }

    #[test]
    fn p2b_receipt_bounds_no_clobber_and_clearing_matrix() {
        let dir = tmpdir();
        let cfg = Config::default();
        save_to(&dir, &cfg).unwrap();
        let fence = p2b_test_fence(&cfg);
        begin_config_mutation_operation(&dir, &cfg, &fence, b"receipt-one").unwrap();
        assert!(begin_config_mutation_operation(&dir, &cfg, &fence, b"receipt-two").is_err());
        assert_eq!(
            read_config_mutation_operation_receipt(&dir)
                .unwrap()
                .as_deref(),
            Some(b"receipt-one".as_slice())
        );
        assert!(write_config_mutation_operation(
            &dir,
            &fence,
            &vec![b'x'; MAX_CONFIG_MUTATION_RECEIPT_BYTES + 1],
            b"receipt-one",
        )
        .is_err());
        assert!(write_config_mutation_operation(&dir, &fence, b"replacement", b"stale").is_err());
        assert_eq!(
            read_config_mutation_operation_receipt(&dir)
                .unwrap()
                .as_deref(),
            Some(b"receipt-one".as_slice())
        );
        let terminal = fence.terminal("b".repeat(64), "before", "preserved", None, None, None);
        publish_config_mutation_terminal_fence(
            &dir,
            &fence,
            &terminal,
            b"receipt-one",
            ConfigMutationTerminalConfigImage::Before,
        )
        .unwrap();
        clear_config_mutation_operation(
            &dir,
            &terminal,
            b"receipt-one",
            ConfigMutationTerminalConfigImage::Before,
        )
        .unwrap();
        assert!(read_config_mutation_operation_receipt(&dir)
            .unwrap()
            .is_none());
        assert!(load_from(&dir)
            .unwrap()
            .config_mutation_operation_fence()
            .unwrap()
            .is_none());
    }

    #[test]
    fn p2b_runtime_effect_admission_rejects_every_receipt_and_fence_shape() {
        for shape in ["receipt", "clearing", "begin_fence", "terminal_fence"] {
            let dir = tmpdir().join(format!(".csswitch-runtime-admission-{shape}"));
            let cfg = Config::default();
            save_to(&dir, &cfg).unwrap();
            match shape {
                "receipt" => {
                    fs::write(
                        dir.join(CONFIG_MUTATION_OPERATION_RECEIPT_FILE),
                        br#"{"schema_version":1,"test":"receipt-only"}"#,
                    )
                    .unwrap();
                }
                "clearing" => {
                    fs::write(
                        dir.join(CONFIG_MUTATION_OPERATION_CLEARING_FILE),
                        br#"{"schema_version":1,"test":"clearing-only"}"#,
                    )
                    .unwrap();
                }
                "begin_fence" | "terminal_fence" => {
                    let begin = ConfigMutationOperationFence::begin(
                        "11".repeat(16),
                        "set_settings_destructive".into(),
                        "22".repeat(32),
                        config_mutation_config_fingerprint(&cfg).unwrap(),
                        Some(config_mutation_config_fingerprint(&cfg).unwrap()),
                    );
                    let fence = if shape == "terminal_fence" {
                        begin.terminal("33".repeat(32), "after", "preserved", None, None, None)
                    } else {
                        begin
                    };
                    let mut fenced = cfg.clone();
                    fenced.set_config_mutation_operation_fence(&fence);
                    test_save_to_without_history_authority_guard(&dir, &fenced).unwrap();
                }
                _ => unreachable!(),
            }
            let error = load_for_runtime_effect_admission(&dir).unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("config_mutation_operation_in_progress"),
                "{shape}: {error}"
            );
            if shape == "clearing" {
                assert!(dir.join(CONFIG_MUTATION_OPERATION_RECEIPT_FILE).is_file());
                assert!(!dir.join(CONFIG_MUTATION_OPERATION_CLEARING_FILE).exists());
            }
        }
    }

    #[test]
    fn p2b_fence_mutual_exclusion_with_p2a_and_runtime_journals() {
        let dir = tmpdir();
        let mut p2a = Config {
            experimental_codex_enabled: true,
            ..Default::default()
        };
        let before = codex_disable_config_fingerprint(&p2a).unwrap();
        let mut after = p2a.clone();
        after.experimental_codex_enabled = false;
        let p2a_fence = CodexDisableOperationFence::new(
            new_id(),
            "c".repeat(64),
            before,
            codex_disable_config_fingerprint(&after).unwrap(),
        );
        p2a.set_codex_disable_operation_fence(&p2a_fence);
        save_to(&dir, &p2a).unwrap();
        let p2b_fence = p2b_test_fence(&p2a);
        assert!(begin_config_mutation_operation(&dir, &p2a, &p2b_fence, b"p2b").is_err());

        let journal_cfg = Config {
            runtime_transaction: Some(
                RuntimeTransactionV1 {
                    transaction_id: "legacy-tx".into(),
                    target_profile_id: "target".into(),
                    stage: "stop_old_science".into(),
                    previous_binding: None,
                    previous_gateway: None,
                }
                .into(),
            ),
            ..Default::default()
        };
        let journal_dir = tmpdir();
        save_to(&journal_dir, &journal_cfg).unwrap();
        let journal_fence = p2b_test_fence(&journal_cfg);
        assert!(begin_config_mutation_operation(
            &journal_dir,
            &journal_cfg,
            &journal_fence,
            b"p2b"
        )
        .is_err());
    }

    #[test]
    fn p2b_fence_first_orphan_and_receipt_only_corruption_matrix() {
        let dir = tmpdir();
        let cfg = Config::default();
        save_to(&dir, &cfg).unwrap();
        let fence = p2b_test_fence(&cfg);
        begin_config_mutation_operation(&dir, &cfg, &fence, b"receipt").unwrap();
        fs::remove_file(dir.join(CONFIG_MUTATION_OPERATION_RECEIPT_FILE)).unwrap();
        assert_eq!(
            recover_orphan_config_mutation_operation_fence(&dir).unwrap(),
            ConfigMutationOrphanFenceRecovery::Cleared
        );

        fs::write(
            dir.join(CONFIG_MUTATION_OPERATION_RECEIPT_FILE),
            b"receipt-only-corruption",
        )
        .unwrap();
        assert_eq!(
            recover_orphan_config_mutation_operation_fence(&dir).unwrap(),
            ConfigMutationOrphanFenceRecovery::Attention
        );
        fs::remove_file(dir.join(CONFIG_MUTATION_OPERATION_RECEIPT_FILE)).unwrap();

        let drift_fence = p2b_test_fence(&cfg);
        let mut fenced = cfg.clone();
        fenced.set_config_mutation_operation_fence(&drift_fence);
        test_save_to_without_history_authority_guard(&dir, &fenced).unwrap();
        let mut drifted = fenced.without_config_mutation_operation_fence();
        drifted.pending_notice = Some("drifted".into());
        // Keep the malformed state on disk only through the test seam; the
        // recovery classifier must fail closed rather than clear the fence.
        let mut drifted_with_fence = drifted.clone();
        drifted_with_fence.set_config_mutation_operation_fence(&drift_fence);
        test_save_to_without_history_authority_guard(&dir, &drifted_with_fence).unwrap();
        assert_eq!(
            recover_orphan_config_mutation_operation_fence(&dir).unwrap(),
            ConfigMutationOrphanFenceRecovery::Attention
        );
    }

    #[test]
    fn p2b_open_fence_blocks_all_ordinary_config_writers_cross_process() {
        let dir = tmpdir();
        let cfg = Config {
            experimental_codex_enabled: true,
            ..Default::default()
        };
        save_to(&dir, &cfg).unwrap();
        let fence = p2b_test_fence(&cfg);
        begin_config_mutation_operation(&dir, &cfg, &fence, b"receipt").unwrap();

        let mut changed = cfg.clone();
        changed.pending_notice = Some("ordinary-writer".into());
        assert!(save_to(&dir, &changed).is_err());
        assert!(update(&dir, |current| {
            current.pending_notice = Some("ordinary-writer".into());
        })
        .is_err());
        assert!(update_result(&dir, |current| {
            current.pending_notice = Some("ordinary-writer".into());
            Ok(((), true))
        })
        .is_err());
        assert!(update_result_with_rolling_backup(&dir, |current| {
            current.pending_notice = Some("ordinary-writer".into());
            Ok(((), true))
        })
        .is_err());
        assert!(read_config_mutation_operation_receipt(&dir)
            .unwrap()
            .is_some());

        // A crash/corruption can leave the durable receipt without its Config
        // fence.  Admission must still fail closed under the same writer lock;
        // boot attention is not a substitute for backend enforcement.
        let no_fence = load_from(&dir)
            .unwrap()
            .without_config_mutation_operation_fence();
        test_save_to_without_history_authority_guard(&dir, &no_fence).unwrap();
        let mut receipt_only_change = no_fence.clone();
        receipt_only_change.pending_notice = Some("receipt-only-writer".into());
        assert!(save_to(&dir, &receipt_only_change).is_err());
        assert!(update_result(&dir, |current| {
            current.pending_notice = Some("receipt-only-writer".into());
            Ok(((), true))
        })
        .is_err());

        let mut disabled = no_fence.clone();
        disabled.experimental_codex_enabled = false;
        let p2a_fence = CodexDisableOperationFence::new(
            new_id(),
            "c".repeat(64),
            codex_disable_config_fingerprint(&no_fence).unwrap(),
            codex_disable_config_fingerprint(&disabled).unwrap(),
        );
        assert!(begin_codex_disable_operation(&dir, &no_fence, &p2a_fence, b"p2a").is_err());
        assert!(read_config_mutation_operation_receipt(&dir)
            .unwrap()
            .is_some());
    }
}
