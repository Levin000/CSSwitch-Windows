//! Mechanical extract from `sandbox_session` (behavior-preserving).
#[cfg(not(unix))]
use std::os::windows::fs::OpenOptionsExt as _;

#[cfg(not(unix))]
use crate::platform::UnixCompatExt;
#[cfg(not(unix))]
use crate::platform::OpenOptionsModeExt;
#[cfg(not(unix))]
use std::os::windows::fs::OpenOptionsExt as _;

use std::io::Read;
#[cfg(unix)]
use std::os::fd::AsRawFd;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use crate::runtime::science::sandbox_home;
use crate::{config, lock, SharedAppState};
use serde::{Deserialize, Serialize};

#[cfg(test)]
use super::authority_snapshot::SANDBOX_SESSION_TEST_SEAMS;
use super::authority_snapshot::{inode_u64, sync_authority_cleanup_parent, AuthorityTreeSnapshot};
pub(super) const PENDING_CLEANUP_MARKER_FILE: &str = ".csswitch-one-click-rollback.marker";
pub(super) const MAX_PENDING_CLEANUP_MANIFEST_BYTES: usize = 64 * 1024;

pub(super) fn cleanup_tombstone_name(entry: &PendingCleanupEntry) -> String {
    format!("{}.deleting", entry.managed_id)
}

pub(super) fn cleanup_tombstone_path(entry: &PendingCleanupEntry) -> PathBuf {
    entry
        .path
        .parent()
        .unwrap_or_else(|| Path::new("/"))
        .join(cleanup_tombstone_name(entry))
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PendingCleanupManifest {
    pub(super) schema_version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) disposition: Option<PendingCleanupDisposition>,
    pub(super) entries: Vec<PendingCleanupEntry>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum PendingCleanupDisposition {
    ActiveRecovery,
    CleanupOnly,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PendingCleanupEntry {
    pub(super) managed_id: String,
    pub(super) path: PathBuf,
    pub(super) device: u64,
    pub(super) inode: u64,
    pub(super) marker: String,
}

#[derive(Clone)]
pub(super) struct AuthorityCleanupContext {
    pub(super) config_dir: PathBuf,
    pub(super) expected_snapshot_parent: PathBuf,
    pub(super) managed_id: String,
    pub(super) root: PathBuf,
    pub(super) expected_root_identity: Option<(u64, u64)>,
    pub(super) state: SharedAppState,
}

pub(super) struct RegisteredAuthorityCleanup {
    pub(super) manifest_raw: Vec<u8>,
    pub(super) entry: PendingCleanupEntry,
}

#[derive(Clone)]
pub(super) struct PendingCleanupClearRetry {
    pub(super) config_dir: PathBuf,
    pub(super) manifest_raw: Vec<u8>,
    pub(super) entry: PendingCleanupEntry,
}

pub(super) static PENDING_CLEANUP_CLEAR_RETRY: std::sync::LazyLock<
    std::sync::Mutex<Option<PendingCleanupClearRetry>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(None));

pub(super) enum PendingCleanupTargetState {
    Missing,
    Present(PendingCleanupEntry),
    Unsafe,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum AuthorityCleanupPhase {
    SnapshotRegistration,
    IdentityValidation,
    Cleanup,
    Retry,
    Clear,
}

impl AuthorityCleanupPhase {
    pub(super) fn cause_code(self) -> &'static str {
        match self {
            Self::SnapshotRegistration => "authority_snapshot_registration_failed",
            Self::IdentityValidation => "authority_cleanup_identity_invalid",
            Self::Cleanup => "authority_cleanup_failed",
            Self::Retry => "authority_cleanup_retry_failed",
            Self::Clear => "authority_cleanup_clear_failed",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct AuthorityCleanupFailure {
    phase: AuthorityCleanupPhase,
    safe_detail: String,
    cleanup_required: Option<(PathBuf, &'static str)>,
}

impl AuthorityCleanupFailure {
    pub(super) fn new(phase: AuthorityCleanupPhase, safe_detail: impl Into<String>) -> Self {
        Self {
            phase,
            safe_detail: safe_detail.into(),
            cleanup_required: None,
        }
    }

    fn cleanup_required(
        phase: AuthorityCleanupPhase,
        primary: &str,
        path: &Path,
        code: &'static str,
    ) -> Self {
        Self {
            phase,
            safe_detail: format!(
                "{primary}；status=degraded；recovery_status=cleanup_required；recovery_path={}；cleanup_code={code}",
                path.display()
            ),
            cleanup_required: Some((path.to_path_buf(), code)),
        }
    }

    pub(super) fn phase(&self) -> AuthorityCleanupPhase {
        self.phase
    }

    pub(super) fn cleanup_requirement(&self) -> Option<(&Path, &'static str)> {
        self.cleanup_required
            .as_ref()
            .map(|(path, code)| (path.as_path(), *code))
    }
}

impl std::fmt::Display for AuthorityCleanupFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.safe_detail)
    }
}

impl From<AuthorityCleanupFailure> for String {
    fn from(failure: AuthorityCleanupFailure) -> Self {
        failure.safe_detail
    }
}

fn cleanup_failure(safe_detail: impl Into<String>) -> AuthorityCleanupFailure {
    AuthorityCleanupFailure::new(AuthorityCleanupPhase::Cleanup, safe_detail)
}

fn retry_failure(safe_detail: impl Into<String>) -> AuthorityCleanupFailure {
    AuthorityCleanupFailure::new(AuthorityCleanupPhase::Retry, safe_detail)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum AuthorityCleanupOutcome {
    Cleared,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PendingCleanupClearOutcome {
    Published,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PendingCleanupClearRetryOutcome {
    NotPending,
    Invalidated,
    Published,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PendingCleanupRetryOutcome {
    NotNeeded,
    Cleared,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum FinalizeAuthorityReplayOutcome {
    Ready,
    CleanupPending(PathBuf),
}

pub(super) fn cleanup_required_error(
    phase: AuthorityCleanupPhase,
    primary: &str,
    path: &Path,
    code: &'static str,
) -> AuthorityCleanupFailure {
    AuthorityCleanupFailure::cleanup_required(phase, primary, path, code)
}

pub(super) fn pending_cleanup_name_is_valid(name: &str) -> bool {
    let Some(suffix) = name.strip_prefix(".one-click-rollback-") else {
        return false;
    };
    suffix.len() == 32
        && suffix
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

pub(super) fn pending_cleanup_manifest_bytes(
    entries: Vec<PendingCleanupEntry>,
    disposition: PendingCleanupDisposition,
) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&PendingCleanupManifest {
        schema_version: 2,
        disposition: Some(disposition),
        entries,
    })
    .map_err(|_| "cleanup_manifest_encode_failed：无法编码待清理事务清单。".into())
}

pub(super) fn parse_pending_cleanup_manifest(
    bytes: &[u8],
) -> Result<PendingCleanupManifest, String> {
    if bytes.is_empty() || bytes.len() > MAX_PENDING_CLEANUP_MANIFEST_BYTES {
        return Err("cleanup_manifest_invalid：待清理事务清单大小非法，已在运行前拒绝。".into());
    }
    let manifest: PendingCleanupManifest = serde_json::from_slice(bytes)
        .map_err(|_| "cleanup_manifest_invalid：待清理事务清单格式非法，已在运行前拒绝。")?;
    let schema_valid = match manifest.schema_version {
        1 => manifest.disposition.is_none(),
        2 => manifest.disposition.is_some(),
        _ => false,
    };
    if !schema_valid || manifest.entries.len() > 1 {
        return Err(
            "cleanup_manifest_invalid：待清理事务清单版本或条目数量非法，已在运行前拒绝。".into(),
        );
    }
    Ok(manifest)
}

pub(super) fn pending_cleanup_requires_recovery(manifest: &PendingCleanupManifest) -> bool {
    manifest.disposition == Some(PendingCleanupDisposition::ActiveRecovery)
}

pub(super) fn read_marker(path: &Path) -> Result<String, AuthorityCleanupFailure> {
    let identity_error =
        |detail| AuthorityCleanupFailure::new(AuthorityCleanupPhase::IdentityValidation, detail);
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|_| identity_error("cleanup_identity_invalid：事务快照 marker 不可用。"))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.uid() != unsafe { crate::platform::geteuid() }
        || metadata.permissions().mode() & 0o777 != 0o600
        || metadata.nlink() != 1
        || metadata.len() > 256
    {
        return Err(identity_error(
            "cleanup_identity_invalid：事务快照 marker 身份不安全。",
        ));
    }
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(crate::platform::O_NOFOLLOW | crate::platform::O_CLOEXEC)
        .open(path)
        .map_err(|_| identity_error("cleanup_identity_invalid：无法安全打开事务快照 marker。"))?;
    let opened = file
        .metadata()
        .map_err(|_| identity_error("cleanup_identity_invalid：无法复核事务快照 marker。"))?;
    if opened.dev() != metadata.dev() || opened.ino() != metadata.ino() {
        return Err(identity_error(
            "cleanup_identity_changed：事务快照 marker 在读取前发生变化。",
        ));
    }
    let mut bytes = Vec::new();
    std::io::Read::take(&mut file, 257)
        .read_to_end(&mut bytes)
        .map_err(|_| identity_error("cleanup_identity_invalid：无法读取事务快照 marker。"))?;
    if bytes.len() > 256 {
        return Err(identity_error(
            "cleanup_identity_invalid：事务快照 marker 过大。",
        ));
    }
    String::from_utf8(bytes)
        .map_err(|_| identity_error("cleanup_identity_invalid：事务快照 marker 不是 UTF-8。"))
}

pub(super) fn inspect_pending_cleanup_target(
    entry: &PendingCleanupEntry,
) -> PendingCleanupTargetState {
    let (actual_path, metadata, is_tombstone) = match std::fs::symlink_metadata(&entry.path) {
        Ok(metadata) => (entry.path.clone(), metadata, false),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let tombstone = cleanup_tombstone_path(entry);
            match std::fs::symlink_metadata(&tombstone) {
                Ok(metadata) => (tombstone, metadata, true),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    return PendingCleanupTargetState::Missing
                }
                Err(_) => return PendingCleanupTargetState::Unsafe,
            }
        }
        Err(_) => return PendingCleanupTargetState::Unsafe,
    };
    let marker = match read_marker(&actual_path.join(PENDING_CLEANUP_MARKER_FILE)) {
        Ok(marker) => marker,
        Err(_) if is_tombstone => format!("{}\n", entry.marker),
        Err(_) => return PendingCleanupTargetState::Unsafe,
    };
    let marker = marker.strip_suffix('\n').unwrap_or(&marker).to_string();
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != unsafe { crate::platform::geteuid() }
        || !crate::platform::dir_mode_is_0700(&metadata)
    {
        return PendingCleanupTargetState::Unsafe;
    }
    PendingCleanupTargetState::Present(PendingCleanupEntry {
        managed_id: entry.managed_id.clone(),
        path: entry.path.clone(),
        device: metadata.dev(),
        inode: metadata.ino(),
        marker,
    })
}

pub(super) fn validate_pending_cleanup_entry(
    entry: &PendingCleanupEntry,
    expected_parent: &Path,
) -> Result<PendingCleanupTargetState, AuthorityCleanupFailure> {
    let identity_error =
        |detail| AuthorityCleanupFailure::new(AuthorityCleanupPhase::IdentityValidation, detail);
    if !pending_cleanup_name_is_valid(&entry.managed_id)
        || entry.marker != entry.managed_id
        || entry.path.parent() != Some(expected_parent)
        || entry.path.file_name().and_then(|name| name.to_str()) != Some(entry.managed_id.as_str())
    {
        return Err(identity_error(
            "cleanup_manifest_invalid：待清理事务清单路径或 managed_id 非法，已在运行前拒绝。",
        ));
    }
    match inspect_pending_cleanup_target(entry) {
        PendingCleanupTargetState::Missing => Ok(PendingCleanupTargetState::Missing),
        PendingCleanupTargetState::Present(current)
            if current.device == entry.device
                && current.inode == entry.inode
                && current.marker == entry.marker =>
        {
            Ok(PendingCleanupTargetState::Present(current))
        }
        _ => Err(identity_error(
            "cleanup_manifest_identity_mismatch：待清理事务快照身份不一致，已在运行前拒绝。",
        )),
    }
}

#[cfg(test)]
pub(super) fn test_pending_cleanup_identity(
    entry: &PendingCleanupEntry,
) -> config::PendingCleanupIdentity {
    config::PendingCleanupIdentity {
        managed_id: entry.managed_id.clone(),
        path: entry.path.clone(),
        device: entry.device,
        inode: entry.inode,
        marker: entry.marker.clone(),
    }
}

impl AuthorityCleanupContext {
    pub(super) fn new(
        config_dir: &Path,
        sandbox_home: &Path,
        state: &SharedAppState,
    ) -> Result<Self, AuthorityCleanupFailure> {
        let expected_snapshot_parent = sandbox_home
            .parent()
            .ok_or_else(|| {
                AuthorityCleanupFailure::new(
                    AuthorityCleanupPhase::SnapshotRegistration,
                    "cleanup_register_failed：沙箱 HOME 无父目录。",
                )
            })?
            .to_path_buf();
        let managed_id = format!(".one-click-rollback-{}", config::new_id());
        let root = expected_snapshot_parent.join(&managed_id);
        Ok(Self {
            config_dir: config_dir.to_path_buf(),
            expected_snapshot_parent,
            managed_id,
            root,
            expected_root_identity: None,
            state: state.clone(),
        })
    }

    pub(super) fn bind_root_identity(
        &mut self,
        entry: &crate::platform::Stat,
    ) -> Result<(), AuthorityCleanupFailure> {
        let device = u64::try_from(entry.st_dev)
            .map_err(|_| self.register_error("事务快照 device 非法。"))?;
        let inode =
            inode_u64(entry.st_ino).ok_or_else(|| self.register_error("事务快照 inode 非法。"))?;
        if entry.st_mode & crate::platform::S_IFMT != crate::platform::S_IFDIR {
            return Err(self.register_error("事务快照不是目录。"));
        }
        self.expected_root_identity = Some((device, inode));
        Ok(())
    }

    pub(super) fn register_error(&self, detail: &str) -> AuthorityCleanupFailure {
        AuthorityCleanupFailure::new(
            AuthorityCleanupPhase::SnapshotRegistration,
            format!(
                "cleanup_register_failed：{detail}；recovery_path={}",
                self.root.display()
            ),
        )
    }
}

#[allow(unreachable_code)]
pub(super) fn register_authority_cleanup(
    context: &AuthorityCleanupContext,
) -> Result<RegisteredAuthorityCleanup, AuthorityCleanupFailure> {
    // Windows 降级注册：真实注册依赖 openat 锚定的目录身份、0600/nlink marker
    // 持久化与 pending 清单 CAS 提交；降级 capture 从未创建快照目录，因此
    // 不写 pending 清单、不登记 state.pending_authority_cleanup，仅返回一张
    // 合成票据，保持 cleanup_when_expendable / registered_snapshot_ticket
    // 降级路径的类型与流程一致（票据不对应任何磁盘状态）。
    #[cfg(not(unix))]
    {
        let entry = PendingCleanupEntry {
            managed_id: context.managed_id.clone(),
            path: context.root.clone(),
            device: 0,
            inode: 0,
            marker: context.managed_id.clone(),
        };
        let manifest_raw = pending_cleanup_manifest_bytes(
            vec![entry.clone()],
            PendingCleanupDisposition::ActiveRecovery,
        )
        .map_err(|_| context.register_error("无法编码降级事务快照清单。"))?;
        return Ok(RegisteredAuthorityCleanup { manifest_raw, entry });
    }
    if context.root.parent() != Some(context.expected_snapshot_parent.as_path())
        || context.root.file_name().and_then(|name| name.to_str())
            != Some(context.managed_id.as_str())
        || !pending_cleanup_name_is_valid(&context.managed_id)
    {
        return Err(context.register_error("事务快照路径不在受管根内。"));
    }
    let parent = AuthorityTreeSnapshot::open_absolute_directory(&context.expected_snapshot_parent)
        .map_err(|_| context.register_error("事务快照父目录不可用。"))?;
    let root_name = AuthorityTreeSnapshot::destination_name(&context.root)
        .map_err(|_| context.register_error("事务快照名称非法。"))?;
    let root = AuthorityTreeSnapshot::open_directory_at(parent.as_raw_fd(), &root_name)
        .map_err(|_| context.register_error("事务快照不可用。"))?;
    let before = root
        .metadata()
        .map_err(|_| context.register_error("事务快照不可用。"))?;
    let before_entry = AuthorityTreeSnapshot::stat_destination_at(&parent, &root_name)
        .map_err(|_| context.register_error("事务快照不可用。"))?;
    let Some((expected_device, expected_inode)) = context.expected_root_identity else {
        return Err(context.register_error("事务快照创建身份缺失。"));
    };
    if !before.is_dir()
        || before.uid() != unsafe { crate::platform::geteuid() }
        || !crate::platform::dir_mode_is_0700(&before)
        || before.dev() != expected_device
        || before.ino() != expected_inode
        || !AuthorityTreeSnapshot::destination_entry_matches_file(
            &before_entry,
            &before,
            crate::platform::S_IFDIR,
        )
    {
        return Err(context.register_error("事务快照身份不安全。"));
    }
    let marker_name = std::ffi::CString::new(PENDING_CLEANUP_MARKER_FILE).unwrap();
    match AuthorityTreeSnapshot::stat_destination_at(&root, &marker_name) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut marker = AuthorityTreeSnapshot::open_destination_at(
                root.as_raw_fd(),
                &marker_name,
                crate::platform::O_WRONLY | crate::platform::O_CREAT | crate::platform::O_EXCL,
                0o600,
            )
            .map_err(|_| context.register_error("无法创建事务快照 marker。"))?;
            std::io::Write::write_all(&mut marker, format!("{}\n", context.managed_id).as_bytes())
                .and_then(|_| marker.set_permissions(crate::platform::permissions_from_mode(0o600)))
                .and_then(|_| marker.sync_all())
                .map_err(|_| context.register_error("无法持久化事务快照 marker。"))?;
            let metadata = marker
                .metadata()
                .map_err(|_| context.register_error("无法复核事务快照 marker。"))?;
            if !metadata.is_file()
                || metadata.uid() != unsafe { crate::platform::geteuid() }
                || metadata.permissions().mode() & 0o777 != 0o600
                || metadata.nlink() != 1
                || metadata.len() > 256
            {
                return Err(context.register_error("事务快照 marker 身份不安全。"));
            }
            root.sync_all()
                .and_then(|_| parent.sync_all())
                .map_err(|_| context.register_error("无法持久化事务快照目录。"))?;
        }
        Ok(_) => {
            let mut marker = AuthorityTreeSnapshot::open_destination_at(
                root.as_raw_fd(),
                &marker_name,
                crate::platform::O_RDONLY,
                0,
            )
            .map_err(|_| context.register_error("事务快照 marker 身份不安全。"))?;
            let metadata = marker
                .metadata()
                .map_err(|_| context.register_error("事务快照 marker 身份不安全。"))?;
            if !metadata.is_file()
                || metadata.uid() != unsafe { crate::platform::geteuid() }
                || metadata.permissions().mode() & 0o777 != 0o600
                || metadata.nlink() != 1
                || metadata.len() > 256
            {
                return Err(context.register_error("事务快照 marker 身份不安全。"));
            }
            let mut bytes = Vec::new();
            std::io::Read::take(&mut marker, 257)
                .read_to_end(&mut bytes)
                .map_err(|_| context.register_error("无法读取事务快照 marker。"))?;
            if bytes != format!("{}\n", context.managed_id).as_bytes() {
                return Err(context.register_error("事务快照 marker 不匹配。"));
            }
        }
        Err(_) => return Err(context.register_error("无法检查事务快照 marker。")),
    }
    let after = root
        .metadata()
        .map_err(|_| context.register_error("无法复核事务快照。"))?;
    let after_entry = AuthorityTreeSnapshot::stat_destination_at(&parent, &root_name)
        .map_err(|_| context.register_error("无法复核事务快照。"))?;
    if after.dev() != before.dev()
        || after.ino() != before.ino()
        || !after.is_dir()
        || after.uid() != unsafe { crate::platform::geteuid() }
        || !crate::platform::dir_mode_is_0700(&after)
        || !AuthorityTreeSnapshot::destination_entry_matches_file(
            &after_entry,
            &after,
            crate::platform::S_IFDIR,
        )
    {
        return Err(context.register_error("事务快照在注册期间发生变化。"));
    }
    let entry = PendingCleanupEntry {
        managed_id: context.managed_id.clone(),
        path: context.root.clone(),
        device: after.dev(),
        inode: after.ino(),
        marker: context.managed_id.clone(),
    };
    if !matches!(
        validate_pending_cleanup_entry(&entry, &context.expected_snapshot_parent),
        Ok(PendingCleanupTargetState::Present(ref current)) if current == &entry
    ) {
        return Err(context.register_error("事务快照持久化后身份复核失败。"));
    }
    #[cfg(test)]
    config::test_pending_cleanup_register_publish_attempt(test_pending_cleanup_identity(&entry))
        .map_err(|_| context.register_error("待清理事务清单 REGISTER 发布失败。"))?;
    let previous = config::read_pending_authority_cleanup_manifest(&context.config_dir)
        .map_err(|_| context.register_error("无法读取待清理事务清单。"))?;
    if let Some(bytes) = previous.as_deref() {
        let existing = parse_pending_cleanup_manifest(bytes)
            .map_err(|_| context.register_error("现有待清理事务清单非法。"))?;
        if !existing.entries.is_empty() && existing.entries != [entry.clone()] {
            return Err(context.register_error("已有不同的待清理事务快照。"));
        }
    }
    let manifest_raw = pending_cleanup_manifest_bytes(
        vec![entry.clone()],
        PendingCleanupDisposition::ActiveRecovery,
    )
    .map_err(|_| context.register_error("无法编码待清理事务清单。"))?;
    let publish = match previous.as_deref() {
        Some(expected) => config::write_pending_authority_cleanup_manifest(
            &context.config_dir,
            &manifest_raw,
            Some(expected),
        ),
        None => config::write_pending_authority_cleanup_manifest_if_absent(
            &context.config_dir,
            &manifest_raw,
        ),
    };
    publish.map_err(|_| context.register_error("无法原子提交待清理事务清单。"))?;
    let mut current = lock(&context.state);
    if !current
        .pending_authority_cleanup
        .iter()
        .any(|pending| pending == &context.root)
    {
        current.pending_authority_cleanup.push(context.root.clone());
    }
    Ok(RegisteredAuthorityCleanup {
        manifest_raw,
        entry,
    })
}

pub(super) fn finalize_failed_authority_snapshot(
    context: &AuthorityCleanupContext,
    primary: String,
) -> String {
    let cleanup = register_authority_cleanup(context)
        .and_then(|ticket| prepare_registered_authority_cleanup(context, &ticket))
        .and_then(|ticket| finalize_registered_authority_cleanup(context, &ticket));
    match cleanup {
        Ok(AuthorityCleanupOutcome::Cleared) => primary,
        Err(cleanup_error) => format!("{primary}；{cleanup_error}"),
    }
}

pub(super) fn publish_pending_cleanup_clear(
    state: &SharedAppState,
    config_dir: &Path,
    manifest_raw: &[u8],
    entry: &PendingCleanupEntry,
    observe_recovery: bool,
) -> Result<PendingCleanupClearOutcome, AuthorityCleanupFailure> {
    #[cfg(not(test))]
    let _ = observe_recovery;
    let empty = pending_cleanup_manifest_bytes(Vec::new(), PendingCleanupDisposition::CleanupOnly)
        .map_err(|error| AuthorityCleanupFailure::new(AuthorityCleanupPhase::Clear, error))?;
    config::write_pending_authority_cleanup_manifest(config_dir, &empty, Some(manifest_raw))
        .map_err(|_| {
            cleanup_required_error(
                AuthorityCleanupPhase::Clear,
                "待清理事务快照已移除，但清单 CLEAR 未提交",
                &entry.path,
                "cleanup_clear_failed",
            )
        })?;
    #[cfg(test)]
    if observe_recovery {
        config::test_observe_pending_cleanup_clear_published();
    }
    lock(state)
        .pending_authority_cleanup
        .retain(|pending| pending != &entry.path);
    *PENDING_CLEANUP_CLEAR_RETRY
        .lock()
        .unwrap_or_else(|error| error.into_inner()) = None;
    Ok(PendingCleanupClearOutcome::Published)
}

pub(super) fn retry_completed_pending_cleanup_clear(
    state: &SharedAppState,
) -> Result<PendingCleanupClearRetryOutcome, AuthorityCleanupFailure> {
    let retry = PENDING_CLEANUP_CLEAR_RETRY
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .clone();
    let Some(retry) = retry else {
        return Ok(PendingCleanupClearRetryOutcome::NotPending);
    };
    let current =
        config::read_pending_authority_cleanup_manifest(&retry.config_dir).map_err(|_| {
            AuthorityCleanupFailure::new(
                AuthorityCleanupPhase::Retry,
                "cleanup_manifest_read_failed：无法读取待清理事务清单。",
            )
        })?;
    if current.as_deref() != Some(retry.manifest_raw.as_slice())
        || !matches!(
            inspect_pending_cleanup_target(&retry.entry),
            PendingCleanupTargetState::Missing
        )
    {
        *PENDING_CLEANUP_CLEAR_RETRY
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = None;
        return Ok(PendingCleanupClearRetryOutcome::Invalidated);
    }
    publish_pending_cleanup_clear(
        state,
        &retry.config_dir,
        &retry.manifest_raw,
        &retry.entry,
        true,
    )?;
    Ok(PendingCleanupClearRetryOutcome::Published)
}

#[allow(unreachable_code)]
pub(super) fn finalize_registered_authority_cleanup(
    context: &AuthorityCleanupContext,
    ticket: &RegisteredAuthorityCleanup,
) -> Result<AuthorityCleanupOutcome, AuthorityCleanupFailure> {
    // Windows 降级 finalize：降级模式下没有快照目录可删除、没有 pending
    // 清单需要 CLEAR，也没有可复验的 dev/inode 身份；直接视为已清理。
    #[cfg(not(unix))]
    {
        let _ = (context, ticket);
        return Ok(AuthorityCleanupOutcome::Cleared);
    }
    let manifest_raw = config::read_pending_authority_cleanup_manifest(&context.config_dir)
        .map_err(|_| {
            cleanup_failure("cleanup_manifest_read_failed：无法安全读取刚注册的待清理事务清单。")
        })?
        .ok_or_else(|| {
            cleanup_failure("cleanup_manifest_missing：刚注册的待清理事务清单不存在。")
        })?;
    if manifest_raw != ticket.manifest_raw {
        return Err(cleanup_failure(
            "cleanup_manifest_causal_mismatch：刚注册的待清理事务清单字节票据不匹配。",
        ));
    }
    let manifest = parse_pending_cleanup_manifest(&manifest_raw).map_err(cleanup_failure)?;
    if manifest.entries.len() != 1 || manifest.entries.first() != Some(&ticket.entry) {
        return Err(cleanup_failure(
            "cleanup_manifest_causal_mismatch：刚注册的待清理事务清单因果票据不匹配。",
        ));
    }
    if pending_cleanup_requires_recovery(&manifest) {
        return Err(cleanup_failure(
            "cleanup_manifest_active_recovery：活动恢复快照未转换为 cleanup-only，拒绝删除。",
        ));
    }
    match validate_pending_cleanup_entry(&ticket.entry, &context.expected_snapshot_parent)? {
        PendingCleanupTargetState::Present(actual) if actual == ticket.entry => {}
        _ => {
            return Err(AuthorityCleanupFailure::new(
                AuthorityCleanupPhase::IdentityValidation,
                "cleanup_identity_changed：刚注册的事务快照在删除前发生变化，已停止清理。",
            ))
        }
    }
    if remove_authority_snapshot_root_with_retry(&ticket.entry, &context.expected_snapshot_parent)
        .is_err()
    {
        return Err(cleanup_required_error(
            AuthorityCleanupPhase::Cleanup,
            "one-click 事务快照仍无法清理",
            &ticket.entry.path,
            "cleanup_remove_failed",
        ));
    }
    if !matches!(
        inspect_pending_cleanup_target(&ticket.entry),
        PendingCleanupTargetState::Missing
    ) {
        return Err(AuthorityCleanupFailure::new(
            AuthorityCleanupPhase::IdentityValidation,
            "cleanup_identity_changed：刚注册的事务快照删除后仍存在，已停止清理。",
        ));
    }
    publish_pending_cleanup_clear(
        &context.state,
        &context.config_dir,
        &manifest_raw,
        &ticket.entry,
        false,
    )?;
    Ok(AuthorityCleanupOutcome::Cleared)
}

#[allow(unreachable_code)]
pub(super) fn prepare_registered_authority_cleanup(
    context: &AuthorityCleanupContext,
    ticket: &RegisteredAuthorityCleanup,
) -> Result<RegisteredAuthorityCleanup, AuthorityCleanupFailure> {
    // Windows 降级 prepare：ActiveRecovery -> CleanupOnly 是 pending 清单的
    // CAS 转换；降级模式没有清单，票据原样透传（身份字段不变）。
    #[cfg(not(unix))]
    {
        let _ = context;
        return Ok(RegisteredAuthorityCleanup {
            manifest_raw: ticket.manifest_raw.clone(),
            entry: ticket.entry.clone(),
        });
    }
    let current = config::read_pending_authority_cleanup_manifest(&context.config_dir)
        .map_err(|_| cleanup_failure("cleanup_manifest_read_failed：无法读取活动恢复快照清单。"))?
        .ok_or_else(|| cleanup_failure("cleanup_manifest_missing：活动恢复快照清单不存在。"))?;
    if current != ticket.manifest_raw {
        return Err(cleanup_failure(
            "cleanup_manifest_causal_mismatch：活动恢复快照清单字节票据不匹配。",
        ));
    }
    let manifest = parse_pending_cleanup_manifest(&current).map_err(cleanup_failure)?;
    if manifest.entries.len() != 1 || manifest.entries.first() != Some(&ticket.entry) {
        return Err(cleanup_failure(
            "cleanup_manifest_causal_mismatch：活动恢复快照清单因果票据不匹配。",
        ));
    }
    let cleanup_only = pending_cleanup_manifest_bytes(
        vec![ticket.entry.clone()],
        PendingCleanupDisposition::CleanupOnly,
    )
    .map_err(cleanup_failure)?;
    #[cfg(test)]
    config::test_pending_cleanup_prepare_publish_attempt().map_err(|_| {
        cleanup_required_error(
            AuthorityCleanupPhase::Cleanup,
            "无法把活动恢复快照原子转换为 cleanup-only",
            &ticket.entry.path,
            "cleanup_prepare_failed",
        )
    })?;
    config::write_pending_authority_cleanup_manifest(
        &context.config_dir,
        &cleanup_only,
        Some(&current),
    )
    .map_err(|_| {
        cleanup_required_error(
            AuthorityCleanupPhase::Cleanup,
            "无法把活动恢复快照原子转换为 cleanup-only",
            &ticket.entry.path,
            "cleanup_prepare_failed",
        )
    })?;
    Ok(RegisteredAuthorityCleanup {
        manifest_raw: cleanup_only,
        entry: ticket.entry.clone(),
    })
}

pub(super) fn retry_pending_authority_cleanup(
    state: &SharedAppState,
) -> Result<PendingCleanupRetryOutcome, AuthorityCleanupFailure> {
    if matches!(
        retry_completed_pending_cleanup_clear(state)?,
        PendingCleanupClearRetryOutcome::Published
    ) {
        return Ok(PendingCleanupRetryOutcome::Cleared);
    }
    let config_dir = config::default_dir();
    let Some(manifest_raw) = config::read_pending_authority_cleanup_manifest(&config_dir)
        .map_err(|_| retry_failure("cleanup_manifest_read_failed：无法安全读取待清理事务清单。"))?
    else {
        return Ok(PendingCleanupRetryOutcome::NotNeeded);
    };
    let manifest = parse_pending_cleanup_manifest(&manifest_raw).map_err(retry_failure)?;
    if manifest.entries.is_empty() {
        lock(state).pending_authority_cleanup.clear();
        return Ok(PendingCleanupRetryOutcome::NotNeeded);
    }
    let recovery_snapshot = pending_cleanup_requires_recovery(&manifest);
    let sandbox_home_path = sandbox_home();
    let expected_parent = sandbox_home_path
        .parent()
        .ok_or_else(|| retry_failure("cleanup_manifest_invalid：沙箱 HOME 无父目录。"))?;
    let entry = manifest
        .entries
        .into_iter()
        .next()
        .ok_or_else(|| retry_failure("cleanup_manifest_invalid：待清理事务清单缺少条目。"))?;
    let initial = validate_pending_cleanup_entry(&entry, expected_parent)?;
    #[cfg(test)]
    config::test_observe_pending_cleanup_manifest_validated(test_pending_cleanup_identity(&entry));
    {
        let mut current = lock(state);
        if !current
            .pending_authority_cleanup
            .iter()
            .any(|pending| pending == &entry.path)
        {
            current.pending_authority_cleanup.push(entry.path.clone());
        }
    }
    if recovery_snapshot {
        return Err(cleanup_required_error(
            AuthorityCleanupPhase::Retry,
            "检测到中断的 one-click authority 事务；活动恢复快照尚未转换为 cleanup-only，已拒绝自动删除",
            &entry.path,
            "authority_snapshot_recovery_required",
        ));
    }
    let active_transaction = config::load_from(&config_dir)
        .map_err(|error| {
            retry_failure(format!(
                "cleanup_manifest_read_failed：无法读取运行事务：{error}"
            ))
        })?
        .runtime_transaction;
    if active_transaction
        .as_ref()
        .is_some_and(|journal| journal.requires_snapshot_preservation())
    {
        return Err(cleanup_required_error(
            AuthorityCleanupPhase::Retry,
            "检测到中断的 one-click authority 事务；已保留精确注册的私有快照，拒绝自动删除或把部分写入态当作新基线",
            &entry.path,
            "authority_snapshot_recovery_required",
        ));
    }
    #[cfg(test)]
    config::test_observe_pending_cleanup_initial_ticket(match &initial {
        PendingCleanupTargetState::Present(_) => {
            config::PendingCleanupInitialTicket::Present(test_pending_cleanup_identity(&entry))
        }
        PendingCleanupTargetState::Missing => {
            config::PendingCleanupInitialTicket::Missing(test_pending_cleanup_identity(&entry))
        }
        PendingCleanupTargetState::Unsafe => unreachable!(),
    });
    #[cfg(test)]
    config::test_pending_cleanup_race_hook()
        .map_err(|_| retry_failure("cleanup_race_hook_failed：待清理事务快照复核失败。"))?;
    let current = inspect_pending_cleanup_target(&entry);
    let completed = match (&initial, &current) {
        (PendingCleanupTargetState::Present(_), PendingCleanupTargetState::Present(actual))
            if actual == &entry =>
        {
            #[cfg(test)]
            config::test_observe_pending_cleanup_delete_attempt();
            if remove_authority_snapshot_root_with_retry(&entry, expected_parent).is_err() {
                #[cfg(test)]
                config::test_observe_pending_cleanup_completion(
                    config::PendingCleanupRemovalOutcome::Error,
                    config::PendingCleanupFinalState::Present(test_pending_cleanup_identity(
                        &entry,
                    )),
                );
                return Err(cleanup_required_error(
                    AuthorityCleanupPhase::Retry,
                    "待清理 one-click 事务快照仍无法清理",
                    &entry.path,
                    "cleanup_remove_failed",
                ));
            }
            matches!(
                inspect_pending_cleanup_target(&entry),
                PendingCleanupTargetState::Missing
            )
        }
        (PendingCleanupTargetState::Missing, PendingCleanupTargetState::Missing) => true,
        _ => false,
    };
    if !completed {
        #[cfg(test)]
        config::test_observe_pending_cleanup_completion(
            config::PendingCleanupRemovalOutcome::Error,
            match current {
                PendingCleanupTargetState::Missing => config::PendingCleanupFinalState::NotFound,
                PendingCleanupTargetState::Present(actual) => {
                    config::PendingCleanupFinalState::Present(test_pending_cleanup_identity(
                        &actual,
                    ))
                }
                PendingCleanupTargetState::Unsafe => config::PendingCleanupFinalState::Error,
            },
        );
        return Err(AuthorityCleanupFailure::new(
            AuthorityCleanupPhase::IdentityValidation,
            "cleanup_identity_changed：待清理事务快照在删除前后发生变化，已停止运行。",
        ));
    }
    #[cfg(test)]
    config::test_observe_pending_cleanup_completion(
        match initial {
            PendingCleanupTargetState::Present(_) => config::PendingCleanupRemovalOutcome::Removed,
            PendingCleanupTargetState::Missing => {
                config::PendingCleanupRemovalOutcome::AlreadyAbsent
            }
            PendingCleanupTargetState::Unsafe => unreachable!(),
        },
        config::PendingCleanupFinalState::NotFound,
    );
    *PENDING_CLEANUP_CLEAR_RETRY
        .lock()
        .unwrap_or_else(|error| error.into_inner()) = Some(PendingCleanupClearRetry {
        config_dir: config_dir.clone(),
        manifest_raw: manifest_raw.clone(),
        entry: entry.clone(),
    });
    publish_pending_cleanup_clear(state, &config_dir, &manifest_raw, &entry, true)?;
    Ok(PendingCleanupRetryOutcome::Cleared)
}

pub(super) fn replay_finalize_authority_cleanup(
    state: &SharedAppState,
    snapshot_ticket: &config::RuntimeSnapshotTicket,
) -> Result<FinalizeAuthorityReplayOutcome, AuthorityCleanupFailure> {
    let config_dir = config::default_dir();
    let Some(manifest_raw) =
        config::read_pending_authority_cleanup_manifest(&config_dir).map_err(|_| {
            retry_failure("cleanup_manifest_read_failed：无法读取 finalize authority 清单。")
        })?
    else {
        return Err(retry_failure(
            "cleanup_manifest_missing：finalize intent 存在时必须保留 authority 清单完成证据。",
        ));
    };
    let manifest = parse_pending_cleanup_manifest(&manifest_raw).map_err(retry_failure)?;
    if manifest.entries.is_empty() {
        return if manifest.schema_version == 2
            && manifest.disposition == Some(PendingCleanupDisposition::CleanupOnly)
        {
            Ok(FinalizeAuthorityReplayOutcome::Ready)
        } else {
            Err(retry_failure(
                "cleanup_manifest_incomplete：只有空的 cleanup-only 清单可证明 finalize authority 已完成。",
            ))
        };
    }
    if manifest.entries.len() != 1 {
        return Err(retry_failure(
            "cleanup_manifest_invalid：finalize authority 清单必须恰好包含一个快照。",
        ));
    }
    let entry = manifest.entries[0].clone();
    if entry.managed_id != snapshot_ticket.managed_id || entry.marker != entry.managed_id {
        return Err(retry_failure(
            "cleanup_manifest_causal_mismatch：finalize intent 与 authority 快照票据不一致。",
        ));
    }
    let sandbox_home_path = sandbox_home();
    let expected_parent = sandbox_home_path
        .parent()
        .ok_or_else(|| retry_failure("cleanup_manifest_invalid：沙箱 HOME 无父目录。"))?
        .to_path_buf();
    match validate_pending_cleanup_entry(&entry, &expected_parent)? {
        PendingCleanupTargetState::Present(actual) if actual == entry => {}
        PendingCleanupTargetState::Missing if !pending_cleanup_requires_recovery(&manifest) => {}
        _ => {
            return Err(AuthorityCleanupFailure::new(
                AuthorityCleanupPhase::IdentityValidation,
                "cleanup_identity_changed：finalize authority 快照身份不再匹配。",
            ))
        }
    }
    if pending_cleanup_requires_recovery(&manifest) {
        let context = AuthorityCleanupContext {
            config_dir: config_dir.clone(),
            expected_snapshot_parent: expected_parent,
            managed_id: entry.managed_id.clone(),
            root: entry.path.clone(),
            expected_root_identity: Some((entry.device, entry.inode)),
            state: state.clone(),
        };
        let registered = RegisteredAuthorityCleanup {
            manifest_raw,
            entry: entry.clone(),
        };
        prepare_registered_authority_cleanup(&context, &registered)?;
    }
    match retry_pending_authority_cleanup(state) {
        Ok(_) => Ok(FinalizeAuthorityReplayOutcome::Ready),
        Err(error) if error.cleanup_requirement().is_some() => {
            Ok(FinalizeAuthorityReplayOutcome::CleanupPending(entry.path))
        }
        Err(error) => Err(error),
    }
}

pub(super) fn registered_authority_snapshot_for_ticket(
    state: &SharedAppState,
    snapshot_ticket: &config::RuntimeSnapshotTicket,
) -> Result<
    (
        PendingCleanupManifest,
        AuthorityCleanupContext,
        RegisteredAuthorityCleanup,
        std::fs::File,
    ),
    AuthorityCleanupFailure,
> {
    let config_dir = config::default_dir();
    let manifest_raw = config::read_pending_authority_cleanup_manifest(&config_dir)
        .map_err(|_| {
            retry_failure("cleanup_manifest_read_failed：无法读取 history authority 清单。")
        })?
        .ok_or_else(|| {
            retry_failure("cleanup_manifest_missing：history journal 缺少 authority 清单。")
        })?;
    let manifest = parse_pending_cleanup_manifest(&manifest_raw).map_err(retry_failure)?;
    if manifest.entries.len() != 1 {
        return Err(retry_failure(
            "cleanup_manifest_invalid：history authority 清单必须恰好包含一个快照。",
        ));
    }
    let entry = manifest.entries[0].clone();
    if entry.managed_id != snapshot_ticket.managed_id || entry.marker != entry.managed_id {
        return Err(retry_failure(
            "cleanup_manifest_causal_mismatch：history journal 与 authority 快照不匹配。",
        ));
    }
    let sandbox_home_path = sandbox_home();
    let expected_parent = sandbox_home_path
        .parent()
        .ok_or_else(|| retry_failure("cleanup_manifest_invalid：沙箱 HOME 无父目录。"))?
        .to_path_buf();
    match validate_pending_cleanup_entry(&entry, &expected_parent)? {
        PendingCleanupTargetState::Present(actual) if actual == entry => {}
        _ => {
            return Err(retry_failure(
                "cleanup_identity_changed：history authority 快照身份不再匹配。",
            ))
        }
    }
    let parent =
        AuthorityTreeSnapshot::open_absolute_directory(&expected_parent).map_err(|_| {
            retry_failure("cleanup_identity_invalid：无法打开 history snapshot 父目录。")
        })?;
    let root_name = AuthorityTreeSnapshot::destination_name(&entry.path)
        .map_err(|_| retry_failure("cleanup_identity_invalid：history snapshot 名称非法。"))?;
    let root = AuthorityTreeSnapshot::open_directory_at(parent.as_raw_fd(), &root_name)
        .map_err(|_| retry_failure("cleanup_identity_invalid：无法打开 history snapshot。"))?;
    let metadata = root
        .metadata()
        .map_err(|_| retry_failure("cleanup_identity_invalid：无法复核 history snapshot。"))?;
    if !metadata.is_dir()
        || metadata.uid() != unsafe { crate::platform::geteuid() }
        || !crate::platform::dir_mode_is_0700(&metadata)
        || metadata.dev() != entry.device
        || metadata.ino() != entry.inode
    {
        return Err(retry_failure(
            "cleanup_identity_changed：history snapshot root 身份已变化。",
        ));
    }
    let context = AuthorityCleanupContext {
        config_dir,
        expected_snapshot_parent: expected_parent,
        managed_id: entry.managed_id.clone(),
        root: entry.path.clone(),
        expected_root_identity: Some((entry.device, entry.inode)),
        state: state.clone(),
    };
    let registered = RegisteredAuthorityCleanup {
        manifest_raw,
        entry,
    };
    Ok((manifest, context, registered, root))
}

pub(super) struct HistorySnapshotRoot {
    pub(super) root: std::fs::File,
    pub(super) active_recovery: bool,
}

pub(super) fn open_history_snapshot_root(
    state: &SharedAppState,
    snapshot_ticket: &config::RuntimeSnapshotTicket,
) -> Result<HistorySnapshotRoot, AuthorityCleanupFailure> {
    let (manifest, _, _, root) = registered_authority_snapshot_for_ticket(state, snapshot_ticket)?;
    if !pending_cleanup_requires_recovery(&manifest)
        && manifest.disposition != Some(PendingCleanupDisposition::CleanupOnly)
    {
        return Err(AuthorityCleanupFailure::new(
            AuthorityCleanupPhase::Retry,
            "cleanup_manifest_invalid：history snapshot disposition 非法。",
        ));
    }
    Ok(HistorySnapshotRoot {
        root,
        active_recovery: pending_cleanup_requires_recovery(&manifest),
    })
}

pub(super) fn prepare_history_snapshot_cleanup_only(
    state: &SharedAppState,
    snapshot_ticket: &config::RuntimeSnapshotTicket,
) -> Result<(), AuthorityCleanupFailure> {
    let (manifest, context, registered, _) =
        registered_authority_snapshot_for_ticket(state, snapshot_ticket)?;
    if pending_cleanup_requires_recovery(&manifest) {
        prepare_registered_authority_cleanup(&context, &registered)?;
    } else if manifest.disposition != Some(PendingCleanupDisposition::CleanupOnly) {
        return Err(AuthorityCleanupFailure::new(
            AuthorityCleanupPhase::Retry,
            "cleanup_manifest_invalid：history cleanup disposition 非法。",
        ));
    }
    Ok(())
}

pub(super) fn replay_compensation_snapshot_cleanup(
    state: &SharedAppState,
    snapshot_ticket: &config::RuntimeSnapshotTicket,
) -> Result<(), AuthorityCleanupFailure> {
    let config_dir = config::default_dir();
    let manifest_raw =
        config::read_pending_authority_cleanup_manifest(&config_dir).map_err(|_| {
            retry_failure("cleanup_manifest_read_failed：无法读取 compensation authority 清单。")
        })?;
    if let Some(raw) = manifest_raw.as_deref() {
        let manifest = parse_pending_cleanup_manifest(raw).map_err(retry_failure)?;
        if manifest.entries.is_empty() {
            if !pending_cleanup_name_is_valid(&snapshot_ticket.managed_id) {
                return Err(retry_failure(
                    "cleanup_manifest_causal_mismatch：compensation snapshot ticket 非法。",
                ));
            }
            let sandbox_home_path = sandbox_home();
            let expected_parent = sandbox_home_path
                .parent()
                .ok_or_else(|| retry_failure("cleanup_manifest_invalid：沙箱 HOME 无父目录。"))?;
            let path = expected_parent.join(&snapshot_ticket.managed_id);
            let tombstone =
                expected_parent.join(format!("{}.deleting", snapshot_ticket.managed_id));
            if !path.exists() && !tombstone.exists() {
                return Ok(());
            }
            return Err(retry_failure(
                "cleanup_identity_changed：compensation 清单已空但 snapshot 仍存在。",
            ));
        }
    }
    let (manifest, context, registered, _) =
        registered_authority_snapshot_for_ticket(state, snapshot_ticket)?;
    if pending_cleanup_requires_recovery(&manifest) {
        prepare_registered_authority_cleanup(&context, &registered)?;
    } else if manifest.disposition != Some(PendingCleanupDisposition::CleanupOnly) {
        return Err(retry_failure(
            "cleanup_manifest_invalid：compensation snapshot disposition 非法。",
        ));
    }
    retry_pending_authority_cleanup(state).map(|_| ())
}

// Snapshot root removal (uses authority FS primitives; owned by cleanup lifecycle).
pub(super) fn remove_authority_snapshot_root(
    entry: &PendingCleanupEntry,
    expected_parent: &Path,
) -> std::io::Result<()> {
    let path = &entry.path;
    #[cfg(test)]
    {
        let observation = {
            let mut seams = SANDBOX_SESSION_TEST_SEAMS
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            let configured = seams
                .cleanup_fault
                .as_ref()
                .filter(|(scope, _, _)| path.starts_with(scope))
                .cloned();
            configured.map(|(_, mode, log_path)| {
                let attempt = seams.cleanup_calls;
                seams.cleanup_calls += 1;
                let injected = mode == "persistent" || (mode == "once" && attempt == 0);
                (attempt, injected, log_path)
            })
        };
        if let Some((attempt, injected, log_path)) = observation {
            if let Ok(mut log) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(log_path)
            {
                use std::io::Write;
                let _ = writeln!(
                    log,
                    "{}\t{}\t{}",
                    attempt + 1,
                    if injected { "injected" } else { "real" },
                    path.display()
                );
            }
            if injected {
                return Err(std::io::Error::other(
                    "test-only authority snapshot cleanup failure",
                ));
            }
        }
    }
    let parent = AuthorityTreeSnapshot::open_absolute_directory(expected_parent)?;
    let name = AuthorityTreeSnapshot::destination_name(path).map_err(std::io::Error::other)?;
    let tombstone_name = std::ffi::CString::new(cleanup_tombstone_name(entry))
        .map_err(|_| std::io::Error::other("invalid cleanup tombstone name"))?;
    let inspect =
        |name: &std::ffi::CStr| match AuthorityTreeSnapshot::stat_destination_at(&parent, name) {
            Ok(value) => Ok(Some(value)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        };
    let identity_matches = |current: &crate::platform::Stat| {
        current.st_mode & crate::platform::S_IFMT == crate::platform::S_IFDIR
            && u64::try_from(current.st_dev).ok() == Some(entry.device)
            && inode_u64(current.st_ino) == Some(entry.inode)
            && u32::from(current.st_mode) & 0o777 == 0o700
            && current.st_uid == unsafe { crate::platform::geteuid() }
    };
    match (inspect(&name)?, inspect(&tombstone_name)?) {
        (None, None) => return sync_authority_cleanup_parent(&parent),
        (Some(current), None) if identity_matches(&current) => {
            #[cfg(unix)]
            let renamed = unsafe {
                libc::renameat(
                    parent.as_raw_fd(),
                    name.as_ptr(),
                    parent.as_raw_fd(),
                    tombstone_name.as_ptr(),
                )
            };
            // Windows 降级：renameat 无等价物；该分支只会经上游 Unsupported 错误到达。
            #[cfg(not(unix))]
            let renamed: i32 = -1;
            if renamed != 0 {
                return Err(std::io::Error::last_os_error());
            }
            sync_authority_cleanup_parent(&parent)?;
        }
        (None, Some(current)) if identity_matches(&current) => {
            sync_authority_cleanup_parent(&parent)?;
        }
        _ => {
            return Err(std::io::Error::other(
                "authority snapshot cleanup identity changed",
            ))
        }
    }
    let tombstone = AuthorityTreeSnapshot::stat_destination_at(&parent, &tombstone_name)?;
    if !identity_matches(&tombstone) {
        return Err(std::io::Error::other(
            "authority snapshot cleanup tombstone identity changed",
        ));
    }
    AuthorityTreeSnapshot::remove_tree_at(&parent, &tombstone_name)?;
    sync_authority_cleanup_parent(&parent)
}

pub(super) fn remove_authority_snapshot_root_with_retry(
    entry: &PendingCleanupEntry,
    expected_parent: &Path,
) -> Result<(), String> {
    match remove_authority_snapshot_root(entry, expected_parent) {
        Ok(()) => Ok(()),
        Err(first) => remove_authority_snapshot_root(entry, expected_parent)
            .map_err(|second| format!("首次清理失败：{first}；重试清理失败：{second}")),
    }
}
