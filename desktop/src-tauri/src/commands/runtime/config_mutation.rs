//! P2-B ordinary Config mutation receipts.
//!
//! This module deliberately owns only the credential-free operation contract
//! and orchestration shared by ordinary Desktop writers.  One-click/History,
//! P2-A Codex disable, Gateway auth storage, and Skill ledgers retain their
//! own authority and wire formats.

#[cfg(not(unix))]
use std::os::windows::fs::OpenOptionsExt as _;

#[cfg(not(unix))]
use crate::platform::UnixCompatExt;
#[cfg(not(unix))]
use crate::platform::OpenOptionsModeExt;
#[cfg(not(unix))]
use std::os::windows::fs::OpenOptionsExt as _;

use std::fs::OpenOptions;
use std::io::Read;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::config::{
    self, Config, ConfigMutationOperationFence, ConfigMutationTerminalConfigImage,
};

pub(crate) const RECEIPT_SCHEMA_VERSION: u32 = 1;
const INTENT_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ConfigMutationOperation {
    SetModeOfficial,
    SetSettingsDestructive,
    CodexAuthStart,
    CodexAuthLogout,
    SetCodexNetwork,
    ClearAppliedProfileKey,
    DeleteAppliedProfile,
}

impl ConfigMutationOperation {
    pub(crate) const ALL: [Self; 7] = [
        Self::SetModeOfficial,
        Self::SetSettingsDestructive,
        Self::CodexAuthStart,
        Self::CodexAuthLogout,
        Self::SetCodexNetwork,
        Self::ClearAppliedProfileKey,
        Self::DeleteAppliedProfile,
    ];

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::SetModeOfficial => "set_mode_official",
            Self::SetSettingsDestructive => "set_settings_destructive",
            Self::CodexAuthStart => "codex_auth_start",
            Self::CodexAuthLogout => "codex_auth_logout",
            Self::SetCodexNetwork => "set_codex_network",
            Self::ClearAppliedProfileKey => "clear_applied_profile_key",
            Self::DeleteAppliedProfile => "delete_applied_profile",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|operation| operation.as_str() == value)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ConfigMutationEffectKind {
    StopScience,
    StopGateway,
    WriteSshBridgeConfig,
    DeleteSshBridgeSidecar,
    DeleteManagedSshStub,
    AuthSidecar,
    AuthGenerationCommit,
    AuthSecretCleanupObservation,
    ConfigCommit,
    DeleteRollingBackup,
    ProfileEnsure,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ConfigMutationEffectState {
    Pending,
    InProgress,
    Succeeded,
    Failed,
    Uncertain,
    Skipped,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ConfigReference {
    pub(crate) schema_version: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) active_profile_id_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) runtime_binding_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) proxy_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) sandbox_port: Option<u16>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MutationTarget {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) proxy_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) sandbox_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) reuse_system_ssh: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) profile_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) network_fingerprint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) auth_epoch: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) auth_generation: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) auth_account_hash: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RuntimePlan {
    pub(crate) owner_generation: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) science_prior_recipe: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) science_restore_launch_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) gateway_identity: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) gateway_profile_id_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) gateway_restore_launch_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AuthSidecarIdentity {
    pub(crate) pid: u32,
    pub(crate) process_start: String,
    pub(crate) executable_fingerprint: String,
    pub(crate) process_group_id: i32,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AuthOperationReceipt {
    pub(crate) auth_operation_id: String,
    pub(crate) supervisor_sequence: u64,
    pub(crate) state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) start_authorization_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) sidecar: Option<AuthSidecarIdentity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) terminal_auth_epoch: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) terminal_auth_generation: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) terminal_account_hash: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AssetIdentity {
    pub(crate) uid: u32,
    pub(crate) device: u64,
    pub(crate) inode: u64,
    pub(crate) mode: u32,
    pub(crate) nlink: u64,
    pub(crate) length: u64,
    pub(crate) digest: String,
}

pub(crate) fn capture_asset_identity(path: &Path) -> Result<Option<AssetIdentity>, String> {
    let mut file = match OpenOptions::new()
        .read(true)
        .custom_flags(crate::platform::O_NOFOLLOW | crate::platform::O_NONBLOCK | crate::platform::O_CLOEXEC)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("无法安全读取 SSH leaf identity：{error}")),
    };
    let metadata = file
        .metadata()
        .map_err(|error| format!("无法检查 SSH leaf identity：{error}"))?;
    // SAFETY: geteuid has no preconditions and does not dereference pointers.
    let uid = unsafe { crate::platform::geteuid() };
    if !metadata.is_file()
        || metadata.uid() != uid
        || metadata.nlink() != 1
        || metadata.len() > 1024 * 1024
    {
        return Err("SSH leaf 不是当前用户拥有的单链接有界普通文件".into());
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.read_to_end(&mut bytes)
        .map_err(|error| format!("无法读取 SSH leaf identity：{error}"))?;
    if bytes.len() as u64 != metadata.len() {
        return Err("SSH leaf 在 identity 读取期间长度变化".into());
    }
    Ok(Some(AssetIdentity {
        uid: metadata.uid(),
        device: metadata.dev(),
        inode: metadata.ino(),
        mode: metadata.permissions().mode() & 0o777,
        nlink: metadata.nlink(),
        length: metadata.len(),
        digest: digest_bytes(b"csswitch-p2b-ssh-leaf-v1\0", bytes),
    }))
}

pub(crate) fn require_asset_absent(path: &Path) -> Result<(), String> {
    match capture_asset_identity(path)? {
        None => Ok(()),
        Some(_) => Err("SSH leaf 删除后的 exact absence 回读失败".into()),
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SshLeafReceipt {
    pub(crate) before_identity_or_absent: Option<AssetIdentity>,
    pub(crate) expected_after: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) observed_after_identity_or_absent: Option<AssetIdentity>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SshPlan {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) bridge_config: Option<SshLeafReceipt>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) bridge_sidecar: Option<SshLeafReceipt>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) managed_stub: Option<SshLeafReceipt>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EffectReceipt {
    pub(crate) kind: ConfigMutationEffectKind,
    pub(crate) state: ConfigMutationEffectState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) attempt_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) outcome_code: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TerminalReceipt {
    pub(crate) state: String,
    pub(crate) config_state: String,
    pub(crate) runtime_state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) cause: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ConfigMutationReceipt {
    pub(crate) schema_version: u32,
    pub(crate) operation_id: String,
    pub(crate) operation: String,
    pub(crate) started_at_ms: i64,
    pub(crate) before_config_fingerprint: String,
    pub(crate) fenced_before_fingerprint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) after_config_fingerprint: Option<String>,
    pub(crate) config_reference: ConfigReference,
    pub(crate) target: MutationTarget,
    pub(crate) runtime_plan: RuntimePlan,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) auth_operation: Option<AuthOperationReceipt>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) ssh_plan: Option<SshPlan>,
    pub(crate) effects: Vec<EffectReceipt>,
    pub(crate) terminal: TerminalReceipt,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ConfigIntentOutcomeV1 {
    pub(crate) schema_version: u32,
    pub(crate) operation: String,
    pub(crate) intent_id: String,
    pub(crate) disposition: String,
    pub(crate) config_state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) selected_profile_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) applied_profile_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) validation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) science_running: Option<bool>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ConfigMutationCommandErrorV1 {
    pub(crate) schema_version: u32,
    pub(crate) code: String,
    pub(crate) operation: String,
    pub(crate) cause: String,
    pub(crate) phase: String,
    pub(crate) retryable: bool,
    pub(crate) attention_required: bool,
    pub(crate) receipt_retained: bool,
    pub(crate) config_state: String,
    pub(crate) runtime_state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) message: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ConfigMutationOutcomeV1 {
    pub(crate) schema_version: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) operation_id: Option<String>,
    pub(crate) operation: String,
    pub(crate) disposition: String,
    pub(crate) config_state: String,
    pub(crate) runtime_state: String,
    pub(crate) recovery_state: String,
}

impl ConfigMutationCommandErrorV1 {
    pub(crate) fn with_message(mut self, message: impl Into<String>) -> Self {
        let message = message.into();
        if !message.is_empty()
            && message.chars().count() <= 512
            && message
                .chars()
                .all(|character| character != '\n' && character != '\r' && character != '\0')
        {
            self.message = Some(message);
        }
        self
    }

    pub(crate) fn json(&self) -> Value {
        serde_json::to_value(self).unwrap_or_else(|_| {
            json!({
                "schema_version": RECEIPT_SCHEMA_VERSION,
                "code": "config_mutation_attention",
                "operation": self.operation,
                "cause": "error_serialization",
                "phase": "unknown",
                "retryable": false,
                "attention_required": true,
                "receipt_retained": true,
                "config_state": "unknown",
                "runtime_state": "unknown"
            })
        })
    }
}

impl std::fmt::Display for ConfigMutationCommandErrorV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self.code.as_str() {
            "mutation_conflict" => "普通配置变更与另一项受管操作冲突。",
            "config_mutation_attention" => "普通配置变更需要人工处理；操作记录已保留。",
            _ => "普通配置变更失败。",
        })
    }
}

fn lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn bounded_token(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

fn digest_bytes(prefix: &[u8], bytes: impl AsRef<[u8]>) -> String {
    let mut hasher = Sha256::new();
    hasher.update(prefix);
    hasher.update(bytes.as_ref());
    format!("{:x}", hasher.finalize())
}

fn digest_string(prefix: &[u8], value: &str) -> String {
    digest_bytes(prefix, value.as_bytes())
}

pub(crate) fn config_reference(cfg: &Config) -> ConfigReference {
    ConfigReference {
        schema_version: INTENT_SCHEMA_VERSION,
        active_profile_id_digest: (!cfg.active_id.is_empty())
            .then(|| digest_string(b"csswitch-p2b-profile-id-v1\0", &cfg.active_id)),
        runtime_binding_digest: cfg.runtime_binding.as_ref().and_then(|binding| {
            serde_json::to_vec(binding)
                .ok()
                .map(|bytes| digest_bytes(b"csswitch-p2b-runtime-binding-v1\0", bytes))
        }),
        proxy_port: Some(cfg.proxy_port),
        sandbox_port: Some(cfg.sandbox_port),
    }
}

pub(crate) fn network_fingerprint(
    settings: &csswitch_codex_network::CodexNetworkSettings,
) -> Result<String, String> {
    let bytes = serde_json::to_vec(settings).map_err(|error| error.to_string())?;
    Ok(digest_bytes(b"csswitch-p2b-network-v1\0", bytes))
}

fn encode_receipt(receipt: &ConfigMutationReceipt) -> Result<Vec<u8>, String> {
    let bytes = serde_json::to_vec(receipt).map_err(|error| error.to_string())?;
    if bytes.is_empty() || bytes.len() > config::MAX_CONFIG_MUTATION_RECEIPT_BYTES {
        return Err("Config mutation receipt 超过 64 KiB 上限".into());
    }
    Ok(bytes)
}

fn validate_receipt(receipt: &ConfigMutationReceipt) -> Result<(), String> {
    if receipt.schema_version != RECEIPT_SCHEMA_VERSION
        || !lower_hex(&receipt.operation_id, 32)
        || ConfigMutationOperation::parse(&receipt.operation).is_none()
        || receipt.before_config_fingerprint != receipt.fenced_before_fingerprint
        || !lower_hex(&receipt.before_config_fingerprint, 64)
        || receipt
            .after_config_fingerprint
            .as_deref()
            .is_some_and(|value| !lower_hex(value, 64))
        || receipt.config_reference.schema_version != INTENT_SCHEMA_VERSION
        || receipt.effects.len() > 32
    {
        return Err("Config mutation receipt schema/identity 非法".into());
    }
    if receipt
        .target
        .profile_id
        .as_deref()
        .is_some_and(|value| value.is_empty() || value.len() > 256 || value.contains('/'))
        || receipt
            .target
            .network_fingerprint
            .as_deref()
            .is_some_and(|value| !lower_hex(value, 64))
        || receipt
            .target
            .auth_account_hash
            .as_deref()
            .is_some_and(|value| !lower_hex(value, 64))
        || receipt
            .target
            .auth_epoch
            .as_deref()
            .is_some_and(|value| !bounded_token(value, 128))
    {
        return Err("Config mutation receipt target 泄露或越界".into());
    }
    if !bounded_token(&receipt.terminal.state, 32)
        || !bounded_token(&receipt.terminal.config_state, 32)
        || !bounded_token(&receipt.terminal.runtime_state, 32)
        || !matches!(
            receipt.terminal.state.as_str(),
            "open" | "completed" | "attention"
        )
        || !matches!(
            receipt.terminal.config_state.as_str(),
            "before" | "after" | "unknown"
        )
        || !matches!(
            receipt.terminal.runtime_state.as_str(),
            "preserved" | "stopped" | "restored" | "unknown"
        )
        || receipt
            .terminal
            .cause
            .as_deref()
            .is_some_and(|value| !bounded_token(value, 64))
    {
        return Err("Config mutation receipt terminal state 非法".into());
    }
    for effect in &receipt.effects {
        if effect
            .attempt_id
            .as_deref()
            .is_some_and(|value| !lower_hex(value, 32))
            || effect
                .outcome_code
                .as_deref()
                .is_some_and(|value| !bounded_token(value, 64))
        {
            return Err("Config mutation effect checkpoint 非法".into());
        }
        let state_shape_valid = match effect.state {
            ConfigMutationEffectState::Pending => {
                effect.attempt_id.is_none() && effect.outcome_code.is_none()
            }
            ConfigMutationEffectState::InProgress => {
                effect.attempt_id.is_some() && effect.outcome_code.is_none()
            }
            // A skip can be known before an attempt (Pending -> Skipped) or
            // discovered by the bounded pre-effect observation after an
            // attempt was durably opened (InProgress -> Skipped).  Preserve
            // the latter attempt identity instead of erasing crash evidence.
            ConfigMutationEffectState::Skipped => effect.outcome_code.is_some(),
            ConfigMutationEffectState::Succeeded
            | ConfigMutationEffectState::Failed
            | ConfigMutationEffectState::Uncertain => {
                effect.attempt_id.is_some() && effect.outcome_code.is_some()
            }
        };
        if !state_shape_valid {
            return Err("Config mutation effect state/attempt identity 非法".into());
        }
    }
    let terminal_shape_valid = match receipt.terminal.state.as_str() {
        "open" => receipt.terminal.cause.is_none(),
        "completed" => {
            receipt.terminal.cause.is_none()
                && receipt.effects.iter().all(|effect| {
                    matches!(
                        effect.state,
                        ConfigMutationEffectState::Succeeded | ConfigMutationEffectState::Skipped
                    )
                })
        }
        "attention" => receipt.terminal.cause.is_some(),
        _ => false,
    };
    if !terminal_shape_valid {
        return Err("Config mutation receipt terminal/effect shape 非法".into());
    }
    if let Some(auth) = receipt.auth_operation.as_ref() {
        if !lower_hex(&auth.auth_operation_id, 32)
            || !matches!(
                auth.state.as_str(),
                "reserved"
                    | "spawned_inert"
                    | "registered"
                    | "start_prepared"
                    | "start_authorized"
                    | "cancel_requested"
                    | "cancelled"
                    | "terminal"
            )
            || auth
                .start_authorization_digest
                .as_deref()
                .is_some_and(|value| !lower_hex(value, 64))
            || auth
                .terminal_account_hash
                .as_deref()
                .is_some_and(|value| !lower_hex(value, 64))
            || auth
                .terminal_auth_epoch
                .as_deref()
                .is_some_and(|value| !bounded_token(value, 128))
            || matches!(auth.state.as_str(), "start_prepared" | "start_authorized")
                && auth.start_authorization_digest.is_none()
        {
            return Err("Config mutation auth operation identity 非法".into());
        }
        if let Some(sidecar) = auth.sidecar.as_ref() {
            if sidecar.pid == 0
                || sidecar.process_group_id <= 0
                || !bounded_token(&sidecar.process_start, 128)
                || !lower_hex(&sidecar.executable_fingerprint, 64)
            {
                return Err("Config mutation auth sidecar identity 非法".into());
            }
        } else if auth.state == "spawned_inert"
            || auth.state == "registered"
            || auth.state == "start_prepared"
            || auth.state == "start_authorized"
        {
            return Err("auth sidecar durable identity 不完整".into());
        }
    }
    if let Some(plan) = receipt.ssh_plan.as_ref() {
        if receipt.operation != ConfigMutationOperation::SetSettingsDestructive.as_str() {
            return Err("SSH plan 只能属于 destructive settings operation".into());
        }
        for leaf in [
            plan.bridge_config.as_ref(),
            plan.bridge_sidecar.as_ref(),
            plan.managed_stub.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            if !matches!(leaf.expected_after.as_str(), "restored" | "absent")
                || leaf.before_identity_or_absent.is_none()
                || leaf
                    .before_identity_or_absent
                    .as_ref()
                    .is_some_and(|identity| !valid_asset_identity(identity))
                || leaf
                    .observed_after_identity_or_absent
                    .as_ref()
                    .is_some_and(|identity| !valid_asset_identity(identity))
                || leaf.expected_after == "absent"
                    && leaf.observed_after_identity_or_absent.is_some()
                || leaf.expected_after == "restored"
                    && receipt.terminal.state == "completed"
                    && leaf.observed_after_identity_or_absent.is_none()
            {
                return Err("SSH plan exact before/after identity 非法".into());
            }
        }
        if receipt
            .effects
            .iter()
            .any(|effect| effect.kind == ConfigMutationEffectKind::DeleteSshBridgeSidecar)
            && (plan.bridge_config.is_none() || plan.bridge_sidecar.is_none())
        {
            return Err("SSH bridge delete effect 缺少 exact leaf plan".into());
        }
        if receipt
            .effects
            .iter()
            .any(|effect| effect.kind == ConfigMutationEffectKind::DeleteManagedSshStub)
            && plan.managed_stub.is_none()
        {
            return Err("SSH stub delete effect 缺少 exact leaf plan".into());
        }
    } else if receipt.effects.iter().any(|effect| {
        matches!(
            effect.kind,
            ConfigMutationEffectKind::DeleteSshBridgeSidecar
                | ConfigMutationEffectKind::DeleteManagedSshStub
        )
    }) {
        return Err("SSH delete effect 缺少 durable SSH plan".into());
    }
    Ok(())
}

fn valid_asset_identity(identity: &AssetIdentity) -> bool {
    identity.uid == unsafe { crate::platform::geteuid() }
        && identity.device > 0
        && identity.inode > 0
        && identity.nlink == 1
        && identity.length <= 1024 * 1024
        && identity.mode & !0o777 == 0
        && lower_hex(&identity.digest, 64)
}

fn serialize_fence(fence: &ConfigMutationOperationFence) -> Result<Vec<u8>, String> {
    serde_json::to_vec(fence).map_err(|error| error.to_string())
}

fn receipt_digest(bytes: &[u8]) -> String {
    digest_bytes(b"csswitch-p2b-receipt-v1\0", bytes)
}

pub(crate) struct OpenConfigMutation {
    dir: std::path::PathBuf,
    fence: ConfigMutationOperationFence,
    receipt: ConfigMutationReceipt,
    bytes: Vec<u8>,
}

impl OpenConfigMutation {
    pub(crate) fn operation_id(&self) -> &str {
        &self.receipt.operation_id
    }

    pub(crate) fn fence(&self) -> &ConfigMutationOperationFence {
        &self.fence
    }

    pub(crate) fn receipt(&self) -> &ConfigMutationReceipt {
        &self.receipt
    }

    pub(crate) fn receipt_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub(crate) fn update_receipt<F>(&mut self, f: F) -> Result<(), String>
    where
        F: FnOnce(&mut ConfigMutationReceipt),
    {
        let mut receipt = self.receipt.clone();
        f(&mut receipt);
        validate_receipt(&receipt)?;
        let next = encode_receipt(&receipt)?;
        config::write_config_mutation_operation(&self.dir, &self.fence, &next, &self.bytes)
            .map_err(|error| error.to_string())?;
        self.receipt = receipt;
        self.bytes = next;
        Ok(())
    }

    pub(crate) fn checkpoint_effect(
        &mut self,
        index: usize,
        state: ConfigMutationEffectState,
        outcome_code: Option<&str>,
    ) -> Result<(), String> {
        let mut receipt = self.receipt.clone();
        let effect = receipt
            .effects
            .get_mut(index)
            .ok_or_else(|| "Config mutation effect index 越界".to_string())?;
        let transition_valid = matches!(
            (effect.state, state),
            (
                ConfigMutationEffectState::Pending,
                ConfigMutationEffectState::InProgress | ConfigMutationEffectState::Skipped
            ) | (
                ConfigMutationEffectState::InProgress,
                ConfigMutationEffectState::Succeeded
                    | ConfigMutationEffectState::Failed
                    | ConfigMutationEffectState::Uncertain
                    | ConfigMutationEffectState::Skipped
            )
        );
        if !transition_valid {
            return Err("Config mutation effect checkpoint transition 非法".into());
        }
        if state == ConfigMutationEffectState::InProgress {
            effect.attempt_id = Some(config::new_id());
        } else if state != ConfigMutationEffectState::Skipped && effect.attempt_id.is_none() {
            return Err("Config mutation terminal effect 缺少 attempt identity".into());
        }
        effect.state = state;
        effect.outcome_code = outcome_code.map(str::to_string);
        validate_receipt(&receipt)?;
        let next = encode_receipt(&receipt)?;
        config::write_config_mutation_operation(&self.dir, &self.fence, &next, &self.bytes)
            .map_err(|error| error.to_string())?;
        self.receipt = receipt;
        self.bytes = next;
        Ok(())
    }

    pub(crate) fn retain_attention(
        &mut self,
        cause: &str,
        config_state: &str,
        runtime_state: &str,
        terminal_image: ConfigMutationTerminalConfigImage,
        message: impl Into<String>,
    ) -> ConfigMutationCommandErrorV1 {
        let message = message.into();
        match self.finish(
            "attention",
            config_state,
            runtime_state,
            Some(cause),
            terminal_image,
        ) {
            Err(error) => error.with_message(message),
            Ok(_) => self
                .attention(cause, "terminal", message.clone(), true)
                .with_message(message),
        }
    }

    pub(crate) fn checkpoint_effect_or_attention(
        &mut self,
        index: usize,
        state: ConfigMutationEffectState,
        outcome_code: Option<&str>,
        cause: &str,
        config_state: &str,
        runtime_state: &str,
        terminal_image: ConfigMutationTerminalConfigImage,
    ) -> Result<(), ConfigMutationCommandErrorV1> {
        self.checkpoint_effect(index, state, outcome_code)
            .map_err(|error| {
                self.retain_attention(cause, config_state, runtime_state, terminal_image, error)
            })
    }

    pub(crate) fn update_config<T, F>(&mut self, f: F) -> Result<T, String>
    where
        F: FnOnce(&mut Config) -> Result<(T, bool), String>,
    {
        config::update_config_mutation_operation(&self.dir, &self.fence, &self.bytes, f)
    }

    pub(crate) fn bind_after_config_fingerprint(
        &mut self,
        after_config_fingerprint: String,
    ) -> Result<(), String> {
        if self
            .fence
            .after_config_fingerprint
            .as_ref()
            .is_some_and(|expected| expected != &after_config_fingerprint)
            || self
                .receipt
                .after_config_fingerprint
                .as_ref()
                .is_some_and(|expected| expected != &after_config_fingerprint)
        {
            return Err("Config mutation dynamic after-image 与既有约束不匹配".into());
        }
        self.update_receipt(|receipt| {
            receipt.after_config_fingerprint = Some(after_config_fingerprint);
        })
    }

    pub(crate) fn finish(
        &mut self,
        disposition: &str,
        config_state: &str,
        runtime_state: &str,
        cause: Option<&str>,
        terminal_image: ConfigMutationTerminalConfigImage,
    ) -> Result<ConfigMutationOutcomeV1, ConfigMutationCommandErrorV1> {
        // Dynamic-after operations must bind the image at their scoped Config
        // commit. Reading it here would absorb an out-of-band drift as the
        // authorized after-image.
        if disposition == "completed"
            && matches!(terminal_image, ConfigMutationTerminalConfigImage::After)
            && self.fence.after_config_fingerprint.is_none()
            && self.receipt.after_config_fingerprint.is_none()
        {
            return Err(self.attention(
                "terminal_after_unbound",
                "terminal",
                "dynamic after-image was not bound at the scoped Config commit".into(),
                true,
            ));
        }
        let mut receipt = self.receipt.clone();
        receipt.terminal = TerminalReceipt {
            state: if disposition == "completed" {
                "completed".into()
            } else {
                "attention".into()
            },
            config_state: config_state.into(),
            runtime_state: runtime_state.into(),
            cause: cause.map(str::to_string),
        };
        if let Err(error) = validate_receipt(&receipt) {
            return Err(self.attention("terminal_invalid", "terminal", error, true));
        }
        let next = match encode_receipt(&receipt) {
            Ok(bytes) => bytes,
            Err(error) => return Err(self.attention("terminal_invalid", "terminal", error, true)),
        };
        if let Err(error) =
            config::write_config_mutation_operation(&self.dir, &self.fence, &next, &self.bytes)
        {
            return Err(self.attention("receipt_checkpoint", "terminal", error.to_string(), true));
        }
        self.receipt = receipt;
        self.bytes = next.clone();
        let mut terminal_base = self.fence.clone();
        if terminal_base.after_config_fingerprint.is_none() {
            terminal_base.after_config_fingerprint = self.receipt.after_config_fingerprint.clone();
        }
        let terminal_fence = terminal_base.terminal(
            receipt_digest(&next),
            config_state,
            runtime_state,
            self.receipt
                .auth_operation
                .as_ref()
                .and_then(|auth| auth.terminal_auth_epoch.clone()),
            self.receipt
                .auth_operation
                .as_ref()
                .and_then(|auth| auth.terminal_auth_generation),
            self.receipt
                .auth_operation
                .as_ref()
                .and_then(|auth| auth.terminal_account_hash.clone()),
        );
        if let Err(error) = config::publish_config_mutation_terminal_fence(
            &self.dir,
            &self.fence,
            &terminal_fence,
            &next,
            terminal_image,
        ) {
            return Err(self.attention("terminal_fence", "terminal", error.to_string(), true));
        }
        if disposition != "completed" {
            self.fence = terminal_fence;
            return Err(self.attention(
                "attention_retained",
                "terminal",
                "terminal attention retained".into(),
                true,
            ));
        }
        if let Err(error) = config::clear_config_mutation_operation(
            &self.dir,
            &terminal_fence,
            &next,
            terminal_image,
        ) {
            return Err(self.attention("cleanup_incomplete", "terminal", error.to_string(), true));
        }
        self.fence = terminal_fence;
        Ok(ConfigMutationOutcomeV1 {
            schema_version: RECEIPT_SCHEMA_VERSION,
            operation_id: Some(self.receipt.operation_id.clone()),
            operation: self.receipt.operation.clone(),
            disposition: disposition.into(),
            config_state: config_state.into(),
            runtime_state: runtime_state.into(),
            recovery_state: "not_needed".into(),
        })
    }

    fn attention(
        &self,
        cause: &str,
        phase: &str,
        _detail: String,
        receipt_retained: bool,
    ) -> ConfigMutationCommandErrorV1 {
        ConfigMutationCommandErrorV1 {
            schema_version: RECEIPT_SCHEMA_VERSION,
            code: "config_mutation_attention".into(),
            operation: self.receipt.operation.clone(),
            cause: cause.into(),
            phase: phase.into(),
            retryable: false,
            attention_required: true,
            receipt_retained,
            config_state: self.receipt.terminal.config_state.clone(),
            runtime_state: self.receipt.terminal.runtime_state.clone(),
            message: None,
        }
    }
}

pub(crate) fn begin(
    dir: &Path,
    operation: ConfigMutationOperation,
    before: &Config,
    after: Option<&Config>,
    target: MutationTarget,
    runtime_plan: RuntimePlan,
    effects: Vec<ConfigMutationEffectKind>,
    auth_operation: Option<AuthOperationReceipt>,
    ssh_plan: Option<SshPlan>,
) -> Result<OpenConfigMutation, ConfigMutationCommandErrorV1> {
    let before_fingerprint =
        config::config_mutation_config_fingerprint(before).map_err(|error| {
            command_error(
                operation,
                "fingerprint",
                "config_fingerprint",
                false,
                false,
                error.to_string(),
            )
        })?;
    let after_fingerprint = after
        .map(|config| config::config_mutation_config_fingerprint(config))
        .transpose()
        .map_err(|error| {
            command_error(
                operation,
                "fingerprint",
                "config_fingerprint",
                false,
                false,
                error.to_string(),
            )
        })?;
    let operation_id = config::new_id();
    let effect_receipts = effects
        .into_iter()
        .map(|kind| EffectReceipt {
            kind,
            state: ConfigMutationEffectState::Pending,
            attempt_id: None,
            outcome_code: None,
        })
        .collect::<Vec<_>>();
    let mut receipt = ConfigMutationReceipt {
        schema_version: RECEIPT_SCHEMA_VERSION,
        operation_id: operation_id.clone(),
        operation: operation.as_str().into(),
        started_at_ms: config::now_ms(),
        before_config_fingerprint: before_fingerprint.clone(),
        fenced_before_fingerprint: before_fingerprint.clone(),
        after_config_fingerprint: after_fingerprint.clone(),
        config_reference: config_reference(before),
        target,
        runtime_plan,
        auth_operation,
        ssh_plan,
        effects: effect_receipts,
        terminal: TerminalReceipt {
            state: "open".into(),
            config_state: "before".into(),
            runtime_state: "preserved".into(),
            cause: None,
        },
    };
    validate_receipt(&receipt).map_err(|error| {
        command_error(operation, "intent", "receipt_schema", false, false, error)
    })?;
    let bytes = encode_receipt(&receipt).map_err(|error| {
        command_error(operation, "intent", "receipt_schema", false, false, error)
    })?;
    let intent_digest = digest_bytes(b"csswitch-p2b-intent-v1\0", &bytes);
    let fence = ConfigMutationOperationFence::begin(
        operation_id,
        operation.as_str().into(),
        intent_digest,
        before_fingerprint,
        after_fingerprint,
    );
    let fence_bytes = serialize_fence(&fence)
        .map_err(|error| command_error(operation, "intent", "fence_schema", false, false, error))?;
    if fence_bytes.len() > 8 * 1024 {
        return Err(command_error(
            operation,
            "intent",
            "fence_bounds",
            false,
            false,
            "Config mutation fence 超过 8 KiB".into(),
        ));
    }
    config::begin_config_mutation_operation(dir, before, &fence, &bytes).map_err(|error| {
        let cause = if error.to_string().contains("operation fence")
            || error.to_string().contains("receipt")
        {
            "mutation_conflict"
        } else {
            "intent"
        };
        command_error(
            operation,
            "intent",
            cause,
            cause == "mutation_conflict",
            false,
            error.to_string(),
        )
    })?;
    // Keep the in-memory copy canonical after the successful publication.
    receipt.fenced_before_fingerprint = fence.before_config_fingerprint.clone();
    Ok(OpenConfigMutation {
        dir: dir.to_path_buf(),
        fence,
        receipt,
        bytes,
    })
}

fn command_error(
    operation: ConfigMutationOperation,
    phase: &str,
    cause: &str,
    retryable: bool,
    retained: bool,
    _detail: String,
) -> ConfigMutationCommandErrorV1 {
    ConfigMutationCommandErrorV1 {
        schema_version: RECEIPT_SCHEMA_VERSION,
        code: if retained {
            "config_mutation_attention"
        } else if cause == "mutation_conflict" {
            "mutation_conflict"
        } else {
            "config_mutation_failed"
        }
        .into(),
        operation: operation.as_str().into(),
        cause: cause.into(),
        phase: phase.into(),
        retryable,
        attention_required: retained,
        receipt_retained: retained,
        config_state: "before".into(),
        runtime_state: "preserved".into(),
        message: None,
    }
}

pub(crate) fn outcome_json(outcome: &ConfigMutationOutcomeV1) -> Value {
    serde_json::to_value(outcome).unwrap_or_else(|_| {
        json!({
            "schema_version": RECEIPT_SCHEMA_VERSION,
            "operation": outcome.operation,
            "disposition": "attention",
            "config_state": "unknown",
            "runtime_state": "unknown",
            "recovery_state": "attention"
        })
    })
}

pub(crate) fn command_error_string(error: &ConfigMutationCommandErrorV1) -> String {
    serde_json::to_string(&error.json()).unwrap_or_else(|_| error.to_string())
}

pub(crate) fn typed_intent_outcome(
    operation: &str,
    disposition: &str,
    config_state: &str,
    selected_profile_id: Option<String>,
    applied_profile_id: Option<String>,
    validation: Option<&str>,
    science_running: Option<bool>,
) -> Value {
    serde_json::to_value(ConfigIntentOutcomeV1 {
        schema_version: INTENT_SCHEMA_VERSION,
        operation: operation.into(),
        intent_id: config::new_id(),
        disposition: disposition.into(),
        config_state: config_state.into(),
        selected_profile_id,
        applied_profile_id,
        validation: validation.map(str::to_string),
        science_running,
    })
    .unwrap_or_else(
        |_| json!({"schema_version": INTENT_SCHEMA_VERSION, "disposition": "inconclusive"}),
    )
}

fn boot_attention(operation: Option<&str>, cause: &str) -> Value {
    json!({
        "schema_version": RECEIPT_SCHEMA_VERSION,
        "code": "config_mutation_boot_attention",
        "operation": operation.unwrap_or("unknown"),
        "disposition": "attention",
        "cause": cause,
        "attention_required": true,
        "receipt_retained": true,
        "config_state": "unknown",
        "runtime_state": "unknown",
    })
}

/// Boot-only P2-B convergence.  Effectful/open receipts are deliberately not
/// guessed at here: only an already terminal, exact receipt/fence pair may
/// finish its final cleanup.  Open or ambiguous records remain visible as a
/// typed attention result and therefore stop normal Gateway/Science boot.
pub(crate) fn boot_recover(dir: &Path) -> Result<Option<Value>, String> {
    let cfg = config::load_from(dir).map_err(|error| error.to_string())?;
    let p2a_receipt =
        config::read_codex_disable_operation_receipt(dir).map_err(|error| error.to_string())?;
    let p2a_fence = cfg
        .codex_disable_operation_fence()
        .map_err(|error| error.to_string())?;
    let p2b_receipt =
        config::read_config_mutation_operation_receipt(dir).map_err(|error| error.to_string())?;
    let p2b_fence = cfg
        .config_mutation_operation_fence()
        .map_err(|error| error.to_string())?;
    if (p2a_receipt.is_some() || p2a_fence.is_some())
        && (p2b_receipt.is_some() || p2b_fence.is_some())
    {
        return Ok(Some(boot_attention(None, "p2a_p2b_mutual_exclusion")));
    }
    if p2b_receipt.is_none() && p2b_fence.is_none() {
        return Ok(None);
    }
    if cfg.has_open_runtime_journal() {
        return Ok(Some(boot_attention(
            p2b_fence.as_ref().map(|fence| fence.operation.as_str()),
            "runtime_journal_conflict",
        )));
    }
    if let Some(bytes) = p2b_receipt {
        let receipt: ConfigMutationReceipt = serde_json::from_slice(&bytes)
            .map_err(|_| "Config mutation boot receipt 非法；已保留 attention".to_string())?;
        validate_receipt(&receipt).map_err(|_| {
            "Config mutation boot receipt schema 非法；已保留 attention".to_string()
        })?;
        let Some(fence) = p2b_fence.as_ref() else {
            return Ok(Some(boot_attention(
                Some(receipt.operation.as_str()),
                "receipt_without_fence",
            )));
        };
        if receipt.operation_id != fence.operation_id
            || receipt.operation != fence.operation
            || receipt.terminal.state != "completed"
            || fence.phase != "terminal"
            || fence.terminal_receipt_digest.as_deref() != Some(receipt_digest(&bytes).as_str())
        {
            return Ok(Some(boot_attention(
                Some(receipt.operation.as_str()),
                "open_or_ambiguous_receipt",
            )));
        }
        let image = match fence.config_state.as_deref() {
            Some("before") => ConfigMutationTerminalConfigImage::Before,
            Some("after") if fence.after_config_fingerprint.is_some() => {
                ConfigMutationTerminalConfigImage::After
            }
            _ => {
                return Ok(Some(boot_attention(
                    Some(receipt.operation.as_str()),
                    "terminal_image_unknown",
                )))
            }
        };
        config::clear_config_mutation_operation(dir, fence, &bytes, image)
            .map_err(|error| error.to_string())?;
        return Ok(None);
    }
    match config::recover_orphan_config_mutation_operation_fence(dir)
        .map_err(|error| error.to_string())?
    {
        config::ConfigMutationOrphanFenceRecovery::Cleared
        | config::ConfigMutationOrphanFenceRecovery::None => Ok(None),
        config::ConfigMutationOrphanFenceRecovery::ActiveReceipt => Ok(Some(boot_attention(
            p2b_fence.as_ref().map(|fence| fence.operation.as_str()),
            "active_receipt_requires_recovery",
        ))),
        config::ConfigMutationOrphanFenceRecovery::ConfigDrift => Ok(Some(boot_attention(
            p2b_fence.as_ref().map(|fence| fence.operation.as_str()),
            "config_drift",
        ))),
        config::ConfigMutationOrphanFenceRecovery::Attention => Ok(Some(boot_attention(
            p2b_fence.as_ref().map(|fence| fence.operation.as_str()),
            "orphan_fence_attention",
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config_dir() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "csswitch-p2b-config-mutation-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn open_fixture(dir: &Path) -> OpenConfigMutation {
        let before = Config::default();
        begin(
            dir,
            ConfigMutationOperation::SetModeOfficial,
            &before,
            None,
            MutationTarget {
                mode: Some("official".into()),
                ..Default::default()
            },
            RuntimePlan::default(),
            vec![ConfigMutationEffectKind::ConfigCommit],
            None,
            None,
        )
        .unwrap()
    }

    #[test]
    fn p2b_receipt_contract_is_credential_free_and_allowlisted() {
        let dir = config_dir();
        config::save_to(&dir, &Config::default()).unwrap();
        let mut operation = open_fixture(&dir);
        let bytes =
            std::fs::read(dir.join(config::CONFIG_MUTATION_OPERATION_RECEIPT_FILE)).unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.contains("set_mode_official"));
        assert!(!text.contains("https://"));
        assert!(!text.contains("api_key"));
        assert_eq!(operation.receipt().schema_version, 1);
        assert!(operation
            .checkpoint_effect(0, ConfigMutationEffectState::Succeeded, Some("committed"))
            .is_err());
        operation
            .checkpoint_effect(0, ConfigMutationEffectState::InProgress, None)
            .unwrap();
        let attempt_id = operation.receipt().effects[0].attempt_id.clone().unwrap();
        operation
            .checkpoint_effect(0, ConfigMutationEffectState::Succeeded, Some("committed"))
            .unwrap();
        assert_eq!(
            operation.receipt().effects[0].attempt_id.as_deref(),
            Some(attempt_id.as_str())
        );
        assert!(operation
            .checkpoint_effect(0, ConfigMutationEffectState::Failed, Some("late_failure"))
            .is_err());

        let replacement_dir = config_dir();
        config::save_to(&replacement_dir, &Config::default()).unwrap();
        let mut replacement = open_fixture(&replacement_dir);
        std::fs::write(
            replacement_dir.join(config::CONFIG_MUTATION_OPERATION_RECEIPT_FILE),
            b"foreign-replacement",
        )
        .unwrap();
        assert!(replacement
            .checkpoint_effect(0, ConfigMutationEffectState::InProgress, None)
            .is_err());
        assert_eq!(
            replacement.receipt().effects[0].state,
            ConfigMutationEffectState::Pending
        );
        assert!(replacement.receipt().effects[0].attempt_id.is_none());
    }

    #[test]
    fn p2b_recovery_keeps_replacement_on_exact_fence_mismatch() {
        let dir = config_dir();
        config::save_to(&dir, &Config::default()).unwrap();
        let mut operation = open_fixture(&dir);
        let original = operation.bytes.clone();
        operation
            .checkpoint_effect(0, ConfigMutationEffectState::InProgress, None)
            .unwrap();
        operation
            .checkpoint_effect(0, ConfigMutationEffectState::Succeeded, Some("committed"))
            .unwrap();
        let replacement = operation.bytes.clone();
        assert!(config::write_config_mutation_operation(
            &dir,
            operation.fence(),
            b"replacement",
            &original,
        )
        .is_err());
        assert_eq!(
            std::fs::read(dir.join(config::CONFIG_MUTATION_OPERATION_RECEIPT_FILE)).unwrap(),
            replacement
        );
    }

    #[test]
    fn p2b_receipt_only_is_not_silently_cleared() {
        let dir = config_dir();
        config::save_to(&dir, &Config::default()).unwrap();
        std::fs::write(
            dir.join(config::CONFIG_MUTATION_OPERATION_RECEIPT_FILE),
            br#"{"schema_version":1}"#,
        )
        .unwrap();
        assert!(matches!(
            config::recover_orphan_config_mutation_operation_fence(&dir).unwrap(),
            config::ConfigMutationOrphanFenceRecovery::Attention
        ));
    }

    #[test]
    fn p2b_set_mode_crash_recovery_matrix() {
        let dir = config_dir();
        config::save_to(&dir, &Config::default()).unwrap();
        let mut operation = open_fixture(&dir);
        operation
            .checkpoint_effect(0, ConfigMutationEffectState::InProgress, None)
            .unwrap();
        operation
            .checkpoint_effect(
                0,
                ConfigMutationEffectState::Succeeded,
                Some("config_commit"),
            )
            .unwrap();
        let outcome = operation
            .finish(
                "completed",
                "before",
                "stopped",
                None,
                ConfigMutationTerminalConfigImage::Before,
            )
            .unwrap();
        assert_eq!(outcome.disposition, "completed");
        assert!(!dir
            .join(config::CONFIG_MUTATION_OPERATION_RECEIPT_FILE)
            .exists());
        assert!(
            config::config_mutation_config_fingerprint(&config::load_from(&dir).unwrap()).is_ok()
        );
    }

    #[test]
    fn p2b_set_mode_generation_effect_is_after_durable_attempts() {
        let source = include_str!("lifecycle.rs");
        let body = source
            .split_once("if mode == \"official\" {")
            .expect("set_mode official branch")
            .1;
        let science_checkpoint = body
            .find("science_stop_checkpoint_failed")
            .expect("Science attempt checkpoint");
        let gateway_checkpoint = body
            .find("gateway_stop_checkpoint_failed")
            .expect("Gateway attempt checkpoint");
        let generation_effect = body
            .find("let generation = lifecycle.bump_generation();")
            .expect("generation invalidation effect");
        let first_stop = body
            .find("claim_process_local_science_stop")
            .expect("first process stop effect");
        assert!(science_checkpoint < generation_effect);
        assert!(gateway_checkpoint < generation_effect);
        assert!(generation_effect < first_stop);
    }

    #[test]
    fn p2b_set_settings_ssh_false_to_false_owned_absent_foreign_matrix() {
        let dir = config_dir();
        config::save_to(&dir, &Config::default()).unwrap();
        let identity = AssetIdentity {
            uid: unsafe { crate::platform::geteuid() },
            device: 1,
            inode: 1,
            mode: 0o600,
            nlink: 1,
            length: 1,
            digest: "11".repeat(32),
        };
        let operation = begin(
            &dir,
            ConfigMutationOperation::SetSettingsDestructive,
            &Config::default(),
            None,
            MutationTarget {
                proxy_port: Some(18991),
                sandbox_port: Some(18765),
                reuse_system_ssh: Some(false),
                ..Default::default()
            },
            RuntimePlan::default(),
            vec![ConfigMutationEffectKind::DeleteManagedSshStub],
            None,
            Some(SshPlan {
                managed_stub: Some(SshLeafReceipt {
                    before_identity_or_absent: Some(identity),
                    expected_after: "absent".into(),
                    observed_after_identity_or_absent: None,
                }),
                ..Default::default()
            }),
        )
        .unwrap();
        assert_eq!(operation.receipt().target.reuse_system_ssh, Some(false));
    }
}
