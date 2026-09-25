//! Windows placeholder for the external-skill install bridge.
//!
//! The POSIX implementation (see `skill_install_unix.rs`) is built on
//! openat/fstatat/flock descriptors and geteuid ownership checks that have no
//! std-only Windows equivalent. On Windows:
//!
//! * `run_mcp` (the standalone MCP bridge binary mode) reports the platform
//!   limitation instead of serving install/uninstall tools.
//! * `start_skill_install_bridge` (see `server::skill_bridge_host`) is already
//!   a `#[cfg(not(unix))]` no-op, so the degraded `AuthorityFenceDescriptor`
//!   returned here is never used to authorize any filesystem write.
//! * The gateway process itself still starts and proxies normally; skill
//!   surface configuration is accepted so existing deployments keep booting.

#![allow(dead_code)]

use serde_json::Value;

pub(crate) const BRIDGE_INSTALL_RESPONSE_TIMEOUT_SECONDS: u64 =
    csswitch_skill_install_core::GITHUB_BUNDLE_OPERATION_TIMEOUT_SECONDS + 60;

/// Degraded authority-fence descriptor.
///
/// On Unix this binds an opened directory + lock file identity (device/inode)
/// inherited through environment descriptors, proving the bridge write host is
/// the process that created the capability. Windows has no openat-style
/// identity binding, so this struct carries no state. It is safe precisely
/// because the bridge host it guards never starts on Windows; if the bridge is
/// ever ported, this type must gain a real Windows capability binding first.
#[derive(Debug, Clone)]
pub(crate) struct AuthorityFenceDescriptor;

impl AuthorityFenceDescriptor {
    /// The Unix implementation fails closed when the fence environment is
    /// missing or malformed. On Windows the bridge host is disabled, so the
    /// fence can never be exercised; accepting a valid-looking token keeps the
    /// gateway startable with existing skill-surface configuration.
    pub(crate) fn from_env(_bridge_token: &str) -> Result<Self, String> {
        Ok(Self)
    }
}

pub fn run_mcp(_args: &[String]) -> Result<(), String> {
    Err(
        "external skill install bridge is not supported on this platform (requires Unix \
         openat/flock authority fencing)"
            .into(),
    )
}

pub(crate) fn validate_bridge_request(
    _bridge_token: &str,
    _filename_id: &str,
    _request: &Value,
) -> Result<(), String> {
    Err("skill install bridge is not supported on this platform".into())
}

pub(crate) fn handle_bridge_request_with_progress(
    _data_dir: &std::path::Path,
    _science_context: Option<&csswitch_skill_install_core::ScienceHostContext>,
    _bridge_dir: Option<&std::path::Path>,
    _authority_root: Option<&std::fs::File>,
    _request: &Value,
    _progress: &mut dyn FnMut(&str, &str),
) -> Value {
    serde_json::json!({
        "schema_version": csswitch_skill_install_core::SCHEMA_VERSION,
        "status": "REQUEST_FAILED",
        "message": "本地 Skill 桥接在当前平台不可用（需要 Unix authority fence）",
        "retryable": false,
        "directory_commit": false,
        "restart_required": false
    })
}
