//! Managed Gateway recovery, launch contracts, bridge state, binary lookup, and lifecycle façade.
//!
//! The included fragments deliberately remain in this module so the historical
//! crate-facing surface, private helper relationships, failure text, state
//! ownership, and test identities stay unchanged while each responsibility has
//! one file owner.

#[cfg(not(unix))]
use crate::platform::{OpenOptionsModeExt, UnixCompatExt};
#[cfg(not(unix))]
use std::os::windows::fs::OpenOptionsExt as _;
use std::fs::{self, File, OpenOptions};
use std::hash::{DefaultHasher, Hash, Hasher};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};
use tauri::{Manager, Runtime};

use crate::runtime::legacy_proxy::{
    stop_legacy_csswitch_python_on_port, stop_managed_gateway_on_port, LegacyProxyCleanup,
    ManagedGatewayCleanup, ManagedGatewayStopUnknownKind,
};
use crate::runtime::operation::{self, OperationStage, OperationTrace, POLL_INTERVAL_MS};
use crate::runtime::provider::{
    assert_format_supported, current_shim_mode_for_adapter, is_openai_adapter, normalize_shim_mode,
    proxy_args_for, proxy_fingerprint_with_runtime, FormalCredential, FormalGatewayPlan,
};
use crate::runtime::proxy::{health_timeout_reason, ProxyAction};
use crate::runtime::system::{
    asset_root, canonical_repo_root, log_path, open_log, redact, repo_root, tail_file,
};
use crate::{config, lifecycle, lock, proc, AppState, SharedAppState};

// Keep include fragments on rustfmt's normal module-discovery path without
// changing the runtime module or the historical visibility surface.
#[cfg(any())]
#[path = "proxy_lifecycle/binary.rs"]
mod format_binary;
#[cfg(any())]
#[path = "proxy_lifecycle/controller.rs"]
mod format_controller;
#[cfg(any())]
#[path = "proxy_lifecycle/launch_contract.rs"]
mod format_launch_contract;
#[cfg(any())]
#[path = "proxy_lifecycle/lifecycle.rs"]
mod format_lifecycle;
#[cfg(any())]
#[path = "proxy_lifecycle/recovery.rs"]
mod format_recovery;
#[cfg(any())]
#[path = "proxy_lifecycle/skill_bridge.rs"]
mod format_skill_bridge;

include!("proxy_lifecycle/recovery.rs");
include!("proxy_lifecycle/launch_contract.rs");
include!("proxy_lifecycle/skill_bridge.rs");
include!("proxy_lifecycle/binary.rs");
include!("proxy_lifecycle/controller.rs");
include!("proxy_lifecycle/lifecycle.rs");

#[cfg(test)]
#[path = "proxy_lifecycle/tests.rs"]
mod tests;
