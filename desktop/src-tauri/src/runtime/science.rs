//! Claude Science executable selection, managed identity, and lifecycle façade.
//!
//! The included fragments deliberately remain in this module so the historical
//! crate-facing surface, private helper relationships, failure codes, and test
//! identities stay unchanged while each responsibility has one file owner.

// Science failures deliberately retain typed ownership receipts, runtime
// identity, and recovery disposition inside this module boundary.
#![allow(clippy::result_large_err)]

#[cfg(not(unix))]
use crate::platform::{OpenOptionsModeExt, UnixCompatExt};
#[cfg(not(unix))]
use std::os::windows::fs::OpenOptionsExt as _;
use std::collections::{BTreeSet, HashMap};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
#[cfg(unix)]
#[cfg(unix)]
use std::os::fd::AsRawFd;
#[cfg(unix)]
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
#[cfg(unix)]
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, PermissionsExt};
#[cfg(unix)]
#[cfg(unix)]
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tauri::Runtime;

use crate::{config, proc};

use super::system::{asset_root, kill_child};

#[cfg(test)]
static SCIENCE_LIFECYCLE_TEST_SEAMS: std::sync::LazyLock<
    std::sync::Mutex<Option<(std::thread::ThreadId, PathBuf)>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(None));

#[cfg(test)]
pub(crate) struct ScienceLifecycleTestSeamGuard;

#[cfg(test)]
impl Drop for ScienceLifecycleTestSeamGuard {
    fn drop(&mut self) {
        *SCIENCE_LIFECYCLE_TEST_SEAMS
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = None;
    }
}

#[cfg(test)]
pub(crate) fn test_arm_post_stop_result_failure(
    config_dir: PathBuf,
) -> ScienceLifecycleTestSeamGuard {
    *SCIENCE_LIFECYCLE_TEST_SEAMS
        .lock()
        .unwrap_or_else(|error| error.into_inner()) =
        Some((std::thread::current().id(), config_dir));
    ScienceLifecycleTestSeamGuard
}

#[cfg(test)]
static SCIENCE_UPDATER_IDENTITY_TEST_SEAM: std::sync::LazyLock<
    std::sync::Mutex<Option<std::thread::ThreadId>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(None));

#[cfg(test)]
pub(crate) struct ScienceUpdaterIdentityTestSeamGuard;

#[cfg(test)]
impl Drop for ScienceUpdaterIdentityTestSeamGuard {
    fn drop(&mut self) {
        *SCIENCE_UPDATER_IDENTITY_TEST_SEAM
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = None;
    }
}

#[cfg(test)]
pub(crate) fn test_arm_fake_science_updater_identity() -> ScienceUpdaterIdentityTestSeamGuard {
    *SCIENCE_UPDATER_IDENTITY_TEST_SEAM
        .lock()
        .unwrap_or_else(|error| error.into_inner()) = Some(std::thread::current().id());
    ScienceUpdaterIdentityTestSeamGuard
}

#[cfg(test)]
fn fake_science_updater_identity_armed_for_current_thread() -> bool {
    SCIENCE_UPDATER_IDENTITY_TEST_SEAM
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .is_some_and(|thread_id| thread_id == std::thread::current().id())
}

// Keep include fragments on rustfmt's normal module-discovery path without
// changing the runtime module or the historical visibility surface.
#[cfg(any())]
#[path = "science/adoption.rs"]
mod format_adoption;
#[cfg(any())]
#[path = "science/contracts.rs"]
mod format_contracts;
#[cfg(any())]
#[path = "science/control_runner.rs"]
mod format_control_runner;
#[cfg(any())]
#[path = "science/executable.rs"]
mod format_executable;
#[cfg(any())]
#[path = "science/host_adapter.rs"]
mod format_host_adapter;
#[cfg(any())]
#[path = "science/lifecycle.rs"]
mod format_lifecycle;
#[cfg(any())]
#[path = "science/managed_launch.rs"]
mod format_managed_launch;
#[cfg(any())]
#[path = "science/runtime_state.rs"]
mod format_runtime_state;
#[cfg(any())]
#[path = "science/selection.rs"]
mod format_selection;

use crate::platform::CanonicalizeExt;
include!("science/contracts.rs");
include!("science/control_runner.rs");
include!("science/executable.rs");
include!("science/adoption.rs");
include!("science/selection.rs");
include!("science/runtime_state.rs");
include!("science/managed_launch.rs");
include!("science/lifecycle.rs");
include!("science/host_adapter.rs");

#[cfg(test)]
pub(crate) fn test_runtime_identity(path: PathBuf) -> ScienceRuntimeIdentity {
    ScienceRuntimeIdentity {
        fingerprint: science_executable_fingerprint(&path)
            .expect("test Science runtime must be a stable executable file"),
        path,
        source: ScienceRuntimeSource::Explicit,
        version: Some("test-only".into()),
        adoption_attempt_id: None,
    }
}

#[cfg(test)]
#[path = "science/tests.rs"]
mod tests;
