//! Authority filesystem snapshot primitives (capture/copy/identity/limits).
//! No pending-cleanup orchestration and no one-click transaction policy live here.

#[cfg(not(unix))]
use crate::platform::{OpenOptionsModeExt, UnixCompatExt};
#[cfg(not(unix))]
use std::os::windows::fs::OpenOptionsExt as _;
#[cfg(unix)]
use std::os::fd::{AsRawFd, FromRawFd};
#[cfg(unix)]
use std::os::unix::ffi::{OsStrExt, OsStringExt};
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

// Keep include fragments on rustfmt's normal module-discovery path without
// changing the runtime module or the historical visibility surface.
#[cfg(any())]
#[path = "authority_snapshot/budget.rs"]
mod format_budget;
#[cfg(any())]
#[path = "authority_snapshot/capture.rs"]
mod format_capture;
#[cfg(any())]
#[path = "authority_snapshot/contracts.rs"]
mod format_contracts;
#[cfg(any())]
#[path = "authority_snapshot/filesystem.rs"]
mod format_filesystem;
#[cfg(any())]
#[path = "authority_snapshot/restore.rs"]
mod format_restore;
#[cfg(any())]
#[path = "authority_snapshot/test_seams.rs"]
mod format_test_seams;

include!("authority_snapshot/contracts.rs");
include!("authority_snapshot/test_seams.rs");
include!("authority_snapshot/budget.rs");
include!("authority_snapshot/filesystem.rs");
include!("authority_snapshot/capture.rs");
include!("authority_snapshot/restore.rs");
