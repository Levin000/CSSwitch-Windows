//! SSH preflight for one-click / running-bridge validation.
#[cfg(not(unix))]
use std::os::windows::fs::OpenOptionsExt as _;

#[cfg(not(unix))]
use crate::platform::UnixCompatExt;
#[cfg(not(unix))]
use crate::platform::OpenOptionsModeExt;
#[cfg(not(unix))]
use std::os::windows::fs::OpenOptionsExt as _;

use crate::config;
use crate::runtime::system::asset_root;
use std::io::Read;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use tauri::Runtime;

const SYSTEM_SSH_WRAPPER_BYTES: &[u8] = include_bytes!("../../../../../scripts/ssh-bridge/ssh");

pub(super) fn validate_system_ssh_wrapper_path<R: Runtime>(
    app: &tauri::AppHandle<R>,
) -> Result<PathBuf, String> {
    #[cfg(test)]
    let wrapper_override =
        std::env::var_os("CSSWITCH_TEST_SSH_WRAPPER_OVERRIDE").map(PathBuf::from);
    #[cfg(not(test))]
    let wrapper_override: Option<PathBuf> = None;
    let wrapper = match wrapper_override {
        Some(wrapper) => wrapper,
        None => {
            let root = asset_root(app).ok_or("打包的 CSSwitch SSH bridge 缺失")?;
            let scripts = root.join("scripts");
            let wrapper_dir = scripts.join("ssh-bridge");
            let wrapper = wrapper_dir.join("ssh");
            for path in [&root, &scripts, &wrapper_dir] {
                let metadata = std::fs::symlink_metadata(path)
                    .map_err(|_| "打包的 CSSwitch SSH bridge 缺失".to_string())?;
                if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
                    return Err("打包的 CSSwitch SSH bridge 不是安全的可执行文件".into());
                }
            }
            wrapper
        }
    };
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(crate::platform::O_NOFOLLOW | crate::platform::O_NONBLOCK | crate::platform::O_CLOEXEC)
        .open(&wrapper)
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                "打包的 CSSwitch SSH bridge 缺失".to_string()
            } else {
                "打包的 CSSwitch SSH bridge 不是安全的可执行文件".to_string()
            }
        })?;
    let opened = file
        .metadata()
        .map_err(|_| "打包的 CSSwitch SSH bridge 不是安全的可执行文件".to_string())?;
    let named = std::fs::symlink_metadata(&wrapper)
        .map_err(|_| "打包的 CSSwitch SSH bridge 缺失".to_string())?;
    // SAFETY: geteuid has no preconditions and does not dereference pointers.
    let uid = unsafe { crate::platform::geteuid() };
    let mode = opened.permissions().mode();
    if !opened.file_type().is_file()
        || named.file_type().is_symlink()
        || !named.file_type().is_file()
        || opened.dev() != named.dev()
        || opened.ino() != named.ino()
        || opened.uid() != uid
        || opened.nlink() != 1
        || mode & 0o111 == 0
        || mode & 0o022 != 0
        || opened.len() != SYSTEM_SSH_WRAPPER_BYTES.len() as u64
    {
        return Err("打包的 CSSwitch SSH bridge 不是安全的可执行文件".into());
    }
    let mut bytes = Vec::with_capacity(SYSTEM_SSH_WRAPPER_BYTES.len());
    file.take((SYSTEM_SSH_WRAPPER_BYTES.len() + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| "打包的 CSSwitch SSH bridge 不是安全的可执行文件".to_string())?;
    if bytes.as_slice() != SYSTEM_SSH_WRAPPER_BYTES {
        return Err("打包的 CSSwitch SSH bridge 内容身份不匹配".into());
    }
    Ok(wrapper)
}

pub(super) fn validate_running_system_ssh_bridge<R: Runtime>(
    app: &tauri::AppHandle<R>,
    sandbox_home: &Path,
) -> Result<(), String> {
    let _validated_wrapper =
        crate::runtime::sandbox_session::validate_system_ssh_wrapper_path(app)?;
    let expected_hosts = crate::runtime::ssh_bridge::validate_science_ssh_bridge(sandbox_home)?;
    crate::runtime::settings::validate_managed_sandbox_ssh_stub(sandbox_home, &expected_hosts)?;
    Ok(())
}

pub(super) fn prevalidate_one_click_system_ssh<R: Runtime>(
    app: &tauri::AppHandle<R>,
    cfg: &config::Config,
    sandbox_home: &Path,
) -> Result<Vec<String>, String> {
    let expected_hosts = crate::runtime::ssh_bridge::prevalidate_science_ssh_bridge(
        sandbox_home,
        cfg.reuse_system_ssh,
    )?;
    crate::runtime::settings::prevalidate_sandbox_ssh_stub(
        sandbox_home,
        &expected_hosts,
        cfg.reuse_system_ssh,
    )?;
    if cfg.reuse_system_ssh {
        let _validated_wrapper =
            crate::runtime::sandbox_session::validate_system_ssh_wrapper_path(app)?;
    }
    Ok(expected_hosts)
}
