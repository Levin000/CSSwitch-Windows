#[cfg(not(unix))]
use crate::platform::UnixCompatExt;
#[cfg(not(unix))]
use crate::platform::OpenOptionsModeExt;

#[cfg(any(test, feature = "acceptance-build"))]
use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};
use tauri::Runtime;

use crate::runtime::external_skill_route::{ensure_route_skill, inspect_route_skill, SKILL_NAME};
use crate::runtime::proxy_lifecycle::gateway_bin_path;
use crate::runtime::science::{
    run_bounded_control_command, BoundedControlCommandError, BoundedControlCommandFailure,
};

const INSTALL_SERVER_NAME: &str = "csswitch-skill-installer";
const UNINSTALL_SERVER_NAME: &str = "csswitch-skill-uninstaller";
const MANAGED_MARKER: &str = "[managed-by:csswitch]";
const ROUTE_STATE_FILE: &str = ".csswitch-route-state.json";
const ROUTE_STATE_SCHEMA: u64 = 1;
const ROUTE_POLICY_REVISION: u64 = 3;
const THIRD_PARTY_CONTROL_TIMEOUT: Duration = Duration::from_secs(10);
const THIRD_PARTY_CONTROL_OUTPUT_LIMIT: u64 = 64 * 1024;
#[cfg(any(test, feature = "acceptance-build"))]
const ACCEPTANCE_GITHUB_BASE_URL_ENV: &str = "CSSWITCH_ACCEPTANCE_GITHUB_BASE_URL";
#[cfg(any(test, feature = "acceptance-build"))]
const ACCEPTANCE_RESERVED_PORTS: [u16; 3] = [1455, 1457, 8765];

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum RegistrationStatus {
    Registered,
    AlreadyRegistered,
    RestartRequired,
    Warning(String),
}

impl RegistrationStatus {
    pub(crate) fn code(&self) -> &'static str {
        match self {
            Self::Registered => "REGISTERED",
            Self::AlreadyRegistered => "AVAILABLE",
            Self::RestartRequired => "RESTART_REQUIRED",
            Self::Warning(_) => "WARNING",
        }
    }

    pub(crate) fn user_note(&self) -> Option<String> {
        match self {
            Self::Registered => Some("外部 Skill 本地安装与卸载工具已注册。".into()),
            Self::AlreadyRegistered => None,
            Self::RestartRequired => {
                Some("外部 Skill 本地安装与卸载工具需要重启 Science 后加载。".into())
            }
            Self::Warning(message) => Some(format!(
                "外部 Skill 本地工具未就绪：{message}；Science 仍会正常启动。"
            )),
        }
    }
}

pub(crate) fn register_before_science_start<R: Runtime>(
    app: &tauri::AppHandle<R>,
    data_dir: &Path,
    bridge_dir: &Path,
    bridge_key_file: &Path,
) -> RegistrationStatus {
    let result = (|| -> Result<bool, String> {
        let _authority_guard = crate::config::acquire_authority_writer_guard()
            .map_err(|error| format!("authority writer fence failed: {error}"))?;
        let (config, expected) = registration_inputs(app, data_dir, bridge_dir, bridge_key_file)?;
        let mcp_changed = merge_runtime_registration(&config, expected)?;
        let route_changed = ensure_route_skill(data_dir)?;
        Ok(mcp_changed || route_changed)
    })();
    match result {
        Ok(true) => RegistrationStatus::Registered,
        Ok(false) => RegistrationStatus::AlreadyRegistered,
        Err(error) => RegistrationStatus::Warning(error),
    }
}

pub(crate) fn inspect_while_science_running<R: Runtime>(
    app: &tauri::AppHandle<R>,
    data_dir: &Path,
    bridge_dir: &Path,
    bridge_key_file: &Path,
) -> RegistrationStatus {
    let result = (|| -> Result<bool, String> {
        let (config, expected) = registration_inputs(app, data_dir, bridge_dir, bridge_key_file)?;
        Ok(registration_matches(&config, &expected)? && inspect_route_skill(data_dir)?)
    })();
    match result {
        Ok(true) => RegistrationStatus::AlreadyRegistered,
        Ok(false) => RegistrationStatus::RestartRequired,
        Err(error) => RegistrationStatus::Warning(error),
    }
}

/// Configure the isolated third-party Science profile through its local control plane.
///
/// The one-time URL is passed via the child environment (never argv), and the
/// gateway command accepts only the fixed policy and loopback origins.
pub(crate) fn configure_third_party_after_science_start<R: Runtime>(
    app: &tauri::AppHandle<R>,
    control_url: &str,
) -> Result<(), String> {
    let deadline = Instant::now()
        .checked_add(THIRD_PARTY_CONTROL_TIMEOUT)
        .ok_or("Science 未接受 CSSwitch 第三方能力配置")?;
    #[cfg(test)]
    if let Some(log) = TEST_THIRD_PARTY_PARTIAL_FAILURE.with(|slot| slot.borrow().clone()) {
        let mut options = OpenOptions::new();
        options.create(true).append(true);
        let mut file = options
            .open(log)
            .map_err(|_| "无法写入第三方配置 partial-mutation 测试证据")?;
        file.write_all(b"configure-third-party-partial\n")
            .map_err(|_| "无法写入第三方配置 partial-mutation 测试证据")?;
        return Err("测试注入：host 配置在 partial mutation 后失败".into());
    }
    #[cfg(test)]
    if let Some(log) = std::env::var_os("CSSWITCH_TEST_THIRD_PARTY_CONFIG_LOG") {
        let mut options = OpenOptions::new();
        options.create(true).append(true);
        let mut file = options
            .open(log)
            .map_err(|_| "无法写入第三方配置测试计数")?;
        file.write_all(b"configure-third-party\n")
            .map_err(|_| "无法写入第三方配置测试计数")?;
        return Ok(());
    }
    let gateway = gateway_bin_path(app).ok_or("找不到 csswitch-gateway sidecar")?;
    configure_third_party_with_gateway_before(&gateway, control_url, deadline)
        .map_err(|error| error.user_message().to_string())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ThirdPartyConfigureError {
    Command(BoundedControlCommandError),
    NonzeroExit,
    InvalidJson,
    IncompleteContract,
}

impl ThirdPartyConfigureError {
    fn user_message(self) -> &'static str {
        match self {
            Self::Command(BoundedControlCommandError::Failed(
                BoundedControlCommandFailure::OutputSetup | BoundedControlCommandFailure::Spawn,
            )) => "启动本地 Science 第三方能力配置命令失败",
            Self::Command(_) | Self::NonzeroExit => "Science 未接受 CSSwitch 第三方能力配置",
            Self::InvalidJson => "本地 Science 第三方能力配置响应非法",
            Self::IncompleteContract => "本地 Science 第三方能力配置结果不完整",
        }
    }
}

fn configure_third_party_with_gateway_before(
    gateway: &Path,
    control_url: &str,
    deadline: Instant,
) -> Result<(), ThirdPartyConfigureError> {
    let mut command = Command::new(gateway);
    command
        .stdin(Stdio::null())
        .arg("science-control")
        .arg("configure-third-party")
        .env("CSSWITCH_SCIENCE_CONTROL_URL", control_url);
    let output = run_bounded_control_command(
        command,
        deadline,
        THIRD_PARTY_CONTROL_OUTPUT_LIMIT,
        THIRD_PARTY_CONTROL_OUTPUT_LIMIT,
    )
    .map_err(ThirdPartyConfigureError::Command)?;
    if !output.status.success() {
        return Err(ThirdPartyConfigureError::NonzeroExit);
    }
    let value: Value = serde_json::from_slice(&output.stdout)
        .map_err(|_| ThirdPartyConfigureError::InvalidJson)?;
    let connectors = value
        .get("connector_ids")
        .and_then(Value::as_array)
        .map(|items| items.iter().filter_map(Value::as_str).collect::<Vec<_>>())
        .unwrap_or_default();
    if value.get("status").and_then(Value::as_str) != Some("CONFIGURED")
        || value.get("skill_name").and_then(Value::as_str) != Some(SKILL_NAME)
        || connectors != ["local:csswitch-skill-installer"]
        || value.get("disabled_skill").and_then(Value::as_str) != Some("customize")
        || value.get("custom_prompt_managed").and_then(Value::as_bool) != Some(true)
    {
        return Err(ThirdPartyConfigureError::IncompleteContract);
    }
    Ok(())
}

#[cfg(test)]
thread_local! {
    static TEST_THIRD_PARTY_PARTIAL_FAILURE: std::cell::RefCell<Option<PathBuf>> = const {
        std::cell::RefCell::new(None)
    };
}

#[cfg(test)]
pub(crate) struct TestThirdPartyPartialFailureGuard;

#[cfg(test)]
impl Drop for TestThirdPartyPartialFailureGuard {
    fn drop(&mut self) {
        TEST_THIRD_PARTY_PARTIAL_FAILURE.with(|slot| *slot.borrow_mut() = None);
    }
}

#[cfg(test)]
pub(crate) fn test_arm_third_party_partial_failure(
    log: PathBuf,
) -> TestThirdPartyPartialFailureGuard {
    TEST_THIRD_PARTY_PARTIAL_FAILURE.with(|slot| {
        let previous = slot.borrow_mut().replace(log);
        assert!(
            previous.is_none(),
            "third-party partial failure seam already armed"
        );
    });
    TestThirdPartyPartialFailureGuard
}

fn expected_route_state(science_version: &str) -> Value {
    json!({
        "schema": ROUTE_STATE_SCHEMA,
        "csswitch_version": env!("CARGO_PKG_VERSION"),
        "science_version": science_version,
        "route_revision": ROUTE_POLICY_REVISION,
    })
}

fn route_state_path(data_dir: &Path) -> PathBuf {
    data_dir.join(ROUTE_STATE_FILE)
}

pub(crate) fn route_configuration_is_current(
    data_dir: &Path,
    science_version: &str,
) -> Result<bool, String> {
    let path = route_state_path(data_dir);
    reject_symlink_path(&path)?;
    let body = match fs::read(&path) {
        Ok(body) => body,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(format!("读取 Skill 路由状态失败：{error}")),
    };
    let Ok(current) = serde_json::from_slice::<Value>(&body) else {
        return Ok(false);
    };
    Ok(current == expected_route_state(science_version))
}

pub(crate) fn invalidate_route_configuration(data_dir: &Path) -> Result<(), String> {
    let _authority_guard = crate::config::acquire_authority_writer_guard()
        .map_err(|error| format!("authority writer fence failed: {error}"))?;
    invalidate_route_configuration_unfenced(data_dir)
}

fn invalidate_route_configuration_unfenced(data_dir: &Path) -> Result<(), String> {
    let path = route_state_path(data_dir);
    reject_symlink_path(&path)?;
    match fs::remove_file(&path) {
        Ok(()) => {
            crate::platform::sync_directory(data_dir)
                .map_err(|error| format!("同步 Skill 路由状态目录失败：{error}"))?;
            Ok(())
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("清除 Skill 路由状态失败：{error}")),
    }
}

pub(crate) fn mark_route_configuration_current(
    data_dir: &Path,
    science_version: &str,
) -> Result<(), String> {
    let _authority_guard = crate::config::acquire_authority_writer_guard()
        .map_err(|error| format!("authority writer fence failed: {error}"))?;
    mark_route_configuration_current_unfenced(data_dir, science_version)
}

fn mark_route_configuration_current_unfenced(
    data_dir: &Path,
    science_version: &str,
) -> Result<(), String> {
    reject_symlink_path(data_dir)?;
    if !data_dir.is_dir() {
        return Err("Science data-dir 不可用，无法记录 Skill 路由状态".into());
    }
    let path = route_state_path(data_dir);
    reject_symlink_path(&path)?;
    write_route_state_atomic(&path, &expected_route_state(science_version))
}

fn registration_inputs<R: Runtime>(
    app: &tauri::AppHandle<R>,
    data_dir: &Path,
    bridge_dir: &Path,
    bridge_key_file: &Path,
) -> Result<(PathBuf, Vec<Value>), String> {
    reject_symlink_path(data_dir)?;
    reject_symlink_path(bridge_key_file)?;
    if !bridge_key_file.is_absolute() || !bridge_key_file.is_file() {
        return Err("CSSwitch 私有 Skill bridge key file 不可用".into());
    }
    let gateway = gateway_bin_path(app).ok_or("找不到 csswitch-gateway sidecar")?;
    // Science's local_mcp_root is instance-scoped (<data-dir>/mcp), while the
    // tool resolves active-org.json again at call time before installing files.
    let config = data_dir.join("mcp").join("local-mcp.json");
    let command = gateway.to_string_lossy();
    let bridge = bridge_dir.to_string_lossy();
    let bridge_key_file = bridge_key_file.to_string_lossy();
    let connector_env = json!({"CSSWITCH_SKILL_BRIDGE_KEY_FILE": bridge_key_file});
    #[cfg(feature = "acceptance-build")]
    let connector_env = {
        let mut connector_env = connector_env;
        if let Some(base) = acceptance_github_fixture_base(
            std::env::var_os(ACCEPTANCE_GITHUB_BASE_URL_ENV).as_deref(),
        )? {
            connector_env[ACCEPTANCE_GITHUB_BASE_URL_ENV] = json!(base);
        }
        connector_env
    };
    let expected = vec![json!({
        "name": INSTALL_SERVER_NAME,
        "command": command,
        "args": ["skill-install-mcp", "--bridge-dir", bridge],
        "env": connector_env,
        "description": format!("安装或卸载外部 Skill；pass the exact public GitHub Skill directory URL to install_external_skill. CSSwitch downloads, validates, commits, and attaches OPERON; the Agent must then call skill(skill_name). Do not download, use shell, host.skills.*, catalog, Skill Manager, or host.agents.attach_skill. Use uninstall_external_skill for removal. {MANAGED_MARKER}")
    })];
    Ok((config, expected))
}

#[cfg(any(test, feature = "acceptance-build"))]
fn acceptance_github_fixture_base(raw: Option<&OsStr>) -> Result<Option<String>, String> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    let value = raw
        .to_str()
        .ok_or("acceptance GitHub fixture URL 不是 UTF-8，已拒绝注册 connector")?;
    let rest = value
        .strip_prefix("http://")
        .ok_or("acceptance GitHub fixture 只允许 loopback HTTP URL")?;
    let (authority, suffix) = rest.split_once('/').unwrap_or((rest, ""));
    if authority.is_empty()
        || authority.contains('@')
        || !matches!(suffix, "" | "/")
        || value.contains('?')
        || value.contains('#')
    {
        return Err("acceptance GitHub fixture 必须是无认证、根路径的 loopback HTTP URL".into());
    }
    let explicit_test_port = authority
        .rsplit_once(':')
        .and_then(|(_, raw)| raw.parse::<u16>().ok())
        .is_some_and(|port| port >= 1024 && !ACCEPTANCE_RESERVED_PORTS.contains(&port));
    if !explicit_test_port {
        return Err("acceptance GitHub fixture 必须使用显式非保留测试端口".into());
    }
    let endpoint = crate::runtime::provider::parse_endpoint(value)
        .ok_or("acceptance GitHub fixture URL 非法")?;
    let host = endpoint.host.trim_end_matches('.');
    let loopback = host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .map(|ip| ip.is_loopback())
            .unwrap_or(false);
    if !loopback {
        return Err("acceptance GitHub fixture 只允许显式 loopback 地址".into());
    }
    Ok(Some(format!("http://{authority}/")))
}

#[cfg(feature = "acceptance-build")]
pub(crate) fn configure_acceptance_github_host_command(cmd: &mut Command) -> Result<(), String> {
    let raw = std::env::var_os(ACCEPTANCE_GITHUB_BASE_URL_ENV);
    configure_acceptance_github_host_command_with(cmd, raw.as_deref())
}

#[cfg(any(test, feature = "acceptance-build"))]
fn configure_acceptance_github_host_command_with(
    cmd: &mut Command,
    raw: Option<&OsStr>,
) -> Result<(), String> {
    if let Some(base) = acceptance_github_fixture_base(raw)? {
        cmd.env(ACCEPTANCE_GITHUB_BASE_URL_ENV, base);
    }
    Ok(())
}

fn registration_matches(config: &Path, expected: &[Value]) -> Result<bool, String> {
    if !config.exists() {
        return Ok(false);
    }
    reject_symlink_path(config)?;
    let root = read_config(config)?;
    let servers = root
        .get("servers")
        .and_then(Value::as_array)
        .ok_or("local-mcp.json 缺少 servers 数组")?;
    let expected_present = expected
        .iter()
        .all(|item| servers.iter().any(|server| server_matches(server, item)));
    Ok(expected_present)
}

fn server_matches(server: &Value, expected: &Value) -> bool {
    ["name", "command", "args", "env", "description"]
        .iter()
        .all(|key| server.get(*key) == expected.get(*key))
        && server
            .get("description")
            .and_then(Value::as_str)
            .map(|description| description.contains(MANAGED_MARKER))
            .unwrap_or(false)
}

#[cfg(test)]
fn merge_registration(config: &Path, expected: Value) -> Result<bool, String> {
    merge_registrations(config, vec![expected])
}

#[cfg(test)]
fn merge_registrations(config: &Path, expected: Vec<Value>) -> Result<bool, String> {
    merge_registrations_and_remove(config, expected, &[])
}

fn merge_runtime_registration(config: &Path, expected: Vec<Value>) -> Result<bool, String> {
    merge_registrations_and_remove(config, expected, &[UNINSTALL_SERVER_NAME])
}

fn merge_registrations_and_remove(
    config: &Path,
    expected: Vec<Value>,
    obsolete_managed_names: &[&str],
) -> Result<bool, String> {
    if let Some(parent) = config.parent() {
        reject_symlink_path(parent)?;
        fs::create_dir_all(parent).map_err(|e| format!("创建本地 MCP 目录失败：{e}"))?;
        reject_symlink_path(parent)?;
    }
    reject_symlink_path(config)?;
    let mut root = if config.exists() {
        read_config(config)?
    } else {
        json!({"servers": []})
    };
    let object = root
        .as_object_mut()
        .ok_or("local-mcp.json 顶层必须是对象")?;
    let servers = object.entry("servers").or_insert_with(|| json!([]));
    let servers = servers
        .as_array_mut()
        .ok_or("local-mcp.json 的 servers 必须是数组")?;
    let mut changed = false;
    for item in expected {
        let name = item
            .get("name")
            .and_then(Value::as_str)
            .ok_or("CSSwitch MCP 配置缺少名称")?;
        let existing = servers
            .iter()
            .position(|server| server.get("name").and_then(Value::as_str) == Some(name));
        if let Some(index) = existing {
            if server_matches(&servers[index], &item) {
                continue;
            }
            let managed = servers[index]
                .get("description")
                .and_then(Value::as_str)
                .map(|description| description.contains(MANAGED_MARKER))
                .unwrap_or(false);
            if !managed {
                return Err(format!(
                    "本地 MCP 已存在同名非 CSSwitch 配置 '{name}'，已拒绝覆盖"
                ));
            }
            servers[index] = item;
        } else {
            servers.push(item);
        }
        changed = true;
    }
    let original_len = servers.len();
    servers.retain(|server| {
        let obsolete = server
            .get("name")
            .and_then(Value::as_str)
            .is_some_and(|name| obsolete_managed_names.contains(&name));
        let managed = server
            .get("description")
            .and_then(Value::as_str)
            .is_some_and(|description| description.contains(MANAGED_MARKER));
        !(obsolete && managed)
    });
    changed |= servers.len() != original_len;
    if !changed {
        return Ok(false);
    }
    write_config_atomic(config, &root)?;
    Ok(true)
}

fn read_config(path: &Path) -> Result<Value, String> {
    let body = fs::read(path).map_err(|e| format!("读取 local-mcp.json 失败：{e}"))?;
    serde_json::from_slice(&body).map_err(|e| format!("local-mcp.json 非法：{e}"))
}

fn write_config_atomic(path: &Path, value: &Value) -> Result<(), String> {
    let parent = path.parent().ok_or("local-mcp.json 缺少父目录")?;
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let temp = parent.join(format!(
        ".local-mcp.json.csswitch-{}-{suffix}",
        std::process::id()
    ));
    let result = (|| -> Result<(), String> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            #[cfg(unix)]
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&temp)
            .map_err(|e| format!("创建 MCP 临时配置失败：{e}"))?;
        serde_json::to_writer_pretty(&mut file, value)
            .map_err(|e| format!("编码 MCP 配置失败：{e}"))?;
        file.write_all(b"\n")
            .map_err(|e| format!("写 MCP 配置失败：{e}"))?;
        file.sync_all()
            .map_err(|e| format!("同步 MCP 配置失败：{e}"))?;
        fs::rename(&temp, path).map_err(|e| format!("提交 MCP 配置失败：{e}"))?;
        crate::platform::sync_directory(parent)
            .map_err(|e| format!("同步 MCP 目录失败：{e}"))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

fn write_route_state_atomic(path: &Path, value: &Value) -> Result<(), String> {
    let parent = path.parent().ok_or("Skill 路由状态缺少父目录")?;
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let temp = parent.join(format!(
        ".csswitch-route-state.{}-{suffix}",
        std::process::id()
    ));
    let result = (|| -> Result<(), String> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            #[cfg(unix)]
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&temp)
            .map_err(|error| format!("创建 Skill 路由状态临时文件失败：{error}"))?;
        serde_json::to_writer(&mut file, value)
            .map_err(|error| format!("编码 Skill 路由状态失败：{error}"))?;
        file.write_all(b"\n")
            .map_err(|error| format!("写入 Skill 路由状态失败：{error}"))?;
        file.sync_all()
            .map_err(|error| format!("同步 Skill 路由状态失败：{error}"))?;
        fs::rename(&temp, path).map_err(|error| format!("提交 Skill 路由状态失败：{error}"))?;
        #[cfg(unix)]
        fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(0o600))
            .map_err(|error| format!("收紧 Skill 路由状态权限失败：{error}"))?;
        crate::platform::sync_directory(parent)
            .map_err(|error| format!("同步 Skill 路由状态目录失败：{error}"))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

fn reject_symlink_path(path: &Path) -> Result<(), String> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err("MCP 配置路径包含符号链接".into())
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(format!("检查 MCP 配置路径失败：{error}")),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_THIRD_PARTY_RESPONSE: &str = r#"{"status":"CONFIGURED","skill_name":"csswitch-external-skill-tools","connector_ids":["local:csswitch-skill-installer"],"disabled_skill":"customize","custom_prompt_managed":true}"#;

    fn temp_dir(label: &str) -> PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = PathBuf::from("/private/tmp").join(format!(
            "csswitch-mcp-{label}-{}-{suffix}",
            std::process::id()
        ));
        fs::create_dir_all(&path).unwrap();
        path
    }

    fn control_script(root: &Path, label: &str, body: &str) -> PathBuf {
        #[cfg(unix)]
        use std::os::unix::fs::PermissionsExt;

        let path = root.join(label);
        fs::write(&path, format!("#!/bin/sh\nset -eu\n{body}\n")).unwrap();
        fs::set_permissions(&path, crate::platform::permissions_from_mode(0o755)).unwrap();
        path
    }

    fn run_test_control(
        gateway: &Path,
        control_url: &str,
        timeout: Duration,
    ) -> Result<(), ThirdPartyConfigureError> {
        configure_third_party_with_gateway_before(
            gateway,
            control_url,
            Instant::now().checked_add(timeout).unwrap(),
        )
    }

    fn expected(command: &str, data: &Path) -> Value {
        expected_named(INSTALL_SERVER_NAME, command, data)
    }

    fn expected_named(name: &str, command: &str, data: &Path) -> Value {
        let _ = data;
        let bridge = "/tmp/CSSwitch-Skill-Bridge-test";
        json!({
            "name": name,
            "command": command,
            "args": ["skill-install-mcp", "--bridge-dir", bridge],
            "env": {},
            "description": format!("installer {MANAGED_MARKER}")
        })
    }

    #[test]
    fn acceptance_github_fixture_is_explicit_loopback_root_only() {
        for accepted in [
            "http://127.0.0.1:32123/",
            "http://localhost:32124",
            "http://[::1]:32125/",
        ] {
            let observed = acceptance_github_fixture_base(Some(OsStr::new(accepted))).unwrap();
            assert!(observed.is_some(), "fixture should accept {accepted}");
        }
        for rejected in [
            "http://127.0.0.1/",
            "http://127.0.0.1:443/",
            "http://127.0.0.1:1455/",
            "http://127.0.0.1:1457/",
            "http://127.0.0.1:8765/",
            "https://127.0.0.1:32123/",
            "http://provider.invalid:32123/",
            "http://127.0.0.1:32123/api/",
            "http://user@127.0.0.1:32123/",
            "http://127.0.0.1:32123/?token=secret",
        ] {
            assert!(
                acceptance_github_fixture_base(Some(OsStr::new(rejected))).is_err(),
                "fixture must reject {rejected}"
            );
        }
        assert_eq!(acceptance_github_fixture_base(None).unwrap(), None);
    }

    #[test]
    fn acceptance_github_fixture_reaches_host_gateway_command_only_when_explicit() {
        let mut accepted = Command::new("csswitch-gateway");
        configure_acceptance_github_host_command_with(
            &mut accepted,
            Some(OsStr::new("http://127.0.0.1:32123/")),
        )
        .unwrap();
        assert!(accepted.get_envs().any(|(key, value)| {
            key == ACCEPTANCE_GITHUB_BASE_URL_ENV
                && value.is_some_and(|value| value == "http://127.0.0.1:32123/")
        }));

        let mut absent = Command::new("csswitch-gateway");
        configure_acceptance_github_host_command_with(&mut absent, None).unwrap();
        assert!(!absent
            .get_envs()
            .any(|(key, _)| key == ACCEPTANCE_GITHUB_BASE_URL_ENV));

        let mut rejected = Command::new("csswitch-gateway");
        assert!(configure_acceptance_github_host_command_with(
            &mut rejected,
            Some(OsStr::new("https://github.com/")),
        )
        .is_err());
        assert!(!rejected
            .get_envs()
            .any(|(key, _)| key == ACCEPTANCE_GITHUB_BASE_URL_ENV));
    }

    #[test]
    fn runtime_registration_preserves_unmanaged_legacy_name() {
        let root = temp_dir("preserve-unmanaged-uninstaller");
        let config = root.join("local-mcp.json");
        let user_uninstaller = json!({
            "name": UNINSTALL_SERVER_NAME,
            "command": "user-owned-tool",
            "description": "not managed by CSSwitch"
        });
        fs::write(
            &config,
            serde_json::to_vec(&json!({"servers": [user_uninstaller.clone()]})).unwrap(),
        )
        .unwrap();
        let combined = expected_named(INSTALL_SERVER_NAME, "/app/gateway", &root);
        assert!(merge_runtime_registration(&config, vec![combined.clone()]).unwrap());
        let saved: Value = serde_json::from_slice(&fs::read(&config).unwrap()).unwrap();
        assert_eq!(saved["servers"].as_array().unwrap().len(), 2);
        assert_eq!(saved["servers"][0], user_uninstaller);
        assert_eq!(saved["servers"][1], combined);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn runtime_registration_migrates_scoped_pair_to_combined_connector() {
        let root = temp_dir("combine-connectors");
        let config = root.join("local-mcp.json");
        let mut old_installer = expected_named(INSTALL_SERVER_NAME, "/old/gateway", &root);
        old_installer["args"] = json!([
            "skill-install-mcp",
            "--bridge-dir",
            "/tmp/CSSwitch-Skill-Bridge-test",
            "--tool-mode",
            "install"
        ]);
        let mut old_uninstaller = expected_named(UNINSTALL_SERVER_NAME, "/old/gateway", &root);
        old_uninstaller["args"] = json!([
            "skill-install-mcp",
            "--bridge-dir",
            "/tmp/CSSwitch-Skill-Bridge-test",
            "--tool-mode",
            "uninstall"
        ]);
        fs::write(
            &config,
            serde_json::to_vec(&json!({
                "servers": [
                    old_installer,
                    {"name":"other","command":"other"},
                    old_uninstaller
                ]
            }))
            .unwrap(),
        )
        .unwrap();
        let combined = expected_named(INSTALL_SERVER_NAME, "/new/gateway", &root);
        assert!(merge_runtime_registration(&config, vec![combined.clone()]).unwrap());
        assert!(!merge_runtime_registration(&config, vec![combined.clone()]).unwrap());
        let saved: Value = serde_json::from_slice(&fs::read(&config).unwrap()).unwrap();
        let servers = saved["servers"].as_array().unwrap();
        assert_eq!(servers.len(), 2);
        assert_eq!(servers[0], combined);
        assert_eq!(servers[1]["name"], "other");
        assert!(!servers.iter().any(|server| {
            server.get("name").and_then(Value::as_str) == Some(UNINSTALL_SERVER_NAME)
        }));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn merge_preserves_other_servers_and_unknown_top_level_fields() {
        let root = temp_dir("preserve");
        let config = root.join("local-mcp.json");
        fs::write(
            &config,
            br#"{"future":7,"servers":[{"name":"other","command":"other"}]}"#,
        )
        .unwrap();
        let item = expected("/app/csswitch-gateway", &root);
        assert!(merge_registration(&config, item.clone()).unwrap());
        let saved: Value = serde_json::from_slice(&fs::read(&config).unwrap()).unwrap();
        assert_eq!(saved["future"], 7);
        assert_eq!(saved["servers"][0]["name"], "other");
        assert_eq!(saved["servers"][1], item);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn merge_is_idempotent_and_updates_only_managed_entry() {
        let root = temp_dir("update");
        let config = root.join("local-mcp.json");
        let old = expected("/old/csswitch-gateway", &root);
        merge_registration(&config, old).unwrap();
        let new = expected("/new/csswitch-gateway", &root);
        assert!(merge_registration(&config, new.clone()).unwrap());
        assert!(!merge_registration(&config, new.clone()).unwrap());
        let saved: Value = serde_json::from_slice(&fs::read(&config).unwrap()).unwrap();
        assert_eq!(saved["servers"].as_array().unwrap().len(), 1);
        assert_eq!(saved["servers"][0], new);
        let mut compatible = new.clone();
        compatible["futureScienceField"] = json!(true);
        assert!(server_matches(&compatible, &new));
        let mut updated_description = new.clone();
        updated_description["description"] =
            json!(format!("installer and uninstaller {MANAGED_MARKER}"));
        assert!(merge_registration(&config, updated_description.clone()).unwrap());
        let saved: Value = serde_json::from_slice(&fs::read(&config).unwrap()).unwrap();
        assert_eq!(saved["servers"][0], updated_description);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn merge_refuses_same_name_unmanaged_entry_and_malformed_config() {
        let root = temp_dir("conflict");
        let config = root.join("local-mcp.json");
        fs::write(
            &config,
            format!(r#"{{"servers":[{{"name":"{INSTALL_SERVER_NAME}","command":"user-tool"}}]}}"#),
        )
        .unwrap();
        assert!(merge_registration(&config, expected("/app/gateway", &root)).is_err());
        assert!(fs::read_to_string(&config).unwrap().contains("user-tool"));
        fs::write(&config, b"{broken").unwrap();
        assert!(merge_registration(&config, expected("/app/gateway", &root)).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn route_state_is_persistent_versioned_and_secret_free() {
        #[cfg(unix)]
        use std::os::unix::fs::PermissionsExt;

        let root = temp_dir("route-state");
        assert!(!route_configuration_is_current(&root, "science-v1").unwrap());
        mark_route_configuration_current(&root, "science-v1").unwrap();
        assert!(route_configuration_is_current(&root, "science-v1").unwrap());
        assert!(!route_configuration_is_current(&root, "science-v2").unwrap());

        let path = route_state_path(&root);
        let body = fs::read_to_string(&path).unwrap();
        assert!(!body.contains("token"));
        assert!(!body.contains("nonce"));
        assert!(!body.contains("CSSwitch-Skill-Bridge"));
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );

        invalidate_route_configuration(&root).unwrap();
        assert!(!path.exists());
        assert!(!route_configuration_is_current(&root, "science-v1").unwrap());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn corrupt_or_unsafe_route_state_never_counts_as_configured() {
        #[cfg(unix)]
        use std::os::unix::fs::symlink;

        let root = temp_dir("route-state-invalid");
        let path = route_state_path(&root);
        fs::write(&path, b"{broken").unwrap();
        assert!(!route_configuration_is_current(&root, "science-v1").unwrap());
        fs::remove_file(&path).unwrap();
        let target = root.join("outside-state");
        fs::write(&target, b"{}").unwrap();
        symlink(&target, &path).unwrap();
        assert!(route_configuration_is_current(&root, "science-v1").is_err());
        assert!(invalidate_route_configuration(&root).is_err());
        assert!(mark_route_configuration_current(&root, "science-v1").is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn failed_route_state_write_does_not_create_success_marker() {
        let root = temp_dir("route-state-failure");
        let missing = root.join("missing-data-dir");
        assert!(mark_route_configuration_current(&missing, "science-v1").is_err());
        assert!(!route_state_path(&missing).exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn bounded_gateway_replacement_preserves_fixed_invocation_and_success_contract() {
        let root = temp_dir("third-party-success");
        let gateway = control_script(
            &root,
            "gateway",
            &format!(
                "[ \"$#\" -eq 2 ] || exit 91\n[ \"$1\" = science-control ] || exit 92\n[ \"$2\" = configure-third-party ] || exit 93\n[ \"${{CSSWITCH_SCIENCE_CONTROL_URL:-}}\" = 'http://127.0.0.1:19090/?nonce=test-only' ] || exit 94\nprintf '%s\\n' '{}'",
                VALID_THIRD_PARTY_RESPONSE
            ),
        );

        assert_eq!(
            run_test_control(
                &gateway,
                "http://127.0.0.1:19090/?nonce=test-only",
                Duration::from_secs(5),
            ),
            Ok(())
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn bounded_gateway_reports_typed_spawn_and_preserves_nonzero_errors() {
        let root = temp_dir("third-party-failures");
        let missing = root.join("missing-gateway");
        let spawn = run_test_control(&missing, "control-url", Duration::from_secs(1)).unwrap_err();
        assert_eq!(
            spawn,
            ThirdPartyConfigureError::Command(BoundedControlCommandError::Failed(
                BoundedControlCommandFailure::Spawn
            ))
        );
        assert_eq!(
            spawn.user_message(),
            "启动本地 Science 第三方能力配置命令失败"
        );

        let nonzero = control_script(&root, "nonzero-gateway", "exit 7");
        let error = run_test_control(&nonzero, "control-url", Duration::from_secs(5)).unwrap_err();
        assert_eq!(error, ThirdPartyConfigureError::NonzeroExit);
        assert_eq!(
            error.user_message(),
            "Science 未接受 CSSwitch 第三方能力配置"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn bounded_gateway_times_out_with_absolute_deadline_and_reaps() {
        let root = temp_dir("third-party-timeout");
        let not_started = root.join("expired-deadline-started");
        let expired = control_script(
            &root,
            "expired-gateway",
            &format!(": > '{}'", not_started.display()),
        );
        assert_eq!(
            configure_third_party_with_gateway_before(&expired, "control-url", Instant::now(),),
            Err(ThirdPartyConfigureError::Command(
                BoundedControlCommandError::Timeout
            ))
        );
        assert!(!not_started.exists());

        let gateway = control_script(&root, "gateway", "exec /bin/sleep 30");
        let started = Instant::now();
        let error =
            run_test_control(&gateway, "control-url", Duration::from_millis(100)).unwrap_err();
        assert_eq!(
            error,
            ThirdPartyConfigureError::Command(BoundedControlCommandError::Timeout)
        );
        assert!(started.elapsed() < Duration::from_secs(2));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn bounded_gateway_cleanup_failure_is_typed_bounded_and_reaper_owned() {
        let root = temp_dir("third-party-cleanup-handoff");
        let started_marker = root.join("descendant-started");
        let late_marker = root.join("descendant-late");
        let pid_file = root.join("descendant-pid");
        let gateway = control_script(
            &root,
            "gateway",
            &format!(
                "( : > '{}'; /bin/sleep 30; : > '{}' ) &\nchild_pid=$!\nprintf '%s\\n' \"$child_pid\" > '{}'\nwhile [ ! -f '{}' ]; do /bin/sleep 0.01; done\nexit 0",
                started_marker.display(),
                late_marker.display(),
                pid_file.display(),
                started_marker.display(),
            ),
        );
        let mut command = Command::new(&gateway);
        command
            .stdin(Stdio::null())
            .arg("science-control")
            .arg("configure-third-party")
            .env("CSSWITCH_SCIENCE_CONTROL_URL", "control-url")
            .env(
                crate::runtime::science::TEST_FORCE_GROUP_KILL_FAILURE_ENV,
                "1",
            );
        let started = Instant::now();
        let error = run_bounded_control_command(
            command,
            Instant::now()
                .checked_add(Duration::from_secs(10))
                .unwrap(),
            THIRD_PARTY_CONTROL_OUTPUT_LIMIT,
            THIRD_PARTY_CONTROL_OUTPUT_LIMIT,
        )
        .unwrap_err();
        assert_eq!(
            error,
            BoundedControlCommandError::Failed(BoundedControlCommandFailure::Cleanup)
        );
        assert!(started.elapsed() < Duration::from_secs(13));
        assert_eq!(
            ThirdPartyConfigureError::Command(error).user_message(),
            "Science 未接受 CSSwitch 第三方能力配置"
        );

        let descendant_pid: i32 = fs::read_to_string(&pid_file)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        let gone = (0..100).any(|_| {
            // SAFETY: signal 0 only probes the test-owned descendant pid.
            if unsafe { crate::platform::kill(descendant_pid, 0) } == -1
                && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
            {
                return true;
            }
            std::thread::sleep(Duration::from_millis(20));
            false
        });
        assert!(started_marker.exists());
        assert!(
            gone,
            "the reaper must retain and clean descendant ownership"
        );
        assert!(!late_marker.exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn bounded_gateway_distinguishes_oversized_stdout_and_stderr() {
        use crate::runtime::science::BoundedControlOutputStream;

        let root = temp_dir("third-party-output-limit");
        for (label, body, stream) in [
            (
                "stdout-gateway",
                "exec /usr/bin/yes stdout",
                BoundedControlOutputStream::Stdout,
            ),
            (
                "stderr-gateway",
                "exec /usr/bin/yes stderr >&2",
                BoundedControlOutputStream::Stderr,
            ),
        ] {
            let gateway = control_script(&root, label, body);
            let error =
                run_test_control(&gateway, "control-url", Duration::from_secs(5)).unwrap_err();
            assert_eq!(
                error,
                ThirdPartyConfigureError::Command(BoundedControlCommandError::OutputLimit(stream)),
                "{label}"
            );
            assert_eq!(
                error.user_message(),
                "Science 未接受 CSSwitch 第三方能力配置"
            );
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn bounded_gateway_kills_output_inheriting_descendant_without_residue() {
        let root = temp_dir("third-party-descendant");
        let started_marker = root.join("descendant-started");
        let late_marker = root.join("descendant-late");
        let pid_file = root.join("descendant-pid");
        let gateway = control_script(
            &root,
            "gateway",
            &format!(
                "( : > '{}'; /bin/sleep 2; : > '{}' ) &\nchild_pid=$!\nprintf '%s\\n' \"$child_pid\" > '{}'\nwhile [ ! -f '{}' ]; do /bin/sleep 0.01; done\nprintf '%s\\n' '{}'",
                started_marker.display(),
                late_marker.display(),
                pid_file.display(),
                started_marker.display(),
                VALID_THIRD_PARTY_RESPONSE
            ),
        );

        run_test_control(&gateway, "control-url", Duration::from_secs(5)).unwrap();
        let descendant_pid: i32 = fs::read_to_string(&pid_file)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        let gone = (0..100).any(|_| {
            // SAFETY: signal 0 only probes the test-owned pid recorded by the
            // private process group; it does not send a signal.
            if unsafe { crate::platform::kill(descendant_pid, 0) } == -1
                && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
            {
                return true;
            }
            std::thread::sleep(Duration::from_millis(20));
            false
        });
        assert!(started_marker.exists());
        assert!(
            gone,
            "the output-inheriting descendant must not survive return"
        );
        std::thread::sleep(Duration::from_millis(2_100));
        assert!(!late_marker.exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn bounded_gateway_preserves_invalid_json_error_contract() {
        let root = temp_dir("third-party-invalid-json");
        let gateway = control_script(&root, "gateway", "printf '%s\\n' 'not-json'");
        let error = run_test_control(&gateway, "control-url", Duration::from_secs(5)).unwrap_err();
        assert_eq!(error, ThirdPartyConfigureError::InvalidJson);
        assert_eq!(error.user_message(), "本地 Science 第三方能力配置响应非法");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn bounded_gateway_preserves_incomplete_response_error_contract() {
        let root = temp_dir("third-party-incomplete");
        let gateway = control_script(
            &root,
            "gateway",
            "printf '%s\\n' '{\"status\":\"CONFIGURED\"}'",
        );
        let error = run_test_control(&gateway, "control-url", Duration::from_secs(5)).unwrap_err();
        assert_eq!(error, ThirdPartyConfigureError::IncompleteContract);
        assert_eq!(
            error.user_message(),
            "本地 Science 第三方能力配置结果不完整"
        );
        fs::remove_dir_all(root).unwrap();
    }
}

#[cfg(test)]
#[path = "skill_install_bridge_e2e.rs"]
mod real_science_e2e;
