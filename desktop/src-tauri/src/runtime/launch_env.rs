//! Explicit process environment allowlists for managed child launches.
//!
//! Desktop must not pass ambient parent environment into Science, the launch
//! script, or the Gateway. Children start from `env_clear` and only receive
//! variables listed here (plus later explicit `.env` calls for plan-specific
//! secrets that remain Gateway-only).

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::config;

/// Fixed PATH for managed children. Do not inherit ambient PATH.
#[cfg(target_os = "windows")]
pub(crate) const SAFE_PATH: &str =
    "C:\\Windows\\System32;C:\\Windows;C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\";
#[cfg(not(target_os = "windows"))]
pub(crate) const SAFE_PATH: &str = "/usr/bin:/bin:/usr/sbin:/sbin";

/// Fixed locale for managed children.
pub(crate) const SAFE_LANG: &str = "en_US.UTF-8";

/// Host home used by the launch script for opt-in system SSH config paths.
/// Never treated as Science HOME.
pub(crate) const HOST_HOME_ENV: &str = "CSSWITCH_HOST_HOME";

/// Explicit isolated-live marker. The launch script validates that it is
/// already running inside an outer macOS sandbox before it may disable
/// Science's incompatible nested sandbox.
pub(crate) const ACCEPTANCE_OUTER_SANDBOX_ENV: &str = "CSSWITCH_ACCEPTANCE_OUTER_SANDBOX";

#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn sandbox_check(pid: i32, operation: *const std::ffi::c_char, filter_type: i32, ...) -> i32;
}

/// Query the kernel sandbox policy for this exact process. A failed nested
/// sandbox launch is not evidence that outbound networking is denied.
pub(crate) fn current_process_denies_network_outbound() -> bool {
    #[cfg(target_os = "macos")]
    {
        let operation = b"network-outbound\0";
        // SAFETY: sandbox_check reads the static NUL-terminated operation and
        // SANDBOX_FILTER_NONE (0) has no variadic filter arguments.
        unsafe { sandbox_check(std::process::id() as i32, operation.as_ptr().cast(), 0) > 0 }
    }
    #[cfg(not(target_os = "macos"))]
    {
        false
    }
}

/// Clear child environment, then set only the provided pairs.
pub(crate) fn apply_allowlist<K, V, I>(cmd: &mut Command, pairs: I)
where
    K: AsRef<OsStr>,
    V: AsRef<OsStr>,
    I: IntoIterator<Item = (K, V)>,
{
    cmd.env_clear();
    for (key, value) in pairs {
        cmd.env(key, value);
    }
}

/// Minimal OS surface shared by Gateway, Science launch script, and stop script.
pub(crate) fn base_process_env() -> Vec<(String, String)> {
    let mut env = vec![
        ("PATH".into(), SAFE_PATH.into()),
        ("TMPDIR".into(), default_tmpdir()),
        ("LANG".into(), SAFE_LANG.into()),
        ("LC_ALL".into(), SAFE_LANG.into()),
    ];
    #[cfg(target_os = "windows")]
    {
        // Windows 进程缺 SystemRoot 等系统变量时 CRT/Winsock 初始化会失败，
        // 子进程可能直接崩溃。这些是 OS 运行必需项，不属于用户隐私泄漏面。
        for key in [
            "SystemRoot",
            "SystemDrive",
            "windir",
            "ComSpec",
            "PATHEXT",
            "TEMP",
            "TMP",
        ] {
            if let Some(value) = std::env::var_os(key) {
                env.push((key.to_string(), value.to_string_lossy().into_owned()));
            }
        }
    }
    env
}

fn default_tmpdir() -> String {
    if cfg!(target_os = "macos") {
        "/private/tmp".into()
    } else if cfg!(target_os = "windows") {
        std::env::var("TEMP")
            .or_else(|_| std::env::var("TMP"))
            .unwrap_or_else(|_| "C:\\Windows\\Temp".into())
    } else {
        "/tmp".into()
    }
}

/// 打包 shell 脚本的解释器。Windows 上没有 zsh，统一用 Git Bash 的 bash
/// 执行经过 bash 兼容化移植的脚本副本。裸调 "bash" 会经系统 PATH 解析到
/// System32 的 WSL bash（把 C:/ 路径当 Linux 路径，报 No such file），
/// 因此显式探测 Git Bash 安装位置；CSSWITCH_GIT_BASH 可覆盖。
#[cfg(target_os = "windows")]
pub(crate) fn science_script_shell() -> String {
    if let Some(explicit) = std::env::var_os("CSSWITCH_GIT_BASH") {
        let explicit = explicit.to_string_lossy().into_owned();
        if std::path::Path::new(&explicit).is_file() {
            return explicit;
        }
    }
    for candidate in [
        r"C:\Program Files\Git\bin\bash.exe",
        r"C:\Program Files\Git\usr\bin\bash.exe",
        r"C:\Program Files (x86)\Git\bin\bash.exe",
        r"C:\Program Files (x86)\Git\usr\bin\bash.exe",
    ] {
        if std::path::Path::new(candidate).is_file() {
            return candidate.to_string();
        }
    }
    "bash".to_string()
}
#[cfg(not(target_os = "windows"))]
pub(crate) fn science_script_shell() -> &'static str {
    "zsh"
}

/// Real user home that owns `~/.csswitch` (parent of config dir).
/// Used only for host-side paths such as system SSH config resolution.
/// Never used as Science sandbox HOME.
pub(crate) fn host_home_dir() -> PathBuf {
    config::default_dir()
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."))
}

/// Absolute host HOME for children that need `$HOME/.csswitch` or real-path
/// collision checks. Prefer the config-dir parent; fall back to current_dir
/// only when that path is somehow relative.
pub(crate) fn absolute_host_home_dir() -> PathBuf {
    let home = host_home_dir();
    if home.is_absolute() {
        return home;
    }
    std::env::current_dir()
        .map(|cwd| cwd.join(&home))
        .unwrap_or(home)
}

/// Control-plane environment for `scripts/launch-virtual-sandbox.sh`.
/// Provider credentials must never appear here.
pub(crate) struct ScienceLaunchScriptEnv<'a> {
    pub sandbox_home: &'a Path,
    pub science_bin: &'a Path,
    pub proxy_url: &'a str,
    pub reuse_system_ssh: bool,
    pub system_ssh_hosts: &'a str,
    pub opaque_bindings: Option<&'a str>,
    pub runtime_version_prechecked: bool,
    pub acceptance_outer_sandbox: bool,
}

pub(crate) fn science_launch_script_env(cfg: &ScienceLaunchScriptEnv<'_>) -> Vec<(String, String)> {
    let mut env = base_process_env();
    env.push((
        HOST_HOME_ENV.into(),
        absolute_host_home_dir().display().to_string(),
    ));
    env.push((
        "SANDBOX_HOME".into(),
        cfg.sandbox_home.display().to_string(),
    ));
    env.push(("SCIENCE_BIN".into(), cfg.science_bin.display().to_string()));
    env.push(("CSSWITCH_PROXY_URL".into(), cfg.proxy_url.into()));
    env.push((
        "CSSWITCH_REUSE_SYSTEM_SSH".into(),
        if cfg.reuse_system_ssh {
            "1".into()
        } else {
            "0".into()
        },
    ));
    env.push((
        "CSSWITCH_SYSTEM_SSH_HOSTS".into(),
        cfg.system_ssh_hosts.into(),
    ));
    if cfg.runtime_version_prechecked {
        env.push(("CSSWITCH_RUNTIME_VERSION_PRECHECKED".into(), "1".into()));
    }
    if cfg.acceptance_outer_sandbox {
        env.push((ACCEPTANCE_OUTER_SANDBOX_ENV.into(), "1".into()));
    }
    if let Some(bindings) = cfg.opaque_bindings {
        if !bindings.is_empty() {
            env.push(("CSSWITCH_SCIENCE_OPAQUE_BINDINGS".into(), bindings.into()));
        }
    }
    env
}

pub(crate) fn configure_science_launch_script_command(
    cmd: &mut Command,
    cfg: &ScienceLaunchScriptEnv<'_>,
) {
    apply_allowlist(cmd, science_launch_script_env(cfg));
}

/// Environment for `scripts/stop-science-sandbox.sh`.
/// Includes `CSSWITCH_HOST_HOME` so the stop script can resolve the real-data-dir
/// collision guard without ambient `HOME`.
pub(crate) fn science_stop_script_env(
    sandbox_home: &Path,
    science_bin: &Path,
) -> Vec<(String, String)> {
    let mut env = base_process_env();
    env.push((
        HOST_HOME_ENV.into(),
        absolute_host_home_dir().display().to_string(),
    ));
    env.push(("SANDBOX_HOME".into(), sandbox_home.display().to_string()));
    env.push(("SCIENCE_BIN".into(), science_bin.display().to_string()));
    env
}

pub(crate) fn configure_science_stop_script_command(
    cmd: &mut Command,
    sandbox_home: &Path,
    science_bin: &Path,
) {
    apply_allowlist(cmd, science_stop_script_env(sandbox_home, science_bin));
}

/// Gateway base allowlist before plan-specific secrets and contract env.
/// Includes absolute host `HOME` so adapters that store state under
/// `$HOME/.csswitch` (notably Codex) keep working without ambient inheritance.
pub(crate) fn gateway_base_env() -> Vec<(String, String)> {
    let mut env = base_process_env();
    env.push((
        "HOME".into(),
        absolute_host_home_dir().display().to_string(),
    ));
    env
}

pub(crate) fn configure_gateway_base_command(cmd: &mut Command) {
    apply_allowlist(cmd, gateway_base_env());
}

/// Keys that may appear after `configure_managed_proxy_command` base setup.
#[cfg(test)]
pub(crate) fn gateway_base_env_keys() -> &'static [&'static str] {
    &[
        "PATH",
        "TMPDIR",
        "LANG",
        "LC_ALL",
        "HOME",
        "CSSWITCH_AUTH_TOKEN",
        "CSSWITCH_LAUNCH_ID",
        "CSSWITCH_TOOLUSE_SHIM",
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::sync::Mutex;

    // Process-global env mutations must be serialized across these tests.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn env_map_keys(pairs: &[(String, String)]) -> HashSet<String> {
        pairs.iter().map(|(k, _)| k.clone()).collect()
    }

    #[test]
    fn base_process_env_is_fixed_allowlist() {
        let env = base_process_env();
        let keys = env_map_keys(&env);
        assert_eq!(
            keys,
            HashSet::from([
                "PATH".into(),
                "TMPDIR".into(),
                "LANG".into(),
                "LC_ALL".into()
            ])
        );
        assert_eq!(
            env.iter()
                .find(|(k, _)| k == "PATH")
                .map(|(_, v)| v.as_str()),
            Some(SAFE_PATH)
        );
        assert!(!env
            .iter()
            .any(|(k, _)| k.contains("API_KEY") || k.contains("SECRET")));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn sandbox_query_distinguishes_deny_egress_from_permissive_outer() {
        const CHILD_ENV: &str = "CSSWITCH_SANDBOX_QUERY_TEST_EXPECTED";
        if let Ok(expected) = std::env::var(CHILD_ENV) {
            assert_eq!(
                current_process_denies_network_outbound(),
                expected == "denied"
            );
            return;
        }
        let nesting_available = Command::new("/usr/bin/sandbox-exec")
            .args(["-p", "(version 1)(allow default)", "/usr/bin/true"])
            .status()
            .map(|status| status.success())
            .unwrap_or(false);
        if !nesting_available {
            return;
        }
        let current_exe = std::env::current_exe().expect("current test executable");
        let test_name =
            "runtime::launch_env::tests::sandbox_query_distinguishes_deny_egress_from_permissive_outer";
        for (profile, expected) in [
            (
                "(version 1)(allow default)(deny network-outbound)(allow network-outbound (remote ip \"localhost:*\"))",
                "denied",
            ),
            (
                "(version 1)(allow default)(deny process-exec (literal \"/usr/bin/sandbox-exec\"))",
                "allowed",
            ),
        ] {
            let status = Command::new("/usr/bin/sandbox-exec")
                .args(["-p", profile])
                .arg(&current_exe)
                .args(["--exact", test_name, "--nocapture"])
                .env(CHILD_ENV, expected)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .expect("sandbox query child must run");
            assert!(status.success(), "sandbox query child failed for {expected}");
        }
    }

    #[test]
    fn science_launch_script_env_excludes_provider_secrets() {
        let home = Path::new("/tmp/csswitch-sandbox-home");
        let bin = Path::new("/tmp/fake-claude-science");
        let env = science_launch_script_env(&ScienceLaunchScriptEnv {
            sandbox_home: home,
            science_bin: bin,
            proxy_url: "http://127.0.0.1:18991/deadbeef",
            reuse_system_ssh: false,
            system_ssh_hosts: "",
            opaque_bindings: Some("binding=value"),
            runtime_version_prechecked: true,
            acceptance_outer_sandbox: false,
        });
        let keys = env_map_keys(&env);
        for forbidden in [
            "DEEPSEEK_API_KEY",
            "OPENAI_API_KEY",
            "CSSWITCH_RELAY_KEY",
            "CSSWITCH_OPENAI_KEY",
            "CSSWITCH_AUTH_TOKEN",
            "AWS_SECRET_ACCESS_KEY",
            "SSH_AUTH_SOCK",
            "CSSWITCH_TEST_SENTINEL_SECRET",
        ] {
            assert!(
                !keys.contains(forbidden),
                "science control env must not include {forbidden}"
            );
        }
        assert!(keys.contains(HOST_HOME_ENV));
        assert!(keys.contains("SANDBOX_HOME"));
        assert!(keys.contains("SCIENCE_BIN"));
        assert!(keys.contains("CSSWITCH_PROXY_URL"));
        assert!(keys.contains("CSSWITCH_SCIENCE_OPAQUE_BINDINGS"));
        assert!(!keys.contains(ACCEPTANCE_OUTER_SANDBOX_ENV));
        assert_eq!(
            env.iter()
                .find(|(k, _)| k == "CSSWITCH_REUSE_SYSTEM_SSH")
                .map(|(_, v)| v.as_str()),
            Some("0")
        );
    }

    #[test]
    fn science_launch_script_env_ssh_flag_only_when_enabled() {
        let home = Path::new("/tmp/csswitch-sandbox-home");
        let bin = Path::new("/tmp/fake-claude-science");
        let off = science_launch_script_env(&ScienceLaunchScriptEnv {
            sandbox_home: home,
            science_bin: bin,
            proxy_url: "http://127.0.0.1:1/x",
            reuse_system_ssh: false,
            system_ssh_hosts: "lab",
            opaque_bindings: None,
            runtime_version_prechecked: true,
            acceptance_outer_sandbox: false,
        });
        assert_eq!(
            off.iter()
                .find(|(k, _)| k == "CSSWITCH_REUSE_SYSTEM_SSH")
                .map(|(_, v)| v.as_str()),
            Some("0")
        );
        // Host list may be present but empty-use; flag off is the contract.
        let on = science_launch_script_env(&ScienceLaunchScriptEnv {
            sandbox_home: home,
            science_bin: bin,
            proxy_url: "http://127.0.0.1:1/x",
            reuse_system_ssh: true,
            system_ssh_hosts: "lab",
            opaque_bindings: None,
            runtime_version_prechecked: true,
            acceptance_outer_sandbox: true,
        });
        assert_eq!(
            on.iter()
                .find(|(k, _)| k == "CSSWITCH_REUSE_SYSTEM_SSH")
                .map(|(_, v)| v.as_str()),
            Some("1")
        );
        assert_eq!(
            on.iter()
                .find(|(k, _)| k == "CSSWITCH_SYSTEM_SSH_HOSTS")
                .map(|(_, v)| v.as_str()),
            Some("lab")
        );
        assert_eq!(
            on.iter()
                .find(|(k, _)| k == ACCEPTANCE_OUTER_SANDBOX_ENV)
                .map(|(_, v)| v.as_str()),
            Some("1")
        );
    }

    #[test]
    fn apply_allowlist_drops_parent_sentinel() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let sentinel_key = "CSSWITCH_TEST_SENTINEL_SECRET";
        let sentinel_value = "parent-ambient-must-not-leak";
        let previous = std::env::var_os(sentinel_key);
        std::env::set_var(sentinel_key, sentinel_value);
        // Also pollute a common provider key name.
        let provider_key = "OPENAI_API_KEY";
        let previous_provider = std::env::var_os(provider_key);
        std::env::set_var(provider_key, "sk-parent-leak");

        let mut cmd = Command::new("/usr/bin/env");
        apply_allowlist(&mut cmd, base_process_env());
        let output = cmd
            .output()
            .expect("/usr/bin/env should run under allowlist");
        assert!(
            output.status.success(),
            "env failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(!stdout.contains(sentinel_key), "child saw sentinel key");
        assert!(!stdout.contains(sentinel_value), "child saw sentinel value");
        assert!(!stdout.contains(provider_key));
        assert!(!stdout.contains("sk-parent-leak"));
        assert!(stdout.contains("PATH="));
        assert!(stdout.contains(SAFE_PATH));

        match previous {
            Some(value) => std::env::set_var(sentinel_key, value),
            None => std::env::remove_var(sentinel_key),
        }
        match previous_provider {
            Some(value) => std::env::set_var(provider_key, value),
            None => std::env::remove_var(provider_key),
        }
    }

    #[test]
    fn science_stop_script_env_is_minimal() {
        let env = science_stop_script_env(Path::new("/tmp/sbx"), Path::new("/tmp/bin"));
        let keys = env_map_keys(&env);
        assert!(keys.contains("SANDBOX_HOME"));
        assert!(keys.contains("SCIENCE_BIN"));
        assert!(keys.contains("PATH"));
        assert!(keys.contains(HOST_HOME_ENV));
        assert!(!keys.contains("CSSWITCH_PROXY_URL"));
        assert!(!keys.contains("DEEPSEEK_API_KEY"));
        // Stop must not receive provider secrets or proxy URL.
        assert!(!keys.contains("CSSWITCH_AUTH_TOKEN"));
    }

    #[test]
    fn gateway_base_env_includes_absolute_home_without_secrets() {
        let env = gateway_base_env();
        let keys = env_map_keys(&env);
        assert!(keys.contains("HOME"));
        assert!(keys.contains("PATH"));
        assert!(!keys.contains("OPENAI_API_KEY"));
        assert!(!keys.contains("DEEPSEEK_API_KEY"));
        assert!(!keys.contains("CSSWITCH_AUTH_TOKEN"));
        let home = env
            .iter()
            .find(|(k, _)| k == "HOME")
            .map(|(_, v)| v.as_str())
            .expect("HOME");
        assert!(
            Path::new(home).is_absolute(),
            "gateway HOME must be absolute for Codex state root: {home}"
        );
    }

    #[test]
    fn gateway_allowlist_child_keeps_home_drops_parent_secret() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let previous = std::env::var_os("OPENAI_API_KEY");
        std::env::set_var("OPENAI_API_KEY", "sk-parent-must-not-reach-gateway-child");
        let mut cmd = Command::new("/usr/bin/env");
        apply_allowlist(&mut cmd, gateway_base_env());
        let output = cmd.output().expect("env under gateway allowlist");
        assert!(output.status.success());
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            !stdout.contains("OPENAI_API_KEY"),
            "gateway child saw parent OPENAI_API_KEY"
        );
        assert!(
            !stdout.contains("sk-parent-must-not-reach-gateway-child"),
            "gateway child saw parent secret value"
        );
        assert!(stdout.contains("HOME="));
        let home_line = stdout
            .lines()
            .find(|line| line.starts_with("HOME="))
            .expect("HOME line");
        let home = &home_line["HOME=".len()..];
        assert!(
            Path::new(home).is_absolute(),
            "child HOME not absolute: {home}"
        );
        match previous {
            Some(value) => std::env::set_var("OPENAI_API_KEY", value),
            None => std::env::remove_var("OPENAI_API_KEY"),
        }
    }
}
