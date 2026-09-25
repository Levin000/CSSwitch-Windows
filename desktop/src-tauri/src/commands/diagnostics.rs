use std::process::Command;

use serde::Serialize;

use crate::lifecycle::RuntimeMutationDomain;
use crate::provider_contracts::AuthMode;
use crate::runtime::provider::adapter_for_profile;
use crate::runtime::sandbox_session::{SkillRouteRepairOutcome, SkillRouteRepairStatus};
use crate::runtime::system::{canonical_asset_root, open_in_browser};
use crate::{config, run_blocking, SharedAppState, SharedLifecycle};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum DoctorIntent {
    ReadOnlyDiagnostics,
    RepairSkillRoute,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ReadOnlyDoctorStatus {
    Passed,
    IssuesFound,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct ReadOnlyDoctorResult {
    schema_version: u8,
    intent: DoctorIntent,
    status: ReadOnlyDoctorStatus,
    message: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct SkillRouteRepairResult {
    schema_version: u8,
    intent: DoctorIntent,
    status: SkillRouteRepairStatus,
    message: String,
}

#[tauri::command]
pub(crate) async fn run_doctor_read_only(
    app: tauri::AppHandle,
) -> Result<ReadOnlyDoctorResult, String> {
    run_blocking(move || run_doctor_read_only_cmd(&app)).await
}

#[tauri::command]
pub(crate) async fn repair_skill_route(
    app: tauri::AppHandle,
    state: tauri::State<'_, SharedAppState>,
    lifecycle: tauri::State<'_, SharedLifecycle>,
) -> Result<SkillRouteRepairResult, String> {
    let state = state.inner().clone();
    let lifecycle = lifecycle.inner().clone();
    run_blocking(move || repair_skill_route_cmd(&app, &state, &lifecycle)).await
}

fn repair_skill_route_cmd<R: tauri::Runtime>(
    app: &tauri::AppHandle<R>,
    state: &SharedAppState,
    lifecycle: &SharedLifecycle,
) -> Result<SkillRouteRepairResult, String> {
    let SkillRouteRepairOutcome { status, message } = lifecycle
        .with_mutation(RuntimeMutationDomain::HostBridge, |_| {
            crate::runtime::sandbox_session::force_third_party_reconcile(app, state)
        })?;
    Ok(SkillRouteRepairResult {
        schema_version: 1,
        intent: DoctorIntent::RepairSkillRoute,
        status,
        message,
    })
}

fn run_doctor_read_only_cmd<R: tauri::Runtime>(
    app: &tauri::AppHandle<R>,
) -> Result<ReadOnlyDoctorResult, String> {
    let root = canonical_asset_root(app)
        .ok_or("找不到 scripts/doctor.sh（打包资源或可执行文件祖先均未命中）。")?;
    let config_dir = config::default_dir();
    let config_path = config_dir.join("config.json");
    let cfg = doctor_config_from(&config_dir)?;
    let doctor = root.join("scripts/doctor.sh");
    // 生效 profile 的展示名（template_id）+ adapter + 脱敏认证类型；无生效配置则留空。
    let (provider_label, adapter, auth_mode, has_key) = match cfg.active_profile() {
        Some(profile) => {
            let public = crate::runtime::provider::resolve_launch_plan(profile)
                .ok()
                .map(|plan| plan.public());
            let auth_mode = match public.as_ref().map(|view| view.auth_mode) {
                Some(AuthMode::ApiKey) => "api_key",
                Some(AuthMode::CsswitchOauth) => "csswitch_oauth",
                Some(AuthMode::None) => "none",
                None => "",
            };
            let has_key = public.as_ref().is_some_and(|view| {
                view.auth_mode == AuthMode::ApiKey && view.credential_configured
            });
            (
                profile.template_id.clone(),
                adapter_for_profile(profile),
                auth_mode,
                has_key,
            )
        }
        None => (String::new(), String::new(), "", false),
    };
    let gateway = crate::runtime::proxy_lifecycle::doctor_gateway_bin_path(app);
    let mut cmd = Command::new(if cfg!(target_os = "windows") {
        crate::runtime::launch_env::science_script_shell()
    } else {
        "/bin/bash".to_string()
    });
    harden_doctor_command(&mut cmd, &config_path, gateway.as_deref());
    // 多 profile：传 template_id + adapter + key 有无（布尔）。doctor 不再按 provider 名写死、
    // 不再去 shell 环境找 key（key 存 config.json）。绝不把真实 key 值传进其环境。
    cmd.arg(crate::platform::bash_path(&doctor))
        .env("CSSWITCH_PROVIDER", &provider_label)
        .env("CSSWITCH_ADAPTER", adapter)
        .env("CSSWITCH_AUTH_MODE", auth_mode)
        .env("CSSWITCH_KEY_PRESENT", if has_key { "1" } else { "0" })
        .env("CSSWITCH_PROXY_PORT", cfg.proxy_port.to_string())
        .env("CSSWITCH_SANDBOX_PORT", cfg.sandbox_port.to_string());
    let out = cmd.output().map_err(|e| e.to_string())?;
    let mut text = String::from_utf8_lossy(&out.stdout).to_string();
    let err = String::from_utf8_lossy(&out.stderr);
    if !err.trim().is_empty() {
        text.push_str("\n[stderr] ");
        text.push_str(err.trim());
    }
    let codex_profile_count = cfg
        .profiles
        .iter()
        .filter(|profile| profile.template_id == "codex")
        .count();
    let auth_summary = if cfg.experimental_codex_enabled || codex_profile_count > 0 {
        super::codex::codex_auth_diagnostic_summary(app)
    } else {
        "auth=not_checked".into()
    };
    text.push_str("\n[Codex 实验]\n  开关=");
    text.push_str(if cfg.experimental_codex_enabled {
        "启用"
    } else {
        "关闭"
    });
    text.push_str(&format!("  配置数={codex_profile_count}  {auth_summary}\n"));
    match csswitch_codex_network::resolve_from_process(&cfg.codex_network) {
        Ok(route) => {
            text.push_str("  网络来源=");
            text.push_str(route.source.as_str());
            text.push_str("  代理类型=");
            text.push_str(route.proxy_scheme.as_deref().unwrap_or("none"));
            if route.source == csswitch_codex_network::RouteSource::Direct {
                text.push_str("  说明=直接 socket，可能由系统 TUN 接管");
            }
            text.push('\n');
        }
        Err(error) => {
            text.push_str("  网络来源=invalid  错误=");
            text.push_str(error.code());
            text.push('\n');
        }
    }
    Ok(ReadOnlyDoctorResult {
        schema_version: 1,
        intent: DoctorIntent::ReadOnlyDiagnostics,
        status: if out.status.success() {
            ReadOnlyDoctorStatus::Passed
        } else {
            ReadOnlyDoctorStatus::IssuesFound
        },
        message: text,
    })
}

fn harden_doctor_command(
    cmd: &mut Command,
    config_path: &std::path::Path,
    gateway_bin: Option<&std::path::Path>,
) {
    cmd.env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .env("LC_ALL", "C")
        .env("CSSWITCH_CONFIG", config_path)
        .env("SCIENCE_BIN", crate::runtime::science::SCIENCE_BIN)
        .env("CSSWITCH_DOCTOR_CHECK_REAL_HOME", "0")
        .env(
            "CSSWITCH_GATEWAY_BIN",
            gateway_bin.unwrap_or_else(|| std::path::Path::new("")),
        );
}

fn doctor_config_from(dir: &std::path::Path) -> Result<config::Config, String> {
    config::load_current_from_read_only(dir)
        .map_err(|e| format!("只读配置检查失败，无法运行自检：{e}"))
}

/// 当前 app 版本（供前端「检查更新」与页脚版本号用）。
#[tauri::command]
pub(crate) fn app_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// 打开 GitHub Releases 页（检查更新时用系统浏览器打开，浏览器走用户自己的代理）。
#[tauri::command]
pub(crate) fn open_release_page() -> Result<(), String> {
    open_in_browser("https://github.com/SuperJJ007/CSSwitch/releases/latest")
}

/// 打开「报 bug」页（预填 bug 模板）；用系统浏览器，走用户自己的代理。
#[tauri::command]
pub(crate) fn report_bug() -> Result<(), String> {
    open_in_browser("https://github.com/SuperJJ007/CSSwitch/issues/new?template=bug_report.yml")
}

/// 在访达里打开构建变体自己的日志目录，方便用户附到 bug 反馈里（先自查有无密钥）。
#[tauri::command]
pub(crate) fn open_logs() -> Result<(), String> {
    let dir = config::default_dir().join("logs");
    let _ = std::fs::create_dir_all(&dir);
    #[cfg(target_os = "windows")]
    let opener = "explorer";
    #[cfg(not(target_os = "windows"))]
    let opener = "open";
    Command::new(opener)
        .arg(&dir)
        .status()
        .map_err(|e| format!("打开日志目录失败：{e}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        doctor_config_from, harden_doctor_command, DoctorIntent, ReadOnlyDoctorStatus,
        SkillRouteRepairStatus,
    };
    use crate::runtime::skill_install_bridge::{
        mark_route_configuration_current, route_configuration_is_current,
    };
    use crate::{AppState, SharedAppState, SharedLifecycle};
    use std::env;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::process::Command;
    use std::sync::{Arc, Mutex};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn tmpdir(name: &str) -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("csswitch-doctor-{name}-{nanos}"))
    }

    #[test]
    fn doctor_config_rejects_reserved_port_instead_of_defaulting() {
        let dir = tmpdir("reserved-port");
        fs::create_dir_all(&dir).unwrap();
        let cfg = crate::config::Config {
            proxy_port: 8765,
            ..Default::default()
        };
        fs::write(
            dir.join("config.json"),
            serde_json::to_vec_pretty(&cfg).unwrap(),
        )
        .unwrap();

        let err = doctor_config_from(&dir).unwrap_err();
        assert!(err.contains("只读配置检查失败"));
        assert!(err.contains("8765"));
    }

    #[test]
    fn d0_doctor_read_only_rejects_legacy_without_migration_or_permission_change() {
        let dir = tmpdir("legacy-read-only");
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.json");
        let legacy = br#"{"schema_version":2,"profiles":[],"active_id":"","proxy_port":18991,"sandbox_port":8990}"#;
        fs::write(&path, legacy).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        let before_mode = fs::metadata(&path).unwrap().permissions().mode();

        let err = doctor_config_from(&dir).unwrap_err();
        assert!(err.contains("read-only consumer requires canonical schema v4"));
        assert_eq!(fs::read(&path).unwrap(), legacy);
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode(),
            before_mode
        );
        assert!(!dir.join("config.json.v2.bak").exists());
        assert!(!dir.join("config.json.v3.bak").exists());

        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn d0_doctor_child_environment_rejects_hostile_parent_overrides() {
        let dir = tmpdir("hostile-parent-env");
        let hostile_home = dir.join("hostile-home");
        let real_science_home = hostile_home.join(".claude-science");
        fs::create_dir_all(&real_science_home).unwrap();
        let config_path = dir.join("config.json");
        fs::write(&config_path, b"{}").unwrap();
        fs::set_permissions(&config_path, fs::Permissions::from_mode(0o600)).unwrap();
        let doctor =
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../scripts/doctor.sh");

        let mut cmd = std::process::Command::new("/bin/bash");
        cmd.arg(&doctor)
            .env("HOME", &hostile_home)
            .env("CSSWITCH_DOCTOR_CHECK_REAL_HOME", "1")
            .env("CSSWITCH_CONFIG", dir.join("hostile-config.json"))
            .env("SCIENCE_BIN", dir.join("hostile-science"))
            .env("CSSWITCH_GATEWAY_BIN", dir.join("hostile-gateway"));
        harden_doctor_command(&mut cmd, &config_path, None);
        let output = cmd.output().unwrap();
        let text = String::from_utf8_lossy(&output.stdout);

        assert!(output.status.success());
        assert!(text.contains("真实 HOME 检查默认跳过"));
        assert!(text.contains(&config_path.display().to_string()));
        assert!(!text.contains(&hostile_home.display().to_string()));
        assert!(!text.contains("hostile-config"));
        assert!(!text.contains("hostile-science"));
        assert!(!text.contains("hostile-gateway"));

        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn r0_doctor_diagnostic_failure_skips_reconcile() {
        let child_name =
            "commands::diagnostics::tests::isolated_r0_doctor_diagnostic_failure_skips_reconcile";
        let output = Command::new(env::current_exe().unwrap())
            .arg("--exact")
            .arg(child_name)
            .arg("--ignored")
            .arg("--nocapture")
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success()
                && stdout.lines().any(|line| line == "running 1 test")
                && stdout
                    .lines()
                    .any(|line| line == format!("test {child_name} ... ok")),
            "isolated doctor characterization failed:\nstdout={}\nstderr={}",
            stdout,
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    #[ignore = "source-gate parent runs both split Doctor intent bodies in an isolated HOME"]
    fn isolated_r0_doctor_diagnostic_failure_skips_reconcile() {
        let root = tmpdir("r0-command-sequence");
        fs::create_dir_all(&root).unwrap();
        let root = root.canonicalize().unwrap();
        let home = root.join("home");
        let repo = root.join("repo");
        let doctor = repo.join("scripts/doctor.sh");
        fs::create_dir_all(doctor.parent().unwrap()).unwrap();
        fs::create_dir_all(repo.join("desktop/gateway")).unwrap();
        fs::write(
            repo.join("desktop/gateway/Cargo.toml"),
            b"[package]\nname='fake'\n",
        )
        .unwrap();
        fs::write(&doctor, b"#!/bin/sh\nprintf 'doctor-hostile\\n'\n").unwrap();
        fs::set_permissions(&doctor, fs::Permissions::from_mode(0o700)).unwrap();
        let hostile_gateway = repo.join("hostile-gateway");
        fs::write(&hostile_gateway, b"#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(&hostile_gateway, fs::Permissions::from_mode(0o700)).unwrap();
        fs::create_dir_all(&home).unwrap();
        env::set_var("HOME", &home);
        env::set_var("CSSWITCH_REPO", &repo);
        env::set_var("CSSWITCH_GATEWAY_BIN", &hostile_gateway);
        env::set_var("CSSWITCH_DOCTOR_CHECK_REAL_HOME", "1");

        let config_dir = crate::config::default_dir();
        let data_dir = config_dir.join("sandbox/home/.claude-science");
        fs::create_dir_all(&data_dir).unwrap();
        mark_route_configuration_current(&data_dir, "science-v1").unwrap();
        fs::write(config_dir.join("config.json"), b"{invalid-config").unwrap();

        let state: SharedAppState = Arc::new(Mutex::new(AppState::default()));
        let lifecycle: SharedLifecycle = Arc::new(crate::lifecycle::Lifecycle::new());
        let app = tauri::test::mock_builder()
            .build(tauri::test::mock_context(tauri::test::noop_assets()))
            .unwrap();

        let first = super::run_doctor_read_only_cmd(app.handle()).unwrap_err();
        assert!(first.contains("只读配置检查失败"));
        assert!(route_configuration_is_current(&data_dir, "science-v1").unwrap());
        assert!(config_dir.join("config.json").is_file());
        assert!(!config_dir.join("config.json.v2.bak").exists());

        let cfg = crate::config::Config {
            proxy_port: 18_992,
            sandbox_port: 18_993,
            ..Default::default()
        };
        crate::config::save_to(&config_dir, &cfg).unwrap();
        let second = super::run_doctor_read_only_cmd(app.handle()).unwrap();
        assert_eq!(second.intent, DoctorIntent::ReadOnlyDiagnostics);
        assert_eq!(second.status, ReadOnlyDoctorStatus::Passed);
        assert!(second.message.contains("诊断完成"));
        assert!(second.message.contains("真实 HOME 检查默认跳过"));
        assert!(!second.message.contains("doctor-hostile"));
        assert!(!second.message.contains(&repo.display().to_string()));
        assert_eq!(
            serde_json::to_value(&second).unwrap()["intent"],
            "read_only_diagnostics"
        );
        assert_eq!(serde_json::to_value(&second).unwrap()["status"], "passed");
        assert!(route_configuration_is_current(&data_dir, "science-v1").unwrap());

        let repair = super::repair_skill_route_cmd(app.handle(), &state, &lifecycle).unwrap();
        assert_eq!(repair.intent, DoctorIntent::RepairSkillRoute);
        assert_eq!(repair.status, SkillRouteRepairStatus::Deferred);
        assert_eq!(
            serde_json::to_value(&repair).unwrap()["intent"],
            "repair_skill_route"
        );
        assert_eq!(serde_json::to_value(&repair).unwrap()["status"], "deferred");
        assert!(!route_configuration_is_current(&data_dir, "science-v1").unwrap());

        drop(app);
        fs::remove_dir_all(root).unwrap();
    }
}
