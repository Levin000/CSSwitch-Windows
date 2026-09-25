//! CSSwitch 桌面 app 后端（进程管家）。
//!
//! 职责：管理「翻译代理」与「沙箱 Science」两个子进程的生命周期；读写
//! `~/.csswitch/config.json`（多 profile 形态）；把第三方 key 以【环境变量】注入代理子进程
//! （绝不进 argv）；探活；把沙箱 URL 交系统浏览器打开。推理与协议转换由随包交付的
//! Rust `csswitch-gateway` 完成；沙箱脚本仍作为受管子进程保留铁律护栏。
//!
//! 运行行为由 typed provider-contract catalog 与生效 profile 合并成受限 launch plan，
//! 再投影给 formal gateway、scratch 和前端；展示模板不再决定 adapter/鉴权/transport。
//!
//! 铁律相关：API key 只在内存与 0600 的 config.json，OAuth token 只在 CSSwitch 私有认证文件；回显前端只给掩码/脱敏状态；沙箱端口/目录护栏
//! 由被调脚本负责（对 8765 与真实目录失败关闭）；关窗只隐藏，显式退出停代理与沙箱。

mod codex_auth_supervisor;
mod commands;
mod config;
mod config_legacy;
mod lifecycle;
mod model_catalog;
mod oauth_forge;
mod opencode_go_models;
mod proc;
mod provider_contracts;
mod platform;
mod runtime;
mod scratch;
mod templates;

use std::process::Child;
use std::sync::{Arc, Mutex};

use tauri::{Emitter, Manager};

use runtime::{science::ScienceHostAdapter, system::stop_child_confirmed};

use codex_auth_supervisor::{CodexAuthSupervisor, SharedCodexAuthSupervisor};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LaunchPath {
    ShowPanel,
    OpenOfficial,
    BootScience,
}

fn decide_launch_with_auto_boot(cfg: &config::Config, auto_boot: bool) -> LaunchPath {
    if !auto_boot {
        return LaunchPath::ShowPanel;
    }
    if cfg.mode == "official" {
        return LaunchPath::OpenOfficial;
    }
    match cfg.active_profile() {
        Some(p)
            if config::require_template_enabled(cfg, &p.template_id).is_ok()
                && p.template_id != "codex"
                && runtime::provider::resolve_launch_plan(p)
                    .map(|plan| plan.public().credential_configured)
                    .unwrap_or(false) =>
        {
            LaunchPath::BootScience
        }
        _ => LaunchPath::ShowPanel,
    }
}

fn decide_launch(cfg: &config::Config) -> LaunchPath {
    let auto_boot = std::env::var("CSSWITCH_AUTO_BOOT_ON_LAUNCH")
        .ok()
        .as_deref()
        == Some("1");
    decide_launch_with_auto_boot(cfg, auto_boot)
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum BootState {
    #[default]
    Idle,
    Starting,
    Ready,
    Failed,
    Attention,
}

fn should_begin_boot(state: BootState) -> bool {
    matches!(
        state,
        BootState::Idle | BootState::Failed | BootState::Attention
    )
}

impl BootState {
    fn code(self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::Starting => "starting",
            Self::Ready => "ready",
            Self::Failed => "failed",
            Self::Attention => "attention",
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub(crate) struct BootPublication {
    pub(crate) sequence: u64,
    pub(crate) state: BootState,
    pub(crate) payload: Option<serde_json::Value>,
}

impl BootPublication {
    pub(crate) fn transition(
        &mut self,
        state: BootState,
        payload: Option<serde_json::Value>,
    ) -> serde_json::Value {
        self.sequence = self.sequence.saturating_add(1);
        self.state = state;
        self.payload = payload;
        self.snapshot()
    }

    pub(crate) fn snapshot(&self) -> serde_json::Value {
        serde_json::json!({
            "sequence": self.sequence,
            "state": self.state.code(),
            "payload": self.payload,
        })
    }
}

#[derive(Clone, Default)]
pub(crate) struct RejectedGatewayRegistry {
    inner: Arc<Mutex<RejectedGatewayRegistryState>>,
}

#[derive(Default)]
struct RejectedGatewayRegistryState {
    children: Vec<Child>,
    cleanup_in_progress: bool,
    cleanup_owned_count: usize,
}

fn terminal_gateway_cleanup_backoff(attempt: u32) -> std::time::Duration {
    let shift = attempt.saturating_sub(1).min(7);
    std::time::Duration::from_millis(10_u64.saturating_mul(1_u64 << shift))
}

fn report_terminal_gateway_cleanup_retry(attempt: u32, owned_count: usize, detail_code: &str) {
    eprintln!(
        "CSSWITCH_TERMINAL_GATEWAY_CLEANUP_RETRY attempt={attempt} owned_count={owned_count} detail_code={detail_code}"
    );
}

impl Drop for RejectedGatewayRegistryState {
    fn drop(&mut self) {
        let mut attempt = 0_u32;
        while let Some(child) = self.children.last_mut() {
            if stop_child_confirmed(child).is_ok() {
                self.children.pop();
                attempt = 0;
            } else {
                // Terminal ownership is fail-closed: without an acknowledged
                // external supervisor, teardown may not discard a live Child.
                attempt = attempt.saturating_add(1);
                report_terminal_gateway_cleanup_retry(
                    attempt,
                    self.children.len(),
                    "drop_stop_unconfirmed",
                );
                std::thread::sleep(terminal_gateway_cleanup_backoff(attempt));
            }
        }
    }
}

struct RejectedGatewayCleanupOwner {
    registry: RejectedGatewayRegistry,
    children: Vec<Child>,
}

impl Drop for RejectedGatewayCleanupOwner {
    fn drop(&mut self) {
        let mut current = self
            .registry
            .inner
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        current.children.append(&mut self.children);
        current.cleanup_in_progress = false;
        current.cleanup_owned_count = 0;
    }
}

impl RejectedGatewayCleanupOwner {
    fn confirm_last_stopped(&mut self) -> Result<(), String> {
        let mut child = self
            .children
            .pop()
            .expect("confirmed Gateway cleanup must own a child");
        if let Err(error) = child.wait() {
            self.children.push(child);
            return Err(format!("无法二次确认 Gateway 子进程已被 reap：{error}"));
        }
        self.registry
            .inner
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .cleanup_owned_count = self.children.len();
        Ok(())
    }
}

impl RejectedGatewayRegistry {
    pub(crate) fn retain(&self, child: Child) {
        self.inner
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .children
            .push(child);
    }

    pub(crate) fn is_idle(&self) -> bool {
        let current = self.inner.lock().unwrap_or_else(|error| error.into_inner());
        !current.cleanup_in_progress && current.children.is_empty()
    }

    pub(crate) fn len(&self) -> usize {
        let current = self.inner.lock().unwrap_or_else(|error| error.into_inner());
        current.children.len() + current.cleanup_owned_count
    }

    pub(crate) fn retry_with<Stop>(&self, mut stop: Stop) -> Result<(), String>
    where
        Stop: FnMut(&mut Child) -> Result<(), String>,
    {
        let mut owner = {
            let mut current = self.inner.lock().unwrap_or_else(|error| error.into_inner());
            if current.cleanup_in_progress {
                return Err("Gateway child cleanup 正在进行；已拒绝并发启动。".into());
            }
            if current.children.is_empty() {
                return Ok(());
            }
            current.cleanup_in_progress = true;
            let children = std::mem::take(&mut current.children);
            current.cleanup_owned_count = children.len();
            RejectedGatewayCleanupOwner {
                registry: self.clone(),
                children,
            }
        };

        while let Some(child) = owner.children.last_mut() {
            match stop(child) {
                Ok(()) => {
                    if let Err(error) = owner.confirm_last_stopped() {
                        let count = owner.children.len();
                        return Err(format!(
                            "仍有 {count} 个 Gateway child 的退出未确认；已保留 cleanup owner，拒绝启动新 Gateway：{error}"
                        ));
                    }
                }
                Err(error) => {
                    let count = owner.children.len();
                    return Err(format!(
                        "仍有 {count} 个 Gateway child 的退出未确认；已保留 cleanup owner，拒绝启动新 Gateway：{error}"
                    ));
                }
            }
        }
        Ok(())
    }

    fn drain_for_terminal_with<Stop>(&self, mut stop: Stop)
    where
        Stop: FnMut(&mut Child) -> Result<(), String>,
    {
        let mut attempt = 0_u32;
        loop {
            match self.retry_with(&mut stop) {
                Ok(()) if self.is_idle() => return,
                Ok(()) => {
                    attempt = attempt.saturating_add(1);
                    report_terminal_gateway_cleanup_retry(
                        attempt,
                        self.len(),
                        "cleanup_owner_busy",
                    );
                    std::thread::sleep(terminal_gateway_cleanup_backoff(attempt));
                }
                Err(_error) => {
                    attempt = attempt.saturating_add(1);
                    report_terminal_gateway_cleanup_retry(attempt, self.len(), "stop_unconfirmed");
                    std::thread::sleep(terminal_gateway_cleanup_backoff(attempt));
                }
            }
        }
    }

    fn drain_for_terminal(&self) {
        self.drain_for_terminal_with(stop_child_confirmed);
    }

    #[cfg(test)]
    pub(crate) fn owned_pids(&self) -> Vec<u32> {
        self.inner
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .children
            .iter()
            .map(Child::id)
            .collect()
    }
}

#[must_use = "Gateway stop uncertainty must be handled before later mutations or exit"]
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum GatewayStopOutcome {
    Stopped,
    Uncertain { owned_count: usize, reason: String },
}

impl GatewayStopOutcome {
    pub(crate) fn require_stopped(self, context: &str) -> Result<(), String> {
        match self {
            Self::Stopped => Ok(()),
            Self::Uncertain {
                owned_count,
                reason,
            } => Err(format!(
                "{context}：仍有 {owned_count} 个 Gateway child 的退出未确认；应用保留 process-local cleanup owner：{reason}"
            )),
        }
    }
}

#[derive(Default)]
pub(crate) struct AppState {
    pub(crate) proxy: Option<Child>,
    /// Rejected Gateway candidates whose exit could not yet be confirmed.
    /// They are never treated as the active proxy and retain process-local
    /// ownership until a later cleanup attempt can reap them.
    pub(crate) rejected_gateway_candidates: RejectedGatewayRegistry,
    pub(crate) proxy_port: u16,
    pub(crate) secret: String,
    /// 当前代理进程所用 adapter 名（deepseek | qwen | relay | openai-custom | openai-responses）；用于健康复用判定。
    pub(crate) provider: String,
    /// 当前代理进程的 gateway 实现身份（生产值固定为 rust）。
    pub(crate) gateway_kind: String,
    /// 当前代理进程的 DeepSeek tool-use shim 模式（off | detect | rewrite）。
    pub(crate) shim_mode: String,
    /// Tauri 每次启动 managed Rust gateway 时生成的唯一实例身份。
    pub(crate) launch_id: String,
    /// 当前代理进程所用 key 的非加密指纹（仅内存、绝不落盘/打印）。
    /// 换 key/换上游后指纹变化 → 触发重启，避免复用带旧配置的代理。
    pub(crate) key_fp: u64,
    /// The exact in-memory launch recipe for the currently tracked Gateway.
    /// It may contain profile credentials, so it is never serialized or logged.
    pub(crate) gateway_launch_context: Option<runtime::proxy_lifecycle::GatewayLaunchRecipe>,
    pub(crate) sandbox: Option<Child>,
    pub(crate) sandbox_port: u16,
    pub(crate) sandbox_url: Option<String>,
    /// 当前 CSSwitch Science daemon 的实际 binary 身份，仅存内存；绝不形成版本偏好。
    pub(crate) science_runtime: Option<runtime::science::ScienceRuntimeIdentity>,
    /// CSSwitch 自己成功停止后的单次快速启动令牌；下一次启动消费，App 重启即丢弃。
    pub(crate) science_confirmed_stopped: Option<runtime::science::ScienceRuntimeIdentity>,
    /// Science 版本探测缓存与 daemon 身份分离；停止 daemon 后仍可复用未变化二进制的版本。
    pub(crate) science_version_cache: runtime::science::ScienceVersionCache,
    /// One-shot, backend-only mapping for the v0.8.0 multi-history recovery UI.
    /// Neither organization UUIDs nor filesystem paths cross the invoke boundary.
    pub(crate) history_recovery: Option<HistoryRecoverySession>,
    /// Exact private rollback roots whose cleanup previously failed. Paths are
    /// backend-only and retried before the next one-click mutation.
    pub(crate) pending_authority_cleanup: Vec<std::path::PathBuf>,
    /// Monotonic process-local boot publication. Snapshot and event consumers
    /// observe the same sequence/state/payload envelope.
    pub(crate) boot: BootPublication,
}

#[derive(Clone)]
pub(crate) struct HistoryRecoverySession {
    pub(crate) active_profile_id: String,
    pub(crate) sandbox_port: u16,
    pub(crate) auth_dir: std::path::PathBuf,
    pub(crate) sandbox_root: std::path::PathBuf,
    pub(crate) science_quiescence: HistoryRecoveryScienceQuiescence,
    pub(crate) choices: Vec<HistoryRecoveryChoice>,
}

#[derive(Clone)]
pub(crate) enum HistoryRecoveryScienceQuiescence {
    ExactStopped(runtime::science::ScienceRuntimeIdentity),
    NoManagedRuntimeObserved,
}

#[derive(Clone)]
pub(crate) struct HistoryRecoveryChoice {
    pub(crate) reference: String,
    pub(crate) candidate: oauth_forge::HistoryOrgCandidate,
}

impl AppState {
    pub(crate) fn clear_proxy_identity(&mut self) {
        self.secret.clear();
        self.provider.clear();
        self.gateway_kind.clear();
        self.shim_mode.clear();
        self.launch_id.clear();
        self.key_fp = 0;
        self.gateway_launch_context = None;
    }

    fn stop_proxy_with<Stop>(&mut self, stop: Stop) -> GatewayStopOutcome
    where
        Stop: FnMut(&mut Child) -> Result<(), String>,
    {
        if let Some(child) = self.proxy.take() {
            // Active and rejected children share the same independent cleanup
            // owner once teardown starts. Never discard the active Child before
            // kill + wait has been confirmed.
            self.rejected_gateway_candidates.retain(child);
        }
        // Clear the active reservation before invoking a fallible callback so
        // panic/unwind cannot leave a permanently stale marker. The registry
        // remains the spawn fence until every transferred child is reaped.
        self.clear_proxy_identity();
        match self.rejected_gateway_candidates.retry_with(stop) {
            Ok(()) => GatewayStopOutcome::Stopped,
            Err(reason) => GatewayStopOutcome::Uncertain {
                owned_count: self.rejected_gateway_candidates.len(),
                reason,
            },
        }
    }

    pub(crate) fn stop_proxy(&mut self) -> GatewayStopOutcome {
        self.stop_proxy_with(stop_child_confirmed)
    }
}

impl Drop for AppState {
    fn drop(&mut self) {
        // `std::process::Child` does not kill on drop. Keep a final owned-child
        // safety net in addition to the Tauri exit events so a graceful app
        // teardown cannot orphan the managed gateway.
        let _ = self.stop_proxy();
        self.rejected_gateway_candidates.drain_for_terminal();
    }
}

pub(crate) type SharedAppState = Arc<Mutex<AppState>>;
pub(crate) type SharedLifecycle = Arc<lifecycle::Lifecycle>;

/// 取锁并从 poison 中恢复：某线程持锁时 panic 不应把整个 app 卡死。
pub(crate) fn lock(m: &Mutex<AppState>) -> std::sync::MutexGuard<'_, AppState> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

pub(crate) async fn run_blocking<T>(
    f: impl FnOnce() -> Result<T, String> + Send + 'static,
) -> Result<T, String>
where
    T: Send + 'static,
{
    tauri::async_runtime::spawn_blocking(f)
        .await
        .map_err(|e| format!("后台任务失败：{e}"))?
}

pub(crate) async fn run_blocking_typed<T, E>(
    f: impl FnOnce() -> Result<T, E> + Send + 'static,
) -> Result<T, E>
where
    T: Send + 'static,
    E: From<String> + Send + 'static,
{
    tauri::async_runtime::spawn_blocking(f)
        .await
        .map_err(|e| E::from(format!("后台任务失败：{e}")))?
}

fn show_main_window<R: tauri::Runtime>(app: &tauri::AppHandle<R>) {
    if let Some(win) = app.get_webview_window("main") {
        let _ = win.show();
        let _ = win.set_focus();
    }
}

fn install_menu(app: &tauri::App) -> tauri::Result<()> {
    // Windows 移植：菜单栏是 macOS 平台惯例（系统菜单 + Cmd+, 偏好设置）；
    // Windows 上显示为窗口顶部菜单条，非本平台习惯，直接不安装。
    #[cfg(not(target_os = "macos"))]
    {
        let _ = app;
        return Ok(());
    }
    #[cfg(target_os = "macos")]
    {
    use tauri::menu::{MenuBuilder, MenuItemBuilder, SubmenuBuilder};

    let preferences = MenuItemBuilder::with_id("preferences", "偏好设置...")
        .accelerator("CmdOrCtrl+,")
        .build(app)?;
    let app_menu = SubmenuBuilder::new(app, "CSSwitch")
        .item(&preferences)
        .separator()
        .quit()
        .build()?;
    let menu_builder = MenuBuilder::new(app).item(&app_menu);
    #[cfg(target_os = "macos")]
    let menu_builder = {
        // Native predefined edit items are what wires the standard macOS
        // Command-X/C/V/A/Z shortcuts into the focused WebView field.
        let edit_menu = SubmenuBuilder::new(app, "编辑")
            .undo_with_text("撤销")
            .redo_with_text("重做")
            .separator()
            .cut_with_text("剪切")
            .copy_with_text("复制")
            .paste_with_text("粘贴")
            .select_all_with_text("全选")
            .build()?;
        menu_builder.item(&edit_menu)
    };
    let menu = menu_builder.build()?;
    app.set_menu(menu)?;
    app.on_menu_event(|app, event| {
        if event.id().as_ref() == "preferences" {
            show_main_window(app);
        }
    });
    Ok(())
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "native-exit cleanup keeps independently injected cancel/wait/signal and Science/Gateway effects so ordering and failure tests exercise the production boundary"
)]
fn cleanup_for_exit_with<R, Cancel, Wait, Term, Kill, ClaimScience, ExecuteScience, StopGateway>(
    app: &tauri::AppHandle<R>,
    mut cancel_codex: Cancel,
    mut wait_codex: Wait,
    mut term_codex: Term,
    mut kill_codex: Kill,
    claim_science: ClaimScience,
    execute_science: ExecuteScience,
    mut stop_gateway: StopGateway,
) -> GatewayStopOutcome
where
    R: tauri::Runtime,
    Cancel: FnMut(),
    Wait: FnMut(std::time::Duration) -> Vec<u32>,
    Term: FnMut(u32),
    Kill: FnMut(u32),
    ClaimScience: FnOnce(
        Option<&runtime::science::ScienceRuntimeIdentity>,
    ) -> Result<
        runtime::science::ScienceStopRequest,
        runtime::science::ScienceStopFailure,
    >,
    ExecuteScience: FnOnce(
        &tauri::AppHandle<R>,
        runtime::science::ScienceStopRequest,
    ) -> (runtime::science::ScienceStopOutcome, bool),
    StopGateway: FnMut(&mut AppState) -> GatewayStopOutcome,
{
    // First give login its protocol-level cancel path and read-only preflight
    // its cancellation token. Do not signal a possibly committing login child
    // until the bounded waiter has had a chance to reap it normally.
    cancel_codex();
    let remaining = wait_codex(std::time::Duration::from_secs(2));
    for pid in remaining {
        term_codex(pid);
    }
    let remaining = wait_codex(std::time::Duration::from_millis(500));
    for pid in remaining {
        kill_codex(pid);
    }
    let _ = wait_codex(std::time::Duration::from_millis(500));
    let state = app.state::<SharedAppState>().inner().clone();
    let lifecycle = app.state::<SharedLifecycle>().inner().clone();
    lifecycle.with_mutation(lifecycle::RuntimeMutationDomain::Terminal, |_| {
        let has_tracked_science = lock(&state).science_runtime.is_some();
        if has_tracked_science {
            // Native exit remains best-effort, but Science stop has the same
            // process-local owner as explicit teardown: claim under AppState,
            // release the lock for bounded stop/wait, then publish only when
            // generation and the full tracked identity still match.
            let _ = commands::runtime::execute_process_local_science_stop_with(
                app,
                &state,
                &lifecycle,
                |_st, _generation| Ok(()),
                claim_science,
                execute_science,
                native_exit_after_science_stop,
            );
        }
        let mut st = lock(&state);
        stop_gateway(&mut st)
    })
}

#[allow(clippy::result_large_err)]
fn native_exit_after_science_stop(
    _state: &mut AppState,
) -> Result<(), runtime::science::ScienceStopFailure> {
    Ok(())
}

#[allow(clippy::result_large_err)]
fn cleanup_for_exit<R: tauri::Runtime>(app: &tauri::AppHandle<R>) -> GatewayStopOutcome {
    let supervisor = app.state::<SharedCodexAuthSupervisor>().inner().clone();
    cleanup_for_exit_with(
        app,
        || {
            let _ = supervisor.cancel_for_exit();
        },
        |timeout| supervisor.wait_for_auth_children_exit(timeout),
        |pid| {
            #[cfg(unix)]
            if supervisor.auth_signal_target_is_current(pid) {
                unsafe {
                    libc::kill(pid as i32, libc::SIGTERM);
                }
            }
        },
        |pid| {
            #[cfg(unix)]
            if supervisor.auth_signal_target_is_current(pid) {
                unsafe {
                    libc::kill(pid as i32, libc::SIGKILL);
                }
            }
        },
        ScienceHostAdapter::claim_stop,
        |app, request| ScienceHostAdapter::execute_stop(app, request).into_parts(),
        AppState::stop_proxy,
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NativeExitEvent {
    ExitRequested,
    Exit,
}

type NativeExitCleanup<R> = fn(&tauri::AppHandle<R>) -> GatewayStopOutcome;

fn production_native_exit_cleanup<R: tauri::Runtime>() -> NativeExitCleanup<R> {
    cleanup_for_exit::<R>
}

fn run_native_exit_event_with<R, Cleanup>(
    app: &tauri::AppHandle<R>,
    event: NativeExitEvent,
    cleanup: Cleanup,
) -> GatewayStopOutcome
where
    R: tauri::Runtime,
    Cleanup: FnOnce(&tauri::AppHandle<R>, NativeExitEvent) -> GatewayStopOutcome,
{
    cleanup(app, event)
}

fn run_native_exit_event<R: tauri::Runtime>(
    app: &tauri::AppHandle<R>,
    event: NativeExitEvent,
) -> GatewayStopOutcome {
    let cleanup = production_native_exit_cleanup();
    run_native_exit_event_with(app, event, |app, _| cleanup(app))
}

pub(crate) fn publish_boot_state<R: tauri::Runtime>(
    app: &tauri::AppHandle<R>,
    next: BootState,
    payload: Option<serde_json::Value>,
) -> serde_json::Value {
    let state = app.state::<SharedAppState>();
    let publication = {
        let mut st = lock(state.inner());
        st.boot.transition(next, payload)
    };
    let _ = app.emit("boot://publication", publication.clone());
    publication
}

pub(crate) fn clear_boot_attention<R: tauri::Runtime>(app: &tauri::AppHandle<R>) {
    let state = app.state::<SharedAppState>();
    let publication = {
        let mut st = lock(state.inner());
        if st.boot.state != BootState::Attention {
            return;
        }
        st.boot.transition(BootState::Idle, None)
    };
    let _ = app.emit("boot://publication", publication);
}

fn mark_boot_failed<R: tauri::Runtime>(app: &tauri::AppHandle<R>, failure: serde_json::Value) {
    publish_boot_state(app, BootState::Failed, Some(failure));
    show_main_window(app);
}

fn mark_boot_attention<R: tauri::Runtime>(app: &tauri::AppHandle<R>, value: serde_json::Value) {
    publish_boot_state(app, BootState::Attention, Some(value));
    show_main_window(app);
}

fn boot_prepare_failure(message: impl Into<String>) -> serde_json::Value {
    crate::runtime::failure::TypedOneClickFailure::new(
        crate::runtime::failure::OneClickFailureKind::Prepare,
        message,
    )
    .project_dto()
}

fn load_boot_config(dir: &std::path::Path) -> Result<config::Config, serde_json::Value> {
    config::load_from(dir).map_err(|error| boot_prepare_failure(format!("读取配置失败：{error}")))
}

fn run_startup_config_sequence<W, B>(dir: &std::path::Path, install_window_hook: W, boot: B)
where
    W: FnOnce(),
    B: FnOnce(),
{
    // Setup migration is intentionally best-effort; boot performs a fresh load
    // and owns the user-visible typed prepare failure.
    let _ = config::load_from(dir);
    install_window_hook();
    boot();
}

type BootScienceCommand<R> =
    fn(
        tauri::AppHandle<R>,
        SharedAppState,
        SharedLifecycle,
        Option<String>,
    ) -> Result<serde_json::Value, crate::commands::codex::RuntimeCommandError>;

fn production_boot_science_command<R: tauri::Runtime>() -> BootScienceCommand<R> {
    commands::runtime::one_click_login_cmd::<R>
}

fn run_boot_decision_with<R, Load, Decide, Open, Boot, Project, Show>(
    app: tauri::AppHandle<R>,
    load_config: Load,
    decide: Decide,
    open_official: Open,
    boot_science: Boot,
    project_consumer_state: Project,
    show: Show,
) where
    R: tauri::Runtime,
    Load: FnOnce() -> Result<config::Config, serde_json::Value>,
    Decide: FnOnce(&config::Config) -> LaunchPath,
    Open: FnOnce() -> Result<(), String>,
    Boot: FnOnce(
        tauri::AppHandle<R>,
        SharedAppState,
        SharedLifecycle,
        Option<String>,
    ) -> Result<serde_json::Value, crate::commands::codex::RuntimeCommandError>,
    Project:
        Fn(&serde_json::Value) -> Result<runtime::finalize_consumer::FinalizeConsumerState, String>,
    Show: Fn(&tauri::AppHandle<R>),
{
    let cfg = match load_config() {
        Ok(cfg) => cfg,
        Err(failure) => {
            mark_boot_failed(&app, failure);
            return;
        }
    };
    let state = app.state::<SharedAppState>();
    match decide(&cfg) {
        LaunchPath::ShowPanel => {
            publish_boot_state(&app, BootState::Idle, None);
            show(&app);
        }
        LaunchPath::OpenOfficial => match open_official() {
            Ok(()) => {
                publish_boot_state(&app, BootState::Idle, None);
            }
            Err(e) => mark_boot_failed(&app, boot_prepare_failure(e)),
        },
        LaunchPath::BootScience => {
            let state_inner = state.inner().clone();
            let lifecycle = app.state::<SharedLifecycle>().inner().clone();
            match boot_science(app.clone(), state_inner, lifecycle, None) {
                Ok(value) => {
                    match project_consumer_state(&value).map(|projection| projection.disposition) {
                        Ok(runtime::finalize_consumer::FinalizeConsumerDisposition::Ready) => {
                            publish_boot_state(&app, BootState::Ready, None);
                        }
                        Ok(runtime::finalize_consumer::FinalizeConsumerDisposition::Attention) => {
                            mark_boot_attention(&app, value);
                        }
                        Ok(runtime::finalize_consumer::FinalizeConsumerDisposition::Manual)
                        | Err(_) => mark_boot_failed(&app, value),
                    }
                }
                Err(e) => mark_boot_failed(&app, boot_prepare_failure(e.to_string())),
            }
        }
    }
}

fn run_boot_decision(app: tauri::AppHandle) {
    match commands::runtime::config_mutation::boot_recover(&config::default_dir()) {
        Ok(Some(attention)) => {
            mark_boot_attention(&app, attention);
            return;
        }
        Ok(None) => {}
        Err(error) => {
            mark_boot_attention(
                &app,
                boot_prepare_failure(format!(
                    "P2-B Config mutation recovery 需要人工处理：{error}"
                )),
            );
            return;
        }
    }
    if let Some(attention) = commands::codex::replay_interrupted_codex_disable(&app) {
        mark_boot_attention(&app, attention);
        return;
    }
    run_boot_decision_with(
        app,
        || load_boot_config(&config::default_dir()),
        decide_launch,
        commands::runtime::open_official,
        production_boot_science_command(),
        |outcome| {
            runtime::finalize_consumer::project_finalize_consumer_state(
                &config::default_dir(),
                outcome,
            )
        },
        show_main_window,
    );
}

fn run_boot_coordinator_with<R, Execute, Show>(
    app: tauri::AppHandle<R>,
    execute: Execute,
    show: Show,
) where
    R: tauri::Runtime,
    Execute: FnOnce(tauri::AppHandle<R>),
    Show: FnOnce(&tauri::AppHandle<R>),
{
    let publication = {
        let state = app.state::<SharedAppState>();
        let mut st = lock(state.inner());
        if !should_begin_boot(st.boot.state) {
            show(&app);
            return;
        }
        st.boot.transition(BootState::Starting, None)
    };
    let _ = app.emit("boot://publication", publication);
    execute(app);
}

fn run_boot_coordinator(app: tauri::AppHandle) {
    run_boot_coordinator_with(
        app,
        |app| {
            tauri::async_runtime::spawn_blocking(move || run_boot_decision(app));
        },
        show_main_window,
    );
}

fn run_second_instance_callback_with<R, Execute, Show>(
    app: &tauri::AppHandle<R>,
    execute: Execute,
    show: Show,
) where
    R: tauri::Runtime,
    Execute: FnOnce(tauri::AppHandle<R>),
    Show: FnOnce(&tauri::AppHandle<R>),
{
    run_boot_coordinator_with(app.clone(), execute, show);
}

fn run_second_instance_callback(app: &tauri::AppHandle) {
    run_second_instance_callback_with(
        app,
        |app| {
            tauri::async_runtime::spawn_blocking(move || run_boot_decision(app));
        },
        show_main_window,
    );
}

fn should_emit_science_runtime_update_event(value: &serde_json::Value) -> bool {
    value["check_status"] == "checked" && !value["pending_update"].is_null()
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ScienceRuntimeUpdateOwner {
    generation: u64,
    runtime: Option<runtime::science::ScienceRuntimeIdentity>,
    confirmed_stopped: Option<runtime::science::ScienceRuntimeIdentity>,
    sandbox_child_pid: Option<u32>,
    sandbox_port: u16,
    sandbox_url: Option<String>,
}

impl ScienceRuntimeUpdateOwner {
    fn claim(state: &AppState, generation: u64) -> Self {
        Self {
            generation,
            runtime: state.science_runtime.clone(),
            confirmed_stopped: state.science_confirmed_stopped.clone(),
            sandbox_child_pid: state.sandbox.as_ref().map(Child::id),
            sandbox_port: state.sandbox_port,
            sandbox_url: state.sandbox_url.clone(),
        }
    }
}

fn observe_science_runtime_update_with<Proof>(
    state: &SharedAppState,
    lifecycle: &SharedLifecycle,
    candidate: &runtime::science::ScienceRuntimeIdentity,
    prove: impl FnOnce(u16, &runtime::science::ScienceRuntimeIdentity) -> Option<Proof>,
    revalidate: impl FnOnce(&Proof) -> bool,
    record: impl FnOnce(Proof, &runtime::science::ScienceRuntimeIdentity) -> Result<(), String>,
) -> &'static str {
    lifecycle.with_observed_context(|| {
        let owner = {
            let authority = lock(state);
            ScienceRuntimeUpdateOwner::claim(&authority, lifecycle.current_generation())
        };
        let Some(running) = owner.runtime.as_ref() else {
            return "not_needed";
        };
        if owner.confirmed_stopped.is_some() {
            return "degraded";
        }
        if running.environment_transaction_id() == candidate.environment_transaction_id()
            && running.version == candidate.version
        {
            return "not_needed";
        }
        let Some(proof) = prove(owner.sandbox_port, running) else {
            return "degraded";
        };
        let still_owned = {
            let authority = lock(state);
            ScienceRuntimeUpdateOwner::claim(&authority, lifecycle.current_generation()) == owner
        };
        if !still_owned || !revalidate(&proof) {
            return "degraded";
        }
        record(proof, candidate)
            .map(|_| "recorded")
            .unwrap_or("degraded")
    })
}

fn reconcile_science_runtime_update_projection_with(
    mut value: serde_json::Value,
    status: impl FnOnce() -> Result<serde_json::Value, String>,
) -> Result<serde_json::Value, String> {
    if value["check_status"] == "checked" {
        let current = status()?;
        if current["pending_update"] != value["pending_update"] {
            value = current;
            value["check_status"] = serde_json::json!("stale_result_discarded");
            value["adoption_record_status"] = serde_json::json!("not_needed");
        }
    }
    Ok(value)
}

fn run_science_runtime_update_once<R: tauri::Runtime>(
    app: &tauri::AppHandle<R>,
) -> Result<serde_json::Value, String> {
    let state = app.state::<SharedAppState>().inner().clone();
    let lifecycle = app.state::<SharedLifecycle>().inner().clone();
    let version_cache = lock(&state).science_version_cache.clone();
    let check = runtime::science::check_science_runtime_update(&version_cache)?;
    let (mut value, candidate) = check.into_parts();
    if let Some(candidate) = candidate.as_ref() {
        let status = observe_science_runtime_update_with(
            &state,
            &lifecycle,
            candidate,
            runtime::science::ScienceHostAdapter::prove_managed_healthy,
            runtime::science::ScienceHostAdapter::revalidate_managed_healthy,
            runtime::science::record_deferred_science_runtime_observation,
        );
        value["adoption_record_status"] = serde_json::json!(status);
    }
    reconcile_science_runtime_update_projection_with(
        value,
        runtime::science::science_runtime_update_status,
    )
}

fn start_science_runtime_update_scheduler(app: tauri::AppHandle) {
    let _ = std::thread::Builder::new()
        .name("science-runtime-update".into())
        .spawn(move || {
            // Startup gets first ownership of bootstrap. The hourly wake-up is
            // cheap; the durable timestamp enforces one source check per 24h.
            std::thread::sleep(std::time::Duration::from_secs(30));
            loop {
                if let Ok(value) = run_science_runtime_update_once(&app) {
                    if should_emit_science_runtime_update_event(&value) {
                        let _ = app.emit("science-runtime://update", value);
                    }
                }
                std::thread::sleep(std::time::Duration::from_secs(60 * 60));
            }
        });
}

// ---------- 入口 ----------
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let app = tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _argv, _cwd| {
            run_second_instance_callback(app);
        }))
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .manage(Arc::new(Mutex::new(AppState::default())))
        .manage(Arc::new(lifecycle::Lifecycle::new()))
        .manage(Arc::new(CodexAuthSupervisor::default()))
        .invoke_handler(tauri::generate_handler![
            commands::codex::set_experimental_codex_enabled,
            commands::codex::set_codex_network,
            commands::codex::codex_auth_status,
            commands::codex::codex_auth_start,
            commands::codex::codex_auth_cancel,
            commands::codex::codex_auth_operation_status,
            commands::codex::codex_ensure_profile,
            commands::codex::codex_auth_logout,
            commands::codex::codex_downgrade_preview,
            commands::codex::codex_downgrade_export_all,
            commands::profiles::get_config,
            commands::profiles::acknowledge_pending_notice,
            commands::runtime::set_settings,
            commands::runtime::set_mode,
            commands::runtime::open_official,
            commands::profiles::create_profile,
            commands::profiles::update_profile_metadata,
            commands::profiles::update_profile_connection,
            commands::profiles::clear_profile_key,
            commands::profiles::delete_profile,
            commands::profiles::set_active_profile,
            commands::runtime::fetch_models,
            commands::runtime::stop_all,
            commands::runtime::one_click_login,
            commands::runtime::finalize_consumer_state,
            commands::runtime::restore_history_choice,
            commands::runtime::science_runtime_preflight,
            commands::runtime::science_runtime_update_status,
            commands::runtime::science_runtime_update_action,
            commands::runtime::open_science_download_page,
            commands::runtime::status,
            commands::runtime::boot_snapshot,
            commands::runtime::open_url,
            commands::skill_install::install_local_skill_package,
            commands::skill_listing::list_installed_skills,
            commands::diagnostics::run_doctor_read_only,
            commands::diagnostics::repair_skill_route,
            commands::diagnostics::app_version,
            commands::diagnostics::open_release_page,
            commands::diagnostics::report_bug,
            commands::diagnostics::open_logs,
            commands::runtime::quit_app
        ])
        .setup(|app| {
            install_menu(app)?;

            let config_dir = config::default_dir();
            run_startup_config_sequence(
                &config_dir,
                || {
                    // 关窗隐藏配置面板，不销毁窗口、不停止后台链路。显式退出清理代理与沙箱。
                    if let Some(win) = app.get_webview_window("main") {
                        let w = win.clone();
                        win.on_window_event(move |ev| {
                            if let tauri::WindowEvent::CloseRequested { api, .. } = ev {
                                api.prevent_close();
                                let _ = w.hide();
                            }
                        });
                    }
                },
                || run_boot_coordinator(app.handle().clone()),
            );
            start_science_runtime_update_scheduler(app.handle().clone());
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("error while building tauri application");

    app.run(|app, event| match event {
        // Reopen is the macOS dock-click event; the variant only exists there.
        #[cfg(target_os = "macos")]
        tauri::RunEvent::Reopen { .. } => show_main_window(app),
        tauri::RunEvent::ExitRequested { api, .. } => {
            if matches!(
                run_native_exit_event(app, NativeExitEvent::ExitRequested),
                GatewayStopOutcome::Uncertain { .. }
            ) {
                api.prevent_exit();
            }
        }
        tauri::RunEvent::Exit => {
            let outcome = run_native_exit_event(app, NativeExitEvent::Exit);
            if matches!(outcome, GatewayStopOutcome::Uncertain { .. }) {
                let registry = lock(app.state::<SharedAppState>().inner())
                    .rejected_gateway_candidates
                    .clone();
                registry.drain_for_terminal();
            }
        }
        _ => {}
    });
}

#[cfg(test)]
mod tests {
    use std::{
        cell::{Cell, RefCell},
        env, fs,
        net::{TcpListener, TcpStream},
        os::unix::fs::PermissionsExt,
        process::Command,
        sync::{Arc, Mutex},
        time::{SystemTime, UNIX_EPOCH},
    };

    use crate::config::{self, Config, Profile};
    use crate::runtime::system::redact;
    use crate::{
        cleanup_for_exit, cleanup_for_exit_with, decide_launch_with_auto_boot, load_boot_config,
        lock, production_boot_science_command, production_native_exit_cleanup,
        run_boot_decision_with, run_native_exit_event_with, run_second_instance_callback_with,
        run_startup_config_sequence, should_begin_boot, AppState, BootPublication,
        BootScienceCommand, BootState, GatewayStopOutcome, LaunchPath, NativeExitCleanup,
        NativeExitEvent, SharedAppState, SharedLifecycle,
    };

    #[test]
    fn h4_auto_boot_consumes_finalize_projection_without_promoting_degraded_to_ready() {
        use crate::runtime::finalize_consumer::FinalizeConsumerDisposition;

        let dto = serde_json::json!({
            "action": "history_choice_required",
            "stage": "history_recovery",
            "status": "degraded",
            "recovery_status": "cleanup_required",
            "choices": [{"reference": "opaque-reference", "label": "history"}],
            "fallback_url": null,
        });
        for (projected, expected_boot) in [
            (FinalizeConsumerDisposition::Ready, BootState::Ready),
            (FinalizeConsumerDisposition::Attention, BootState::Attention),
            (FinalizeConsumerDisposition::Manual, BootState::Failed),
        ] {
            let state: SharedAppState = Arc::new(Mutex::new(AppState::default()));
            let lifecycle: SharedLifecycle = Arc::new(crate::lifecycle::Lifecycle::new());
            let app = tauri::test::mock_builder()
                .manage(state.clone())
                .manage(lifecycle)
                .build(tauri::test::mock_context(tauri::test::noop_assets()))
                .unwrap();
            run_boot_decision_with(
                app.handle().clone(),
                || Ok(Config::default()),
                |_| LaunchPath::BootScience,
                || -> Result<(), String> { unreachable!() },
                |_, _, _, _| Ok(dto.clone()),
                |_| {
                    Ok(crate::runtime::finalize_consumer::test_consumer_state(
                        projected,
                    ))
                },
                |_| {},
            );
            let authority = lock(&state);
            assert_eq!(authority.boot.state, expected_boot);
            assert_eq!(authority.boot.sequence, 1);
            match projected {
                FinalizeConsumerDisposition::Ready => {
                    assert!(authority.boot.payload.is_none());
                }
                FinalizeConsumerDisposition::Attention => {
                    assert_eq!(authority.boot.payload.as_ref(), Some(&dto));
                }
                FinalizeConsumerDisposition::Manual => {
                    assert_eq!(authority.boot.payload.as_ref(), Some(&dto));
                }
            }
            assert_eq!(authority.boot.snapshot()["sequence"], 1);
            assert_eq!(authority.boot.snapshot()["state"], expected_boot.code());
        }

        let state: SharedAppState = Arc::new(Mutex::new(AppState::default()));
        let lifecycle: SharedLifecycle = Arc::new(crate::lifecycle::Lifecycle::new());
        let app = tauri::test::mock_builder()
            .manage(state.clone())
            .manage(lifecycle)
            .build(tauri::test::mock_context(tauri::test::noop_assets()))
            .unwrap();
        run_boot_decision_with(
            app.handle().clone(),
            || Ok(Config::default()),
            |_| LaunchPath::BootScience,
            || -> Result<(), String> { unreachable!() },
            |_, _, _, _| Ok(dto.clone()),
            |_| Err("controlled readback failure".into()),
            |_| {},
        );
        let authority = lock(&state);
        assert_eq!(authority.boot.state, BootState::Failed);
        assert_eq!(authority.boot.payload.as_ref(), Some(&dto));
    }

    #[test]
    fn r0_boot_surfaces_prepare_failure_after_setup_load_error() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = env::temp_dir().join(format!(
            "csswitch-r0-g-startup-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("config.json"), b"{invalid-config").unwrap();

        let events = std::cell::RefCell::new(Vec::new());
        let failure = std::cell::RefCell::new(None);
        run_startup_config_sequence(
            &dir,
            || events.borrow_mut().push("window-hook"),
            || {
                events.borrow_mut().push("boot-load");
                failure.replace(Some(load_boot_config(&dir).unwrap_err()));
            },
        );
        assert_eq!(*events.borrow(), vec!["window-hook", "boot-load"]);
        let failure = failure.borrow_mut().take().unwrap();
        assert_eq!(failure["status"], "error");
        assert_eq!(failure["stage"], "prepare");
        assert!(failure["message"]
            .as_str()
            .unwrap()
            .contains("读取配置失败"));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn app_state_clear_proxy_identity_removes_runtime_credentials() {
        let mut st = AppState::default();
        st.secret = "secret".into();
        st.provider = "deepseek".into();
        st.gateway_kind = "rust".into();
        st.shim_mode = "off".into();
        st.launch_id = "launch-old".into();
        st.key_fp = 42;
        st.clear_proxy_identity();
        assert!(st.secret.is_empty());
        assert!(st.provider.is_empty());
        assert!(st.gateway_kind.is_empty());
        assert!(st.shim_mode.is_empty());
        assert!(st.launch_id.is_empty());
        assert_eq!(st.key_fp, 0);
    }

    #[test]
    fn active_gateway_stop_uncertainty_retains_owner_until_reap_is_confirmed() {
        let child = Command::new("/bin/sleep").arg("30").spawn().unwrap();
        let child_pid = child.id();
        let mut state = AppState::default();
        state.proxy = Some(child);
        state.secret = "active-secret".into();
        state.provider = "deepseek".into();
        state.gateway_kind = "rust".into();
        state.shim_mode = "off".into();
        state.launch_id = "active-launch".into();
        state.key_fp = 47;

        let outcome =
            state.stop_proxy_with(|_| Err("injected active-child stop uncertainty".into()));
        assert!(matches!(
            outcome,
            GatewayStopOutcome::Uncertain { owned_count: 1, .. }
        ));
        assert!(state.proxy.is_none());
        assert!(state.secret.is_empty());
        assert!(state.launch_id.is_empty());
        assert_eq!(
            state.rejected_gateway_candidates.owned_pids(),
            vec![child_pid]
        );
        assert_eq!(unsafe { libc::kill(child_pid as i32, 0) }, 0);

        state
            .rejected_gateway_candidates
            .retry_with(crate::runtime::system::stop_child_confirmed)
            .unwrap();
        assert!(state.rejected_gateway_candidates.is_idle());
        assert_ne!(unsafe { libc::kill(child_pid as i32, 0) }, 0);
    }

    #[test]
    fn r0_app_state_drop_stops_tracked_gateway() {
        let child = Command::new("/bin/sleep")
            .arg("30")
            .spawn()
            .expect("spawn owned test child");
        let pid = child.id();
        {
            let mut st = AppState::default();
            st.proxy = Some(child);
        }
        let status = Command::new("/bin/ps")
            .args(["-p", &pid.to_string(), "-o", "pid="])
            .output()
            .expect("inspect owned test child");
        assert!(
            String::from_utf8_lossy(&status.stdout).trim().is_empty(),
            "AppState drop left owned proxy child {pid} alive"
        );
    }

    #[test]
    fn r0_native_exit_events_share_repeatable_best_effort_cleanup() {
        let child_name =
            "tests::isolated_r0_native_exit_events_share_repeatable_best_effort_cleanup";
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
            "isolated native-exit characterization failed:\nstdout={}\nstderr={}",
            stdout,
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    #[allow(clippy::result_large_err)]
    fn r0_native_exit_requested_and_exit_repeat_full_terminal_cleanup() {
        type MockNativeExitCleanup = NativeExitCleanup<tauri::test::MockRuntime>;
        let production: MockNativeExitCleanup = production_native_exit_cleanup();
        let expected: MockNativeExitCleanup = cleanup_for_exit::<tauri::test::MockRuntime>;
        assert_eq!(
            production as usize, expected as usize,
            "native exit events must remain bound to cleanup_for_exit"
        );

        let gateway = Command::new("/bin/sleep").arg("30").spawn().unwrap();
        let gateway_pid = gateway.id();
        let runtime = crate::runtime::science::test_runtime_identity(env::current_exe().unwrap());
        let mut authority = AppState::default();
        authority.proxy = Some(gateway);
        authority.science_runtime = Some(runtime.clone());
        let state: SharedAppState = Arc::new(Mutex::new(authority));
        let lifecycle: SharedLifecycle = Arc::new(crate::lifecycle::Lifecycle::new());
        let generation = lifecycle.current_generation();
        let app = tauri::test::mock_builder()
            .manage(state.clone())
            .manage(lifecycle.clone())
            .build(tauri::test::mock_context(tauri::test::noop_assets()))
            .unwrap();

        let actions = RefCell::new(Vec::new());
        let science_attempts = Cell::new(0);
        for event in [NativeExitEvent::ExitRequested, NativeExitEvent::Exit] {
            let term_child = Command::new("/bin/sleep").arg("30").spawn().unwrap();
            let term_pid = term_child.id();
            let kill_child = Command::new("/bin/sleep").arg("30").spawn().unwrap();
            let kill_pid = kill_child.id();
            let children = RefCell::new(vec![term_child, kill_child]);
            let wait_index = Cell::new(0);

            let outcome = run_native_exit_event_with(app.handle(), event, |app, observed_event| {
                assert_eq!(observed_event, event);
                actions.borrow_mut().push(format!("event:{event:?}"));
                let outcome = cleanup_for_exit_with(
                    app,
                    || actions.borrow_mut().push("codex:cancel".into()),
                    |timeout| {
                        actions
                            .borrow_mut()
                            .push(format!("codex:wait:{}", timeout.as_millis()));
                        let index = wait_index.get();
                        wait_index.set(index + 1);
                        match index {
                            0 => vec![term_pid],
                            1 => vec![kill_pid],
                            2 => {
                                for child in children.borrow_mut().iter_mut() {
                                    child.wait().unwrap();
                                }
                                Vec::new()
                            }
                            _ => panic!("unexpected Codex wait round: {index}"),
                        }
                    },
                    |pid| {
                        actions.borrow_mut().push("codex:term".into());
                        assert_eq!(pid, term_pid);
                        assert_eq!(unsafe { libc::kill(pid as i32, libc::SIGTERM) }, 0);
                    },
                    |pid| {
                        actions.borrow_mut().push("codex:kill".into());
                        assert_eq!(pid, kill_pid);
                        assert_eq!(unsafe { libc::kill(pid as i32, libc::SIGKILL) }, 0);
                    },
                    |observed_runtime| {
                        assert_eq!(observed_runtime, Some(&runtime));
                        Ok(crate::runtime::science::ScienceStopRequest::recover(
                            observed_runtime,
                        ))
                    },
                    |_, _request| {
                        let attempt = science_attempts.get() + 1;
                        science_attempts.set(attempt);
                        if attempt == 1 {
                            actions.borrow_mut().push("science:error".into());
                            (
                                Err(crate::runtime::science::ScienceStopFailure::outcome_publication_failure(
                                    "controlled first Science stop failure",
                                )),
                                false,
                            )
                        } else {
                            actions.borrow_mut().push("science:stopped".into());
                            (
                                Ok(crate::runtime::science::VerifiedScienceStop {
                                    runtime: Some(runtime.clone()),
                                    ownership_was_proven: true,
                                }),
                                false,
                            )
                        }
                    },
                    |app_state| {
                        actions.borrow_mut().push("gateway:stop".into());
                        app_state.stop_proxy()
                    },
                );
                actions.borrow_mut().push(format!("completed:{event:?}"));
                outcome
            });
            assert_eq!(outcome, GatewayStopOutcome::Stopped);

            assert_eq!(wait_index.get(), 3);
            assert_eq!(lifecycle.current_generation(), generation);
            let current = lock(&state);
            assert!(current.proxy.is_none());
            if event == NativeExitEvent::ExitRequested {
                assert_eq!(current.science_runtime.as_ref(), Some(&runtime));
            } else {
                assert!(current.science_runtime.is_none());
            }
        }

        assert!(unsafe { libc::kill(gateway_pid as i32, 0) } != 0);
        assert_eq!(science_attempts.get(), 2);
        assert_eq!(lifecycle.current_generation(), generation);
        assert_eq!(
            *actions.borrow(),
            vec![
                "event:ExitRequested",
                "codex:cancel",
                "codex:wait:2000",
                "codex:term",
                "codex:wait:500",
                "codex:kill",
                "codex:wait:500",
                "science:error",
                "gateway:stop",
                "completed:ExitRequested",
                "event:Exit",
                "codex:cancel",
                "codex:wait:2000",
                "codex:term",
                "codex:wait:500",
                "codex:kill",
                "codex:wait:500",
                "science:stopped",
                "gateway:stop",
                "completed:Exit",
            ]
        );
    }

    #[test]
    #[allow(clippy::result_large_err)]
    fn rejected_gateway_terminal_uncertainty_blocks_exit_until_reap_is_confirmed() {
        assert_eq!(super::terminal_gateway_cleanup_backoff(1).as_millis(), 10);
        assert_eq!(
            super::terminal_gateway_cleanup_backoff(8).as_millis(),
            1_280
        );
        assert_eq!(
            super::terminal_gateway_cleanup_backoff(80).as_millis(),
            1_280
        );
        let child = Command::new("/bin/sleep").arg("30").spawn().unwrap();
        let child_pid = child.id();
        let authority = AppState::default();
        authority.rejected_gateway_candidates.retain(child);
        let state: SharedAppState = Arc::new(Mutex::new(authority));
        let lifecycle: SharedLifecycle = Arc::new(crate::lifecycle::Lifecycle::new());
        let app = tauri::test::mock_builder()
            .manage(state.clone())
            .manage(lifecycle)
            .build(tauri::test::mock_context(tauri::test::noop_assets()))
            .unwrap();

        let outcome =
            run_native_exit_event_with(app.handle(), NativeExitEvent::ExitRequested, |app, _| {
                cleanup_for_exit_with(
                    app,
                    || {},
                    |_| Vec::new(),
                    |_| {},
                    |_| {},
                    |_| -> Result<
                        crate::runtime::science::ScienceStopRequest,
                        crate::runtime::science::ScienceStopFailure,
                    > { panic!("no Science owner expected") },
                    |_, _| -> (crate::runtime::science::ScienceStopOutcome, bool) {
                        panic!("no Science stop expected")
                    },
                    |current| {
                        current
                            .stop_proxy_with(|_| Err("injected terminal stop uncertainty".into()))
                    },
                )
            });
        assert!(matches!(
            outcome,
            GatewayStopOutcome::Uncertain { owned_count: 1, .. }
        ));
        let rejected = lock(&state).rejected_gateway_candidates.clone();
        assert_eq!(rejected.owned_pids(), vec![child_pid]);
        assert_eq!(unsafe { libc::kill(child_pid as i32, 0) }, 0);

        let attempts = Cell::new(0usize);
        rejected.drain_for_terminal_with(|child| {
            let next = attempts.get() + 1;
            attempts.set(next);
            if next < 3 {
                Err("injected repeated terminal uncertainty".into())
            } else {
                crate::runtime::system::stop_child_confirmed(child)
            }
        });
        assert_eq!(attempts.get(), 3);
        assert!(rejected.is_idle());
        assert_ne!(unsafe { libc::kill(child_pid as i32, 0) }, 0);
    }

    #[test]
    #[allow(clippy::result_large_err)]
    fn r1_native_exit_wait_releases_read_model_and_stale_result_preserves_replacement() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = env::temp_dir().join(format!(
            "csswitch-r1-native-exit-owner-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&root).unwrap();
        let root = root.canonicalize().unwrap();
        let prior_binary = root.join("prior-science");
        let replacement_binary = root.join("replacement-science");
        fs::write(&prior_binary, b"#!/bin/sh\nexit 0\n").unwrap();
        fs::write(&replacement_binary, b"#!/bin/sh\nexit 0\n# replacement\n").unwrap();
        fs::set_permissions(&prior_binary, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&replacement_binary, fs::Permissions::from_mode(0o700)).unwrap();
        let prior = crate::runtime::science::test_runtime_identity(prior_binary);
        let replacement = crate::runtime::science::test_runtime_identity(replacement_binary);

        for (case, replace_identity, bump_generation) in [
            ("generation-only", false, true),
            ("identity-only", true, false),
        ] {
            let gateway = Command::new("/bin/sleep").arg("30").spawn().unwrap();
            let gateway_pid = gateway.id();
            let mut authority = AppState::default();
            authority.proxy = Some(gateway);
            authority.science_runtime = Some(prior.clone());
            authority.sandbox_port = 18765;
            authority.sandbox_url = Some("http://127.0.0.1:18765/prior".into());
            let state: SharedAppState = Arc::new(Mutex::new(authority));
            let lifecycle: SharedLifecycle = Arc::new(crate::lifecycle::Lifecycle::new());
            let app = tauri::test::mock_builder()
                .manage(state.clone())
                .manage(lifecycle.clone())
                .build(tauri::test::mock_context(tauri::test::noop_assets()))
                .unwrap();
            let handle = app.handle().clone();
            let worker_prior = prior.clone();
            let (stop_started_tx, stop_started_rx) = std::sync::mpsc::channel();
            let (release_stop_tx, release_stop_rx) = std::sync::mpsc::channel();
            let worker = std::thread::spawn(move || {
                let _ = cleanup_for_exit_with(
                    &handle,
                    || {},
                    |_| Vec::new(),
                    |_| {},
                    |_| {},
                    |runtime| {
                        Ok(crate::runtime::science::ScienceStopRequest::recover(
                            runtime,
                        ))
                    },
                    move |_, _request| {
                        stop_started_tx.send(()).unwrap();
                        release_stop_rx.recv().unwrap();
                        (
                            Ok(crate::runtime::science::VerifiedScienceStop {
                                runtime: Some(worker_prior),
                                ownership_was_proven: true,
                            }),
                            true,
                        )
                    },
                    AppState::stop_proxy,
                );
            });

            stop_started_rx.recv().unwrap();
            {
                let mut read_model = state
                    .try_lock()
                    .expect("native-exit Science stop wait must not retain AppState");
                assert_eq!(read_model.science_runtime.as_ref(), Some(&prior), "{case}");
                if replace_identity {
                    read_model.science_runtime = Some(replacement.clone());
                    read_model.sandbox_url = Some("http://127.0.0.1:18765/replacement".into());
                }
            }
            if bump_generation {
                lifecycle.bump_generation();
            }
            release_stop_tx.send(()).unwrap();
            worker.join().unwrap();

            let current = lock(&state);
            let expected_runtime = if replace_identity {
                &replacement
            } else {
                &prior
            };
            let expected_url = if replace_identity {
                "http://127.0.0.1:18765/replacement"
            } else {
                "http://127.0.0.1:18765/prior"
            };
            assert_eq!(
                current.science_runtime.as_ref(),
                Some(expected_runtime),
                "{case}"
            );
            assert!(current.science_confirmed_stopped.is_none(), "{case}");
            assert_eq!(current.sandbox_url.as_deref(), Some(expected_url), "{case}");
            assert!(current.proxy.is_none(), "{case}");
            drop(current);
            assert!(unsafe { libc::kill(gateway_pid as i32, 0) } != 0, "{case}");
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    #[ignore = "source-gate parent executes exact isolated native-exit cleanup with temp HOME, fake process identity, and a dynamic loopback port"]
    fn isolated_r0_native_exit_events_share_repeatable_best_effort_cleanup() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = env::temp_dir().join(format!(
            "csswitch-r0-d-native-exit-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&root).unwrap();
        let root = root.canonicalize().unwrap();
        let home = root.join("home");
        fs::create_dir_all(&home).unwrap();
        env::set_var("HOME", &home);
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let sandbox_port = listener.local_addr().unwrap().port();
        assert_ne!(sandbox_port, 8765);
        let proxy_port = TcpListener::bind(("127.0.0.1", 0))
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        assert_ne!(proxy_port, 8765);
        let config_dir = config::default_dir();
        fs::create_dir_all(&config_dir).unwrap();
        let cfg = Config {
            sandbox_port,
            proxy_port,
            ..Default::default()
        };
        config::save_to(&config_dir, &cfg).unwrap();

        let fake_science = root.join("fake-science");
        fs::write(&fake_science, b"#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(&fake_science, fs::Permissions::from_mode(0o700)).unwrap();
        let runtime = crate::runtime::science::test_runtime_identity(fake_science);
        let first_proxy = Command::new("/bin/sleep").arg("30").spawn().unwrap();
        let first_pid = first_proxy.id();
        let mut authority = AppState::default();
        authority.proxy = Some(first_proxy);
        authority.science_runtime = Some(runtime.clone());
        let state: SharedAppState = Arc::new(Mutex::new(authority));
        let lifecycle: SharedLifecycle = Arc::new(crate::lifecycle::Lifecycle::new());
        let supervisor = Arc::new(crate::codex_auth_supervisor::CodexAuthSupervisor::default());
        let app = tauri::test::mock_builder()
            .manage(state.clone())
            .manage(lifecycle.clone())
            .manage(supervisor)
            .build(tauri::test::mock_context(tauri::test::noop_assets()))
            .unwrap();
        let generation = lifecycle.current_generation();

        assert_eq!(cleanup_for_exit(app.handle()), GatewayStopOutcome::Stopped);
        assert!(lock(&state).proxy.is_none());
        assert!(unsafe { libc::kill(first_pid as i32, 0) } != 0);
        assert_eq!(lock(&state).science_runtime.as_ref(), Some(&runtime));
        assert_eq!(lifecycle.current_generation(), generation);
        assert!(TcpStream::connect(("127.0.0.1", sandbox_port)).is_ok());

        let second_proxy = Command::new("/bin/sleep").arg("30").spawn().unwrap();
        let second_pid = second_proxy.id();
        lock(&state).proxy = Some(second_proxy);
        assert_eq!(cleanup_for_exit(app.handle()), GatewayStopOutcome::Stopped);
        assert!(lock(&state).proxy.is_none());
        assert!(unsafe { libc::kill(second_pid as i32, 0) } != 0);
        assert_eq!(lock(&state).science_runtime.as_ref(), Some(&runtime));
        assert_eq!(lifecycle.current_generation(), generation);
        assert!(TcpStream::connect(("127.0.0.1", sandbox_port)).is_ok());

        drop(app);
        drop(listener);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn redact_scrubs_secret_and_is_noop_when_empty() {
        assert_eq!(
            redact("推理指向 http://127.0.0.1:18991/abcd1234 尾巴", "abcd1234"),
            "推理指向 http://127.0.0.1:18991/**** 尾巴"
        );
        assert_eq!(redact("原样返回", ""), "原样返回");
        assert!(!redact("leak abcd1234 leak abcd1234", "abcd1234").contains("abcd1234"));
    }

    fn keyed_profile(id: &str, key: &str) -> Profile {
        let (model_catalog, default_model_route_id, role_bindings) =
            crate::model_catalog::new_profile_catalog("deepseek", "anthropic", None).unwrap();
        let model = model_catalog
            .iter()
            .find(|route| route.selector_id == default_model_route_id)
            .unwrap()
            .upstream_model
            .clone();
        Profile {
            id: id.into(),
            name: id.into(),
            template_id: "deepseek".into(),
            category: "cn_official".into(),
            api_format: "anthropic".into(),
            api_key: key.into(),
            model,
            model_catalog,
            default_model_route_id,
            role_bindings,
            model_policy: crate::provider_contracts::ModelPolicy::SavedCatalog,
            ..Default::default()
        }
    }

    fn codex_profile(id: &str) -> Profile {
        Profile {
            id: id.into(),
            name: id.into(),
            template_id: "codex".into(),
            category: "experimental".into(),
            api_format: "openai_responses".into(),
            credential_source: crate::provider_contracts::CredentialSource::CsswitchOauth,
            credential_ref: Some("csswitch:codex:default".into()),
            model_policy: crate::provider_contracts::ModelPolicy::DynamicCatalog,
            ..Default::default()
        }
    }

    #[test]
    fn decide_launch_defaults_to_showing_panel() {
        let active_with_key = Config {
            profiles: vec![keyed_profile("p1", "sk-present")],
            active_id: "p1".into(),
            ..Default::default()
        };
        assert_eq!(
            decide_launch_with_auto_boot(&active_with_key, false),
            LaunchPath::ShowPanel
        );
    }

    #[test]
    fn decide_launch_auto_boot_uses_current_mode_and_active_profile_key() {
        let official = Config {
            mode: "official".into(),
            ..Default::default()
        };
        assert_eq!(
            decide_launch_with_auto_boot(&official, true),
            LaunchPath::OpenOfficial
        );

        let no_active = Config {
            profiles: vec![keyed_profile("p1", "sk-present")],
            active_id: String::new(),
            ..Default::default()
        };
        assert_eq!(
            decide_launch_with_auto_boot(&no_active, true),
            LaunchPath::ShowPanel
        );

        let active_without_key = Config {
            profiles: vec![keyed_profile("p1", "")],
            active_id: "p1".into(),
            ..Default::default()
        };
        assert_eq!(
            decide_launch_with_auto_boot(&active_without_key, true),
            LaunchPath::ShowPanel
        );

        let active_with_key = Config {
            profiles: vec![keyed_profile("p1", "sk-present")],
            active_id: "p1".into(),
            ..Default::default()
        };
        assert_eq!(
            decide_launch_with_auto_boot(&active_with_key, true),
            LaunchPath::BootScience
        );

        let dangling_active = Config {
            profiles: vec![keyed_profile("p1", "sk-present")],
            active_id: "missing".into(),
            ..Default::default()
        };
        assert_eq!(
            decide_launch_with_auto_boot(&dangling_active, true),
            LaunchPath::ShowPanel
        );

        let codex_disabled = Config {
            profiles: vec![codex_profile("codex-1")],
            active_id: "codex-1".into(),
            ..Default::default()
        };
        assert_eq!(
            decide_launch_with_auto_boot(&codex_disabled, true),
            LaunchPath::ShowPanel
        );
        let codex_enabled = Config {
            experimental_codex_enabled: true,
            ..codex_disabled
        };
        assert_eq!(
            decide_launch_with_auto_boot(&codex_enabled, true),
            LaunchPath::ShowPanel
        );
    }

    #[test]
    fn should_begin_boot_only_from_idle_or_failed() {
        assert!(should_begin_boot(BootState::Idle));
        assert!(should_begin_boot(BootState::Failed));
        assert!(should_begin_boot(BootState::Attention));
        assert!(!should_begin_boot(BootState::Starting));
        assert!(!should_begin_boot(BootState::Ready));
    }

    #[test]
    fn r0_second_instance_callback_boot_state_matrix_reuses_one_click_login_cmd() {
        type MockBootScienceCommand = BootScienceCommand<tauri::test::MockRuntime>;
        let production: MockBootScienceCommand = production_boot_science_command();
        let expected: MockBootScienceCommand =
            crate::commands::runtime::one_click_login_cmd::<tauri::test::MockRuntime>;
        assert_eq!(
            production as usize, expected as usize,
            "the production BootScience binding must remain the manual one-click command"
        );

        let choices = RefCell::new(Vec::new());
        for initial in [
            BootState::Idle,
            BootState::Failed,
            BootState::Attention,
            BootState::Starting,
            BootState::Ready,
        ] {
            let mut authority = AppState::default();
            authority.boot = BootPublication {
                sequence: 7,
                state: initial,
                payload: Some(serde_json::json!({"sentinel": "payload"})),
            };
            let state: SharedAppState = Arc::new(Mutex::new(authority));
            let lifecycle: SharedLifecycle = Arc::new(crate::lifecycle::Lifecycle::new());
            let app = tauri::test::mock_builder()
                .manage(state.clone())
                .manage(lifecycle)
                .build(tauri::test::mock_context(tauri::test::noop_assets()))
                .unwrap();

            let execute_count = Cell::new(0);
            let load_count = Cell::new(0);
            let decision_count = Cell::new(0);
            let command_count = Cell::new(0);
            let show_count = Cell::new(0);
            run_second_instance_callback_with(
                app.handle(),
                |app| {
                    execute_count.set(execute_count.get() + 1);
                    assert_eq!(lock(&state).boot.state, BootState::Starting);
                    run_boot_decision_with(
                        app,
                        || {
                            load_count.set(load_count.get() + 1);
                            Ok(Config::default())
                        },
                        |_| {
                            decision_count.set(decision_count.get() + 1);
                            LaunchPath::BootScience
                        },
                        || -> Result<(), String> {
                            panic!("BootScience must not call the official launch action")
                        },
                        |_,
                         _,
                         _,
                         runtime_choice|
                         -> Result<
                            serde_json::Value,
                            crate::commands::codex::RuntimeCommandError,
                        > {
                            command_count.set(command_count.get() + 1);
                            choices.borrow_mut().push(runtime_choice);
                            Ok(serde_json::json!({"status": "ok"}))
                        },
                        |_| {
                            Ok(crate::runtime::finalize_consumer::test_consumer_state(
                                crate::runtime::finalize_consumer::FinalizeConsumerDisposition::Ready,
                            ))
                        },
                        |_| show_count.set(show_count.get() + 1),
                    );
                },
                |_| show_count.set(show_count.get() + 1),
            );

            let authority = lock(&state);
            if matches!(
                initial,
                BootState::Idle | BootState::Failed | BootState::Attention
            ) {
                assert_eq!(execute_count.get(), 1, "initial state: {initial:?}");
                assert_eq!(load_count.get(), 1, "initial state: {initial:?}");
                assert_eq!(decision_count.get(), 1, "initial state: {initial:?}");
                assert_eq!(command_count.get(), 1, "initial state: {initial:?}");
                assert_eq!(show_count.get(), 0, "initial state: {initial:?}");
                assert_eq!(authority.boot.state, BootState::Ready);
                assert_eq!(authority.boot.sequence, 9);
                assert!(authority.boot.payload.is_none());
            } else {
                assert_eq!(execute_count.get(), 0, "initial state: {initial:?}");
                assert_eq!(load_count.get(), 0, "initial state: {initial:?}");
                assert_eq!(decision_count.get(), 0, "initial state: {initial:?}");
                assert_eq!(command_count.get(), 0, "initial state: {initial:?}");
                assert_eq!(show_count.get(), 1, "initial state: {initial:?}");
                assert_eq!(authority.boot.state, initial);
                assert_eq!(authority.boot.sequence, 7);
                assert_eq!(
                    authority.boot.payload,
                    Some(serde_json::json!({"sentinel": "payload"}))
                );
            }
        }
        assert_eq!(
            *choices.borrow(),
            vec![None, None, None],
            "Idle, Failed, and Attention callbacks must pass no runtime choice"
        );
    }
}
