use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use regex::Regex;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use csswitch_skill_install_core::{
    active_org, attach_skill, find_bundle_for_skill, install_github_package_with_progress,
    quarantine_bundle, read_agent_skill_names, release_unstaged_install_plan_reservation,
    reserve_install_plan_capacity, resolve_exact_github_archive, update_agent_skills,
    verify_attach_control_ready, AttachError, AttachResult, BundleCommit, ConfirmablePlanRequestV1,
    ConfirmablePlanTargetV1, InstallCommit, InstallError, InstalledPackage, ScienceHostContext,
    SkillOperationConfirmationCapabilityV1, SkillOperationOperonAdapter,
    SkillOperationPrepareRequestV1, SkillOperationPrepared, SkillOperationRemovalPrepared,
    SkillOperationTargetBindingV1, SkillRemovalRoots, GITHUB_BUNDLE_OPERATION_TIMEOUT_SECONDS,
    SCHEMA_VERSION,
};
#[cfg(test)]
use csswitch_skill_install_core::{install_local_package, LocalArchiveInput};

const INSTALL_TOOL_NAME: &str = "install_external_skill";
const UNINSTALL_TOOL_NAME: &str = "uninstall_external_skill";
const POLL_TOOL_NAME: &str = "poll_external_skill_request";
const IMPORT_ORIGIN_FILE: &str = ".import-origin";
const CSSWITCH_MARKETPLACE: &str = "csswitch-local-bridge";
const MAX_IMPORT_ORIGIN_BYTES: usize = 16 * 1024;
const BRIDGE_KEY_FILE_ENV: &str = "CSSWITCH_SKILL_BRIDGE_KEY_FILE";
const BRIDGE_REQUEST_VERSION: u64 = 1;
const BRIDGE_REQUEST_TTL_SECONDS: u64 = 180;
const CONFIRMATION_SCHEMA_VERSION: u64 = 1;
const SKILL_OPERATION_PLAN_TTL_SECONDS: u64 = 300;
pub(crate) const BRIDGE_INSTALL_RESPONSE_TIMEOUT_SECONDS: u64 =
    GITHUB_BUNDLE_OPERATION_TIMEOUT_SECONDS + 60;

#[derive(Debug)]
pub(crate) struct AuthorityFenceDescriptor {
    directory: File,
    directory_device: u64,
    directory_inode: u64,
    lock_device: u64,
    lock_inode: u64,
}

impl Clone for AuthorityFenceDescriptor {
    fn clone(&self) -> Self {
        Self {
            directory: self
                .directory
                .try_clone()
                .expect("verified authority fence directory descriptor must remain open"),
            directory_device: self.directory_device,
            directory_inode: self.directory_inode,
            lock_device: self.lock_device,
            lock_inode: self.lock_inode,
        }
    }
}

#[derive(Debug)]
pub(crate) struct AuthorityFenceSharedGuard {
    file: File,
    // This clone is made only after the inherited descriptor and its lock
    // entry have both been revalidated.  It is deliberately not a pathname:
    // the bridge mailbox is guest-writable and never contains operation
    // staging, ledgers, or quarantine data.
    directory: File,
}

#[cfg(test)]
static AUTHORITY_FENCE_AFTER_LOCK_SEAM: std::sync::LazyLock<
    std::sync::Mutex<Option<(PathBuf, PathBuf)>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(None));

fn authority_fence_metadata_matches(metadata: &std::fs::Metadata, device: u64, inode: u64) -> bool {
    metadata.is_file()
        && metadata.dev() == device
        && metadata.ino() == inode
        && metadata.uid() == unsafe { libc::geteuid() }
        && metadata.nlink() == 1
        && metadata.permissions().mode() & 0o077 == 0
}

impl Drop for AuthorityFenceSharedGuard {
    fn drop(&mut self) {
        // SAFETY: this guard owns the per-mutation open-file-description.
        unsafe {
            libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

impl AuthorityFenceSharedGuard {
    pub(crate) fn authority_root(&self) -> &File {
        &self.directory
    }
}

impl AuthorityFenceDescriptor {
    #[cfg(test)]
    pub(crate) fn test_only(
        directory: File,
        directory_device: u64,
        directory_inode: u64,
        lock_device: u64,
        lock_inode: u64,
    ) -> Self {
        Self {
            directory,
            directory_device,
            directory_inode,
            lock_device,
            lock_inode,
        }
    }

    pub(crate) fn from_env(bridge_token: &str) -> Result<Self, String> {
        let parse = |name: &str| {
            std::env::var(name)
                .ok()
                .and_then(|value| value.parse::<u64>().ok())
                .ok_or_else(|| format!("{name} 非法或缺失"))
        };
        let fd = std::env::var("CSSWITCH_AUTHORITY_FENCE_FD")
            .ok()
            .and_then(|value| value.parse::<i32>().ok())
            .filter(|value| *value >= 3)
            .ok_or("CSSWITCH_AUTHORITY_FENCE_FD 非法或缺失")?;
        let directory_device = parse("CSSWITCH_AUTHORITY_FENCE_DIRECTORY_DEVICE")?;
        let directory_inode = parse("CSSWITCH_AUTHORITY_FENCE_DIRECTORY_INODE")?;
        let lock_device = parse("CSSWITCH_AUTHORITY_FENCE_LOCK_DEVICE")?;
        let lock_inode = parse("CSSWITCH_AUTHORITY_FENCE_LOCK_INODE")?;
        let binding = std::env::var("CSSWITCH_AUTHORITY_FENCE_NONCE")
            .map_err(|_| "CSSWITCH_AUTHORITY_FENCE_NONCE 缺失")?;
        let mut expected = Sha256::new();
        expected.update(b"csswitch-skill-authority-fence-v1\0");
        expected.update(bridge_token.as_bytes());
        if binding != format!("{:x}", expected.finalize()) {
            return Err("Skill authority fence descriptor 与当前 bridge 配置不匹配".into());
        }
        let owned_fd = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 64) };
        if owned_fd < 0 {
            return Err("无法接管 Skill authority fence directory descriptor".into());
        }
        // Trusted Desktop spawn supplied this raw descriptor only across the
        // Desktop -> Gateway exec boundary. Close it before Gateway can launch
        // any downloader child; untrusted standalone callers fail validation.
        if unsafe { libc::close(fd) } != 0 {
            unsafe { libc::close(owned_fd) };
            return Err("无法关闭已继承的 Skill authority fence descriptor".into());
        }
        let directory = unsafe { File::from_raw_fd(owned_fd) };
        let metadata = directory
            .metadata()
            .map_err(|_| "无法检查 Skill authority fence directory descriptor")?;
        if !metadata.is_dir()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.permissions().mode() & 0o077 != 0
            || metadata.dev() != directory_device
            || metadata.ino() != directory_inode
        {
            return Err("Skill authority fence directory descriptor identity 或权限不匹配".into());
        }
        Ok(Self {
            directory,
            directory_device,
            directory_inode,
            lock_device,
            lock_inode,
        })
    }

    pub(crate) fn acquire_shared(&self) -> Result<AuthorityFenceSharedGuard, String> {
        let directory = self
            .directory
            .metadata()
            .map_err(|_| "无法复核 Skill authority fence directory descriptor")?;
        if !directory.is_dir()
            || directory.uid() != unsafe { libc::geteuid() }
            || directory.permissions().mode() & 0o077 != 0
            || directory.dev() != self.directory_device
            || directory.ino() != self.directory_inode
        {
            return Err("Skill authority fence directory descriptor 已漂移".into());
        }
        let name = std::ffi::CString::new(".runtime-compensation.auth.lock").unwrap();
        let fd = unsafe {
            libc::openat(
                self.directory.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDWR | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            )
        };
        if fd < 0 {
            return Err("Skill authority fence lock entry 不可用".into());
        }
        let file = unsafe { File::from_raw_fd(fd) };
        let metadata = file
            .metadata()
            .map_err(|_| "无法检查 Skill authority fence lock")?;
        if !authority_fence_metadata_matches(&metadata, self.lock_device, self.lock_inode) {
            return Err("Skill authority fence descriptor identity 或权限不匹配".into());
        }
        loop {
            // SAFETY: `file` is a new O_CLOEXEC open-file-description for this mutation.
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_SH) } == 0 {
                let after_lock = match file.metadata() {
                    Ok(metadata) => metadata,
                    Err(_) => {
                        unsafe {
                            libc::flock(file.as_raw_fd(), libc::LOCK_UN);
                        }
                        return Err("无法复核已锁定的 Skill authority fence".into());
                    }
                };
                #[cfg(test)]
                if let Some((entered, release)) = AUTHORITY_FENCE_AFTER_LOCK_SEAM
                    .lock()
                    .unwrap_or_else(|error| error.into_inner())
                    .clone()
                {
                    fs::write(entered, b"locked").map_err(|_| {
                        unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) };
                        "无法发布 authority fence after-lock 测试同步点"
                    })?;
                    wait_for_authority_fence_test_path(&release)?;
                }
                let fresh_fd = unsafe {
                    libc::openat(
                        self.directory.as_raw_fd(),
                        name.as_ptr(),
                        libc::O_RDWR | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
                    )
                };
                if fresh_fd < 0 {
                    unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) };
                    return Err("已锁定后无法重新打开 Skill authority fence entry".into());
                }
                let fresh = unsafe { File::from_raw_fd(fresh_fd) };
                let fresh_metadata = match fresh.metadata() {
                    Ok(metadata) => metadata,
                    Err(_) => {
                        unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) };
                        return Err("已锁定后无法复核 Skill authority fence entry".into());
                    }
                };
                if authority_fence_metadata_matches(&after_lock, self.lock_device, self.lock_inode)
                    && authority_fence_metadata_matches(
                        &fresh_metadata,
                        self.lock_device,
                        self.lock_inode,
                    )
                    && fresh_metadata.dev() == after_lock.dev()
                    && fresh_metadata.ino() == after_lock.ino()
                {
                    let directory = self.directory.try_clone().map_err(|_| {
                        unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) };
                        "无法克隆已验证的 Skill authority root descriptor"
                    })?;
                    return Ok(AuthorityFenceSharedGuard { file, directory });
                }
                unsafe {
                    libc::flock(file.as_raw_fd(), libc::LOCK_UN);
                }
                return Err("已锁定的 Skill authority fence identity 或权限不匹配".into());
            }
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::Interrupted {
                return Err(format!("无法取得 Skill authority shared fence: {error}"));
            }
        }
    }
}

#[cfg(test)]
fn wait_for_authority_fence_test_path(path: &Path) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        if path.exists() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    Err("authority fence 测试同步点超时".into())
}

#[derive(Debug)]
struct InstallLock {
    _file: File,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ToolMode {
    Install,
    Uninstall,
    All,
}

impl ToolMode {
    fn server_name(self) -> &'static str {
        match self {
            Self::Install => "csswitch-skill-installer",
            Self::Uninstall => "csswitch-skill-uninstaller",
            Self::All => "csswitch-external-skill-bridge",
        }
    }

    fn allows(self, tool_name: &str) -> bool {
        match self {
            Self::Install => matches!(tool_name, INSTALL_TOOL_NAME | POLL_TOOL_NAME),
            Self::Uninstall => matches!(tool_name, UNINSTALL_TOOL_NAME | POLL_TOOL_NAME),
            Self::All => matches!(
                tool_name,
                INSTALL_TOOL_NAME | UNINSTALL_TOOL_NAME | POLL_TOOL_NAME
            ),
        }
    }

    fn definitions(self) -> Vec<Value> {
        match self {
            Self::Install => vec![install_tool_definition(), poll_tool_definition()],
            Self::Uninstall => vec![uninstall_tool_definition(), poll_tool_definition()],
            Self::All => vec![
                install_tool_definition(),
                uninstall_tool_definition(),
                poll_tool_definition(),
            ],
        }
    }
}

pub fn run_mcp(args: &[String]) -> Result<(), String> {
    let (bridge_dir, tool_mode) = parse_mcp_args(args)?;
    let bridge_token = read_bridge_token_file()?;
    let stdin = io::stdin();
    let mut stdout = io::stdout().lock();
    for line in stdin.lock().lines() {
        let line = line.map_err(|e| format!("读取 MCP 请求失败：{e}"))?;
        if line.trim().is_empty() {
            continue;
        }
        let request: Value = match serde_json::from_str(&line) {
            Ok(value) => value,
            Err(_) => continue,
        };
        if let Some(response) = handle_mcp_request(&bridge_dir, &bridge_token, tool_mode, &request)
        {
            serde_json::to_writer(&mut stdout, &response)
                .map_err(|e| format!("编码 MCP 响应失败：{e}"))?;
            stdout
                .write_all(b"\n")
                .map_err(|e| format!("写 MCP 响应失败：{e}"))?;
            stdout
                .flush()
                .map_err(|e| format!("刷新 MCP 响应失败：{e}"))?;
        }
    }
    Ok(())
}

fn parse_mcp_args(args: &[String]) -> Result<(PathBuf, ToolMode), String> {
    if !matches!(args.len(), 2 | 4) || args[0] != "--bridge-dir" {
        return Err("用法：skill-install-mcp --bridge-dir <CSSwitch private bridge dir> [--tool-mode install|uninstall]".into());
    }
    let path = PathBuf::from(args[1].trim());
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("");
    if !path.is_absolute() || !name.starts_with("CSSwitch-Skill-Bridge-") {
        return Err("安装宿主必须是 CSSwitch 生成的隔离 HOME bridge directory".into());
    }
    let tool_mode = if args.len() == 2 {
        ToolMode::All
    } else {
        if args[2] != "--tool-mode" {
            return Err("MCP tool mode 参数非法".into());
        }
        match args[3].as_str() {
            "install" => ToolMode::Install,
            "uninstall" => ToolMode::Uninstall,
            _ => return Err("MCP tool mode 只支持 install 或 uninstall".into()),
        }
    };
    Ok((path, tool_mode))
}

fn handle_mcp_request(
    bridge_dir: &Path,
    bridge_token: &str,
    tool_mode: ToolMode,
    request: &Value,
) -> Option<Value> {
    let id = request.get("id")?.clone();
    let method = request.get("method").and_then(Value::as_str).unwrap_or("");
    let result = match method {
        "initialize" => json!({
            "protocolVersion": "2025-03-26",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": tool_mode.server_name(), "version": "0.1.0"}
        }),
        "ping" => json!({}),
        "tools/list" => json!({"tools": tool_mode.definitions()}),
        "tools/call" => {
            let params = request.get("params").cloned().unwrap_or_else(|| json!({}));
            let tool_name = params.get("name").and_then(Value::as_str).unwrap_or("");
            if !tool_mode.allows(tool_name) {
                return Some(rpc_error(id, -32602, "该 connector 不提供此工具"));
            }
            let arguments = params
                .get("arguments")
                .cloned()
                .unwrap_or_else(|| json!({}));
            // Apply remains source-url-bound at signed-host validation, but
            // must not be converted into the legacy name-only response before
            // it reaches that boundary.
            let confirmation_operation_action = confirmation_request(&arguments)
                .ok()
                .flatten()
                .is_some_and(|confirmation| {
                    matches!(
                        confirmation.action,
                        ConfirmationAction::Apply
                            | ConfirmationAction::Reconcile
                            | ConfirmationAction::Continue
                    )
                });
            let uninstall_operation_authoritative = confirmation_request(&arguments)
                .ok()
                .flatten()
                .is_some_and(|confirmation| {
                    matches!(
                        confirmation.action,
                        ConfirmationAction::Apply
                            | ConfirmationAction::Reconcile
                            | ConfirmationAction::Continue
                    )
                });
            let payload = match tool_name {
                INSTALL_TOOL_NAME => {
                    if arguments
                        .get("source_url")
                        .and_then(Value::as_str)
                        .is_none_or(|value| value.trim().is_empty())
                        && !confirmation_operation_action
                    {
                        install_from_arguments(Path::new("/"), &arguments)
                    } else {
                        host_access_request(bridge_dir, bridge_token, "install", &arguments)
                    }
                }
                UNINSTALL_TOOL_NAME if uninstall_operation_authoritative => {
                    host_access_request(bridge_dir, bridge_token, "uninstall", &arguments)
                }
                UNINSTALL_TOOL_NAME => match validate_uninstall_arguments(&arguments) {
                    Ok(_) => host_access_request(bridge_dir, bridge_token, "uninstall", &arguments),
                    Err(message) => uninstall_failure(message),
                },
                POLL_TOOL_NAME => poll_bridge_request(bridge_dir, &arguments),
                _ => return Some(rpc_error(id, -32602, "未知工具")),
            };
            tool_result(payload)
        }
        _ => return Some(rpc_error(id, -32601, "未知 MCP 方法")),
    };
    Some(json!({"jsonrpc": "2.0", "id": id, "result": result}))
}

fn host_access_request(
    bridge_dir: &Path,
    bridge_token: &str,
    operation: &str,
    arguments: &Value,
) -> Value {
    let id = random_request_id().unwrap_or_else(|_| format!("{:032x}", unique_suffix()));
    let host_path = bridge_dir.to_string_lossy().into_owned();
    let mut request = json!({
        "version": BRIDGE_REQUEST_VERSION,
        "id": id,
        "issued_at": unix_seconds(),
        "operation": operation,
        "arguments": arguments
    });
    let signature = sign_bridge_request(bridge_token, &request).unwrap_or_else(|_| "0".repeat(64));
    request["signature"] = Value::String(signature);
    json!({
        "status": "HOST_ACCESS_REQUIRED",
        "request_id": id,
        "message": "调用 request_host_access，为 host_access.host_path 请求 rw 权限。授权成功后必须使用返回的 guestPath：只调用一次 edit_file（old_string 为空）把 request.payload 写入 guestPath/request.filename。随后只调用 poll_external_skill_request 查询同一 request_id；首次不传 last_sequence，后续传回上次 sequence，让 gateway 长轮询阶段变化或最终响应。不要直接反复读取文件，不要运行 sleep、shell/Python 轮询，也绝不能再次写 request_filename、再次调用安装/卸载工具或创建新请求。宿主会把成功、失败、超时或中断恢复写成最终响应并清理 .processing；poll 工具超过 deadline_at + terminal_grace_seconds 仍无最终响应时会返回 HOST_RESPONSE_TIMEOUT。任何最终响应（包括 retryable 错误）都必须原样告知用户并结束本次请求；没有用户新的明确指令，绝不能自动重试或生成新 request_id。安装不要改用 host.skills.edit/publish；卸载不要改用 host.skills.delete 或 skills.deleteDraft。",
        "bridge_dir": bridge_dir,
        "host_access": {
            "host_path": host_path,
            "mode": "rw",
            "use_returned_guest_path": true
        },
        "request": {
            "filename": format!("{id}.request.json"),
            "status_filename": format!("{id}.status.json"),
            "response_filename": format!("{id}.response.json"),
            "poll_tool": POLL_TOOL_NAME,
            "poll_after_seconds": 0,
            "timeout_seconds": BRIDGE_INSTALL_RESPONSE_TIMEOUT_SECONDS,
            "terminal_grace_seconds": 5,
            "payload": request
        },
        "directory_commit": false,
        "restart_required": false
    })
}

fn poll_bridge_request(bridge_dir: &Path, arguments: &Value) -> Value {
    let request_id = arguments
        .get("request_id")
        .and_then(Value::as_str)
        .unwrap_or("");
    if request_id.len() != 32
        || !request_id
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return json!({
            "status": "REQUEST_STATUS_INVALID",
            "request_id": request_id,
            "poll_again": false,
            "message": "request_id 必须是 install/uninstall 工具原样返回的 32 位小写十六进制 ID。"
        });
    }
    let last_sequence = arguments.get("last_sequence").and_then(Value::as_u64);
    let response_path = bridge_dir.join(format!("{request_id}.response.json"));
    let status_path = bridge_dir.join(format!("{request_id}.status.json"));
    let wait_deadline = Instant::now() + Duration::from_secs(10);
    let mut latest_status = None;
    loop {
        match read_bridge_poll_json(&response_path) {
            Ok(Some(mut response)) => {
                if let Some(object) = response.as_object_mut() {
                    object
                        .entry("request_id")
                        .or_insert_with(|| json!(request_id));
                    object.insert("poll_complete".into(), Value::Bool(true));
                    object.insert("poll_again".into(), Value::Bool(false));
                }
                return response;
            }
            Ok(None) => {}
            Err(message) => return poll_read_failure(request_id, &message),
        }
        match read_bridge_poll_json(&status_path) {
            Ok(Some(mut status)) => {
                let sequence = status.get("sequence").and_then(Value::as_u64);
                let deadline_at = status.get("deadline_at").and_then(Value::as_u64);
                let terminal_grace = status
                    .get("terminal_grace_seconds")
                    .and_then(Value::as_u64)
                    .unwrap_or(5);
                if deadline_at.is_some_and(|deadline| {
                    unix_seconds() > deadline.saturating_add(terminal_grace)
                }) {
                    return json!({
                        "status": "HOST_RESPONSE_TIMEOUT",
                        "request_id": request_id,
                        "poll_again": false,
                        "deadline_at": deadline_at,
                        "message": "宿主最终响应超过固定 deadline 与 grace；停止轮询，禁止重复提交同一请求。"
                    });
                }
                if let Some(object) = status.as_object_mut() {
                    object.insert("poll_complete".into(), Value::Bool(false));
                    object.insert("poll_again".into(), Value::Bool(true));
                    object.insert("poll_tool".into(), Value::String(POLL_TOOL_NAME.into()));
                }
                latest_status = Some(status);
                if last_sequence.is_none() || sequence != last_sequence {
                    return latest_status.expect("status was just stored");
                }
            }
            Ok(None) => {}
            Err(message) => return poll_read_failure(request_id, &message),
        }
        if Instant::now() >= wait_deadline {
            return latest_status.unwrap_or_else(|| {
                json!({
                    "status": "REQUEST_NOT_READY",
                    "request_id": request_id,
                    "poll_complete": false,
                    "poll_again": true,
                    "poll_tool": POLL_TOOL_NAME,
                    "message": "宿主尚未接收该请求；保持同一 request_id 继续查询，禁止重新提交。"
                })
            });
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

fn poll_read_failure(request_id: &str, message: &str) -> Value {
    json!({
        "status": "REQUEST_STATUS_UNAVAILABLE",
        "request_id": request_id,
        "poll_again": false,
        "message": format!("无法安全读取宿主请求状态：{message}")
    })
}

fn read_bridge_poll_json(path: &Path) -> Result<Option<Value>, String> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
    }
    let file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.to_string()),
    };
    let metadata = file.metadata().map_err(|error| error.to_string())?;
    if !metadata.is_file() || metadata.len() > 1024 * 1024 {
        return Err("状态文件类型或大小非法".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.uid() != unsafe { libc::geteuid() }
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err("状态文件属主或权限非法".into());
        }
    }
    serde_json::from_reader(file)
        .map(Some)
        .map_err(|_| "状态文件 JSON 非法".into())
}

fn read_bridge_token_file() -> Result<String, String> {
    let path = std::env::var_os(BRIDGE_KEY_FILE_ENV)
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .ok_or("缺少 CSSwitch 私有 Skill bridge key file")?;
    reject_symlink_path(&path)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
    }
    let file = options
        .open(&path)
        .map_err(|_| "无法读取 CSSwitch 私有 Skill bridge key file")?;
    let metadata = file
        .metadata()
        .map_err(|_| "无法检查 CSSwitch 私有 Skill bridge key file")?;
    if !metadata.is_file() || metadata.len() > 128 {
        return Err("CSSwitch 私有 Skill bridge key file 类型非法".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.uid() != unsafe { libc::geteuid() }
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err("CSSwitch 私有 Skill bridge key file 权限非法".into());
        }
    }
    let mut token = String::new();
    file.take(129)
        .read_to_string(&mut token)
        .map_err(|_| "无法读取 CSSwitch 私有 Skill bridge key file")?;
    let token = token.trim().to_ascii_lowercase();
    validate_bridge_token(&token)?;
    Ok(token)
}

fn validate_bridge_token(token: &str) -> Result<(), String> {
    if token.len() == 64 && token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err("CSSwitch Skill bridge token 格式非法".into())
    }
}

fn random_request_id() -> Result<String, String> {
    let mut bytes = [0_u8; 16];
    getrandom::getrandom(&mut bytes).map_err(|_| "无法生成本地 Skill request id")?;
    Ok(hex_encode(&bytes))
}

fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn canonical_json(value: &Value) -> Value {
    match value {
        Value::Object(object) => {
            let mut sorted = BTreeMap::new();
            for (key, value) in object {
                sorted.insert(key.clone(), canonical_json(value));
            }
            Value::Object(sorted.into_iter().collect())
        }
        Value::Array(items) => Value::Array(items.iter().map(canonical_json).collect()),
        _ => value.clone(),
    }
}

fn sign_bridge_request(token: &str, unsigned_request: &Value) -> Result<String, String> {
    validate_bridge_token(token)?;
    let canonical = canonical_json(unsigned_request);
    let body = serde_json::to_vec(&canonical).map_err(|_| "无法编码本地 Skill 请求")?;
    let mut mac = Hmac::<Sha256>::new_from_slice(token.as_bytes())
        .map_err(|_| "无法初始化本地 Skill 请求签名")?;
    mac.update(&body);
    Ok(hex_encode(&mac.finalize().into_bytes()))
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn hex_decode_32(value: &str) -> Result<[u8; 32], String> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("本地 Skill 请求签名非法".into());
    }
    let mut bytes = [0_u8; 32];
    for (index, output) in bytes.iter_mut().enumerate() {
        *output = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| "本地 Skill 请求签名非法")?;
    }
    Ok(bytes)
}

pub(crate) fn validate_bridge_request(
    bridge_token: &str,
    filename_id: &str,
    request: &Value,
) -> Result<(), String> {
    validate_bridge_token(bridge_token)?;
    if filename_id.len() != 32
        || !filename_id
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err("本地 Skill request id 非法".into());
    }
    let object = request.as_object().ok_or("本地 Skill 请求不是对象")?;
    let allowed = [
        "version",
        "id",
        "issued_at",
        "operation",
        "arguments",
        "signature",
    ];
    if object.len() != allowed.len() || object.keys().any(|key| !allowed.contains(&key.as_str())) {
        return Err("本地 Skill 请求字段非法".into());
    }
    if request.get("version").and_then(Value::as_u64) != Some(BRIDGE_REQUEST_VERSION)
        || request.get("id").and_then(Value::as_str) != Some(filename_id)
    {
        return Err("本地 Skill 请求身份非法".into());
    }
    let issued_at = request
        .get("issued_at")
        .and_then(Value::as_u64)
        .ok_or("本地 Skill 请求时间非法")?;
    let now = unix_seconds();
    if issued_at > now.saturating_add(5)
        || now.saturating_sub(issued_at) > BRIDGE_REQUEST_TTL_SECONDS
    {
        return Err("本地 Skill 请求已过期".into());
    }
    let operation = request
        .get("operation")
        .and_then(Value::as_str)
        .ok_or("本地 Skill 操作非法")?;
    let arguments = request
        .get("arguments")
        .and_then(Value::as_object)
        .ok_or("本地 Skill 请求参数非法")?;
    match operation {
        "install" => {
            let confirmation = confirmation_request(request.get("arguments").unwrap())?;
            let readback_or_continue = confirmation.is_some_and(|confirmation| {
                matches!(
                    confirmation.action,
                    ConfirmationAction::Reconcile | ConfirmationAction::Continue
                )
            });
            if readback_or_continue {
                if arguments.keys().any(|key| key != "confirmation") {
                    return Err(
                        "确认式安装 reconcile/continue 只能携带 operation_id，不能携带 source_url 或 skill_name"
                            .into(),
                    );
                }
            } else if arguments
                .keys()
                .any(|key| !matches!(key.as_str(), "source_url" | "skill_name" | "confirmation"))
                || arguments
                    .get("source_url")
                    .and_then(Value::as_str)
                    .is_none_or(|value| value.trim().is_empty())
            {
                return Err("本地 Skill 安装参数非法".into());
            }
        }
        "uninstall" => {
            let arguments = request.get("arguments").unwrap();
            let operation_authoritative = confirmation_request(arguments)
                .ok()
                .flatten()
                .is_some_and(|confirmation| {
                    matches!(
                        confirmation.action,
                        ConfirmationAction::Apply
                            | ConfirmationAction::Reconcile
                            | ConfirmationAction::Continue
                    )
                });
            if operation_authoritative {
                let object = arguments.as_object().ok_or("本地 Skill 卸载参数非法")?;
                if object.keys().any(|key| key != "confirmation") {
                    return Err("确认式卸载 apply/reconcile/continue 只能携带 operation_id".into());
                }
                confirmation_request(arguments)?;
            } else {
                validate_uninstall_arguments(arguments)?;
            }
        }
        _ => return Err("未知的本地 Skill 操作".into()),
    }
    let signature = request
        .get("signature")
        .and_then(Value::as_str)
        .ok_or("本地 Skill 请求缺少签名")?;
    let signature = hex_decode_32(signature)?;
    let mut unsigned = request.clone();
    unsigned
        .as_object_mut()
        .expect("validated bridge request object")
        .remove("signature");
    let canonical = canonical_json(&unsigned);
    let body = serde_json::to_vec(&canonical).map_err(|_| "无法编码本地 Skill 请求")?;
    let mut mac = Hmac::<Sha256>::new_from_slice(bridge_token.as_bytes())
        .map_err(|_| "无法初始化本地 Skill 请求签名")?;
    mac.update(&body);
    mac.verify_slice(&signature)
        .map_err(|_| "本地 Skill 请求签名不匹配".into())
}

fn rpc_error(id: Value, code: i64, message: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})
}

fn install_tool_definition() -> Value {
    json!({
        "name": INSTALL_TOOL_NAME,
        "description": "安装、导入或添加公开 GitHub 中的单个 Skill 或 Nature-like Skill bundle。Agent 只提交准确 URL，不下载文件、不使用 shell、catalog、Skill Manager、host.skills.edit 或 host.skills.publish。CSSwitch 宿主完成 archive 下载、验证、原子提交并绑定 OPERON；不要手工调用 host.agents.attach_skill。单 Skill返回 INSTALLED_ATTACHED_VERIFY_REQUIRED 后必须调用 skill(skill_name)；bundle 返回 BUNDLE_INSTALLED_ATTACHED 后可直接报告已安装并绑定全部成员。任何最终错误都结束本次请求；即使 retryable=true，也必须先报告用户，禁止自动再次调用本工具。重试 FILES_COMMITTED_ATTACH_REQUIRED 时才可在同一用户请求内再次调用本工具。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "source_url": {"type": "string", "description": "Public GitHub repository, plugin/collection, or exact Skill directory URL."},
                "skill_name": {"type": "string", "description": "The name supplied by the user when no source URL is available."},
                "confirmation": {"type": "object", "description": "Optional exact-plan protocol. schema_version=1; plan creates a short-lived immutable plan, apply consumes its exact operation_id/digest/capability, reconcile is operation_id-only readback, and continue is operation_id-only continuation of a durable verified prefix. Omit it to preserve the legacy installer contract.", "properties": {"schema_version":{"const":1}, "action":{"enum":["plan","apply","reconcile","continue"]}, "operation_id":{"type":"string"}, "plan_digest":{"type":"string"}, "capability":{"type":"string"}}, "required":["schema_version","action"], "additionalProperties":false}
            },
            "additionalProperties": false
        }
    })
}

fn uninstall_tool_definition() -> Value {
    json!({
        "name": UNINSTALL_TOOL_NAME,
        "description": "卸载 CSSwitch 导入的外部 Skill。省略 confirmation 时严格保留旧的单 Skill 隔离和手工 detach 流程。confirmation 可选地启用单 Skill 精确计划：plan 只生成短期 capability，apply 只消费原 operation_id、plan_digest、capability。确认式卸载接纳任一带精确 CSSwitch ownership marker 的非 bundle 已安装单 Skill，包括 local_zip；bundle、Plugin、MCP 和其他非单 Skill 形态均不进入确认式路径。bundle 成员首次调用只返回 BUNDLE_UNINSTALL_CONFIRMATION_REQUIRED、整包信息和受影响 Skill 列表，不改文件或绑定；必须向用户展示完整列表并等待明确确认，确认后把响应的 bundle_id 原样作为 confirm_bundle_id 传回；不支持部分物理删除。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "skill_name": {"type": "string", "description": "Exact installed Skill directory name to uninstall."},
                "confirm_bundle_id": {"type": "string", "description": "Only after explicit user confirmation of BUNDLE_UNINSTALL_CONFIRMATION_REQUIRED, pass that response's exact bundle_id. Omit on the first call and for single-Skill uninstall."},
                "confirmation": {"type": "object", "description": "Optional exact-plan protocol for a single CSSwitch-owned non-bundle Skill. schema_version=1; plan/apply use the exact confirmed plan, reconcile is operation_id-only readback, and continue is operation_id-only verified-prefix continuation. Omit to preserve legacy uninstall exactly.", "properties": {"schema_version":{"const":1}, "action":{"enum":["plan","apply","reconcile","continue"]}, "operation_id":{"type":"string"}, "plan_digest":{"type":"string"}, "capability":{"type":"string"}}, "required":["schema_version","action"], "additionalProperties":false}
            },
            "allOf": [
                {"if":{"not":{"required":["confirmation"]}},"then":{"required":["skill_name"]}},
                {"if":{"properties":{"confirmation":{"properties":{"action":{"const":"plan"}},"required":["action"]}},"required":["confirmation"]},"then":{"required":["skill_name"]}},
                {"if":{"properties":{"confirmation":{"properties":{"action":{"enum":["apply","reconcile","continue"]}},"required":["action"]}},"required":["confirmation"]},"then":{"not":{"anyOf":[{"required":["skill_name"]},{"required":["confirm_bundle_id"]}]}}}
            ],
            "additionalProperties": false
        }
    })
}

fn poll_tool_definition() -> Value {
    json!({
        "name": POLL_TOOL_NAME,
        "description": "只读查询一次已提交的 CSSwitch 外部 Skill 请求。首次只传 request_id；若返回 PROCESSING，下一次把其 sequence 原样作为 last_sequence，gateway 会在内部等待最多 10 秒直到阶段变化。不得用本工具创建新请求，也不得再次调用安装/卸载工具。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "request_id": {"type": "string", "description": "HOST_ACCESS_REQUIRED 原样返回的 request payload id。"},
                "last_sequence": {"type": "integer", "minimum": 0, "description": "上一次 PROCESSING 返回的 sequence；首次查询省略。"}
            },
            "required": ["request_id"],
            "additionalProperties": false
        }
    })
}

fn tool_result(payload: Value) -> Value {
    let payload = with_schema(payload);
    let status = payload.get("status").and_then(Value::as_str);
    let is_error = status.is_some_and(|status| {
        status.starts_with("GITHUB_")
            || status.starts_with("SKILL_OPERATION_")
            || matches!(
                status,
                "HOST_RESPONSE_TIMEOUT"
                    | "REQUEST_STATUS_INVALID"
                    | "REQUEST_STATUS_UNAVAILABLE"
                    | "SOURCE_REF_REQUIRES_COMMIT_SHA"
                    | "LEGACY_INTEGRITY_UNVERIFIED"
                    | "INSTALL_FAILED"
                    | "UNINSTALL_FAILED"
                    | "SKILL_NAME_CONFLICT"
                    | "INSTALLED_CONTENT_CHANGED"
                    | "UNSUPPORTED_SHARED_DEPENDENCY"
                    | "MULTIPLE_BUNDLE_CANDIDATES"
                    | "BUNDLE_STRUCTURE_UNSUPPORTED"
                    | "BUNDLE_LIMIT_EXCEEDED"
                    | "BUNDLE_PATH_CONFLICT"
                    | "UNSUPPORTED_PLUGIN_RUNTIME_DEPENDENCY"
            )
    });
    let text = serde_json::to_string(&payload).unwrap_or_else(|_| "{}".to_string());
    json!({
        "content": [{"type": "text", "text": text}],
        "structuredContent": payload,
        "isError": is_error
    })
}

fn with_schema(mut payload: Value) -> Value {
    if let Some(object) = payload.as_object_mut() {
        object.insert("schema_version".into(), Value::from(SCHEMA_VERSION));
    }
    payload
}

pub(crate) fn handle_bridge_request_with_progress(
    data_dir: &Path,
    science_context: Option<&ScienceHostContext>,
    bridge_dir: Option<&Path>,
    authority_root: Option<&File>,
    request: &Value,
    progress: &mut dyn FnMut(&str, &str),
) -> Value {
    let operation = request
        .get("operation")
        .and_then(Value::as_str)
        .unwrap_or("");
    let arguments = request.get("arguments").unwrap_or(&Value::Null);
    with_schema(match operation {
        "install" => install_from_arguments_with_context_and_progress(
            data_dir,
            science_context,
            bridge_dir,
            authority_root,
            request.get("id").and_then(Value::as_str),
            arguments,
            progress,
        ),
        "uninstall" => uninstall_from_arguments_with_context_and_bridge(
            data_dir,
            science_context,
            bridge_dir,
            authority_root,
            request.get("id").and_then(Value::as_str),
            arguments,
        ),
        _ => json!({
            "status": "REQUEST_FAILED",
            "message": "未知的本地 Skill 操作",
            "directory_commit": false,
            "restart_required": false
        }),
    })
}

pub(crate) fn install_from_arguments(data_dir: &Path, arguments: &Value) -> Value {
    install_from_arguments_with_context(data_dir, None, arguments)
}

fn install_from_arguments_with_context(
    data_dir: &Path,
    science_context: Option<&ScienceHostContext>,
    arguments: &Value,
) -> Value {
    let mut progress = |_: &str, _: &str| {};
    install_from_arguments_with_context_and_progress(
        data_dir,
        science_context,
        None,
        None,
        None,
        arguments,
        &mut progress,
    )
}

fn install_from_arguments_with_context_and_progress(
    data_dir: &Path,
    science_context: Option<&ScienceHostContext>,
    bridge_dir: Option<&Path>,
    authority_root: Option<&File>,
    request_id: Option<&str>,
    arguments: &Value,
    progress: &mut dyn FnMut(&str, &str),
) -> Value {
    let source_url = arguments
        .get("source_url")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let skill_name = arguments
        .get("skill_name")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty());
    // Readback and typed continuation are operation-id-only protocol calls.
    // Do this before the legacy source_url precondition, otherwise a recovery
    // would be accidentally routed to NEED_SOURCE_URL.
    if let Ok(Some(confirmation)) = confirmation_request(arguments) {
        if matches!(
            confirmation.action,
            ConfirmationAction::Reconcile | ConfirmationAction::Continue
        ) {
            if source_url.is_some() || skill_name.is_some() {
                return skill_operation_error(
                    "SKILL_OPERATION_CONFIRMATION_INVALID",
                    "confirmation",
                    "reconcile 或 continue 只能携带 operation_id，不能重新提供 source_url 或 skill_name",
                );
            }
            let Some(context) = science_context else {
                return install_not_ready(None, "CSSwitch 尚未确认可用的 Science runtime");
            };
            let Some(_bridge_dir) = bridge_dir else {
                return skill_operation_error(
                    "SKILL_OPERATION_BRIDGE_UNAVAILABLE",
                    "confirmation",
                    "确认式安装只能由已验证的 CSSwitch bridge 宿主执行",
                );
            };
            let Some(authority_root) = authority_root else {
                return skill_operation_error(
                    "SKILL_OPERATION_AUTHORITY_UNAVAILABLE",
                    "confirmation",
                    "确认式安装必须持有已验证的 host-only authority root",
                );
            };
            return match confirmation.action {
                ConfirmationAction::Reconcile => reconcile_skill_operation_plan(
                    data_dir,
                    context,
                    authority_root,
                    confirmation.operation_id.as_deref().unwrap_or_default(),
                ),
                ConfirmationAction::Continue => continue_skill_operation_plan(
                    data_dir,
                    context,
                    authority_root,
                    confirmation.operation_id.as_deref().unwrap_or_default(),
                ),
                _ => unreachable!(),
            };
        }
    }
    let Some(source_url) = source_url else {
        return json!({
            "status": "NEED_SOURCE_URL",
            "skill_name": skill_name,
            "source_kind": "github",
            "directory_commit": false,
            "attach_attempted": false,
            "attach_required": false,
            "attach_verified": false,
            "load_verification_required": false,
            "content_sha256": null,
            "resolved_commit_sha": null,
            "message": "请提供公开 GitHub 仓库、Skill 集合或准确 Skill 目录链接。CSSwitch 不会根据名称猜测来源。",
            "restart_required": false
        });
    };
    let Some(science_context) = science_context else {
        return install_not_ready(skill_name, "CSSwitch 尚未确认可用的 Science runtime");
    };
    match confirmation_request(arguments) {
        Ok(Some(confirmation)) => {
            let Some(_bridge_dir) = bridge_dir else {
                return skill_operation_error(
                    "SKILL_OPERATION_BRIDGE_UNAVAILABLE",
                    "confirmation",
                    "确认式安装只能由已验证的 CSSwitch bridge 宿主执行",
                );
            };
            let Some(authority_root) = authority_root else {
                return skill_operation_error(
                    "SKILL_OPERATION_AUTHORITY_UNAVAILABLE",
                    "confirmation",
                    "确认式安装必须持有已验证的 host-only authority root",
                );
            };
            return match confirmation.action {
                ConfirmationAction::Plan => {
                    let Some(operation_id) = request_id else {
                        return skill_operation_error(
                            "SKILL_OPERATION_REQUEST_ID_REQUIRED",
                            "confirmation",
                            "确认式安装缺少宿主分配的 operation identity",
                        );
                    };
                    create_skill_operation_plan(
                        data_dir,
                        science_context,
                        authority_root,
                        operation_id,
                        source_url,
                        progress,
                    )
                }
                ConfirmationAction::Apply => apply_skill_operation_plan(
                    data_dir,
                    science_context,
                    authority_root,
                    source_url,
                    confirmation.operation_id.as_deref().unwrap_or_default(),
                    confirmation.plan_digest.as_deref().unwrap_or_default(),
                    confirmation.capability.as_deref().unwrap_or_default(),
                    progress,
                ),
                ConfirmationAction::Reconcile => reconcile_skill_operation_plan(
                    data_dir,
                    science_context,
                    authority_root,
                    confirmation.operation_id.as_deref().unwrap_or_default(),
                ),
                ConfirmationAction::Continue => unreachable!(),
            };
        }
        Ok(None) => {}
        Err(message) => {
            return skill_operation_error(
                "SKILL_OPERATION_CONFIRMATION_INVALID",
                "confirmation",
                &message,
            )
        }
    }
    progress("preflight", "正在确认 Science runtime 与 OPERON 控制面");
    if let Err(error) = verify_attach_control_ready_for_operation(science_context) {
        return install_not_ready(skill_name, &error.message);
    }
    match install_external_skill(data_dir, source_url, science_context, progress) {
        Ok(value) => value,
        Err(error) => install_error_payload(skill_name, error),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ConfirmationAction {
    Plan,
    Apply,
    Reconcile,
    Continue,
}

#[derive(Clone, Debug)]
struct ConfirmationRequest {
    action: ConfirmationAction,
    operation_id: Option<String>,
    plan_digest: Option<String>,
    capability: Option<String>,
}

fn confirmation_request(arguments: &Value) -> Result<Option<ConfirmationRequest>, String> {
    let Some(value) = arguments.get("confirmation") else {
        return Ok(None);
    };
    let object = value.as_object().ok_or("confirmation 必须是对象")?;
    if object.keys().any(|key| {
        !matches!(
            key.as_str(),
            "schema_version" | "action" | "operation_id" | "plan_digest" | "capability"
        )
    }) || object.get("schema_version").and_then(Value::as_u64)
        != Some(CONFIRMATION_SCHEMA_VERSION)
    {
        return Err("confirmation schema_version 或字段非法".into());
    }
    let action = match object.get("action").and_then(Value::as_str) {
        Some("plan") => ConfirmationAction::Plan,
        Some("apply") => ConfirmationAction::Apply,
        Some("reconcile") => ConfirmationAction::Reconcile,
        Some("continue") => ConfirmationAction::Continue,
        _ => return Err("confirmation.action 只支持 plan、apply、reconcile 或 continue".into()),
    };
    let optional_string = |name: &str| -> Result<Option<String>, String> {
        match object.get(name) {
            None => Ok(None),
            Some(Value::String(value)) => Ok(Some(value.to_string())),
            Some(_) => Err(format!("confirmation.{name} 必须是字符串")),
        }
    };
    let operation_id = optional_string("operation_id")?;
    let plan_digest = optional_string("plan_digest")?;
    let capability = optional_string("capability")?;
    if matches!(action, ConfirmationAction::Plan)
        && (operation_id.is_some() || plan_digest.is_some() || capability.is_some())
    {
        return Err("plan 确认请求不能携带 operation_id、digest 或 capability".into());
    }
    if matches!(action, ConfirmationAction::Apply)
        && (!operation_id.as_deref().is_some_and(valid_operation_id)
            || !plan_digest.as_deref().is_some_and(is_sha256)
            || !capability
                .as_deref()
                .is_some_and(|value| value.len() <= 256))
    {
        return Err(
            "apply 确认请求必须携带原 operation_id、64 位 plan_digest 和短期 capability".into(),
        );
    }
    if matches!(action, ConfirmationAction::Reconcile)
        && (!operation_id.as_deref().is_some_and(valid_operation_id)
            || plan_digest.is_some()
            || capability.is_some())
    {
        return Err(
            "reconcile 只能携带原 operation_id，且不能携带 digest、capability 或 source".into(),
        );
    }
    if matches!(action, ConfirmationAction::Continue)
        && (!operation_id.as_deref().is_some_and(valid_operation_id)
            || plan_digest.is_some()
            || capability.is_some())
    {
        return Err(
            "continue 只能携带原 operation_id；它只允许完成已验证前缀后的下一个未开始 effect"
                .into(),
        );
    }
    Ok(Some(ConfirmationRequest {
        action,
        operation_id,
        plan_digest,
        capability,
    }))
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn valid_operation_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

fn skill_operation_error(code: &str, phase: &str, message: &str) -> Value {
    json!({
        "status": code,
        "phase": phase,
        "directory_commit": false,
        "attach_attempted": false,
        "attach_verified": false,
        "recovery_required": false,
        "message": message,
        "restart_required": false,
    })
}

fn operation_error(error: csswitch_skill_install_core::SkillOperationError) -> Value {
    let recovery_required = error.recovery_required();
    // The core owns this classification.  Do not turn deterministic request
    // rejection into a fictional durable recovery path; conversely, preserve
    // unknown fields only when the core says an authority receipt may need
    // readback.
    json!({
        "status": error.code,
        "phase": error.phase,
        "directory_commit": if recovery_required { Value::Null } else { Value::Bool(false) },
        "attach_verified": if recovery_required { Value::Null } else { Value::Bool(false) },
        "recovery_required": recovery_required,
        "message": if recovery_required { "确认式 Skill operation 的 durable authority 结果可能未完整持久化；必须以同一 operation_id reconcile 读取 ledger。" } else { "确认式 Skill operation 在副作用前被拒绝或没有可恢复 authority 状态；请按 status 修正后重新 plan。" },
        "restart_required": false,
    })
}

fn removal_operation_error(error: csswitch_skill_install_core::SkillOperationError) -> Value {
    let recovery_required = error.recovery_required();
    json!({
        "status": error.code,
        "phase": error.phase,
        "detach_verified": if recovery_required { Value::Null } else { Value::Bool(false) },
        "quarantine_commit": if recovery_required { Value::Null } else { Value::Bool(false) },
        "recovery_required": recovery_required,
        "message": if recovery_required { "确认式卸载的 durable authority 结果可能未完整持久化；必须以同一 operation_id reconcile 读取 ledger。" } else { "确认式卸载在副作用前被拒绝或没有可恢复 authority 状态；请按 status 修正后重新 plan。" },
        "restart_required": false,
    })
}

fn operation_roots(authority_root: &File) -> Result<(File, File), String> {
    let staging = open_private_operation_child(authority_root, "skill-operation-staging")?;
    let ledger = open_private_operation_child(authority_root, "skill-operation-ledger")?;
    Ok((staging, ledger))
}

fn open_private_operation_child(bridge: &File, name: &str) -> Result<File, String> {
    let name = std::ffi::CString::new(name).map_err(|_| "operation 根名称非法")?;
    if unsafe { libc::mkdirat(bridge.as_raw_fd(), name.as_ptr(), 0o700) } != 0
        && io::Error::last_os_error().kind() != io::ErrorKind::AlreadyExists
    {
        return Err("无法建立确认式 Skill operation 私有根".into());
    }
    let fd = unsafe {
        libc::openat(
            bridge.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err("无法安全打开确认式 Skill operation 私有根".into());
    }
    let file = unsafe { File::from_raw_fd(fd) };
    let metadata = file
        .metadata()
        .map_err(|_| "无法复核确认式 Skill operation 私有根")?;
    if !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o7777 != 0o700
    {
        return Err("确认式 Skill operation 私有根属主或权限非法".into());
    }
    Ok(file)
}

fn target_binding(
    data_dir: &Path,
    context: &ScienceHostContext,
) -> Result<SkillOperationTargetBindingV1, String> {
    if context.data_dir != data_dir {
        return Err("Science host context data-dir 与 bridge target 不一致".into());
    }
    let metadata = fs::symlink_metadata(data_dir).map_err(|_| "无法检查当前 Science data-dir")?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("当前 Science data-dir 类型非法".into());
    }
    let runtime = serde_json::to_vec(context).map_err(|_| "无法编码 Science runtime identity")?;
    let data_identity = sha256_text(&format!(
        "{}:{}:{}:{}",
        metadata.dev(),
        metadata.ino(),
        metadata.uid(),
        metadata.permissions().mode() & 0o7777,
    ));
    let org = active_org(data_dir).map_err(|_| "无法读取当前 Science active org")?;
    let skills_root = install_operation_skills_root(data_dir, &org)?;
    let skills_metadata = skills_root
        .metadata()
        .map_err(|_| "无法复核当前组织的 Skills 根")?;
    Ok(SkillOperationTargetBindingV1 {
        science_runtime_identity_sha256: sha256_bytes(&runtime),
        data_dir_identity_sha256: data_identity.clone(),
        active_org_identity_sha256: sha256_text(&format!("{data_identity}:{org}")),
        active_org: org,
        skills_root_device: skills_metadata.dev(),
        skills_root_inode: skills_metadata.ino(),
    })
}

fn sha256_text(value: &str) -> String {
    sha256_bytes(value.as_bytes())
}

fn sha256_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn create_skill_operation_plan(
    data_dir: &Path,
    context: &ScienceHostContext,
    authority_root: &File,
    operation_id: &str,
    source_url: &str,
    progress: &mut dyn FnMut(&str, &str),
) -> Value {
    progress(
        "preflight",
        "正在确认 immutable plan 的 Science target binding",
    );
    if let Err(error) = verify_attach_control_ready_for_operation(context) {
        return install_not_ready(None, &error.message);
    }
    let target = match target_binding(data_dir, context) {
        Ok(value) => value,
        Err(message) => {
            return skill_operation_error("SKILL_OPERATION_TARGET_INVALID", "preflight", &message)
        }
    };
    let (staging_root, ledger_root) = match operation_roots(authority_root) {
        Ok(value) => value,
        Err(message) => {
            return skill_operation_error("SKILL_OPERATION_ROOT_UNAVAILABLE", "ledger", &message)
        }
    };
    let expires_at_unix_seconds = unix_seconds().saturating_add(SKILL_OPERATION_PLAN_TTL_SECONDS);
    // Reserve a worst-case archive before any remote transfer.  Remote HEAD
    // metadata is mutable and therefore cannot establish lifecycle capacity.
    if let Err(error) = reserve_install_plan_capacity(
        &staging_root,
        &ledger_root,
        operation_id,
        expires_at_unix_seconds,
    ) {
        return operation_error(error);
    }
    let archive = match resolve_exact_github_archive(source_url, progress) {
        Ok(value) => value,
        Err(error) => {
            if let Err(release_error) =
                release_unstaged_install_plan_reservation(&ledger_root, operation_id)
            {
                return operation_error(release_error);
            }
            return install_error_payload(None, error);
        }
    };
    let request = SkillOperationPrepareRequestV1 {
        operation_id: operation_id.to_string(),
        source_request_sha256: sha256_text(source_url),
        plan: ConfirmablePlanRequestV1 {
            plan_id: operation_id.to_string(),
            expires_at_unix_seconds,
            target: ConfirmablePlanTargetV1 {
                science_runtime_identity_sha256: target.science_runtime_identity_sha256.clone(),
                data_dir_identity_sha256: target.data_dir_identity_sha256.clone(),
                active_org_identity_sha256: target.active_org_identity_sha256.clone(),
                skills_root_device: target.skills_root_device,
                skills_root_inode: target.skills_root_inode,
            },
        },
        target,
    };
    progress(
        "plan",
        "已固定 archive，正在生成不可变 effects 与确认 capability",
    );
    let prepared = match SkillOperationPrepared::prepare_reserved(
        &staging_root,
        &ledger_root,
        archive.source,
        &archive.bytes,
        request,
    ) {
        Ok(value) => value,
        Err(error) => return operation_error(error),
    };
    let plan = prepared.plan();
    json!({
        "status": "CONFIRMATION_REQUIRED",
        "operation_id": prepared.ledger().operation_id,
        "plan": plan,
        "plan_digest": plan.plan_digest_sha256,
        "capability": prepared.confirmation_capability().raw(),
        "expires_at_unix_seconds": prepared.ledger().expires_at_unix_seconds,
        "effects": plan.effects,
        "directory_commit": false,
        "attach_attempted": false,
        "attach_verified": false,
        "recovery_required": false,
        "message": "请向用户展示 source、effects、expiry 和 degradation；只有用户明确确认完全相同 plan 后，才用原 plan_digest 与 capability 调用 apply。host access 批准不是该确认。",
        "restart_required": false,
    })
}

fn apply_skill_operation_plan(
    data_dir: &Path,
    context: &ScienceHostContext,
    authority_root: &File,
    source_url: &str,
    operation_id: &str,
    plan_digest: &str,
    capability: &str,
    progress: &mut dyn FnMut(&str, &str),
) -> Value {
    let (staging_root, ledger_root) = match operation_roots(authority_root) {
        Ok(value) => value,
        Err(message) => {
            return skill_operation_error("SKILL_OPERATION_ROOT_UNAVAILABLE", "ledger", &message)
        }
    };
    let prepared = match SkillOperationPrepared::resume(&staging_root, &ledger_root, operation_id) {
        Ok(value) => value,
        Err(error) => return operation_error(error),
    };
    if prepared.ledger().source_request_sha256.as_deref() != Some(sha256_text(source_url).as_str())
        || prepared.ledger().plan_digest_sha256 != plan_digest
    {
        return skill_operation_error(
            "SKILL_OPERATION_PLAN_MISMATCH",
            "confirmation",
            "source_url 或 plan_digest 与 durable operation 不匹配；必须重新建立并确认新计划。",
        );
    }
    progress(
        "preflight",
        "正在复核确认后的 runtime、data-dir 与 active-org binding",
    );
    if let Err(error) = verify_attach_control_ready_for_operation(context) {
        return install_not_ready(None, &error.message);
    }
    let target = match target_binding(data_dir, context) {
        Ok(value) => value,
        Err(message) => {
            return skill_operation_error("SKILL_OPERATION_TARGET_INVALID", "preflight", &message)
        }
    };
    let confirmation = SkillOperationConfirmationCapabilityV1::from_raw(
        operation_id.to_string(),
        capability.to_string(),
    );
    let skills_root = match install_operation_skills_root(data_dir, &target.active_org) {
        Ok(root) => root,
        Err(message) => {
            return skill_operation_error(
                "SKILL_OPERATION_SKILLS_ROOT_INVALID",
                "preflight",
                &message,
            )
        }
    };
    let mut operon = GatewaySkillOperationOperonAdapter { context };
    progress(
        "apply",
        "正在从同一 durable archive snapshot 提交并原生回读 OPERON",
    );
    match prepared.apply(data_dir, &skills_root, &confirmation, &target, &mut operon) {
        Ok(receipt) => json!({
            "status": receipt.final_response.status,
            "operation_id": receipt.final_response.operation_id,
            "directory_commit": receipt.final_response.directory_commit,
            "attach_verified": receipt.final_response.attach_verified,
            "recovery_required": receipt.final_response.recovery_required,
            "post_effect_observation": receipt.final_response.post_effect_observation,
            "plan_digest": receipt.ledger.plan_digest_sha256,
            "message": "结果来自 durable operation ledger；attach 成功后仍需当前 Agent session 调用 skill(skill_name) 验证加载。",
            "restart_required": false,
        }),
        Err(error) => operation_error(error),
    }
}

fn reconcile_skill_operation_plan(
    data_dir: &Path,
    context: &ScienceHostContext,
    authority_root: &File,
    operation_id: &str,
) -> Value {
    // A reconcile is readback-only, but its reads are still target-bound: do
    // not inspect a ledger created for a different runtime/data-dir/org.
    let target = match target_binding(data_dir, context) {
        Ok(value) => value,
        Err(message) => {
            return skill_operation_error("SKILL_OPERATION_TARGET_INVALID", "recovery", &message)
        }
    };
    let (staging_root, ledger_root) = match operation_roots(authority_root) {
        Ok(value) => value,
        Err(message) => {
            return skill_operation_error("SKILL_OPERATION_ROOT_UNAVAILABLE", "ledger", &message)
        }
    };
    let mut prepared =
        match SkillOperationPrepared::resume(&staging_root, &ledger_root, operation_id) {
            Ok(value) => value,
            Err(error) => return operation_error(error),
        };
    let skills_root = match install_operation_skills_root(data_dir, &target.active_org) {
        Ok(root) => root,
        Err(message) => {
            return skill_operation_error(
                "SKILL_OPERATION_SKILLS_ROOT_INVALID",
                "recovery",
                &message,
            )
        }
    };
    let mut operon = GatewaySkillOperationOperonAdapter { context };
    let result = if prepared.ledger().effects.first().is_some_and(|effect| {
        effect.intent == csswitch_skill_install_core::SkillOperationEffectIntentV1::InProgress
    }) {
        prepared.reconcile_package_readback(&skills_root, &target)
    } else if prepared.ledger().effects.get(1).is_some_and(|effect| {
        effect.intent == csswitch_skill_install_core::SkillOperationEffectIntentV1::InProgress
    }) {
        prepared.reconcile_attach_readback(&target, &mut operon)
    } else {
        return skill_operation_error(
            "SKILL_OPERATION_RECONCILE_NOT_ADMITTED",
            "recovery",
            "该 operation 没有可读取恢复的 in-progress effect。",
        );
    };
    match result {
        Ok(response) => {
            json!({"status":response.status,"operation_id":response.operation_id,"directory_commit":response.directory_commit,"attach_verified":response.attach_verified,"recovery_required":response.recovery_required,"post_effect_observation":response.post_effect_observation,"message":"reconcile 只做 durable snapshot 和 Science native GET readback，未重放副作用。","restart_required":false})
        }
        Err(error) => operation_error(error),
    }
}

fn continue_skill_operation_plan(
    data_dir: &Path,
    context: &ScienceHostContext,
    authority_root: &File,
    operation_id: &str,
) -> Value {
    let (staging_root, ledger_root) = match operation_roots(authority_root) {
        Ok(value) => value,
        Err(message) => {
            return skill_operation_error("SKILL_OPERATION_ROOT_UNAVAILABLE", "ledger", &message)
        }
    };
    let target = match target_binding(data_dir, context) {
        Ok(value) => value,
        Err(message) => {
            return skill_operation_error("SKILL_OPERATION_TARGET_INVALID", "preflight", &message)
        }
    };
    let prepared = match SkillOperationPrepared::resume(&staging_root, &ledger_root, operation_id) {
        Ok(value) => value,
        Err(error) => return operation_error(error),
    };
    let skills_root = match install_operation_skills_root(data_dir, &target.active_org) {
        Ok(root) => root,
        Err(message) => {
            return skill_operation_error(
                "SKILL_OPERATION_SKILLS_ROOT_INVALID",
                "preflight",
                &message,
            )
        }
    };
    let mut operon = GatewaySkillOperationOperonAdapter { context };
    match prepared.continue_apply(data_dir, &skills_root, &target, &mut operon) {
        Ok(receipt) => json!({
            "status": receipt.final_response.status,
            "operation_id": receipt.final_response.operation_id,
            "directory_commit": receipt.final_response.directory_commit,
            "attach_verified": receipt.final_response.attach_verified,
            "recovery_required": receipt.final_response.recovery_required,
            "post_effect_observation": receipt.final_response.post_effect_observation,
            "message": "continue 仅执行 verified 前缀后的一个尚未开始 effect；不会重放 package commit。",
            "restart_required": false,
        }),
        Err(error) => operation_error(error),
    }
}

fn removal_operation_roots(
    data_dir: &Path,
    active_org: &str,
    authority_root: &File,
) -> Result<SkillRemovalRoots, String> {
    let skills_path = data_dir.join("orgs").join(active_org).join("skills");
    ensure_safe_root(data_dir, &skills_path)?;
    let mut options = OpenOptions::new();
    options.read(true);
    options.custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let skills_root = options
        .open(&skills_path)
        .map_err(|_| "无法安全打开当前组织的 Skills 根".to_string())?;
    let quarantine_root =
        open_private_operation_child(authority_root, "skill-operation-quarantine")?;
    Ok(SkillRemovalRoots {
        skills_root,
        quarantine_root,
    })
}

fn install_operation_skills_root(data_dir: &Path, active_org: &str) -> Result<File, String> {
    let path = data_dir.join("orgs").join(active_org).join("skills");
    ensure_safe_root(data_dir, &path)?;
    let mut options = OpenOptions::new();
    options.read(true);
    options.custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let root = options
        .open(&path)
        .map_err(|_| "无法安全打开当前组织的 Skills 根".to_string())?;
    let metadata = root
        .metadata()
        .map_err(|_| "无法复核当前组织的 Skills 根".to_string())?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err("当前组织的 Skills 根类型非法".into());
    }
    Ok(root)
}

fn create_skill_removal_plan(
    data_dir: &Path,
    context: &ScienceHostContext,
    authority_root: &File,
    operation_id: &str,
    skill_name: &str,
) -> Value {
    if let Err(error) = verify_attach_control_ready_for_operation(context) {
        return skill_operation_error(
            "SKILL_OPERATION_CONTROL_NOT_READY",
            "preflight",
            &format!("确认式卸载前无法确认 Science 控制面：{}", error.message),
        );
    }
    let target = match target_binding(data_dir, context) {
        Ok(value) => value,
        Err(message) => {
            return skill_operation_error("SKILL_OPERATION_TARGET_INVALID", "preflight", &message)
        }
    };
    let roots = match removal_operation_roots(data_dir, &target.active_org, authority_root) {
        Ok(value) => value,
        Err(message) => {
            return skill_operation_error("SKILL_OPERATION_ROOT_UNAVAILABLE", "preflight", &message)
        }
    };
    let (staging_root, ledger_root) = match operation_roots(authority_root) {
        Ok(value) => value,
        Err(message) => {
            return skill_operation_error("SKILL_OPERATION_ROOT_UNAVAILABLE", "ledger", &message)
        }
    };
    let prepared = match SkillOperationRemovalPrepared::prepare(
        &staging_root,
        &ledger_root,
        data_dir,
        &roots,
        operation_id.to_string(),
        unix_seconds().saturating_add(SKILL_OPERATION_PLAN_TTL_SECONDS),
        target,
        skill_name.to_string(),
    ) {
        Ok(value) => value,
        Err(error) => return removal_operation_error(error),
    };
    let plan = prepared.ledger().plan.clone();
    json!({
        "status": "REMOVAL_CONFIRMATION_REQUIRED",
        "operation_id": prepared.ledger().operation_id,
        "plan": plan,
        "plan_digest": prepared.ledger().plan_digest_sha256,
        "capability": prepared.confirmation_capability().raw(),
        "expires_at_unix_seconds": prepared.ledger().expires_at_unix_seconds,
        "effects": prepared.ledger().plan.effects,
        "detach_verified": false,
        "quarantine_commit": false,
        "recovery_required": false,
        "message": "请向用户展示精确 target、detach 与 quarantine effects；只有明确确认同一 plan 后才可 apply。host access 批准不是该确认。",
        "restart_required": false,
    })
}

fn apply_skill_removal_plan(
    data_dir: &Path,
    context: &ScienceHostContext,
    authority_root: &File,
    operation_id: &str,
    plan_digest: &str,
    capability: &str,
) -> Value {
    if let Err(error) = verify_attach_control_ready_for_operation(context) {
        return skill_operation_error(
            "SKILL_OPERATION_CONTROL_NOT_READY",
            "preflight",
            &format!("确认式卸载前无法确认 Science 控制面：{}", error.message),
        );
    }
    let target = match target_binding(data_dir, context) {
        Ok(value) => value,
        Err(message) => {
            return skill_operation_error("SKILL_OPERATION_TARGET_INVALID", "preflight", &message)
        }
    };
    let roots = match removal_operation_roots(data_dir, &target.active_org, authority_root) {
        Ok(value) => value,
        Err(message) => {
            return skill_operation_error("SKILL_OPERATION_ROOT_UNAVAILABLE", "preflight", &message)
        }
    };
    let (_, ledger_root) = match operation_roots(authority_root) {
        Ok(value) => value,
        Err(message) => {
            return skill_operation_error("SKILL_OPERATION_ROOT_UNAVAILABLE", "ledger", &message)
        }
    };
    let prepared = match SkillOperationRemovalPrepared::resume(&ledger_root, operation_id) {
        Ok(value) => value,
        Err(error) => return removal_operation_error(error),
    };
    if prepared.ledger().plan_digest_sha256 != plan_digest {
        return skill_operation_error(
            "SKILL_OPERATION_PLAN_MISMATCH",
            "confirmation",
            "plan_digest 与 durable removal operation 不匹配；必须重新建立并确认计划。",
        );
    }
    let confirmation = SkillOperationConfirmationCapabilityV1::from_raw(
        operation_id.to_string(),
        capability.to_string(),
    );
    let mut operon = GatewaySkillOperationOperonAdapter { context };
    match prepared.apply(data_dir, &roots, &confirmation, &target, &mut operon) {
        Ok(receipt) => json!({
            "status": receipt.final_response.status,
            "operation_id": receipt.final_response.operation_id,
            "detach_verified": receipt.final_response.detach_verified,
            "quarantine_commit": receipt.final_response.quarantine_commit,
            "recovery_required": receipt.final_response.recovery_required,
            "post_effect_observation": receipt.final_response.post_effect_observation,
            "plan_digest": receipt.ledger.plan_digest_sha256,
            "message": "结果来自 durable removal ledger；不确定状态只能读取 reconcile，不能自动重试 detach 或 quarantine。",
            "restart_required": false,
        }),
        Err(error) => removal_operation_error(error),
    }
}

fn reconcile_skill_removal_plan(
    data_dir: &Path,
    context: &ScienceHostContext,
    authority_root: &File,
    operation_id: &str,
) -> Value {
    let target = match target_binding(data_dir, context) {
        Ok(value) => value,
        Err(message) => {
            return skill_operation_error("SKILL_OPERATION_TARGET_INVALID", "preflight", &message)
        }
    };
    let roots = match removal_operation_roots(data_dir, &target.active_org, authority_root) {
        Ok(value) => value,
        Err(message) => {
            return skill_operation_error("SKILL_OPERATION_ROOT_UNAVAILABLE", "preflight", &message)
        }
    };
    let (_, ledger_root) = match operation_roots(authority_root) {
        Ok(value) => value,
        Err(message) => {
            return skill_operation_error("SKILL_OPERATION_ROOT_UNAVAILABLE", "ledger", &message)
        }
    };
    let mut prepared = match SkillOperationRemovalPrepared::resume(&ledger_root, operation_id) {
        Ok(value) => value,
        Err(error) => return removal_operation_error(error),
    };
    let mut operon = GatewaySkillOperationOperonAdapter { context };
    let result = if prepared.ledger().effects.first().is_some_and(|effect| {
        effect.intent == csswitch_skill_install_core::SkillOperationEffectIntentV1::InProgress
    }) {
        prepared.reconcile_detach_readback(&target, &mut operon)
    } else if prepared.ledger().effects.get(1).is_some_and(|effect| {
        effect.intent == csswitch_skill_install_core::SkillOperationEffectIntentV1::InProgress
    }) {
        prepared.reconcile_quarantine_readback(&roots, &target)
    } else {
        return skill_operation_error(
            "SKILL_OPERATION_RECONCILE_NOT_ADMITTED",
            "recovery",
            "该 removal operation 没有可读取恢复的 in-progress effect。",
        );
    };
    match result {
        Ok(response) => {
            json!({"status":response.status,"operation_id":response.operation_id,"detach_verified":response.detach_verified,"quarantine_commit":response.quarantine_commit,"recovery_required":response.recovery_required,"post_effect_observation":response.post_effect_observation,"message":"reconcile 只做 native GET 和 fd-relative readback，未重放 detach 或 quarantine。","restart_required":false})
        }
        Err(error) => removal_operation_error(error),
    }
}

fn continue_skill_removal_plan(
    data_dir: &Path,
    context: &ScienceHostContext,
    authority_root: &File,
    operation_id: &str,
) -> Value {
    let target = match target_binding(data_dir, context) {
        Ok(value) => value,
        Err(message) => {
            return skill_operation_error("SKILL_OPERATION_TARGET_INVALID", "preflight", &message)
        }
    };
    let roots = match removal_operation_roots(data_dir, &target.active_org, authority_root) {
        Ok(value) => value,
        Err(message) => {
            return skill_operation_error("SKILL_OPERATION_ROOT_UNAVAILABLE", "preflight", &message)
        }
    };
    let (_, ledger_root) = match operation_roots(authority_root) {
        Ok(value) => value,
        Err(message) => {
            return skill_operation_error("SKILL_OPERATION_ROOT_UNAVAILABLE", "ledger", &message)
        }
    };
    let prepared = match SkillOperationRemovalPrepared::resume(&ledger_root, operation_id) {
        Ok(value) => value,
        Err(error) => return removal_operation_error(error),
    };
    match prepared.continue_apply(data_dir, &roots, &target) {
        Ok(receipt) => json!({
            "status": receipt.final_response.status,
            "operation_id": receipt.final_response.operation_id,
            "detach_verified": receipt.final_response.detach_verified,
            "quarantine_commit": receipt.final_response.quarantine_commit,
            "recovery_required": receipt.final_response.recovery_required,
            "post_effect_observation": receipt.final_response.post_effect_observation,
            "message": "continue 仅执行 verified detach 后的 quarantine；不会重放 native detach。",
            "restart_required": false,
        }),
        Err(error) => removal_operation_error(error),
    }
}

struct GatewaySkillOperationOperonAdapter<'a> {
    context: &'a ScienceHostContext,
}

impl SkillOperationOperonAdapter for GatewaySkillOperationOperonAdapter<'_> {
    fn attach_and_readback(&mut self, skill: &str, org: &str) -> Result<(), AttachError> {
        match attach_skill(self.context, skill, org)? {
            AttachResult::Attached | AttachResult::AlreadyAttached => Ok(()),
        }
    }

    fn detach_and_readback(&mut self, skill: &str, org: &str) -> Result<(), AttachError> {
        update_agent_skills(self.context, &[], &[skill.to_string()], org).map(|_| ())
    }

    fn readback(&mut self, skill: &str, org: &str) -> Result<bool, AttachError> {
        Ok(read_agent_skill_names(self.context, org)?.contains(skill))
    }
}

fn verify_attach_control_ready_for_operation(
    context: &ScienceHostContext,
) -> Result<(), csswitch_skill_install_core::AttachError> {
    #[cfg(test)]
    if TEST_READY_CONTEXT.with(|slot| slot.borrow().as_ref() == Some(context)) {
        return Ok(());
    }
    verify_attach_control_ready(context)
}

fn install_external_skill(
    data_dir: &Path,
    source_url: &str,
    science_context: &ScienceHostContext,
    progress: &mut dyn FnMut(&str, &str),
) -> Result<Value, InstallError> {
    match resolve_install_package(data_dir, source_url, progress)? {
        InstalledPackage::Skill(commit) => {
            progress("attach", "文件已提交，正在绑定 OPERON 并回读确认");
            Ok(attach_install_commit(science_context, commit))
        }
        InstalledPackage::Bundle(commit) => {
            progress("attach", "bundle 已提交，正在批量绑定 OPERON 并回读确认");
            Ok(attach_bundle_commit(science_context, commit))
        }
    }
}

fn resolve_install_package(
    data_dir: &Path,
    source_url: &str,
    progress: &mut dyn FnMut(&str, &str),
) -> Result<InstalledPackage, InstallError> {
    #[cfg(test)]
    if let Some(archive) = test_local_archive_for(data_dir) {
        let archive_name = archive
            .file_name()
            .and_then(|value| value.to_str())
            .expect("test archive name");
        let mut file = File::open(&archive).expect("test archive must remain readable");
        progress("download", "测试夹具已提供隔离 archive");
        return install_local_package(
            data_dir,
            LocalArchiveInput {
                file: &mut file,
                archive_name,
            },
        );
    }
    install_github_package_with_progress(data_dir, source_url, progress)
}

#[cfg(test)]
thread_local! {
    static TEST_LOCAL_ARCHIVE: std::cell::RefCell<Option<(PathBuf, PathBuf)>> = const {
        std::cell::RefCell::new(None)
    };
    static TEST_READY_CONTEXT: std::cell::RefCell<Option<ScienceHostContext>> = const {
        std::cell::RefCell::new(None)
    };
}

#[cfg(test)]
struct TestLocalArchiveGuard;

#[cfg(test)]
struct TestReadyContextGuard;

#[cfg(test)]
impl Drop for TestLocalArchiveGuard {
    fn drop(&mut self) {
        TEST_LOCAL_ARCHIVE.with(|slot| *slot.borrow_mut() = None);
    }
}

#[cfg(test)]
impl Drop for TestReadyContextGuard {
    fn drop(&mut self) {
        TEST_READY_CONTEXT.with(|slot| *slot.borrow_mut() = None);
    }
}

#[cfg(test)]
fn test_arm_local_archive(data_dir: &Path, archive: PathBuf) -> TestLocalArchiveGuard {
    TEST_LOCAL_ARCHIVE.with(|slot| {
        let previous = slot.borrow_mut().replace((data_dir.to_path_buf(), archive));
        assert!(previous.is_none(), "test archive seam already armed");
    });
    TestLocalArchiveGuard
}

#[cfg(test)]
fn test_arm_ready_context(context: ScienceHostContext) -> TestReadyContextGuard {
    TEST_READY_CONTEXT.with(|slot| {
        let previous = slot.borrow_mut().replace(context);
        assert!(previous.is_none(), "test ready context seam already armed");
    });
    TestReadyContextGuard
}

#[cfg(test)]
fn test_local_archive_for(data_dir: &Path) -> Option<PathBuf> {
    TEST_LOCAL_ARCHIVE.with(|slot| {
        slot.borrow()
            .as_ref()
            .filter(|(expected, _)| expected == data_dir)
            .map(|(_, archive)| archive.clone())
    })
}

fn attach_bundle_commit(context: &ScienceHostContext, commit: BundleCommit) -> Value {
    let attach = update_agent_skills(context, &commit.skill_names, &[], &commit.active_org);
    let (status, message, attach_required, attach_verified) = match attach.as_ref() {
        Ok(_) => (
            "BUNDLE_INSTALLED_ATTACHED",
            format!(
                "bundle 文件已安装，OPERON 已回读确认绑定 {} 个 Skill。",
                commit.skill_names.len()
            ),
            false,
            true,
        ),
        Err(error) if error.uncertain => (
            "ATTACH_STATE_UNCERTAIN",
            format!("bundle 文件已保留，但批量绑定结果不确定：{}", error.message),
            true,
            false,
        ),
        Err(error) => (
            "FILES_COMMITTED_ATTACH_REQUIRED",
            format!("bundle 文件已保留，但自动批量绑定未完成：{}", error.message),
            true,
            false,
        ),
    };
    let attach_error = attach.as_ref().err().cloned();
    let attached_names = attach
        .as_ref()
        .map(|result| result.attached.clone())
        .unwrap_or_default();
    let missing_names = if attach_verified {
        Vec::new()
    } else {
        commit.skill_names.clone()
    };
    let skills = commit
        .members
        .iter()
        .map(|member| {
            json!({
                "skill_name": member.skill_name,
                "content_sha256": member.content_sha256,
                "install_action": member.install_action,
                "attach_verified": attach_verified,
            })
        })
        .collect::<Vec<_>>();
    let content_fetch = !matches!(
        commit.action,
        csswitch_skill_install_core::InstallAction::ReusedVerified
    );
    json!({
        "status": status,
        "package_kind": "bundle",
        "bundle_id": commit.bundle_id,
        "bundle_name": commit.bundle_name,
        "skill_name": commit.skill_names.first(),
        "skill_names": commit.skill_names,
        "support_paths": commit.support_paths,
        "skills": skills,
        "source_kind": commit.source_kind.as_str(),
        "directory_commit": commit.directory_commit,
        "install_action": commit.action.as_str(),
        "attach_attempted": true,
        "attach_required": attach_required,
        "attach_verified": attach_verified,
        "attached_skill_names": attached_names,
        "missing_skill_names": missing_names,
        "load_verification_required": false,
        "content_sha256": commit.bundle_content_sha256,
        "resolved_commit_sha": commit.resolved_commit_sha,
        "source_digest_sha256": commit.source_digest_sha256,
        "dependency_scan": "BEST_EFFORT",
        "agent_name": "OPERON",
        "attach_method": "csswitch_batch_auto_attach",
        "source_resolution": true,
        "content_fetch": content_fetch,
        "science_discovery": if attach_verified { "BATCH_ATTACHED" } else { "FILES_VISIBLE_NOT_ATTACHED" },
        "skill_trigger": "NOT_REQUIRED_FOR_BUNDLE_ACCEPTANCE",
        "function_run": "NOT_VERIFIED",
        "restart_required": false,
        "new_conversation_required": false,
        "import_origin_written": true,
        "attach_error": attach_error,
        "message": message
    })
}

fn attach_install_commit(context: &ScienceHostContext, commit: InstallCommit) -> Value {
    let attach = attach_skill(context, &commit.skill_name, &commit.active_org);
    let (status, message, attach_required, attach_verified) = match attach.as_ref() {
        Ok(AttachResult::Attached | AttachResult::AlreadyAttached) => (
            "INSTALLED_ATTACHED_VERIFY_REQUIRED",
            "Skill 文件已验证并绑定 OPERON。Agent 现在必须调用 skill(skill_name) 验证当前会话加载；验证前不得报告可用。".to_string(),
            false,
            true,
        ),
        Err(error) if error.uncertain => (
            "ATTACH_STATE_UNCERTAIN",
            format!("Skill 文件已保留，但 OPERON 绑定结果不确定：{}", error.message),
            true,
            false,
        ),
        Err(error) => (
            "FILES_COMMITTED_ATTACH_REQUIRED",
            format!("Skill 文件已保留，但自动绑定未完成：{}。请重新调用同一安装工具重试。", error.message),
            true,
            false,
        ),
    };
    let attach_error = attach.err();
    let content_fetch = !matches!(
        commit.action,
        csswitch_skill_install_core::InstallAction::ReusedVerified
    );
    json!({
        "status": status,
        "skill_name": commit.skill_name,
        "source_kind": commit.source_kind.as_str(),
        "directory_commit": commit.directory_commit,
        "install_action": commit.action.as_str(),
        "attach_attempted": true,
        "attach_required": attach_required,
        "attach_verified": attach_verified,
        "load_verification_required": attach_verified,
        "content_sha256": commit.content_sha256,
        "resolved_commit_sha": commit.resolved_commit_sha,
        "source_digest_sha256": commit.source_digest_sha256,
        "dependency_scan": commit.dependency_scan,
        "agent_name": "OPERON",
        "attach_method": "csswitch_auto_attach",
        "source_resolution": true,
        "content_fetch": content_fetch,
        "science_discovery": if attach_verified { "ATTACHED" } else { "FILES_VISIBLE_NOT_ATTACHED" },
        "skill_trigger": "NOT_VERIFIED",
        "function_run": "NOT_VERIFIED",
        "restart_required": false,
        "new_conversation_required": false,
        "import_origin_written": true,
        "attach_error": attach_error,
        "message": message
    })
}

fn install_not_ready(skill_name: Option<&str>, message: &str) -> Value {
    json!({
        "status": "SCIENCE_NOT_READY",
        "skill_name": skill_name,
        "source_kind": "github",
        "directory_commit": false,
        "attach_attempted": false,
        "attach_required": false,
        "attach_verified": false,
        "load_verification_required": false,
        "content_sha256": null,
        "resolved_commit_sha": null,
        "restart_required": false,
        "message": message
    })
}

fn install_error_payload(skill_name: Option<&str>, error: InstallError) -> Value {
    let status = match error.code.as_str() {
        "SKILL_NAME_CONFLICT"
        | "INSTALLED_CONTENT_CHANGED"
        | "UNSUPPORTED_SHARED_DEPENDENCY"
        | "MULTIPLE_BUNDLE_CANDIDATES"
        | "BUNDLE_STRUCTURE_UNSUPPORTED"
        | "BUNDLE_LIMIT_EXCEEDED"
        | "BUNDLE_PATH_CONFLICT"
        | "UNSUPPORTED_PLUGIN_RUNTIME_DEPENDENCY"
        | "SOURCE_REF_REQUIRES_COMMIT_SHA"
        | "LEGACY_INTEGRITY_UNVERIFIED" => error.code.as_str(),
        code if code.starts_with("GITHUB_") => error.code.as_str(),
        "SCIENCE_NOT_READY" => "SCIENCE_NOT_READY",
        _ => "INSTALL_FAILED",
    };
    let user_retry_available = error.retryable;
    let message = format!(
        "{}。本次请求已结束且 bridge 状态已清理；不得自动重试。{}",
        error.message,
        if user_retry_available {
            "如需重试，必须先向用户报告并等待新的明确指令。"
        } else {
            "请向用户报告该最终错误。"
        }
    );
    json!({
        "status": status,
        "skill_name": skill_name,
        "source_kind": "github",
        "directory_commit": error.directory_commit,
        "attach_attempted": false,
        "attach_required": false,
        "attach_verified": false,
        "load_verification_required": false,
        "content_sha256": null,
        "resolved_commit_sha": null,
        "restart_required": false,
        "request_terminal": true,
        "automatic_retry_allowed": false,
        "user_retry_available": user_retry_available,
        "error": error,
        "message": message
    })
}

fn requested_skill_name(arguments: &Value) -> Result<String, String> {
    let name = arguments
        .get("skill_name")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or("请提供要卸载的准确 Skill 名称")?;
    validate_skill_name(name)?;
    Ok(name.to_string())
}

fn requested_bundle_confirmation(arguments: &Value) -> Result<Option<String>, String> {
    let Some(value) = arguments.get("confirm_bundle_id") else {
        return Ok(None);
    };
    let id = value
        .as_str()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or("bundle 确认 ID 非法")?;
    if id.len() != 64
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err("bundle 确认 ID 非法".into());
    }
    Ok(Some(id.to_string()))
}

fn validate_uninstall_arguments(arguments: &Value) -> Result<(String, Option<String>), String> {
    let object = arguments.as_object().ok_or("本地 Skill 卸载参数非法")?;
    if object.keys().any(|key| {
        !matches!(
            key.as_str(),
            "skill_name" | "confirm_bundle_id" | "confirmation"
        )
    }) {
        return Err("本地 Skill 卸载参数非法".into());
    }
    let skill_name = requested_skill_name(arguments)?;
    let confirm_bundle_id = requested_bundle_confirmation(arguments)?;
    Ok((skill_name, confirm_bundle_id))
}

fn validate_skill_name(name: &str) -> Result<(), String> {
    let valid = Regex::new(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$").expect("static regex");
    if !valid.is_match(name) || matches!(name, "." | "..") {
        return Err("Skill 名称非法".into());
    }
    Ok(())
}

fn uninstall_failure(message: String) -> Value {
    json!({
        "status": "UNINSTALL_FAILED",
        "message": message,
        "directory_removed": false,
        "quarantine_commit": false,
        "restart_required": false
    })
}

#[cfg(test)]
pub(crate) fn uninstall_from_arguments(data_dir: &Path, arguments: &Value) -> Value {
    uninstall_from_arguments_with_context_and_bridge(data_dir, None, None, None, None, arguments)
}

fn uninstall_from_arguments_with_context_and_bridge(
    data_dir: &Path,
    science_context: Option<&ScienceHostContext>,
    bridge_dir: Option<&Path>,
    authority_root: Option<&File>,
    request_id: Option<&str>,
    arguments: &Value,
) -> Value {
    if let Ok(Some(confirmation)) = confirmation_request(arguments) {
        if matches!(
            confirmation.action,
            ConfirmationAction::Apply
                | ConfirmationAction::Reconcile
                | ConfirmationAction::Continue
        ) {
            let Some(object) = arguments.as_object() else {
                return uninstall_failure("本地 Skill 卸载参数非法".into());
            };
            if object.keys().any(|key| key != "confirmation") {
                return skill_operation_error(
                    "SKILL_OPERATION_CONFIRMATION_INVALID",
                    "confirmation",
                    "removal apply/reconcile/continue 只能携带 operation authority，不能携带 skill_name 或其他解绑目标",
                );
            }
            let Some(context) = science_context else {
                return uninstall_failure(
                    "确认式卸载需要 CSSwitch 已确认的 Science runtime；文件和绑定尚未改动".into(),
                );
            };
            let Some(_bridge_dir) = bridge_dir else {
                return skill_operation_error(
                    "SKILL_OPERATION_BRIDGE_UNAVAILABLE",
                    "confirmation",
                    "确认式卸载只能由已验证的 CSSwitch bridge 宿主执行",
                );
            };
            let Some(authority_root) = authority_root else {
                return skill_operation_error(
                    "SKILL_OPERATION_AUTHORITY_UNAVAILABLE",
                    "confirmation",
                    "确认式卸载必须持有已验证的 host-only authority root",
                );
            };
            return match confirmation.action {
                ConfirmationAction::Apply => apply_skill_removal_plan(
                    data_dir,
                    context,
                    authority_root,
                    confirmation.operation_id.as_deref().unwrap_or_default(),
                    confirmation.plan_digest.as_deref().unwrap_or_default(),
                    confirmation.capability.as_deref().unwrap_or_default(),
                ),
                ConfirmationAction::Reconcile => reconcile_skill_removal_plan(
                    data_dir,
                    context,
                    authority_root,
                    confirmation.operation_id.as_deref().unwrap_or_default(),
                ),
                ConfirmationAction::Continue => continue_skill_removal_plan(
                    data_dir,
                    context,
                    authority_root,
                    confirmation.operation_id.as_deref().unwrap_or_default(),
                ),
                ConfirmationAction::Plan => unreachable!(),
            };
        }
    }
    let (skill_name, confirm_bundle_id) = match validate_uninstall_arguments(arguments) {
        Ok(values) => values,
        Err(message) => return uninstall_failure(message),
    };
    match confirmation_request(arguments) {
        Ok(Some(confirmation)) => {
            let Some(context) = science_context else {
                return uninstall_failure(
                    "确认式卸载需要 CSSwitch 已确认的 Science runtime；文件和绑定尚未改动".into(),
                );
            };
            let Some(_bridge_dir) = bridge_dir else {
                return skill_operation_error(
                    "SKILL_OPERATION_BRIDGE_UNAVAILABLE",
                    "confirmation",
                    "确认式卸载只能由已验证的 CSSwitch bridge 宿主执行",
                );
            };
            let Some(authority_root) = authority_root else {
                return skill_operation_error(
                    "SKILL_OPERATION_AUTHORITY_UNAVAILABLE",
                    "confirmation",
                    "确认式卸载必须持有已验证的 host-only authority root",
                );
            };
            if confirm_bundle_id.is_some()
                || find_bundle_for_skill(data_dir, &skill_name)
                    .ok()
                    .flatten()
                    .is_some()
            {
                return skill_operation_error(
                    "SKILL_OPERATION_BUNDLE_UNSUPPORTED",
                    "preflight",
                    "bundle 只能使用原整包确认卸载合同，不进入单 Skill 精确计划。",
                );
            }
            return match confirmation.action {
                ConfirmationAction::Plan => match request_id {
                    Some(operation_id) => create_skill_removal_plan(
                        data_dir,
                        context,
                        authority_root,
                        operation_id,
                        &skill_name,
                    ),
                    None => skill_operation_error(
                        "SKILL_OPERATION_REQUEST_ID_REQUIRED",
                        "confirmation",
                        "确认式卸载缺少宿主分配的 operation identity",
                    ),
                },
                ConfirmationAction::Apply => apply_skill_removal_plan(
                    data_dir,
                    context,
                    authority_root,
                    confirmation.operation_id.as_deref().unwrap_or_default(),
                    confirmation.plan_digest.as_deref().unwrap_or_default(),
                    confirmation.capability.as_deref().unwrap_or_default(),
                ),
                ConfirmationAction::Reconcile => reconcile_skill_removal_plan(
                    data_dir,
                    context,
                    authority_root,
                    confirmation.operation_id.as_deref().unwrap_or_default(),
                ),
                ConfirmationAction::Continue => unreachable!(),
            };
        }
        Ok(None) => {}
        Err(message) => {
            return skill_operation_error(
                "SKILL_OPERATION_CONFIRMATION_INVALID",
                "confirmation",
                &message,
            )
        }
    }
    match uninstall_external_skill(
        data_dir,
        science_context,
        &skill_name,
        confirm_bundle_id.as_deref(),
    ) {
        Ok(value) => value,
        Err(message) => uninstall_failure(message),
    }
}

fn bundle_uninstall_confirmation(
    bundle: &csswitch_skill_install_core::BundleUninstall,
    skill_name: &str,
    confirmation_changed: bool,
) -> Value {
    let message = if confirmation_changed {
        "bundle 归属或确认 ID 已变化；文件和绑定尚未改动。请向用户重新展示当前整包成员，并等待新的明确确认。"
    } else {
        "该 Skill 属于 bundle；文件和绑定尚未改动。请向用户展示完整受影响 Skill 列表，并确认是否整包卸载。取消时不要再次调用卸载工具。"
    };
    json!({
        "status": "BUNDLE_UNINSTALL_CONFIRMATION_REQUIRED",
        "package_kind": "bundle",
        "bundle_id": bundle.bundle_id,
        "confirm_bundle_id": bundle.bundle_id,
        "bundle_name": bundle.bundle_name,
        "skill_name": skill_name,
        "skill_names": bundle.skill_names,
        "affected_skill_names": bundle.skill_names,
        "confirmation_required": true,
        "confirmation_scope": "whole_bundle",
        "partial_uninstall_supported": false,
        "detach_required": false,
        "detach_attempted": false,
        "detach_verified": false,
        "directory_removed": false,
        "quarantine_commit": false,
        "restart_required": false,
        "request_terminal": true,
        "automatic_retry_allowed": false,
        "message": message
    })
}

fn uninstall_external_skill(
    data_dir: &Path,
    science_context: Option<&ScienceHostContext>,
    skill_name: &str,
    confirm_bundle_id: Option<&str>,
) -> Result<Value, String> {
    validate_skill_name(skill_name)?;
    if let Some(bundle) = find_bundle_for_skill(data_dir, skill_name).map_err(|e| e.to_string())? {
        if confirm_bundle_id != Some(bundle.bundle_id.as_str()) {
            return Ok(bundle_uninstall_confirmation(
                &bundle,
                skill_name,
                confirm_bundle_id.is_some(),
            ));
        }
        let context = science_context
            .ok_or("bundle 卸载需要 CSSwitch 已确认的 Science runtime；文件尚未改动")?;
        update_agent_skills(context, &[], &bundle.skill_names, &bundle.active_org).map_err(
            |error| format!("bundle 批量 detach 未确认，文件尚未改动：{}", error.message),
        )?;
        let commit = match quarantine_bundle(data_dir, &bundle) {
            Ok(commit) => commit,
            Err(error) => {
                return match update_agent_skills(
                    context,
                    &bundle.skill_names,
                    &[],
                    &bundle.active_org,
                ) {
                    Ok(_) => Err(format!(
                        "bundle 整包隔离失败，已恢复 OPERON 绑定：{}",
                        error.message
                    )),
                    Err(restore_error) => Err(format!(
                        "bundle 整包隔离失败，且 OPERON 绑定恢复未确认：{}；{}",
                        error.message, restore_error.message
                    )),
                };
            }
        };
        return Ok(json!({
            "status": "BUNDLE_UNINSTALLED_DETACHED",
            "package_kind": "bundle",
            "bundle_id": commit.bundle_id,
            "bundle_name": commit.bundle_name,
            "skill_name": skill_name,
            "skill_names": commit.skill_names,
            "agent_name": "OPERON",
            "detach_required": false,
            "detach_verified": true,
            "detach_method": "csswitch_batch_auto_detach",
            "directory_removed": true,
            "quarantine_commit": true,
            "quarantine_path": commit.quarantined_path,
            "restart_required": false,
            "message": "bundle 已整包解除 OPERON 绑定并移入 CSSwitch 隔离回收区。"
        }));
    }
    if confirm_bundle_id.is_some() {
        return Err("确认的 bundle 已不存在，或该 Skill 的 bundle 归属已改变；文件尚未改动".into());
    }
    let active_org = read_active_org(data_dir)?;
    let skills_root = data_dir.join("orgs").join(&active_org).join("skills");
    ensure_safe_root(data_dir, &skills_root)?;
    let target = skills_root.join(skill_name);
    reject_symlink_path(&target)?;
    let metadata = fs::metadata(&target).map_err(|error| match error.kind() {
        io::ErrorKind::NotFound => format!("Skill '{skill_name}' 不存在"),
        _ => format!("读取 Skill '{skill_name}' 失败：{error}"),
    })?;
    if !metadata.is_dir() {
        return Err(format!("Skill '{skill_name}' 不是目录，拒绝操作"));
    }
    verify_csswitch_import_origin(&target, skill_name)?;

    let lock_path = skills_root.join(format!(".csswitch-install-{skill_name}.lock"));
    let lock = acquire_lock(&lock_path)?;
    // Recheck the target and its marker while holding the same per-name lock used
    // by installation, so an install/uninstall pair cannot cross in flight.
    reject_symlink_path(&target)?;
    verify_csswitch_import_origin(&target, skill_name)?;

    let trash_root = skill_trash_root(data_dir)?;
    prepare_trash_root(data_dir, &trash_root)?;
    let quarantine_name = format!(
        "{skill_name}-{}-{}-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        std::process::id(),
        unique_suffix()
    );
    let quarantine = trash_root.join(&quarantine_name);
    rename_no_replace(&target, &quarantine)?;
    drop(lock);
    let sync_warning = sync_directory(&skills_root)
        .and_then(|_| sync_directory(&trash_root))
        .err();
    Ok(json!({
        "status": "QUARANTINED_DETACH_REQUIRED",
        "skill_name": skill_name,
        "agent_name": "OPERON",
        "detach_required": true,
        "detach_method": "host.agents.detach_skill",
        "directory_removed": true,
        "quarantine_commit": true,
        "quarantine_name": quarantine_name,
        "durability_sync": sync_warning.is_none(),
        "warning": sync_warning,
        "restart_required": false,
        "new_conversation_recommended": false,
        "message": "Skill 目录已从当前组织移入 CSSwitch 本地隔离回收区，但 Agent 绑定尚未解除。现在必须调用 host.agents.detach_skill('OPERON', skill_name)，随后验证 skill(skill_name) 不再可加载；完成前不要向用户报告卸载成功。"
    }))
}

fn verify_csswitch_import_origin(skill_dir: &Path, skill_name: &str) -> Result<Value, String> {
    let marker_path = skill_dir.join(IMPORT_ORIGIN_FILE);
    reject_symlink_path(&marker_path)?;
    let metadata = fs::metadata(&marker_path).map_err(|error| match error.kind() {
        io::ErrorKind::NotFound => format!(
            "Skill '{skill_name}' 没有 CSSwitch 导入来源标记；拒绝删除手工、内置或其他来源 Skill"
        ),
        _ => format!("读取 Skill 导入来源失败：{error}"),
    })?;
    if !metadata.is_file() || metadata.len() as usize > MAX_IMPORT_ORIGIN_BYTES {
        return Err("Skill 导入来源标记不是受支持的小型普通文件".into());
    }
    let body = fs::read(&marker_path).map_err(|e| format!("读取 Skill 导入来源失败：{e}"))?;
    let marker: Value = serde_json::from_slice(&body)
        .map_err(|_| "Skill 导入来源标记非法；拒绝删除".to_string())?;
    let repo = marker.get("repo").and_then(Value::as_str).unwrap_or("");
    let sha = marker.get("sha").and_then(Value::as_str).unwrap_or("");
    let plugin = marker.get("plugin").and_then(Value::as_str).unwrap_or("");
    let marketplace = marker
        .get("marketplace")
        .and_then(Value::as_str)
        .unwrap_or("");
    let path = marker.get("path").and_then(Value::as_str).unwrap_or("");
    let imported_at = marker
        .get("importedAt")
        .and_then(Value::as_str)
        .unwrap_or("");
    let license = marker.get("license").and_then(Value::as_str).unwrap_or("");
    let repo_valid = repo.split_once('/').is_some_and(|(owner, name)| {
        !owner.is_empty()
            && owner.len() <= 100
            && !matches!(owner, "." | "..")
            && !name.is_empty()
            && name.len() <= 100
            && !matches!(name, "." | "..")
            && owner
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte))
            && name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte))
            && !name.contains('/')
    });
    let valid = marker.get("version").and_then(Value::as_u64) == Some(1)
        && repo_valid
        && sha.len() == 40
        && sha
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        && plugin == skill_name
        && marketplace == CSSWITCH_MARKETPLACE
        && !path.is_empty()
        && path.len() <= 500
        && path.split('/').all(safe_component)
        && !imported_at.is_empty()
        && imported_at.len() <= 100
        && !license.is_empty()
        && license.len() <= 100;
    if !valid {
        return Err(format!(
            "Skill '{skill_name}' 不是可验证的 CSSwitch 本地导入；拒绝删除"
        ));
    }
    Ok(marker)
}

fn skill_trash_root(data_dir: &Path) -> Result<PathBuf, String> {
    if data_dir.file_name().and_then(|part| part.to_str()) != Some(".claude-science") {
        return Err("Science data-dir 不是 CSSwitch 管理的标准路径；拒绝卸载".into());
    }
    let home = data_dir
        .parent()
        .ok_or("Science data-dir 缺少 HOME 父目录")?;
    if home.file_name().and_then(|part| part.to_str()) != Some("home") {
        return Err("Science data-dir 不在 CSSwitch sandbox/home 下；拒绝卸载".into());
    }
    let sandbox = home
        .parent()
        .ok_or("Science data-dir 缺少 sandbox 父目录")?;
    Ok(sandbox.join("skill-trash"))
}

fn prepare_trash_root(data_dir: &Path, trash_root: &Path) -> Result<(), String> {
    let sandbox = data_dir
        .parent()
        .and_then(Path::parent)
        .ok_or("Science data-dir 缺少 sandbox 父目录")?;
    if trash_root.parent() != Some(sandbox) {
        return Err("Skill 隔离回收目录越界".into());
    }
    reject_symlink_path(sandbox)?;
    reject_symlink_path(trash_root)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        if !trash_root.exists() {
            let mut builder = fs::DirBuilder::new();
            builder.mode(0o700);
            builder
                .create(trash_root)
                .map_err(|e| format!("创建 Skill 隔离回收目录失败：{e}"))?;
        }
        fs::set_permissions(trash_root, fs::Permissions::from_mode(0o700))
            .map_err(|e| format!("设置 Skill 隔离回收目录权限失败：{e}"))?;
    }
    #[cfg(not(unix))]
    fs::create_dir_all(trash_root).map_err(|e| format!("创建 Skill 隔离回收目录失败：{e}"))?;
    reject_symlink_path(trash_root)?;
    Ok(())
}

fn safe_component(value: &str) -> bool {
    !value.is_empty()
        && value != "."
        && value != ".."
        && !value.contains('/')
        && !value.contains('\\')
        && !value.contains('\0')
}

fn read_active_org(data_dir: &Path) -> Result<String, String> {
    if !data_dir.is_absolute() {
        return Err("Science data-dir 必须是绝对路径".into());
    }
    reject_symlink_path(data_dir)?;
    let active = data_dir.join("active-org.json");
    reject_symlink_path(&active)?;
    let body = fs::read(&active).map_err(|_| "读取 Science active-org.json 失败")?;
    let value: Value = serde_json::from_slice(&body).map_err(|_| "Science active-org.json 非法")?;
    let org = value
        .get("org_uuid")
        .and_then(Value::as_str)
        .ok_or("active-org.json 缺少 org_uuid")?;
    let valid = Regex::new(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$").expect("static regex");
    if !valid.is_match(org) {
        return Err("active org 标识非法".into());
    }
    Ok(org.to_string())
}

fn ensure_safe_root(data_dir: &Path, skills_root: &Path) -> Result<(), String> {
    let orgs = data_dir.join("orgs");
    if skills_root.strip_prefix(&orgs).is_err() {
        return Err("Skills 目标目录越界".into());
    }
    reject_symlink_path(data_dir)?;
    if orgs.exists() {
        reject_symlink_path(&orgs)?;
    }
    // Check the full intended path before create_dir_all so an existing org/skills
    // symlink cannot cause even a temporary write outside this Science data-dir.
    reject_symlink_path(skills_root)?;
    Ok(())
}

fn reject_symlink_path(path: &Path) -> Result<(), String> {
    let mut current = PathBuf::new();
    for part in path.components() {
        current.push(part.as_os_str());
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err("路径包含符号链接，拒绝操作".into())
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(format!("检查路径失败：{error}")),
        }
    }
    Ok(())
}

fn acquire_lock(path: &Path) -> Result<InstallLock, String> {
    reject_symlink_path(path)?;
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let file = options
        .open(path)
        .map_err(|_| "同名 Skill 正在安装，或存在残留安装锁")?;
    #[cfg(unix)]
    fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(0o600))
        .map_err(|_| "无法收紧 Skill 安装锁权限")?;
    file.try_lock().map_err(|_| "同名 Skill 正在安装")?;
    Ok(InstallLock { _file: file })
}

fn unique_suffix() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
}

fn sync_directory(path: &Path) -> Result<(), String> {
    File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(|e| format!("同步目录失败：{e}"))
}

#[cfg(target_os = "macos")]
fn rename_no_replace(source: &Path, target: &Path) -> Result<(), String> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    extern "C" {
        fn renameatx_np(fromfd: i32, from: *const i8, tofd: i32, to: *const i8, flags: u32) -> i32;
    }
    const AT_FDCWD: i32 = -2;
    const RENAME_EXCL: u32 = 0x0000_0004;
    let from = CString::new(source.as_os_str().as_bytes()).map_err(|_| "临时路径非法")?;
    let to = CString::new(target.as_os_str().as_bytes()).map_err(|_| "目标路径非法")?;
    let result =
        unsafe { renameatx_np(AT_FDCWD, from.as_ptr(), AT_FDCWD, to.as_ptr(), RENAME_EXCL) };
    if result == 0 {
        Ok(())
    } else {
        Err(format!(
            "原子提交 Skill 失败：{}",
            io::Error::last_os_error()
        ))
    }
}

#[cfg(target_os = "linux")]
fn rename_no_replace(source: &Path, target: &Path) -> Result<(), String> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    extern "C" {
        fn renameat2(
            olddirfd: i32,
            oldpath: *const i8,
            newdirfd: i32,
            newpath: *const i8,
            flags: u32,
        ) -> i32;
    }
    const AT_FDCWD: i32 = -100;
    const RENAME_NOREPLACE: u32 = 1;
    let from = CString::new(source.as_os_str().as_bytes()).map_err(|_| "临时路径非法")?;
    let to = CString::new(target.as_os_str().as_bytes()).map_err(|_| "目标路径非法")?;
    let result = unsafe {
        renameat2(
            AT_FDCWD,
            from.as_ptr(),
            AT_FDCWD,
            to.as_ptr(),
            RENAME_NOREPLACE,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(format!(
            "原子提交 Skill 失败：{}",
            io::Error::last_os_error()
        ))
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn rename_no_replace(source: &Path, target: &Path) -> Result<(), String> {
    if target.exists() {
        return Err("Skill 已存在；拒绝覆盖".into());
    }
    fs::rename(source, target).map_err(|e| format!("提交 Skill 失败：{e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::OpenOptionsExt;
    use std::process::Stdio;
    use std::sync::atomic::{AtomicU64, Ordering};

    const TEST_BRIDGE_TOKEN: &str =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    static TEST_TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    fn mcp_request(bridge: &Path, tool_mode: ToolMode, request: &Value) -> Option<Value> {
        handle_mcp_request(bridge, TEST_BRIDGE_TOKEN, tool_mode, request)
    }

    fn temp_dir(label: &str) -> PathBuf {
        let path = PathBuf::from("/private/tmp").join(format!(
            "csswitch-{label}-{}-{}",
            std::process::id(),
            format!(
                "{}-{}",
                unique_suffix(),
                TEST_TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
            )
        ));
        fs::create_dir_all(&path).unwrap();
        path
    }

    fn standard_data_dir(label: &str) -> (PathBuf, PathBuf) {
        let root = temp_dir(label);
        let data = root.join("sandbox/home/.claude-science");
        fs::create_dir_all(data.join("orgs/org-test/skills")).unwrap();
        fs::write(data.join("active-org.json"), br#"{"org_uuid":"org-test"}"#).unwrap();
        (root, data)
    }

    #[test]
    fn confirmation_schema_is_strict_and_apply_requires_returned_operation_identity() {
        assert!(confirmation_request(&json!({
            "confirmation": {"schema_version": 1, "action": "plan"}
        }))
        .unwrap()
        .is_some());
        assert!(confirmation_request(&json!({
            "confirmation": {"schema_version": 1, "action": "plan", "capability": "x"}
        }))
        .is_err());
        assert!(confirmation_request(&json!({
            "confirmation": {"schema_version": 1, "action": "apply", "plan_digest": "a".repeat(64), "capability": "b".repeat(64)}
        }))
        .is_err());
        let confirmed = confirmation_request(&json!({
            "confirmation": {
                "schema_version": 1,
                "action": "apply",
                "operation_id": "a1b2c3",
                "plan_digest": "a".repeat(64),
                "capability": "b".repeat(64)
            }
        }))
        .unwrap()
        .unwrap();
        assert_eq!(confirmed.operation_id.as_deref(), Some("a1b2c3"));
    }

    #[test]
    fn skill_operation_results_preserve_confirmation_as_normal_and_failures_as_errors() {
        assert_eq!(
            tool_result(json!({"status": "CONFIRMATION_REQUIRED"}))["isError"],
            false
        );
        assert_eq!(
            tool_result(json!({"status": "SKILL_OPERATION_PLAN_MISMATCH"}))["isError"],
            true
        );
    }

    #[test]
    fn operation_roots_require_verified_authority_fd_and_are_fd_opened() {
        let root = temp_dir("skill-operation-root");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let authority = File::open(&root).unwrap();
        let (staging, ledger) = operation_roots(&authority).unwrap();
        assert!(staging.metadata().unwrap().is_dir());
        assert!(ledger.metadata().unwrap().is_dir());
        assert_eq!(
            staging.metadata().unwrap().permissions().mode() & 0o7777,
            0o700
        );
        assert_eq!(
            ledger.metadata().unwrap().permissions().mode() & 0o7777,
            0o700
        );
        fs::remove_dir_all(root).unwrap();
    }

    fn test_authority_fence(root: &Path) -> (File, AuthorityFenceDescriptor) {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
        fs::create_dir_all(root).unwrap();
        fs::set_permissions(root, fs::Permissions::from_mode(0o700)).unwrap();
        let path = root.join(".runtime-compensation.auth.lock");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .unwrap();
        let metadata = file.metadata().unwrap();
        let directory = File::open(root).unwrap();
        let directory_metadata = directory.metadata().unwrap();
        (
            file,
            AuthorityFenceDescriptor::test_only(
                directory,
                directory_metadata.dev(),
                directory_metadata.ino(),
                metadata.dev(),
                metadata.ino(),
            ),
        )
    }

    struct AuthorityFenceAfterLockGuard;

    impl Drop for AuthorityFenceAfterLockGuard {
        fn drop(&mut self) {
            *AUTHORITY_FENCE_AFTER_LOCK_SEAM
                .lock()
                .unwrap_or_else(|error| error.into_inner()) = None;
        }
    }

    fn arm_authority_fence_after_lock(
        entered: PathBuf,
        release: PathBuf,
    ) -> AuthorityFenceAfterLockGuard {
        *AUTHORITY_FENCE_AFTER_LOCK_SEAM
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = Some((entered, release));
        AuthorityFenceAfterLockGuard
    }

    #[test]
    fn authority_fence_rejects_closed_and_replaced_descriptor() {
        let root = temp_dir("authority-fence-invalid");
        let (closed, descriptor) = test_authority_fence(&root);
        drop(closed);
        fs::remove_file(root.join(".runtime-compensation.auth.lock")).unwrap();
        assert!(descriptor.acquire_shared().is_err());

        let replacement_root = root.join("replacement");
        let (original, descriptor) = test_authority_fence(&replacement_root);
        fs::remove_file(replacement_root.join(".runtime-compensation.auth.lock")).unwrap();
        let (replacement, _) = test_authority_fence(&root.join("other"));
        fs::hard_link(
            root.join("other/.runtime-compensation.auth.lock"),
            replacement_root.join(".runtime-compensation.auth.lock"),
        )
        .unwrap();
        assert!(descriptor.acquire_shared().is_err());
        drop(original);
        drop(replacement);
    }

    #[test]
    fn authority_fence_rejects_rename_away_and_recreated_entry_after_sh_lock() {
        let root = temp_dir("authority-fence-rebind-after-lock");
        let (frozen, descriptor) = test_authority_fence(&root);
        let entered = root.join("after-lock-entered");
        let release = root.join("after-lock-release");
        let _seam = arm_authority_fence_after_lock(entered.clone(), release.clone());
        let worker = std::thread::spawn(move || descriptor.acquire_shared());
        wait_for_authority_fence_test_path(&entered).unwrap();
        let lock = root.join(".runtime-compensation.auth.lock");
        fs::rename(&lock, root.join("frozen-a-renamed-away")).unwrap();
        let recreated = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&lock)
            .unwrap();
        fs::write(&release, b"continue").unwrap();
        assert!(
            worker.join().unwrap().is_err(),
            "a name rebound after SH on frozen A must not be accepted as the shared fence"
        );
        drop(recreated);
        drop(frozen);
    }

    #[test]
    fn authority_fence_child() {
        if let Some(marker) = std::env::var_os("CSSWITCH_TEST_AUTHORITY_FENCE_LEAK_MARKER") {
            let raw_fd = std::env::var("CSSWITCH_AUTHORITY_FENCE_FD")
                .unwrap()
                .parse::<i32>()
                .unwrap();
            let _descriptor = AuthorityFenceDescriptor::from_env(TEST_BRIDGE_TOKEN).unwrap();
            let output = std::process::Command::new("/bin/sh")
                .arg("-c")
                .arg(format!("test ! -e /dev/fd/{raw_fd}"))
                .output()
                .unwrap();
            assert!(output.status.success(), "authority dirfd leaked to child");
            fs::write(marker, b"no-leak").unwrap();
            return;
        }
        if let Some(marker) = std::env::var_os("CSSWITCH_TEST_AUTHORITY_FENCE_EX_MARKER") {
            let descriptor = AuthorityFenceDescriptor::from_env(TEST_BRIDGE_TOKEN).unwrap();
            if let Some(about) = std::env::var_os("CSSWITCH_TEST_AUTHORITY_FENCE_ABOUT_TO_FLOCK") {
                fs::write(about, b"about-to-flock").unwrap();
            }
            let name = std::ffi::CString::new(".runtime-compensation.auth.lock").unwrap();
            let fd = unsafe {
                libc::openat(
                    descriptor.directory.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDWR | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            assert!(fd >= 0);
            let file = unsafe { File::from_raw_fd(fd) };
            assert_eq!(unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) }, 0);
            fs::write(marker, b"entered").unwrap();
            return;
        }
        let Some(marker) = std::env::var_os("CSSWITCH_TEST_AUTHORITY_FENCE_CHILD_MARKER") else {
            return;
        };
        let descriptor = AuthorityFenceDescriptor::from_env(TEST_BRIDGE_TOKEN).unwrap();
        if let Some(about) = std::env::var_os("CSSWITCH_TEST_AUTHORITY_FENCE_ABOUT_TO_FLOCK") {
            fs::write(about, b"about-to-flock").unwrap();
        }
        let _guard = descriptor.acquire_shared().unwrap();
        fs::write(marker, b"entered").unwrap();
    }

    #[test]
    fn authority_fence_shared_waits_for_ex_and_releases_after_guard_drop() {
        let root = temp_dir("authority-fence-blocking");
        let (_fence, descriptor) = test_authority_fence(&root);
        let fd = descriptor.directory.as_raw_fd();
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        assert!(flags >= 0);
        assert_eq!(
            unsafe { libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) },
            0
        );
        let ex_owner = OpenOptions::new()
            .read(true)
            .write(true)
            .open(root.join(".runtime-compensation.auth.lock"))
            .unwrap();
        assert_eq!(
            unsafe { libc::flock(std::os::fd::AsRawFd::as_raw_fd(&ex_owner), libc::LOCK_EX) },
            0
        );
        let marker = root.join("child-entered");
        let about = root.join("child-about-to-flock");
        let contender = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "skill_install::tests::authority_fence_child",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("CSSWITCH_TEST_AUTHORITY_FENCE_CHILD_MARKER", &marker)
            .env("CSSWITCH_TEST_AUTHORITY_FENCE_ABOUT_TO_FLOCK", &about)
            .env("CSSWITCH_AUTHORITY_FENCE_FD", fd.to_string())
            .env(
                "CSSWITCH_AUTHORITY_FENCE_DIRECTORY_DEVICE",
                descriptor.directory_device.to_string(),
            )
            .env(
                "CSSWITCH_AUTHORITY_FENCE_DIRECTORY_INODE",
                descriptor.directory_inode.to_string(),
            )
            .env(
                "CSSWITCH_AUTHORITY_FENCE_LOCK_DEVICE",
                descriptor.lock_device.to_string(),
            )
            .env(
                "CSSWITCH_AUTHORITY_FENCE_LOCK_INODE",
                descriptor.lock_inode.to_string(),
            )
            .env(
                "CSSWITCH_AUTHORITY_FENCE_NONCE",
                authority_fence_test_binding(),
            )
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        wait_for_authority_fence_test_path(&about).unwrap();
        assert!(
            !marker.exists(),
            "inherited Skill authority writer must wait for the EX owner"
        );
        assert_eq!(
            unsafe { libc::flock(std::os::fd::AsRawFd::as_raw_fd(&ex_owner), libc::LOCK_UN,) },
            0
        );
        let output = contender.wait_with_output().unwrap();
        assert!(output.status.success());
        assert!(marker.is_file());
    }

    #[test]
    fn two_skill_mutations_keep_excluded_owner_blocked_until_both_finish() {
        let root = temp_dir("authority-fence-two-writers");
        let (_fence, descriptor) = test_authority_fence(&root);
        let descriptor = std::sync::Arc::new(descriptor);
        let first = descriptor.acquire_shared().unwrap();
        let (second_entered_tx, second_entered_rx) = std::sync::mpsc::channel();
        let (release_second_tx, release_second_rx) = std::sync::mpsc::channel();
        let second_descriptor = std::sync::Arc::clone(&descriptor);
        let second = std::thread::spawn(move || {
            let _second = second_descriptor.acquire_shared().unwrap();
            second_entered_tx.send(()).unwrap();
            release_second_rx.recv().unwrap();
        });
        second_entered_rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap();
        let fd = descriptor.directory.as_raw_fd();
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        assert!(flags >= 0);
        assert_eq!(
            unsafe { libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) },
            0
        );
        drop(first);
        let marker = root.join("ex-entered");
        let about = root.join("ex-about-to-flock");
        let contender = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "skill_install::tests::authority_fence_child",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("CSSWITCH_TEST_AUTHORITY_FENCE_EX_MARKER", &marker)
            .env("CSSWITCH_TEST_AUTHORITY_FENCE_ABOUT_TO_FLOCK", &about)
            .env("CSSWITCH_AUTHORITY_FENCE_FD", fd.to_string())
            .env(
                "CSSWITCH_AUTHORITY_FENCE_DIRECTORY_DEVICE",
                descriptor.directory_device.to_string(),
            )
            .env(
                "CSSWITCH_AUTHORITY_FENCE_DIRECTORY_INODE",
                descriptor.directory_inode.to_string(),
            )
            .env(
                "CSSWITCH_AUTHORITY_FENCE_LOCK_DEVICE",
                descriptor.lock_device.to_string(),
            )
            .env(
                "CSSWITCH_AUTHORITY_FENCE_LOCK_INODE",
                descriptor.lock_inode.to_string(),
            )
            .env(
                "CSSWITCH_AUTHORITY_FENCE_NONCE",
                authority_fence_test_binding(),
            )
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        wait_for_authority_fence_test_path(&about).unwrap();
        assert!(
            !marker.exists(),
            "dropping one mutation guard must not unlock the other mutation's SH"
        );
        release_second_tx.send(()).unwrap();
        second.join().unwrap();
        assert!(contender.wait_with_output().unwrap().status.success());
        assert!(marker.is_file());
    }

    #[test]
    fn gateway_closes_inherited_authority_dirfd_before_spawned_children() {
        let root = temp_dir("authority-fence-no-child-leak");
        let (_fence, descriptor) = test_authority_fence(&root);
        let fd = descriptor.directory.as_raw_fd();
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        assert!(flags >= 0);
        assert_eq!(
            unsafe { libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) },
            0
        );
        let marker = root.join("no-child-leak");
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "skill_install::tests::authority_fence_child",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("CSSWITCH_TEST_AUTHORITY_FENCE_LEAK_MARKER", &marker)
            .env("CSSWITCH_AUTHORITY_FENCE_FD", fd.to_string())
            .env(
                "CSSWITCH_AUTHORITY_FENCE_DIRECTORY_DEVICE",
                descriptor.directory_device.to_string(),
            )
            .env(
                "CSSWITCH_AUTHORITY_FENCE_DIRECTORY_INODE",
                descriptor.directory_inode.to_string(),
            )
            .env(
                "CSSWITCH_AUTHORITY_FENCE_LOCK_DEVICE",
                descriptor.lock_device.to_string(),
            )
            .env(
                "CSSWITCH_AUTHORITY_FENCE_LOCK_INODE",
                descriptor.lock_inode.to_string(),
            )
            .env(
                "CSSWITCH_AUTHORITY_FENCE_NONCE",
                authority_fence_test_binding(),
            )
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .unwrap();
        assert!(output.status.success());
        assert!(marker.is_file());
    }

    fn authority_fence_test_binding() -> String {
        let mut binding = Sha256::new();
        binding.update(b"csswitch-skill-authority-fence-v1\0");
        binding.update(TEST_BRIDGE_TOKEN.as_bytes());
        format!("{:x}", binding.finalize())
    }

    fn write_skill_archive(root: &Path, skill_name: &str) -> PathBuf {
        let source = root.join(format!("{skill_name}-source"));
        fs::create_dir_all(&source).unwrap();
        fs::write(
            source.join("SKILL.md"),
            format!("---\nname: {skill_name}\n---\n# {skill_name}\n"),
        )
        .unwrap();
        let archive = root.join(format!("{skill_name}.zip"));
        let output = std::process::Command::new("/usr/bin/zip")
            .args(["-q", "-r"])
            .arg(&archive)
            .arg("SKILL.md")
            .current_dir(&source)
            .output()
            .unwrap();
        assert!(output.status.success(), "zip fixture creation failed");
        archive
    }

    fn write_poll_json(path: &Path, value: &Value) {
        let temp = path.with_extension("tmp");
        fs::write(&temp, serde_json::to_vec(value).unwrap()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&temp, fs::Permissions::from_mode(0o600)).unwrap();
        }
        fs::rename(temp, path).unwrap();
    }

    fn imported_skill(data: &Path, name: &str) -> PathBuf {
        let skill = data.join("orgs/org-test/skills").join(name);
        fs::create_dir(&skill).unwrap();
        fs::write(skill.join("SKILL.md"), b"---\nname: test\n---\n").unwrap();
        let marker = json!({
            "version": 1,
            "repo": "owner/repo",
            "sha": "0123456789abcdef0123456789abcdef01234567",
            "plugin": name,
            "marketplace": CSSWITCH_MARKETPLACE,
            "path": format!("skills/{name}"),
            "importedAt": "2026-07-15T00:00:00Z",
            "license": "NOASSERTION"
        });
        fs::write(
            skill.join(IMPORT_ORIGIN_FILE),
            serde_json::to_vec(&marker).unwrap(),
        )
        .unwrap();
        skill
    }

    #[test]
    fn name_only_requests_source_without_writing() {
        let data = temp_dir("name-only");
        let result = install_from_arguments(&data, &json!({"skill_name": "pdf"}));
        assert_eq!(result["status"], "NEED_SOURCE_URL");
        assert_eq!(result["directory_commit"], false);
        assert!(!data.join("orgs").exists());
        fs::remove_dir_all(data).unwrap();
    }

    #[test]
    fn tool_description_routes_download_and_attach_to_csswitch() {
        let tool = install_tool_definition();
        let description = tool["description"].as_str().unwrap();
        assert!(description.contains("host.skills.edit"));
        assert!(description.contains("host.skills.publish"));
        assert!(description.contains("Agent 只提交准确 URL"));
        assert!(description.contains("不下载文件"));
        assert!(description.contains("不要手工调用 host.agents.attach_skill"));
        assert!(description.contains("skill(skill_name)"));

        let uninstall = uninstall_tool_definition();
        let uninstall_description = uninstall["description"].as_str().unwrap();
        assert!(uninstall_description.contains("BUNDLE_UNINSTALL_CONFIRMATION_REQUIRED"));
        assert!(uninstall_description.contains("confirm_bundle_id"));
        assert!(uninstall_description.contains("不支持部分物理删除"));
        assert!(uninstall["inputSchema"]["properties"]["confirm_bundle_id"].is_object());
    }

    #[test]
    fn bundle_uninstall_confirmation_is_structured_and_non_mutating() {
        let bundle = csswitch_skill_install_core::BundleUninstall {
            bundle_id: "a".repeat(64),
            bundle_name: "nature-skills".into(),
            active_org: "org-test".into(),
            skill_names: vec!["nature-reader".into(), "nature-writing".into()],
            top_level_paths: vec![
                "_shared".into(),
                "nature-reader".into(),
                "nature-writing".into(),
            ],
            manifest_path: PathBuf::from("/private/tmp/bundle.json"),
        };
        let result = bundle_uninstall_confirmation(&bundle, "nature-reader", false);
        assert_eq!(result["status"], "BUNDLE_UNINSTALL_CONFIRMATION_REQUIRED");
        assert_eq!(result["bundle_id"], "a".repeat(64));
        assert_eq!(result["confirm_bundle_id"], "a".repeat(64));
        assert_eq!(result["bundle_name"], "nature-skills");
        assert_eq!(result["skill_name"], "nature-reader");
        assert_eq!(result["skill_names"], result["affected_skill_names"]);
        assert_eq!(result["skill_names"].as_array().unwrap().len(), 2);
        assert_eq!(result["confirmation_required"], true);
        assert_eq!(result["confirmation_scope"], "whole_bundle");
        assert_eq!(result["partial_uninstall_supported"], false);
        assert_eq!(result["detach_attempted"], false);
        assert_eq!(result["directory_removed"], false);
        assert_eq!(result["quarantine_commit"], false);

        let changed = bundle_uninstall_confirmation(&bundle, "nature-reader", true);
        assert!(changed["message"].as_str().unwrap().contains("重新展示"));
    }

    #[test]
    fn bundle_confirmation_argument_is_strictly_bound() {
        let id = "b".repeat(64);
        let parsed = validate_uninstall_arguments(
            &json!({"skill_name":"nature-reader","confirm_bundle_id":id}),
        )
        .unwrap();
        assert_eq!(parsed.0, "nature-reader");
        assert_eq!(
            parsed.1.as_deref(),
            Some("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
        );
        assert!(validate_uninstall_arguments(
            &json!({"skill_name":"nature-reader","confirm_bundle_id":"B".repeat(64)})
        )
        .is_err());
        assert!(validate_uninstall_arguments(
            &json!({"skill_name":"nature-reader","confirm_bundle_id":"b".repeat(64),"confirm":true})
        )
        .is_err());
    }

    #[test]
    fn source_url_without_science_context_never_writes() {
        let data = temp_dir("science-not-ready");
        let result = install_from_arguments(
            &data,
            &json!({"source_url": "https://github.com/a/b/tree/main/skill"}),
        );
        assert_eq!(result["status"], "SCIENCE_NOT_READY");
        assert_eq!(result["directory_commit"], false);
        assert!(!data.join("orgs").exists());
        fs::remove_dir_all(data).unwrap();
    }

    #[test]
    fn github_failures_keep_structured_status_and_mcp_error_semantics() {
        for code in [
            "GITHUB_RATE_LIMITED",
            "GITHUB_PERMISSION_DENIED",
            "GITHUB_NOT_FOUND",
            "GITHUB_TIMEOUT",
            "GITHUB_REDIRECT_INVALID",
            "SOURCE_REF_REQUIRES_COMMIT_SHA",
            "LEGACY_INTEGRITY_UNVERIFIED",
        ] {
            let payload = install_error_payload(
                Some("demo"),
                InstallError::new(code, "expected failure", "test").retryable(true),
            );
            assert_eq!(payload["status"], code);
            assert_eq!(payload["request_terminal"], true);
            assert_eq!(payload["automatic_retry_allowed"], false);
            assert_eq!(payload["user_retry_available"], true);
            assert!(payload["message"]
                .as_str()
                .unwrap()
                .contains("不得自动重试"));
            let result = tool_result(payload);
            assert_eq!(result["isError"], true);
            assert_eq!(result["structuredContent"]["status"], code);
        }
    }

    #[test]
    fn uninstall_moves_only_csswitch_import_to_quarantine() {
        let (root, data) = standard_data_dir("uninstall");
        let runtime_sentinel = data.join("runtime/fake-version/skills/do-not-touch.txt");
        fs::create_dir_all(runtime_sentinel.parent().unwrap()).unwrap();
        fs::write(&runtime_sentinel, b"science-owned-runtime").unwrap();
        let skill = imported_skill(&data, "internal-comms");
        let result = uninstall_from_arguments(&data, &json!({"skill_name":"internal-comms"}));
        assert_eq!(result["status"], "QUARANTINED_DETACH_REQUIRED", "{result}");
        assert_eq!(result["detach_required"], true);
        assert_eq!(result["detach_method"], "host.agents.detach_skill");
        assert_eq!(result["directory_removed"], true);
        assert_eq!(result["quarantine_commit"], true);
        assert!(!skill.exists());
        let quarantine = data
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("skill-trash")
            .join(result["quarantine_name"].as_str().unwrap());
        assert!(quarantine.join("SKILL.md").is_file());
        assert!(quarantine.join(IMPORT_ORIGIN_FILE).is_file());
        assert_eq!(
            fs::read(&runtime_sentinel).unwrap(),
            b"science-owned-runtime",
            "uninstall must never mutate a version-runtime directory"
        );
        let repeated = uninstall_from_arguments(&data, &json!({"skill_name":"internal-comms"}));
        assert_eq!(repeated["status"], "UNINSTALL_FAILED");
        assert!(repeated["message"].as_str().unwrap().contains("不存在"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn r0_bridge_install_and_uninstall_freeze_file_and_attachment_outcomes() {
        let (root, data) = standard_data_dir("r0-file-attachment-outcomes");
        let archive = write_skill_archive(&root, "install-retained");
        let installed = data.join("orgs/org-test/skills/install-retained");
        assert!(
            !installed.exists(),
            "fixture must begin before package commit"
        );
        let context = ScienceHostContext {
            binary: root.join("missing-science"),
            version: "test-version".into(),
            fingerprint: csswitch_skill_install_core::ScienceExecutableFingerprint {
                device: 0,
                inode: 0,
                size: 0,
                modified_seconds: 0,
                modified_nanoseconds: 0,
                mode: 0,
                sha256: "0".repeat(64),
            },
            home: root.join("sandbox/home"),
            data_dir: data.clone(),
            sandbox_port: 19_941,
        };
        let _archive_guard = test_arm_local_archive(&data, archive);
        let _ready_guard = test_arm_ready_context(context.clone());
        let mut phases = Vec::new();
        let install = handle_bridge_request_with_progress(
            &data,
            Some(&context),
            None,
            None,
            &json!({
                "operation":"install",
                "arguments":{
                    "source_url":"https://github.com/csswitch/r0-g-test/tree/main/install-retained",
                    "skill_name":"install-retained"
                }
            }),
            &mut |phase, _| phases.push(phase.to_string()),
        );
        assert_eq!(install["status"], "FILES_COMMITTED_ATTACH_REQUIRED");
        assert_eq!(install["directory_commit"], true);
        assert_eq!(install["attach_required"], true);
        assert!(installed.is_dir());
        assert_eq!(phases, vec!["preflight", "download", "attach"]);

        let removed = imported_skill(&data, "uninstall-quarantined");
        let uninstall = handle_bridge_request_with_progress(
            &data,
            None,
            None,
            None,
            &json!({
                "operation":"uninstall",
                "arguments":{"skill_name":"uninstall-quarantined"}
            }),
            &mut |_, _| {},
        );
        assert_eq!(uninstall["status"], "QUARANTINED_DETACH_REQUIRED");
        assert_eq!(uninstall["directory_removed"], true);
        assert_eq!(uninstall["quarantine_commit"], true);
        assert_eq!(uninstall["detach_required"], true);
        assert!(!removed.exists());
        let quarantine = root
            .join("sandbox/skill-trash")
            .join(uninstall["quarantine_name"].as_str().unwrap());
        assert!(quarantine.join("SKILL.md").is_file());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn uninstall_refuses_unmarked_foreign_and_invalid_names() {
        let (root, data) = standard_data_dir("uninstall-refuse");
        let skills = data.join("orgs/org-test/skills");
        let manual = skills.join("manual-skill");
        fs::create_dir(&manual).unwrap();
        fs::write(manual.join("SKILL.md"), b"manual").unwrap();
        let unmarked = uninstall_from_arguments(&data, &json!({"skill_name":"manual-skill"}));
        assert_eq!(unmarked["status"], "UNINSTALL_FAILED");
        assert!(manual.exists());

        let foreign = imported_skill(&data, "foreign-skill");
        let mut marker: Value =
            serde_json::from_slice(&fs::read(foreign.join(IMPORT_ORIGIN_FILE)).unwrap()).unwrap();
        marker["marketplace"] = json!("another-importer");
        fs::write(
            foreign.join(IMPORT_ORIGIN_FILE),
            serde_json::to_vec(&marker).unwrap(),
        )
        .unwrap();
        let foreign_result =
            uninstall_from_arguments(&data, &json!({"skill_name":"foreign-skill"}));
        assert_eq!(foreign_result["status"], "UNINSTALL_FAILED");
        assert!(foreign.exists());

        let invalid = uninstall_from_arguments(&data, &json!({"skill_name":"../escape"}));
        assert_eq!(invalid["status"], "UNINSTALL_FAILED");
        assert!(invalid["message"].as_str().unwrap().contains("非法"));

        let single = imported_skill(&data, "single-skill");
        let stale_confirmation = uninstall_from_arguments(
            &data,
            &json!({"skill_name":"single-skill","confirm_bundle_id":"c".repeat(64)}),
        );
        assert_eq!(stale_confirmation["status"], "UNINSTALL_FAILED");
        assert!(stale_confirmation["message"]
            .as_str()
            .unwrap()
            .contains("bundle"));
        assert!(single.exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn uninstall_accepts_v1_compatible_local_zip_marker() {
        let (root, data) = standard_data_dir("uninstall-local-zip");
        let skill = data.join("orgs/org-test/skills/local-demo");
        fs::create_dir(&skill).unwrap();
        fs::write(skill.join("SKILL.md"), b"demo").unwrap();
        fs::write(
            skill.join(IMPORT_ORIGIN_FILE),
            serde_json::to_vec(&json!({
                "version": 1,
                "repo": "csswitch/local-archive",
                "sha": "a".repeat(40),
                "plugin": "local-demo",
                "marketplace": CSSWITCH_MARKETPLACE,
                "path": "local-demo",
                "importedAt": "2026-07-15T00:00:00Z",
                "license": "NOASSERTION",
                "csswitch_revision": 2,
                "source_kind": "local_zip",
                "content_sha256": "b".repeat(64),
                "archive_sha256": "a".repeat(64)
            }))
            .unwrap(),
        )
        .unwrap();
        let result = uninstall_from_arguments(&data, &json!({"skill_name":"local-demo"}));
        assert_eq!(result["status"], "QUARANTINED_DETACH_REQUIRED");
        assert!(!skill.exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn existing_org_symlink_is_rejected_before_directory_creation() {
        use std::os::unix::fs::symlink;

        let root = temp_dir("org-symlink");
        let data = root.join("data");
        let outside = root.join("outside");
        fs::create_dir_all(data.join("orgs")).unwrap();
        fs::create_dir(&outside).unwrap();
        symlink(&outside, data.join("orgs/org-test")).unwrap();
        let skills = data.join("orgs/org-test/skills");
        assert!(ensure_safe_root(&data, &skills).is_err());
        assert!(!outside.join("skills").exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rename_no_replace_never_overwrites_existing_target() {
        let root = temp_dir("rename");
        let source = root.join("source");
        let target = root.join("target");
        fs::create_dir(&source).unwrap();
        fs::create_dir(&target).unwrap();
        fs::write(source.join("new"), b"new").unwrap();
        fs::write(target.join("old"), b"old").unwrap();
        assert!(rename_no_replace(&source, &target).is_err());
        assert_eq!(fs::read(target.join("old")).unwrap(), b"old");
        assert!(source.join("new").is_file());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn mcp_list_and_name_only_call_have_stable_shapes() {
        let bridge = Path::new("/tmp/CSSwitch-Skill-Bridge-test");
        let listed = mcp_request(
            bridge,
            ToolMode::All,
            &json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}),
        )
        .unwrap();
        let names = listed["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|tool| tool["name"].as_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            names,
            [INSTALL_TOOL_NAME, UNINSTALL_TOOL_NAME, POLL_TOOL_NAME]
        );
        let called = mcp_request(bridge, ToolMode::All, &json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":INSTALL_TOOL_NAME,"arguments":{"skill_name":"pdf"}}})).unwrap();
        assert_eq!(
            called["result"]["structuredContent"]["status"],
            "NEED_SOURCE_URL"
        );
        let uninstall = mcp_request(bridge, ToolMode::All, &json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":UNINSTALL_TOOL_NAME,"arguments":{"skill_name":"pdf"}}})).unwrap();
        assert_eq!(
            uninstall["result"]["structuredContent"]["status"],
            "HOST_ACCESS_REQUIRED"
        );
        assert_eq!(
            uninstall["result"]["structuredContent"]["request"]["payload"]["operation"],
            "uninstall"
        );
        let confirmed = mcp_request(bridge, ToolMode::All, &json!({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":UNINSTALL_TOOL_NAME,"arguments":{"skill_name":"pdf","confirm_bundle_id":"d".repeat(64)}}})).unwrap();
        assert_eq!(
            confirmed["result"]["structuredContent"]["request"]["payload"]["arguments"]
                ["confirm_bundle_id"],
            "d".repeat(64)
        );
    }

    #[test]
    fn scoped_connectors_expose_only_their_intended_tool() {
        let bridge = Path::new("/tmp/CSSwitch-Skill-Bridge-test");
        let initialized = mcp_request(
            bridge,
            ToolMode::Uninstall,
            &json!({"jsonrpc":"2.0","id":1,"method":"initialize"}),
        )
        .unwrap();
        assert_eq!(
            initialized["result"]["serverInfo"]["name"],
            "csswitch-skill-uninstaller"
        );
        let listed = mcp_request(
            bridge,
            ToolMode::Uninstall,
            &json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}),
        )
        .unwrap();
        assert_eq!(listed["result"]["tools"].as_array().unwrap().len(), 2);
        assert_eq!(listed["result"]["tools"][0]["name"], UNINSTALL_TOOL_NAME);
        assert_eq!(listed["result"]["tools"][1]["name"], POLL_TOOL_NAME);
        let rejected = mcp_request(
            bridge,
            ToolMode::Uninstall,
            &json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":INSTALL_TOOL_NAME,"arguments":{}}}),
        )
        .unwrap();
        assert_eq!(rejected["error"]["code"], -32602);
    }

    #[test]
    fn mcp_operation_only_reconcile_reaches_signed_host_request() {
        let bridge = Path::new("/tmp/CSSwitch-Skill-Bridge-test");
        let response = mcp_request(
            bridge,
            ToolMode::All,
            &json!({"jsonrpc":"2.0","id":7,"method":"tools/call","params":{
                "name": INSTALL_TOOL_NAME,
                "arguments":{"confirmation":{"schema_version":1,"action":"reconcile","operation_id":"op-reconcile"}}
            }}),
        )
        .unwrap();
        let payload = &response["result"]["structuredContent"];
        assert_eq!(payload["status"], "HOST_ACCESS_REQUIRED");
        assert_eq!(payload["request"]["payload"]["operation"], "install");
        assert_eq!(
            payload["request"]["payload"]["arguments"]["confirmation"]["operation_id"],
            "op-reconcile"
        );
    }

    #[test]
    fn install_mcp_confirmation_actions_preserve_apply_source_binding() {
        let bridge = Path::new("/tmp/CSSwitch-Skill-Bridge-test");
        let exact_source =
            "https://github.com/example/skill-repo/tree/0123456789abcdef0123456789abcdef01234567/demo";
        for (action, arguments) in [
            (
                "apply",
                json!({
                    "source_url": exact_source,
                    "confirmation": {
                        "schema_version": 1,
                        "action": "apply",
                        "operation_id": "op-install-apply",
                        "plan_digest": "a".repeat(64),
                        "capability": "capability"
                    }
                }),
            ),
            (
                "reconcile",
                json!({"confirmation": {
                    "schema_version": 1,
                    "action": "reconcile",
                    "operation_id": "op-install-reconcile"
                }}),
            ),
            (
                "continue",
                json!({"confirmation": {
                    "schema_version": 1,
                    "action": "continue",
                    "operation_id": "op-install-continue"
                }}),
            ),
        ] {
            let response = mcp_request(
                bridge,
                ToolMode::All,
                &json!({"jsonrpc":"2.0","id":7,"method":"tools/call","params":{
                    "name": INSTALL_TOOL_NAME,
                    "arguments": arguments
                }}),
            )
            .unwrap();
            let payload = &response["result"]["structuredContent"];
            assert_eq!(
                payload["status"], "HOST_ACCESS_REQUIRED",
                "{action}: {payload}"
            );
            let request = &payload["request"]["payload"];
            let request_id = payload["request_id"].as_str().unwrap();
            validate_bridge_request(TEST_BRIDGE_TOKEN, request_id, request).unwrap();
            assert_eq!(request["arguments"]["confirmation"]["action"], action);
            assert_eq!(
                request["arguments"].get("source_url").is_some(),
                action == "apply",
            );
        }

        // An apply without its source is still refused by signed-host
        // validation, rather than falling back to legacy NEED_SOURCE_URL.
        let response = mcp_request(
            bridge,
            ToolMode::All,
            &json!({"jsonrpc":"2.0","id":8,"method":"tools/call","params":{
                "name": INSTALL_TOOL_NAME,
                "arguments":{"confirmation":{
                    "schema_version":1,
                    "action":"apply",
                    "operation_id":"op-install-missing-source",
                    "plan_digest":"a".repeat(64),
                    "capability":"capability"
                }}
            }}),
        )
        .unwrap();
        let payload = &response["result"]["structuredContent"];
        assert_eq!(payload["status"], "HOST_ACCESS_REQUIRED");
        assert!(validate_bridge_request(
            TEST_BRIDGE_TOKEN,
            payload["request_id"].as_str().unwrap(),
            &payload["request"]["payload"],
        )
        .is_err());
    }

    #[test]
    fn install_confirmation_handler_dispatches_without_legacy_source_fallback() {
        use std::os::unix::fs::PermissionsExt;

        let (root, data) = standard_data_dir("install-operation-handler-dispatch");
        let bridge = root.join("CSSwitch-Skill-Bridge-operation-handler");
        fs::create_dir(&bridge).unwrap();
        fs::set_permissions(&bridge, fs::Permissions::from_mode(0o700)).unwrap();
        let context = ScienceHostContext {
            binary: root.join("missing-science"),
            version: "test-version".into(),
            fingerprint: csswitch_skill_install_core::ScienceExecutableFingerprint {
                device: 0,
                inode: 0,
                size: 0,
                modified_seconds: 0,
                modified_nanoseconds: 0,
                mode: 0,
                sha256: "0".repeat(64),
            },
            home: root.join("sandbox/home"),
            data_dir: data.clone(),
            sandbox_port: 19_941,
        };
        for (action, arguments) in [
            (
                "apply",
                json!({
                    "source_url":"https://github.com/example/skill-repo/tree/0123456789abcdef0123456789abcdef01234567/demo",
                    "confirmation":{"schema_version":1,"action":"apply","operation_id":"op-dispatch-apply","plan_digest":"a".repeat(64),"capability":"capability"}
                }),
            ),
            (
                "reconcile",
                json!({"confirmation":{"schema_version":1,"action":"reconcile","operation_id":"op-dispatch-reconcile"}}),
            ),
            (
                "continue",
                json!({"confirmation":{"schema_version":1,"action":"continue","operation_id":"op-dispatch-continue"}}),
            ),
        ] {
            let response = handle_bridge_request_with_progress(
                &data,
                Some(&context),
                Some(&bridge),
                None,
                &json!({"operation":"install","arguments":arguments}),
                &mut |_, _| {},
            );
            assert_ne!(
                response["status"], "NEED_SOURCE_URL",
                "{action}: {response}"
            );
            assert_ne!(response["status"], "REQUEST_FAILED", "{action}: {response}");
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn operation_handler_ignores_agent_writable_mailbox_operation_forgery() {
        use std::os::unix::fs::PermissionsExt;

        let (root, data) = standard_data_dir("operation-mailbox-forgery");
        let bridge = root.join("CSSwitch-Skill-Bridge-agent-mailbox");
        let authority_path = root.join("host-only-operation-authority");
        fs::create_dir(&bridge).unwrap();
        fs::create_dir(&authority_path).unwrap();
        fs::set_permissions(&bridge, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&authority_path, fs::Permissions::from_mode(0o700)).unwrap();
        let authority = File::open(&authority_path).unwrap();
        let _real_roots = operation_roots(&authority).unwrap();
        let operation_id = "a".repeat(32);
        for name in [
            "skill-operation-staging",
            "skill-operation-ledger",
            "skill-operation-quarantine",
        ] {
            fs::create_dir(bridge.join(name)).unwrap();
        }
        fs::write(
            bridge
                .join("skill-operation-ledger")
                .join(format!("{operation_id}.skill-operation-ledger.json")),
            br#"{"schema":"forged-agent-mailbox-ledger"}"#,
        )
        .unwrap();
        let context = ScienceHostContext {
            binary: root.join("missing-science"),
            version: "test-version".into(),
            fingerprint: csswitch_skill_install_core::ScienceExecutableFingerprint {
                device: 0,
                inode: 0,
                size: 0,
                modified_seconds: 0,
                modified_nanoseconds: 0,
                mode: 0,
                sha256: "0".repeat(64),
            },
            home: root.join("sandbox/home"),
            data_dir: data.clone(),
            sandbox_port: 19_943,
        };
        for (action, arguments) in [
            (
                "apply",
                json!({
                    "source_url":"https://github.com/owner/repo/tree/0123456789abcdef0123456789abcdef01234567/skills/demo",
                    "confirmation":{"schema_version":1,"action":"apply","operation_id":operation_id,"plan_digest":"a".repeat(64),"capability":"forged"}
                }),
            ),
            (
                "reconcile",
                json!({"confirmation":{"schema_version":1,"action":"reconcile","operation_id":operation_id}}),
            ),
            (
                "continue",
                json!({"confirmation":{"schema_version":1,"action":"continue","operation_id":operation_id}}),
            ),
        ] {
            let response = handle_bridge_request_with_progress(
                &data,
                Some(&context),
                Some(&bridge),
                Some(&authority),
                &json!({"operation":"install","arguments":arguments}),
                &mut |_, _| {},
            );
            assert_eq!(
                response["status"], "SKILL_OPERATION_LEDGER_NOT_FOUND",
                "{action} must use host-only authority roots, not mailbox: {response}"
            );
        }
        assert!(bridge.join("skill-operation-staging").is_dir());
        assert!(bridge
            .join("skill-operation-ledger")
            .join(format!("{operation_id}.skill-operation-ledger.json"))
            .is_file());
        assert!(
            !authority_path
                .join("skill-operation-ledger")
                .join(format!("{operation_id}.skill-operation-ledger.json"))
                .exists(),
            "mailbox forgery must create no authority ledger or mutation"
        );
        assert!(data
            .join("orgs/org-test/skills")
            .read_dir()
            .unwrap()
            .next()
            .is_none());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn removal_confirmation_handler_dispatches_without_legacy_uninstall_fallback() {
        use std::os::unix::fs::PermissionsExt;

        let (root, data) = standard_data_dir("removal-operation-handler-dispatch");
        let bridge = root.join("CSSwitch-Skill-Bridge-removal-handler");
        fs::create_dir(&bridge).unwrap();
        fs::set_permissions(&bridge, fs::Permissions::from_mode(0o700)).unwrap();
        let context = ScienceHostContext {
            binary: root.join("missing-science"),
            version: "test-version".into(),
            fingerprint: csswitch_skill_install_core::ScienceExecutableFingerprint {
                device: 0,
                inode: 0,
                size: 0,
                modified_seconds: 0,
                modified_nanoseconds: 0,
                mode: 0,
                sha256: "0".repeat(64),
            },
            home: root.join("sandbox/home"),
            data_dir: data.clone(),
            sandbox_port: 19_942,
        };
        for (action, confirmation) in [
            (
                "apply",
                json!({"schema_version":1,"action":"apply","operation_id":"op-removal-dispatch-apply","plan_digest":"a".repeat(64),"capability":"capability"}),
            ),
            (
                "reconcile",
                json!({"schema_version":1,"action":"reconcile","operation_id":"op-removal-dispatch-reconcile"}),
            ),
            (
                "continue",
                json!({"schema_version":1,"action":"continue","operation_id":"op-removal-dispatch-continue"}),
            ),
        ] {
            let response = handle_bridge_request_with_progress(
                &data,
                Some(&context),
                Some(&bridge),
                None,
                &json!({"operation":"uninstall","arguments":{"confirmation":confirmation}}),
                &mut |_, _| {},
            );
            assert_ne!(
                response["status"], "UNINSTALL_FAILED",
                "{action}: {response}"
            );
            assert_ne!(response["status"], "REQUEST_FAILED", "{action}: {response}");
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn uninstall_mcp_operation_authoritative_actions_reach_signed_host_request() {
        let bridge = Path::new("/tmp/CSSwitch-Skill-Bridge-test");
        let definition = uninstall_tool_definition();
        assert!(
            definition["inputSchema"].get("required").is_none(),
            "reconcile/continue are operation-id-only at the MCP schema boundary"
        );
        for (action, extra) in [
            (
                "apply",
                json!({"plan_digest":"a".repeat(64), "capability":"capability"}),
            ),
            ("reconcile", json!({})),
            ("continue", json!({})),
        ] {
            let mut confirmation = json!({
                "schema_version": 1,
                "action": action,
                "operation_id": "op-removal",
            });
            confirmation
                .as_object_mut()
                .unwrap()
                .extend(extra.as_object().unwrap().clone());
            let response = mcp_request(
                bridge,
                ToolMode::All,
                &json!({"jsonrpc":"2.0","id":7,"method":"tools/call","params":{
                    "name": UNINSTALL_TOOL_NAME,
                    "arguments":{"confirmation":confirmation}
                }}),
            )
            .unwrap();
            let payload = &response["result"]["structuredContent"];
            assert_eq!(
                payload["status"], "HOST_ACCESS_REQUIRED",
                "{action}: {payload}"
            );
            assert_eq!(payload["request"]["payload"]["operation"], "uninstall");
            assert_eq!(
                payload["request"]["payload"]["arguments"]["confirmation"]["operation_id"],
                "op-removal"
            );
            assert_eq!(
                payload["request"]["payload"]["arguments"]["confirmation"]["action"],
                action
            );
            let request = payload["request"]["payload"].clone();
            let request_id = payload["request_id"].as_str().unwrap();
            validate_bridge_request(TEST_BRIDGE_TOKEN, request_id, &request).unwrap();
        }
    }

    #[test]
    fn uninstall_operation_authoritative_request_rejects_outer_target_fields() {
        let bridge = Path::new("/tmp/CSSwitch-Skill-Bridge-test");
        let request = host_access_request(
            bridge,
            TEST_BRIDGE_TOKEN,
            "uninstall",
            &json!({
                "skill_name":"must-not-be-forwarded",
                "confirmation":{
                    "schema_version":1,
                    "action":"apply",
                    "operation_id":"op-removal",
                    "plan_digest":"a".repeat(64),
                    "capability":"capability"
                }
            }),
        );
        let request_id = request["request_id"].as_str().unwrap();
        assert!(validate_bridge_request(
            TEST_BRIDGE_TOKEN,
            request_id,
            &request["request"]["payload"],
        )
        .is_err());
    }

    #[test]
    fn bridge_request_signature_rejects_tampering_expiry_and_wrong_filename() {
        let bridge = Path::new("/tmp/CSSwitch-Skill-Bridge-test");
        let result = host_access_request(
            bridge,
            TEST_BRIDGE_TOKEN,
            "uninstall",
            &json!({"skill_name":"pdf","confirm_bundle_id":"e".repeat(64)}),
        );
        let filename = result["request"]["filename"].as_str().unwrap();
        let id = filename.strip_suffix(".request.json").unwrap();
        assert_eq!(result["request_id"], id);
        assert_eq!(
            result["request"]["status_filename"],
            format!("{id}.status.json")
        );
        assert_eq!(result["request"]["poll_tool"], POLL_TOOL_NAME);
        assert_eq!(result["request"]["poll_after_seconds"], 0);
        assert_eq!(
            result["request"]["timeout_seconds"],
            BRIDGE_INSTALL_RESPONSE_TIMEOUT_SECONDS
        );
        assert_eq!(result["request"]["terminal_grace_seconds"], 5);
        assert!(result["message"]
            .as_str()
            .unwrap()
            .contains("绝不能再次写 request_filename"));
        assert!(result["message"]
            .as_str()
            .unwrap()
            .contains("不要运行 sleep"));
        let request = result["request"]["payload"].clone();
        validate_bridge_request(TEST_BRIDGE_TOKEN, id, &request).unwrap();

        let mut tampered = request.clone();
        tampered["arguments"]["skill_name"] = json!("other");
        assert!(validate_bridge_request(TEST_BRIDGE_TOKEN, id, &tampered).is_err());
        assert!(validate_bridge_request(TEST_BRIDGE_TOKEN, &"f".repeat(32), &request).is_err());

        let mut expired = request;
        expired["issued_at"] = json!(unix_seconds().saturating_sub(BRIDGE_REQUEST_TTL_SECONDS + 1));
        expired.as_object_mut().unwrap().remove("signature");
        let expired_signature = sign_bridge_request(TEST_BRIDGE_TOKEN, &expired).unwrap();
        expired["signature"] = json!(expired_signature);
        assert!(validate_bridge_request(TEST_BRIDGE_TOKEN, id, &expired).is_err());
    }

    #[test]
    fn poll_tool_reports_progress_long_polls_and_returns_final_response() {
        let bridge = temp_dir("poll-bridge");
        let id = "a".repeat(32);
        let status_path = bridge.join(format!("{id}.status.json"));
        let response_path = bridge.join(format!("{id}.response.json"));
        write_poll_json(
            &status_path,
            &json!({
                "status": "PROCESSING",
                "request_id": id,
                "phase": "download",
                "sequence": 7,
                "elapsed_seconds": 12,
                "deadline_at": unix_seconds() + 60,
                "terminal_grace_seconds": 5
            }),
        );
        let first = poll_bridge_request(&bridge, &json!({"request_id": id}));
        assert_eq!(first["status"], "PROCESSING");
        assert_eq!(first["phase"], "download");
        assert_eq!(first["sequence"], 7);
        assert_eq!(first["poll_again"], true);

        let response_for_thread = response_path.clone();
        let worker = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            write_poll_json(
                &response_for_thread,
                &json!({"status":"BUNDLE_INSTALLED_ATTACHED","directory_commit":true}),
            );
        });
        let final_response =
            poll_bridge_request(&bridge, &json!({"request_id": id, "last_sequence": 7}));
        worker.join().unwrap();
        assert_eq!(final_response["status"], "BUNDLE_INSTALLED_ATTACHED");
        assert_eq!(final_response["request_id"], id);
        assert_eq!(final_response["poll_complete"], true);
        assert_eq!(final_response["poll_again"], false);

        let invalid = poll_bridge_request(&bridge, &json!({"request_id":"../escape"}));
        assert_eq!(invalid["status"], "REQUEST_STATUS_INVALID");
        fs::remove_dir_all(bridge).unwrap();
    }

    #[test]
    fn poll_tool_stops_after_host_deadline_without_resubmitting() {
        let bridge = temp_dir("poll-timeout");
        let id = "b".repeat(32);
        write_poll_json(
            &bridge.join(format!("{id}.status.json")),
            &json!({
                "status": "PROCESSING",
                "request_id": id,
                "phase": "download",
                "sequence": 4,
                "deadline_at": unix_seconds().saturating_sub(10),
                "terminal_grace_seconds": 5
            }),
        );
        let result = poll_bridge_request(&bridge, &json!({"request_id": id}));
        assert_eq!(result["status"], "HOST_RESPONSE_TIMEOUT");
        assert_eq!(result["poll_again"], false);
        fs::remove_dir_all(bridge).unwrap();
    }

    #[test]
    fn persistent_advisory_lock_recovers_stale_file_and_serializes_callers() {
        let root = temp_dir("advisory-lock");
        let lock_path = root.join(".csswitch-install-pdf.lock");
        fs::write(&lock_path, b"stale").unwrap();
        let first = acquire_lock(&lock_path).unwrap();
        assert!(acquire_lock(&lock_path).is_err());
        drop(first);
        let second = acquire_lock(&lock_path).unwrap();
        drop(second);
        assert!(lock_path.is_file());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn operation_error_projection_keeps_definite_rejections_out_of_reconcile() {
        for code in [
            "SKILL_OPERATION_LEDGER_NOT_FOUND",
            "SKILL_OPERATION_CONFIRMATION_CAPABILITY_INVALID",
            "SKILL_OPERATION_TARGET_BINDING_DRIFT",
        ] {
            let install = operation_error(csswitch_skill_install_core::SkillOperationError {
                code: code.into(),
                phase: "recovery".into(),
            });
            assert_eq!(install["recovery_required"], false, "{code}");
            assert_eq!(install["directory_commit"], false, "{code}");
            assert_eq!(install["attach_verified"], false, "{code}");
        }

        let removal = removal_operation_error(csswitch_skill_install_core::SkillOperationError {
            code: "SKILL_OPERATION_CONFIRMATION_EXPIRED".into(),
            phase: "confirmation".into(),
        });
        assert_eq!(removal["recovery_required"], false);
        assert_eq!(removal["detach_verified"], false);
        assert_eq!(removal["quarantine_commit"], false);

        let removal_target =
            removal_operation_error(csswitch_skill_install_core::SkillOperationError {
                code: "SKILL_OPERATION_TARGET_BINDING_DRIFT".into(),
                phase: "preflight".into(),
            });
        assert_eq!(removal_target["recovery_required"], false);
        assert_eq!(removal_target["detach_verified"], false);

        let durable = operation_error(csswitch_skill_install_core::SkillOperationError {
            code: "SKILL_OPERATION_LEDGER_INVALID".into(),
            phase: "recovery".into(),
        });
        assert_eq!(durable["recovery_required"], true);
        assert!(durable["directory_commit"].is_null());
    }
}
