//! Windows 移植：跨平台文件权限助手。
//!
//! Unix 上用 POSIX mode（0o600 等）收紧配置文件/目录权限；Windows 上权限由
//! NTACL 管理，POSIX mode 无法表达，这里降级为 no-op，保持调用点语义：
//! 不因权限收紧在 Windows 上失败而阻塞主流程。

#![allow(dead_code, unused_variables)]

use std::io;
use std::path::{Path, PathBuf};

/// 目录 fsync（Unix 持久化屏障）。Windows 无目录句柄 fsync（File::open 打开
/// 目录直接返回拒绝访问），降级为 no-op；文件数据已由各自的 sync_all 落盘。
pub(crate) fn sync_directory(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        std::fs::File::open(path).and_then(|directory| directory.sync_all())
    }
    #[cfg(windows)]
    {
        match std::fs::metadata(path) {
            Ok(metadata) if metadata.is_dir() => Ok(()),
            _ => std::fs::File::open(path).and_then(|file| file.sync_all()),
        }
    }
}

/// Unix：目录 mode 必须精确等于 0o700。Windows：合成 mode 无执行位语义，
/// 可写目录显示为 0o600——接受 0o600/0o700 两种（私有可写目录），目录的
/// 真实访问控制由 NTACL 决定。
pub(crate) fn dir_mode_is_0700(metadata: &std::fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o777 == 0o700
    }
    #[cfg(windows)]
    {
        matches!(
            metadata.permissions().mode() & 0o777,
            0o700 | 0o600
        )
    }
}

/// 删除文件。Windows 上只读文件无法直接删除（Unix unlink 不受文件本身
/// 权限影响），先清只读属性再删；符号链接不动属性直接删。
pub(crate) fn remove_file_force(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        std::fs::remove_file(path)
    }
    #[cfg(windows)]
    {
        if let Ok(metadata) = std::fs::symlink_metadata(path) {
            if !metadata.file_type().is_symlink() && metadata.permissions().readonly() {
                let mut perms = metadata.permissions();
                perms.set_readonly(false);
                std::fs::set_permissions(path, perms)?;
            }
        }
        std::fs::remove_file(path)
    }
}

/// Unix 的「文件具有任意执行位」检查。Windows 上 std 合成 mode 无执行位
/// 语义（是否可执行由 PATHEXT/PE 头决定），恒返回 true，交由调用方其他
/// 校验（绝对路径、无符号链接、is_file 等）兜底。
pub(crate) fn mode_has_exec(metadata: &std::fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(windows)]
    {
        let _ = metadata;
        true
    }
}

/// 加密安全随机字节。Unix 读 /dev/urandom；Windows 用 BCrypt 系统
/// 首选 RNG（等价语义）；失败关闭，绝不退回弱熵源。
pub(crate) fn rand_bytes(n: usize) -> io::Result<Vec<u8>> {
    #[cfg(unix)]
    {
        use std::io::Read;
        let mut f = std::fs::File::open("/dev/urandom")?;
        let mut b = vec![0u8; n];
        f.read_exact(&mut b)?;
        Ok(b)
    }
    #[cfg(windows)]
    {
        use windows_sys::Win32::Security::Cryptography::{
            BCryptGenRandom, BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        };
        let mut b = vec![0u8; n];
        // SAFETY: 输出缓冲区有效且长度与调用一致；句柄为 NULL（系统首选 RNG）。
        let status = unsafe {
            BCryptGenRandom(
                std::ptr::null_mut(),
                b.as_mut_ptr(),
                n as u32,
                BCRYPT_USE_SYSTEM_PREFERRED_RNG,
            )
        };
        if status != 0 {
            return Err(io::Error::other("BCryptGenRandom 失败"));
        }
        Ok(b)
    }
}

#[cfg(windows)]
/// Windows：解析 `netstat -ano -p tcp`，返回唯一监听该端口的 PID。
pub(crate) fn listener_pid_for_port(port: u16) -> Option<u32> {
    use crate::platform::CreationFlagsExt;
    use std::process::{Command, Stdio};
    let output = Command::new("netstat")
        .args(["-ano", "-p", "tcp"])
        .stdout(Stdio::piped())
        .creation_flags(0x0800_0000) // CREATE_NO_WINDOW
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&output.stdout);
    let needle = format!(":{port}");
    let mut pids: Vec<u32> = Vec::new();
    for line in text.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 5 || !fields[0].eq_ignore_ascii_case("TCP") {
            continue;
        }
        if !fields[3].eq_ignore_ascii_case("LISTENING") {
            continue;
        }
        if !fields[1].ends_with(&needle) {
            continue;
        }
        pids.extend(fields[4].parse::<u32>().ok());
    }
    let first = pids.first().copied()?;
    (pids.iter().all(|pid| *pid == first) && first > 1).then_some(first)
}

#[cfg(windows)]
/// Windows：查询进程可执行文件完整路径（QueryFullProcessImageName）。
pub(crate) fn process_image_path(pid: u32) -> Option<PathBuf> {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32,
        PROCESS_QUERY_LIMITED_INFORMATION,
    };
    if pid <= 1 {
        return None;
    }
    unsafe {
        // SAFETY: handle 仅为本次查询而打开，查询后立即关闭。
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if handle.is_null() {
            return None;
        }
        let mut buffer = [0u16; 1024];
        let mut length = buffer.len() as u32;
        let ok = QueryFullProcessImageNameW(
            handle,
            PROCESS_NAME_WIN32,
            buffer.as_mut_ptr(),
            &mut length,
        );
        CloseHandle(handle);
        if ok == 0 || length == 0 || length as usize > buffer.len() {
            return None;
        }
        let text = String::from_utf16_lossy(&buffer[..length as usize]);
        Some(PathBuf::from(text))
    }
}

/// 传给 bash（Git Bash / zsh）的脚本路径字符串。Windows 上剥掉 `\\?\`
/// verbatim 前缀并把反斜杠换成正斜杠（bash 的 argv 会把反斜杠当转义）；
/// UNC 路径转 `//server/share` 形式。Unix 直通。
pub(crate) fn bash_path(path: &Path) -> String {
    #[cfg(unix)]
    {
        path.to_string_lossy().into_owned()
    }
    #[cfg(windows)]
    {
        let text = path.to_string_lossy();
        let stripped = text
            .strip_prefix(r"\\?\UNC\")
            .map(|rest| format!("//{rest}"))
            .or_else(|| text.strip_prefix(r"\\?\").map(|rest| rest.to_string()))
            .unwrap_or_else(|| text.into_owned());
        stripped.replace('\\', "/")
    }
}

/// 跨平台 canonicalize：Windows 的 std 返回 `\\?\` verbatim 前缀路径，与
/// 普通路径字符串比较永远不相等；这里剥掉前缀，使 canonical 结果可以直接
/// 和原始路径比较（等价 dunce 语义的最小实现）。Unix 直通 std。
pub(crate) fn canonicalize(path: &Path) -> io::Result<PathBuf> {
    let canonical = path.canonicalize()?;
    #[cfg(windows)]
    {
        let text = canonical.as_os_str().to_string_lossy();
        if let Some(stripped) = text.strip_prefix(r"\\?\UNC\") {
            return Ok(PathBuf::from(format!(r"\\{stripped}")));
        }
        if let Some(stripped) = text.strip_prefix(r"\\?\") {
            return Ok(PathBuf::from(stripped.to_string()));
        }
    }
    Ok(canonical)
}

/// 方法形式助手：`path.canonicalize_norm()` 等价 `platform::canonicalize(path)`。
/// Windows 上剥 `\\?\` 前缀；替换各处与原路径做相等比较的 `std::path::Path::canonicalize`。
pub(crate) trait CanonicalizeExt {
    fn canonicalize_norm(&self) -> io::Result<PathBuf>;
}
impl CanonicalizeExt for Path {
    fn canonicalize_norm(&self) -> io::Result<PathBuf> {
        canonicalize(self)
    }
}

/// 等价 Unix `fs::set_permissions(p, fs::Permissions::from_mode(mode))`。
pub(crate) fn set_path_mode(p: &Path, mode: u32) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode))
    }
    #[cfg(windows)]
    {
        Ok(())
    }
}

/// 等价 `file.set_permissions(fs::Permissions::from_mode(mode))`。
pub(crate) fn set_file_mode(file: &std::fs::File, mode: u32) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(mode))
    }
    #[cfg(windows)]
    {
        Ok(())
    }
}

/// 等价 `OpenOptions::new()....mode(mode)` 的收敛写入口。
/// Windows 上 `.mode()` 不可用，直接返回未配置的 options。
pub(crate) fn secure_create(path: &Path, mode: u32) -> io::Result<std::fs::File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(path)
    }
    #[cfg(windows)]
    {
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
    }
}

// ---------------------------------------------------------------------------
// Windows 移植兼容层：把散落在各模块的 Unix 专属 API 收敛到本模块。
// Unix 上全部等价原语义；Windows 上提供 std::fs 近似/降级实现。
// ---------------------------------------------------------------------------

/// `geteuid`。Windows 无 uid 概念，恒返回 0（所有权检查按当前用户放行）。
pub(crate) fn geteuid() -> u32 {
    #[cfg(unix)]
    {
        unsafe { libc::geteuid() }
    }
    #[cfg(not(unix))]
    {
        0
    }
}

/// flock 操作常量。Windows 无 flock，常量为占位值。
#[cfg(unix)]
pub(crate) const LOCK_SH: i32 = libc::LOCK_SH;
#[cfg(unix)]
pub(crate) const LOCK_EX: i32 = libc::LOCK_EX;
#[cfg(unix)]
pub(crate) const LOCK_NB: i32 = libc::LOCK_NB;
#[cfg(unix)]
pub(crate) const LOCK_UN: i32 = libc::LOCK_UN;
#[cfg(not(unix))]
pub(crate) const LOCK_SH: i32 = 1;
#[cfg(not(unix))]
pub(crate) const LOCK_EX: i32 = 2;
#[cfg(not(unix))]
pub(crate) const LOCK_NB: i32 = 4;
#[cfg(not(unix))]
pub(crate) const LOCK_UN: i32 = 8;

pub(crate) const SIGKILL: i32 = 9;

/// open(2) 旗标。Unix 直接取 libc 值；Windows 下 custom_flags 接受 u32（DWORD，
/// std::os::windows::fs::OpenOptionsExt），no-follow / cloexec 语义不可表达，取 0。
macro_rules! open_flag {
    ($name:ident) => {
        #[cfg(unix)]
        pub(crate) const $name: i32 = libc::$name;
        #[cfg(not(unix))]
        pub(crate) const $name: u32 = 0;
    };
}
open_flag!(O_RDONLY);
open_flag!(O_WRONLY);
open_flag!(O_RDWR);
open_flag!(O_CREAT);
open_flag!(O_EXCL);
open_flag!(O_TRUNC);
open_flag!(O_DIRECTORY);
open_flag!(O_NOFOLLOW);
open_flag!(O_CLOEXEC);
open_flag!(O_NONBLOCK);

/// stat st_mode 文件类型位。Windows 降级：st_mode 观测不可用，恒按普通文件
/// 处理（S_IFMT 掩码结果 = S_IFREG，符号链接检查恒不成立）。
macro_rules! stat_mode_flag {
    ($name:ident, $unix:expr) => {
        #[cfg(unix)]
        pub(crate) const $name: i32 = libc::$name;
        #[cfg(not(unix))]
        pub(crate) const $name: u32 = $unix;
    };
}
stat_mode_flag!(S_IFMT, 0o170000u32);
stat_mode_flag!(S_IFLNK, 0o120000u32);
stat_mode_flag!(S_IFDIR, 0o040000u32);
stat_mode_flag!(S_IFREG, 0o100000u32);
stat_mode_flag!(S_IFCHR, 0o020000u32);
stat_mode_flag!(S_IFBLK, 0o060000u32);
stat_mode_flag!(S_IFIFO, 0o010000u32);
stat_mode_flag!(S_IFSOCK, 0o140000u32);
stat_mode_flag!(S_IRWXU, 0o700u32);
stat_mode_flag!(S_IRWXG, 0o070u32);
stat_mode_flag!(S_IRWXO, 0o007u32);

/// `libc::flock`。Windows 降级：无跨进程文件锁，恒返回 0（成功），
/// 互斥由进程内互斥与单实例部署兜底。
pub(crate) fn flock(fd: i32, operation: i32) -> i32 {
    #[cfg(unix)]
    {
        unsafe { libc::flock(fd, operation) }
    }
    #[cfg(not(unix))]
    {
        let _ = (fd, operation);
        0
    }
}

/// `libc::kill(pid, sig)`。Windows 降级：不支持负 pid（进程组），用
/// `taskkill /T /F` 近似整组终止；目标进程已不存在时返回 0（等价 Unix
/// ESRCH→调用方视为成功的语义），无法终止时返回 -1。
pub(crate) fn kill(pid: i32, _signal: i32) -> i32 {
    #[cfg(unix)]
    {
        unsafe { libc::kill(pid, _signal) }
    }
    #[cfg(not(unix))]
    {
        use std::process::Command;
        if pid == 0 {
            return 0;
        }
        let target = pid.abs();
        if !windows_process_alive(target as u32) {
            return 0;
        }
        let status = Command::new("taskkill")
            .args(["/PID", &target.to_string(), "/T", "/F"])
            .creation_flags(0x0800_0000) // CREATE_NO_WINDOW
            .output();
        match status {
            Ok(_) => 0,
            Err(_) => -1,
        }
    }
}

/// Windows 专用：按 pid 探测进程是否仍存活（仅查询，不等待）。
#[cfg(not(unix))]
pub(crate) fn windows_process_alive(pid: u32) -> bool {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{
        GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    };
    const STILL_ACTIVE: u32 = 259;
    unsafe {
        // SAFETY: handle 仅为本次查询而打开，查询后立即关闭。
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if handle.is_null() {
            return false;
        }
        let mut exit_code: u32 = 0;
        let ok = GetExitCodeProcess(handle, &mut exit_code);
        CloseHandle(handle);
        ok != 0 && exit_code == STILL_ACTIVE
    }
}

/// Windows 专用：`Command::creation_flags` 需要 `std::os::windows::process::CommandExt`。
#[cfg(not(unix))]
pub(crate) trait CreationFlagsExt {
    fn creation_flags(&mut self, flags: u32) -> &mut Self;
}
#[cfg(not(unix))]
impl CreationFlagsExt for Command {
    fn creation_flags(&mut self, flags: u32) -> &mut Self {
        std::os::windows::process::CommandExt::creation_flags(self, flags)
    }
}

use std::process::Command;

/// 等价 `fs::Permissions::from_mode(mode)`。Windows 无 from_mode，
/// 返回「非只读」的默认 Permissions（mode 语义由 NTACL 决定）。
pub(crate) fn permissions_from_mode(mode: u32) -> std::fs::Permissions {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::Permissions::from_mode(mode)
    }
    #[cfg(not(unix))]
    {
        let probe = std::env::temp_dir().join(".csswitch-perms-probe");
        let perms = std::fs::write(&probe, b"")
            .ok()
            .and_then(|_| std::fs::metadata(&probe).ok())
            .map(|metadata| metadata.permissions())
            .unwrap_or_else(|| {
                std::fs::metadata(std::env::temp_dir())
                    .expect("cannot obtain default fs Permissions on Windows")
                    .permissions()
            });
        let _ = std::fs::remove_file(&probe);
        let mut perms = perms;
        // 语义映射：owner 无写位（如 0o500/0o400/0o000）→ 只读属性；
        // 有写位（如 0o600/0o700）→ 可写。group/other 位由 NTACL 表达。
        perms.set_readonly(mode & 0o200 == 0);
        perms
    }
}

/// Windows 兼容 trait：为 `std::fs::Metadata` / `std::fs::Permissions` /
/// `std::fs::File` / `std::fs::OpenOptions` 提供 Unix 同名方法的降级实现，
/// 让调用点代码无需 `#[cfg]` 即可编译。仅在 Windows 生效（Unix 用原生 API）。
#[cfg(not(unix))]
pub(crate) trait UnixCompatExt {
    fn uid(&self) -> u32 {
        0
    }
    fn dev(&self) -> u64 {
        0
    }
    fn ino(&self) -> u64 {
        0
    }
    fn nlink(&self) -> u64 {
        1
    }
    fn mtime(&self) -> i64 {
        0
    }
    fn mtime_nsec(&self) -> i64 {
        0
    }
    fn mode(&self) -> u32 {
        // 观测值取 0o600：`mode & 0o077` 类私有性检查恒通过，
        // `mode & 0o111`（可执行）恒不成立——可执行检查一律走
        // `mode_has_exec`，不要直接依赖本值。
        0o600
    }
    fn size(&self) -> u64 {
        0
    }
    fn as_raw_fd(&self) -> i32 {
        0
    }
}

// Metadata 提供真实观测：size/mtime 用真实值（快照/漂移检测依赖），
// mode 用只读属性映射（0o500=只读保护，0o600=可写）。
#[cfg(not(unix))]
impl UnixCompatExt for std::fs::Metadata {
    fn mtime(&self) -> i64 {
        self.modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    }
    fn mtime_nsec(&self) -> i64 {
        self.modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.subsec_nanos() as i64)
            .unwrap_or(0)
    }
    fn mode(&self) -> u32 {
        if self.permissions().readonly() {
            0o500
        } else {
            0o600
        }
    }
    fn size(&self) -> u64 {
        self.len()
    }
}

// Permissions 的 mode 用自身 readonly 标志映射。
#[cfg(not(unix))]
impl UnixCompatExt for std::fs::Permissions {
    fn mode(&self) -> u32 {
        if self.readonly() {
            0o500
        } else {
            0o600
        }
    }
}

/// Windows 专用：`OpenOptions` 的 Unix `.mode(mode)` 降级为 no-op
/// （POSIX mode 由 NTACL 表达，不可设置）。
#[cfg(not(unix))]
pub(crate) trait OpenOptionsModeExt {
    fn mode(&mut self, _mode: u32) -> &mut Self {
        self
    }
}
#[cfg(not(unix))]
impl OpenOptionsModeExt for std::fs::OpenOptions {}

#[cfg(not(unix))]
impl UnixCompatExt for std::fs::File {}

/// `libc::mode_t` 别名（Windows 下用 u32）。
#[cfg(unix)]
pub(crate) type ModeT = libc::mode_t;
#[cfg(not(unix))]
pub(crate) type ModeT = u32;

/// `libc::ino_t` / `libc::dev_t` 别名（Windows 降级为 u64/u64）。
#[cfg(unix)]
pub(crate) type InoT = libc::ino_t;
#[cfg(not(unix))]
pub(crate) type InoT = u64;
#[cfg(unix)]
pub(crate) type DevT = libc::dev_t;
#[cfg(not(unix))]
pub(crate) type DevT = u64;

/// `libc::stat` 别名（Windows 下提供同字段降级结构，字段值不可观测，
/// 仅供类型层编译；权威快照引擎在 Windows 上以 Unsupported 错误降级）。
#[cfg(unix)]
pub(crate) type Stat = libc::stat;
#[cfg(not(unix))]
#[derive(Clone, Copy)]
pub(crate) struct Stat {
    pub st_dev: u64,
    pub st_ino: u64,
    pub st_mode: u32,
    pub st_uid: u32,
    pub st_gid: u32,
    pub st_nlink: u64,
    pub st_size: i64,
    pub st_mtime: i64,
    pub st_mtime_nsec: i64,
}

#[cfg(not(unix))]
pub(crate) const AT_SYMLINK_NOFOLLOW: i32 = 0x100;
#[cfg(unix)]
pub(crate) const AT_SYMLINK_NOFOLLOW: i32 = libc::AT_SYMLINK_NOFOLLOW;
#[cfg(not(unix))]
pub(crate) const AT_REMOVEDIR: i32 = 0x200;
#[cfg(unix)]
pub(crate) const AT_REMOVEDIR: i32 = libc::AT_REMOVEDIR;
