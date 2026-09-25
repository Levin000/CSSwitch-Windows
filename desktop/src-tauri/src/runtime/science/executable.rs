fn is_executable_file(path: &Path) -> bool {
    if !path.is_absolute() {
        return false;
    }
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        match current.symlink_metadata() {
            Ok(metadata) if metadata.file_type().is_symlink() => return false,
            Ok(_) => {}
            Err(_) => return false,
        }
    }
    path.is_file() && path.metadata().map(|metadata| crate::platform::mode_has_exec(&metadata)).unwrap_or(false)
}

fn is_explicit_executable_file(path: &Path) -> bool {
    is_executable_file(path)
}

fn fixed_path_entry_exists(path: &Path, label: &str) -> Result<bool, String> {
    if !path.is_absolute() {
        return Err(format!("{label} 固定路径不是绝对路径"));
    }
    let components = path.components().count();
    let mut current = PathBuf::new();
    for (index, component) in path.components().enumerate() {
        current.push(component.as_os_str());
        match current.symlink_metadata() {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(format!("{label} 固定路径包含 symlink"))
            }
            Ok(metadata) if index + 1 < components && !metadata.file_type().is_dir() => {
                return Err(format!("{label} 固定路径上级包含非目录文件"))
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(format!("检查 {label} 固定路径失败：{error}")),
        }
    }
    Ok(true)
}

fn embedded_identity_metadata_matches(details: &str, identifier: &str, team_id: &str) -> bool {
    details
        .lines()
        .any(|line| line == format!("Identifier={identifier}"))
        && details
            .lines()
            .any(|line| line == format!("TeamIdentifier={team_id}"))
}

fn official_updated_embedded_identity_metadata_matches(details: &str) -> bool {
    OFFICIAL_UPDATED_SCIENCE_IDENTIFIERS
        .iter()
        .any(|identifier| {
            embedded_identity_metadata_matches(details, identifier, OFFICIAL_SCIENCE_TEAM_ID)
        })
}

fn official_updated_identity_metadata_matches(path: &Path) -> bool {
    // Official updater executables observed in 0.1.25 use either
    // `com.anthropic.operon` or `com.anthropic.operon.cli`, including an updater
    // seeded byte-for-byte from the installed App.
    // Both currently fail strict cryptographic `codesign --verify`. Treat the
    // exact allowlisted fields only as format/identity guards; the local trust
    // boundary remains the fixed user-owned path plus SHA-256-bound runtime
    // identity below, not a claim of verified official provenance.
    let output = Command::new("/usr/bin/codesign")
        .args(["-d", "--verbose=4"])
        .arg(path)
        .stdout(Stdio::null())
        .output();
    let Ok(output) = output else {
        return false;
    };
    if !output.status.success() || output.stderr.len() > 64 * 1024 {
        return false;
    }
    let details = String::from_utf8_lossy(&output.stderr);
    official_updated_embedded_identity_metadata_matches(&details)
}

fn file_is_macho(path: &Path) -> bool {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(crate::platform::O_NOFOLLOW | crate::platform::O_CLOEXEC)
        .open(path);
    let Ok(mut file) = file else {
        return false;
    };
    let mut magic = [0u8; 4];
    if file.read_exact(&mut magic).is_err() {
        return false;
    }
    matches!(
        magic,
        [0xfe, 0xed, 0xfa, 0xce]
            | [0xce, 0xfa, 0xed, 0xfe]
            | [0xfe, 0xed, 0xfa, 0xcf]
            | [0xcf, 0xfa, 0xed, 0xfe]
            | [0xca, 0xfe, 0xba, 0xbe]
            | [0xbe, 0xba, 0xfe, 0xca]
            | [0xca, 0xfe, 0xba, 0xbf]
            | [0xbf, 0xba, 0xfe, 0xca]
    )
}

fn official_updated_science_bin_for_home(
    home: &Path,
    verify_local_identity: bool,
) -> Option<PathBuf> {
    if !home.is_absolute() || home.canonicalize_norm().ok().as_deref() != Some(home) {
        return None;
    }
    let science_dir = home.join(".claude-science");
    let bin_dir = science_dir.join("bin");
    let candidate = home.join(OFFICIAL_UPDATED_RUNTIME_RELATIVE);
    if !is_executable_file(&candidate) {
        return None;
    }
    // SAFETY: geteuid has no preconditions and does not dereference pointers.
    let uid = unsafe { crate::platform::geteuid() };
    for directory in [home, &science_dir, &bin_dir] {
        let metadata = directory.symlink_metadata().ok()?;
        if !metadata.file_type().is_dir()
            || metadata.uid() != uid
            || metadata.permissions().mode() & 0o022 != 0
        {
            return None;
        }
    }
    let metadata = candidate.symlink_metadata().ok()?;
    if !metadata.file_type().is_file()
        || metadata.uid() != uid
        || metadata.permissions().mode() & 0o111 == 0
        || metadata.permissions().mode() & 0o022 != 0
    {
        return None;
    }
    if verify_local_identity
        && (!(MIN_SCIENCE_BINARY_SIZE..=MAX_SCIENCE_BINARY_SIZE).contains(&metadata.len())
            || !file_is_macho(&candidate)
            || !official_updated_identity_metadata_matches(&candidate))
    {
        return None;
    }
    Some(candidate)
}

fn fingerprint_sha256_hex(fingerprint: &ScienceExecutableFingerprint) -> String {
    fingerprint
        .sha256
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn secure_runtime_snapshot_root(root: &Path) -> Result<PathBuf, String> {
    if !root.is_absolute() {
        return Err("Science runtime snapshot 目录不是绝对路径".into());
    }
    let mut cursor = Some(root);
    while let Some(path) = cursor {
        match path.symlink_metadata() {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err("Science runtime snapshot 目录路径包含 symlink，已拒绝使用".into())
            }
            Ok(metadata) if !metadata.file_type().is_dir() => {
                return Err("Science runtime snapshot 目录路径包含非目录文件".into())
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(format!("检查 Science runtime snapshot 目录失败：{error}")),
        }
        cursor = path.parent();
    }
    fs::create_dir_all(root)
        .map_err(|error| format!("创建 Science runtime snapshot 目录失败：{error}"))?;
    let canonical = root
        .canonicalize_norm()
        .map_err(|error| format!("确认 Science runtime snapshot 目录失败：{error}"))?;
    if canonical != root {
        return Err("Science runtime snapshot 目录包含 symlink，已拒绝使用".into());
    }
    // SAFETY: geteuid has no preconditions and does not dereference pointers.
    let uid = unsafe { crate::platform::geteuid() };
    let metadata = root
        .symlink_metadata()
        .map_err(|error| format!("读取 Science runtime snapshot 目录失败：{error}"))?;
    if !metadata.file_type().is_dir() || metadata.uid() != uid {
        return Err("Science runtime snapshot 目录属主或权限不安全".into());
    }
    fs::set_permissions(root, crate::platform::permissions_from_mode(0o700))
        .map_err(|error| format!("收紧 Science runtime snapshot 目录权限失败：{error}"))?;
    Ok(canonical)
}

fn official_updated_snapshot_from_process_paths(
    snapshot_root: &Path,
    process_paths: &[PathBuf],
    verify_local_identity: bool,
) -> Result<Option<PathBuf>, String> {
    let metadata = match snapshot_root.symlink_metadata() {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("读取 Science runtime snapshot 目录失败：{error}")),
    };
    // SAFETY: geteuid has no preconditions and does not dereference pointers.
    let uid = unsafe { crate::platform::geteuid() };
    if !snapshot_root.is_absolute()
        || metadata.file_type().is_symlink()
        || !metadata.file_type().is_dir()
        || metadata.uid() != uid
        || metadata.permissions().mode() & 0o022 != 0
        || snapshot_root.canonicalize_norm().ok().as_deref() != Some(snapshot_root)
    {
        return Err("Science runtime snapshot 目录身份或权限不安全".into());
    }
    let mut matching = process_paths
        .iter()
        .filter(|path| path.parent() == Some(snapshot_root));
    let Some(path) = matching.next() else {
        return Ok(None);
    };
    if matching.next().is_some() {
        return Err("Science listener 映射到多个 runtime snapshot，已拒绝恢复".into());
    }
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("Science runtime snapshot 文件名不可识别")?;
    let Some(expected_sha) = name.strip_prefix("claude-science-") else {
        return Err("Science listener executable 不是内容寻址 snapshot".into());
    };
    if expected_sha.len() != 64 || !expected_sha.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("Science runtime snapshot 文件名 SHA-256 非法".into());
    }
    let metadata = path
        .symlink_metadata()
        .map_err(|error| format!("读取 Science runtime snapshot 文件失败：{error}"))?;
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_file()
        || metadata.uid() != uid
        || metadata.permissions().mode() & 0o111 == 0
        || metadata.permissions().mode() & 0o022 != 0
        || !(MIN_SCIENCE_BINARY_SIZE..=MAX_SCIENCE_BINARY_SIZE).contains(&metadata.len())
        || path.canonicalize_norm().ok().as_deref() != Some(path.as_path())
    {
        return Err("Science runtime snapshot 文件身份或权限不安全".into());
    }
    let fingerprint =
        science_executable_fingerprint(path).ok_or("Science runtime snapshot 内容无法确认")?;
    if fingerprint_sha256_hex(&fingerprint) != expected_sha.to_ascii_lowercase() {
        return Err("Science runtime snapshot 文件名与内容 SHA-256 不一致".into());
    }
    if verify_local_identity
        && (!file_is_macho(path) || !official_updated_identity_metadata_matches(path))
    {
        return Err("Science runtime snapshot 未通过 Mach-O/embedded metadata 复核".into());
    }
    Ok(Some(path.clone()))
}

fn official_updated_snapshot_for_listener(
    port: u16,
    snapshot_root: &Path,
    verify_local_identity: bool,
) -> Result<Option<PathBuf>, String> {
    let Some(pid) = unique_listener_pid(port) else {
        return Ok(None);
    };
    let Some(process_paths) = process_text_paths(pid) else {
        return Ok(None);
    };
    official_updated_snapshot_from_process_paths(
        snapshot_root,
        &process_paths,
        verify_local_identity,
    )
}

fn snapshot_science_executable(
    candidate: &Path,
    snapshot_root: &Path,
    source_label: &str,
    expected_source: Option<&ScienceExecutableFingerprint>,
    verify_current_source: impl Fn() -> bool,
    verify_snapshot_identity: impl Fn(&Path) -> bool,
) -> Result<PathBuf, String> {
    let mut source = OpenOptions::new()
        .read(true)
        .custom_flags(crate::platform::O_NOFOLLOW | crate::platform::O_CLOEXEC)
        .open(candidate)
        .map_err(|error| format!("打开 {source_label} Science executable 失败：{error}"))?;
    let source_before = source
        .metadata()
        .map_err(|error| format!("读取 {source_label} Science executable 失败：{error}"))?;
    if !source_before.file_type().is_file()
        || !(MIN_SCIENCE_BINARY_SIZE..=MAX_SCIENCE_BINARY_SIZE).contains(&source_before.len())
    {
        return Err(format!(
            "{source_label} Science executable 大小或文件类型不安全"
        ));
    }

    let snapshot_root = secure_runtime_snapshot_root(snapshot_root)?;
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "系统时间异常，无法创建 Science runtime snapshot")?
        .as_nanos();
    let temporary = snapshot_root.join(format!(
        ".claude-science-{}-{nonce}.tmp",
        std::process::id()
    ));
    let result = (|| -> Result<PathBuf, String> {
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o500)
            .custom_flags(crate::platform::O_NOFOLLOW | crate::platform::O_CLOEXEC)
            .open(&temporary)
            .map_err(|error| format!("创建 Science runtime snapshot 临时文件失败：{error}"))?;
        let mut digest = Sha256::new();
        let mut buffer = [0u8; 64 * 1024];
        loop {
            let count = source
                .read(&mut buffer)
                .map_err(|error| format!("读取 {source_label} Science executable 失败：{error}"))?;
            if count == 0 {
                break;
            }
            digest.update(&buffer[..count]);
            output
                .write_all(&buffer[..count])
                .map_err(|error| format!("写入 Science runtime snapshot 失败：{error}"))?;
        }
        output
            .sync_all()
            .map_err(|error| format!("持久化 Science runtime snapshot 失败：{error}"))?;
        drop(output);

        let source_after = source
            .metadata()
            .map_err(|error| format!("复核 {source_label} Science executable 失败：{error}"))?;
        let current = candidate
            .symlink_metadata()
            .map_err(|error| format!("复核 {source_label} Science executable 路径失败：{error}"))?;
        if source_before.dev() != source_after.dev()
            || source_before.ino() != source_after.ino()
            || source_before.size() != source_after.size()
            || source_before.mtime() != source_after.mtime()
            || source_before.mtime_nsec() != source_after.mtime_nsec()
            || source_before.mode() != source_after.mode()
            || source_after.dev() != current.dev()
            || source_after.ino() != current.ino()
            || !verify_current_source()
        {
            return Err(format!(
                "{source_label} Science executable 在快照期间发生变化；请重试"
            ));
        }
        fs::set_permissions(&temporary, crate::platform::permissions_from_mode(0o500))
            .map_err(|error| format!("收紧 Science runtime snapshot 权限失败：{error}"))?;
        if !verify_snapshot_identity(&temporary) {
            return Err(format!(
                "{source_label} Science executable 未通过 snapshot 身份校验"
            ));
        }

        let sha256: [u8; 32] = digest.finalize().into();
        if expected_source.is_some_and(|expected| {
            expected.device != source_after.dev()
                || expected.inode != source_after.ino()
                || expected.size != source_after.size()
                || expected.modified_seconds != source_after.mtime()
                || expected.modified_nanoseconds != source_after.mtime_nsec()
                || expected.mode != source_after.mode()
                || expected.sha256 != sha256
        }) {
            return Err(format!(
                "{source_label} Science executable 与版本探测时的完整身份不一致"
            ));
        }
        let name: String = sha256.iter().map(|byte| format!("{byte:02x}")).collect();
        let snapshot = snapshot_root.join(format!("claude-science-{name}"));
        let created = match fs::hard_link(&temporary, &snapshot) {
            Ok(()) => true,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => false,
            Err(error) => {
                return Err(format!("提交 Science runtime snapshot 失败：{error}"));
            }
        };
        if !created {
            // Windows 移植：既有快照可能由旧版本以可写属性创建；重申 0o500
            // 收紧（幂等，Unix 上原文件本应已是 0500，重设无害）。
            fs::set_permissions(&snapshot, crate::platform::permissions_from_mode(0o500))
                .map_err(|error| format!("收紧 Science runtime snapshot 权限失败：{error}"))?;
        }
        if created {
            match crate::platform::remove_file_force(&temporary) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(format!(
                        "清理 Science runtime snapshot 临时链接失败：{error}"
                    ))
                }
            }
            // Windows 移植：hard link 共享文件记录，remove_file_force 为删除
            // 而清除的只读属性同样作用于快照；删除临时链接后重新收紧。
            fs::set_permissions(&snapshot, crate::platform::permissions_from_mode(0o500))
                .map_err(|error| format!("收紧 Science runtime snapshot 权限失败：{error}"))?;
        }
        let mut snapshot_metadata = snapshot
            .symlink_metadata()
            .map_err(|error| format!("复核 Science runtime snapshot 身份失败：{error}"))?;
        if snapshot_metadata.nlink() != 1 {
            remove_science_snapshot_temp_links(&snapshot_root, &snapshot)?;
            snapshot_metadata = snapshot
                .symlink_metadata()
                .map_err(|error| format!("复核 Science runtime snapshot 身份失败：{error}"))?;
        }
        if !snapshot_metadata.file_type().is_file()
            || snapshot_metadata.uid() != unsafe { crate::platform::geteuid() }
            || snapshot_metadata.permissions().mode() & 0o777 != 0o500
            || snapshot_metadata.nlink() != 1
            || snapshot_metadata.len() != source_after.size()
        {
            return Err("Science runtime snapshot 不是私有 0500 单链接文件".into());
        }
        let fingerprint = science_executable_fingerprint(&snapshot)
            .ok_or("Science runtime snapshot 无法重新确认")?;
        if fingerprint.sha256 != sha256
            || fingerprint.size != source_after.size()
            || fingerprint.mode & 0o022 != 0
        {
            return Err("Science runtime snapshot 内容或权限与已验证候选不一致".into());
        }
        #[cfg(unix)]
        File::open(&snapshot_root)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| format!("持久化 Science runtime snapshot 目录失败：{error}"))?;
        // Windows 无目录句柄 fsync；数据已随文件 sync_all 落盘（注释降级）。
        Ok(snapshot)
    })();
    let _ = crate::platform::remove_file_force(&temporary);
    result
}

fn remove_science_snapshot_temp_links(root: &Path, snapshot: &Path) -> Result<(), String> {
    let snapshot_metadata = snapshot
        .symlink_metadata()
        .map_err(|error| format!("读取 Science runtime snapshot 失败：{error}"))?;
    let mut entries = fs::read_dir(root)
        .map_err(|error| format!("枚举 Science runtime snapshot 临时文件失败：{error}"))?;
    while let Some(entry) = entries
        .next()
        .transpose()
        .map_err(|error| format!("读取 Science runtime snapshot 临时文件失败：{error}"))?
    {
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if !name.starts_with(".claude-science-") || !name.ends_with(".tmp") {
            continue;
        }
        let metadata = match entry.path().symlink_metadata() {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(format!(
                    "检查 Science runtime snapshot 临时文件失败：{error}"
                ))
            }
        };
        if metadata.file_type().is_file()
            && metadata.uid() == unsafe { crate::platform::geteuid() }
            && metadata.dev() == snapshot_metadata.dev()
            && metadata.ino() == snapshot_metadata.ino()
        {
            match fs::remove_file(entry.path()) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(format!(
                        "清理 Science runtime snapshot 临时链接失败：{error}"
                    ))
                }
            }
        }
    }
    Ok(())
}

fn official_updated_snapshot_for_home(
    home: &Path,
    snapshot_root: &Path,
    verify_local_identity: bool,
) -> Result<Option<PathBuf>, String> {
    #[cfg(test)]
    let verify_local_identity =
        verify_local_identity && !fake_science_updater_identity_armed_for_current_thread();
    let candidate = home.join(OFFICIAL_UPDATED_RUNTIME_RELATIVE);
    if !fixed_path_entry_exists(&candidate, "updater Science executable")? {
        return Ok(None);
    }
    let candidate = official_updated_science_bin_for_home(home, false).ok_or(
        "检测到 updater Science executable，但固定路径、属主或权限校验未通过；已拒绝静默回退旧 App",
    )?;
    snapshot_science_executable(
        &candidate,
        snapshot_root,
        "updater",
        None,
        || {
            official_updated_science_bin_for_home(home, false).as_deref()
                == Some(candidate.as_path())
        },
        |snapshot| {
            !verify_local_identity
                || (file_is_macho(snapshot) && official_updated_identity_metadata_matches(snapshot))
        },
    )
    .map(Some)
}

fn installed_app_snapshot(
    candidate: &Path,
    expected_source: &ScienceExecutableFingerprint,
    snapshot_root: &Path,
) -> Result<Option<PathBuf>, String> {
    if !fixed_path_entry_exists(candidate, "Claude Science App executable")? {
        return Ok(None);
    }
    if !is_executable_file(candidate) {
        return Err("Claude Science App executable 路径不安全".into());
    }
    snapshot_science_executable(
        candidate,
        snapshot_root,
        "installed App",
        Some(expected_source),
        || is_executable_file(candidate),
        |_| true,
    )
    .map(Some)
}

/// 平台感知的「已安装 Claude Science App」固定路径。
/// Unix 沿用编译期常量 SCIENCE_BIN（macOS App Bundle 内的 CLI）。
/// Windows 安装器布局未知，按常见 NSIS/Electron 布局探测候选；可用
/// `CSSWITCH_SCIENCE_APP_BIN` 显式指定绝对路径覆盖。找不到返回 None。
fn installed_app_fixed_bin() -> Option<PathBuf> {
    #[cfg(unix)]
    {
        Some(PathBuf::from(SCIENCE_BIN))
    }
    #[cfg(not(unix))]
    {
        if let Some(explicit) = std::env::var_os("CSSWITCH_SCIENCE_APP_BIN") {
            let path = PathBuf::from(explicit);
            if path.is_absolute() {
                return Some(path);
            }
        }
        let local = std::env::var_os("LOCALAPPDATA")?;
        let base = PathBuf::from(local).join("Programs");
        let candidates = [
            base.join("Claude Science")
                .join("resources")
                .join("bin")
                .join("claude-science.exe"),
            base.join("Claude Science").join("claude-science.exe"),
            base.join("claude-science").join("claude-science.exe"),
            base.join("ClaudeScience").join("claude-science.exe"),
        ];
        candidates.into_iter().find(|c| c.is_file())
    }
}

fn official_updated_science_bin() -> Result<Option<PathBuf>, String> {
    let Some(home) = std::env::var_os("HOME").map(PathBuf::from) else {
        return Ok(None);
    };
    let snapshot_root = config::default_dir().join(OFFICIAL_UPDATED_SNAPSHOT_DIR);
    official_updated_snapshot_for_home(&home, &snapshot_root, true)
}

fn science_executable_fingerprint(path: &Path) -> Option<ScienceExecutableFingerprint> {
    if !is_executable_file(path) {
        return None;
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(crate::platform::O_NOFOLLOW | crate::platform::O_CLOEXEC)
        .open(path)
        .ok()?;
    let before = file.metadata().ok()?;
    if !before.file_type().is_file() || !crate::platform::mode_has_exec(&before) {
        return None;
    }
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).ok()?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    let after = file.metadata().ok()?;
    let path_metadata = path.symlink_metadata().ok()?;
    if path_metadata.file_type().is_symlink()
        || before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.size() != after.size()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.mode() != after.mode()
        || after.dev() != path_metadata.dev()
        || after.ino() != path_metadata.ino()
    {
        return None;
    }
    Some(ScienceExecutableFingerprint {
        device: after.dev(),
        inode: after.ino(),
        size: after.size(),
        modified_seconds: after.mtime(),
        modified_nanoseconds: after.mtime_nsec(),
        mode: after.mode(),
        sha256: digest.finalize().into(),
    })
}

fn cached_science_bin(data_dir: &Path) -> PathBuf {
    data_dir.join("bin").join("claude-science")
}

fn safe_science_version_with_timeout(path: &Path, timeout: Duration) -> Option<String> {
    let out = run_science_control_command(path, &sandbox_home(), timeout, 1024, 1024, |command| {
        command.arg("--version");
    })?;
    if !out.status.success() {
        return None;
    }
    let value = String::from_utf8(out.stdout).ok()?;
    let value = value.lines().next()?.trim();
    if value.is_empty()
        || value.len() > 160
        || !value
            .bytes()
            .all(|byte| byte == b' ' || (0x21..=0x7e).contains(&byte))
    {
        return None;
    }
    Some(value.to_string())
}

fn safe_science_version(path: &Path) -> Option<String> {
    safe_science_version_with_timeout(path, SCIENCE_VERSION_TIMEOUT)
}

fn runtime_identity(
    path: PathBuf,
    source: ScienceRuntimeSource,
    version_cache: &ScienceVersionCache,
) -> Option<ScienceRuntimeIdentity> {
    for _ in 0..2 {
        let before = science_executable_fingerprint(&path)?;
        let version = version_cache.version(&path)?;
        let after = science_executable_fingerprint(&path)?;
        if before == after {
            return Some(ScienceRuntimeIdentity {
                path,
                source,
                version: Some(version),
                fingerprint: after,
                adoption_attempt_id: None,
            });
        }
        let _ = version_cache.force_refresh(&path);
    }
    None
}

pub(crate) fn runtime_identity_is_current(runtime: &ScienceRuntimeIdentity) -> bool {
    runtime.is_current()
}

pub(crate) fn runtime_identity_from_prior_recipe(
    recipe: &config::RuntimePriorScienceRecipe,
) -> Result<ScienceRuntimeIdentity, String> {
    runtime_identity_from_durable_parts(
        &recipe.runtime_path,
        &recipe.runtime_source,
        recipe.runtime_version.clone(),
        &recipe.runtime_fingerprint,
        recipe.runtime_adoption_attempt_id.clone(),
    )
}

pub(crate) fn runtime_identity_from_durable_parts(
    runtime_path: &Path,
    runtime_source: &str,
    runtime_version: Option<String>,
    runtime_fingerprint: &str,
    recipe_adoption_attempt_id: Option<String>,
) -> Result<ScienceRuntimeIdentity, String> {
    let source = match runtime_source {
        "explicit" => ScienceRuntimeSource::Explicit,
        "official_updated" => ScienceRuntimeSource::OfficialUpdated,
        "installed_app" => ScienceRuntimeSource::InstalledApp,
        "cached_once" => ScienceRuntimeSource::CachedOnce,
        _ => return Err("durable prior Science recipe has an unknown runtime source".into()),
    };
    let canonical = runtime_path
        .canonicalize_norm()
        .map_err(|_| "durable prior Science runtime is unavailable")?;
    if canonical != runtime_path {
        return Err("durable prior Science runtime path is not canonical".into());
    }
    let fingerprint = science_executable_fingerprint(&canonical)
        .ok_or("durable prior Science runtime identity is unavailable")?;
    if recipe_adoption_attempt_id
        .as_deref()
        .is_some_and(|value| !valid_lower_hex(value, 32))
    {
        return Err("durable prior Science runtime adoption attempt id is invalid".into());
    }
    if source == ScienceRuntimeSource::OfficialUpdated
        && (!file_is_macho(&canonical) || !official_updated_identity_metadata_matches(&canonical))
    {
        return Err("durable updater Science runtime embedded identity is unavailable".into());
    }
    let runtime = ScienceRuntimeIdentity {
        path: canonical,
        source,
        version: runtime_version,
        fingerprint,
        adoption_attempt_id: recipe_adoption_attempt_id,
    };
    if runtime.environment_transaction_id() != runtime_fingerprint {
        return Err("durable prior Science runtime fingerprint changed".into());
    }
    Ok(runtime)
}

fn explicit_science_bin() -> Result<Option<PathBuf>, String> {
    let Some(path) = std::env::var_os("SCIENCE_BIN").map(PathBuf::from) else {
        return Ok(None);
    };
    if !is_explicit_executable_file(&path) {
        return Err("显式 SCIENCE_BIN 不是安全的绝对可执行文件；已拒绝回退".into());
    }
    Ok(Some(path))
}

fn preferred_science_runtime_candidate(
    version_cache: &ScienceVersionCache,
    allow_installed_app_fallback: bool,
) -> Result<Option<ScienceRuntimeIdentity>, ScienceCandidateRejection> {
    if std::env::var_os("SCIENCE_BIN").is_some() {
        let path = explicit_science_bin()
            .map_err(|message| ScienceCandidateRejection {
                source: ScienceRuntimeSource::Explicit,
                code: ScienceAdoptionRejectionCode::PathValidationFailed,
                message,
            })?
            .ok_or_else(|| ScienceCandidateRejection {
                source: ScienceRuntimeSource::Explicit,
                code: ScienceAdoptionRejectionCode::RuntimeUnavailable,
                message: "显式 SCIENCE_BIN 不可用；已拒绝回退".into(),
            })?;
        return runtime_identity(path, ScienceRuntimeSource::Explicit, version_cache)
            .map(Some)
            .ok_or_else(|| ScienceCandidateRejection {
                source: ScienceRuntimeSource::Explicit,
                code: ScienceAdoptionRejectionCode::VersionProbeFailed,
                message: "显式 SCIENCE_BIN 未通过版本预检；已拒绝回退".into(),
            });
    }

    let official_updated =
        official_updated_science_bin().map_err(|message| ScienceCandidateRejection {
            source: ScienceRuntimeSource::OfficialUpdated,
            code: ScienceAdoptionRejectionCode::LocalIdentityValidationFailed,
            message,
        })?;
    if let Some(path) = official_updated {
        return runtime_identity(path, ScienceRuntimeSource::OfficialUpdated, version_cache)
            .map(Some)
            .ok_or_else(|| ScienceCandidateRejection {
                source: ScienceRuntimeSource::OfficialUpdated,
                code: ScienceAdoptionRejectionCode::VersionProbeFailed,
                message: "updater Science snapshot 未通过版本预检；已拒绝回退旧 App".into(),
            });
    }
    if !allow_installed_app_fallback {
        return Ok(None);
    }

    // Windows 移植：固定路径按平台解析；找不到已安装 App 时安静返回 None
    //（由上层报告「未安装」），不再把 macOS 路径常量硬套到 Windows 触发
    // 「固定路径不是绝对路径」。
    let app = match installed_app_fixed_bin() {
        Some(path) => path,
        None => return Ok(None),
    };
    if let Some(runtime) = runtime_identity(
        app.clone(),
        ScienceRuntimeSource::InstalledApp,
        version_cache,
    ) {
        return Ok(Some(runtime));
    }
    match fixed_path_entry_exists(&app, "Claude Science App executable") {
        Ok(true) => {
            return Err(ScienceCandidateRejection {
                source: ScienceRuntimeSource::InstalledApp,
                code: ScienceAdoptionRejectionCode::VersionProbeFailed,
                message: "Claude Science App executable 未通过版本预检".into(),
            })
        }
        Ok(false) => {}
        Err(message) => {
            return Err(ScienceCandidateRejection {
                source: ScienceRuntimeSource::InstalledApp,
                code: ScienceAdoptionRejectionCode::LocalIdentityValidationFailed,
                message,
            })
        }
    }
    Ok(None)
}

#[cfg(test)]
fn science_runtime_preflight_for_paths(
    data_dir: &Path,
    explicit_bin: Option<&Path>,
    app_bin: &Path,
) -> Result<Value, String> {
    science_runtime_preflight_for_paths_cached(
        data_dir,
        explicit_bin,
        None,
        app_bin,
        &ScienceVersionCache::default(),
    )
}

#[cfg(test)]
fn science_runtime_preflight_for_paths_with_updated(
    data_dir: &Path,
    explicit_bin: Option<&Path>,
    official_updated_bin: Option<&Path>,
    app_bin: &Path,
) -> Result<Value, String> {
    science_runtime_preflight_for_paths_cached(
        data_dir,
        explicit_bin,
        official_updated_bin,
        app_bin,
        &ScienceVersionCache::default(),
    )
}

fn science_runtime_preflight_for_paths_cached(
    data_dir: &Path,
    explicit_bin: Option<&Path>,
    official_updated_bin: Option<&Path>,
    app_bin: &Path,
    version_cache: &ScienceVersionCache,
) -> Result<Value, String> {
    if let Some(bin) = explicit_bin {
        if !is_explicit_executable_file(bin) {
            return Err("显式 SCIENCE_BIN 不是安全的绝对可执行文件；已拒绝回退".into());
        }
        let runtime = runtime_identity(
            bin.to_path_buf(),
            ScienceRuntimeSource::Explicit,
            version_cache,
        )
        .ok_or("显式 SCIENCE_BIN 未通过版本预检；已拒绝回退")?;
        return Ok(json!({
            "status": "installed_ready",
            "selected_source": runtime.source.code(),
            "selected_version": runtime.version,
            "cached_version": Value::Null,
            "download_url": SCIENCE_DOWNLOAD_URL,
        }));
    }
    if let Some(bin) = official_updated_bin {
        let runtime = runtime_identity(
            bin.to_path_buf(),
            ScienceRuntimeSource::OfficialUpdated,
            version_cache,
        )
        .ok_or("updater Science snapshot 未通过版本预检；已拒绝回退旧 App")?;
        return Ok(json!({
            "status": "installed_ready",
            "selected_source": runtime.source.code(),
            "selected_version": runtime.version,
            "cached_version": Value::Null,
            "download_url": SCIENCE_DOWNLOAD_URL,
        }));
    }
    if let Some(runtime) = runtime_identity(
        app_bin.to_path_buf(),
        ScienceRuntimeSource::InstalledApp,
        version_cache,
    ) {
        return Ok(json!({
            "status": "installed_ready",
            "selected_source": runtime.source.code(),
            "selected_version": runtime.version,
            "cached_version": Value::Null,
            "download_url": SCIENCE_DOWNLOAD_URL,
        }));
    }
    let cached = cached_science_bin(data_dir);
    let cached_version = version_cache.version(&cached);
    if let Some(version) = cached_version {
        return Ok(json!({
            "status": "cached_choice_required",
            "selected_source": Value::Null,
            "selected_version": Value::Null,
            "cached_version": version,
            "download_url": SCIENCE_DOWNLOAD_URL,
        }));
    }
    Ok(json!({
        "status": "missing",
        "selected_source": Value::Null,
        "selected_version": Value::Null,
        "cached_version": Value::Null,
        "download_url": SCIENCE_DOWNLOAD_URL,
    }))
}

pub(crate) fn science_runtime_preflight(
    version_cache: &ScienceVersionCache,
    _confirmed_stopped: Option<&ScienceRuntimeIdentity>,
) -> Result<Value, String> {
    if let Ok(cfg) = config::load_from(&config::default_dir()) {
        let (state, runtime) = ScienceHostAdapter::probe_cached(cfg.sandbox_port, version_cache)?;
        if state == SandboxScienceState::RunningHealthy {
            let runtime = runtime.ok_or("Science 状态为运行中，但无法确认其 binary 身份")?;
            let adoption_record_status = if reconcile_current_science_runtime_adoption(
                &runtime,
                cfg.runtime_binding.as_ref(),
            )
            .is_ok()
            {
                "recorded"
            } else {
                "degraded"
            };
            return Ok(json!({
                "status": "installed_ready",
                "selected_source": runtime.source.code(),
                "selected_version": runtime.version,
                "cached_version": Value::Null,
                "download_url": SCIENCE_DOWNLOAD_URL,
                "adoption_record_status": adoption_record_status,
            }));
        }
    }
    if std::env::var_os("SCIENCE_BIN").is_some() {
        match preferred_science_runtime_candidate(version_cache, true) {
            Ok(Some(runtime)) => {
                return Ok(json!({
                    "status": "installed_ready",
                    "selected_source": runtime.source.code(),
                    "selected_version": runtime.version,
                    "cached_version": Value::Null,
                    "download_url": SCIENCE_DOWNLOAD_URL,
                    "adoption_record_status": "explicit_override",
                }))
            }
            Err(rejection) => {
                let message = rejection.message.clone();
                let _ = record_rejected_science_runtime_attempt(None, rejection);
                return Err(message);
            }
            Ok(None) => {}
        }
    }
    match resolve_active_or_bootstrap_science_runtime(version_cache) {
        Ok(Some(runtime)) => {
            return Ok(json!({
                "status": "installed_ready",
                "selected_source": runtime.source.code(),
                "selected_version": runtime.version,
                "cached_version": Value::Null,
                "download_url": SCIENCE_DOWNLOAD_URL,
                "adoption_record_status": "active_selection",
            }))
        }
        Ok(None) => {}
        Err(error) => return Err(error),
    }
    let data_dir = sandbox_data_dir();
    science_runtime_preflight_for_paths_cached(
        &data_dir,
        None,
        None,
        Path::new(SCIENCE_BIN),
        version_cache,
    )
}

#[cfg(test)]
fn select_science_runtime_for_paths(
    data_dir: &Path,
    explicit_bin: Option<&Path>,
    app_bin: &Path,
    choice: Option<&str>,
) -> Result<ScienceRuntimeIdentity, String> {
    select_science_runtime_for_paths_cached(
        data_dir,
        explicit_bin,
        None,
        app_bin,
        choice,
        &ScienceVersionCache::default(),
    )
}

#[cfg(test)]
fn select_science_runtime_for_paths_with_updated(
    data_dir: &Path,
    explicit_bin: Option<&Path>,
    official_updated_bin: Option<&Path>,
    app_bin: &Path,
    choice: Option<&str>,
) -> Result<ScienceRuntimeIdentity, String> {
    select_science_runtime_for_paths_cached(
        data_dir,
        explicit_bin,
        official_updated_bin,
        app_bin,
        choice,
        &ScienceVersionCache::default(),
    )
}

#[cfg(test)]
fn select_science_runtime_for_paths_cached(
    data_dir: &Path,
    explicit_bin: Option<&Path>,
    official_updated_bin: Option<&Path>,
    app_bin: &Path,
    choice: Option<&str>,
    version_cache: &ScienceVersionCache,
) -> Result<ScienceRuntimeIdentity, String> {
    if let Some(bin) = explicit_bin {
        if !is_explicit_executable_file(bin) {
            return Err("显式 SCIENCE_BIN 不是安全的绝对可执行文件；已拒绝回退".into());
        }
        return runtime_identity(
            bin.to_path_buf(),
            ScienceRuntimeSource::Explicit,
            version_cache,
        )
        .ok_or_else(|| "显式 SCIENCE_BIN 未通过版本预检；已拒绝回退".to_string());
    }
    if let Some(bin) = official_updated_bin {
        return runtime_identity(
            bin.to_path_buf(),
            ScienceRuntimeSource::OfficialUpdated,
            version_cache,
        )
        .ok_or_else(|| "updater Science snapshot 未通过版本预检；已拒绝回退旧 App".to_string());
    }
    if let Some(runtime) = runtime_identity(
        app_bin.to_path_buf(),
        ScienceRuntimeSource::InstalledApp,
        version_cache,
    ) {
        return Ok(runtime);
    }
    let cached = cached_science_bin(data_dir);
    let cached_version = version_cache.version(&cached);
    if choice == Some(CACHED_ONCE_CHOICE) {
        let _ = cached_version
            .ok_or("缓存 Science 版本无法确认；请安装或更新 Claude Science 后再试")?;
        return runtime_identity(cached, ScienceRuntimeSource::CachedOnce, version_cache)
            .ok_or("缓存 Science 文件在版本确认期间发生变化；已拒绝启动".into());
    }
    if cached_version.is_some() {
        return Err("SCIENCE_RUNTIME_CHOICE_REQUIRED：请明确选择仅本次使用缓存版本，或安装/更新 Claude Science".into());
    }
    Err("找不到可用的 Claude Science App；请先安装或更新 Claude Science".into())
}

pub(crate) fn select_science_runtime_cached(
    choice: Option<&str>,
    version_cache: &ScienceVersionCache,
) -> Result<ScienceRuntimeIdentity, String> {
    let data_dir = sandbox_data_dir();
    if std::env::var_os("SCIENCE_BIN").is_some() {
        match preferred_science_runtime_candidate(version_cache, true) {
            Ok(Some(mut runtime)) => {
                bind_selected_science_runtime_attempt(&mut runtime)?;
                return Ok(runtime);
            }
            Err(rejection) => {
                let message = rejection.message.clone();
                let _ = record_rejected_science_runtime_attempt(None, rejection);
                return Err(message);
            }
            Ok(None) => {}
        }
    } else if let Some(mut runtime) = resolve_active_or_bootstrap_science_runtime(version_cache)? {
        bind_selected_science_runtime_attempt(&mut runtime)?;
        return Ok(runtime);
    }
    let cached = cached_science_bin(&data_dir);
    let cached_version = version_cache.version(&cached);
    if choice == Some(CACHED_ONCE_CHOICE) {
        let _ = cached_version.ok_or_else(|| {
            let rejection = ScienceCandidateRejection {
                source: ScienceRuntimeSource::CachedOnce,
                code: ScienceAdoptionRejectionCode::VersionProbeFailed,
                message: "缓存 Science 版本无法确认；请安装或更新 Claude Science 后再试".into(),
            };
            let _ = record_rejected_science_runtime_attempt(None, rejection);
            "缓存 Science 版本无法确认；请安装或更新 Claude Science 后再试"
        })?;
        let mut runtime = runtime_identity(cached, ScienceRuntimeSource::CachedOnce, version_cache)
            .ok_or("缓存 Science 文件在版本确认期间发生变化；已拒绝启动")?;
        bind_selected_science_runtime_attempt(&mut runtime)?;
        return Ok(runtime);
    }
    if cached_version.is_some() {
        let rejection = ScienceCandidateRejection {
            source: ScienceRuntimeSource::CachedOnce,
            code: ScienceAdoptionRejectionCode::CachedChoiceRequired,
            message: "SCIENCE_RUNTIME_CHOICE_REQUIRED：请明确选择仅本次使用缓存版本，或安装/更新 Claude Science"
                .into(),
        };
        let _ = record_rejected_science_runtime_attempt(None, rejection);
        return Err("SCIENCE_RUNTIME_CHOICE_REQUIRED：请明确选择仅本次使用缓存版本，或安装/更新 Claude Science".into());
    }
    let rejection = ScienceCandidateRejection {
        source: ScienceRuntimeSource::InstalledApp,
        code: ScienceAdoptionRejectionCode::RuntimeUnavailable,
        message: "找不到可用的 Claude Science App；请先安装或更新 Claude Science".into(),
    };
    let _ = record_rejected_science_runtime_attempt(None, rejection);
    Err("找不到可用的 Claude Science App；请先安装或更新 Claude Science".into())
}

fn runtime_probe_candidates(
    port: u16,
    version_cache: &ScienceVersionCache,
) -> Result<Vec<ScienceRuntimeIdentity>, String> {
    if let Some(explicit) = explicit_science_bin()? {
        return Ok(
            runtime_identity(explicit, ScienceRuntimeSource::Explicit, version_cache)
                .into_iter()
                .collect(),
        );
    }
    if let Some((record, _)) = read_managed_launch_snapshot_result()? {
        if record.port == port {
            if let (Some(source), Some(version)) = (
                record.runtime_source.as_deref(),
                record.runtime_version.clone(),
            ) {
                if let Ok(runtime) = runtime_identity_from_durable_parts(
                    &record.runtime_path,
                    source,
                    Some(version),
                    &record.runtime_sha256,
                    record.adoption_attempt_id.clone(),
                ) {
                    return Ok(vec![runtime]);
                }
            }
        }
    }
    if let Some(active) = active_science_runtime()? {
        return Ok(vec![active]);
    }
    let mut candidates = Vec::new();
    #[cfg(test)]
    if fake_science_updater_identity_armed_for_current_thread() {
        if let Some((record, _)) = read_managed_launch_snapshot_result()? {
            if record.port == port
                && record.runtime_source.as_deref()
                    == Some(ScienceRuntimeSource::OfficialUpdated.code())
            {
                if let Some(runtime) = runtime_identity(
                    record.runtime_path,
                    ScienceRuntimeSource::OfficialUpdated,
                    version_cache,
                ) {
                    candidates.push(runtime);
                    return Ok(candidates);
                }
            }
        }
    }
    let snapshot_root = config::default_dir().join(OFFICIAL_UPDATED_SNAPSHOT_DIR);
    if let Some(snapshot) = official_updated_snapshot_for_listener(port, &snapshot_root, true)? {
        if let Some(runtime) = runtime_identity(
            snapshot,
            ScienceRuntimeSource::OfficialUpdated,
            version_cache,
        ) {
            candidates.push(runtime);
        }
    }
    let app = PathBuf::from(SCIENCE_BIN);
    if let Some(app) = runtime_identity(app, ScienceRuntimeSource::InstalledApp, version_cache) {
        candidates.push(app);
    }
    let cached = cached_science_bin(&sandbox_data_dir());
    if let Some(cached) = runtime_identity(cached, ScienceRuntimeSource::CachedOnce, version_cache)
    {
        candidates.push(cached);
    }
    Ok(candidates)
}
