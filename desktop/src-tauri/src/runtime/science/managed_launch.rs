fn managed_launch_record_for(
    port: u16,
    listener_pid: u32,
    runtime: &ScienceRuntimeIdentity,
    launch_id: Option<&str>,
    adoption_attempt_id: Option<&str>,
) -> Option<ScienceManagedLaunchRecord> {
    if !runtime.is_current() {
        return None;
    }
    let runtime_path = runtime.path.canonicalize_norm().ok()?;
    if runtime_path != runtime.path {
        return None;
    }
    let process_start = process_start_identity(listener_pid)?;
    let (data_dir, data_dir_device, data_dir_inode) = data_dir_identity()?;
    let fingerprint = &runtime.fingerprint;
    if adoption_attempt_id.is_some_and(|value| !valid_lower_hex(value, 32)) {
        return None;
    }
    Some(ScienceManagedLaunchRecord {
        schema_version: if adoption_attempt_id.is_some() { 2 } else { 1 },
        launch_id: managed_launch_id(launch_id),
        port,
        listener_pid,
        process_start,
        runtime_path,
        runtime_device: fingerprint.device,
        runtime_inode: fingerprint.inode,
        runtime_size: fingerprint.size,
        runtime_modified_seconds: fingerprint.modified_seconds,
        runtime_modified_nanoseconds: fingerprint.modified_nanoseconds,
        runtime_mode: fingerprint.mode,
        runtime_sha256: fingerprint_sha256_hex(fingerprint),
        runtime_source: adoption_attempt_id.map(|_| runtime.source.code().to_string()),
        runtime_version: adoption_attempt_id.and_then(|_| runtime.version.clone()),
        adoption_attempt_id: adoption_attempt_id.map(str::to_string),
        data_dir,
        data_dir_device,
        data_dir_inode,
    })
}

fn managed_launch_id(durable: Option<&str>) -> String {
    durable.map(str::to_string).unwrap_or_else(config::new_id)
}

fn record_matches_runtime(
    record: &ScienceManagedLaunchRecord,
    port: u16,
    runtime: &ScienceRuntimeIdentity,
) -> bool {
    let Some((data_dir, data_dir_device, data_dir_inode)) = data_dir_identity() else {
        return false;
    };
    let fingerprint = &runtime.fingerprint;
    let provenance_matches = match record.schema_version {
        1 => {
            record.runtime_source.is_none()
                && record.runtime_version.is_none()
                && record.adoption_attempt_id.is_none()
        }
        2 => {
            record.runtime_source.as_deref() == Some(runtime.source.code())
                && record.runtime_version == runtime.version
                && record
                    .adoption_attempt_id
                    .as_deref()
                    .is_some_and(|value| valid_lower_hex(value, 32))
                && runtime
                    .adoption_attempt_id
                    .as_ref()
                    .is_none_or(|value| Some(value) == record.adoption_attempt_id.as_ref())
        }
        _ => false,
    };
    provenance_matches
        && record.launch_id.len() >= 16
        && record.launch_id.len() <= 128
        && record
            .launch_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        && record.port == port
        && record.listener_pid > 1
        && record.runtime_path == runtime.path
        && record.runtime_device == fingerprint.device
        && record.runtime_inode == fingerprint.inode
        && record.runtime_size == fingerprint.size
        && record.runtime_modified_seconds == fingerprint.modified_seconds
        && record.runtime_modified_nanoseconds == fingerprint.modified_nanoseconds
        && record.runtime_mode == fingerprint.mode
        && record.runtime_sha256 == fingerprint_sha256_hex(fingerprint)
        && record.data_dir == data_dir
        && record.data_dir_device == data_dir_device
        && record.data_dir_inode == data_dir_inode
}

fn managed_launch_file_identity(metadata: &fs::Metadata) -> ManagedLaunchFileIdentity {
    ManagedLaunchFileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        size: metadata.len(),
        modified_seconds: metadata.mtime(),
        modified_nanoseconds: metadata.mtime_nsec(),
        mode: metadata.permissions().mode(),
        uid: metadata.uid(),
    }
}

fn private_managed_launch_file(metadata: &fs::Metadata) -> bool {
    metadata.file_type().is_file()
        && metadata.uid() == unsafe { crate::platform::geteuid() }
        && metadata.permissions().mode() & 0o077 == 0
        && metadata.len() > 0
        && metadata.len() <= MAX_MANAGED_LAUNCH_BYTES
}

fn valid_managed_launch_record_structure(record: &ScienceManagedLaunchRecord) -> bool {
    let provenance_valid = match record.schema_version {
        1 => {
            record.runtime_source.is_none()
                && record.runtime_version.is_none()
                && record.adoption_attempt_id.is_none()
        }
        2 => {
            record.runtime_source.as_deref().is_some_and(|source| {
                matches!(
                    source,
                    "explicit" | "official_updated" | "installed_app" | "cached_once"
                )
            }) && record.runtime_version.as_deref().is_some_and(|version| {
                !version.is_empty()
                    && version.len() <= 1024
                    && !version
                        .bytes()
                        .any(|byte| byte == 0 || byte == b'\n' || byte == b'\r')
            }) && record
                .adoption_attempt_id
                .as_deref()
                .is_some_and(|value| valid_lower_hex(value, 32))
        }
        _ => false,
    };
    provenance_valid
        && record.launch_id.len() >= 16
        && record.launch_id.len() <= 128
        && record
            .launch_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        && record.port != 0
        && record.listener_pid > 1
        && !record.process_start.is_empty()
        && record.process_start.len() <= 128
        && record.runtime_path.is_absolute()
        && record.runtime_size > 0
        && valid_lower_hex(&record.runtime_sha256, 64)
        && record.data_dir.is_absolute()
}

fn read_managed_launch_snapshot_at_result(
    path: &Path,
) -> Result<Option<(ScienceManagedLaunchRecord, ManagedLaunchFileIdentity)>, String> {
    let metadata = match path.symlink_metadata() {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("无法读取 Science managed launch 记录身份：{error}")),
    };
    let parent = path
        .parent()
        .ok_or("Science managed launch 记录路径无父目录")?;
    let parent_metadata = parent
        .symlink_metadata()
        .map_err(|error| format!("无法读取 Science managed launch 记录目录身份：{error}"))?;
    if !parent_metadata.file_type().is_dir()
        || parent_metadata.uid() != unsafe { crate::platform::geteuid() }
        || parent_metadata.permissions().mode() & 0o022 != 0
    {
        return Err("Science managed launch 记录目录身份不安全".into());
    }
    if !private_managed_launch_file(&metadata) {
        return Err("Science managed launch 记录不是安全私有普通文件或大小非法".into());
    }
    let expected_file = managed_launch_file_identity(&metadata);
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(crate::platform::O_NOFOLLOW | crate::platform::O_CLOEXEC)
        .open(path)
        .map_err(|error| format!("无法安全打开 Science managed launch 记录：{error}"))?;
    let after = file
        .metadata()
        .map_err(|error| format!("无法复核 Science managed launch 记录身份：{error}"))?;
    if !private_managed_launch_file(&after) || managed_launch_file_identity(&after) != expected_file
    {
        return Err("Science managed launch 记录在打开期间发生身份变化".into());
    }
    #[cfg(test)]
    if let Some(barrier_dir) = std::env::var_os("CSSWITCH_TEST_MANAGED_LAUNCH_READ_BARRIER") {
        let barrier_dir = PathBuf::from(barrier_dir);
        fs::write(barrier_dir.join("ready"), b"ready")
            .map_err(|error| format!("无法发布 Science managed launch 测试读取屏障：{error}"))?;
        let mut released = false;
        for _ in 0..500 {
            if barrier_dir.join("continue").is_file() {
                released = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        if !released {
            return Err("Science managed launch 测试读取屏障未释放".into());
        }
    }
    let mut bytes = Vec::with_capacity(
        usize::try_from(expected_file.size.min(MAX_MANAGED_LAUNCH_BYTES + 1))
            .map_err(|_| "Science managed launch 记录大小无法表示")?,
    );
    (&mut file)
        .take(MAX_MANAGED_LAUNCH_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("无法读取 Science managed launch 记录：{error}"))?;
    #[cfg(test)]
    MANAGED_LAUNCH_LAST_READ_BYTES.store(bytes.len() as u64, Ordering::SeqCst);
    let final_metadata = file
        .metadata()
        .map_err(|error| format!("无法完成 Science managed launch 记录身份复核：{error}"))?;
    if !private_managed_launch_file(&final_metadata)
        || managed_launch_file_identity(&final_metadata) != expected_file
        || bytes.len() as u64 != expected_file.size
        || bytes.len() as u64 > MAX_MANAGED_LAUNCH_BYTES
    {
        return Err("Science managed launch 记录在读取期间发生变化或超过上限".into());
    }
    let record = serde_json::from_slice(&bytes)
        .map_err(|error| format!("Science managed launch 记录无法解析：{error}"))?;
    if !valid_managed_launch_record_structure(&record) {
        return Err("Science managed launch 记录 schema 或字段语义非法".into());
    }
    Ok(Some((record, expected_file)))
}

fn read_managed_launch_snapshot_at(
    path: &Path,
) -> Option<(ScienceManagedLaunchRecord, ManagedLaunchFileIdentity)> {
    read_managed_launch_snapshot_at_result(path).ok().flatten()
}

fn read_managed_launch_snapshot() -> Option<(ScienceManagedLaunchRecord, ManagedLaunchFileIdentity)>
{
    read_managed_launch_snapshot_at(&managed_launch_path())
}

fn read_managed_launch_snapshot_result(
) -> Result<Option<(ScienceManagedLaunchRecord, ManagedLaunchFileIdentity)>, String> {
    read_managed_launch_snapshot_at_result(&managed_launch_path())
}

pub(crate) fn prior_restart_receipt_is_absent(
    recipe: &config::RuntimePriorScienceRecipe,
    runtime: &ScienceRuntimeIdentity,
) -> bool {
    prior_restart_receipt_is_absent_at(recipe, runtime, &managed_launch_path())
}

fn prior_restart_receipt_is_absent_at(
    recipe: &config::RuntimePriorScienceRecipe,
    runtime: &ScienceRuntimeIdentity,
    receipt_path: &Path,
) -> bool {
    recipe.runtime_path == runtime.path
        && recipe.runtime_source == runtime.source.code()
        && recipe.runtime_version == runtime.version
        && runtime.environment_transaction_id() == recipe.runtime_fingerprint
        && matches!(
            fs::symlink_metadata(receipt_path),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound
        )
}

pub(crate) fn hydrate_runtime_from_v2_managed_launch(
    port: u16,
    runtime: &mut ScienceRuntimeIdentity,
    launch_id: &str,
) -> Result<(), String> {
    let token = managed_launch_token(port, runtime)
        .ok_or("Science prior restart managed launch receipt 不可用")?;
    if token.record.schema_version != 2 || token.record.launch_id != launch_id {
        return Err("Science prior restart managed launch V2 identity 不匹配".into());
    }
    hydrate_runtime_adoption_from_managed_launch(&token, runtime)?;
    if runtime.adoption_attempt_id.is_none()
        || !managed_launch_token_is_current_for_runtime(&token, runtime)
    {
        return Err("Science prior restart managed launch V2 provenance 已变化".into());
    }
    Ok(())
}

#[cfg(test)]
fn read_managed_launch_record() -> Option<ScienceManagedLaunchRecord> {
    read_managed_launch_snapshot().map(|(record, _)| record)
}

fn write_managed_launch_record(record: &ScienceManagedLaunchRecord) -> Result<(), String> {
    let _authority_guard = config::acquire_authority_writer_guard()
        .map_err(|error| format!("Science managed launch authority fence unavailable: {error}"))?;
    write_managed_launch_record_unfenced(record)
}

/// The caller already owns the exclusive compensation/replay fence.  Retain
/// the non-Send/non-Sync proof through this leaf so a nested SH flock cannot
/// self-deadlock the EX owner.
fn write_managed_launch_record_with_authority_bypass(
    record: &ScienceManagedLaunchRecord,
    bypass: &config::AuthorityWriterBypass<'_>,
) -> Result<(), String> {
    let _authority_guard = config::authority_writer_guard_from_bypass(bypass);
    write_managed_launch_record_unfenced(record)
}

fn write_managed_launch_record_unfenced(record: &ScienceManagedLaunchRecord) -> Result<(), String> {
    let path = managed_launch_path();
    let parent = path
        .parent()
        .ok_or("Science managed launch 记录路径无父目录")?;
    let parent_metadata = parent
        .symlink_metadata()
        .map_err(|_| "Science managed launch 记录目录不可用")?;
    if !parent_metadata.file_type().is_dir()
        || parent_metadata.uid() != unsafe { crate::platform::geteuid() }
        || parent_metadata.permissions().mode() & 0o022 != 0
    {
        return Err("Science managed launch 记录目录不安全".into());
    }
    if let Ok(metadata) = path.symlink_metadata() {
        if !metadata.file_type().is_file()
            || metadata.uid() != unsafe { crate::platform::geteuid() }
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err("Science managed launch 记录不是安全私有普通文件".into());
        }
    }
    let bytes = serde_json::to_vec(record).map_err(|_| "Science managed launch 记录无法序列化")?;
    if bytes.is_empty() || bytes.len() as u64 > MAX_MANAGED_LAUNCH_BYTES {
        return Err("Science managed launch 记录大小非法".into());
    }
    let temp = parent.join(format!(".{MANAGED_LAUNCH_FILE}.{}.tmp", record.launch_id));
    let write_result = (|| -> Result<(), String> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(crate::platform::O_NOFOLLOW | crate::platform::O_CLOEXEC)
            .open(&temp)
            .map_err(|_| "无法创建 Science managed launch 临时记录")?;
        file.write_all(&bytes)
            .map_err(|_| "无法写入 Science managed launch 临时记录")?;
        file.sync_all()
            .map_err(|_| "无法持久化 Science managed launch 临时记录")?;
        fs::rename(&temp, &path).map_err(|_| "无法提交 Science managed launch 记录")?;
        crate::platform::sync_directory(parent)
            .map_err(|_| "无法持久化 Science managed launch 记录目录")?;
        Ok(())
    })();
    if write_result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    write_result
}

#[allow(clippy::result_large_err)]
pub(crate) fn record_managed_science_launch(
    port: u16,
    runtime: &ScienceRuntimeIdentity,
) -> Result<ScienceManagedLaunchToken, ScienceManagedLaunchCommitError> {
    record_managed_science_launch_with_id(port, runtime, None, None)
}

pub(crate) fn record_managed_science_launch_with_launch_id(
    port: u16,
    runtime: &ScienceRuntimeIdentity,
    launch_id: &str,
) -> Result<ScienceManagedLaunchToken, ScienceManagedLaunchCommitError> {
    record_managed_science_launch_with_id(port, runtime, Some(launch_id), None)
}

pub(crate) fn record_managed_science_launch_with_authority_bypass(
    port: u16,
    runtime: &ScienceRuntimeIdentity,
    bypass: &config::AuthorityWriterBypass<'_>,
) -> Result<ScienceManagedLaunchToken, ScienceManagedLaunchCommitError> {
    record_managed_science_launch_with_id(port, runtime, None, Some(bypass))
}

pub(crate) fn record_managed_science_launch_with_launch_id_and_authority_bypass(
    port: u16,
    runtime: &ScienceRuntimeIdentity,
    launch_id: &str,
    bypass: &config::AuthorityWriterBypass<'_>,
) -> Result<ScienceManagedLaunchToken, ScienceManagedLaunchCommitError> {
    record_managed_science_launch_with_id(port, runtime, Some(launch_id), Some(bypass))
}

fn record_managed_science_launch_with_id(
    port: u16,
    runtime: &ScienceRuntimeIdentity,
    launch_id: Option<&str>,
    bypass: Option<&config::AuthorityWriterBypass<'_>>,
) -> Result<ScienceManagedLaunchToken, ScienceManagedLaunchCommitError> {
    let listener_pid =
        listener_runtime_pid(port, runtime).ok_or_else(|| ScienceManagedLaunchCommitError {
            message: "Science listener 身份在 managed launch 提交前无法确认".into(),
            token: None,
        })?;
    let uncommitted_record =
        managed_launch_record_for(port, listener_pid, runtime, launch_id, None).ok_or_else(
            || ScienceManagedLaunchCommitError {
                message: "Science managed launch 身份无法建立".into(),
                token: None,
            },
        )?;
    let uncommitted_token = ScienceManagedLaunchToken {
        record: uncommitted_record.clone(),
        receipt_file: None,
    };
    let adoption_attempt_id =
        ensure_selected_science_runtime_attempt(runtime).map_err(|message| {
            ScienceManagedLaunchCommitError {
                message,
                token: Some(uncommitted_token.clone()),
            }
        })?;
    let record = managed_launch_record_for(
        port,
        listener_pid,
        runtime,
        launch_id,
        Some(&adoption_attempt_id),
    )
    .ok_or_else(|| ScienceManagedLaunchCommitError {
        message: "Science managed launch v2 provenance 身份无法建立".into(),
        token: Some(uncommitted_token.clone()),
    })?;
    let v2_uncommitted_token = ScienceManagedLaunchToken {
        record: record.clone(),
        receipt_file: None,
    };
    #[cfg(test)]
    {
        let persistent = std::env::var_os("CSSWITCH_TEST_MANAGED_LAUNCH_COMMIT_FAILURE").is_some();
        let once = std::env::var_os("CSSWITCH_TEST_MANAGED_LAUNCH_COMMIT_FAILURE_ONCE").is_some()
            && !MANAGED_LAUNCH_COMMIT_FAILURE_ONCE_FIRED
                .swap(true, std::sync::atomic::Ordering::SeqCst);
        if persistent || once {
            if let Some(observation) =
                std::env::var_os("CSSWITCH_TEST_MANAGED_LAUNCH_FAILURE_PID_LOG")
            {
                let _ = std::fs::write(observation, format!("{listener_pid}\n"));
            }
            return Err(ScienceManagedLaunchCommitError {
                message: "test-only managed launch commit failure after listener identity".into(),
                token: Some(v2_uncommitted_token.clone()),
            });
        }
    }
    if unique_listener_pid(port) != Some(listener_pid)
        || process_start_identity(listener_pid).as_deref() != Some(record.process_start.as_str())
    {
        return Err(ScienceManagedLaunchCommitError {
            message: "Science listener 在 managed launch 提交前发生变化".into(),
            token: Some(v2_uncommitted_token.clone()),
        });
    }
    let write = match bypass {
        Some(bypass) => write_managed_launch_record_with_authority_bypass(&record, bypass),
        None => write_managed_launch_record(&record),
    };
    if let Err(message) = write {
        return Err(ScienceManagedLaunchCommitError {
            message,
            token: Some(v2_uncommitted_token.clone()),
        });
    }
    let committed =
        managed_launch_token(port, runtime).ok_or_else(|| ScienceManagedLaunchCommitError {
            message: "Science managed launch 记录提交后回读不一致".into(),
            token: Some(v2_uncommitted_token),
        })?;
    if let Err(message) =
        mark_science_runtime_adoption_launch_committed(&adoption_attempt_id, runtime)
    {
        return Err(ScienceManagedLaunchCommitError {
            message,
            token: Some(committed),
        });
    }
    Ok(committed)
}

/// Capture an exact, receipt-free stop token for a newly spawned Science
/// listener. This is only valid for the narrow post-spawn/pre-receipt window:
/// callers must either commit the managed receipt or use this token to stop
/// the same PID/process-start/runtime identity before returning.
pub(crate) fn uncommitted_managed_science_launch_token(
    port: u16,
    runtime: &ScienceRuntimeIdentity,
) -> Option<ScienceManagedLaunchToken> {
    let listener_pid = listener_runtime_pid(port, runtime)?;
    let record = managed_launch_record_for(port, listener_pid, runtime, None, None)?;
    let token = ScienceManagedLaunchToken {
        record,
        receipt_file: None,
    };
    managed_launch_token_is_current(&token, runtime).then_some(token)
}

fn managed_launch_token(
    port: u16,
    runtime: &ScienceRuntimeIdentity,
) -> Option<ScienceManagedLaunchToken> {
    if !runtime.is_current() {
        return None;
    }
    let (record, receipt_file) = read_managed_launch_snapshot()?;
    if !record_matches_runtime(&record, port, runtime) {
        return None;
    }
    let pid_before = unique_listener_pid(port);
    if pid_before != Some(record.listener_pid)
        || process_start_identity(record.listener_pid).as_deref()
            != Some(record.process_start.as_str())
        || listener_runtime_pid(port, runtime) != Some(record.listener_pid)
    {
        return None;
    }
    if unique_listener_pid(port) != Some(record.listener_pid)
        || process_start_identity(record.listener_pid).as_deref()
            != Some(record.process_start.as_str())
    {
        return None;
    }
    Some(ScienceManagedLaunchToken {
        record,
        receipt_file: Some(receipt_file),
    })
}

pub(crate) fn managed_launch_token_for_runtime(
    port: u16,
    runtime: &ScienceRuntimeIdentity,
) -> Option<ScienceManagedLaunchToken> {
    managed_launch_token(port, runtime)
}

pub(crate) fn managed_launch_token_process_is_alive(token: &ScienceManagedLaunchToken) -> bool {
    process_start_identity(token.record.listener_pid).as_deref()
        == Some(token.record.process_start.as_str())
}

fn managed_launch_identity_matches(port: u16, runtime: &ScienceRuntimeIdentity) -> bool {
    managed_launch_token(port, runtime).is_some()
}

fn hydrate_runtime_adoption_from_managed_launch(
    token: &ScienceManagedLaunchToken,
    runtime: &mut ScienceRuntimeIdentity,
) -> Result<(), String> {
    if !record_matches_runtime(&token.record, token.record.port, runtime) {
        return Err("Science managed launch provenance 与 runtime 身份不匹配".into());
    }
    runtime.adoption_attempt_id = token.record.adoption_attempt_id.clone();
    Ok(())
}

fn managed_launch_token_is_current(
    token: &ScienceManagedLaunchToken,
    runtime: &ScienceRuntimeIdentity,
) -> bool {
    let record = &token.record;
    if !runtime.is_current()
        || !record_matches_runtime(record, record.port, runtime)
        || unique_listener_pid(record.port) != Some(record.listener_pid)
        || process_start_identity(record.listener_pid).as_deref()
            != Some(record.process_start.as_str())
        || listener_runtime_pid(record.port, runtime) != Some(record.listener_pid)
    {
        return false;
    }
    if let Some(expected_file) = token.receipt_file.as_ref() {
        let Some((current_record, current_file)) = read_managed_launch_snapshot() else {
            return false;
        };
        if current_record != *record || current_file != *expected_file {
            return false;
        }
    }
    unique_listener_pid(record.port) == Some(record.listener_pid)
        && process_start_identity(record.listener_pid).as_deref()
            == Some(record.process_start.as_str())
}

pub(crate) fn managed_launch_token_is_current_for_runtime(
    token: &ScienceManagedLaunchToken,
    runtime: &ScienceRuntimeIdentity,
) -> bool {
    managed_launch_token_is_current(token, runtime)
}

fn restore_unmatched_managed_launch_tombstone(tombstone: &Path, path: &Path) -> Result<(), String> {
    match path.symlink_metadata() {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            #[cfg(test)]
            if let Some(barrier_dir) =
                std::env::var_os("CSSWITCH_TEST_TOMBSTONE_RESTORE_BARRIER").map(PathBuf::from)
            {
                fs::write(barrier_dir.join("ready"), b"ready")
                    .map_err(|_| "Science managed launch 测试恢复屏障不可用".to_string())?;
                let mut released = false;
                for _ in 0..500 {
                    if barrier_dir.join("continue").is_file() {
                        released = true;
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                if !released {
                    return Err("Science managed launch 测试恢复屏障超时".into());
                }
            }
            match fs::hard_link(tombstone, path) {
                Ok(()) => {
                    fs::remove_file(tombstone)
                        .map_err(|_| "Science managed launch 记录已恢复但 tombstone 无法清理")?;
                    let parent = path.parent().ok_or("Science managed launch 恢复路径无父目录")?;
                    crate::platform::sync_directory(parent)
                        .map_err(|_| "Science managed launch 恢复目录无法持久化")?;
                    Ok(())
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Err(
                    "Science managed launch 原子 no-clobber 恢复冲突；新记录与旧 tombstone 均已保留"
                        .into(),
                ),
                Err(_) => Err("Science managed launch 记录变化且无法原位恢复".into()),
            }
        }
        Ok(_) => {
            Err("Science managed launch 记录变化且新记录已出现；旧记录保留在 tombstone".into())
        }
        Err(_) => Err("Science managed launch 记录变化且无法确认恢复目标".into()),
    }
}

fn clear_managed_launch_identity(
    token: &ScienceManagedLaunchToken,
    runtime: &ScienceRuntimeIdentity,
) -> Result<(), String> {
    let _authority_guard = config::acquire_authority_writer_guard()
        .map_err(|error| format!("Science managed launch authority fence unavailable: {error}"))?;
    clear_managed_launch_identity_unfenced(token, runtime)
}

pub(crate) fn clear_managed_launch_identity_with_authority_bypass(
    token: &ScienceManagedLaunchToken,
    runtime: &ScienceRuntimeIdentity,
    bypass: &config::AuthorityWriterBypass<'_>,
) -> Result<(), String> {
    let _authority_guard = config::authority_writer_guard_from_bypass(bypass);
    clear_managed_launch_identity_unfenced(token, runtime)
}

fn clear_managed_launch_identity_unfenced(
    token: &ScienceManagedLaunchToken,
    runtime: &ScienceRuntimeIdentity,
) -> Result<(), String> {
    let path = managed_launch_path();
    let Some((record, receipt_file)) = read_managed_launch_snapshot() else {
        return match path.symlink_metadata() {
            Ok(_) => Err("Science managed launch 记录无效，未删除".into()),
            Err(error)
                if error.kind() == std::io::ErrorKind::NotFound && token.receipt_file.is_none() =>
            {
                Ok(())
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                Err("Science managed launch 已提交记录在停止清理前消失".into())
            }
            Err(_) => Err("无法确认 Science managed launch 记录".into()),
        };
    };
    if record != token.record
        || token
            .receipt_file
            .as_ref()
            .is_some_and(|expected| expected != &receipt_file)
        || !record_matches_runtime(&record, token.record.port, runtime)
    {
        return Err("Science managed launch 记录与停止目标不匹配，未删除".into());
    }
    let parent = path.parent().ok_or("Science managed launch 路径无父目录")?;
    let tombstone = parent.join(format!(
        ".{MANAGED_LAUNCH_FILE}.{}.stopped",
        token.record.launch_id
    ));
    if tombstone.symlink_metadata().is_ok() {
        return Err("Science managed launch 清理 tombstone 已存在".into());
    }
    fs::rename(&path, &tombstone).map_err(|_| "无法冻结待清理 Science managed launch 记录")?;
    let moved = read_managed_launch_snapshot_at(&tombstone);
    if moved.as_ref() != Some(&(record, receipt_file)) {
        let restore = restore_unmatched_managed_launch_tombstone(&tombstone, &path);
        return Err(match restore {
            Ok(()) => "Science managed launch 记录在清理前变化；已恢复且拒绝删除".into(),
            Err(error) => error,
        });
    }
    fs::remove_file(&tombstone).map_err(|_| "无法清理 Science managed launch 记录")?;
    crate::platform::sync_directory(parent)
        .map_err(|_| "无法持久化 Science managed launch 清理")?;
    Ok(())
}
