#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct SciencePinnedRuntime {
    source: String,
    version: String,
    sha256: String,
    size: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ScienceRuntimeSelection {
    schema_version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    active: Option<SciencePinnedRuntime>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pending: Option<SciencePinnedRuntime>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    dismissed_sha256s: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_checked_at_ms: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    update_check_id: Option<String>,
}

impl Default for ScienceRuntimeSelection {
    fn default() -> Self {
        Self {
            schema_version: 1,
            active: None,
            pending: None,
            dismissed_sha256s: Vec::new(),
            last_checked_at_ms: None,
            update_check_id: None,
        }
    }
}

fn valid_science_runtime_version(version: &str) -> bool {
    !version.is_empty()
        && version.len() <= 160
        && version
            .bytes()
            .all(|byte| byte == b' ' || (0x21..=0x7e).contains(&byte))
}

fn valid_pinned_science_runtime(runtime: &SciencePinnedRuntime) -> bool {
    matches!(
        runtime.source.as_str(),
        "official_updated" | "installed_app"
    ) && valid_science_runtime_version(&runtime.version)
        && valid_lower_hex(&runtime.sha256, 64)
        && (MIN_SCIENCE_BINARY_SIZE..=MAX_SCIENCE_BINARY_SIZE).contains(&runtime.size)
}

fn valid_science_runtime_selection(selection: &ScienceRuntimeSelection) -> bool {
    selection.schema_version == 1
        && selection.active.is_some()
        && selection
            .active
            .as_ref()
            .is_none_or(valid_pinned_science_runtime)
        && selection
            .pending
            .as_ref()
            .is_none_or(valid_pinned_science_runtime)
        && selection.dismissed_sha256s.len() <= 64
        && selection
            .dismissed_sha256s
            .iter()
            .all(|value| valid_lower_hex(value, 64))
        && selection
            .dismissed_sha256s
            .iter()
            .collect::<BTreeSet<_>>()
            .len()
            == selection.dismissed_sha256s.len()
        && selection.last_checked_at_ms.is_none_or(|value| value >= 0)
        && selection
            .update_check_id
            .as_deref()
            .is_none_or(|value| valid_lower_hex(value, 32))
        && (selection.update_check_id.is_none() || selection.last_checked_at_ms.is_some())
        && selection
            .active
            .as_ref()
            .zip(selection.pending.as_ref())
            .is_none_or(|(active, pending)| {
                active.sha256 != pending.sha256 || active.version != pending.version
            })
}

fn private_science_runtime_selection_file(metadata: &fs::Metadata) -> bool {
    metadata.file_type().is_file()
        && metadata.uid() == unsafe { crate::platform::geteuid() }
        && metadata.permissions().mode() & 0o077 == 0
        && metadata.nlink() == 1
        && metadata.len() > 0
        && metadata.len() <= MAX_SCIENCE_RUNTIME_SELECTION_BYTES
}

fn read_science_runtime_selection_snapshot(
    root: &Path,
) -> Result<
    (
        ScienceRuntimeSelection,
        Option<ScienceAdoptionFileIdentity>,
        Vec<u8>,
    ),
    String,
> {
    let path = root.join(SCIENCE_RUNTIME_SELECTION_FILE);
    let visible = match path.symlink_metadata() {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok((ScienceRuntimeSelection::default(), None, Vec::new()))
        }
        Err(error) => return Err(format!("读取 Science runtime selection 身份失败：{error}")),
    };
    if !private_science_runtime_selection_file(&visible) {
        return Err("Science runtime selection 文件身份或权限不安全".into());
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(crate::platform::O_NOFOLLOW | crate::platform::O_CLOEXEC)
        .open(&path)
        .map_err(|error| format!("打开 Science runtime selection 失败：{error}"))?;
    let opened = file
        .metadata()
        .map_err(|error| format!("读取 Science runtime selection 失败：{error}"))?;
    if !private_science_runtime_selection_file(&opened)
        || science_adoption_file_identity(&opened) != science_adoption_file_identity(&visible)
    {
        return Err("Science runtime selection 在打开期间被替换".into());
    }
    let mut bytes = Vec::with_capacity(opened.len() as usize);
    Read::by_ref(&mut file)
        .take(MAX_SCIENCE_RUNTIME_SELECTION_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("读取 Science runtime selection 内容失败：{error}"))?;
    let after = file
        .metadata()
        .map_err(|error| format!("复核 Science runtime selection 失败：{error}"))?;
    if bytes.is_empty()
        || bytes.len() as u64 > MAX_SCIENCE_RUNTIME_SELECTION_BYTES
        || science_adoption_file_identity(&opened) != science_adoption_file_identity(&after)
    {
        return Err("Science runtime selection 内容越界或读取期间发生变化".into());
    }
    let selection: ScienceRuntimeSelection =
        serde_json::from_slice(&bytes).map_err(|_| "Science runtime selection 无法解析")?;
    if !valid_science_runtime_selection(&selection) {
        return Err("Science runtime selection 合同无效".into());
    }
    Ok((
        selection,
        Some(science_adoption_file_identity(&opened)),
        bytes,
    ))
}

fn write_science_runtime_selection_cas(
    root: &Path,
    expected_identity: Option<&ScienceAdoptionFileIdentity>,
    expected_bytes: &[u8],
    selection: &ScienceRuntimeSelection,
) -> Result<(), String> {
    if !valid_science_runtime_selection(selection) {
        return Err("拒绝写入无效 Science runtime selection".into());
    }
    let bytes =
        serde_json::to_vec(selection).map_err(|_| "Science runtime selection 无法序列化")?;
    if bytes.is_empty() || bytes.len() as u64 > MAX_SCIENCE_RUNTIME_SELECTION_BYTES {
        return Err("Science runtime selection 超过存储上限".into());
    }
    let (_, current_identity, current_bytes) = read_science_runtime_selection_snapshot(root)?;
    if current_identity.as_ref() != expected_identity || current_bytes != expected_bytes {
        return Err("Science runtime selection CAS 期望状态已变化".into());
    }
    let path = root.join(SCIENCE_RUNTIME_SELECTION_FILE);
    let temp = root.join(format!(
        ".{SCIENCE_RUNTIME_SELECTION_FILE}.{}.{}.tmp",
        std::process::id(),
        config::new_id()
    ));
    let result = (|| -> Result<(), String> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(crate::platform::O_NOFOLLOW | crate::platform::O_CLOEXEC)
            .open(&temp)
            .map_err(|error| format!("创建 Science runtime selection 临时文件失败：{error}"))?;
        file.write_all(&bytes)
            .map_err(|error| format!("写入 Science runtime selection 失败：{error}"))?;
        file.sync_all()
            .map_err(|error| format!("持久化 Science runtime selection 失败：{error}"))?;
        let (_, before_identity, before_bytes) = read_science_runtime_selection_snapshot(root)?;
        if before_identity.as_ref() != expected_identity || before_bytes != expected_bytes {
            return Err("Science runtime selection 在原子提交前发生变化".into());
        }
        fs::rename(&temp, &path)
            .map_err(|error| format!("原子提交 Science runtime selection 失败：{error}"))?;
        #[cfg(test)]
        if SCIENCE_SELECTION_FAIL_NEXT_DIRECTORY_SYNC.swap(false, Ordering::SeqCst) {
            return Err("测试注入：Science runtime selection rename 后目录持久化失败".into());
        }
        crate::platform::sync_directory(root)
            .map_err(|error| format!("持久化 Science runtime selection 目录失败：{error}"))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

#[cfg(test)]
static SCIENCE_SELECTION_FAIL_NEXT_DIRECTORY_SYNC: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

#[cfg(test)]
fn test_fail_next_science_selection_directory_sync() {
    SCIENCE_SELECTION_FAIL_NEXT_DIRECTORY_SYNC.store(true, Ordering::SeqCst);
}

fn mutate_science_runtime_selection_at<T>(
    root: &Path,
    mutation: impl FnOnce(&mut ScienceRuntimeSelection) -> Result<T, String>,
) -> Result<T, String> {
    let root = secure_science_adoption_store_root(root)?;
    let _lock = acquire_science_adoption_ledger_lock(&root)?;
    let (mut selection, identity, bytes) = read_science_runtime_selection_snapshot(&root)?;
    let before = selection.clone();
    let output = mutation(&mut selection)?;
    if selection != before {
        write_science_runtime_selection_cas(&root, identity.as_ref(), &bytes, &selection)?;
    }
    Ok(output)
}

fn mutate_science_runtime_selection<T>(
    mutation: impl FnOnce(&mut ScienceRuntimeSelection) -> Result<T, String>,
) -> Result<T, String> {
    mutate_science_runtime_selection_at(&science_adoption_store_root(), mutation)
}

fn remove_science_runtime_selection_cas(
    root: &Path,
    expected_identity: &ScienceAdoptionFileIdentity,
    expected_bytes: &[u8],
) -> Result<(), String> {
    let (_, current_identity, current_bytes) = read_science_runtime_selection_snapshot(root)?;
    if current_identity.as_ref() != Some(expected_identity) || current_bytes != expected_bytes {
        return Err("Science runtime selection 回滚 CAS 期望状态已变化".into());
    }
    fs::remove_file(root.join(SCIENCE_RUNTIME_SELECTION_FILE))
        .map_err(|error| format!("回滚 Science runtime selection 失败：{error}"))?;
    crate::platform::sync_directory(root)
        .map_err(|error| format!("持久化 Science runtime selection 回滚失败：{error}"))
}

fn rollback_published_science_runtime_selection(
    root: &Path,
    prior: &ScienceRuntimeSelection,
    prior_identity: Option<&ScienceAdoptionFileIdentity>,
    committed_identity: &ScienceAdoptionFileIdentity,
    committed_bytes: &[u8],
) -> Result<(), String> {
    match prior_identity {
        Some(_) => write_science_runtime_selection_cas(
            root,
            Some(committed_identity),
            committed_bytes,
            prior,
        ),
        None => remove_science_runtime_selection_cas(root, committed_identity, committed_bytes),
    }
}

fn mutate_science_runtime_selection_checked<T>(
    mutation: impl FnOnce(&mut ScienceRuntimeSelection) -> Result<T, String>,
    validate_committed: impl Fn(&ScienceRuntimeSelection) -> Result<(), String>,
) -> Result<T, String> {
    let root = secure_science_adoption_store_root(&science_adoption_store_root())?;
    let _lock = acquire_science_adoption_ledger_lock(&root)?;
    let (mut selection, prior_identity, prior_bytes) =
        read_science_runtime_selection_snapshot(&root)?;
    let prior = selection.clone();
    let output = mutation(&mut selection)?;
    if selection == prior {
        return Ok(output);
    }
    validate_committed(&selection)?;
    if let Err(write_error) = write_science_runtime_selection_cas(
        &root,
        prior_identity.as_ref(),
        &prior_bytes,
        &selection,
    ) {
        let publication = read_science_runtime_selection_snapshot(&root).map_err(|read_error| {
            format!("{write_error}；Science runtime selection 提交结果无法确认：{read_error}")
        })?;
        if publication.0 != selection {
            return Err(write_error);
        }
        let committed_identity = publication
            .1
            .as_ref()
            .ok_or("Science runtime selection 已发布但写后身份缺失，无法回滚")?;
        return match rollback_published_science_runtime_selection(
            &root,
            &prior,
            prior_identity.as_ref(),
            committed_identity,
            &publication.2,
        ) {
            Ok(()) => Err(format!(
                "Science runtime selection 已发布但持久化确认失败，已回滚：{write_error}"
            )),
            Err(rollback_error) => Err(format!(
                "Science runtime selection 已发布但持久化确认失败且回滚失败：{write_error}；{rollback_error}"
            )),
        };
    }
    let (committed_selection, committed_identity, committed_bytes) =
        read_science_runtime_selection_snapshot(&root)?;
    let post_validation = if committed_selection != selection {
        Err("Science runtime selection 写后内容与期望不一致".into())
    } else {
        validate_committed(&committed_selection)
    };
    if let Err(validation_error) = post_validation {
        let committed_identity = committed_identity
            .as_ref()
            .ok_or("Science runtime selection 写后身份缺失，无法回滚")?;
        let rollback = rollback_published_science_runtime_selection(
            &root,
            &prior,
            prior_identity.as_ref(),
            committed_identity,
            &committed_bytes,
        );
        return match rollback {
            Ok(()) => Err(format!(
                "Science runtime selection 写后 snapshot 复核失败，已回滚：{validation_error}"
            )),
            Err(rollback_error) => Err(format!(
                "Science runtime selection 写后 snapshot 复核失败且回滚失败：{validation_error}；{rollback_error}"
            )),
        };
    }
    Ok(output)
}

fn read_science_runtime_selection() -> Result<ScienceRuntimeSelection, String> {
    let Some(root) = existing_secure_science_adoption_store_root(&science_adoption_store_root())?
    else {
        return Ok(ScienceRuntimeSelection::default());
    };
    read_science_runtime_selection_snapshot(&root).map(|(selection, _, _)| selection)
}

fn pinned_runtime_from_identity(
    runtime: &ScienceRuntimeIdentity,
) -> Result<SciencePinnedRuntime, String> {
    if !matches!(
        runtime.source,
        ScienceRuntimeSource::OfficialUpdated | ScienceRuntimeSource::InstalledApp
    ) || !runtime.is_current()
    {
        return Err("Science runtime 不能持久化为 active selection".into());
    }
    let version = runtime
        .version
        .as_ref()
        .filter(|value| valid_science_runtime_version(value))
        .ok_or("Science runtime active selection 缺少有效版本")?
        .clone();
    let pinned = SciencePinnedRuntime {
        source: runtime.source.code().to_string(),
        version,
        sha256: fingerprint_sha256_hex(&runtime.fingerprint),
        size: runtime.fingerprint.size,
    };
    valid_pinned_science_runtime(&pinned)
        .then_some(pinned)
        .ok_or_else(|| "Science runtime active selection 身份无效".into())
}

fn runtime_from_pinned_selection(
    pinned: &SciencePinnedRuntime,
) -> Result<ScienceRuntimeIdentity, String> {
    if !valid_pinned_science_runtime(pinned) {
        return Err("Science active runtime 记录无效".into());
    }
    let source = match pinned.source.as_str() {
        "official_updated" => ScienceRuntimeSource::OfficialUpdated,
        "installed_app" => ScienceRuntimeSource::InstalledApp,
        _ => return Err("Science active runtime 来源无效".into()),
    };
    let root = config::default_dir().join(OFFICIAL_UPDATED_SNAPSHOT_DIR);
    let root_metadata = root
        .symlink_metadata()
        .map_err(|_| "Science active runtime snapshot 目录不可用")?;
    if root.canonicalize_norm().ok().as_deref() != Some(root.as_path())
        || !root_metadata.file_type().is_dir()
        || root_metadata.uid() != unsafe { crate::platform::geteuid() }
        || !crate::platform::dir_mode_is_0700(&root_metadata)
    {
        return Err("Science active runtime snapshot 目录身份或权限不安全".into());
    }
    let path = root.join(format!("claude-science-{}", pinned.sha256));
    let canonical = path
        .canonicalize_norm()
        .map_err(|_| "Science active runtime snapshot 不可用")?;
    if canonical != path {
        return Err("Science active runtime snapshot 不是 canonical path".into());
    }
    let metadata = path
        .symlink_metadata()
        .map_err(|_| "Science active runtime snapshot 身份不可用")?;
    if !metadata.file_type().is_file()
        || metadata.uid() != unsafe { crate::platform::geteuid() }
        || metadata.permissions().mode() & 0o777 != 0o500
        || metadata.nlink() != 1
        || metadata.len() != pinned.size
    {
        return Err("Science active runtime snapshot 不是私有 0500 单链接文件".into());
    }
    let fingerprint = science_executable_fingerprint(&canonical)
        .ok_or("Science active runtime snapshot 身份无法确认")?;
    if fingerprint_sha256_hex(&fingerprint) != pinned.sha256
        || fingerprint.size != pinned.size
        || fingerprint.mode & 0o777 != 0o500
    {
        return Err("Science active runtime snapshot 与固定身份不一致".into());
    }
    if source == ScienceRuntimeSource::OfficialUpdated
        && (!file_is_macho(&canonical) || !official_updated_identity_metadata_matches(&canonical))
    {
        #[cfg(not(test))]
        return Err("Science active updater runtime embedded identity 无法确认".into());
    }
    let root_after = root
        .symlink_metadata()
        .map_err(|_| "Science active runtime snapshot 目录复核失败")?;
    let metadata_after = path
        .symlink_metadata()
        .map_err(|_| "Science active runtime snapshot 身份复核失败")?;
    if root_after.dev() != root_metadata.dev()
        || root_after.ino() != root_metadata.ino()
        || root_after.uid() != root_metadata.uid()
        || root_after.mode() != root_metadata.mode()
        || science_adoption_file_identity(&metadata_after)
            != science_adoption_file_identity(&metadata)
    {
        return Err("Science active runtime snapshot 身份在验证期间变化".into());
    }
    Ok(ScienceRuntimeIdentity {
        path: canonical,
        source,
        version: Some(pinned.version.clone()),
        fingerprint,
        adoption_attempt_id: None,
    })
}

fn content_matches_pinned(a: &SciencePinnedRuntime, b: &SciencePinnedRuntime) -> bool {
    a.sha256 == b.sha256 && a.version == b.version
}

fn science_runtime_source_priority(source: &str) -> u8 {
    match source {
        "official_updated" => 2,
        "installed_app" => 1,
        _ => 0,
    }
}

fn snapshot_candidate_runtime(
    runtime: ScienceRuntimeIdentity,
) -> Result<(ScienceRuntimeIdentity, SciencePinnedRuntime), String> {
    let snapshot = match runtime.source {
        ScienceRuntimeSource::OfficialUpdated => runtime.path.clone(),
        ScienceRuntimeSource::InstalledApp => installed_app_snapshot(
            &runtime.path,
            &runtime.fingerprint,
            &config::default_dir().join(OFFICIAL_UPDATED_SNAPSHOT_DIR),
        )?
        .ok_or("Claude Science App executable 在 snapshot 前消失")?,
        _ => return Err("只有官方 updater 或 installed App 可以进入 active runtime".into()),
    };
    let fingerprint =
        science_executable_fingerprint(&snapshot).ok_or("Science runtime snapshot 身份无法确认")?;
    let snapshot_runtime = ScienceRuntimeIdentity {
        path: snapshot,
        source: runtime.source,
        version: runtime.version,
        fingerprint,
        adoption_attempt_id: None,
    };
    let pinned = pinned_runtime_from_identity(&snapshot_runtime)?;
    Ok((snapshot_runtime, pinned))
}

fn discover_pinned_science_runtime(
    version_cache: &ScienceVersionCache,
    allow_installed_app_fallback: bool,
) -> Result<Option<(ScienceRuntimeIdentity, SciencePinnedRuntime)>, ScienceCandidateRejection> {
    match preferred_science_runtime_candidate(version_cache, allow_installed_app_fallback)? {
        Some(runtime) => {
            let source = runtime.source;
            snapshot_candidate_runtime(runtime)
                .map(Some)
                .map_err(|message| ScienceCandidateRejection {
                    source,
                    code: ScienceAdoptionRejectionCode::LocalIdentityValidationFailed,
                    message,
                })
        }
        None => Ok(None),
    }
}

fn active_science_runtime() -> Result<Option<ScienceRuntimeIdentity>, String> {
    read_science_runtime_selection()?
        .active
        .as_ref()
        .map(runtime_from_pinned_selection)
        .transpose()
}

fn validate_active_science_runtime_snapshot(
    selection: &ScienceRuntimeSelection,
) -> Result<(), String> {
    selection
        .active
        .as_ref()
        .ok_or_else(|| "Science runtime selection 缺少 active".to_string())
        .and_then(runtime_from_pinned_selection)
        .map(|_| ())
}

fn resolve_active_or_bootstrap_science_runtime(
    version_cache: &ScienceVersionCache,
) -> Result<Option<ScienceRuntimeIdentity>, String> {
    let current = read_science_runtime_selection()?;
    if let Some(active) = current.active.as_ref() {
        return runtime_from_pinned_selection(active).map(Some);
    }

    let discovered = discover_pinned_science_runtime(version_cache, true).map_err(|rejection| {
        let message = rejection.message.clone();
        let _ = record_rejected_science_runtime_attempt(None, rejection);
        message
    })?;
    let discovered_pin = discovered.as_ref().map(|(_, pinned)| pinned.clone());
    let selected = mutate_science_runtime_selection_checked(
        |selection| {
            if let Some(active) = selection.active.clone() {
                return Ok(Some(active));
            }
            let active = discovered_pin;
            let Some(active) = active else {
                return Ok(None);
            };
            selection.active = Some(active.clone());
            Ok(Some(active))
        },
        validate_active_science_runtime_snapshot,
    )?;
    selected
        .as_ref()
        .map(runtime_from_pinned_selection)
        .transpose()
}

fn science_runtime_update_due(last_checked_at_ms: Option<i64>, now_ms: i64) -> bool {
    last_checked_at_ms.is_none_or(|last| {
        now_ms >= last && now_ms.saturating_sub(last) >= SCIENCE_RUNTIME_UPDATE_INTERVAL_MS
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ScienceRuntimeUpdateClaim {
    Uninitialized(ScienceRuntimeSelection),
    PendingChoice(ScienceRuntimeSelection),
    NotDue(ScienceRuntimeSelection),
    Claimed(ScienceRuntimeSelection),
}

fn claim_science_runtime_update(
    selection: &mut ScienceRuntimeSelection,
    now_ms: i64,
    claim_id: &str,
) -> ScienceRuntimeUpdateClaim {
    if selection.active.is_none() {
        return ScienceRuntimeUpdateClaim::Uninitialized(selection.clone());
    }
    if selection.pending.is_some() {
        return ScienceRuntimeUpdateClaim::PendingChoice(selection.clone());
    }
    if !science_runtime_update_due(selection.last_checked_at_ms, now_ms) {
        return ScienceRuntimeUpdateClaim::NotDue(selection.clone());
    }
    selection.last_checked_at_ms = Some(now_ms);
    selection.update_check_id = Some(claim_id.to_string());
    ScienceRuntimeUpdateClaim::Claimed(selection.clone())
}

fn apply_discovered_science_update(
    selection: &mut ScienceRuntimeSelection,
    candidate: Option<SciencePinnedRuntime>,
    checked_at_ms: i64,
) {
    selection.last_checked_at_ms = Some(checked_at_ms);
    selection.update_check_id = None;
    if selection.pending.is_some() {
        return;
    }
    selection.pending = match candidate {
        Some(candidate)
            if selection.active.as_ref().is_none_or(|active| {
                !content_matches_pinned(active, &candidate)
                    && science_runtime_source_priority(&candidate.source)
                        >= science_runtime_source_priority(&active.source)
            }) && !selection.dismissed_sha256s.contains(&candidate.sha256) =>
        {
            Some(candidate)
        }
        _ => None,
    };
}

fn apply_discovered_science_update_if_current(
    selection: &mut ScienceRuntimeSelection,
    expected: &ScienceRuntimeSelection,
    candidate: Option<SciencePinnedRuntime>,
    checked_at_ms: i64,
) -> bool {
    if selection != expected {
        return false;
    }
    apply_discovered_science_update(selection, candidate, checked_at_ms);
    true
}

fn science_runtime_selection_value(selection: &ScienceRuntimeSelection) -> Value {
    json!({
        "schema_version": 1,
        "status": if selection.active.is_some() { "ready" } else { "uninitialized" },
        "active_source": selection.active.as_ref().map(|runtime| runtime.source.as_str()),
        "active_version": selection.active.as_ref().map(|runtime| runtime.version.as_str()),
        "pending_update": selection.pending.as_ref().map(|runtime| json!({
            "source": runtime.source,
            "version": runtime.version,
            "sha256": runtime.sha256,
        })),
        "last_checked_at_ms": selection.last_checked_at_ms,
        "activation_policy": "next_cold_start",
    })
}

pub(crate) fn science_runtime_update_status() -> Result<Value, String> {
    read_science_runtime_selection().map(|selection| science_runtime_selection_value(&selection))
}

pub(crate) fn science_runtime_update_action(
    action: &str,
    expected_sha256: &str,
) -> Result<Value, String> {
    if !valid_lower_hex(expected_sha256, 64) {
        return Err("Science pending update 身份无效".into());
    }
    let selection = mutate_science_runtime_selection_checked(
        |selection| {
            let pending = selection
                .pending
                .clone()
                .filter(|pending| pending.sha256 == expected_sha256)
                .ok_or("Science pending update 已变化，请刷新后重试")?;
            match action {
                "activate_pending" => {
                    selection.active = Some(pending);
                    selection.pending = None;
                    selection.update_check_id = None;
                }
                "keep_active" if selection.active.is_some() => {
                    if !selection.dismissed_sha256s.contains(&pending.sha256) {
                        if selection.dismissed_sha256s.len() >= 64 {
                            return Err(
                                "Science runtime 已拒绝候选记录已满，无法安全遗忘旧选择".into()
                            );
                        }
                        selection.dismissed_sha256s.push(pending.sha256);
                        selection.dismissed_sha256s.sort();
                    }
                    selection.pending = None;
                    selection.update_check_id = None;
                }
                "keep_active" => return Err("尚无可继续使用的 active Science runtime".into()),
                _ => return Err("未知 Science runtime update action".into()),
            }
            Ok(selection.clone())
        },
        |selection| {
            validate_active_science_runtime_snapshot(selection)
                .map_err(|error| format!("Science active runtime snapshot 无法确认：{error}"))
        },
    )?;
    Ok(science_runtime_selection_value(&selection))
}

pub(crate) struct ScienceRuntimeUpdateCheck {
    value: Value,
    candidate_runtime: Option<ScienceRuntimeIdentity>,
}

impl ScienceRuntimeUpdateCheck {
    fn without_candidate(mut value: Value) -> Self {
        value["adoption_record_status"] = json!("not_needed");
        Self {
            value,
            candidate_runtime: None,
        }
    }

    pub(crate) fn into_parts(self) -> (Value, Option<ScienceRuntimeIdentity>) {
        (self.value, self.candidate_runtime)
    }

    #[cfg(test)]
    pub(crate) fn into_value(self) -> Value {
        self.value
    }
}

pub(crate) fn check_science_runtime_update(
    version_cache: &ScienceVersionCache,
) -> Result<ScienceRuntimeUpdateCheck, String> {
    if std::env::var_os("SCIENCE_BIN").is_some() {
        let mut value = science_runtime_update_status()?;
        value["check_status"] = json!("explicit_override_skipped");
        return Ok(ScienceRuntimeUpdateCheck::without_candidate(value));
    }
    let now_ms = config::now_ms();
    let observed = read_science_runtime_selection()?;
    if observed.active.is_none() {
        let mut value = science_runtime_selection_value(&observed);
        value["check_status"] = json!("uninitialized_skipped");
        return Ok(ScienceRuntimeUpdateCheck::without_candidate(value));
    }
    if observed.pending.is_some() {
        let mut value = science_runtime_selection_value(&observed);
        value["check_status"] = json!("pending_choice_waiting");
        return Ok(ScienceRuntimeUpdateCheck::without_candidate(value));
    }
    if !science_runtime_update_due(observed.last_checked_at_ms, now_ms) {
        let mut value = science_runtime_selection_value(&observed);
        value["check_status"] = json!("not_due");
        return Ok(ScienceRuntimeUpdateCheck::without_candidate(value));
    }
    let claim_id = config::new_id();
    let claim = mutate_science_runtime_selection(|selection| {
        Ok(claim_science_runtime_update(selection, now_ms, &claim_id))
    })?;
    let before = match claim {
        ScienceRuntimeUpdateClaim::Uninitialized(selection) => {
            let mut value = science_runtime_selection_value(&selection);
            value["check_status"] = json!("uninitialized_skipped");
            return Ok(ScienceRuntimeUpdateCheck::without_candidate(value));
        }
        ScienceRuntimeUpdateClaim::PendingChoice(selection) => {
            let mut value = science_runtime_selection_value(&selection);
            value["check_status"] = json!("pending_choice_waiting");
            return Ok(ScienceRuntimeUpdateCheck::without_candidate(value));
        }
        ScienceRuntimeUpdateClaim::NotDue(selection) => {
            let mut value = science_runtime_selection_value(&selection);
            value["check_status"] = json!("not_due");
            return Ok(ScienceRuntimeUpdateCheck::without_candidate(value));
        }
        ScienceRuntimeUpdateClaim::Claimed(selection) => selection,
    };
    let allow_installed_app_fallback = before
        .active
        .as_ref()
        .is_none_or(|active| active.source != "official_updated");
    let discovered =
        match discover_pinned_science_runtime(version_cache, allow_installed_app_fallback) {
            Ok(value) => value,
            Err(rejection) => {
                let message = rejection.message.clone();
                let _ = record_rejected_science_runtime_attempt(None, rejection);
                mutate_science_runtime_selection(|selection| {
                    if *selection == before {
                        selection.update_check_id = None;
                    }
                    Ok(())
                })
                .map_err(|finish_error| {
                    format!("{message}；Science update check lease 收尾失败：{finish_error}")
                })?;
                return Err(message);
            }
        };
    let candidate_runtime = discovered.as_ref().map(|(runtime, _)| runtime.clone());
    let candidate = discovered.map(|(_, pinned)| pinned);
    let mut stale_result = false;
    let selection = mutate_science_runtime_selection(|selection| {
        stale_result = !apply_discovered_science_update_if_current(
            selection,
            &before,
            candidate.clone(),
            now_ms,
        );
        Ok(selection.clone())
    })?;
    let candidate_runtime = (!stale_result)
        .then_some(candidate_runtime)
        .flatten()
        .filter(|candidate| {
            selection.pending.as_ref().is_some_and(|pending| {
                pending.sha256 == fingerprint_sha256_hex(&candidate.fingerprint)
            })
        });
    let mut value = science_runtime_selection_value(&selection);
    value["check_status"] = json!(if stale_result {
        "stale_result_discarded"
    } else {
        "checked"
    });
    value["adoption_record_status"] = json!("not_needed");
    Ok(ScienceRuntimeUpdateCheck {
        value,
        candidate_runtime,
    })
}

#[cfg(test)]
fn read_science_runtime_selection_at(root: &Path) -> Result<ScienceRuntimeSelection, String> {
    let root = secure_science_adoption_store_root(root)?;
    let _lock = acquire_science_adoption_ledger_lock(&root)?;
    read_science_runtime_selection_snapshot(&root).map(|(selection, _, _)| selection)
}
