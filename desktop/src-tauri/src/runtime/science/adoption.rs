#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ScienceEmbeddedIdentityObservation {
    ValidatedAllowlist,
    NotValidatedBySourcePolicy,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ScienceObservationField {
    Source,
    Version,
    Sha256,
    Size,
    EmbeddedIdentity,
    SnapshotId,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ScienceAdoptionDecision {
    DeferredHealthy,
    Rejected,
    Selected,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ScienceAdoptionMilestone {
    Observed,
    LaunchCommitted,
    Finalized,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum ScienceAdoptionRejectionCode {
    PathValidationFailed,
    LocalIdentityValidationFailed,
    VersionProbeFailed,
    CachedChoiceRequired,
    RuntimeUnavailable,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ScienceCandidateRejection {
    pub(super) source: ScienceRuntimeSource,
    pub(super) code: ScienceAdoptionRejectionCode,
    pub(super) message: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ScienceExecutableObservation {
    source: String,
    version: String,
    sha256: String,
    size: u64,
    embedded_identity: ScienceEmbeddedIdentityObservation,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    snapshot_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ScienceUpdateAttempt {
    attempt_id: String,
    observed_at_ms: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    predecessor: Option<ScienceExecutableObservation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    candidate: Option<ScienceExecutableObservation>,
    normalized_diff: Vec<ScienceObservationField>,
    decision: ScienceAdoptionDecision,
    milestone: ScienceAdoptionMilestone,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    rejection_code: Option<ScienceAdoptionRejectionCode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    rejected_source: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ScienceAdoptionLedger {
    schema_version: u32,
    attempts: Vec<ScienceUpdateAttempt>,
}

impl Default for ScienceAdoptionLedger {
    fn default() -> Self {
        Self {
            schema_version: 1,
            attempts: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ScienceAdoptionFileIdentity {
    device: u64,
    inode: u64,
    size: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    mode: u32,
    uid: u32,
    links: u64,
}

struct ScienceAdoptionLedgerLock {
    file: File,
}

impl Drop for ScienceAdoptionLedgerLock {
    fn drop(&mut self) {
        // SAFETY: the descriptor belongs to this guard and remains open here.
        unsafe {
            crate::platform::flock(self.file.as_raw_fd(), crate::platform::LOCK_UN);
        }
    }
}

fn valid_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn science_adoption_file_identity(metadata: &fs::Metadata) -> ScienceAdoptionFileIdentity {
    ScienceAdoptionFileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        size: metadata.len(),
        modified_seconds: metadata.mtime(),
        modified_nanoseconds: metadata.mtime_nsec(),
        mode: metadata.permissions().mode(),
        uid: metadata.uid(),
        links: metadata.nlink(),
    }
}

fn private_science_adoption_file(metadata: &fs::Metadata) -> bool {
    metadata.file_type().is_file()
        && metadata.uid() == unsafe { crate::platform::geteuid() }
        && metadata.permissions().mode() & 0o077 == 0
        && metadata.nlink() == 1
        && metadata.len() <= MAX_SCIENCE_ADOPTION_LEDGER_BYTES
}

fn science_adoption_store_root() -> PathBuf {
    config::default_dir().join(SCIENCE_ADOPTION_STORE_DIR)
}

fn secure_science_adoption_store_root(root: &Path) -> Result<PathBuf, String> {
    if !root.is_absolute() {
        return Err("Science runtime adoption 存储目录不是绝对路径".into());
    }
    let mut cursor = Some(root);
    while let Some(path) = cursor {
        match path.symlink_metadata() {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err("Science runtime adoption 存储路径包含 symlink".into())
            }
            Ok(metadata) if !metadata.file_type().is_dir() => {
                return Err("Science runtime adoption 存储路径包含非目录文件".into())
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(format!("检查 Science runtime adoption 存储失败：{error}")),
        }
        cursor = path.parent();
    }
    fs::create_dir_all(root)
        .map_err(|error| format!("创建 Science runtime adoption 存储失败：{error}"))?;
    let canonical = root
        .canonicalize_norm()
        .map_err(|error| format!("确认 Science runtime adoption 存储失败：{error}"))?;
    let metadata = root
        .symlink_metadata()
        .map_err(|error| format!("读取 Science runtime adoption 存储失败：{error}"))?;
    if canonical != root
        || metadata.file_type().is_symlink()
        || !metadata.file_type().is_dir()
        || metadata.uid() != unsafe { crate::platform::geteuid() }
    {
        return Err("Science runtime adoption 存储目录身份不安全".into());
    }
    fs::set_permissions(root, crate::platform::permissions_from_mode(0o700))
        .map_err(|error| format!("收紧 Science runtime adoption 存储权限失败：{error}"))?;
    Ok(canonical)
}

fn existing_secure_science_adoption_store_root(root: &Path) -> Result<Option<PathBuf>, String> {
    if !root.is_absolute() {
        return Err("Science runtime adoption 存储目录不是绝对路径".into());
    }
    let root_metadata = match root.symlink_metadata() {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("检查 Science runtime adoption 存储失败：{error}")),
    };
    let mut cursor = Some(root);
    while let Some(path) = cursor {
        let metadata = path
            .symlink_metadata()
            .map_err(|error| format!("检查 Science runtime adoption 存储失败：{error}"))?;
        if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
            return Err("Science runtime adoption 存储路径身份不安全".into());
        }
        cursor = path.parent();
    }
    let canonical = root
        .canonicalize_norm()
        .map_err(|error| format!("确认 Science runtime adoption 存储失败：{error}"))?;
    if canonical != root
        || root_metadata.uid() != unsafe { crate::platform::geteuid() }
        || root_metadata.permissions().mode() & 0o077 != 0
    {
        return Err("Science runtime adoption 存储目录身份或权限不安全".into());
    }
    Ok(Some(canonical))
}

fn acquire_science_adoption_ledger_lock(root: &Path) -> Result<ScienceAdoptionLedgerLock, String> {
    let path = root.join(SCIENCE_ADOPTION_LOCK_FILE);
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(crate::platform::O_NOFOLLOW | crate::platform::O_CLOEXEC)
        .open(&path)
        .map_err(|error| format!("打开 Science runtime adoption writer lock 失败：{error}"))?;
    let opened = file
        .metadata()
        .map_err(|error| format!("读取 Science runtime adoption writer lock 失败：{error}"))?;
    let visible = path
        .symlink_metadata()
        .map_err(|error| format!("复核 Science runtime adoption writer lock 失败：{error}"))?;
    if !private_science_adoption_file(&opened)
        || !private_science_adoption_file(&visible)
        || science_adoption_file_identity(&opened) != science_adoption_file_identity(&visible)
    {
        return Err("Science runtime adoption writer lock 身份或权限不安全".into());
    }
    // SAFETY: flock receives a valid, open descriptor and does not outlive it.
    if unsafe { crate::platform::flock(file.as_raw_fd(), crate::platform::LOCK_EX) } != 0 {
        return Err("无法取得 Science runtime adoption writer lock".into());
    }
    let after = file
        .metadata()
        .map_err(|error| format!("取得 Science runtime adoption lock 后复核失败：{error}"))?;
    let current = path
        .symlink_metadata()
        .map_err(|error| format!("取得 Science runtime adoption lock 后路径复核失败：{error}"))?;
    if science_adoption_file_identity(&after) != science_adoption_file_identity(&current) {
        return Err("Science runtime adoption writer lock 在获取期间被替换".into());
    }
    Ok(ScienceAdoptionLedgerLock { file })
}

fn science_observation_diff(
    predecessor: Option<&ScienceExecutableObservation>,
    candidate: &ScienceExecutableObservation,
) -> Vec<ScienceObservationField> {
    let mut fields = Vec::new();
    if predecessor.is_none_or(|value| value.source != candidate.source) {
        fields.push(ScienceObservationField::Source);
    }
    if predecessor.is_none_or(|value| value.version != candidate.version) {
        fields.push(ScienceObservationField::Version);
    }
    if predecessor.is_none_or(|value| value.sha256 != candidate.sha256) {
        fields.push(ScienceObservationField::Sha256);
    }
    if predecessor.is_none_or(|value| value.size != candidate.size) {
        fields.push(ScienceObservationField::Size);
    }
    if predecessor.is_none_or(|value| value.embedded_identity != candidate.embedded_identity) {
        fields.push(ScienceObservationField::EmbeddedIdentity);
    }
    if predecessor.is_none_or(|value| value.snapshot_id != candidate.snapshot_id) {
        fields.push(ScienceObservationField::SnapshotId);
    }
    fields
}

fn valid_science_executable_observation(observation: &ScienceExecutableObservation) -> bool {
    matches!(
        observation.source.as_str(),
        "explicit" | "official_updated" | "installed_app" | "cached_once"
    ) && !observation.version.is_empty()
        && observation.version.len() <= 160
        && observation
            .version
            .bytes()
            .all(|byte| byte == b' ' || (0x21..=0x7e).contains(&byte))
        && valid_lower_hex(&observation.sha256, 64)
        && observation.size > 0
        && observation
            .snapshot_id
            .as_deref()
            .is_none_or(|value| valid_lower_hex(value, 64))
        && (observation.source == "official_updated")
            == (observation.embedded_identity
                == ScienceEmbeddedIdentityObservation::ValidatedAllowlist)
        && (observation.source == "official_updated") == observation.snapshot_id.is_some()
}

fn valid_science_update_attempt(attempt: &ScienceUpdateAttempt) -> bool {
    if !valid_lower_hex(&attempt.attempt_id, 32)
        || attempt.observed_at_ms < 0
        || attempt
            .predecessor
            .as_ref()
            .is_some_and(|value| !valid_science_executable_observation(value))
        || attempt
            .candidate
            .as_ref()
            .is_some_and(|value| !valid_science_executable_observation(value))
    {
        return false;
    }
    match attempt.decision {
        ScienceAdoptionDecision::Rejected => {
            attempt.candidate.is_none()
                && attempt.normalized_diff.is_empty()
                && attempt.milestone == ScienceAdoptionMilestone::Observed
                && attempt.rejection_code.is_some()
                && attempt.rejected_source.as_deref().is_some_and(|value| {
                    matches!(
                        value,
                        "explicit" | "official_updated" | "installed_app" | "cached_once"
                    )
                })
        }
        ScienceAdoptionDecision::DeferredHealthy => {
            attempt.candidate.is_some()
                && attempt.milestone == ScienceAdoptionMilestone::Observed
                && attempt.rejection_code.is_none()
                && attempt.rejected_source.is_none()
                && attempt.normalized_diff
                    == science_observation_diff(
                        attempt.predecessor.as_ref(),
                        attempt.candidate.as_ref().expect("checked candidate"),
                    )
        }
        ScienceAdoptionDecision::Selected => {
            attempt.candidate.is_some()
                && attempt.rejection_code.is_none()
                && attempt.rejected_source.is_none()
                && attempt.normalized_diff
                    == science_observation_diff(
                        attempt.predecessor.as_ref(),
                        attempt.candidate.as_ref().expect("checked candidate"),
                    )
        }
    }
}

fn validate_science_adoption_ledger(ledger: &ScienceAdoptionLedger) -> bool {
    ledger.schema_version == 1
        && ledger.attempts.len() <= MAX_SCIENCE_ADOPTION_ATTEMPTS
        && ledger.attempts.iter().all(valid_science_update_attempt)
        && ledger
            .attempts
            .iter()
            .map(|attempt| attempt.attempt_id.as_str())
            .collect::<BTreeSet<_>>()
            .len()
            == ledger.attempts.len()
}

fn read_science_adoption_ledger_snapshot(
    root: &Path,
) -> Result<
    (
        ScienceAdoptionLedger,
        Option<ScienceAdoptionFileIdentity>,
        Vec<u8>,
    ),
    String,
> {
    let path = root.join(SCIENCE_ADOPTION_LEDGER_FILE);
    let visible = match path.symlink_metadata() {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok((ScienceAdoptionLedger::default(), None, Vec::new()))
        }
        Err(error) => {
            return Err(format!(
                "读取 Science runtime adoption ledger 失败：{error}"
            ))
        }
    };
    if !private_science_adoption_file(&visible) || visible.len() == 0 {
        return Err("Science runtime adoption ledger 不是安全的有界私有普通文件".into());
    }
    let expected = science_adoption_file_identity(&visible);
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(crate::platform::O_NOFOLLOW | crate::platform::O_CLOEXEC)
        .open(&path)
        .map_err(|error| format!("打开 Science runtime adoption ledger 失败：{error}"))?;
    let opened = file
        .metadata()
        .map_err(|error| format!("读取 Science runtime adoption ledger 身份失败：{error}"))?;
    if !private_science_adoption_file(&opened)
        || science_adoption_file_identity(&opened) != expected
    {
        return Err("Science runtime adoption ledger 在打开期间发生变化".into());
    }
    let mut bytes = Vec::with_capacity(
        usize::try_from(expected.size.min(MAX_SCIENCE_ADOPTION_LEDGER_BYTES + 1))
            .map_err(|_| "Science runtime adoption ledger 大小不可表示")?,
    );
    (&mut file)
        .take(MAX_SCIENCE_ADOPTION_LEDGER_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("读取 Science runtime adoption ledger 内容失败：{error}"))?;
    let final_metadata = file
        .metadata()
        .map_err(|error| format!("复核 Science runtime adoption ledger 失败：{error}"))?;
    if science_adoption_file_identity(&final_metadata) != expected
        || bytes.len() as u64 != expected.size
        || bytes.len() as u64 > MAX_SCIENCE_ADOPTION_LEDGER_BYTES
    {
        return Err("Science runtime adoption ledger 在读取期间发生变化或超过上限".into());
    }
    let ledger: ScienceAdoptionLedger =
        serde_json::from_slice(&bytes).map_err(|_| "Science runtime adoption ledger 无法解析")?;
    if !validate_science_adoption_ledger(&ledger) {
        return Err("Science runtime adoption ledger 合同无效".into());
    }
    Ok((ledger, Some(expected), bytes))
}

fn write_science_adoption_ledger_cas(
    root: &Path,
    expected_identity: Option<&ScienceAdoptionFileIdentity>,
    expected_bytes: &[u8],
    ledger: &ScienceAdoptionLedger,
) -> Result<(), String> {
    if !validate_science_adoption_ledger(ledger) {
        return Err("拒绝写入无效 Science runtime adoption ledger".into());
    }
    let bytes =
        serde_json::to_vec(ledger).map_err(|_| "Science runtime adoption ledger 无法序列化")?;
    if bytes.is_empty() || bytes.len() as u64 > MAX_SCIENCE_ADOPTION_LEDGER_BYTES {
        return Err("Science runtime adoption ledger 超过存储上限".into());
    }
    let (current, current_identity, current_bytes) = read_science_adoption_ledger_snapshot(root)?;
    let _ = current;
    if current_identity.as_ref() != expected_identity || current_bytes != expected_bytes {
        return Err("Science runtime adoption ledger CAS 期望状态已变化".into());
    }
    let path = root.join(SCIENCE_ADOPTION_LEDGER_FILE);
    let temp = root.join(format!(
        ".{SCIENCE_ADOPTION_LEDGER_FILE}.{}.{}.tmp",
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
            .map_err(|error| format!("创建 Science runtime adoption 临时 ledger 失败：{error}"))?;
        file.write_all(&bytes)
            .map_err(|error| format!("写入 Science runtime adoption 临时 ledger 失败：{error}"))?;
        file.sync_all().map_err(|error| {
            format!("持久化 Science runtime adoption 临时 ledger 失败：{error}")
        })?;
        let (_, before_commit_identity, before_commit_bytes) =
            read_science_adoption_ledger_snapshot(root)?;
        if before_commit_identity.as_ref() != expected_identity
            || before_commit_bytes != expected_bytes
        {
            return Err("Science runtime adoption ledger 在原子提交前发生变化".into());
        }
        fs::rename(&temp, &path)
            .map_err(|error| format!("原子提交 Science runtime adoption ledger 失败：{error}"))?;
        crate::platform::sync_directory(root)
            .map_err(|error| format!("持久化 Science runtime adoption ledger 目录失败：{error}"))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

fn referenced_science_adoption_attempt_ids() -> Result<BTreeSet<String>, String> {
    let mut referenced = BTreeSet::new();
    if let Some((record, _)) = read_managed_launch_snapshot_result()
        .map_err(|error| format!("读取 Science adoption live receipt 引用失败：{error}"))?
    {
        if let Some(attempt_id) = record.adoption_attempt_id {
            referenced.insert(attempt_id);
        }
    }
    let cfg = config::load_from(&config::default_dir())
        .map_err(|error| format!("读取 Science adoption recovery 引用失败：{error}"))?;
    if let Some(attempt_id) = cfg
        .runtime_binding
        .as_ref()
        .and_then(|binding| binding.science_adoption_attempt_id.clone())
    {
        referenced.insert(attempt_id);
    }
    if let Some(config::RuntimeTransactionRecord::V2(transaction)) = cfg.runtime_transaction {
        let recipe = match transaction.prior_stop {
            config::RuntimePriorStopState::Intent { recipe }
            | config::RuntimePriorStopState::Outcome { recipe, .. } => Some(recipe),
            config::RuntimePriorStopState::NotRequired => None,
        };
        if let Some(attempt_id) = recipe.and_then(|value| value.runtime_adoption_attempt_id) {
            referenced.insert(attempt_id);
        }
    }
    if let Some(compensation) = cfg.runtime_compensation {
        referenced.extend(compensation.science_adoption_attempt_ids);
    }
    Ok(referenced)
}

fn compact_science_adoption_ledger(ledger: &mut ScienceAdoptionLedger) -> Result<(), String> {
    if ledger.attempts.len() <= MAX_SCIENCE_ADOPTION_ATTEMPTS {
        return Ok(());
    }
    let referenced = referenced_science_adoption_attempt_ids()?;
    while ledger.attempts.len() > MAX_SCIENCE_ADOPTION_ATTEMPTS {
        let recent_start = ledger
            .attempts
            .len()
            .saturating_sub(MIN_RECENT_SCIENCE_ADOPTION_ATTEMPTS);
        let removable = ledger
            .attempts
            .iter()
            .enumerate()
            .take(recent_start)
            .find(|(_, attempt)| {
                !(referenced.contains(&attempt.attempt_id)
                    || attempt.decision == ScienceAdoptionDecision::Selected
                        && attempt.milestone != ScienceAdoptionMilestone::Finalized)
            })
            .map(|(index, _)| index);
        let Some(index) = removable else {
            return Err(
                "Science runtime adoption ledger 已达上限，且全部旧记录仍被 live/recovery 引用"
                    .into(),
            );
        };
        ledger.attempts.remove(index);
    }
    Ok(())
}

fn mutate_science_adoption_ledger<T>(
    root: &Path,
    mutation: impl FnOnce(&mut ScienceAdoptionLedger) -> Result<T, String>,
) -> Result<T, String> {
    let root = secure_science_adoption_store_root(root)?;
    let _lock = acquire_science_adoption_ledger_lock(&root)?;
    let (mut ledger, identity, bytes) = read_science_adoption_ledger_snapshot(&root)?;
    let before = ledger.clone();
    let output = mutation(&mut ledger)?;
    compact_science_adoption_ledger(&mut ledger)?;
    if ledger != before {
        write_science_adoption_ledger_cas(&root, identity.as_ref(), &bytes, &ledger)?;
    }
    Ok(output)
}

fn science_executable_observation(
    runtime: &ScienceRuntimeIdentity,
) -> Result<ScienceExecutableObservation, String> {
    if !runtime.is_current() {
        return Err("Science runtime 在 adoption observation 前发生变化".into());
    }
    let version = runtime
        .version
        .as_ref()
        .filter(|value| !value.trim().is_empty())
        .ok_or("Science runtime adoption observation 缺少已验证版本")?
        .clone();
    let sha256 = fingerprint_sha256_hex(&runtime.fingerprint);
    let snapshot_id = if runtime.source == ScienceRuntimeSource::OfficialUpdated {
        let name = runtime
            .path
            .file_name()
            .and_then(|value| value.to_str())
            .and_then(|value| value.strip_prefix("claude-science-"))
            .filter(|value| valid_lower_hex(value, 64))
            .ok_or("official_updated runtime 缺少有效内容寻址 snapshot id")?;
        if name != sha256 {
            return Err("official_updated runtime snapshot id 与内容指纹不一致".into());
        }
        Some(name.to_string())
    } else {
        None
    };
    Ok(ScienceExecutableObservation {
        source: runtime.source.code().to_string(),
        version,
        sha256,
        size: runtime.fingerprint.size,
        embedded_identity: if runtime.source == ScienceRuntimeSource::OfficialUpdated {
            ScienceEmbeddedIdentityObservation::ValidatedAllowlist
        } else {
            ScienceEmbeddedIdentityObservation::NotValidatedBySourcePolicy
        },
        snapshot_id,
    })
}

fn latest_finalized_science_observation(
    ledger: &ScienceAdoptionLedger,
) -> Option<ScienceExecutableObservation> {
    ledger.attempts.iter().rev().find_map(|attempt| {
        (attempt.decision == ScienceAdoptionDecision::Selected
            && attempt.milestone == ScienceAdoptionMilestone::Finalized)
            .then(|| attempt.candidate.clone())
            .flatten()
    })
}

fn selected_science_predecessor(
    ledger: &ScienceAdoptionLedger,
    candidate: &ScienceExecutableObservation,
) -> Option<ScienceExecutableObservation> {
    latest_finalized_science_observation(ledger).or_else(|| {
        ledger.attempts.iter().rev().find_map(|attempt| {
            (attempt.decision == ScienceAdoptionDecision::DeferredHealthy
                && attempt.candidate.as_ref() == Some(candidate))
            .then(|| attempt.predecessor.clone())
            .flatten()
        })
    })
}

fn append_science_update_attempt(
    ledger: &mut ScienceAdoptionLedger,
    predecessor: Option<ScienceExecutableObservation>,
    candidate: Option<ScienceExecutableObservation>,
    decision: ScienceAdoptionDecision,
    rejection_code: Option<ScienceAdoptionRejectionCode>,
    rejected_source: Option<String>,
) -> String {
    let normalized_diff = candidate
        .as_ref()
        .map(|value| science_observation_diff(predecessor.as_ref(), value))
        .unwrap_or_default();
    let attempt_id = config::new_id();
    ledger.attempts.push(ScienceUpdateAttempt {
        attempt_id: attempt_id.clone(),
        observed_at_ms: config::now_ms(),
        predecessor,
        candidate,
        normalized_diff,
        decision,
        milestone: ScienceAdoptionMilestone::Observed,
        rejection_code,
        rejected_source,
    });
    attempt_id
}

fn ensure_selected_science_runtime_attempt(
    runtime: &ScienceRuntimeIdentity,
) -> Result<String, String> {
    let candidate = science_executable_observation(runtime)?;
    mutate_science_adoption_ledger(&science_adoption_store_root(), |ledger| {
        if let Some(expected_id) = runtime.adoption_attempt_id.as_deref() {
            let expected = ledger
                .attempts
                .iter()
                .find(|attempt| attempt.attempt_id == expected_id)
                .filter(|attempt| {
                    attempt.decision == ScienceAdoptionDecision::Selected
                        && attempt.candidate.as_ref() == Some(&candidate)
                })
                .ok_or("Science runtime adoption attempt id 不存在或候选身份不匹配")?;
            return Ok(expected.attempt_id.clone());
        }
        if let Some(existing) = ledger
            .attempts
            .iter()
            .rev()
            .find(|attempt| attempt.decision == ScienceAdoptionDecision::Selected)
            .filter(|attempt| attempt.candidate.as_ref() == Some(&candidate))
        {
            return Ok(existing.attempt_id.clone());
        }
        let predecessor = selected_science_predecessor(ledger, &candidate);
        Ok(append_science_update_attempt(
            ledger,
            predecessor,
            Some(candidate),
            ScienceAdoptionDecision::Selected,
            None,
            None,
        ))
    })
}

pub(crate) fn bind_selected_science_runtime_attempt(
    runtime: &mut ScienceRuntimeIdentity,
) -> Result<(), String> {
    let attempt_id = ensure_selected_science_runtime_attempt(runtime)?;
    runtime.adoption_attempt_id = Some(attempt_id);
    Ok(())
}

pub(super) fn record_rejected_science_runtime_attempt(
    predecessor: Option<&ScienceRuntimeIdentity>,
    rejection: ScienceCandidateRejection,
) -> Result<(), String> {
    let predecessor = predecessor
        .map(science_executable_observation)
        .transpose()?;
    mutate_science_adoption_ledger(&science_adoption_store_root(), |ledger| {
        if ledger.attempts.last().is_some_and(|attempt| {
            attempt.decision == ScienceAdoptionDecision::Rejected
                && attempt.predecessor == predecessor
                && attempt.rejection_code == Some(rejection.code)
                && attempt.rejected_source.as_deref() == Some(rejection.source.code())
        }) {
            return Ok(());
        }
        append_science_update_attempt(
            ledger,
            predecessor,
            None,
            ScienceAdoptionDecision::Rejected,
            Some(rejection.code),
            Some(rejection.source.code().to_string()),
        );
        Ok(())
    })
}

#[cfg(test)]
pub(crate) fn record_deferred_science_runtime_candidate(
    running: &ScienceRuntimeIdentity,
    version_cache: &ScienceVersionCache,
) -> Result<(), String> {
    let candidate = match preferred_science_runtime_candidate(version_cache, true) {
        Ok(Some(candidate)) => candidate,
        Ok(None) => return Ok(()),
        Err(rejection) => return record_rejected_science_runtime_attempt(Some(running), rejection),
    };
    record_deferred_science_runtime_observations(running, &candidate)
}

pub(crate) fn record_deferred_science_runtime_observation(
    proof: ScienceManagedHealthyProof,
    candidate: &ScienceRuntimeIdentity,
) -> Result<(), String> {
    let root = science_adoption_store_root();
    mutate_science_adoption_ledger(&root, |ledger| {
        let pending = pinned_runtime_from_identity(candidate)?;
        let (selection, _, _) = read_science_runtime_selection_snapshot(&root)?;
        if selection.pending.as_ref() != Some(&pending) {
            return Err("Science pending update 在 adoption 记账前已变化".into());
        }
        if !ScienceHostAdapter::revalidate_managed_healthy(&proof) {
            return Err("Science managed healthy proof 在 adoption 记账前已失效".into());
        }
        let predecessor = science_executable_observation(proof.runtime())?;
        let candidate = science_executable_observation(candidate)?;
        append_deferred_science_runtime_observations(ledger, predecessor, candidate);
        Ok(())
    })
}

#[cfg(test)]
fn record_deferred_science_runtime_observations(
    running: &ScienceRuntimeIdentity,
    candidate: &ScienceRuntimeIdentity,
) -> Result<(), String> {
    let predecessor = science_executable_observation(running)?;
    let candidate = science_executable_observation(candidate)?;
    mutate_science_adoption_ledger(&science_adoption_store_root(), |ledger| {
        append_deferred_science_runtime_observations(
            ledger,
            predecessor.clone(),
            candidate.clone(),
        );
        Ok(())
    })
}

fn append_deferred_science_runtime_observations(
    ledger: &mut ScienceAdoptionLedger,
    predecessor: ScienceExecutableObservation,
    candidate: ScienceExecutableObservation,
) {
    if predecessor == candidate {
        return;
    }
    if ledger.attempts.last().is_some_and(|attempt| {
        attempt.decision == ScienceAdoptionDecision::DeferredHealthy
            && attempt.predecessor.as_ref() == Some(&predecessor)
            && attempt.candidate.as_ref() == Some(&candidate)
    }) {
        return;
    }
    append_science_update_attempt(
        ledger,
        Some(predecessor),
        Some(candidate),
        ScienceAdoptionDecision::DeferredHealthy,
        None,
        None,
    );
}

fn advance_science_runtime_adoption_attempt(
    attempt_id: &str,
    candidate: Option<&ScienceRuntimeIdentity>,
    milestone: ScienceAdoptionMilestone,
) -> Result<(), String> {
    if !valid_lower_hex(attempt_id, 32) {
        return Err("Science runtime adoption attempt id 非法".into());
    }
    let candidate = candidate.map(science_executable_observation).transpose()?;
    mutate_science_adoption_ledger(&science_adoption_store_root(), |ledger| {
        let attempt = ledger
            .attempts
            .iter_mut()
            .find(|attempt| attempt.attempt_id == attempt_id)
            .ok_or("Science runtime adoption attempt 不存在")?;
        if attempt.decision != ScienceAdoptionDecision::Selected
            || candidate
                .as_ref()
                .is_some_and(|value| attempt.candidate.as_ref() != Some(value))
        {
            return Err("Science runtime adoption attempt 与 selected candidate 不匹配".into());
        }
        match (attempt.milestone, milestone) {
            (ScienceAdoptionMilestone::Observed, ScienceAdoptionMilestone::LaunchCommitted)
            | (ScienceAdoptionMilestone::LaunchCommitted, ScienceAdoptionMilestone::Finalized) => {
                attempt.milestone = milestone;
            }
            (ScienceAdoptionMilestone::Finalized, _)
            | (
                ScienceAdoptionMilestone::LaunchCommitted,
                ScienceAdoptionMilestone::LaunchCommitted,
            )
            | (ScienceAdoptionMilestone::Observed, ScienceAdoptionMilestone::Observed) => {}
            _ => return Err("Science runtime adoption milestone CAS 顺序非法".into()),
        }
        Ok(())
    })
}

pub(super) fn mark_science_runtime_adoption_launch_committed(
    attempt_id: &str,
    runtime: &ScienceRuntimeIdentity,
) -> Result<(), String> {
    advance_science_runtime_adoption_attempt(
        attempt_id,
        Some(runtime),
        ScienceAdoptionMilestone::LaunchCommitted,
    )
}

pub(crate) fn mark_science_runtime_adoption_finalized(
    runtime: &ScienceRuntimeIdentity,
) -> Result<(), String> {
    let attempt_id = runtime
        .adoption_attempt_id
        .as_deref()
        .ok_or("Science runtime managed receipt 没有 adoption provenance")?;
    advance_science_runtime_adoption_attempt(
        attempt_id,
        Some(runtime),
        ScienceAdoptionMilestone::Finalized,
    )
}

pub(crate) fn reconcile_current_science_runtime_adoption(
    runtime: &ScienceRuntimeIdentity,
    committed_binding: Option<&config::RuntimeBindingCommit>,
) -> Result<(), String> {
    let Some((record, _)) = read_managed_launch_snapshot_result()? else {
        return Ok(());
    };
    if !record_matches_runtime(&record, record.port, runtime) {
        return Err("Science runtime managed receipt 与当前 runtime 身份不匹配".into());
    }
    let Some(attempt_id) = record.adoption_attempt_id else {
        return Ok(());
    };
    advance_science_runtime_adoption_attempt(
        &attempt_id,
        Some(runtime),
        ScienceAdoptionMilestone::LaunchCommitted,
    )?;
    if committed_binding.and_then(|binding| binding.science_adoption_attempt_id.as_deref())
        == Some(attempt_id.as_str())
    {
        advance_science_runtime_adoption_attempt(
            &attempt_id,
            Some(runtime),
            ScienceAdoptionMilestone::Finalized,
        )?;
    }
    Ok(())
}

#[cfg(test)]
fn read_science_adoption_ledger_at(root: &Path) -> Result<ScienceAdoptionLedger, String> {
    let root = secure_science_adoption_store_root(root)?;
    let _lock = acquire_science_adoption_ledger_lock(&root)?;
    read_science_adoption_ledger_snapshot(&root).map(|(ledger, _, _)| ledger)
}

#[cfg(test)]
pub(crate) fn science_adoption_ledger_json_for_test() -> Result<Value, String> {
    serde_json::to_value(read_science_adoption_ledger_at(
        &science_adoption_store_root(),
    )?)
    .map_err(|error| format!("序列化 Science adoption 测试 ledger 失败：{error}"))
}
