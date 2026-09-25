pub(crate) fn skill_install_bridge_dir(secret: &str) -> Result<PathBuf, String> {
    if secret.len() < 24 || !secret.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err("CSSwitch secret 格式非法，无法创建 Skill 安装桥".into());
    }
    let csswitch_dir = config::default_dir();
    let home = csswitch_dir.parent().ok_or("无法确定用户主目录")?;
    Ok(home.join(format!("CSSwitch-Skill-Bridge-{}", &secret[..24])))
}

pub(crate) struct PreparedSkillInstallHost {
    key: Option<PreparedSkillInstallBridgeKey>,
    // Kept open until the Gateway has inherited it.  The descriptor is passed
    // only through exec inheritance; no authority path is exposed to Gateway.
    authority_fence: Option<config::AuthorityFenceCapability>,
}

impl PreparedSkillInstallHost {
    pub(crate) fn close_parent_authority_fence_after_spawn(&mut self) {
        // The child already inherited the non-CLOEXEC dirfd at successful exec.
        // Keeping it in Desktop would let later unrelated child spawns inherit it.
        self.authority_fence.take();
    }

    pub(crate) fn publish(&mut self) -> Result<PathBuf, String> {
        self.key
            .as_mut()
            .expect("prepared Skill bridge key may only be published once")
            .publish_canonical_key()
    }
}

pub(crate) fn prepare_skill_install_host(
    cmd: &mut Command,
    data_dir: &Path,
    secret: &str,
    launch_id: &str,
    science_context: Option<&csswitch_skill_install_core::ScienceHostContext>,
) -> Result<PreparedSkillInstallHost, String> {
    let bridge_dir = skill_install_bridge_dir(secret)?;
    let bridge_token = skill_install_bridge_token(secret, launch_id)?;
    let authority_fence = config::prepare_authority_fence_capability(&config::default_dir())
        .map_err(|error| format!("无法准备 Skill authority fence capability: {error}"))?;
    // This deterministic value only detects accidental bridge-config mixing;
    // authority comes from the inherited directory descriptor plus identities.
    let mut binding = Sha256::new();
    binding.update(b"csswitch-skill-authority-fence-v1\0");
    binding.update(bridge_token.as_bytes());
    let authority_fence_binding = format!("{:x}", binding.finalize());
    let science_context = science_context
        .map(|context| {
            serde_json::to_string(context).map_err(|_| "无法编码 Science Skill attach host context")
        })
        .transpose()?;
    let key = stage_skill_install_bridge_key(&bridge_token)?;
    cmd.env("CSSWITCH_SKILL_DATA_DIR", data_dir)
        .env("CSSWITCH_SKILL_BRIDGE_DIR", bridge_dir)
        .env("CSSWITCH_SKILL_BRIDGE_TOKEN", bridge_token)
        .env(
            "CSSWITCH_AUTHORITY_FENCE_FD",
            authority_fence.fd().to_string(),
        )
        .env(
            "CSSWITCH_AUTHORITY_FENCE_DIRECTORY_DEVICE",
            authority_fence.directory_device().to_string(),
        )
        .env(
            "CSSWITCH_AUTHORITY_FENCE_DIRECTORY_INODE",
            authority_fence.directory_inode().to_string(),
        )
        .env(
            "CSSWITCH_AUTHORITY_FENCE_LOCK_DEVICE",
            authority_fence.lock_device().to_string(),
        )
        .env(
            "CSSWITCH_AUTHORITY_FENCE_LOCK_INODE",
            authority_fence.lock_inode().to_string(),
        )
        .env("CSSWITCH_AUTHORITY_FENCE_NONCE", authority_fence_binding);
    if let Some(encoded) = science_context {
        cmd.env("CSSWITCH_SCIENCE_HOST_CONTEXT", encoded);
    } else {
        cmd.env_remove("CSSWITCH_SCIENCE_HOST_CONTEXT");
    }
    Ok(PreparedSkillInstallHost {
        key: Some(key),
        authority_fence: Some(authority_fence),
    })
}

fn proxy_fingerprint_with_science_context(
    base: u64,
    context: Option<&csswitch_skill_install_core::ScienceHostContext>,
) -> u64 {
    let mut hasher = DefaultHasher::new();
    base.hash(&mut hasher);
    serde_json::to_vec(&context)
        .unwrap_or_default()
        .hash(&mut hasher);
    hasher.finish()
}

fn skill_install_bridge_token(secret: &str, launch_id: &str) -> Result<String, String> {
    if secret.len() < 24
        || !secret
            .chars()
            .all(|character| character.is_ascii_hexdigit())
        || launch_id.len() < 24
        || !launch_id
            .chars()
            .all(|character| character.is_ascii_hexdigit())
    {
        return Err("CSSwitch secret 格式非法，无法保护 Skill 安装桥".into());
    }
    let mut hash = Sha256::new();
    hash.update(b"csswitch-skill-install-bridge-v1\0");
    hash.update(secret.as_bytes());
    hash.update(b"\0");
    hash.update(launch_id.as_bytes());
    Ok(format!("{:x}", hash.finalize()))
}

#[cfg(test)]
pub(crate) fn test_skill_install_bridge_token(
    secret: &str,
    launch_id: &str,
) -> Result<String, String> {
    skill_install_bridge_token(secret, launch_id)
}

fn skill_install_bridge_key_path() -> PathBuf {
    config::default_dir()
        .join("runtime")
        .join("skill-install-bridge.key")
}

pub(crate) fn current_skill_install_bridge_key() -> Result<PathBuf, String> {
    let key_file = skill_install_bridge_key_path();
    reject_skill_bridge_symlinks(&key_file)?;
    let metadata =
        fs::metadata(&key_file).map_err(|_| "CSSwitch 私有 Skill bridge key file 不可用")?;
    if !metadata.is_file() || metadata.len() > 128 {
        return Err("CSSwitch 私有 Skill bridge key file 类型非法".into());
    }
    #[cfg(unix)]
    {
        #[cfg(unix)]
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.uid() != unsafe { crate::platform::geteuid() }
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err("CSSwitch 私有 Skill bridge key file 权限非法".into());
        }
    }
    Ok(key_file)
}

struct PreparedSkillInstallBridgeKey {
    runtime_dir: PathBuf,
    key_file: PathBuf,
    temporary: Option<PathBuf>,
}

impl PreparedSkillInstallBridgeKey {
    fn publish_canonical_key(&mut self) -> Result<PathBuf, String> {
        let _authority_guard = crate::config::acquire_authority_writer_guard()
            .map_err(|error| format!("authority writer fence failed: {error}"))?;
        let temporary = self
            .temporary
            .as_ref()
            .expect("prepared Skill bridge key must own its temporary file");
        fs::rename(temporary, &self.key_file)
            .map_err(|_| "无法提交 CSSwitch 私有 Skill bridge key")?;
        #[cfg(unix)]
        {
            #[cfg(unix)]
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&self.key_file, crate::platform::permissions_from_mode(0o600))
                .map_err(|_| "无法收紧 CSSwitch 私有 Skill bridge key 权限")?;
        }
        crate::platform::sync_directory(&self.runtime_dir)
            .map_err(|_| "无法同步 CSSwitch 私有 Skill bridge key 目录")?;
        self.temporary = None;
        Ok(self.key_file.clone())
    }
}

impl Drop for PreparedSkillInstallBridgeKey {
    fn drop(&mut self) {
        if let Some(temporary) = self.temporary.take() {
            let _ = fs::remove_file(temporary);
        }
    }
}

fn stage_skill_install_bridge_key(token: &str) -> Result<PreparedSkillInstallBridgeKey, String> {
    let runtime_dir = config::default_dir().join("runtime");
    let key_file = runtime_dir.join("skill-install-bridge.key");
    stage_skill_install_bridge_key_at(runtime_dir, key_file, token)
}

fn stage_skill_install_bridge_key_at(
    runtime_dir: PathBuf,
    key_file: PathBuf,
    token: &str,
) -> Result<PreparedSkillInstallBridgeKey, String> {
    reject_skill_bridge_symlinks(&runtime_dir)?;
    fs::create_dir_all(&runtime_dir).map_err(|_| "无法创建 CSSwitch 私有 Skill bridge key 目录")?;
    reject_skill_bridge_symlinks(&runtime_dir)?;
    #[cfg(unix)]
    fs::set_permissions(
        &runtime_dir,
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )
    .map_err(|_| "无法收紧 CSSwitch 私有 Skill bridge key 目录权限")?;
    reject_skill_bridge_symlinks(&key_file)?;
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let temporary = runtime_dir.join(format!(
        ".skill-install-bridge.key.{}-{suffix}",
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
            .open(&temporary)
            .map_err(|_| "无法创建 CSSwitch 私有 Skill bridge key")?;
        file.write_all(token.as_bytes())
            .and_then(|_| file.write_all(b"\n"))
            .and_then(|_| file.sync_all())
            .map_err(|_| "无法写入 CSSwitch 私有 Skill bridge key")?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result?;
    Ok(PreparedSkillInstallBridgeKey {
        runtime_dir,
        key_file,
        temporary: Some(temporary),
    })
}

fn reject_skill_bridge_symlinks(path: &Path) -> Result<(), String> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err("CSSwitch 私有 Skill bridge key 路径包含符号链接".into())
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err("无法检查 CSSwitch 私有 Skill bridge key 路径".into()),
        }
    }
    Ok(())
}
