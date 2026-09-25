impl AuthorityTreeSnapshot {
    pub(super) fn os_error_code(error: &std::io::Error) -> i32 {
        error.raw_os_error().unwrap_or(-1)
    }

    #[cfg(unix)]
pub(super) fn clone_regular_file_at(
        source_fd: i32,
        parent_fd: i32,
        destination_name: &std::ffi::CStr,
    ) -> Result<(), std::io::Error> {
        #[cfg(test)]
        if let Some((_, errno)) = SANDBOX_SESSION_TEST_SEAMS
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .authority_clone_errno
            .filter(|(thread, _)| *thread == std::thread::current().id())
        {
            return Err(std::io::Error::from_raw_os_error(errno));
        }
        let result =
            unsafe { libc::fclonefileat(source_fd, parent_fd, destination_name.as_ptr(), 0) };
        if result == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }

    #[cfg(unix)]
pub(super) fn open_destination_at(
        parent_fd: i32,
        destination_name: &std::ffi::CStr,
        flags: i32,
        mode: crate::platform::ModeT,
    ) -> Result<std::fs::File, std::io::Error> {
        let fd = unsafe {
            libc::openat(
                parent_fd,
                destination_name.as_ptr(),
                flags | crate::platform::O_NOFOLLOW | crate::platform::O_CLOEXEC,
                libc::c_uint::from(mode),
            )
        };
        if fd < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(unsafe { std::fs::File::from_raw_fd(fd) })
        }
    }

    #[cfg(unix)]
pub(super) fn open_directory_at(
        parent_fd: i32,
        destination_name: &std::ffi::CStr,
    ) -> Result<std::fs::File, std::io::Error> {
        Self::open_destination_at(
            parent_fd,
            destination_name,
            crate::platform::O_RDONLY | crate::platform::O_DIRECTORY,
            0,
        )
    }

    #[cfg(unix)]
pub(super) fn open_absolute_directory(path: &Path) -> Result<std::fs::File, std::io::Error> {
        if !path.is_absolute() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "directory path must be absolute",
            ));
        }
        let mut directory = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(crate::platform::O_DIRECTORY | crate::platform::O_NOFOLLOW | crate::platform::O_CLOEXEC)
            .open("/")?;
        for component in path.components() {
            match component {
                std::path::Component::RootDir => {}
                std::path::Component::Normal(name) => {
                    let name = std::ffi::CString::new(name.as_encoded_bytes()).map_err(|_| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            "directory component contains NUL",
                        )
                    })?;
                    directory = Self::open_directory_at(directory.as_raw_fd(), &name)?;
                }
                _ => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "directory path contains unsupported component",
                    ))
                }
            }
        }
        Ok(directory)
    }

    pub(super) fn open_or_create_authority_snapshot_parent(
        config_dir: &Path,
        sandbox_home: &Path,
    ) -> Result<std::fs::File, String> {
        let expected_parent = sandbox_home
            .parent()
            .ok_or("code=authority_snapshot_root_parent_missing")?;
        if sandbox_home != config_dir.join("sandbox").join("home") {
            return Err("code=authority_snapshot_root_parent_contract_failed".into());
        }
        let config_parent = Self::open_absolute_directory(config_dir).map_err(|error| {
            format!(
                "code=authority_snapshot_config_parent_open_failed os_error={}",
                Self::os_error_code(&error)
            )
        })?;
        let initial_config_parent_metadata = config_parent.metadata().map_err(|error| {
            format!(
                "code=authority_snapshot_config_parent_validate_failed os_error={}",
                Self::os_error_code(&error)
            )
        })?;
        if !initial_config_parent_metadata.is_dir()
            || initial_config_parent_metadata.uid() != unsafe { crate::platform::geteuid() }
        {
            return Err("code=authority_snapshot_config_parent_identity_failed".into());
        }
        config_parent
            .set_permissions(crate::platform::permissions_from_mode(0o700))
            .map_err(|error| {
                format!(
                    "code=authority_snapshot_config_parent_chmod_failed os_error={}",
                    Self::os_error_code(&error)
                )
            })?;
        let config_parent_metadata = config_parent.metadata().map_err(|error| {
            format!(
                "code=authority_snapshot_config_parent_validate_failed os_error={}",
                Self::os_error_code(&error)
            )
        })?;
        if !config_parent_metadata.is_dir()
            || config_parent_metadata.uid() != unsafe { crate::platform::geteuid() }
            || !crate::platform::dir_mode_is_0700(&config_parent_metadata)
        {
            return Err("code=authority_snapshot_config_parent_identity_failed".into());
        }

        let parent_name = Self::destination_name(expected_parent)?;
        match Self::stat_destination_at(&config_parent, &parent_name) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                match Self::mkdir_destination_at(config_parent.as_raw_fd(), &parent_name, 0o700) {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(error) => {
                        return Err(format!(
                            "code=authority_snapshot_root_parent_create_failed os_error={}",
                            Self::os_error_code(&error)
                        ))
                    }
                }
            }
            Err(error) => {
                return Err(format!(
                    "code=authority_snapshot_root_parent_entry_validate_failed os_error={}",
                    Self::os_error_code(&error)
                ))
            }
        }
        let parent_entry =
            Self::stat_destination_at(&config_parent, &parent_name).map_err(|error| {
                format!(
                    "code=authority_snapshot_root_parent_entry_validate_failed os_error={}",
                    Self::os_error_code(&error)
                )
            })?;
        #[cfg(test)]
        if let Some(barrier) = SANDBOX_SESSION_TEST_SEAMS
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .snapshot_parent_barrier
            .as_ref()
            .filter(|(target, _)| target == expected_parent)
            .map(|(_, barrier)| barrier.clone())
        {
            std::fs::create_dir_all(&barrier).map_err(|error| {
                format!("test-only snapshot parent barrier create failed: {error}")
            })?;
            std::fs::write(barrier.join("ready"), b"ready\n").map_err(|error| {
                format!("test-only snapshot parent barrier arm failed: {error}")
            })?;
            let mut released = false;
            for _ in 0..200 {
                if barrier.join("release").is_file() {
                    released = true;
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            if !released {
                return Err("test-only snapshot parent barrier timed out".into());
            }
        }
        let snapshot_parent = Self::open_directory_at(config_parent.as_raw_fd(), &parent_name)
            .map_err(|error| {
                format!(
                    "code=authority_snapshot_root_parent_open_failed os_error={}",
                    Self::os_error_code(&error)
                )
            })?;
        let initial_snapshot_parent_metadata = snapshot_parent.metadata().map_err(|error| {
            format!(
                "code=authority_snapshot_root_parent_validate_failed os_error={}",
                Self::os_error_code(&error)
            )
        })?;
        if !initial_snapshot_parent_metadata.is_dir()
            || initial_snapshot_parent_metadata.uid() != unsafe { crate::platform::geteuid() }
            || !Self::destination_entry_matches_file(
                &parent_entry,
                &initial_snapshot_parent_metadata,
                crate::platform::S_IFDIR,
            )
        {
            return Err("code=authority_snapshot_root_parent_identity_failed".into());
        }
        snapshot_parent
            .set_permissions(crate::platform::permissions_from_mode(0o700))
            .map_err(|error| {
                format!(
                    "code=authority_snapshot_root_parent_chmod_failed os_error={}",
                    Self::os_error_code(&error)
                )
            })?;
        let snapshot_parent_metadata = snapshot_parent.metadata().map_err(|error| {
            format!(
                "code=authority_snapshot_root_parent_validate_failed os_error={}",
                Self::os_error_code(&error)
            )
        })?;
        if !snapshot_parent_metadata.is_dir()
            || snapshot_parent_metadata.uid() != unsafe { crate::platform::geteuid() }
            || !crate::platform::dir_mode_is_0700(&snapshot_parent_metadata)
            || !Self::destination_entry_matches_file(
                &parent_entry,
                &snapshot_parent_metadata,
                crate::platform::S_IFDIR,
            )
        {
            return Err("code=authority_snapshot_root_parent_identity_failed".into());
        }
        if !Self::absolute_directory_binding_matches(config_dir, &config_parent).map_err(
            |error| {
                format!(
                    "code=authority_snapshot_config_parent_revalidate_failed os_error={}",
                    Self::os_error_code(&error)
                )
            },
        )? {
            return Err("code=authority_snapshot_config_parent_rebound".into());
        }
        if !Self::absolute_directory_binding_matches(expected_parent, &snapshot_parent).map_err(
            |error| {
                format!(
                    "code=authority_snapshot_root_parent_revalidate_failed os_error={}",
                    Self::os_error_code(&error)
                )
            },
        )? {
            return Err("code=authority_snapshot_root_parent_rebound".into());
        }
        snapshot_parent.sync_all().map_err(|error| {
            format!(
                "code=authority_snapshot_root_parent_sync_failed os_error={}",
                Self::os_error_code(&error)
            )
        })?;
        config_parent.sync_all().map_err(|error| {
            format!(
                "code=authority_snapshot_config_parent_sync_failed os_error={}",
                Self::os_error_code(&error)
            )
        })?;
        Ok(snapshot_parent)
    }

    pub(super) fn absolute_directory_binding_matches(
        path: &Path,
        pinned: &std::fs::File,
    ) -> Result<bool, std::io::Error> {
        let current = Self::open_absolute_directory(path)?;
        let expected = pinned.metadata()?;
        let actual = current.metadata()?;
        Ok(expected.is_dir()
            && actual.is_dir()
            && expected.dev() == actual.dev()
            && expected.ino() == actual.ino()
            && expected.uid() == actual.uid())
    }

    #[cfg(unix)]
pub(super) fn read_directory_names(
        directory: &std::fs::File,
    ) -> Result<Vec<std::ffi::OsString>, std::io::Error> {
        let duplicate = unsafe { libc::fcntl(directory.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
        if duplicate < 0 {
            return Err(std::io::Error::last_os_error());
        }
        if unsafe { libc::lseek(duplicate, 0, libc::SEEK_SET) } < 0 {
            let error = std::io::Error::last_os_error();
            unsafe {
                libc::close(duplicate);
            }
            return Err(error);
        }
        let stream = unsafe { libc::fdopendir(duplicate) };
        if stream.is_null() {
            let error = std::io::Error::last_os_error();
            unsafe {
                libc::close(duplicate);
            }
            return Err(error);
        }
        let stream = AuthorityDirectoryStream(stream);
        let mut names = Vec::new();
        loop {
            unsafe {
                *libc::__error() = 0;
            }
            let entry = unsafe { libc::readdir(stream.0) };
            if entry.is_null() {
                let error = std::io::Error::last_os_error();
                if error.raw_os_error().unwrap_or(0) == 0 {
                    break;
                }
                return Err(error);
            }
            let name = unsafe { std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
            if name == b"." || name == b".." {
                continue;
            }
            names.push(std::ffi::OsString::from_vec(name.to_vec()));
        }
        names.sort();
        Ok(names)
    }

    #[cfg(unix)]
pub(super) fn remove_tree_at(
        destination_parent: &std::fs::File,
        destination_name: &std::ffi::CStr,
    ) -> Result<(), std::io::Error> {
        let entry = Self::stat_destination_at(destination_parent, destination_name)?;
        match entry.st_mode & crate::platform::S_IFMT {
            crate::platform::S_IFDIR => {
                let directory =
                    Self::open_directory_at(destination_parent.as_raw_fd(), destination_name)?;
                let metadata = directory.metadata()?;
                if !Self::destination_entry_matches_file(&entry, &metadata, crate::platform::S_IFDIR) {
                    return Err(std::io::Error::other("directory entry identity changed"));
                }
                for child in Self::read_directory_names(&directory)? {
                    let child = std::ffi::CString::new(child.as_encoded_bytes()).map_err(|_| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            "directory entry contains NUL",
                        )
                    })?;
                    Self::remove_tree_at(&directory, &child)?;
                }
                directory.sync_all()?;
                let final_entry = Self::stat_destination_at(destination_parent, destination_name)?;
                let final_metadata = directory.metadata()?;
                if !Self::destination_entry_matches_file(
                    &final_entry,
                    &final_metadata,
                    crate::platform::S_IFDIR,
                ) {
                    return Err(std::io::Error::other(
                        "directory entry rebound before removal",
                    ));
                }
                let result = unsafe {
                    libc::unlinkat(
                        destination_parent.as_raw_fd(),
                        destination_name.as_ptr(),
                        crate::platform::AT_REMOVEDIR,
                    )
                };
                if result != 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            crate::platform::S_IFREG | crate::platform::S_IFLNK => {
                Self::unlink_destination_at(destination_parent.as_raw_fd(), destination_name)?;
            }
            _ => {
                return Err(std::io::Error::other(
                    "refusing to remove special authority entry",
                ))
            }
        }
        destination_parent.sync_all()
    }

    #[cfg(unix)]
pub(super) fn mkdir_destination_at(
        parent_fd: i32,
        destination_name: &std::ffi::CStr,
        mode: crate::platform::ModeT,
    ) -> Result<(), std::io::Error> {
        let result = unsafe { libc::mkdirat(parent_fd, destination_name.as_ptr(), mode) };
        if result == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }

    #[cfg(unix)]
pub(super) fn unlink_destination_at(
        parent_fd: i32,
        destination_name: &std::ffi::CStr,
    ) -> Result<(), std::io::Error> {
        let result = unsafe { libc::unlinkat(parent_fd, destination_name.as_ptr(), 0) };
        if result == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }

    pub(super) fn destination_name(path: &Path) -> Result<std::ffi::CString, String> {
        let name = path
            .file_name()
            .ok_or("code=authority_snapshot_destination_name_missing")?;
        std::ffi::CString::new(name.as_encoded_bytes())
            .map_err(|_| "code=authority_snapshot_destination_name_invalid".into())
    }

    pub(super) fn cleanup_created_destination(
        destination_parent: &std::fs::File,
        destination_name: &std::ffi::CStr,
        scope: AuthoritySnapshotScope,
        category: AuthoritySnapshotCategory,
    ) -> Result<(), String> {
        Self::unlink_destination_at(destination_parent.as_raw_fd(), destination_name)
            .map_err(|error| {
                format!(
                    "code=authority_snapshot_cleanup_unlink_failed scope={} category={} os_error={}",
                    scope.code(),
                    category.code(),
                    Self::os_error_code(&error)
                )
            })?;
        destination_parent.sync_all().map_err(|error| {
            format!(
                "code=authority_snapshot_cleanup_sync_failed scope={} category={} os_error={}",
                scope.code(),
                category.code(),
                Self::os_error_code(&error)
            )
        })
    }

    #[cfg(unix)]
pub(super) fn stat_destination_at(
        destination_parent: &std::fs::File,
        destination_name: &std::ffi::CStr,
    ) -> Result<crate::platform::Stat, std::io::Error> {
        let mut stat = std::mem::MaybeUninit::<crate::platform::Stat>::zeroed();
        let result = unsafe {
            libc::fstatat(
                destination_parent.as_raw_fd(),
                destination_name.as_ptr(),
                stat.as_mut_ptr(),
                crate::platform::AT_SYMLINK_NOFOLLOW,
            )
        };
        if result == 0 {
            Ok(unsafe { stat.assume_init() })
        } else {
            Err(std::io::Error::last_os_error())
        }
    }

    pub(super) fn destination_entry_matches_file(
        entry: &crate::platform::Stat,
        file: &std::fs::Metadata,
        expected_kind: crate::platform::ModeT,
    ) -> bool {
        u64::try_from(entry.st_dev).ok() == Some(file.dev())
            && inode_u64(entry.st_ino) == Some(file.ino())
            && entry.st_mode & crate::platform::S_IFMT == expected_kind
    }

    #[cfg(unix)]
pub(super) fn readlink_destination_at(
        destination_parent: &std::fs::File,
        destination_name: &std::ffi::CStr,
        expected_len: usize,
    ) -> Result<Vec<u8>, std::io::Error> {
        let mut bytes = vec![0u8; expected_len.saturating_add(1)];
        let length = unsafe {
            libc::readlinkat(
                destination_parent.as_raw_fd(),
                destination_name.as_ptr(),
                bytes.as_mut_ptr().cast(),
                bytes.len(),
            )
        };
        if length < 0 {
            return Err(std::io::Error::last_os_error());
        }
        bytes.truncate(length as usize);
        Ok(bytes)
    }

    pub(super) fn category(
        scope: AuthoritySnapshotScope,
        root: &Path,
        current: &Path,
    ) -> AuthoritySnapshotCategory {
        if scope != AuthoritySnapshotScope::ScienceData {
            return AuthoritySnapshotCategory::Other;
        }
        let Ok(relative) = current.strip_prefix(root) else {
            return AuthoritySnapshotCategory::Other;
        };
        let components = relative
            .components()
            .filter_map(|component| component.as_os_str().to_str())
            .collect::<Vec<_>>();
        let Some(first) = components.first().copied() else {
            return AuthoritySnapshotCategory::Other;
        };
        if first == "conda" {
            return AuthoritySnapshotCategory::CondaCache;
        }
        if matches!(first, "runtime" | "seed-assets" | "r-libs" | "sbx-bind-src") {
            return AuthoritySnapshotCategory::ScienceRuntime;
        }
        if components
            .iter()
            .any(|component| matches!(*component, "skills" | "marketplace-plugins"))
        {
            return AuthoritySnapshotCategory::Skills;
        }
        if matches!(
            first,
            ".oauth-tokens"
                | ".key-backups"
                | "active-org.json"
                | "auth-owner.lock"
                | "encryption.key"
                | "mcp"
                | "orgs"
        ) {
            return AuthoritySnapshotCategory::OrgState;
        }
        AuthoritySnapshotCategory::Other
    }

    pub(super) fn stat_entry_stable(initial: &crate::platform::Stat, final_entry: &crate::platform::Stat) -> bool {
        initial.st_dev == final_entry.st_dev
            && initial.st_ino == final_entry.st_ino
            && initial.st_mode == final_entry.st_mode
            && initial.st_uid == final_entry.st_uid
            && initial.st_gid == final_entry.st_gid
            && initial.st_nlink == final_entry.st_nlink
            && initial.st_size == final_entry.st_size
            && initial.st_mtime == final_entry.st_mtime
            && initial.st_mtime_nsec == final_entry.st_mtime_nsec
    }

    pub(super) fn directory_manifest_at(
        directory: &std::fs::File,
        names: &[std::ffi::OsString],
    ) -> Result<Vec<AuthorityDirectoryEntryIdentity>, String> {
        names
            .iter()
            .map(|name| {
                let name_c = std::ffi::CString::new(name.as_encoded_bytes())
                    .map_err(|_| "code=authority_snapshot_source_name_invalid")?;
                let metadata = Self::stat_destination_at(directory, &name_c).map_err(|error| {
                    format!(
                        "code=authority_snapshot_directory_member_validate_failed os_error={}",
                        Self::os_error_code(&error)
                    )
                })?;
                let kind = match metadata.st_mode & crate::platform::S_IFMT {
                    crate::platform::S_IFREG => 1,
                    crate::platform::S_IFDIR => 2,
                    crate::platform::S_IFLNK => 3,
                    _ => 4,
                };
                Ok(AuthorityDirectoryEntryIdentity {
                    name: name.clone(),
                    kind,
                    device: u64::try_from(metadata.st_dev)
                        .map_err(|_| "code=authority_snapshot_source_device_invalid")?,
                    inode: inode_u64(metadata.st_ino)
                        .ok_or("code=authority_snapshot_source_inode_invalid")?,
                    size: u64::try_from(metadata.st_size)
                        .map_err(|_| "code=authority_snapshot_source_size_invalid")?,
                    mode: u32::from(metadata.st_mode) & 0o777,
                    modified_seconds: metadata.st_mtime,
                    modified_nanoseconds: metadata.st_mtime_nsec,
                })
            })
            .collect()
    }

    #[cfg(not(unix))]
    // Windows 降级：整个权威快照引擎基于 openat/fstatat/fdopendir 相对描述符，
    // std 无法在 Windows 上复刻；一律返回 Unsupported，由上层调用流程显式报错。
    pub(super) fn clone_regular_file_at(
        _source_fd: i32,
        _parent_fd: i32,
        _destination_name: &std::ffi::CStr,
    ) -> Result<(), std::io::Error> {
        Err(std::io::Error::new(std::io::ErrorKind::Unsupported, "authority snapshot requires POSIX openat/fstatat and is unavailable on this platform"))
    }

    #[cfg(not(unix))]
    pub(super) fn open_destination_at(
        _parent_fd: i32,
        _destination_name: &std::ffi::CStr,
        _flags: crate::platform::ModeT,
        _mode: crate::platform::ModeT,
    ) -> Result<std::fs::File, std::io::Error> {
        Err(std::io::Error::new(std::io::ErrorKind::Unsupported, "authority snapshot requires POSIX openat/fstatat and is unavailable on this platform"))
    }

    #[cfg(not(unix))]
    pub(super) fn open_directory_at(
        _parent_fd: i32,
        _destination_name: &std::ffi::CStr,
    ) -> Result<std::fs::File, std::io::Error> {
        Err(std::io::Error::new(std::io::ErrorKind::Unsupported, "authority snapshot requires POSIX openat/fstatat and is unavailable on this platform"))
    }

    #[cfg(not(unix))]
    pub(super) fn open_absolute_directory(_path: &Path) -> Result<std::fs::File, std::io::Error> {
        Err(std::io::Error::new(std::io::ErrorKind::Unsupported, "authority snapshot requires POSIX openat/fstatat and is unavailable on this platform"))
    }

    #[cfg(not(unix))]
    pub(super) fn read_directory_names(
        _directory: &std::fs::File,
    ) -> Result<Vec<std::ffi::OsString>, std::io::Error> {
        Err(std::io::Error::new(std::io::ErrorKind::Unsupported, "authority snapshot requires POSIX openat/fstatat and is unavailable on this platform"))
    }

    #[cfg(not(unix))]
    pub(super) fn remove_tree_at(
        _destination_parent: &std::fs::File,
        _destination_name: &std::ffi::CStr,
    ) -> Result<(), std::io::Error> {
        Err(std::io::Error::new(std::io::ErrorKind::Unsupported, "authority snapshot requires POSIX openat/fstatat and is unavailable on this platform"))
    }

    #[cfg(not(unix))]
    pub(super) fn mkdir_destination_at(
        _parent_fd: i32,
        _destination_name: &std::ffi::CStr,
        _mode: crate::platform::ModeT,
    ) -> Result<(), std::io::Error> {
        Err(std::io::Error::new(std::io::ErrorKind::Unsupported, "authority snapshot requires POSIX openat/fstatat and is unavailable on this platform"))
    }

    #[cfg(not(unix))]
    pub(super) fn unlink_destination_at(
        _parent_fd: i32,
        _destination_name: &std::ffi::CStr,
    ) -> Result<(), std::io::Error> {
        Err(std::io::Error::new(std::io::ErrorKind::Unsupported, "authority snapshot requires POSIX openat/fstatat and is unavailable on this platform"))
    }

    #[cfg(not(unix))]
    pub(super) fn stat_destination_at(
        _destination_parent: &std::fs::File,
        _destination_name: &std::ffi::CStr,
    ) -> Result<crate::platform::Stat, std::io::Error> {
        Err(std::io::Error::new(std::io::ErrorKind::Unsupported, "authority snapshot requires POSIX openat/fstatat and is unavailable on this platform"))
    }

    #[cfg(not(unix))]
    pub(super) fn readlink_destination_at(
        _destination_parent: &std::fs::File,
        _destination_name: &std::ffi::CStr,
        _expected_len: usize,
    ) -> Result<Vec<u8>, std::io::Error> {
        Err(std::io::Error::new(std::io::ErrorKind::Unsupported, "authority snapshot requires POSIX openat/fstatat and is unavailable on this platform"))
    }

}
