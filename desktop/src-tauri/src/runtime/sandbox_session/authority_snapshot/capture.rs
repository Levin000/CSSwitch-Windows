impl AuthorityTreeSnapshot {
    #[cfg(test)]
    pub(super) fn capture(source: PathBuf, backup: PathBuf) -> Result<Self, String> {
        Self::capture_scoped(AuthoritySnapshotScope::Test, source, backup)
    }

    #[cfg(test)]
    pub(super) fn capture_scoped(
        scope: AuthoritySnapshotScope,
        source: PathBuf,
        backup: PathBuf,
    ) -> Result<Self, String> {
        let backup_parent = backup
            .parent()
            .ok_or("code=authority_snapshot_destination_parent_missing")?;
        let backup_parent_file = Self::open_absolute_directory(backup_parent).map_err(|error| {
            format!(
                "code=authority_snapshot_destination_parent_open_failed scope={} os_error={}",
                scope.code(),
                Self::os_error_code(&error)
            )
        })?;
        let backup_name = Self::destination_name(&backup)?;
        Self::capture_scoped_at(scope, source, backup, &backup_parent_file, &backup_name)
    }

    pub(super) fn capture_scoped_at(
        scope: AuthoritySnapshotScope,
        source: PathBuf,
        backup: PathBuf,
        backup_parent: &std::fs::File,
        backup_name: &std::ffi::CStr,
    ) -> Result<Self, String> {
        let mut budget = AuthorityCopyBudget::default();
        Self::capture_scoped_at_with_budget(
            scope,
            source,
            backup,
            backup_parent,
            backup_name,
            &mut budget,
        )
    }

    pub(super) fn capture_scoped_at_with_budget(
        scope: AuthoritySnapshotScope,
        source: PathBuf,
        backup: PathBuf,
        backup_parent: &std::fs::File,
        backup_name: &std::ffi::CStr,
        budget: &mut AuthorityCopyBudget,
    ) -> Result<Self, String> {
        let source_parent_path = source
            .parent()
            .ok_or("code=authority_snapshot_source_parent_missing")?;
        let source_parent = match Self::open_absolute_directory(source_parent_path) {
            Ok(parent) => parent,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self {
                    scope,
                    source,
                    backup,
                    existed: false,
                    source_parent: None,
                    source_name: None,
                    backup_identity: None,
                    backup_parent: None,
                    backup_name: None,
                })
            }
            Err(error) => {
                return Err(format!(
                    "code=authority_snapshot_source_parent_open_failed scope={} os_error={}",
                    scope.code(),
                    Self::os_error_code(&error)
                ))
            }
        };
        let source_name = Self::destination_name(&source)?;
        Self::capture_scoped_from_parent_with_budget(
            scope,
            source,
            backup,
            &source_parent,
            &source_name,
            backup_parent,
            backup_name,
            budget,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn capture_scoped_from_parent_with_budget(
        scope: AuthoritySnapshotScope,
        source: PathBuf,
        backup: PathBuf,
        source_parent: &std::fs::File,
        source_name: &std::ffi::CStr,
        backup_parent: &std::fs::File,
        backup_name: &std::ffi::CStr,
        budget: &mut AuthorityCopyBudget,
    ) -> Result<Self, String> {
        #[cfg(test)]
        if SANDBOX_SESSION_TEST_SEAMS
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .capture_fail_source
            .as_ref()
            == Some(&source)
        {
            return Err(format!(
                "test-only authority snapshot capture failure for {}",
                source.display()
            ));
        }
        let source_parent_path = source
            .parent()
            .ok_or("code=authority_snapshot_source_parent_missing")?;
        let backup_identity = match Self::stat_destination_at(source_parent, source_name) {
            Ok(source_identity) => {
                if source_identity.st_mode & crate::platform::S_IFMT == crate::platform::S_IFLNK {
                    return Err(format!(
                        "code=authority_snapshot_root_symlink scope={} category=other",
                        scope.code()
                    ));
                }
                Self::copy_tree_from_at(
                    &source,
                    source_parent,
                    source_name,
                    backup_parent,
                    backup_name,
                    budget,
                    false,
                    scope,
                    &source,
                )?;
                let source_parent_still_bound =
                    Self::absolute_directory_binding_matches(
                        source_parent_path,
                        source_parent,
                    )
                    .map_err(|error| {
                        format!(
                            "code=authority_snapshot_source_parent_revalidate_failed scope={} os_error={}",
                            scope.code(),
                            Self::os_error_code(&error)
                        )
                    })?;
                if !source_parent_still_bound {
                    let primary = format!(
                        "code=authority_snapshot_source_parent_rebound scope={}",
                        scope.code()
                    );
                    return match Self::cleanup_created_destination(
                        backup_parent,
                        backup_name,
                        scope,
                        AuthoritySnapshotCategory::Other,
                    ) {
                        Ok(()) => Err(primary),
                        Err(cleanup) => Err(format!("{primary}; {cleanup}")),
                    };
                }
                let identity =
                    Self::stat_destination_at(backup_parent, backup_name)
                        .map_err(|error| {
                            format!(
                                "code=authority_snapshot_root_entry_validate_failed scope={} os_error={}",
                                scope.code(),
                                Self::os_error_code(&error)
                            )
                        })?;
                Some((
                    u64::try_from(identity.st_dev)
                        .map_err(|_| "code=authority_snapshot_root_device_invalid")?,
                    inode_u64(identity.st_ino)
                        .ok_or("code=authority_snapshot_root_inode_invalid")?,
                    identity.st_mode & crate::platform::S_IFMT,
                ))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => {
                return Err(format!(
                "code=authority_snapshot_root_metadata_failed scope={} category=other os_error={}",
                scope.code(),
                Self::os_error_code(&error)
            ))
            }
        };
        let backup_parent_handle = if backup_identity.is_some() {
            Some(backup_parent.try_clone().map_err(|error| {
                format!(
                    "code=authority_snapshot_backup_parent_pin_failed scope={} os_error={}",
                    scope.code(),
                    Self::os_error_code(&error)
                )
            })?)
        } else {
            None
        };
        let backup_name_handle = backup_identity.as_ref().map(|_| backup_name.to_owned());
        let source_parent_handle = source_parent.try_clone().map_err(|error| {
            format!(
                "code=authority_snapshot_source_parent_pin_failed scope={} os_error={}",
                scope.code(),
                Self::os_error_code(&error)
            )
        })?;
        Ok(Self {
            scope,
            source,
            backup,
            existed: backup_identity.is_some(),
            source_parent: Some(source_parent_handle),
            source_name: Some(source_name.to_owned()),
            backup_identity,
            backup_parent: backup_parent_handle,
            backup_name: backup_name_handle,
        })
    }

    pub(super) fn charge_entry(
        budget: &mut AuthorityCopyBudget,
        file_bytes: u64,
        scope: AuthoritySnapshotScope,
        category: AuthoritySnapshotCategory,
    ) -> Result<(), String> {
        budget.entries = budget.entries.checked_add(1).ok_or_else(|| {
            format!(
                "code=authority_snapshot_entry_overflow scope={} category={}",
                scope.code(),
                category.code()
            )
        })?;
        if budget.entries > MAX_AUTHORITY_SNAPSHOT_ENTRIES {
            return Err(format!(
                "code=authority_snapshot_entry_limit scope={} category={} observed_entries={} entry_limit={MAX_AUTHORITY_SNAPSHOT_ENTRIES}",
                scope.code(),
                category.code(),
                budget.entries
            ));
        }
        if file_bytes > MAX_AUTHORITY_SNAPSHOT_FILE_BYTES {
            return Err(format!(
                "code=authority_snapshot_file_limit scope={} category={} observed_bytes={file_bytes} file_limit={MAX_AUTHORITY_SNAPSHOT_FILE_BYTES}",
                scope.code(),
                category.code()
            ));
        }
        budget.bytes = budget.bytes.checked_add(file_bytes).ok_or_else(|| {
            format!(
                "code=authority_snapshot_total_overflow scope={} category={} observed_entries={}",
                scope.code(),
                category.code(),
                budget.entries
            )
        })?;
        if budget.bytes > MAX_AUTHORITY_SNAPSHOT_TOTAL_BYTES {
            return Err(format!(
                "code=authority_snapshot_total_limit scope={} category={} observed_total_bytes={} total_limit={MAX_AUTHORITY_SNAPSHOT_TOTAL_BYTES} observed_entries={}",
                scope.code(),
                category.code(),
                budget.bytes,
                budget.entries
            ));
        }
        Ok(())
    }

    pub(super) fn charge_full_copy(
        budget: &mut AuthorityCopyBudget,
        file_bytes: u64,
        scope: AuthoritySnapshotScope,
        category: AuthoritySnapshotCategory,
    ) -> Result<(), String> {
        if file_bytes > MAX_AUTHORITY_FULL_COPY_FILE_BYTES {
            return Err(format!(
                "code=authority_snapshot_clone_required scope={} category={} observed_bytes={file_bytes} full_copy_file_limit={MAX_AUTHORITY_FULL_COPY_FILE_BYTES}",
                scope.code(),
                category.code()
            ));
        }
        budget.full_copy_bytes =
            budget
                .full_copy_bytes
                .checked_add(file_bytes)
                .ok_or_else(|| {
                    format!(
                        "code=authority_snapshot_full_copy_overflow scope={} category={}",
                        scope.code(),
                        category.code()
                    )
                })?;
        if budget.full_copy_bytes > MAX_AUTHORITY_FULL_COPY_TOTAL_BYTES {
            return Err(format!(
                "code=authority_snapshot_clone_required scope={} category={} observed_full_copy_bytes={} full_copy_total_limit={MAX_AUTHORITY_FULL_COPY_TOTAL_BYTES}",
                scope.code(),
                category.code(),
                budget.full_copy_bytes
            ));
        }
        Ok(())
    }

    pub(super) fn sync_snapshot_completion(
        backup_root: &std::fs::File,
        snapshot_parent: &std::fs::File,
    ) -> Result<(), std::io::Error> {
        #[cfg(test)]
        if SANDBOX_SESSION_TEST_SEAMS
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .authority_completion_sync_failure
            .is_some_and(|thread| thread == std::thread::current().id())
        {
            return Err(std::io::Error::from_raw_os_error(libc::EIO));
        }
        backup_root.sync_all()?;
        snapshot_parent.sync_all()
    }

    #[cfg(test)]
    pub(super) fn copy_tree(
        source: &Path,
        backup: &Path,
        budget: &mut AuthorityCopyBudget,
        allow_symlink: bool,
        scope: AuthoritySnapshotScope,
        root: &Path,
    ) -> Result<(), String> {
        let parent = backup
            .parent()
            .ok_or("code=authority_snapshot_destination_parent_missing")?;
        let parent_file = Self::open_absolute_directory(parent).map_err(|error| {
            format!(
                "code=authority_snapshot_destination_parent_open_failed scope={} os_error={}",
                scope.code(),
                Self::os_error_code(&error)
            )
        })?;
        let backup_name = Self::destination_name(backup)?;
        let source_parent_path = source
            .parent()
            .ok_or("code=authority_snapshot_source_parent_missing")?;
        let source_parent = Self::open_absolute_directory(source_parent_path).map_err(|error| {
            format!(
                "code=authority_snapshot_source_parent_open_failed scope={} os_error={}",
                scope.code(),
                Self::os_error_code(&error)
            )
        })?;
        let source_name = Self::destination_name(source)?;
        Self::copy_tree_from_at(
            source,
            &source_parent,
            &source_name,
            &parent_file,
            &backup_name,
            budget,
            allow_symlink,
            scope,
            root,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn copy_tree_from_at(
        source_logical: &Path,
        source_parent: &std::fs::File,
        source_name: &std::ffi::CStr,
        destination_parent: &std::fs::File,
        destination_name: &std::ffi::CStr,
        budget: &mut AuthorityCopyBudget,
        allow_symlink: bool,
        scope: AuthoritySnapshotScope,
        root: &Path,
    ) -> Result<(), String> {
        let category = Self::category(scope, root, source_logical);
        let metadata = Self::stat_destination_at(source_parent, source_name).map_err(|error| {
            format!(
                "code=authority_snapshot_metadata_failed scope={} category={} os_error={}",
                scope.code(),
                category.code(),
                Self::os_error_code(&error)
            )
        })?;
        let source_kind = metadata.st_mode & crate::platform::S_IFMT;
        if source_kind == crate::platform::S_IFLNK {
            if !allow_symlink {
                return Err(format!(
                    "code=authority_snapshot_root_symlink scope={} category={}",
                    scope.code(),
                    category.code()
                ));
            }
            let expected_len = usize::try_from(metadata.st_size).map_err(|_| {
                format!(
                    "code=authority_snapshot_symlink_size_invalid scope={} category={}",
                    scope.code(),
                    category.code()
                )
            })?;
            let target_bytes =
                Self::readlink_destination_at(source_parent, source_name, expected_len).map_err(
                    |error| {
                        format!(
                    "code=authority_snapshot_symlink_read_failed scope={} category={} os_error={}",
                    scope.code(),
                    category.code(),
                    Self::os_error_code(&error)
                )
                    },
                )?;
            Self::charge_entry(budget, target_bytes.len() as u64, scope, category)?;
            let target_name = std::ffi::CString::new(target_bytes.clone())
                .map_err(|_| "code=authority_snapshot_symlink_target_invalid")?;
            #[cfg(unix)]
            let symlink_result = unsafe {
                libc::symlinkat(
                    target_name.as_ptr(),
                    destination_parent.as_raw_fd(),
                    destination_name.as_ptr(),
                )
            };
            // Windows 降级：symlinkat 无等价物；该分支只会经上游 Unsupported 错误到达。
            #[cfg(not(unix))]
            let symlink_result: i32 = -1;
            if symlink_result != 0 {
                let error = std::io::Error::last_os_error();
                return Err(format!(
                    "code=authority_snapshot_symlink_create_failed scope={} category={} os_error={}",
                    scope.code(),
                    category.code(),
                    Self::os_error_code(&error)
                ));
            }
            let destination_identity =
                Self::stat_destination_at(destination_parent, destination_name)
                    .map_err(|error| {
                        format!(
                            "code=authority_snapshot_symlink_validate_failed scope={} category={} os_error={}",
                            scope.code(),
                            category.code(),
                            Self::os_error_code(&error)
                        )
                    });
            let snapshot_result = (|| -> Result<(), String> {
                let destination_identity = destination_identity?;
                if destination_identity.st_mode & crate::platform::S_IFMT != crate::platform::S_IFLNK {
                    return Err(format!(
                        "code=authority_snapshot_symlink_identity_failed scope={} category={}",
                        scope.code(),
                        category.code()
                    ));
                }
                let final_metadata =
                    Self::stat_destination_at(source_parent, source_name).map_err(
                        |error| {
                            format!(
                                "code=authority_snapshot_symlink_revalidate_failed scope={} category={} os_error={}",
                                scope.code(),
                                category.code(),
                                Self::os_error_code(&error)
                            )
                        },
                    )?;
                let final_target = Self::readlink_destination_at(
                    source_parent,
                    source_name,
                    target_bytes.len(),
                )
                .map_err(|error| {
                    format!(
                        "code=authority_snapshot_symlink_target_revalidate_failed scope={} category={} os_error={}",
                        scope.code(),
                        category.code(),
                        Self::os_error_code(&error)
                    )
                })?;
                if !Self::stat_entry_stable(&metadata, &final_metadata)
                    || final_metadata.st_mode & crate::platform::S_IFMT != crate::platform::S_IFLNK
                    || final_target != target_bytes
                {
                    return Err(format!(
                        "code=authority_snapshot_symlink_changed scope={} category={}",
                        scope.code(),
                        category.code()
                    ));
                }
                let final_destination =
                    Self::stat_destination_at(destination_parent, destination_name)
                        .map_err(|error| {
                            format!(
                                "code=authority_snapshot_symlink_entry_revalidate_failed scope={} category={} os_error={}",
                                scope.code(),
                                category.code(),
                                Self::os_error_code(&error)
                            )
                        })?;
                let final_destination_target = Self::readlink_destination_at(
                    destination_parent,
                    destination_name,
                    target_bytes.len(),
                )
                .map_err(|error| {
                    format!(
                        "code=authority_snapshot_symlink_target_validate_failed scope={} category={} os_error={}",
                        scope.code(),
                        category.code(),
                        Self::os_error_code(&error)
                    )
                })?;
                if final_destination.st_dev != destination_identity.st_dev
                    || final_destination.st_ino != destination_identity.st_ino
                    || final_destination.st_mode & crate::platform::S_IFMT != crate::platform::S_IFLNK
                    || final_destination_target != target_bytes
                {
                    return Err(format!(
                        "code=authority_snapshot_destination_rebound scope={} category={} kind=symlink",
                        scope.code(),
                        category.code()
                    ));
                }
                destination_parent.sync_all().map_err(|error| {
                    format!(
                        "code=authority_snapshot_parent_sync_failed scope={} category={} os_error={}",
                        scope.code(),
                        category.code(),
                        Self::os_error_code(&error)
                    )
                })
            })();
            if let Err(primary) = snapshot_result {
                return match Self::cleanup_created_destination(
                    destination_parent,
                    destination_name,
                    scope,
                    category,
                ) {
                    Ok(()) => Err(primary),
                    Err(cleanup) => Err(format!("{primary}; {cleanup}")),
                };
            }
            return Ok(());
        }
        if source_kind == crate::platform::S_IFREG {
            let source_size = u64::try_from(metadata.st_size).map_err(|_| {
                format!(
                    "code=authority_snapshot_source_size_invalid scope={} category={}",
                    scope.code(),
                    category.code()
                )
            })?;
            let source_mode = u32::from(metadata.st_mode) & 0o777;
            Self::charge_entry(budget, source_size, scope, category)?;
            let mut input = Self::open_destination_at(
                source_parent.as_raw_fd(),
                source_name,
                crate::platform::O_RDONLY,
                0,
            )
            .map_err(|error| {
                format!(
                    "code=authority_snapshot_source_open_failed scope={} category={} os_error={}",
                    scope.code(),
                    category.code(),
                    Self::os_error_code(&error)
                )
            })?;
            let opened = input
                .metadata()
                .map_err(|error| {
                    format!(
                        "code=authority_snapshot_source_open_validate_failed scope={} category={} os_error={}",
                        scope.code(),
                        category.code(),
                        Self::os_error_code(&error)
                    )
                })?;
            if !opened.is_file()
                || !Self::destination_entry_matches_file(&metadata, &opened, crate::platform::S_IFREG)
                || opened.len() != source_size
            {
                return Err(format!(
                    "code=authority_snapshot_source_changed scope={} category={} phase=open",
                    scope.code(),
                    category.code()
                ));
            }
            let parent_fd = destination_parent.as_raw_fd();
            let clone_result =
                Self::clone_regular_file_at(input.as_raw_fd(), parent_fd, destination_name);
            let mut destination_created = clone_result.is_ok();
            let cloned = clone_result.is_ok();
            let snapshot_result = (|| -> Result<(), String> {
                let output = match clone_result {
                    Ok(()) => Self::open_destination_at(
                        parent_fd,
                        destination_name,
                        crate::platform::O_RDONLY,
                        0,
                    )
                    .map_err(|error| {
                        format!(
                            "code=authority_snapshot_clone_open_failed scope={} category={} os_error={}",
                            scope.code(),
                            category.code(),
                            Self::os_error_code(&error)
                        )
                    })?,
                    Err(clone_error)
                        if matches!(
                            clone_error.raw_os_error(),
                            Some(libc::ENOTSUP) | Some(libc::EXDEV)
                        ) =>
                    {
                        Self::charge_full_copy(budget, source_size, scope, category)?;
                        let mut output = Self::open_destination_at(
                            parent_fd,
                            destination_name,
                            crate::platform::O_WRONLY | crate::platform::O_CREAT | crate::platform::O_EXCL,
                            0o600,
                        )
                        .map_err(|error| {
                            format!(
                                "code=authority_snapshot_copy_create_failed scope={} category={} os_error={}",
                                scope.code(),
                                category.code(),
                                Self::os_error_code(&error)
                            )
                        })?;
                        destination_created = true;
                        #[cfg(test)]
                        if SANDBOX_SESSION_TEST_SEAMS
                            .lock()
                            .unwrap_or_else(|error| error.into_inner())
                            .authority_fallback_fail_after_create
                            .is_some_and(|thread| thread == std::thread::current().id())
                        {
                            return Err(format!(
                                "code=authority_snapshot_copy_injected_failure scope={} category={}",
                                scope.code(),
                                category.code()
                            ));
                        }
                        let copied = std::io::copy(&mut input, &mut output).map_err(|error| {
                            format!(
                                "code=authority_snapshot_copy_failed scope={} category={} os_error={}",
                                scope.code(),
                                category.code(),
                                Self::os_error_code(&error)
                            )
                        })?;
                        if copied != source_size {
                            return Err(format!(
                                "code=authority_snapshot_source_changed scope={} category={} phase=copy",
                                scope.code(),
                                category.code()
                            ));
                        }
                        output
                    }
                    Err(clone_error) => {
                        return Err(format!(
                            "code=authority_snapshot_clone_failed scope={} category={} os_error={}",
                            scope.code(),
                            category.code(),
                            Self::os_error_code(&clone_error)
                        ))
                    }
                };
                output
                    .set_permissions(crate::platform::permissions_from_mode(source_mode))
                    .map_err(|error| {
                        format!(
                            "code=authority_snapshot_chmod_failed scope={} category={} os_error={}",
                            scope.code(),
                            category.code(),
                            Self::os_error_code(&error)
                        )
                    })?;
                let saved = output.metadata().map_err(|error| {
                    format!(
                        "code=authority_snapshot_validate_failed scope={} category={} os_error={}",
                        scope.code(),
                        category.code(),
                        Self::os_error_code(&error)
                    )
                })?;
                if !saved.is_file()
                    || (cloned && saved.dev() != opened.dev())
                    || (saved.dev() == opened.dev() && saved.ino() == opened.ino())
                    || saved.len() != opened.len()
                    || saved.permissions().mode() & 0o777 != source_mode
                {
                    return Err(format!(
                        "code=authority_snapshot_independence_failed scope={} category={}",
                        scope.code(),
                        category.code()
                    ));
                }
                let destination_entry =
                    Self::stat_destination_at(destination_parent, destination_name)
                        .map_err(|error| {
                            format!(
                                "code=authority_snapshot_entry_revalidate_failed scope={} category={} os_error={}",
                                scope.code(),
                                category.code(),
                                Self::os_error_code(&error)
                            )
                        })?;
                if !Self::destination_entry_matches_file(&destination_entry, &saved, crate::platform::S_IFREG)
                {
                    return Err(format!(
                        "code=authority_snapshot_destination_rebound scope={} category={} kind=file",
                        scope.code(),
                        category.code()
                    ));
                }
                let final_entry =
                    Self::stat_destination_at(source_parent, source_name).map_err(
                        |error| {
                            format!(
                                "code=authority_snapshot_source_entry_revalidate_failed scope={} category={} os_error={}",
                                scope.code(),
                                category.code(),
                                Self::os_error_code(&error)
                            )
                        },
                    )?;
                let final_metadata = input.metadata().map_err(|error| {
                    format!(
                        "code=authority_snapshot_source_revalidate_failed scope={} category={} os_error={}",
                        scope.code(),
                        category.code(),
                        Self::os_error_code(&error)
                    )
                })?;
                if !Self::stat_entry_stable(&metadata, &final_entry)
                    || !Self::destination_entry_matches_file(
                        &final_entry,
                        &final_metadata,
                        crate::platform::S_IFREG,
                    )
                    || final_metadata.dev() != opened.dev()
                    || final_metadata.ino() != opened.ino()
                    || final_metadata.len() != opened.len()
                    || final_metadata.permissions().mode() & 0o777
                        != opened.permissions().mode() & 0o777
                    || final_metadata.mtime() != opened.mtime()
                    || final_metadata.mtime_nsec() != opened.mtime_nsec()
                {
                    return Err(format!(
                        "code=authority_snapshot_source_changed scope={} category={} phase=revalidate",
                        scope.code(),
                        category.code()
                    ));
                }
                output.sync_all().map_err(|error| {
                    format!(
                        "code=authority_snapshot_sync_failed scope={} category={} os_error={}",
                        scope.code(),
                        category.code(),
                        Self::os_error_code(&error)
                    )
                })?;
                destination_parent.sync_all().map_err(|error| {
                    format!(
                        "code=authority_snapshot_parent_sync_failed scope={} category={} os_error={}",
                        scope.code(),
                        category.code(),
                        Self::os_error_code(&error)
                    )
                })?;
                Ok(())
            })();
            if let Err(primary) = snapshot_result {
                if destination_created {
                    return match Self::cleanup_created_destination(
                        destination_parent,
                        destination_name,
                        scope,
                        category,
                    ) {
                        Ok(()) => Err(primary),
                        Err(cleanup) => Err(format!("{primary}; {cleanup}")),
                    };
                }
                return Err(primary);
            }
            return Ok(());
        }
        if source_kind != crate::platform::S_IFDIR {
            return Err(format!(
                "code=authority_snapshot_special_file scope={} category={}",
                scope.code(),
                category.code()
            ));
        }
        let source_directory =
            Self::open_directory_at(source_parent.as_raw_fd(), source_name).map_err(
                |error| {
                    format!(
                        "code=authority_snapshot_directory_source_open_failed scope={} category={} os_error={}",
                        scope.code(),
                        category.code(),
                        Self::os_error_code(&error)
                    )
                },
            )?;
        let source_directory_metadata = source_directory.metadata().map_err(|error| {
            format!(
                "code=authority_snapshot_directory_source_validate_failed scope={} category={} os_error={}",
                scope.code(),
                category.code(),
                Self::os_error_code(&error)
            )
        })?;
        if !source_directory_metadata.is_dir()
            || !Self::destination_entry_matches_file(
                &metadata,
                &source_directory_metadata,
                crate::platform::S_IFDIR,
            )
        {
            return Err(format!(
                "code=authority_snapshot_source_changed scope={} category={} phase=directory_open",
                scope.code(),
                category.code()
            ));
        }
        let source_mode = u32::from(metadata.st_mode) & 0o777;
        Self::charge_entry(budget, 0, scope, category)?;
        Self::mkdir_destination_at(destination_parent.as_raw_fd(), destination_name, 0o700)
            .map_err(|error| {
                format!(
                "code=authority_snapshot_directory_create_failed scope={} category={} os_error={}",
                scope.code(),
                category.code(),
                Self::os_error_code(&error)
            )
            })?;
        let created_destination_entry =
            Self::stat_destination_at(destination_parent, destination_name)
                .map_err(|error| {
                    format!(
                        "code=authority_snapshot_directory_entry_validate_failed scope={} category={} os_error={}",
                        scope.code(),
                        category.code(),
                        Self::os_error_code(&error)
                    )
                })?;
        let destination_directory =
            Self::open_directory_at(destination_parent.as_raw_fd(), destination_name).map_err(
                |error| {
                    format!(
                "code=authority_snapshot_directory_open_failed scope={} category={} os_error={}",
                scope.code(),
                category.code(),
                Self::os_error_code(&error)
            )
                },
            )?;
        destination_directory
            .set_permissions(crate::platform::permissions_from_mode(0o700))
            .map_err(|error| {
                format!(
                    "code=authority_snapshot_directory_chmod_failed scope={} category={} os_error={}",
                    scope.code(),
                    category.code(),
                    Self::os_error_code(&error)
                )
            })?;
        let destination_metadata = destination_directory.metadata().map_err(|error| {
            format!(
                "code=authority_snapshot_directory_validate_failed scope={} category={} os_error={}",
                scope.code(),
                category.code(),
                Self::os_error_code(&error)
            )
        })?;
        if !destination_metadata.is_dir()
            || destination_metadata.file_type().is_symlink()
            || destination_metadata.uid() != unsafe { crate::platform::geteuid() }
            || (destination_metadata.dev() == source_directory_metadata.dev()
                && destination_metadata.ino() == source_directory_metadata.ino())
            || !Self::destination_entry_matches_file(
                &created_destination_entry,
                &destination_metadata,
                crate::platform::S_IFDIR,
            )
        {
            return Err(format!(
                "code=authority_snapshot_directory_identity_failed scope={} category={}",
                scope.code(),
                category.code()
            ));
        }
        let children = Self::read_directory_names(&source_directory).map_err(|error| {
            format!(
                "code=authority_snapshot_directory_enumerate_failed scope={} category={} os_error={}",
                scope.code(),
                category.code(),
                Self::os_error_code(&error)
            )
        })?;
        let initial_manifest = Self::directory_manifest_at(&source_directory, &children)?;
        #[cfg(test)]
        if let Some(barrier) = SANDBOX_SESSION_TEST_SEAMS
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .directory_barrier
            .as_ref()
            .filter(|(target, _)| target == source_logical)
            .map(|(_, barrier)| barrier.clone())
        {
            std::fs::create_dir_all(&barrier)
                .map_err(|error| format!("test-only snapshot barrier create failed: {error}"))?;
            std::fs::write(barrier.join("ready"), b"ready\n")
                .map_err(|error| format!("test-only snapshot barrier arm failed: {error}"))?;
            let mut released = false;
            for _ in 0..200 {
                if barrier.join("release").is_file() {
                    released = true;
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            if !released {
                return Err("test-only authority snapshot barrier timed out".into());
            }
        }
        for child in &children {
            let child_name = std::ffi::CString::new(child.as_encoded_bytes()).map_err(|_| {
                format!(
                    "code=authority_snapshot_source_name_invalid scope={} category={}",
                    scope.code(),
                    category.code()
                )
            })?;
            let child_logical = source_logical.join(child);
            Self::copy_tree_from_at(
                &child_logical,
                &source_directory,
                &child_name,
                &destination_directory,
                &child_name,
                budget,
                true,
                scope,
                root,
            )?;
        }
        let final_children =
            Self::read_directory_names(&source_directory).map_err(|error| {
                format!(
                    "code=authority_snapshot_directory_reenumerate_failed scope={} category={} os_error={}",
                    scope.code(),
                    category.code(),
                    Self::os_error_code(&error)
                )
            })?;
        let final_manifest = Self::directory_manifest_at(&source_directory, &final_children)?;
        let final_entry =
            Self::stat_destination_at(source_parent, source_name).map_err(|error| {
                format!(
                    "code=authority_snapshot_directory_source_entry_revalidate_failed scope={} category={} os_error={}",
                    scope.code(),
                    category.code(),
                    Self::os_error_code(&error)
                )
            })?;
        let final_metadata = source_directory.metadata().map_err(|error| {
            format!(
                "code=authority_snapshot_directory_source_revalidate_failed scope={} category={} os_error={}",
                scope.code(),
                category.code(),
                Self::os_error_code(&error)
            )
        })?;
        let membership_stable = initial_manifest == final_manifest && children == final_children;
        let entry_stable = Self::stat_entry_stable(&metadata, &final_entry);
        let binding_stable =
            Self::destination_entry_matches_file(&final_entry, &final_metadata, crate::platform::S_IFDIR);
        let opened_stable = final_metadata.dev() == source_directory_metadata.dev()
            && final_metadata.ino() == source_directory_metadata.ino()
            && final_metadata.uid() == source_directory_metadata.uid()
            && final_metadata.permissions().mode() & 0o777
                == source_directory_metadata.permissions().mode() & 0o777
            && final_metadata.mtime() == source_directory_metadata.mtime()
            && final_metadata.mtime_nsec() == source_directory_metadata.mtime_nsec();
        if !membership_stable
            || !final_metadata.is_dir()
            || !entry_stable
            || !binding_stable
            || !opened_stable
        {
            let manifest_detail = initial_manifest
                .iter()
                .zip(&final_manifest)
                .enumerate()
                .find_map(|(index, (initial, final_entry))| {
                    (initial != final_entry).then(|| {
                        format!(
                            " first_mismatch_index={index} name_equal={} kind_equal={} device_equal={} inode_equal={} size_equal={} mode_equal={} mtime_equal={}",
                            initial.name == final_entry.name,
                            initial.kind == final_entry.kind,
                            initial.device == final_entry.device,
                            initial.inode == final_entry.inode,
                            initial.size == final_entry.size,
                            initial.mode == final_entry.mode,
                            initial.modified_seconds == final_entry.modified_seconds
                                && initial.modified_nanoseconds
                                    == final_entry.modified_nanoseconds
                        )
                    })
                })
                .unwrap_or_default();
            return Err(format!(
                "code=authority_snapshot_directory_changed scope={} category={} membership_stable={} entry_stable={} binding_stable={} opened_stable={} initial_entries={} final_entries={}{}",
                scope.code(),
                category.code(),
                membership_stable,
                entry_stable,
                binding_stable,
                opened_stable,
                initial_manifest.len(),
                final_manifest.len(),
                manifest_detail
            ));
        }
        destination_directory
            .set_permissions(crate::platform::permissions_from_mode(
                source_mode,
            ))
            .map_err(|error| {
                format!(
                    "code=authority_snapshot_directory_chmod_failed scope={} category={} os_error={}",
                    scope.code(),
                    category.code(),
                    Self::os_error_code(&error)
                )
            })?;
        let final_destination_metadata =
            destination_directory.metadata().map_err(|error| {
                format!(
                    "code=authority_snapshot_directory_validate_failed scope={} category={} os_error={}",
                    scope.code(),
                    category.code(),
                    Self::os_error_code(&error)
                )
            })?;
        let final_destination_entry =
            Self::stat_destination_at(destination_parent, destination_name)
                .map_err(|error| {
                    format!(
                        "code=authority_snapshot_directory_entry_revalidate_failed scope={} category={} os_error={}",
                        scope.code(),
                        category.code(),
                        Self::os_error_code(&error)
                    )
                })?;
        if !Self::destination_entry_matches_file(
            &final_destination_entry,
            &final_destination_metadata,
            crate::platform::S_IFDIR,
        ) {
            return Err(format!(
                "code=authority_snapshot_destination_rebound scope={} category={} kind=directory",
                scope.code(),
                category.code()
            ));
        }
        destination_directory.sync_all().map_err(|error| {
            format!(
                "code=authority_snapshot_directory_sync_failed scope={} category={} os_error={}",
                scope.code(),
                category.code(),
                Self::os_error_code(&error)
            )
        })?;
        destination_parent.sync_all().map_err(|error| {
            format!(
                "code=authority_snapshot_parent_sync_failed scope={} category={} os_error={}",
                scope.code(),
                category.code(),
                Self::os_error_code(&error)
            )
        })?;
        Ok(())
    }
}
