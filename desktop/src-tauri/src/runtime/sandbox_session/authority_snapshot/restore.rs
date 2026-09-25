impl AuthorityTreeSnapshot {
    pub(super) fn remove_current_at(
        scope: AuthoritySnapshotScope,
        parent: &std::fs::File,
        name: &std::ffi::CStr,
    ) -> Result<(), String> {
        let metadata = match Self::stat_destination_at(parent, name) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return parent.sync_all().map_err(|sync_error| {
                    format!(
                        "code=authority_restore_parent_sync_failed scope={} os_error={}",
                        scope.code(),
                        Self::os_error_code(&sync_error)
                    )
                })
            }
            Err(error) => {
                return Err(format!(
                    "code=authority_restore_metadata_failed scope={} os_error={}",
                    scope.code(),
                    Self::os_error_code(&error)
                ))
            }
        };
        if metadata.st_mode & crate::platform::S_IFMT == crate::platform::S_IFLNK {
            return Err(format!(
                "code=authority_restore_root_symlink scope={}",
                scope.code()
            ));
        }
        if matches!(
            metadata.st_mode & crate::platform::S_IFMT,
            crate::platform::S_IFDIR | crate::platform::S_IFREG
        ) {
            Self::remove_tree_at(parent, name).map_err(|error| {
                format!(
                    "code=authority_restore_remove_failed scope={} os_error={}",
                    scope.code(),
                    Self::os_error_code(&error)
                )
            })
        } else {
            Err(format!(
                "code=authority_restore_special_file scope={}",
                scope.code()
            ))
        }
    }

    pub(super) fn validate_backup_identity(&self) -> Result<(), String> {
        let Some((expected_device, expected_inode, expected_kind)) = self.backup_identity else {
            return if self.existed {
                Err(format!(
                    "code=authority_restore_backup_identity_missing scope={}",
                    self.scope.code()
                ))
            } else {
                Ok(())
            };
        };
        let parent = self.backup_parent.as_ref().ok_or_else(|| {
            format!(
                "code=authority_restore_backup_parent_missing scope={}",
                self.scope.code()
            )
        })?;
        let name = self.backup_name.as_deref().ok_or_else(|| {
            format!(
                "code=authority_restore_backup_name_missing scope={}",
                self.scope.code()
            )
        })?;
        let parent_path = self
            .backup
            .parent()
            .ok_or("code=authority_restore_backup_parent_missing")?;
        if !Self::absolute_directory_binding_matches(parent_path, parent).map_err(|error| {
            format!(
                "code=authority_restore_backup_parent_revalidate_failed scope={} os_error={}",
                self.scope.code(),
                Self::os_error_code(&error)
            )
        })? {
            return Err(format!(
                "code=authority_restore_backup_parent_rebound scope={}",
                self.scope.code()
            ));
        }
        let current = Self::stat_destination_at(parent, name).map_err(|error| {
            format!(
                "code=authority_restore_backup_validate_failed scope={} os_error={}",
                self.scope.code(),
                Self::os_error_code(&error)
            )
        })?;
        if u64::try_from(current.st_dev).ok() != Some(expected_device)
            || inode_u64(current.st_ino) != Some(expected_inode)
            || current.st_mode & crate::platform::S_IFMT != expected_kind
        {
            return Err(format!(
                "code=authority_restore_backup_identity_changed scope={}",
                self.scope.code()
            ));
        }
        Ok(())
    }

    pub(super) fn restore(&mut self) -> Result<(), String> {
        self.validate_backup_identity()?;
        let parent_path = self.source.parent().ok_or("隔离 authority 没有父目录")?;
        let opened_parent;
        let parent = match self.source_parent.as_ref() {
            Some(parent) => {
                if !Self::absolute_directory_binding_matches(parent_path, parent).map_err(
                    |error| {
                        format!(
                            "code=authority_restore_parent_revalidate_failed scope={} os_error={}",
                            self.scope.code(),
                            Self::os_error_code(&error)
                        )
                    },
                )? {
                    return Err(format!(
                        "code=authority_restore_parent_rebound scope={}",
                        self.scope.code()
                    ));
                }
                parent
            }
            None => {
                opened_parent = match Self::open_absolute_directory(parent_path) {
                    Ok(parent) => parent,
                    Err(error) if !self.existed && error.kind() == std::io::ErrorKind::NotFound => {
                        return Ok(())
                    }
                    Err(error) => {
                        return Err(format!(
                            "code=authority_restore_parent_open_failed scope={} os_error={}",
                            self.scope.code(),
                            Self::os_error_code(&error)
                        ))
                    }
                };
                &opened_parent
            }
        };
        let computed_source_name;
        let source_name = match self.source_name.as_deref() {
            Some(name) => name,
            None => {
                computed_source_name = Self::destination_name(&self.source)?;
                &computed_source_name
            }
        };
        Self::remove_current_at(self.scope, parent, source_name)?;
        if self.existed {
            let mut budget = AuthorityCopyBudget::default();
            let backup_root = self.backup.clone();
            let backup_parent = self.backup_parent.as_ref().ok_or_else(|| {
                format!(
                    "code=authority_restore_backup_parent_missing scope={}",
                    self.scope.code()
                )
            })?;
            let backup_name = self.backup_name.as_deref().ok_or_else(|| {
                format!(
                    "code=authority_restore_backup_name_missing scope={}",
                    self.scope.code()
                )
            })?;
            Self::copy_tree_from_at(
                &self.backup,
                backup_parent,
                backup_name,
                parent,
                source_name,
                &mut budget,
                false,
                self.scope,
                &backup_root,
            )
            .map_err(|error| format!("无法恢复隔离 authority：{error}"))?;
            self.validate_backup_identity()?;
        }
        if !Self::absolute_directory_binding_matches(parent_path, parent).map_err(|error| {
            format!(
                "code=authority_restore_parent_revalidate_failed scope={} os_error={}",
                self.scope.code(),
                Self::os_error_code(&error)
            )
        })? {
            return Err(format!(
                "code=authority_restore_parent_rebound scope={}",
                self.scope.code()
            ));
        }
        Ok(())
    }
}
