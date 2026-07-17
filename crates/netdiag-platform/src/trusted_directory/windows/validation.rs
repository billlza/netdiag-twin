use super::{DirectoryTrustError, TrustedDirectory, open};

impl TrustedDirectory {
    pub fn validate_identity(&self) -> Result<(), DirectoryTrustError> {
        let current = open(&self.resolved_path, false)?;
        let unchanged =
            crate::windows::same_file(&self.directory, &current.directory).map_err(|source| {
                DirectoryTrustError::Inspect {
                    path: self.resolved_path.clone(),
                    source,
                }
            })?;
        if !unchanged {
            return Err(DirectoryTrustError::IdentityChanged {
                path: self.resolved_path.clone(),
            });
        }
        Ok(())
    }

    pub fn validate_private_security(&self) -> Result<(), DirectoryTrustError> {
        crate::windows::validate_mutable_parent_security(&self.directory).map_err(|source| {
            DirectoryTrustError::Acl {
                path: self.resolved_path.clone(),
                source,
            }
        })
    }

    pub fn validate_coordination_security(&self) -> Result<(), DirectoryTrustError> {
        crate::windows::validate_private_object_security(&self.directory).map_err(|source| {
            DirectoryTrustError::Acl {
                path: self.resolved_path.clone(),
                source,
            }
        })
    }
}
