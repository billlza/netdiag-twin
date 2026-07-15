use super::{DirectoryTrustError, TrustedDirectory, inspect};

impl TrustedDirectory {
    /// Returns a versioned, fixed-size identity for coarse coordination keys.
    /// Using the opened parent handle collapses case, trailing-dot, Unicode,
    /// and legacy 8.3 path aliases onto the same coordination key.
    pub fn coordination_identity(&self) -> Result<[u8; 32], DirectoryTrustError> {
        crate::windows::identity_bytes(&self.directory)
            .map_err(|source| inspect(&self.resolved_path, source))
    }
}
