use crate::error::{IoContext, NetdiagError, Result};
use sha2::{Digest, Sha256};
use std::path::{Component, Path, PathBuf};

const LOCK_NAMESPACE_PREFIX: &str = "netdiag-twin-locks";
const LOCK_KEY_DOMAIN: &[u8] = b"netdiag-twin-coordination-lock/v1\0";
const LOCK_STRIPE_HEX_DIGITS: usize = 3;
const COORDINATION_ROOT_CONTEXT: &str = "coordination lock namespace";

pub(super) fn absolute_target(target: &Path) -> Result<PathBuf> {
    let absolute = if target.is_absolute() {
        target.to_path_buf()
    } else {
        std::env::current_dir().with_path(".")?.join(target)
    };
    let mut normalized = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            Component::RootDir => normalized.push(component.as_os_str()),
            Component::CurDir => {}
            Component::Normal(name) => normalized.push(name),
            Component::ParentDir => {
                return Err(NetdiagError::InvalidTrace(format!(
                    "coordination lock target contains a parent component: {}",
                    target.display()
                )));
            }
        }
    }
    Ok(normalized)
}

pub(super) fn stripe_key(parent_identity: &[u8; 32]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(LOCK_KEY_DOMAIN);
    hasher.update(parent_identity);
    let digest = hasher.finalize();
    let first_twelve_bits = u16::from_be_bytes([digest[0], digest[1]]) >> 4;
    format!("{first_twelve_bits:0LOCK_STRIPE_HEX_DIGITS$x}")
}

#[cfg(unix)]
pub(super) fn namespace_path() -> Result<PathBuf> {
    use rustix::process::geteuid;
    Ok(netdiag_platform::system_temporary_root_path()
        .map_err(coordination_system_temporary_root_error)?
        .join(format!("{LOCK_NAMESPACE_PREFIX}-{}", geteuid().as_raw())))
}

#[cfg(windows)]
pub(super) fn namespace_path() -> Result<PathBuf> {
    let sid = netdiag_platform::current_user_sid_bytes().map_err(|source| {
        NetdiagError::WindowsCoordinationPrincipal {
            context: COORDINATION_ROOT_CONTEXT,
            source,
        }
    })?;
    let mut hasher = Sha256::new();
    hasher.update(b"netdiag-twin-coordination-principal/v1\0");
    hasher.update(sid);
    let principal = format!("{:x}", hasher.finalize());
    let root = netdiag_platform::current_user_local_app_data_path().map_err(|source| {
        NetdiagError::WindowsCoordinationLocalAppData {
            context: COORDINATION_ROOT_CONTEXT,
            source,
        }
    })?;
    Ok(root.join(format!("{LOCK_NAMESPACE_PREFIX}-{principal}")))
}

#[cfg(unix)]
pub(super) fn coordination_system_temporary_root_error(
    source: netdiag_platform::SystemTemporaryRootError,
) -> NetdiagError {
    NetdiagError::CoordinationSystemTemporaryRoot {
        context: COORDINATION_ROOT_CONTEXT,
        source,
    }
}

#[cfg(not(any(unix, windows)))]
pub(super) fn namespace_path() -> Result<PathBuf> {
    Err(NetdiagError::InvalidTrace(
        "coordination locks are unavailable on this platform".to_string(),
    ))
}
