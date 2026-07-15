use crate::error::{IoContext, NetdiagError, Result};
use std::ffi::OsStr;
use std::path::{Component, Path, PathBuf};

#[cfg(any(unix, windows))]
use std::sync::Arc;

#[cfg(unix)]
mod durability;
mod security;

#[derive(Clone)]
pub(super) struct TrustedModelDirectory {
    path: PathBuf,
    #[cfg(any(unix, windows))]
    directory: Arc<netdiag_platform::TrustedDirectory>,
    #[cfg(unix)]
    parent_directory: Option<Arc<netdiag_platform::TrustedDirectory>>,
}

enum OpenMode {
    Existing,
    CreateDurable,
}

impl TrustedModelDirectory {
    pub(super) fn open(path: &Path) -> Result<Self> {
        Self::open_with(path, OpenMode::Existing)
    }

    pub(super) fn open_or_create_durable(path: &Path) -> Result<Self> {
        Self::open_with(path, OpenMode::CreateDurable)
    }

    pub(super) fn path(&self) -> &Path {
        &self.path
    }

    pub(super) fn open_existing_child(&self, name: &OsStr) -> Result<Self> {
        validate_child_name(name)?;
        self.validate()?;
        let path = self.path.join(name);
        self.finish(Self::open(&path))
    }

    pub(super) fn open_or_create_durable_child(&self, name: &OsStr) -> Result<Self> {
        validate_child_name(name)?;
        self.validate()?;
        #[cfg(any(unix, windows))]
        {
            let directory = netdiag_platform::open_or_create_durable_trusted_subdirectory(
                &self.directory,
                name,
            )
            .map_err(trust_error)?;
            let trusted = Self::from_opened(directory)?;
            #[cfg(unix)]
            let trusted = {
                let mut trusted = trusted;
                trusted.parent_directory = Some(Arc::clone(&self.directory));
                trusted
            };
            self.finish(Ok(trusted))
        }
        #[cfg(not(any(unix, windows)))]
        {
            Err(unsupported_trust())
        }
    }

    pub(super) fn validate(&self) -> Result<()> {
        #[cfg(any(unix, windows))]
        {
            validate_opened(&self.directory, &self.path)
        }
        #[cfg(not(any(unix, windows)))]
        {
            Err(unsupported_trust())
        }
    }

    pub(super) fn finish<T>(&self, result: Result<T>) -> Result<T> {
        combine_validation(result, self.validate())
    }

    fn open_with(path: &Path, mode: OpenMode) -> Result<Self> {
        let absolute = absolute_path(path)?;
        #[cfg(any(unix, windows))]
        {
            let directory = match mode {
                OpenMode::Existing => netdiag_platform::open_trusted_directory_chain(&absolute),
                OpenMode::CreateDurable => {
                    netdiag_platform::open_or_create_durable_trusted_directory_chain(&absolute)
                }
            };
            Self::from_opened(directory.map_err(trust_error)?)
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = (absolute, mode);
            Err(unsupported_trust())
        }
    }

    #[cfg(any(unix, windows))]
    fn from_opened(directory: netdiag_platform::TrustedDirectory) -> Result<Self> {
        let trusted = Self {
            path: directory.resolved_path().to_path_buf(),
            directory: Arc::new(directory),
            #[cfg(unix)]
            parent_directory: None,
        };
        trusted.validate()?;
        Ok(trusted)
    }
}

#[cfg(any(unix, windows))]
fn validate_opened(directory: &netdiag_platform::TrustedDirectory, path: &Path) -> Result<()> {
    directory.validate_identity().map_err(trust_error)?;
    directory.validate_private_security().map_err(trust_error)?;
    security::validate(directory, path)?;
    directory.validate_identity().map_err(trust_error)
}

fn absolute_path(path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(std::env::current_dir()
            .with_path(Path::new("."))?
            .join(path))
    }
}

fn validate_child_name(name: &OsStr) -> Result<()> {
    let mut components = Path::new(name).components();
    if !matches!(components.next(), Some(Component::Normal(_))) || components.next().is_some() {
        return Err(NetdiagError::Ml(format!(
            "model bundle child name is unsafe: {name:?}"
        )));
    }
    Ok(())
}

fn combine_validation<T>(result: Result<T>, validation: Result<()>) -> Result<T> {
    match (result, validation) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
        (Err(primary), Err(identity)) => Err(primary.with_secondary_failure(
            "model bundle operation failed",
            "model bundle directory post-operation validation also failed",
            identity,
        )),
    }
}

#[cfg(any(unix, windows))]
pub(super) fn trust_error(source: netdiag_platform::DirectoryTrustError) -> NetdiagError {
    NetdiagError::FilesystemTrust {
        context: "model bundle directory",
        source,
    }
}

#[cfg(not(any(unix, windows)))]
fn unsupported_trust() -> NetdiagError {
    NetdiagError::Ml(
        "model bundle directory trust validation is unavailable on this platform".to_string(),
    )
}
