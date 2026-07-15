use super::StagedAdapters;
#[cfg(unix)]
use super::stage::stage_adapter;
#[cfg(unix)]
use super::trusted_root::TrustedRoot;
#[cfg(not(unix))]
use crate::error::NetdiagError;
use crate::error::Result;
#[cfg(unix)]
use crate::managed_temp_directory::ManagedTempDirectory;
use crate::pilot::PilotManifest;
#[cfg(unix)]
use crate::pilot::PilotSourceKind;
#[cfg(unix)]
use std::collections::BTreeMap;
use std::path::Path;

impl StagedAdapters {
    pub(in crate::pilot::pilot_sources::adapter_boundary) fn prepare(
        manifest: &PilotManifest,
        manifest_dir: &Path,
        trusted_root: &Path,
        configured_root: &str,
    ) -> Result<Self> {
        #[cfg(not(unix))]
        {
            let _ = (manifest, manifest_dir, trusted_root, configured_root);
            return Err(NetdiagError::Connector(
                "adapter staging is disabled on this platform because no atomic no-follow filesystem boundary is available"
                    .to_string(),
            ));
        }
        #[cfg(unix)]
        {
            Self::prepare_unix_with_directory_hook(
                manifest,
                manifest_dir,
                trusted_root,
                configured_root,
                |_| {},
            )
        }
    }

    #[cfg(unix)]
    pub(super) fn prepare_unix_with_directory_hook(
        manifest: &PilotManifest,
        manifest_dir: &Path,
        trusted_root_path: &Path,
        configured_root: &str,
        after_directory_created: impl FnOnce(&Path),
    ) -> Result<Self> {
        let trusted_root = TrustedRoot::open(trusted_root_path, configured_root)?;
        let directory = ManagedTempDirectory::create(
            "trusted adapter staging directory",
            "netdiag-trusted-adapters-",
        )?;
        let operation = (|| {
            after_directory_created(directory.path());
            let mut adapters = BTreeMap::new();
            for source in manifest
                .sources
                .iter()
                .filter(|source| source.kind == PilotSourceKind::AdapterSample)
            {
                let staged = stage_adapter(
                    manifest_dir,
                    &trusted_root,
                    directory.path(),
                    &source.name,
                    &source.endpoint,
                )?;
                adapters.insert(source.name.clone(), staged);
            }
            trusted_root.verify_unchanged()?;
            Ok(adapters)
        })();
        let adapters = match operation {
            Ok(adapters) => adapters,
            Err(error) => return directory.finish(Err(error)),
        };
        Ok(Self {
            directory,
            adapters,
        })
    }
}
