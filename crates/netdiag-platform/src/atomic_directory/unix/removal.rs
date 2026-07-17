use super::identity::verify_directory_entry_identity;
use crate::TrustedDirectory;
use rustix::fs::{AtFlags, Dir, FileType, Mode, OFlags, openat, statat, unlinkat};
use std::ffi::{CStr, CString, OsStr};
use std::fs::File;
use std::io;
use std::os::unix::ffi::OsStrExt;

const MAX_REMOVAL_DEPTH: usize = 64;
const MAX_REMOVAL_ENTRIES: usize = 100_000;

struct RemovalBudget {
    entries: usize,
    max_entries: usize,
    max_depth: usize,
}

pub(super) fn remove(
    parent: &TrustedDirectory,
    staged: &TrustedDirectory,
    name: &OsStr,
) -> io::Result<()> {
    remove_with_limits(parent, staged, name, MAX_REMOVAL_DEPTH, MAX_REMOVAL_ENTRIES)
}

fn remove_with_limits(
    parent: &TrustedDirectory,
    staged: &TrustedDirectory,
    name: &OsStr,
    max_depth: usize,
    max_entries: usize,
) -> io::Result<()> {
    if max_depth == 0 || max_entries == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "directory cleanup limits must be non-zero",
        ));
    }
    verify_directory_entry_identity(parent.as_file(), staged.as_file(), name)?;
    let mut budget = RemovalBudget {
        entries: 0,
        max_entries,
        max_depth,
    };
    remove_contents(staged.as_file(), 0, &mut budget)?;
    verify_directory_entry_identity(parent.as_file(), staged.as_file(), name)?;
    unlinkat(parent.as_file(), name, AtFlags::REMOVEDIR).map_err(Into::into)
}

fn remove_contents(directory: &File, depth: usize, budget: &mut RemovalBudget) -> io::Result<()> {
    let entries = read_entries(directory, budget)?;
    for name in entries {
        let metadata = statat(directory, name.as_c_str(), AtFlags::SYMLINK_NOFOLLOW)
            .map_err(io::Error::from)?;
        if FileType::from_raw_mode(metadata.st_mode) == FileType::Directory {
            remove_child_directory(directory, name.as_c_str(), depth, budget)?;
        } else {
            unlinkat(directory, name.as_c_str(), AtFlags::empty()).map_err(io::Error::from)?;
        }
    }
    Ok(())
}

fn read_entries(directory: &File, budget: &mut RemovalBudget) -> io::Result<Vec<CString>> {
    let mut stream = Dir::read_from(directory).map_err(io::Error::from)?;
    let mut entries = Vec::new();
    while let Some(entry) = stream.read() {
        let entry = entry.map_err(io::Error::from)?;
        let name = entry.file_name();
        if is_dot_entry(name) {
            continue;
        }
        budget.entries = budget.entries.checked_add(1).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "directory cleanup entry count overflowed",
            )
        })?;
        if budget.entries > budget.max_entries {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "directory cleanup exceeds the {}-entry safety limit",
                    budget.max_entries
                ),
            ));
        }
        entries.push(name.to_owned());
    }
    Ok(entries)
}

fn remove_child_directory(
    parent: &File,
    name: &CStr,
    depth: usize,
    budget: &mut RemovalBudget,
) -> io::Result<()> {
    let child_depth = depth.checked_add(1).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "directory cleanup depth overflowed",
        )
    })?;
    if child_depth > budget.max_depth {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "directory cleanup exceeds the {}-level depth safety limit",
                budget.max_depth
            ),
        ));
    }
    let child = openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(io::Error::from)?;
    remove_contents(&child, child_depth, budget)?;
    verify_directory_entry_identity(parent, &child, OsStr::from_bytes(name.to_bytes()))?;
    unlinkat(parent, name, AtFlags::REMOVEDIR).map_err(Into::into)
}

fn is_dot_entry(name: &CStr) -> bool {
    matches!(name.to_bytes(), b"." | b"..")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{create_new_private_trusted_subdirectory, open_trusted_directory_chain};
    use std::os::unix::ffi::OsStrExt;

    #[test]
    fn bounded_cleanup_rejects_the_first_excess_entry() {
        let root = tempfile::tempdir().expect("temporary root");
        let parent = open_trusted_directory_chain(root.path()).expect("trusted parent");
        let staged = create_new_private_trusted_subdirectory(&parent, OsStr::new("stage"))
            .expect("private stage");
        std::fs::write(staged.resolved_path().join("one"), b"one").expect("first entry");
        std::fs::write(staged.resolved_path().join("two"), b"two").expect("second entry");

        let error = remove_with_limits(&parent, &staged, OsStr::new("stage"), 8, 1)
            .expect_err("entry budget must fail closed");

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("entry safety limit"), "{error}");
        assert!(root.path().join("stage").is_dir());
    }

    #[test]
    fn nested_cleanup_does_not_follow_symbolic_links() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().expect("temporary root");
        let external = root.path().join("external");
        std::fs::create_dir(&external).expect("external directory");
        std::fs::write(external.join("sentinel"), b"preserved").expect("external sentinel");
        let parent_path = root.path().join("parent");
        std::fs::create_dir(&parent_path).expect("parent directory");
        let parent = open_trusted_directory_chain(&parent_path).expect("trusted parent");
        let staged = create_new_private_trusted_subdirectory(&parent, OsStr::new("stage"))
            .expect("private stage");
        std::fs::create_dir(staged.resolved_path().join("nested")).expect("nested directory");
        std::fs::write(staged.resolved_path().join("nested/artifact"), b"artifact")
            .expect("nested artifact");
        symlink(&external, staged.resolved_path().join("outside-link")).expect("outside link");

        remove(&parent, &staged, OsStr::from_bytes(b"stage")).expect("recursive cleanup");

        assert!(!parent_path.join("stage").exists());
        assert_eq!(
            std::fs::read(external.join("sentinel")).expect("preserved external sentinel"),
            b"preserved"
        );
    }
}
