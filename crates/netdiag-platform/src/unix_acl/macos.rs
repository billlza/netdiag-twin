use super::UnixAclTrustError;
use std::ffi::{c_int, c_void};
use std::io;
use std::os::fd::{AsRawFd, BorrowedFd};
use std::ptr::NonNull;

const ACL_TYPE_EXTENDED: c_int = 0x0000_0100;
const ACL_FIRST_ENTRY: c_int = 0;
const ACL_NEXT_ENTRY: c_int = -1;
const ACL_EXTENDED_ALLOW: c_int = 1;
const ACL_EXTENDED_DENY: c_int = 2;
const ID_TYPE_UID: c_int = 0;
const ID_TYPE_GID: c_int = 1;
const ENOENT: c_int = 2;
const EINVAL: c_int = 22;
const ACL_MAX_ENTRIES: usize = 128;

const ACL_READ_DATA: u64 = 1 << 1;
const ACL_WRITE_DATA: u64 = 1 << 2;
const ACL_EXECUTE: u64 = 1 << 3;
const ACL_DELETE: u64 = 1 << 4;
const ACL_APPEND_DATA: u64 = 1 << 5;
const ACL_DELETE_CHILD: u64 = 1 << 6;
const ACL_READ_ATTRIBUTES: u64 = 1 << 7;
const ACL_WRITE_ATTRIBUTES: u64 = 1 << 8;
const ACL_READ_EXTATTRIBUTES: u64 = 1 << 9;
const ACL_WRITE_EXTATTRIBUTES: u64 = 1 << 10;
const ACL_READ_SECURITY: u64 = 1 << 11;
const ACL_WRITE_SECURITY: u64 = 1 << 12;
const ACL_CHANGE_OWNER: u64 = 1 << 13;
const ACL_SYNCHRONIZE: u64 = 1 << 20;
const KNOWN_PERMISSIONS: u64 = ACL_READ_DATA
    | ACL_WRITE_DATA
    | ACL_EXECUTE
    | ACL_DELETE
    | ACL_APPEND_DATA
    | ACL_DELETE_CHILD
    | ACL_READ_ATTRIBUTES
    | ACL_WRITE_ATTRIBUTES
    | ACL_READ_EXTATTRIBUTES
    | ACL_WRITE_EXTATTRIBUTES
    | ACL_READ_SECURITY
    | ACL_WRITE_SECURITY
    | ACL_CHANGE_OWNER
    | ACL_SYNCHRONIZE;
const DANGEROUS_PERMISSIONS: u64 = ACL_WRITE_DATA
    | ACL_DELETE
    | ACL_APPEND_DATA
    | ACL_DELETE_CHILD
    | ACL_WRITE_ATTRIBUTES
    | ACL_WRITE_EXTATTRIBUTES
    | ACL_WRITE_SECURITY
    | ACL_CHANGE_OWNER;

#[repr(C)]
struct AclOpaque {
    _private: [u8; 0],
}

#[repr(C)]
struct AclEntryOpaque {
    _private: [u8; 0],
}

type Acl = *mut AclOpaque;
type AclEntry = *mut AclEntryOpaque;

// SAFETY: These declarations exactly mirror the macOS SDK's sys/acl.h and
// membership.h ABIs. All returned allocations are checked for null and freed
// with acl_free, and no pointer outlives the owning ACL.
unsafe extern "C" {
    fn acl_get_fd_np(fd: c_int, acl_type: c_int) -> Acl;
    fn acl_valid(acl: Acl) -> c_int;
    fn acl_get_entry(acl: Acl, entry_id: c_int, entry: *mut AclEntry) -> c_int;
    fn acl_get_tag_type(entry: AclEntry, tag: *mut c_int) -> c_int;
    fn acl_get_permset_mask_np(entry: AclEntry, mask: *mut u64) -> c_int;
    fn acl_get_qualifier(entry: AclEntry) -> *mut c_void;
    fn acl_free(object: *mut c_void) -> c_int;
    fn mbr_uuid_to_id(uuid: *const u8, id: *mut u32, id_type: *mut c_int) -> c_int;
}

struct OwnedAcl(NonNull<AclOpaque>);

impl Drop for OwnedAcl {
    fn drop(&mut self) {
        // SAFETY: The pointer was returned by acl_get_fd_np and this guard is
        // its unique owner. acl_free accepts the allocation as void*.
        unsafe {
            acl_free(self.0.as_ptr().cast());
        }
    }
}

enum Principal {
    User(u32),
    Group(u32),
}

impl Principal {
    fn label(&self) -> String {
        match self {
            Self::User(uid) => format!("uid {uid}"),
            Self::Group(gid) => format!("gid {gid}"),
        }
    }
}

pub(super) fn validate(fd: BorrowedFd<'_>, effective_uid: u32) -> Result<(), UnixAclTrustError> {
    // SAFETY: fd is borrowed and valid for the call; the ACL type constant is
    // defined by macOS. The result is immediately checked and uniquely owned.
    let acl = unsafe { acl_get_fd_np(fd.as_raw_fd(), ACL_TYPE_EXTENDED) };
    let Some(acl) = NonNull::new(acl).map(OwnedAcl) else {
        let source = io::Error::last_os_error();
        // macOS uses ENOENT specifically to report that a valid opened object
        // has no extended ACL. The borrowed descriptor itself cannot disappear
        // during this call, so this is the explicit empty-ACL state, not a
        // path lookup fallback.
        if source.raw_os_error() == Some(ENOENT) {
            return Ok(());
        }
        return Err(UnixAclTrustError::inspection("acl_get_fd_np", source));
    };
    // SAFETY: the ACL allocation is live for this call. Validation makes an
    // EINVAL from subsequent iteration an unambiguous end-of-list marker.
    if unsafe { acl_valid(acl.0.as_ptr()) } != 0 {
        return Err(UnixAclTrustError::inspection(
            "acl_valid",
            io::Error::last_os_error(),
        ));
    }
    validate_entries(acl.0.as_ptr(), effective_uid)
}

fn validate_entries(acl: Acl, effective_uid: u32) -> Result<(), UnixAclTrustError> {
    let mut entry_id = ACL_FIRST_ENTRY;
    for index in 0..=ACL_MAX_ENTRIES {
        let mut entry = std::ptr::null_mut();
        // SAFETY: acl is live for this function and entry points to writable
        // storage for the borrowed entry pointer.
        let status = unsafe { acl_get_entry(acl, entry_id, &mut entry) };
        if status != 0 {
            let source = io::Error::last_os_error();
            if source.raw_os_error() == Some(EINVAL) {
                return Ok(());
            }
            return Err(UnixAclTrustError::inspection("acl_get_entry", source));
        }
        if index == ACL_MAX_ENTRIES {
            return Err(UnixAclTrustError::UnsupportedAcl {
                detail: format!("ACL exceeds the macOS limit of {ACL_MAX_ENTRIES} entries"),
            });
        }
        let entry = NonNull::new(entry).ok_or_else(|| UnixAclTrustError::UnsupportedAcl {
            detail: "acl_get_entry returned a null entry".to_string(),
        })?;
        validate_entry(entry.as_ptr(), effective_uid)?;
        entry_id = ACL_NEXT_ENTRY;
    }
    unreachable!("bounded ACL iteration always returns")
}

fn validate_entry(entry: AclEntry, effective_uid: u32) -> Result<(), UnixAclTrustError> {
    let tag = entry_tag(entry)?;
    let permissions = entry_permissions(entry)?;
    let principal = entry_principal(entry)?;
    if tag == ACL_EXTENDED_ALLOW
        && permissions & DANGEROUS_PERMISSIONS != 0
        && !matches!(principal, Principal::User(uid) if uid == 0 || uid == effective_uid)
    {
        return Err(UnixAclTrustError::UntrustedAllow {
            principal: principal.label(),
        });
    }
    Ok(())
}

fn entry_tag(entry: AclEntry) -> Result<c_int, UnixAclTrustError> {
    let mut tag = 0;
    // SAFETY: entry is a live borrowed ACL entry and tag is writable.
    if unsafe { acl_get_tag_type(entry, &mut tag) } != 0 {
        return Err(UnixAclTrustError::inspection(
            "acl_get_tag_type",
            io::Error::last_os_error(),
        ));
    }
    if !matches!(tag, ACL_EXTENDED_ALLOW | ACL_EXTENDED_DENY) {
        return Err(UnixAclTrustError::UnsupportedAcl {
            detail: format!("unknown macOS ACL tag {tag}"),
        });
    }
    Ok(tag)
}

fn entry_permissions(entry: AclEntry) -> Result<u64, UnixAclTrustError> {
    let mut permissions = 0;
    // SAFETY: entry is live and permissions is writable for the documented
    // 64-bit acl_permset_mask_t result.
    if unsafe { acl_get_permset_mask_np(entry, &mut permissions) } != 0 {
        return Err(UnixAclTrustError::inspection(
            "acl_get_permset_mask_np",
            io::Error::last_os_error(),
        ));
    }
    let unknown = permissions & !KNOWN_PERMISSIONS;
    if unknown != 0 {
        return Err(UnixAclTrustError::UnsupportedAcl {
            detail: format!("unknown macOS ACL permission bits 0x{unknown:x}"),
        });
    }
    Ok(permissions)
}

fn entry_principal(entry: AclEntry) -> Result<Principal, UnixAclTrustError> {
    // SAFETY: entry is a live extended ACL entry. The SDK documents that its
    // qualifier is an acl_free-owned uuid_t allocation.
    let qualifier = unsafe { acl_get_qualifier(entry) };
    let qualifier = NonNull::new(qualifier).ok_or_else(|| UnixAclTrustError::UnsupportedAcl {
        detail: "macOS ACL entry has no qualifier".to_string(),
    })?;
    let mut uuid = [0_u8; 16];
    // SAFETY: A macOS extended ACL qualifier is exactly a 16-byte uuid_t and
    // uuid is valid non-overlapping destination storage.
    unsafe {
        std::ptr::copy_nonoverlapping(
            qualifier.as_ptr().cast::<u8>(),
            uuid.as_mut_ptr(),
            uuid.len(),
        );
    }
    // SAFETY: qualifier came from acl_get_qualifier and is freed exactly once.
    let free_status = unsafe { acl_free(qualifier.as_ptr()) };
    if free_status != 0 {
        return Err(UnixAclTrustError::inspection(
            "acl_free qualifier",
            io::Error::last_os_error(),
        ));
    }

    let mut id = 0_u32;
    let mut id_type = -1;
    // SAFETY: uuid has the expected 16-byte representation and the output
    // pointers remain valid for the duration of the call.
    let status = unsafe { mbr_uuid_to_id(uuid.as_ptr(), &mut id, &mut id_type) };
    if status != 0 {
        return Err(UnixAclTrustError::inspection(
            "mbr_uuid_to_id",
            io::Error::from_raw_os_error(status),
        ));
    }
    match id_type {
        ID_TYPE_UID => Ok(Principal::User(id)),
        ID_TYPE_GID => Ok(Principal::Group(id)),
        _ => Err(UnixAclTrustError::UnsupportedAcl {
            detail: format!("unknown macOS ACL qualifier type {id_type}"),
        }),
    }
}
