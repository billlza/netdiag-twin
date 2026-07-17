use super::super::sid::TrustedSids;
use super::AclPolicy;
use std::io;
use std::mem::{offset_of, size_of};
use std::ptr;
use windows_sys::Win32::Foundation::{GENERIC_ALL, GENERIC_WRITE};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, ACL_SIZE_INFORMATION, AclSizeInformation, GetAce,
    GetAclInformation, GetLengthSid, IsValidSid, PSID,
};
use windows_sys::Win32::Storage::FileSystem::{
    DELETE, FILE_ALL_ACCESS, FILE_APPEND_DATA, FILE_DELETE_CHILD, FILE_WRITE_ATTRIBUTES,
    FILE_WRITE_DATA, FILE_WRITE_EA, WRITE_DAC, WRITE_OWNER,
};
use windows_sys::Win32::System::SystemServices::{
    ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE, ACCESS_SYSTEM_SECURITY, MAXIMUM_ALLOWED,
};

const MAX_PRIVATE_ACES: u32 = 32;
const MIN_SID_BYTES: usize = 8;

pub(super) fn validate(dacl: *mut ACL, trusted: &TrustedSids, policy: AclPolicy) -> io::Result<()> {
    let mut information = ACL_SIZE_INFORMATION::default();
    // SAFETY: `dacl` passed IsValidAcl and `information` is writable.
    if unsafe {
        GetAclInformation(
            dacl,
            (&mut information as *mut ACL_SIZE_INFORMATION).cast(),
            size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if information.AceCount == 0 || information.AceCount > MAX_PRIVATE_ACES {
        return Err(io::Error::other(
            "Windows coordination DACL has an invalid ACE count",
        ));
    }
    let mut rights = [0_u32; 3];
    for index in 0..information.AceCount {
        validate_ace(dacl, index, trusted, policy, &mut rights)?;
    }
    if policy == AclPolicy::PrivateCoordination
        && rights
            .iter()
            .any(|mask| mask & FILE_ALL_ACCESS != FILE_ALL_ACCESS && mask & GENERIC_ALL == 0)
    {
        return Err(io::Error::other(
            "Windows coordination DACL does not grant full control to every trusted principal",
        ));
    }
    Ok(())
}

fn validate_ace(
    dacl: *mut ACL,
    index: u32,
    trusted: &TrustedSids,
    policy: AclPolicy,
    rights: &mut [u32; 3],
) -> io::Result<()> {
    let mut raw_ace = ptr::null_mut();
    // SAFETY: IsValidAcl and the bounded ACE count validate this index.
    if unsafe { GetAce(dacl, index, &mut raw_ace) } == 0 || raw_ace.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: GetAce returns at least an ACE_HEADER for a valid ACL entry.
    let header = unsafe { &*raw_ace.cast::<ACE_HEADER>() };
    if u32::from(header.AceType) == ACCESS_DENIED_ACE_TYPE && policy == AclPolicy::MutableParent {
        return Ok(());
    }
    if u32::from(header.AceType) != ACCESS_ALLOWED_ACE_TYPE {
        return Err(io::Error::other(
            "Windows coordination DACL contains a non-allow or unsupported ACE",
        ));
    }
    let ace_size = usize::from(header.AceSize);
    let sid_offset = offset_of!(ACCESS_ALLOWED_ACE, SidStart);
    if ace_size < sid_offset + MIN_SID_BYTES {
        return Err(io::Error::other(
            "Windows coordination allow ACE is structurally incomplete",
        ));
    }
    // SAFETY: the size check covers the SID header and GetAce keeps the ACE
    // storage live while the descriptor buffer is live.
    let sid_bytes = unsafe { raw_ace.cast::<u8>().add(sid_offset) };
    let subauthority_count = usize::from(unsafe { *sid_bytes.add(1) });
    let sid_len = MIN_SID_BYTES
        .checked_add(
            subauthority_count
                .checked_mul(size_of::<u32>())
                .ok_or_else(|| io::Error::other("Windows coordination SID length overflow"))?,
        )
        .ok_or_else(|| io::Error::other("Windows coordination SID length overflow"))?;
    if sid_offset + sid_len > ace_size {
        return Err(io::Error::other(
            "Windows coordination allow ACE contains a truncated SID",
        ));
    }
    let sid: PSID = sid_bytes.cast();
    // SAFETY: the explicit bounds check covers the complete SID bytes.
    if unsafe { IsValidSid(sid) } == 0
        || usize::try_from(unsafe { GetLengthSid(sid) }).ok() != Some(sid_len)
    {
        return Err(io::Error::other(
            "Windows coordination allow ACE contains an invalid SID",
        ));
    }
    // SAFETY: the ACE size check covers ACCESS_ALLOWED_ACE's fixed fields.
    let mask = unsafe { (*raw_ace.cast::<ACCESS_ALLOWED_ACE>()).Mask };
    match trusted.index_of(sid) {
        Some(principal) => rights[principal] |= mask,
        None if policy == AclPolicy::MutableParent && mask & MUTATION_RIGHTS == 0 => {}
        None => {
            return Err(io::Error::other(
                "Windows mutable object grants write, delete, or permission rights to an untrusted principal",
            ));
        }
    }
    Ok(())
}

const MUTATION_RIGHTS: u32 = GENERIC_ALL
    | GENERIC_WRITE
    | MAXIMUM_ALLOWED
    | ACCESS_SYSTEM_SECURITY
    | DELETE
    | WRITE_DAC
    | WRITE_OWNER
    | FILE_DELETE_CHILD
    | FILE_WRITE_DATA
    | FILE_APPEND_DATA
    | FILE_WRITE_EA
    | FILE_WRITE_ATTRIBUTES;
