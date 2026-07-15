mod acl;

use super::buffer::AlignedBuffer;
use super::sid::TrustedSids;
use std::ffi::c_void;
use std::fs::File;
use std::io;
use std::os::windows::io::AsRawHandle;
use std::ptr;
use windows_sys::Win32::Foundation::ERROR_INSUFFICIENT_BUFFER;
use windows_sys::Win32::Security::{
    ACL, DACL_SECURITY_INFORMATION, GetKernelObjectSecurity, GetSecurityDescriptorControl,
    GetSecurityDescriptorDacl, GetSecurityDescriptorOwner, IsValidAcl, IsValidSecurityDescriptor,
    IsValidSid, OWNER_SECURITY_INFORMATION, PSID, SE_DACL_PROTECTED,
};

const MAX_SECURITY_DESCRIPTOR_BYTES: usize = 64 * 1024;

pub(crate) fn validate_private_object_security(file: &File) -> io::Result<()> {
    validate_object_security(file, AclPolicy::PrivateCoordination)
}

pub(crate) fn validate_mutable_parent_security(file: &File) -> io::Result<()> {
    validate_object_security(file, AclPolicy::MutableParent)
}

fn validate_object_security(file: &File, policy: AclPolicy) -> io::Result<()> {
    let descriptor = load_security_descriptor(file)?;
    let pointer = descriptor.as_ptr::<c_void>().cast_mut();
    // SAFETY: the bounded buffer was initialized by GetKernelObjectSecurity.
    if unsafe { IsValidSecurityDescriptor(pointer) } == 0 {
        return Err(io::Error::other(
            "Windows coordination security descriptor is invalid",
        ));
    }
    validate_dacl(pointer, policy)
}

fn load_security_descriptor(file: &File) -> io::Result<AlignedBuffer> {
    let information = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
    let mut required = 0_u32;
    // SAFETY: the handle is live, `required` is writable, and null/zero is the
    // documented size-query form.
    let queried = unsafe {
        GetKernelObjectSecurity(
            file.as_raw_handle().cast(),
            information,
            ptr::null_mut(),
            0,
            &mut required,
        )
    };
    if queried != 0 || required == 0 {
        return Err(io::Error::other(
            "Windows security descriptor query returned an invalid size result",
        ));
    }
    let source = io::Error::last_os_error();
    if source.raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as i32) {
        return Err(source);
    }
    let required_usize = usize::try_from(required)
        .map_err(|_| io::Error::other("Windows security descriptor is too large"))?;
    if required_usize > MAX_SECURITY_DESCRIPTOR_BYTES {
        return Err(io::Error::other(
            "Windows security descriptor exceeds the private-object bound",
        ));
    }
    let mut descriptor = AlignedBuffer::zeroed(required_usize)?;
    // SAFETY: the aligned buffer has the exact bounded capacity requested by
    // the first call and remains writable for this call.
    if unsafe {
        GetKernelObjectSecurity(
            file.as_raw_handle().cast(),
            information,
            descriptor.as_mut_ptr(),
            required,
            &mut required,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if usize::try_from(required).ok() != Some(required_usize) {
        return Err(io::Error::other(
            "Windows security descriptor length changed during inspection",
        ));
    }
    Ok(descriptor)
}

fn validate_dacl(descriptor: *mut c_void, policy: AclPolicy) -> io::Result<()> {
    let mut control = 0_u16;
    let mut revision = 0_u32;
    // SAFETY: `descriptor` is a validated live security descriptor.
    if unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if policy == AclPolicy::PrivateCoordination && control & SE_DACL_PROTECTED == 0 {
        return Err(io::Error::other(
            "Windows coordination DACL is not protected from inheritance",
        ));
    }
    let trusted = TrustedSids::load()?;
    if trusted.index_of(descriptor_owner(descriptor)?).is_none() {
        return Err(io::Error::other(
            "Windows coordination object has an untrusted owner SID",
        ));
    }
    acl::validate(descriptor_dacl(descriptor)?, &trusted, policy)
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum AclPolicy {
    PrivateCoordination,
    MutableParent,
}

fn descriptor_owner(descriptor: *mut c_void) -> io::Result<PSID> {
    let mut owner = ptr::null_mut();
    let mut defaulted = 0;
    // SAFETY: all output pointers are writable and `descriptor` is valid.
    if unsafe { GetSecurityDescriptorOwner(descriptor, &mut owner, &mut defaulted) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if owner.is_null() || unsafe { IsValidSid(owner) } == 0 {
        return Err(io::Error::other(
            "Windows coordination owner SID is missing or invalid",
        ));
    }
    Ok(owner)
}

fn descriptor_dacl(descriptor: *mut c_void) -> io::Result<*mut ACL> {
    let mut present = 0;
    let mut dacl = ptr::null_mut();
    let mut defaulted = 0;
    // SAFETY: all output pointers are writable and `descriptor` is valid.
    if unsafe { GetSecurityDescriptorDacl(descriptor, &mut present, &mut dacl, &mut defaulted) }
        == 0
    {
        return Err(io::Error::last_os_error());
    }
    if present == 0 || dacl.is_null() || unsafe { IsValidAcl(dacl) } == 0 {
        return Err(io::Error::other(
            "Windows coordination DACL is missing, null, or invalid",
        ));
    }
    Ok(dacl)
}
