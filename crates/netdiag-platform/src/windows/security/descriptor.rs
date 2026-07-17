use super::buffer::AlignedBuffer;
use super::sid::{SidBuffer, TrustedSids};
use std::io;
use std::mem::size_of;
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACL, ACL_REVISION, AddAccessAllowedAceEx, CONTAINER_INHERIT_ACE,
    InitializeAcl, InitializeSecurityDescriptor, OBJECT_INHERIT_ACE, SE_DACL_PROTECTED,
    SECURITY_ATTRIBUTES, SECURITY_DESCRIPTOR, SetSecurityDescriptorControl,
    SetSecurityDescriptorDacl, SetSecurityDescriptorGroup, SetSecurityDescriptorOwner,
};
use windows_sys::Win32::Storage::FileSystem::FILE_ALL_ACCESS;
use windows_sys::Win32::System::SystemServices::SECURITY_DESCRIPTOR_REVISION;

pub(super) struct PrivateSecurityDescriptor {
    _owner: SidBuffer,
    _acl: AlignedBuffer,
    descriptor: SECURITY_DESCRIPTOR,
}

impl PrivateSecurityDescriptor {
    pub(super) fn new() -> io::Result<Self> {
        let trusted = TrustedSids::load()?;
        let mut acl = private_acl(&trusted)?;
        let mut descriptor = SECURITY_DESCRIPTOR::default();
        // SAFETY: `descriptor` is writable, correctly aligned storage.
        if unsafe {
            InitializeSecurityDescriptor(
                (&mut descriptor as *mut SECURITY_DESCRIPTOR).cast(),
                SECURITY_DESCRIPTOR_REVISION,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: all pointers refer to live, validated SID/ACL allocations.
        if unsafe {
            SetSecurityDescriptorOwner(
                (&mut descriptor as *mut SECURITY_DESCRIPTOR).cast(),
                trusted.current.as_psid(),
                0,
            )
        } == 0
            || unsafe {
                SetSecurityDescriptorGroup(
                    (&mut descriptor as *mut SECURITY_DESCRIPTOR).cast(),
                    trusted.current.as_psid(),
                    0,
                )
            } == 0
            || unsafe {
                SetSecurityDescriptorDacl(
                    (&mut descriptor as *mut SECURITY_DESCRIPTOR).cast(),
                    1,
                    acl.as_mut_ptr(),
                    0,
                )
            } == 0
            || unsafe {
                SetSecurityDescriptorControl(
                    (&mut descriptor as *mut SECURITY_DESCRIPTOR).cast(),
                    SE_DACL_PROTECTED,
                    SE_DACL_PROTECTED,
                )
            } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            _owner: trusted.current,
            _acl: acl,
            descriptor,
        })
    }

    pub(super) fn attributes(&mut self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: (&mut self.descriptor as *mut SECURITY_DESCRIPTOR).cast(),
            bInheritHandle: 0,
        }
    }
}

fn private_acl(trusted: &TrustedSids) -> io::Result<AlignedBuffer> {
    let ace_prefix = size_of::<ACCESS_ALLOWED_ACE>() - size_of::<u32>();
    let acl_len = [
        trusted.current.len(),
        trusted.system.len(),
        trusted.administrators.len(),
    ]
    .into_iter()
    .try_fold(size_of::<ACL>(), |length, sid_len| {
        length.checked_add(ace_prefix + sid_len)
    })
    .ok_or_else(|| io::Error::other("Windows private ACL length overflow"))?;
    let acl_len_u32 =
        u32::try_from(acl_len).map_err(|_| io::Error::other("Windows private ACL is too large"))?;
    let mut acl = AlignedBuffer::zeroed(acl_len)?;
    // SAFETY: `acl` is aligned writable storage of `acl_len_u32` bytes.
    if unsafe { InitializeAcl(acl.as_mut_ptr(), acl_len_u32, ACL_REVISION) } == 0 {
        return Err(io::Error::last_os_error());
    }
    for sid in [&trusted.current, &trusted.system, &trusted.administrators] {
        // SAFETY: InitializeAcl initialized the bounded ACL and each SID was
        // validated when loaded. The precomputed buffer covers all three ACEs.
        if unsafe {
            AddAccessAllowedAceEx(
                acl.as_mut_ptr(),
                ACL_REVISION,
                CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE,
                FILE_ALL_ACCESS,
                sid.as_psid(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(acl)
}
