use super::buffer::AlignedBuffer;
use std::io;
use std::mem::size_of;
use std::ptr;
use std::slice;
use windows_sys::Win32::Foundation::{CloseHandle, ERROR_INSUFFICIENT_BUFFER, HANDLE};
use windows_sys::Win32::Security::{
    CreateWellKnownSid, GetLengthSid, GetTokenInformation, IsValidSid, PSID, SECURITY_MAX_SID_SIZE,
    TOKEN_QUERY, TOKEN_USER, TokenUser, WinBuiltinAdministratorsSid, WinLocalSystemSid,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

pub(super) struct SidBuffer {
    storage: AlignedBuffer,
    sid_len: usize,
}

impl SidBuffer {
    pub(super) fn current_user() -> io::Result<Self> {
        let token = ProcessToken::open()?;
        let mut required = 0_u32;
        // SAFETY: `required` is writable and the null/zero buffer pair is the
        // documented size-query form of GetTokenInformation.
        let queried =
            unsafe { GetTokenInformation(token.0, TokenUser, ptr::null_mut(), 0, &mut required) };
        if queried != 0 || required == 0 {
            return Err(io::Error::other(
                "Windows token user query returned an invalid size result",
            ));
        }
        let source = io::Error::last_os_error();
        if source.raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as i32) {
            return Err(source);
        }

        let required_usize = usize::try_from(required)
            .map_err(|_| io::Error::other("Windows token user buffer is too large"))?;
        let mut information = AlignedBuffer::zeroed(required_usize)?;
        // SAFETY: the aligned buffer has the exact byte capacity requested by
        // the first call and remains writable for the duration of the call.
        let loaded = unsafe {
            GetTokenInformation(
                token.0,
                TokenUser,
                information.as_mut_ptr(),
                required,
                &mut required,
            )
        };
        if loaded == 0 {
            return Err(io::Error::last_os_error());
        }
        if required_usize < size_of::<TOKEN_USER>() {
            return Err(io::Error::other(
                "Windows token user response is structurally incomplete",
            ));
        }
        // SAFETY: GetTokenInformation initialized a suitably aligned buffer
        // whose validated length covers TOKEN_USER.
        let token_user = unsafe { &*information.as_ptr::<TOKEN_USER>() };
        Self::copy_from(token_user.User.Sid)
    }

    pub(super) fn well_known(kind: i32) -> io::Result<Self> {
        let mut storage = AlignedBuffer::zeroed(SECURITY_MAX_SID_SIZE as usize)?;
        let mut sid_len = SECURITY_MAX_SID_SIZE;
        // SAFETY: the destination is aligned writable storage of `sid_len`
        // bytes; a null domain SID is required for these well-known SIDs.
        let created = unsafe {
            CreateWellKnownSid(kind, ptr::null_mut(), storage.as_mut_ptr(), &mut sid_len)
        };
        if created == 0 {
            return Err(io::Error::last_os_error());
        }
        let sid_len = usize::try_from(sid_len)
            .map_err(|_| io::Error::other("well-known Windows SID is too large"))?;
        if sid_len == 0 || sid_len > storage.byte_len() {
            return Err(io::Error::other(
                "well-known Windows SID returned an invalid length",
            ));
        }
        Ok(Self { storage, sid_len })
    }

    fn copy_from(source: PSID) -> io::Result<Self> {
        if source.is_null() {
            return Err(io::Error::other("Windows token user SID is missing"));
        }
        // SAFETY: `source` is owned by the live token-information buffer.
        if unsafe { IsValidSid(source) } == 0 {
            return Err(io::Error::other("Windows token user SID is invalid"));
        }
        // SAFETY: IsValidSid established that the SID header is valid.
        let sid_len = usize::try_from(unsafe { GetLengthSid(source) })
            .map_err(|_| io::Error::other("Windows token user SID is too large"))?;
        if sid_len == 0 || sid_len > SECURITY_MAX_SID_SIZE as usize {
            return Err(io::Error::other(
                "Windows token user SID length is outside the supported bound",
            ));
        }
        let mut storage = AlignedBuffer::zeroed(sid_len)?;
        // SAFETY: the destination has `sid_len` bytes and the validated source
        // SID reports exactly that many readable bytes.
        unsafe {
            ptr::copy_nonoverlapping(source.cast::<u8>(), storage.as_mut_ptr(), sid_len);
        }
        Ok(Self { storage, sid_len })
    }

    pub(super) fn as_psid(&self) -> PSID {
        self.storage.as_ptr::<u8>().cast_mut().cast()
    }

    pub(super) fn bytes(&self) -> &[u8] {
        // SAFETY: the aligned allocation remains alive with at least `sid_len`
        // initialized bytes for the lifetime of `self`.
        unsafe { slice::from_raw_parts(self.storage.as_ptr(), self.sid_len) }
    }

    pub(super) fn len(&self) -> usize {
        self.sid_len
    }
}

pub(super) struct TrustedSids {
    pub(super) current: SidBuffer,
    pub(super) system: SidBuffer,
    pub(super) administrators: SidBuffer,
}

impl TrustedSids {
    pub(super) fn load() -> io::Result<Self> {
        Ok(Self {
            current: SidBuffer::current_user()?,
            system: SidBuffer::well_known(WinLocalSystemSid)?,
            administrators: SidBuffer::well_known(WinBuiltinAdministratorsSid)?,
        })
    }

    pub(super) fn index_of(&self, candidate: PSID) -> Option<usize> {
        [&self.current, &self.system, &self.administrators]
            .into_iter()
            .position(|trusted| {
                // SAFETY: the caller validates `candidate`; every trusted SID is
                // constructed through a validating Windows API.
                unsafe { windows_sys::Win32::Security::EqualSid(candidate, trusted.as_psid()) != 0 }
            })
    }
}

struct ProcessToken(HANDLE);

impl ProcessToken {
    fn open() -> io::Result<Self> {
        let mut token = ptr::null_mut();
        // SAFETY: `token` is writable and GetCurrentProcess returns a valid
        // process pseudo-handle for the current process.
        let opened = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) };
        if opened == 0 {
            return Err(io::Error::last_os_error());
        }
        if token.is_null() {
            return Err(io::Error::other(
                "OpenProcessToken returned a null token handle",
            ));
        }
        Ok(Self(token))
    }
}

impl Drop for ProcessToken {
    fn drop(&mut self) {
        // SAFETY: this type exclusively owns the non-null token handle.
        let _ = unsafe { CloseHandle(self.0) };
    }
}
