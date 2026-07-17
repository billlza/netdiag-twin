use std::io;
use std::mem::size_of;

pub(super) struct AlignedBuffer {
    words: Vec<usize>,
    byte_len: usize,
}

impl AlignedBuffer {
    pub(super) fn zeroed(byte_len: usize) -> io::Result<Self> {
        if byte_len == 0 {
            return Err(io::Error::other("Windows security buffer cannot be empty"));
        }
        let word_len = byte_len
            .checked_add(size_of::<usize>() - 1)
            .ok_or_else(|| io::Error::other("Windows security buffer length overflow"))?
            / size_of::<usize>();
        Ok(Self {
            words: vec![0; word_len],
            byte_len,
        })
    }

    pub(super) fn byte_len(&self) -> usize {
        self.byte_len
    }

    pub(super) fn as_ptr<T>(&self) -> *const T {
        self.words.as_ptr().cast()
    }

    pub(super) fn as_mut_ptr<T>(&mut self) -> *mut T {
        self.words.as_mut_ptr().cast()
    }
}
