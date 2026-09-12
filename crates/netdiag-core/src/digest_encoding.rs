/// Preserve the lowercase, two-digits-per-byte encoding used by persisted hashes.
pub(crate) fn hex_digest(digest: impl AsRef<[u8]>) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    digest
        .as_ref()
        .iter()
        .flat_map(|byte| {
            [
                char::from(HEX[usize::from(byte >> 4)]),
                char::from(HEX[usize::from(byte & 0x0f)]),
            ]
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::hex_digest;
    use sha2::{Digest, Sha256};

    #[test]
    fn sha256_encoding_preserves_persisted_digest_format() {
        assert_eq!(
            hex_digest(Sha256::digest(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        );
        assert_eq!(
            hex_digest(Sha256::digest(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        );
        assert_eq!(hex_digest([0, 1, 15, 16, 255]), "00010f10ff");
    }
}
