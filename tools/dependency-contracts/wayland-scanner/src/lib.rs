#![cfg(unix)]

//! Compile-time XML parsing contract for NetDiag's vendored `wayland-scanner` patch.

#[cfg(test)]
mod generated {
    wayland_scanner::generate_interfaces!("protocol.xml");
}

#[cfg(test)]
mod tests {
    use super::generated::NETDIAG_PATCH_CONTRACT_INTERFACE;

    #[test]
    fn patched_scanner_parses_and_generates_the_protocol() {
        let interface: &wayland_backend::protocol::Interface = &NETDIAG_PATCH_CONTRACT_INTERFACE;
        assert_eq!(interface.name, "netdiag_patch_contract");
        assert_eq!(interface.version, 1);
    }
}
