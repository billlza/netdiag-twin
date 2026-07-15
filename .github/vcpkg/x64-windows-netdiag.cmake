# CI-only dynamic libpcap build. The Rust `pcap` crate links `wpcap`, while
# upstream libpcap defaults to `pcap` on Windows; name the audited null-capture
# build explicitly so offline pcap parsing tests link and execute without a
# privileged packet-capture driver.
set(VCPKG_TARGET_ARCHITECTURE x64)
set(VCPKG_CRT_LINKAGE dynamic)
set(VCPKG_LIBRARY_LINKAGE dynamic)
set(VCPKG_CMAKE_CONFIGURE_OPTIONS "-DLIBRARY_NAME=wpcap")
