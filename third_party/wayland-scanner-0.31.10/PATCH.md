# wayland-scanner 0.31.10 security compatibility patch

This directory is the published `wayland-scanner` 0.31.10 crate source
(crates.io checksum
`9c324a910fd86ebdc364a3e61ec1f11737d3b1d6c273c0239ee8ff4bc0d24b4a`).

The behavioral compatibility change is limited to raising the `quick-xml`
dependency requirement from 0.39 to 0.41 and using the protocol-appropriate
`BytesRef::xml10_content` API.
The released scanner code remains compatible with
the released Wayland 0.31 component set, while quick-xml 0.41 fixes
RUSTSEC-2026-0194 and RUSTSEC-2026-0195.

The published `tests/scanner_assets/` directory is retained byte-for-byte.
Those five upstream unit tests now run directly against this patch in the
strict contract gate, and their test sources cannot be modified, added to, or
removed by the diff allow-list. The local `Cargo.lock` changes only the
`quick-xml` version and checksum. Two equivalent match guards in `parse.rs`
replace nested boolean checks so the restored upstream test target is clean
under the supported Clippy version; no parsing behavior changes.

`PATCH_PROVENANCE.json` records every published archive file hash, the raw
archive SHA-256, and exact post-patch hashes for every allowed difference. The
normal gate verifies the snapshot offline. Raw archive bytes can also be
checked offline when supplied explicitly:

```bash
python3 scripts/check_patch_contract_hygiene.py --archive-dir /path/to/crate-archives
```

Remove this directory and the workspace `[patch.crates-io]` entry once a
compatible wayland-scanner release declares `quick-xml >=0.41`.

The workspace package `netdiag-wayland-scanner-patch-contract` invokes the
patched procedural macro against an XML 1.0 fixture with escaped character
content. Strict tests and Clippy therefore exercise both the parser change and
the generated interface contract.
