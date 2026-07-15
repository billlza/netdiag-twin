# argmin 0.11.0 `paste` removal patch

This directory contains the published `argmin` 0.11.0 crate source from
crates.io (archive checksum
`e7ab7ca97779074715a402e5e8045fae27e7191acaec9b4c5653276316e9e404`).
The published source corresponds to upstream commit
`c94c32adefd6c2525ce05806092ca868ec85fba4` in
`argmin-rs/argmin`, under `crates/argmin`.

The patch is intentionally limited to removing the unmaintained `paste`
procedural macro (RUSTSEC-2024-0436) from production dependency resolution:

- `bulk!` accepts the bulk method identifier explicitly instead of generating
  it with `paste::item!`.
- The five existing invocations pass `bulk_apply`, `bulk_cost`,
  `bulk_gradient`, `bulk_hessian`, and `bulk_jacobian` respectively.
- Three-argument `bulk!` compatibility arms remain for those five public trait
  methods, with a compile-and-behavior regression test, so existing supported
  macro invocations keep their source contract.
- `paste` moves from normal dependencies to development dependencies because
  upstream's `cfg(test)`-only trait assertion macros still use it. As this
  vendored crate is a non-workspace dependency, that development-only edge is
  not part of NetDiag's lockfile, builds, tests, or shipped artifacts.
- The existing `wasm-bindgen` feature now spells its `getrandom` dependency as
  `dep:getrandom` and records that feature-only dependency in `lib.rs`. This is
  semantically equivalent to upstream's implicit activation, preserves the
  Web entropy backend, and lets dependency hygiene tools verify the edge
  without an ignore entry.
- The workspace package `netdiag-argmin-patch-contract` compiles and executes
  the public three-argument `bulk!` source contract in every strict test and
  Clippy gate without enabling this vendored crate's heavyweight upstream
  development dependency set.
- Four trailing-space-only occurrences in the upstream README and Rust
  documentation are normalized so the repository-wide whitespace gate remains
  strict; this does not change compiled behavior or documentation content.
- Published archive files, including `.cargo_vcs_info.json`, `.gitignore`,
  `Cargo.lock`, and `src/tests.rs`, remain present. The two license files are
  explicit additions sourced under the crate's declared dual license.

`PATCH_PROVENANCE.json` records the complete published archive file inventory,
the archive SHA-256, and the exact modified/added/removed allow-list with
post-patch hashes. The normal integrity gate verifies that inventory entirely
offline. A maintainer with the two original `.crate` files can additionally
verify the raw archives and regenerated inventory without network access:

```bash
python3 scripts/check_patch_contract_hygiene.py --archive-dir /path/to/crate-archives
```

No solver implementation, numeric operation, supported public macro
invocation, public method name, trait bound, feature, serialization format, or
error behavior is changed. The original
MIT/Apache-2.0 license declaration, source headers, README, and license texts
are retained.

Remove this directory and the workspace `[patch.crates-io]` entry once an
argmin release removes `paste` from its normal dependency graph. At removal,
update the lockfile and require all of the following before merging:

1. `cargo tree --workspace -i paste` has no matches.
2. `cargo audit` and `cargo deny --locked check` report no warnings.
3. NetDiag's ML training/model tests and workspace check/clippy gates pass.
