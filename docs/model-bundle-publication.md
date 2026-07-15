# Model Bundle Publication

NetDiag publishes an ML model and its bound manifest as one crash-atomic logical
bundle. The model directory has one source of truth:

```text
model/
  current.json
  generations/
    generation-<32 lowercase hex characters>/
      rust_logistic_model.json
      model_manifest.json
```

`current.json` uses schema `netdiag-model-current/v1` and contains exactly one
generation basename. `model_manifest.json` remains schema
`netdiag-model-manifest/v2`, and its public `model_file` field remains the
basename `rust_logistic_model.json`.

## Publication contract

A writer holds the model bundle lock for the full operation. Before creating a
new generation it validates the current bundle, enumerates at most 16 generation
entries, and durably removes every non-current orphan or old generation. A
cleanup error aborts before publication. The writer then creates a unique
generation directory through the already-validated parent handle. Missing Unix
directory chains are created and persisted component by component through held
directory handles, without reopening paths for durability flushes. The writer
then atomically writes and syncs the model and its hash-bound manifest, and
finally atomically replaces `current.json`.
The current generation is retained as the previous generation, so the normal
steady state contains two complete generations.

If pointer replacement fails before rename, the old pointer remains current and
the complete new directory is an orphan for the next bounded cleanup. If rename
succeeds but parent-directory sync fails, the API returns the typed
`PublishedButDurabilityUncertain` error. It does not report success or delete
migration inputs: after recovery, either the old or new pointer state references
a complete, hash-valid bundle.

Readers hold the bundle lock while parsing `current.json` once and resolving
only that generation. They never scan `generations/` during inference. Every
path-based load opens the model and manifest without following links and reads
each file twice from the same handle before deserialization, with hard limits of
16 MiB and 2 MiB respectively; `current.json` is limited to 4 KiB. Identity,
size, timestamp, content, and manifest-bound model hash changes fail closed.
There is no process-global reader cache: one operation may reuse its owned,
already-validated `ModelBundleSnapshot` for zero-I/O inference, while the next
operation audits the current on-disk generation again. Writers use the same
validation semantics before cleanup or publication.

A manifest-only update publishes a new immutable generation while preserving
the validated model file bytes exactly; it never reserializes the model. The
model file hash therefore remains stable while the manifest hash and generation
identity change. The returned snapshot is the one created by that locked
publication, so callers do not reopen a potentially newer generation.

## Trust boundary

The manifest SHA-256 binds exact model bytes to metadata and detects accidental,
partial, or single-file replacement. Trusted-directory ownership and ACL checks,
no-follow opens, stable handle identity, and bounded double reads also reject
path substitution and concurrent mutation. These controls provide integrity and
crash consistency; they do not authenticate who produced a bundle.

A malicious process already running as the same OS account can replace both the
model and manifest and calculate matching hashes. NetDiag therefore does not
describe the current bundle format as signed or source-authenticated. Adding
that property requires a separately reviewed signature schema, mandatory trust
policy, embedded or externally provisioned public keys, key rotation and
revocation, and migration rules covering training, calibration, promotion, CLI,
and App consumers. An optional signature field with an unsigned fallback would
not close this boundary and is intentionally not part of v0.5.3.

Generation publication currently requires Unix directory `fsync` semantics.
Windows can read an existing valid bundle, but training, calibration updates,
and explicit rebuild fail with a typed `NotPublished` error before creating,
garbage-collecting, or deleting any model path until the Windows platform
adapter provides a reviewed durable directory-create/flush boundary. Platforms
without the stable no-follow read boundary also reject reads. A no-op directory
flush is never reported as crash-safe publication.

## Legacy flat-bundle migration

When `current.json` does not exist, readers accept only a complete, hash-valid
top-level v2 pair:

```text
model/rust_logistic_model.json
model/model_manifest.json
```

An incomplete, invalid, v1, or hash-mismatched legacy pair is returned as an
error and is never repaired by synthetic fallback. A valid flat v2 pair is
copied into a retained generation by the first successful write. Once
`current.json` exists, top-level files are not read as truth and are not
maintained as mirrors.

The artifact-root ownership command may recognize an exact v0.5.2 flat v1
bundle as product evidence, but it is read-only and does not enable runtime v1
loading. Only a serialized model writer can migrate v1. Under the model lock it
stable-reads and validates the complete model and schema-independent manifest
payload, requires the v1 hash field to be empty, and rejects unknown or
ambiguous entries before creating a generation. It then copies the exact v1
model bytes into a retained v2 generation whose manifest binds their SHA-256,
writes the requested replacement as another complete v2 generation, and
atomically publishes `current.json` as the commit point.

Until that pointer commit succeeds, the v1 model, manifest, and any recognized
promotion-gate file remain unchanged. A pre-commit interruption can leave only
bounded, unreferenced generation directories; the next locked writer validates
the v1 source again, removes those directories, and retries. If pointer
publication is reported as durability-uncertain, neither outcome is reported
as success and the flat source remains available for recovery. Once a valid
v2 pointer is observable, a later locked write deterministically removes any
flat residue. Successful publication removes the flat files only after the
pointer commit.
