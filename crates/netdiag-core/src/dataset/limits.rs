/// Maximum immutable JSONL input accepted by dataset operations.
pub(super) const MAX_INPUT_BYTES: u64 = 512 * 1024 * 1024;

/// Maximum bytes in one physical JSONL line, including a trailing newline.
pub(super) const MAX_LINE_BYTES: usize = 1024 * 1024;

/// CPU bound for physical lines, including blank lines.
pub(super) const MAX_PHYSICAL_LINES: usize = 2_000_000;

/// CPU bound for non-empty JSON rows streamed through validators and summaries.
pub(super) const MAX_ROWS: usize = 1_000_000;

/// Split operations retain row text for deterministic partitioning; keep that footprint lower.
pub(super) const MAX_RETAINED_BYTES: u64 = 128 * 1024 * 1024;

/// Bound retained row allocation independently from the streamed validation contract.
pub(super) const MAX_RETAINED_ROWS: usize = 250_000;
