/// Maximum number of independently collected sources in one declared run.
pub(crate) const MAX_DECLARED_SOURCES: usize = 64;

/// Maximum aggregate wall-clock budget declared for source execution.
pub(crate) const MAX_TOTAL_SOURCE_EXECUTION_SECS: u64 = 600;

/// Maximum timeout for one source collection operation.
pub(crate) const MAX_COLLECTION_TIMEOUT_SECS: u64 = 300;

/// Maximum immutable file snapshot accepted by local trace ingestion.
pub(crate) const MAX_SOURCE_INPUT_BYTES: u64 = 16 * 1024 * 1024;

/// Maximum packets accepted by native pcap collection across every entry point.
pub const MAX_PCAP_PACKET_LIMIT: usize = 10_000;

/// Maximum canonical records retained from one trace or connector response.
pub(crate) const MAX_SOURCE_RECORDS: usize = 100_000;

/// Maximum flow metadata entries accepted from one connector response.
pub const MAX_CONNECTOR_FLOW_METADATA_ITEMS: usize = 1_024;

/// Maximum UTF-8 bytes accepted in one connector metadata string field.
pub const MAX_CONNECTOR_METADATA_STRING_BYTES: usize = 1_024;

/// Maximum aggregate UTF-8 bytes retained across connector metadata strings.
pub const MAX_CONNECTOR_METADATA_TOTAL_STRING_BYTES: usize = 2 * 1024 * 1024;

/// Maximum aggregate source payload retained by one Lab run.
pub(crate) const MAX_SCENARIO_RETAINED_BYTES: u64 = 64 * 1024 * 1024;

/// Maximum aggregate canonical records retained by one Lab run.
pub(crate) const MAX_SCENARIO_RECORDS: usize = 250_000;
