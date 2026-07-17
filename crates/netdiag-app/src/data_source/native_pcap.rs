use netdiag_core::connectors::NativePcapSource;
use std::path::PathBuf;

/// Classifies native-pcap input without consulting mutable filesystem state.
///
/// Use `iface:<name>` for an unambiguous interface. File inputs must be an
/// absolute path, contain a path separator, or use the `.pcap` suffix; a bare
/// name such as `en0` remains an interface even if a same-named file exists.
/// Opening the selected file is the I/O boundary and reports its real error.
pub fn native_pcap_source(raw: &str) -> NativePcapSource {
    let trimmed = raw.trim();
    if let Some(interface) = trimmed.strip_prefix("iface:") {
        return NativePcapSource::Interface(interface.trim().to_string());
    }
    let path = PathBuf::from(trimmed);
    if path.is_absolute()
        || trimmed.contains('/')
        || trimmed.contains('\\')
        || trimmed.to_ascii_lowercase().ends_with(".pcap")
    {
        NativePcapSource::File(path)
    } else {
        NativePcapSource::Interface(if trimmed.is_empty() {
            "lo0".to_string()
        } else {
            trimmed.to_string()
        })
    }
}
