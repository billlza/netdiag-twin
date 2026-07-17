use netdiag_core::connectors::NativePcapSource;
use std::path::PathBuf;

pub(super) fn native_pcap_source(endpoint: &str) -> anyhow::Result<NativePcapSource> {
    if endpoint.is_empty() {
        anyhow::bail!("native pcap source must not be empty");
    }
    if let Some(interface) = endpoint.strip_prefix("iface:") {
        if interface.is_empty() {
            anyhow::bail!("native pcap interface must not be empty");
        }
        return Ok(NativePcapSource::Interface(interface.to_string()));
    }
    Ok(NativePcapSource::File(PathBuf::from(endpoint)))
}

pub(super) fn system_interface(endpoint: String) -> Option<String> {
    (!endpoint.is_empty() && endpoint != "all").then_some(endpoint)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_pcap_source_is_lexical_and_never_falls_back_to_an_interface() {
        let interface = native_pcap_source("iface:en0").expect("explicit interface");
        assert!(matches!(
            interface,
            NativePcapSource::Interface(value) if value == "en0"
        ));
        let file = native_pcap_source("missing-capture.pcap").expect("file path");
        assert!(matches!(
            file,
            NativePcapSource::File(path)
                if path.as_path() == std::path::Path::new("missing-capture.pcap")
        ));
        assert!(native_pcap_source("").is_err());
        assert!(native_pcap_source("iface:").is_err());
    }

    #[test]
    fn system_counter_all_is_explicit_without_whitespace_normalization() {
        assert_eq!(system_interface(String::new()), None);
        assert_eq!(system_interface("all".to_string()), None);
        assert_eq!(
            system_interface(" en0 ".to_string()),
            Some(" en0 ".to_string())
        );
    }
}
