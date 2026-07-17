use crate::error::NetdiagError;

pub(super) fn pcap_device_read_error(interface: &str, error: &pcap::Error) -> NetdiagError {
    NetdiagError::Connector(format!(
        "failed while reading capture device {interface}: {error}"
    ))
}
