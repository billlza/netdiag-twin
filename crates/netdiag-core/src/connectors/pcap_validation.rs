use crate::error::{NetdiagError, Result};

pub(super) fn validated_capture_window(
    first_ts_ms: Option<i64>,
    last_ts_ms: Option<i64>,
) -> Result<(i64, i64)> {
    let (first_ts_ms, last_ts_ms) = first_ts_ms.zip(last_ts_ms).ok_or_else(|| {
        NetdiagError::Connector(
            "native pcap capture produced packets without timestamps".to_string(),
        )
    })?;
    match last_ts_ms.checked_sub(first_ts_ms) {
        Some(elapsed_ms) if elapsed_ms >= 0 => Ok((last_ts_ms, elapsed_ms)),
        Some(_) => Err(NetdiagError::Connector(format!(
            "native pcap capture timestamps are not monotonic: first={first_ts_ms}, last={last_ts_ms}"
        ))),
        None => Err(NetdiagError::Connector(
            "native pcap capture timestamps overflowed while calculating duration".to_string(),
        )),
    }
}
