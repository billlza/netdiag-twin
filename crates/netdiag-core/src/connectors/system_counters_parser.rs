use super::InterfaceCounters;
use crate::error::{NetdiagError, Result};
use std::collections::BTreeMap;

pub(super) fn parse_netstat_counters(text: &str) -> Result<BTreeMap<String, InterfaceCounters>> {
    let mut lines = text.lines().filter(|line| !line.trim().is_empty());
    let header = lines
        .next()
        .ok_or_else(|| NetdiagError::Connector("netstat output is empty".to_string()))?;
    let columns = header.split_whitespace().collect::<Vec<_>>();
    if !columns.starts_with(&["Name", "Mtu", "Network", "Address"]) {
        return Err(NetdiagError::Connector(
            "netstat header must start with Name Mtu Network Address".to_string(),
        ));
    }
    let index = |name: &str| -> Result<usize> {
        let mut matches = columns
            .iter()
            .enumerate()
            .filter(|(_, column)| **column == name);
        let (position, _) = matches
            .next()
            .ok_or_else(|| NetdiagError::Connector(format!("netstat missing {name} column")))?;
        if matches.next().is_some() {
            return Err(NetdiagError::Connector(format!(
                "netstat repeated {name} column"
            )));
        }
        Ok(position)
    };
    let ipkts_idx = index("Ipkts")?;
    let ierrs_idx = index("Ierrs")?;
    let ibytes_idx = index("Ibytes")?;
    let opkts_idx = index("Opkts")?;
    let oerrs_idx = index("Oerrs")?;
    let obytes_idx = index("Obytes")?;
    let mut counters = BTreeMap::<String, InterfaceCounters>::new();
    for (row_index, line) in lines.enumerate() {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        let malformed = || {
            NetdiagError::Connector(format!(
                "netstat row {} is missing or has unexpected counter columns",
                row_index + 2
            ))
        };
        let network = fields.get(2).ok_or_else(malformed)?;
        // AF_INET/AF_INET6 rows describe addresses, not interface totals. Their
        // error counters are legitimately unavailable and must not replace or
        // be added to the authoritative AF_LINK row.
        if !network.starts_with("<Link#") {
            continue;
        }
        let link_index = network
            .strip_prefix("<Link#")
            .and_then(|value| value.strip_suffix('>'))
            .and_then(|value| value.parse::<u32>().ok());
        if link_index.is_none() {
            return Err(NetdiagError::Connector(format!(
                "netstat row {} has an invalid link index",
                row_index + 2
            )));
        }
        // Loopback and tunnel interfaces have a blank Address column. Splitting
        // whitespace removes that field, so align counters against the complete
        // header tail instead of shifting every numeric column to the right.
        let omitted_address = if fields.len() == columns.len() {
            0
        } else if fields.len() + 1 == columns.len() {
            1
        } else {
            return Err(malformed());
        };
        let name = fields[0].to_string();
        let counter = |column: usize| parse_u64_field(fields[column - omitted_address]);
        let parsed = InterfaceCounters {
            bytes: checked_counter_pair(
                &name,
                "bytes",
                counter(ibytes_idx)?,
                counter(obytes_idx)?,
            )?,
            packets: checked_counter_pair(
                &name,
                "packets",
                counter(ipkts_idx)?,
                counter(opkts_idx)?,
            )?,
            errors: checked_counter_pair(
                &name,
                "errors",
                counter(ierrs_idx)?,
                counter(oerrs_idx)?,
            )?,
        };
        if let Some(current) = counters.insert(name.clone(), parsed)
            && current != parsed
        {
            return Err(NetdiagError::Connector(format!(
                "netstat emitted inconsistent duplicate counters for interface {name}"
            )));
        }
    }
    if counters.is_empty() {
        return Err(NetdiagError::Connector(
            "netstat output contained no interface counters".to_string(),
        ));
    }
    Ok(counters)
}

fn parse_u64_field(value: &str) -> Result<u64> {
    if value == "-" {
        return Err(NetdiagError::Connector(
            "netstat counter is unavailable (`-`)".to_string(),
        ));
    }
    value
        .parse::<u64>()
        .map_err(|_| NetdiagError::Connector(format!("invalid netstat counter: {value}")))
}

fn checked_counter_pair(interface: &str, kind: &str, incoming: u64, outgoing: u64) -> Result<u64> {
    incoming.checked_add(outgoing).ok_or_else(|| {
        NetdiagError::Connector(format!(
            "netstat {kind} counter overflowed for interface {interface}"
        ))
    })
}
