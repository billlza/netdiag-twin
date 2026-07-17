use super::{PartitionReceipt, SplitReceipt};
use crate::dataset::split_publication::SplitRequest;
use crate::error::{NetdiagError, Result};
use std::collections::BTreeMap;
use std::path::{Component, Path};

pub(super) fn validate(receipt: &SplitReceipt, schema: &str, algorithm: &str) -> Result<()> {
    if receipt.schema != schema
        || receipt.algorithm != algorithm
        || receipt.manifest.schema != "netdiag-dataset/v1"
    {
        return Err(invalid("unsupported schema or split algorithm"));
    }
    validate_request(receipt.request)?;
    for partition in receipt.partitions() {
        validate_partition(partition)?;
    }
    let (rows, labels) = aggregate_partitions(receipt.partitions())?;
    if rows != receipt.manifest.rows || labels != receipt.manifest.label_distribution {
        return Err(invalid(
            "partition statistics contradict the committed manifest",
        ));
    }
    let seed_source = format!("split_seed:{}", receipt.request.seed);
    if !receipt
        .manifest
        .sources
        .iter()
        .any(|source| source == &seed_source)
    {
        return Err(invalid(
            "committed manifest does not bind the receipt split seed",
        ));
    }
    Ok(())
}

fn validate_request(request: SplitRequest) -> Result<()> {
    let ratios = [request.validation_ratio, request.test_ratio];
    if ratios
        .iter()
        .any(|ratio| !ratio.is_finite() || !(0.0..1.0).contains(ratio))
        || request.validation_ratio + request.test_ratio >= 1.0
    {
        return Err(invalid("split ratios are invalid"));
    }
    Ok(())
}

fn validate_partition(partition: &PartitionReceipt) -> Result<()> {
    let mut components = Path::new(&partition.file_name).components();
    let label_rows = partition
        .label_distribution
        .values()
        .try_fold(0_usize, |total, count| total.checked_add(*count))
        .ok_or_else(|| invalid("partition label count overflowed"))?;
    let minimum_bytes = u64::try_from(partition.rows)
        .map_err(|_| invalid("partition row count could not be represented"))?;
    if !matches!(components.next(), Some(Component::Normal(_)))
        || components.next().is_some()
        || partition.hash_sha256.len() != 64
        || !partition
            .hash_sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        || partition
            .label_distribution
            .values()
            .any(|count| *count == 0)
        || label_rows != partition.rows
        || (partition.rows == 0 && partition.byte_len != 0)
        || (partition.rows > 0 && partition.byte_len < minimum_bytes)
    {
        return Err(invalid("partition identity is internally inconsistent"));
    }
    Ok(())
}

fn aggregate_partitions<'a>(
    partitions: impl Iterator<Item = &'a PartitionReceipt>,
) -> Result<(usize, BTreeMap<String, usize>)> {
    let mut rows = 0_usize;
    let mut labels = BTreeMap::<String, usize>::new();
    for partition in partitions {
        rows = rows
            .checked_add(partition.rows)
            .ok_or_else(|| invalid("partition row count overflowed"))?;
        for (label, count) in &partition.label_distribution {
            let total = labels.entry(label.clone()).or_default();
            *total = total
                .checked_add(*count)
                .ok_or_else(|| invalid("partition label count overflowed"))?;
        }
    }
    Ok((rows, labels))
}

fn invalid(detail: &str) -> NetdiagError {
    NetdiagError::InvalidTrace(format!(
        "dataset split transaction receipt is invalid: {detail}"
    ))
}
