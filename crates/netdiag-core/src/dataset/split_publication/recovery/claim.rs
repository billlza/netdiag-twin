use super::{ensure_absent, preserve_failed_noclobber_state};
use crate::dataset::split_publication::plan::SplitReceipt;
use crate::dataset::trusted_root::TrustedDatasetRoot;
use crate::error::{AtomicPublishPhase, IoContext, NetdiagError, Result};
use crate::storage::{
    self, BoundAtomicFileTarget, NoClobberDisposition,
    write_file_atomically_noclobber_or_existing_to_bound,
};
use std::io::Write;

const MAX_SPLIT_RECEIPT_BYTES: u64 = 256 * 1024;

pub(in crate::dataset::split_publication) struct ReceiptClaim {
    pub(in crate::dataset::split_publication) receipt: SplitReceipt,
    pub(in crate::dataset::split_publication) was_existing: bool,
}

pub(in crate::dataset::split_publication) fn claim(
    root: &TrustedDatasetRoot,
    target: &BoundAtomicFileTarget,
    public_targets: &[&BoundAtomicFileTarget],
    expected: &SplitReceipt,
) -> Result<ReceiptClaim> {
    expected.validate()?;
    if let Some(existing) = read_receipt(target)? {
        validate_existing(target, expected, &existing)?;
        return Ok(existing_claim(existing));
    }
    ensure_absent(public_targets, "unowned existing output")?;
    let prepared = storage::typed_json::prepare_json_bounded(
        expected,
        MAX_SPLIT_RECEIPT_BYTES,
        "dataset split transaction receipt",
    )?;
    let publication =
        write_file_atomically_noclobber_or_existing_to_bound(target, "json", |file| {
            file.write_all(prepared.as_bytes())
                .with_path(target.resolved_path())
        });
    match publication {
        Ok((NoClobberDisposition::Created, ())) => created_claim(root, target, expected),
        Ok((NoClobberDisposition::Existing, ())) => existing_after_collision(target, expected),
        Err(error) => Err(preserve_failed_noclobber_state(target, error, || {
            existing_after_collision(target, expected).map(drop)
        })),
    }
}

fn created_claim(
    root: &TrustedDatasetRoot,
    target: &BoundAtomicFileTarget,
    expected: &SplitReceipt,
) -> Result<ReceiptClaim> {
    match read_validated(target, expected) {
        Ok(receipt) => Ok(ReceiptClaim {
            receipt,
            was_existing: false,
        }),
        Err(error) => {
            root.remove_created_file_after_error(target, AtomicPublishPhase::Published, error)
        }
    }
}

fn existing_after_collision(
    target: &BoundAtomicFileTarget,
    expected: &SplitReceipt,
) -> Result<ReceiptClaim> {
    read_validated(target, expected).map(existing_claim)
}

fn read_validated(target: &BoundAtomicFileTarget, expected: &SplitReceipt) -> Result<SplitReceipt> {
    let existing = storage::typed_json::read_required_stable_json_bounded_at(
        target,
        MAX_SPLIT_RECEIPT_BYTES,
        "dataset split transaction receipt",
    )?;
    validate_existing(target, expected, &existing)?;
    Ok(existing)
}

fn read_receipt(target: &BoundAtomicFileTarget) -> Result<Option<SplitReceipt>> {
    storage::typed_json::read_optional_stable_json_bounded_at(
        target,
        MAX_SPLIT_RECEIPT_BYTES,
        "dataset split transaction receipt",
    )
}

fn validate_existing(
    target: &BoundAtomicFileTarget,
    expected: &SplitReceipt,
    existing: &SplitReceipt,
) -> Result<()> {
    existing.validate()?;
    if existing.is_compatible_with(expected) {
        return Ok(());
    }
    Err(NetdiagError::InvalidTrace(format!(
        "dataset split transaction receipt conflicts with this request at {}; existing outputs remain untouched",
        target.resolved_path().display()
    )))
}

fn existing_claim(receipt: SplitReceipt) -> ReceiptClaim {
    ReceiptClaim {
        receipt,
        was_existing: true,
    }
}
