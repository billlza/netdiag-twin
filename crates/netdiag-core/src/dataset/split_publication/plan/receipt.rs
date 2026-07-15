use super::{PartitionPlan, PartitionReceipt};
use crate::dataset::DatasetManifest;
use crate::dataset::split_publication::SplitRequest;
use crate::error::Result;
use serde::{Deserialize, Serialize};

mod validation;

const RECEIPT_SCHEMA: &str = "netdiag-dataset-split-transaction/v1";
const SPLIT_ALGORITHM: &str = "sha256-seeded-row-order/v1";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::dataset::split_publication) struct SplitReceipt {
    schema: String,
    algorithm: String,
    pub(in crate::dataset::split_publication) manifest: DatasetManifest,
    request: SplitRequest,
    train: PartitionReceipt,
    validation: PartitionReceipt,
    #[serde(skip_serializing_if = "Option::is_none")]
    test: Option<PartitionReceipt>,
}

impl SplitReceipt {
    pub(in crate::dataset::split_publication) fn new(
        manifest: &DatasetManifest,
        request: SplitRequest,
        train: &PartitionPlan,
        validation: &PartitionPlan,
        test: Option<&PartitionPlan>,
    ) -> Self {
        Self {
            schema: RECEIPT_SCHEMA.to_string(),
            algorithm: SPLIT_ALGORITHM.to_string(),
            manifest: manifest.clone(),
            request,
            train: train.receipt.clone(),
            validation: validation.receipt.clone(),
            test: test.map(|partition| partition.receipt.clone()),
        }
    }

    pub(in crate::dataset::split_publication) fn validate(&self) -> Result<()> {
        validation::validate(self, RECEIPT_SCHEMA, SPLIT_ALGORITHM)
    }

    pub(in crate::dataset::split_publication) fn is_compatible_with(
        &self,
        expected: &Self,
    ) -> bool {
        self.schema == expected.schema
            && self.algorithm == expected.algorithm
            && self.request == expected.request
            && self.train == expected.train
            && self.validation == expected.validation
            && self.test == expected.test
            && same_manifest_identity(&self.manifest, &expected.manifest)
    }

    fn partitions(&self) -> impl Iterator<Item = &PartitionReceipt> {
        [&self.train, &self.validation]
            .into_iter()
            .chain(self.test.iter())
    }
}

fn same_manifest_identity(left: &DatasetManifest, right: &DatasetManifest) -> bool {
    let mut normalized = left.clone();
    normalized.created_at = right.created_at;
    normalized == *right
}
