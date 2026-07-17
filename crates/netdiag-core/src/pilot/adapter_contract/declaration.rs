use super::super::PilotSource;
use crate::error::{NetdiagError, Result};

mod options;
pub(in crate::pilot) use options::validate_adapter_options;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::pilot) enum AdapterContractDeclaration {
    Absent,
    Supported,
    Unknown(String),
}

pub(in crate::pilot) fn adapter_contract_declaration(
    source: &PilotSource,
) -> Result<AdapterContractDeclaration> {
    let adapter_contract = source
        .metadata
        .get("adapter_contract")
        .map(|value| value.trim());
    let contract = source.metadata.get("contract").map(|value| value.trim());
    let declaration = match (adapter_contract, contract) {
        (None, None) => return Ok(AdapterContractDeclaration::Absent),
        (Some(left), Some(right)) if left != right => {
            return Err(NetdiagError::InvalidTrace(format!(
                "adapter source {} has conflicting adapter_contract={left:?} and contract={right:?}",
                source.name
            )));
        }
        (Some(value), _) | (_, Some(value)) => value,
    };
    if matches!(
        declaration,
        "v1" | "adapter-v1" | "netdiag-adapter/v1" | "netdiag-adapter-preflight/v1"
    ) {
        Ok(AdapterContractDeclaration::Supported)
    } else {
        Ok(AdapterContractDeclaration::Unknown(declaration.to_string()))
    }
}

pub(in crate::pilot) fn validated_adapter_contract(
    source: &PilotSource,
) -> Result<AdapterContractDeclaration> {
    match adapter_contract_declaration(source)? {
        AdapterContractDeclaration::Absent => Err(NetdiagError::InvalidTrace(format!(
            "adapter source {} must declare metadata.adapter_contract=netdiag-adapter/v1",
            source.name
        ))),
        AdapterContractDeclaration::Unknown(declaration) => {
            Err(NetdiagError::InvalidTrace(format!(
                "adapter source {} declares unsupported adapter contract {declaration:?}",
                source.name
            )))
        }
        AdapterContractDeclaration::Supported => Ok(AdapterContractDeclaration::Supported),
    }
}
