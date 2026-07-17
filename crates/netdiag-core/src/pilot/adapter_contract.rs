mod declaration;
mod preflight;
mod process;

pub(super) use declaration::{validate_adapter_options, validated_adapter_contract};
pub(super) use preflight::validate_adapter_preflight;
pub(super) use process::{
    ResolvedInterpreter, adapter_stderr_excerpt, resolve_python_interpreter, run_python_adapter,
};
#[cfg(test)]
mod tests;
