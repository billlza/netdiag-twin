use crate::error::{NetdiagError, Result};
use crate::pilot::PilotSource;

mod environment;
use environment::validate_env_allowlist;

const MAX_ADAPTER_ARGUMENTS: usize = 64;
const MAX_ADAPTER_ARGUMENT_BYTES: usize = 4 * 1024;
const MAX_ADAPTER_ARGUMENT_TOTAL_BYTES: usize = 64 * 1024;

pub(in crate::pilot) fn validate_adapter_options(source: &PilotSource) -> Result<()> {
    if source.adapter.mode.is_none() {
        return Err(NetdiagError::InvalidTrace(format!(
            "adapter source {} must declare adapter.mode as sample or live",
            source.name
        )));
    }
    for legacy_key in ["sample_mode", "ci_sample", "sample_only"] {
        if source.metadata.contains_key(legacy_key) {
            return Err(NetdiagError::InvalidTrace(format!(
                "adapter source {} uses legacy metadata key {legacy_key:?}; set adapter.mode to sample or live",
                source.name
            )));
        }
    }
    if source.adapter.args.len() > MAX_ADAPTER_ARGUMENTS {
        return Err(NetdiagError::InvalidTrace(format!(
            "adapter source {} declares more than {MAX_ADAPTER_ARGUMENTS} passthrough arguments",
            source.name
        )));
    }
    let total_argument_bytes =
        source
            .adapter
            .args
            .iter()
            .try_fold(0_usize, |total, argument| {
                total.checked_add(argument.len()).ok_or_else(|| {
                    NetdiagError::InvalidTrace(format!(
                        "adapter source {} passthrough argument size overflowed",
                        source.name
                    ))
                })
            })?;
    if total_argument_bytes > MAX_ADAPTER_ARGUMENT_TOTAL_BYTES {
        return Err(NetdiagError::InvalidTrace(format!(
            "adapter source {} passthrough arguments exceed {MAX_ADAPTER_ARGUMENT_TOTAL_BYTES} bytes",
            source.name
        )));
    }
    for argument in &source.adapter.args {
        validate_argument(source, argument)?;
    }
    validate_env_allowlist(source)
}

fn validate_argument(source: &PilotSource, argument: &str) -> Result<()> {
    let trimmed = argument.trim();
    if trimmed.is_empty() {
        return Err(NetdiagError::InvalidTrace(format!(
            "adapter source {} contains an empty passthrough argument",
            source.name
        )));
    }
    if argument.len() > MAX_ADAPTER_ARGUMENT_BYTES {
        return Err(NetdiagError::InvalidTrace(format!(
            "adapter source {} passthrough argument exceeds {MAX_ADAPTER_ARGUMENT_BYTES} bytes",
            source.name
        )));
    }
    let flag = match trimmed.split_once('=') {
        Some(("--", _)) => {
            return Err(NetdiagError::InvalidTrace(format!(
                "adapter source {} passthrough argument has an empty long option name",
                source.name
            )));
        }
        Some((name, _)) => name,
        None => trimmed,
    }
    .to_ascii_lowercase();
    if matches!(flag.as_str(), "--preflight" | "--collect" | "--emit-sample") {
        return Err(NetdiagError::InvalidTrace(format!(
            "adapter source {} passthrough args must not override control flag {flag}",
            source.name
        )));
    }
    if is_obvious_secret_flag(&flag) {
        return Err(NetdiagError::InvalidTrace(format!(
            "adapter source {} passthrough args must not carry secret flag {flag}; use a secret boundary instead",
            source.name
        )));
    }
    if flag == "--apply" && !source.active {
        return Err(NetdiagError::InvalidTrace(format!(
            "adapter source {} must set active=true before passthrough arg --apply is allowed",
            source.name
        )));
    }
    Ok(())
}

fn is_obvious_secret_flag(flag: &str) -> bool {
    matches!(
        flag,
        "--token"
            | "--api-token"
            | "--bearer-token"
            | "--password"
            | "--passphrase"
            | "--auth-passphrase"
            | "--secret"
            | "--api-key"
            | "--private-key"
            | "--community"
    ) || flag.ends_with("-token")
        || flag.ends_with("-password")
        || flag.ends_with("-passphrase")
        || flag.ends_with("-secret")
        || flag.ends_with("-api-key")
}
