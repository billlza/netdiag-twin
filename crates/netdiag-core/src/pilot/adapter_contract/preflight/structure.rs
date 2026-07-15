use crate::error::{NetdiagError, Result};
use serde_json::{Map, Value};

pub(super) fn validate_report_structure(report: &Map<String, Value>, passed: bool) -> Result<()> {
    validate_checks(report, passed)?;
    validate_health(report, passed)?;
    validate_redaction(report)
}

fn validate_checks(report: &Map<String, Value>, passed: bool) -> Result<()> {
    let checks = report
        .get("checks")
        .and_then(Value::as_array)
        .filter(|checks| !checks.is_empty() && checks.len() <= 64)
        .ok_or_else(|| {
            NetdiagError::Connector(
                "adapter preflight must include 1..=64 structured checks".to_string(),
            )
        })?;
    let checks_passed = checks.iter().try_fold(true, |aggregate, check| {
        let check = check.as_object().ok_or_else(|| {
            NetdiagError::Connector("adapter preflight checks must be objects".to_string())
        })?;
        let name = check.get("name").and_then(Value::as_str).ok_or_else(|| {
            NetdiagError::Connector("adapter preflight check name must be a string".to_string())
        })?;
        if name.trim().is_empty() || name.len() > 128 {
            return Err(NetdiagError::Connector(
                "adapter preflight check name must contain 1..=128 bytes".to_string(),
            ));
        }
        match check.get("status").and_then(Value::as_str) {
            Some("ok" | "degraded") => Ok(aggregate),
            Some("error") => Ok(false),
            _ => Err(NetdiagError::Connector(
                "adapter preflight check status must be ok, degraded, or error".to_string(),
            )),
        }
    })?;
    if checks_passed != passed {
        return Err(NetdiagError::Connector(
            "adapter preflight passed does not match aggregate check status".to_string(),
        ));
    }
    Ok(())
}

fn validate_health(report: &Map<String, Value>, passed: bool) -> Result<()> {
    let health = report
        .get("health")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            NetdiagError::Connector("adapter preflight health must be an object".to_string())
        })?;
    let health_passed = match health.get("status").and_then(Value::as_str) {
        Some("ok" | "degraded") => true,
        Some("error") => false,
        _ => {
            return Err(NetdiagError::Connector(
                "adapter preflight health.status must be ok, degraded, or error".to_string(),
            ));
        }
    };
    if health_passed != passed {
        return Err(NetdiagError::Connector(
            "adapter preflight passed does not match health.status".to_string(),
        ));
    }
    Ok(())
}

fn validate_redaction(report: &Map<String, Value>) -> Result<()> {
    let redaction = report
        .get("redaction")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            NetdiagError::Connector("adapter preflight redaction must be an object".to_string())
        })?;
    if redaction.get("fields").is_some_and(|fields| {
        fields
            .as_array()
            .is_some_and(|fields| fields.iter().all(Value::is_string))
    }) {
        Ok(())
    } else {
        Err(NetdiagError::Connector(
            "adapter preflight redaction.fields must be a string array".to_string(),
        ))
    }
}
