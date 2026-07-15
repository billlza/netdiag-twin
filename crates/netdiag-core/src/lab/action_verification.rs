use super::LabVerification;
use crate::error::{NetdiagError, Result};
use crate::models::{
    ActionVerificationVerdict, MetricQuality, Recommendation, RunComparison, TwinPolicyImpact,
    WhatIfResult,
};
use crate::report::Report;
use crate::twin::{round_decimal, validate_policy_action_shape};
use std::collections::BTreeMap;

pub(super) fn predicted_delta_pct_map(
    effect: Option<&TwinPolicyImpact>,
) -> Result<BTreeMap<String, f64>> {
    let Some(effect) = effect else {
        return Ok(BTreeMap::new());
    };
    Ok(BTreeMap::from([
        (
            "latency_p95_delta_pct".to_string(),
            normalize_impact_to_pct("latency_delta_pct", effect.latency_delta_pct)?,
        ),
        (
            "packet_loss_delta_pct".to_string(),
            normalize_impact_to_pct("loss_delta_pct", effect.loss_delta_pct)?,
        ),
        (
            "throughput_delta_pct".to_string(),
            normalize_impact_to_pct("throughput_delta_pct", effect.throughput_delta_pct)?,
        ),
    ]))
}

fn normalize_impact_to_pct(name: &str, value: f64) -> Result<f64> {
    require_finite(name, value)?;
    let pct = if value.abs() <= 1.0 {
        value * 100.0
    } else {
        value
    };
    require_finite(name, pct)?;
    Ok(round_decimal(pct, 10_000.0))
}

pub(super) fn observed_delta_pct_map(comparison: &RunComparison) -> Result<BTreeMap<String, f64>> {
    let mut observed = BTreeMap::new();
    for (key, value) in [
        ("latency_p95_delta_pct", comparison.latency_p95_delta_pct),
        ("packet_loss_delta_pct", comparison.loss_delta_pct),
        ("throughput_delta_pct", comparison.throughput_delta_pct),
    ] {
        if let Some(value) = value {
            require_finite(key, value)?;
            observed.insert(key.to_string(), round_decimal(value, 10_000.0));
        }
    }
    Ok(observed)
}

pub(super) fn prediction_error_pct_map(
    predicted: &BTreeMap<String, f64>,
    observed: &BTreeMap<String, f64>,
) -> Result<BTreeMap<String, f64>> {
    let mut errors = BTreeMap::new();
    for (key, predicted) in predicted {
        require_finite(&format!("predicted {key}"), *predicted)?;
        if let Some(observed) = observed.get(key) {
            require_finite(&format!("observed {key}"), *observed)?;
            let error = observed - predicted;
            require_finite(&format!("prediction error {key}"), error)?;
            errors.insert(key.clone(), round_decimal(error, 10_000.0));
        }
    }
    Ok(errors)
}

pub(super) fn predicted_action_effect(
    report: &Report,
    recommendation_id: Option<&str>,
) -> Result<Option<TwinPolicyImpact>> {
    let requested_action_id = recommendation_id
        .map(|id| recommendation_action_id(&report.recommendations, id))
        .transpose()?;
    select_what_if_effect(report.what_if.as_ref(), requested_action_id)
}

fn recommendation_action_id<'a>(
    recommendations: &'a [Recommendation],
    recommendation_id: &str,
) -> Result<&'a str> {
    let recommendation = recommendations
        .iter()
        .find(|recommendation| recommendation.recommendation_id == recommendation_id)
        .ok_or_else(|| NetdiagError::UnknownRecommendation(recommendation_id.to_string()))?;
    recommendation.what_if_action_id.as_deref().ok_or_else(|| {
        NetdiagError::InvalidTrace(format!(
            "recommendation {recommendation_id} does not reference a what-if action"
        ))
    })
}

fn select_what_if_effect(
    what_if: Option<&WhatIfResult>,
    requested_action_id: Option<&str>,
) -> Result<Option<TwinPolicyImpact>> {
    match (what_if, requested_action_id) {
        (None, None) => Ok(None),
        (Some(what_if), None) => what_if_effect(what_if).map(Some),
        (None, Some(action_id)) => Err(NetdiagError::InvalidTrace(format!(
            "report is missing the requested what-if action {action_id}"
        ))),
        (Some(what_if), Some(action_id)) if what_if.action_id != action_id => {
            Err(NetdiagError::InvalidTrace(format!(
                "report what-if action {} does not match requested action {action_id}",
                what_if.action_id
            )))
        }
        (Some(what_if), Some(_)) => what_if_effect(what_if).map(Some),
    }
}

fn what_if_effect(what_if: &WhatIfResult) -> Result<TwinPolicyImpact> {
    if let Some(action) = &what_if.policy_action {
        validate_policy_action_shape(action)?;
        if action.id != what_if.action_id {
            return Err(NetdiagError::InvalidTrace(format!(
                "what-if action {} embeds policy action {}",
                what_if.action_id, action.id
            )));
        }
        return Ok(action.impact);
    }
    Ok(TwinPolicyImpact {
        latency_delta_pct: legacy_delta(what_if, "latency_pct")?,
        loss_delta_pct: legacy_delta(what_if, "loss_pct")?,
        throughput_delta_pct: legacy_delta(what_if, "throughput_pct")?,
    })
}

fn legacy_delta(what_if: &WhatIfResult, key: &str) -> Result<f64> {
    let value = what_if.delta.get(key).copied().ok_or_else(|| {
        NetdiagError::InvalidTrace(format!(
            "legacy what-if action {} is missing delta {key}",
            what_if.action_id
        ))
    })?;
    require_finite(&format!("what-if delta {key}"), value)?;
    Ok(value)
}

fn require_finite(name: &str, value: f64) -> Result<()> {
    if value.is_finite() {
        Ok(())
    } else {
        Err(NetdiagError::InvalidTrace(format!(
            "action verification {name} must be finite"
        )))
    }
}

#[derive(Debug, Clone, Copy)]
enum MetricComparator {
    Lt,
    Le,
    Eq,
    Ge,
    Gt,
}

#[derive(Debug, Clone, Copy)]
struct MetricCondition {
    comparator: MetricComparator,
    threshold: f64,
}

fn parse_metric_condition(expr: &str) -> std::result::Result<MetricCondition, String> {
    let expr = expr.trim();
    for (prefix, comparator) in [
        ("<=", MetricComparator::Le),
        (">=", MetricComparator::Ge),
        ("==", MetricComparator::Eq),
        ("<", MetricComparator::Lt),
        (">", MetricComparator::Gt),
    ] {
        if let Some(value) = expr.strip_prefix(prefix) {
            let threshold = value.trim().parse::<f64>().map_err(|error| {
                format!("invalid verification condition `{expr}` threshold: {error}")
            })?;
            if !threshold.is_finite() {
                return Err(format!(
                    "invalid verification condition `{expr}` threshold: value must be finite"
                ));
            }
            return Ok(MetricCondition {
                comparator,
                threshold,
            });
        }
    }
    Err(format!(
        "invalid verification condition `{expr}`; expected one of <=, >=, ==, <, >"
    ))
}

fn metric_delta(comparison: &RunComparison, metric: &str) -> Option<f64> {
    match metric {
        "latency_p95_delta_pct" | "latency_delta_pct" => comparison.latency_p95_delta_pct,
        "packet_loss_delta_pct" | "loss_delta_pct" => comparison.loss_delta_pct,
        "throughput_delta_pct" => comparison.throughput_delta_pct,
        _ => None,
    }
}

fn condition_matches(value: f64, condition: MetricCondition) -> bool {
    match condition.comparator {
        MetricComparator::Lt => value < condition.threshold,
        MetricComparator::Le => value <= condition.threshold,
        MetricComparator::Eq => value == condition.threshold,
        MetricComparator::Ge => value >= condition.threshold,
        MetricComparator::Gt => value > condition.threshold,
    }
}

pub(super) fn action_verification_verdict(
    comparison: &RunComparison,
    policy: Option<&LabVerification>,
    predicted_deltas_pct: &BTreeMap<String, f64>,
    observed_deltas_pct: &BTreeMap<String, f64>,
) -> (ActionVerificationVerdict, Vec<String>) {
    let quality_reasons = quality_degradation_reasons(comparison);
    if !quality_reasons.is_empty() {
        return (ActionVerificationVerdict::Inconclusive, quality_reasons);
    }
    if let Some(reason) = non_finite_verification_reason(comparison, predicted_deltas_pct) {
        return (ActionVerificationVerdict::Inconclusive, vec![reason]);
    }
    if let Some(policy_verdict) = policy_verdict(comparison, policy) {
        return policy_verdict;
    }
    default_verdict(comparison, predicted_deltas_pct, observed_deltas_pct)
}

fn quality_degradation_reasons(comparison: &RunComparison) -> Vec<String> {
    let mut reasons = Vec::new();
    if comparison.right.quality_status > comparison.left.quality_status {
        reasons.push(format!(
            "connector quality degraded from {} to {}",
            comparison.left.quality_status, comparison.right.quality_status
        ));
    }
    for change in &comparison.measurement_quality_changes {
        if metric_quality_rank(change.right_quality) > metric_quality_rank(change.left_quality) {
            reasons.push(format!(
                "{} quality degraded from {} to {}",
                change.field,
                change.left_quality.as_str(),
                change.right_quality.as_str()
            ));
        }
    }
    reasons
}

fn non_finite_verification_reason(
    comparison: &RunComparison,
    predicted: &BTreeMap<String, f64>,
) -> Option<String> {
    [
        ("latency_p95_delta_pct", comparison.latency_p95_delta_pct),
        ("packet_loss_delta_pct", comparison.loss_delta_pct),
        ("throughput_delta_pct", comparison.throughput_delta_pct),
    ]
    .into_iter()
    .find_map(|(name, value)| {
        value
            .is_some_and(|value| !value.is_finite())
            .then(|| format!("verification metric {name} must be finite"))
    })
    .or_else(|| {
        predicted.iter().find_map(|(name, value)| {
            (!value.is_finite()).then(|| format!("predicted metric {name} must be finite"))
        })
    })
}

fn policy_verdict(
    comparison: &RunComparison,
    policy: Option<&LabVerification>,
) -> Option<(ActionVerificationVerdict, Vec<String>)> {
    let policy = policy.filter(|policy| !policy.is_empty())?;
    for (metric, expr) in &policy.fail_if {
        let condition = match parse_metric_condition(expr) {
            Ok(condition) => condition,
            Err(error) => return Some((ActionVerificationVerdict::Inconclusive, vec![error])),
        };
        let Some(value) = metric_delta(comparison, metric) else {
            return Some((
                ActionVerificationVerdict::Inconclusive,
                vec![format!("verification fail_if metric {metric} is missing")],
            ));
        };
        if condition_matches(value, condition) {
            return Some((
                ActionVerificationVerdict::NotVerified,
                vec![format!(
                    "verification fail_if matched: {metric}={value:.4} {expr}"
                )],
            ));
        }
    }
    if policy.objective.is_empty() {
        return None;
    }
    for (metric, expr) in &policy.objective {
        let condition = match parse_metric_condition(expr) {
            Ok(condition) => condition,
            Err(error) => return Some((ActionVerificationVerdict::Inconclusive, vec![error])),
        };
        let Some(value) = metric_delta(comparison, metric) else {
            return Some((
                ActionVerificationVerdict::Inconclusive,
                vec![format!("verification objective metric {metric} is missing")],
            ));
        };
        if !condition_matches(value, condition) {
            return Some((
                ActionVerificationVerdict::NotVerified,
                vec![format!(
                    "verification objective was not met: {metric}={value:.4} expected {expr}"
                )],
            ));
        }
    }
    Some((
        ActionVerificationVerdict::Verified,
        vec!["observed before/after telemetry met the scenario verification objective".to_string()],
    ))
}

fn default_verdict(
    comparison: &RunComparison,
    predicted: &BTreeMap<String, f64>,
    observed: &BTreeMap<String, f64>,
) -> (ActionVerificationVerdict, Vec<String>) {
    if comparison.latency_p95_delta_pct.is_none()
        && comparison.loss_delta_pct.is_none()
        && comparison.throughput_delta_pct.is_none()
    {
        return (
            ActionVerificationVerdict::Inconclusive,
            vec!["required before/after metrics are missing".to_string()],
        );
    }
    let failures = tradeoff_failures(comparison, predicted, observed);
    if !failures.is_empty() {
        return (ActionVerificationVerdict::NotVerified, failures);
    }
    if comparison
        .latency_p95_delta_pct
        .is_some_and(|delta| delta <= -5.0)
        || comparison.loss_delta_pct.is_some_and(|delta| delta <= -5.0)
        || comparison
            .throughput_delta_pct
            .is_some_and(|delta| delta >= 5.0)
    {
        return (
            ActionVerificationVerdict::Verified,
            vec![
                "observed before/after telemetry improved by at least 5% without quality degradation"
                    .to_string(),
            ],
        );
    }
    (
        ActionVerificationVerdict::NotVerified,
        vec![
            "observed before/after telemetry did not meet the 5% improvement threshold".to_string(),
        ],
    )
}

fn tradeoff_failures(
    comparison: &RunComparison,
    predicted: &BTreeMap<String, f64>,
    observed: &BTreeMap<String, f64>,
) -> Vec<String> {
    let mut failures = Vec::new();
    if let Some(delta) = comparison
        .latency_p95_delta_pct
        .filter(|delta| *delta > 5.0)
    {
        failures.push(format!("latency_p95_delta_pct regressed by {delta:.2}%"));
    }
    if let Some(delta) = comparison.loss_delta_pct.filter(|delta| *delta > 5.0) {
        failures.push(format!("packet_loss_delta_pct regressed by {delta:.2}%"));
    }
    if let Some(delta) = comparison
        .throughput_delta_pct
        .filter(|delta| *delta < -5.0)
    {
        failures.push(format!("throughput_delta_pct regressed by {delta:.2}%"));
    }
    for (metric, predicted) in predicted {
        if predicted_improves_metric(metric, *predicted)
            && let Some(observed) = observed
                .get(metric)
                .filter(|observed| observed_degrades_metric(metric, **observed))
        {
            failures.push(format!(
                "{metric} moved opposite the predicted improvement (predicted {predicted:.2}%, observed {observed:.2}%)"
            ));
        }
    }
    failures
}

fn predicted_improves_metric(metric: &str, delta: f64) -> bool {
    match metric {
        "latency_p95_delta_pct" | "packet_loss_delta_pct" => delta <= -5.0,
        "throughput_delta_pct" => delta >= 5.0,
        _ => false,
    }
}

fn observed_degrades_metric(metric: &str, delta: f64) -> bool {
    match metric {
        "latency_p95_delta_pct" | "packet_loss_delta_pct" => delta > 5.0,
        "throughput_delta_pct" => delta < -5.0,
        _ => false,
    }
}

fn metric_quality_rank(quality: MetricQuality) -> u8 {
    match quality {
        MetricQuality::Measured => 0,
        MetricQuality::Estimated => 1,
        MetricQuality::Fallback => 2,
        MetricQuality::Missing => 3,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn legacy_what_if(delta: BTreeMap<String, f64>) -> WhatIfResult {
        WhatIfResult {
            action_id: "action-1".to_string(),
            action_notes: String::new(),
            policy_action: None,
            topology: "topology".to_string(),
            topology_snapshot: None,
            modified_topology_snapshot: None,
            baseline: BTreeMap::new(),
            proposed: BTreeMap::new(),
            delta,
        }
    }

    #[test]
    fn predicted_percentages_preserve_finite_extreme_values() {
        let values = predicted_delta_pct_map(Some(&TwinPolicyImpact {
            latency_delta_pct: f64::MAX,
            loss_delta_pct: -f64::MAX,
            throughput_delta_pct: 0.5,
        }))
        .expect("finite impacts");

        assert_eq!(values["latency_p95_delta_pct"], f64::MAX);
        assert_eq!(values["packet_loss_delta_pct"], -f64::MAX);
        assert_eq!(values["throughput_delta_pct"], 50.0);
        assert!(values.values().all(|value| value.is_finite()));
    }

    #[test]
    fn prediction_error_rejects_unrepresentable_subtraction() {
        let predicted = BTreeMap::from([("latency_p95_delta_pct".to_string(), -f64::MAX)]);
        let observed = BTreeMap::from([("latency_p95_delta_pct".to_string(), f64::MAX)]);

        let error = prediction_error_pct_map(&predicted, &observed)
            .expect_err("overflowing difference must fail");

        assert!(error.to_string().contains("prediction error"), "{error}");
    }

    #[test]
    fn legacy_what_if_requires_every_delta() {
        let what_if = legacy_what_if(BTreeMap::from([
            ("latency_pct".to_string(), -1.0),
            ("loss_pct".to_string(), -2.0),
        ]));

        let error = what_if_effect(&what_if).expect_err("missing throughput must fail");

        assert!(error.to_string().contains("throughput_pct"), "{error}");
    }

    #[test]
    fn requested_action_must_exist_and_match() {
        let what_if = legacy_what_if(BTreeMap::from([
            ("latency_pct".to_string(), -1.0),
            ("loss_pct".to_string(), -2.0),
            ("throughput_pct".to_string(), 3.0),
        ]));

        assert!(select_what_if_effect(None, Some("action-1")).is_err());
        assert!(select_what_if_effect(Some(&what_if), Some("other-action")).is_err());
    }

    #[test]
    fn verification_conditions_reject_non_finite_thresholds() {
        let error = parse_metric_condition("<= inf").expect_err("infinite threshold must fail");
        assert!(error.contains("finite"), "{error}");
    }
}
