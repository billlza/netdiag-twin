use super::FEATURES;
use crate::error::{NetdiagError, Result};
use crate::models::{FaultLabel, ModelUncertaintyThresholds};
use std::collections::BTreeSet;

pub(super) fn scale_row(row: &[f64], means: &[f64], stds: &[f64]) -> Result<Vec<f64>> {
    if row.len() != FEATURES.len() {
        return Err(NetdiagError::Ml(format!(
            "feature row has {} entries, expected {}",
            row.len(),
            FEATURES.len()
        )));
    }
    if means.len() != FEATURES.len() || stds.len() != FEATURES.len() {
        return Err(NetdiagError::Ml(
            "model scaler dimensions do not match inference features".to_string(),
        ));
    }
    row.iter()
        .enumerate()
        .map(|(index, value)| {
            let mean = means[index];
            let std = stds[index];
            if !value.is_finite() || !mean.is_finite() || !std.is_finite() || std <= 0.0 {
                return Err(NetdiagError::Ml(format!(
                    "feature {} cannot be scaled with non-finite input or scaler",
                    FEATURES[index]
                )));
            }
            let denominator = std.max(1e-9);
            let difference = value - mean;
            let scaled = if difference.is_finite() {
                difference / denominator
            } else {
                value / denominator - mean / denominator
            };
            if !scaled.is_finite() {
                return Err(NetdiagError::Ml(format!(
                    "feature {} produced a non-finite scaled value",
                    FEATURES[index]
                )));
            }
            Ok(scaled)
        })
        .collect()
}

pub(super) fn calibrate_probabilities(
    mut probabilities: Vec<f64>,
    classes: &[usize],
    features: &[f64],
) -> Result<Vec<f64>> {
    validate_probability_distribution(&probabilities, "raw model")?;
    validate_probability_classes(classes, probabilities.len())?;
    if features.len() != FEATURES.len() {
        return Err(NetdiagError::Ml(format!(
            "probability calibration received {} features, expected {}",
            features.len(),
            FEATURES.len()
        )));
    }
    if features.iter().any(|value| !value.is_finite()) {
        return Err(NetdiagError::Ml(
            "probability calibration received non-finite features".to_string(),
        ));
    }

    let latency_mean = features[0];
    let loss_rate = features[3];
    let retrans_rate = features[4];
    let throughput = features[7];
    let dns_events = features[8];
    let tls_events = features[9];
    let quic_ratio = features[10];

    if dns_events > 0.0 {
        scale_probability(&mut probabilities, classes, FaultLabel::DnsFailure, 8.0)?;
    } else {
        scale_probability(&mut probabilities, classes, FaultLabel::DnsFailure, 0.05)?;
    }
    if tls_events > 0.0 {
        scale_probability(&mut probabilities, classes, FaultLabel::TlsFailure, 8.0)?;
    } else {
        scale_probability(&mut probabilities, classes, FaultLabel::TlsFailure, 0.05)?;
    }
    if quic_ratio > 0.25 {
        scale_probability(&mut probabilities, classes, FaultLabel::UdpQuicBlocked, 6.0)?;
    } else {
        scale_probability(
            &mut probabilities,
            classes,
            FaultLabel::UdpQuicBlocked,
            0.25,
        )?;
    }
    if loss_rate > 1.0 && dns_events <= 0.0 && tls_events <= 0.0 && quic_ratio <= 0.25 {
        scale_probability(&mut probabilities, classes, FaultLabel::RandomLoss, 4.0)?;
    }
    if latency_mean > 120.0 && retrans_rate > 1.5 && throughput < 35.0 {
        scale_probability(&mut probabilities, classes, FaultLabel::Congestion, 4.0)?;
    }

    let total = probability_sum(&probabilities, "weighted model")?;
    if total <= 0.0 {
        return Err(NetdiagError::Ml(
            "weighted model probability total must be positive".to_string(),
        ));
    }
    for probability in &mut probabilities {
        *probability /= total;
        if !probability.is_finite() || !(0.0..=1.0).contains(probability) {
            return Err(NetdiagError::Ml(
                "calibrated model produced an invalid probability".to_string(),
            ));
        }
    }
    validate_probability_distribution(&probabilities, "calibrated model")?;
    Ok(probabilities)
}

fn scale_probability(
    probabilities: &mut [f64],
    classes: &[usize],
    label: FaultLabel,
    factor: f64,
) -> Result<()> {
    if let Some(index) = classes.iter().position(|class| *class == label.index()) {
        let scaled = probabilities[index] * factor;
        if !scaled.is_finite() || scaled < 0.0 {
            return Err(NetdiagError::Ml(format!(
                "probability calibration overflowed for {}",
                label.as_str()
            )));
        }
        probabilities[index] = scaled;
    }
    Ok(())
}

pub(super) fn validate_probability_classes(
    classes: &[usize],
    probability_count: usize,
) -> Result<()> {
    if classes.len() != probability_count {
        return Err(NetdiagError::Ml(format!(
            "model returned {probability_count} probabilities for {} classes",
            classes.len()
        )));
    }
    let mut seen = BTreeSet::new();
    for class in classes {
        if *class >= FaultLabel::ALL.len() {
            return Err(NetdiagError::Ml(format!(
                "model probability references unknown class index {class}"
            )));
        }
        if !seen.insert(*class) {
            return Err(NetdiagError::Ml(format!(
                "model probability references class index {class} more than once"
            )));
        }
    }
    Ok(())
}

pub(super) fn validate_probability_distribution(
    probabilities: &[f64],
    context: &str,
) -> Result<()> {
    if probabilities.len() < 2 {
        return Err(NetdiagError::Ml(format!(
            "{context} probability distribution must contain at least two classes"
        )));
    }
    for (index, probability) in probabilities.iter().enumerate() {
        if !probability.is_finite() || !(0.0..=1.0).contains(probability) {
            return Err(NetdiagError::Ml(format!(
                "{context} probability at index {index} must be finite and between 0 and 1"
            )));
        }
    }
    let total = probability_sum(probabilities, context)?;
    let tolerance = probabilities.len() as f64 * 1e-9;
    if (total - 1.0).abs() > tolerance {
        return Err(NetdiagError::Ml(format!(
            "{context} probabilities must sum to 1, got {total}"
        )));
    }
    Ok(())
}

fn probability_sum(probabilities: &[f64], context: &str) -> Result<f64> {
    let total = probabilities.iter().sum::<f64>();
    if !total.is_finite() {
        return Err(NetdiagError::Ml(format!(
            "{context} probability total is not finite"
        )));
    }
    Ok(total)
}

pub(super) fn finite_l2_norm(values: &[f64], context: &str) -> Result<f64> {
    let mut norm = 0.0_f64;
    for (index, value) in values.iter().enumerate() {
        if !value.is_finite() {
            return Err(NetdiagError::Ml(format!(
                "{context} contains a non-finite value at index {index}"
            )));
        }
        norm = norm.hypot(*value);
        if !norm.is_finite() {
            return Err(NetdiagError::Ml(format!(
                "{context} L2 norm exceeds the finite f64 range"
            )));
        }
    }
    Ok(norm)
}

pub(super) fn validate_uncertainty_thresholds(
    thresholds: &ModelUncertaintyThresholds,
) -> Result<()> {
    for (name, value) in [
        ("min_max_probability", thresholds.min_max_probability),
        ("min_probability_margin", thresholds.min_probability_margin),
        ("max_entropy", thresholds.max_entropy),
    ] {
        if !value.is_finite() || !(0.0..=1.0).contains(&value) {
            return Err(NetdiagError::Ml(format!(
                "model uncertainty threshold {name} must be finite and between 0 and 1"
            )));
        }
    }
    if !thresholds.max_feature_distance.is_finite() || thresholds.max_feature_distance < 0.0 {
        return Err(NetdiagError::Ml(
            "model uncertainty threshold max_feature_distance must be finite and non-negative"
                .to_string(),
        ));
    }
    for (feature, bounds) in &thresholds.feature_bounds {
        if !FEATURES.contains(&feature.as_str()) {
            return Err(NetdiagError::Ml(format!(
                "model uncertainty bounds reference unknown feature {feature}"
            )));
        }
        if !bounds.min.is_finite() || !bounds.max.is_finite() || bounds.min > bounds.max {
            return Err(NetdiagError::Ml(format!(
                "model uncertainty bounds for {feature} must be finite and ordered"
            )));
        }
    }
    Ok(())
}
