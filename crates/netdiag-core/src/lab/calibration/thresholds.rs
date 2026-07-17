use super::{LabCalibrationDistribution, LabCalibrationInputs};
use crate::models::{FeatureBounds, ModelUncertaintyThresholds};
use crate::telemetry::quantile;
use std::collections::BTreeMap;

use super::super::round4;

pub(super) fn calibrated_thresholds(
    inputs: &LabCalibrationInputs,
    previous: &ModelUncertaintyThresholds,
) -> ModelUncertaintyThresholds {
    let known_distance_p95 = quantile(&inputs.known_distance, 0.95);
    ModelUncertaintyThresholds {
        min_max_probability: round4(
            quantile(&inputs.known_max_probability, 0.05).clamp(0.05, 0.99),
        ),
        min_probability_margin: round4(quantile(&inputs.known_margin, 0.05).clamp(0.0, 0.80)),
        max_entropy: round4(quantile(&inputs.known_entropy, 0.95).clamp(0.05, 1.0)),
        max_feature_distance: round4(max_feature_distance(inputs, known_distance_p95)),
        feature_bounds: calibrated_feature_bounds(&inputs.known_feature_values, previous),
    }
}

pub(super) fn calibration_distribution(values: &[f64]) -> LabCalibrationDistribution {
    let finite = values
        .iter()
        .copied()
        .filter(|value| value.is_finite())
        .collect::<Vec<_>>();
    LabCalibrationDistribution {
        count: finite.len(),
        p50: round4(quantile(&finite, 0.50)),
        p95: round4(quantile(&finite, 0.95)),
        max: round4(finite.into_iter().fold(0.0, f64::max)),
    }
}

fn max_feature_distance(inputs: &LabCalibrationInputs, known_distance_p95: f64) -> f64 {
    let from_ood = inputs
        .ood_distance
        .iter()
        .copied()
        .filter(|value| value.is_finite())
        .min_by(f64::total_cmp)
        .filter(|distance| *distance > known_distance_p95)
        .map(|min_ood_distance| (known_distance_p95 + min_ood_distance) / 2.0);
    from_ood.unwrap_or(known_distance_p95 * 1.25).max(1.0)
}

fn calibrated_feature_bounds(
    values: &BTreeMap<String, Vec<f64>>,
    previous: &ModelUncertaintyThresholds,
) -> BTreeMap<String, FeatureBounds> {
    let mut bounds = previous.feature_bounds.clone();
    for (name, samples) in values {
        let finite = samples
            .iter()
            .copied()
            .filter(|value| value.is_finite())
            .collect::<Vec<_>>();
        if finite.len() < 2 {
            continue;
        }
        let min = finite.iter().copied().fold(f64::INFINITY, f64::min);
        let max = finite.iter().copied().fold(f64::NEG_INFINITY, f64::max);
        let span = (max - min)
            .abs()
            .max(max.abs().max(min.abs()) * 0.05)
            .max(1e-6);
        bounds.insert(
            name.clone(),
            FeatureBounds {
                min: round4(min - span * 0.10),
                max: round4(max + span * 0.10),
            },
        );
    }
    bounds
}
