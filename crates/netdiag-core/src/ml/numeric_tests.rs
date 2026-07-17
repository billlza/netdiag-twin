use super::*;

#[test]
fn scale_row_avoids_overflow_when_scaled_difference_is_representable() {
    let mut features = vec![0.0; FEATURES.len()];
    let mut means = vec![0.0; FEATURES.len()];
    let mut stds = vec![1.0; FEATURES.len()];
    features[0] = f64::MAX;
    means[0] = -f64::MAX;
    stds[0] = f64::MAX;

    let scaled = scale_row(&features, &means, &stds).expect("representable scaled difference");

    assert_eq!(scaled[0], 2.0);
    assert!(scaled.iter().all(|value| value.is_finite()));
}

#[test]
fn scale_row_rejects_unrepresentable_derived_value() {
    let mut features = vec![0.0; FEATURES.len()];
    let mut means = vec![0.0; FEATURES.len()];
    let stds = vec![1.0; FEATURES.len()];
    features[0] = f64::MAX;
    means[0] = -f64::MAX;

    let error = scale_row(&features, &means, &stds)
        .expect_err("unrepresentable scaled difference must fail");

    assert!(
        error.to_string().contains("non-finite scaled value"),
        "{error}"
    );
}

#[test]
fn calibration_and_uncertainty_keep_extreme_representable_values_finite() {
    let classes = FaultLabel::ALL
        .iter()
        .map(|label| label.index())
        .collect::<Vec<_>>();
    let mut features = vec![0.0; FEATURES.len()];
    features[8] = 1.0;
    let calibrated = calibrate_probabilities(
        vec![1.0 / classes.len() as f64; classes.len()],
        &classes,
        &features,
    )
    .expect("valid calibrated distribution");
    let mut ranking = classes
        .iter()
        .zip(&calibrated)
        .map(|(class, probability)| Prediction {
            label: FaultLabel::from_index(*class).expect("known class"),
            prob: *probability,
        })
        .collect::<Vec<_>>();
    ranking.sort_by(|left, right| right.prob.total_cmp(&left.prob));
    let scaled_features = vec![f64::MAX / 4.0; FEATURES.len()];

    let assessment = assess_uncertainty(
        &ranking,
        &features,
        &scaled_features,
        &BTreeMap::new(),
        None,
    )
    .expect("finite extreme assessment");

    assert!((calibrated.iter().sum::<f64>() - 1.0).abs() <= classes.len() as f64 * 1e-9);
    assert!(calibrated.iter().all(|probability| probability.is_finite()));
    assert!(assessment.feature_distance.is_finite());
    assert_eq!(round4(f64::MAX), f64::MAX);
}

#[test]
fn trained_model_inference_produces_a_valid_finite_probability_chain() {
    let temp = tempfile::tempdir().expect("tempdir");
    let model_dir = temp.path().join("model");
    let model = train_default_model().expect("trained model");
    let manifest = build_model_manifest(
        &model,
        ModelManifestBuild {
            training_source: "numeric-chain-test".to_string(),
            training_examples: 1,
            label_distribution: BTreeMap::new(),
            synthetic_fallback: false,
            dataset_hash_sha256: None,
            training_config: None,
            uncertainty_thresholds: None,
        },
    )
    .expect("model manifest");
    write_model_bundle(&model_dir, &model, &manifest).expect("model bundle");

    let result =
        infer_with_quality_from_existing_model_dir(&[], "numeric-chain-test", &model_dir, &[])
            .expect("finite model inference");

    assert!(!result.top_predictions.is_empty());
    assert!(
        result
            .top_predictions
            .iter()
            .all(|prediction| prediction.prob.is_finite() && (0.0..=1.0).contains(&prediction.prob))
    );
    assert!(result.uncertainty.max_probability.is_finite());
    assert!(result.uncertainty.probability_margin.is_finite());
    assert!(result.uncertainty.entropy.is_finite());
    assert!(result.uncertainty.feature_distance.is_finite());
}

#[test]
fn probability_calibration_rejects_invalid_model_output_and_features() {
    let classes = FaultLabel::ALL
        .iter()
        .map(|label| label.index())
        .collect::<Vec<_>>();
    let valid_features = vec![0.0; FEATURES.len()];
    for invalid in [
        vec![f64::NAN, 0.2, 0.2, 0.2, 0.2, 0.2],
        vec![-0.1, 0.3, 0.2, 0.2, 0.2, 0.2],
        vec![0.4; FaultLabel::ALL.len()],
        vec![0.0; FaultLabel::ALL.len()],
    ] {
        let error = calibrate_probabilities(invalid, &classes, &valid_features)
            .expect_err("invalid probability vector must fail");
        assert!(error.to_string().contains("probabilit"), "{error}");
    }

    let mut invalid_features = valid_features;
    invalid_features[3] = f64::INFINITY;
    let error = calibrate_probabilities(
        vec![1.0 / classes.len() as f64; classes.len()],
        &classes,
        &invalid_features,
    )
    .expect_err("non-finite calibration feature must fail");
    assert!(error.to_string().contains("non-finite features"), "{error}");
}

#[test]
fn uncertainty_rejects_unrepresentable_l2_norm_and_invalid_thresholds() {
    let ranking = [
        Prediction {
            label: FaultLabel::Normal,
            prob: 0.5,
        },
        Prediction {
            label: FaultLabel::Congestion,
            prob: 0.5,
        },
    ];
    let weighted_features = vec![0.0; FEATURES.len()];
    let mut scaled_features = vec![0.0; FEATURES.len()];
    scaled_features[0] = f64::MAX;
    scaled_features[1] = f64::MAX;

    let error = assess_uncertainty(
        &ranking,
        &weighted_features,
        &scaled_features,
        &BTreeMap::new(),
        None,
    )
    .expect_err("unrepresentable L2 norm must fail");
    assert!(error.to_string().contains("L2 norm"), "{error}");

    let thresholds = ModelUncertaintyThresholds {
        max_entropy: f64::NAN,
        ..ModelUncertaintyThresholds::default()
    };
    let error =
        validate_uncertainty_thresholds(&thresholds).expect_err("non-finite threshold must fail");
    assert!(error.to_string().contains("max_entropy"), "{error}");
}
