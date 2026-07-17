use super::*;

#[test]
fn concurrent_store_save_rejects_the_stale_writer_and_preserves_the_winner() {
    let path = temp_settings_path();
    let first_store = SettingsStore::new(path.clone());
    let mut first = AppSettings::default();
    first_store.save(&mut first).expect("persist baseline");
    let second_store = SettingsStore::new(path.clone());
    let mut second = second_store.load().expect("load second process snapshot");

    first.language = LanguageSetting::En;
    first_store.save(&mut first).expect("first writer wins");
    second.startup.auto_run_diagnosis = false;
    let error = second_store
        .save(&mut second)
        .expect_err("stale writer must fail closed");

    assert!(format!("{error:#}").contains("changed in another process"));
    let persisted = SettingsStore::new(path.clone())
        .load()
        .expect("load winning settings");
    assert_eq!(persisted, first);
    cleanup_temp_path(path);
}

#[test]
fn a_detected_settings_conflict_remains_blocked_until_explicit_reload() {
    let path = temp_settings_path();
    let writer = SettingsStore::new(path.clone());
    let mut winner = AppSettings::default();
    writer.save(&mut winner).expect("persist baseline");
    let stale_store = SettingsStore::new(path.clone());
    let mut stale = stale_store.load().expect("load stale snapshot");
    let stale_bytes = fs::read(&path).expect("stale bytes");

    winner.language = LanguageSetting::En;
    writer.save(&mut winner).expect("publish concurrent change");
    assert!(stale_store.save(&mut stale).is_err());
    fs::write(&path, stale_bytes).expect("restore exact stale bytes");

    let error = stale_store
        .save(&mut stale)
        .expect_err("conflict state must remain poisoned despite an ABA rewrite");
    assert!(format!("{error:#}").contains("after Conflict state"));
    let reloaded = stale_store.load().expect("explicit reload clears conflict");
    assert_eq!(reloaded, stale);
    cleanup_temp_path(path);
}

#[test]
fn a_transaction_rejects_unsaved_mutation_without_poisoning_the_loaded_baseline() {
    let path = temp_settings_path();
    let store = SettingsStore::new(path.clone());
    let mut settings = AppSettings::default();

    let error = store
        .with_current_transaction(&mut settings, |settings| {
            settings.language = LanguageSetting::En;
            Ok(())
        })
        .expect_err("transaction must not leak an unpersisted snapshot");
    assert!(error.to_string().contains("unpersisted in-memory snapshot"));
    assert!(matches!(
        store.verify_current(&settings),
        Err(SettingsVerificationError::UnpersistedSnapshot { .. })
    ));

    settings = AppSettings::default();
    store
        .with_current_transaction(&mut settings, |_| Ok(()))
        .expect("snapshot mismatch must not poison the valid baseline");
    cleanup_temp_path(path);
}

#[test]
fn legacy_settings_without_a_generation_upgrade_on_first_save() {
    let path = temp_settings_path();
    fs::create_dir_all(path.parent().expect("settings parent")).expect("settings directory");
    fs::write(&path, b"{}").expect("legacy settings fixture");
    let store = SettingsStore::new(path.clone());
    let mut settings = store.load().expect("load legacy settings");
    assert_eq!(settings.settings_generation, 0);

    store.save(&mut settings).expect("upgrade generation");

    assert_eq!(settings.settings_generation, 1);
    assert_eq!(
        SettingsStore::new(path.clone())
            .load()
            .expect("reload upgraded settings")
            .settings_generation,
        1
    );
    cleanup_temp_path(path);
}

#[test]
fn generation_growth_is_revalidated_before_atomic_publication() {
    let path = temp_settings_path();
    let mut settings = AppSettings {
        settings_generation: 9,
        what_if: WhatIfSettings {
            custom_topology: Some(TopologyModel {
                key: "generation-size-boundary".to_string(),
                name: "Generation size boundary".to_string(),
                nodes: Vec::new(),
                links: Vec::new(),
                metadata: std::collections::BTreeMap::from([
                    ("bulk".to_string(), serde_json::Value::Array(Vec::new())),
                    (
                        "padding".to_string(),
                        serde_json::Value::String(String::new()),
                    ),
                ]),
            }),
            ..WhatIfSettings::default()
        },
        ..AppSettings::default()
    };
    let mut low = 0usize;
    let mut high = 150_000usize;
    while low < high {
        let middle = low + (high - low).div_ceil(2);
        set_boundary_bulk(&mut settings, middle);
        if serde_json::to_vec_pretty(&settings)
            .expect("serialize boundary candidate")
            .len()
            <= MAX_SETTINGS_FILE_BYTES
        {
            low = middle;
        } else {
            high = middle - 1;
        }
    }
    set_boundary_bulk(&mut settings, low);
    let base_len = serde_json::to_vec_pretty(&settings)
        .expect("serialize bounded candidate")
        .len();
    set_boundary_padding(&mut settings, MAX_SETTINGS_FILE_BYTES - base_len);
    let original = serde_json::to_vec_pretty(&settings).expect("serialize exact boundary");
    assert_eq!(original.len(), MAX_SETTINGS_FILE_BYTES);
    validate_settings(&settings).expect("generation 9 exact boundary is valid");
    fs::create_dir_all(path.parent().expect("settings parent")).expect("settings directory");
    fs::write(&path, &original).expect("write exact boundary fixture");
    let store = SettingsStore::new(path.clone());
    let mut loaded = store.load().expect("load exact boundary fixture");

    let error = store
        .save(&mut loaded)
        .expect_err("generation 10 must be rejected before publication");

    assert!(
        format!("{error:#}").contains("settings file limit"),
        "{error:#}"
    );
    assert_eq!(fs::read(&path).expect("unchanged settings"), original);
    assert_eq!(
        SettingsStore::new(path.clone())
            .load()
            .expect("published settings remain loadable")
            .settings_generation,
        9
    );
    cleanup_temp_path(path);
}

fn set_boundary_bulk(settings: &mut AppSettings, count: usize) {
    settings
        .what_if
        .custom_topology
        .as_mut()
        .expect("boundary topology")
        .metadata
        .insert(
            "bulk".to_string(),
            serde_json::Value::Array(vec![serde_json::Value::Bool(true); count]),
        );
}

fn set_boundary_padding(settings: &mut AppSettings, bytes: usize) {
    settings
        .what_if
        .custom_topology
        .as_mut()
        .expect("boundary topology")
        .metadata
        .insert(
            "padding".to_string(),
            serde_json::Value::String("x".repeat(bytes)),
        );
}
