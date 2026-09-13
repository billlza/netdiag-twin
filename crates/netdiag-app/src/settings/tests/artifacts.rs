use super::*;

#[test]
fn an_explicit_artifact_root_survives_settings_reload() {
    let path = temp_settings_path();
    let workspace = path.parent().expect("workspace");
    fs::create_dir_all(workspace.join("crates")).expect("workspace crates");
    fs::write(workspace.join("Cargo.toml"), b"[workspace]\n").expect("workspace manifest");
    let mut settings = AppSettings {
        artifacts_root: workspace.join("artifacts"),
        ..AppSettings::default()
    };
    assert!(
        bundle_artifacts_root_needs_migration(&settings),
        "legacy default migrates"
    );
    settings.artifacts_root_user_selected = true;
    let store = SettingsStore::new(path.clone());
    store
        .save(&mut settings)
        .expect("persist explicit selection");
    let reloaded = SettingsStore::new(path.clone()).load_for_startup();
    assert!(reloaded.startup_authorized());
    assert_eq!(reloaded.settings.artifacts_root, settings.artifacts_root);
    assert!(reloaded.settings.artifacts_root_user_selected);
    assert!(!bundle_artifacts_root_needs_migration(&reloaded.settings));
    fs::remove_dir_all(workspace).expect("fixture cleanup");
}

#[test]
fn a_nested_artifact_root_is_not_the_legacy_workspace_default() {
    let path = temp_settings_path();
    let workspace = path.parent().expect("workspace");
    fs::create_dir_all(workspace.join("crates")).expect("workspace crates");
    fs::write(workspace.join("Cargo.toml"), b"[workspace]\n").expect("workspace manifest");
    let settings = AppSettings {
        artifacts_root: workspace.join("target/validation/artifacts"),
        ..AppSettings::default()
    };
    assert!(!bundle_artifacts_root_needs_migration(&settings));
    fs::remove_dir_all(workspace).expect("fixture cleanup");
}
