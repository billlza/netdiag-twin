use super::*;

#[test]
fn bundled_cjk_font_contains_required_chinese_glyphs() {
    let face = ttf_parser::Face::parse(CJK_FONT_BYTES, 0).expect("bundled CJK font parses");

    for ch in "概览诊断规则数字孪生设置导入仿真真实拥塞实验室".chars() {
        assert!(
            face.glyph_index(ch).is_some(),
            "bundled CJK font is missing {ch}"
        );
    }
}

#[test]
fn compact_text_middle_truncates_long_values() {
    let text = compact_text("sim.congestion.long.trace.name", 14);
    assert!(text.contains('…'));
    assert!(text.len() < "sim.congestion.long.trace.name".len());
}

#[test]
fn summary_card_rows_center_value_with_icon_when_no_caption() {
    let rows = summary_card_text_rows(80.0, false);
    assert_eq!(rows.caption_y, None);
    assert_eq!(rows.label_y, 58.0);
    assert_eq!(rows.value_y, 80.0);
}

#[test]
fn summary_card_rows_keep_trace_text_group_balanced() {
    let rows = summary_card_text_rows(80.0, true);
    assert_eq!(rows.label_y, 54.0);
    assert_eq!(rows.value_y, 80.0);
    assert_eq!(rows.caption_y, Some(106.0));
    let group_center = (rows.label_y + rows.caption_y.unwrap()) / 2.0;
    assert!((group_center - 80.0).abs() < 0.1);
}

#[test]
fn startup_tab_round_trip_includes_lab() {
    assert!(StartupTab::ALL.contains(&StartupTab::Lab));
    assert_eq!(Tab::from(StartupTab::Lab), Tab::Lab);
    assert_eq!(StartupTab::from(Tab::Lab), StartupTab::Lab);
    assert_eq!(title_for_tab(Tab::Lab, Language::En), "Lab");
}
