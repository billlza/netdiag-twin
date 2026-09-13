use eframe::egui::{self, Pos2, Rect, Vec2};

pub const SUMMARY_CARD_COUNT: usize = 5;
pub const SUMMARY_CARD_GAP: f32 = 20.0;
pub const SUMMARY_CARD_HEIGHT: f32 = 104.0;
pub const HEADER_ACTION_WIDTH: f32 = 144.0;
pub const HEADER_ACTION_HEIGHT: f32 = 44.0;
pub const OVERVIEW_MIN_CONTENT_HEIGHT: f32 = 820.0;

pub fn summary_card_rects(bounds: Rect) -> Vec<Rect> {
    let total_gap = SUMMARY_CARD_GAP * (SUMMARY_CARD_COUNT.saturating_sub(1) as f32);
    let card_width = ((bounds.width() - total_gap) / SUMMARY_CARD_COUNT as f32).max(1.0);
    (0..SUMMARY_CARD_COUNT)
        .map(|idx| {
            let left = bounds.left() + idx as f32 * (card_width + SUMMARY_CARD_GAP);
            let right = if idx + 1 == SUMMARY_CARD_COUNT {
                bounds.right()
            } else {
                left + card_width
            };
            Rect::from_min_size(
                Pos2::new(left, bounds.top()),
                Vec2::new((right - left).max(1.0), SUMMARY_CARD_HEIGHT),
            )
        })
        .collect()
}

pub fn overview_content_height(available_height: f32) -> f32 {
    available_height.max(OVERVIEW_MIN_CONTENT_HEIGHT)
}

pub fn show_overview(ui: &mut egui::Ui, render: impl FnOnce(&mut egui::Ui, Rect)) {
    let bounds = ui.max_rect();
    if bounds.height() < OVERVIEW_MIN_CONTENT_HEIGHT {
        egui::ScrollArea::vertical()
            .id_salt("overview_scroll")
            .auto_shrink([false, false])
            .show_viewport(ui, |ui, _| {
                let size = Vec2::new(
                    ui.available_width(),
                    overview_content_height(bounds.height()),
                );
                ui.set_min_size(size);
                render(ui, Rect::from_min_size(ui.min_rect().min, size));
            });
    } else {
        render(ui, bounds);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summary_cards_are_equal_size_and_gap() {
        let rects = summary_card_rects(Rect::from_min_size(
            Pos2::ZERO,
            Vec2::new(1200.0, SUMMARY_CARD_HEIGHT),
        ));

        assert_eq!(rects.len(), SUMMARY_CARD_COUNT);
        for rect in &rects {
            assert_eq!(rect.height(), SUMMARY_CARD_HEIGHT);
            assert!((rect.width() - rects[0].width()).abs() < 0.01);
        }
        for pair in rects.windows(2) {
            assert!((pair[1].left() - pair[0].right() - SUMMARY_CARD_GAP).abs() < 0.01);
        }
    }

    #[test]
    fn summary_cards_keep_equal_widths_when_space_is_not_evenly_divisible() {
        for width in [772.0, 1040.5, 1201.25] {
            let bounds =
                Rect::from_min_size(Pos2::new(12.0, 20.0), Vec2::new(width, SUMMARY_CARD_HEIGHT));
            let rects = summary_card_rects(bounds);
            for rect in &rects {
                assert!(
                    (rect.width() - rects[0].width()).abs() < 0.01,
                    "unequal summary card widths at content width {width}: {rects:?}",
                );
            }
            assert!((rects[0].left() - bounds.left()).abs() < 0.01);
            assert!((rects[SUMMARY_CARD_COUNT - 1].right() - bounds.right()).abs() < 0.01);
        }
    }

    #[test]
    fn summary_cards_stay_inside_narrow_overview_bounds() {
        let bounds =
            Rect::from_min_size(Pos2::new(12.0, 20.0), Vec2::new(772.0, SUMMARY_CARD_HEIGHT));
        let rects = summary_card_rects(bounds);

        assert_eq!(rects.len(), SUMMARY_CARD_COUNT);
        for rect in rects {
            assert!(rect.left() >= bounds.left());
            assert!(rect.right() <= bounds.right() + 0.01);
            assert_eq!(rect.top(), bounds.top());
            assert!(rect.bottom() <= bounds.bottom() + 0.01);
        }
    }

    #[test]
    fn overview_content_has_minimum_height() {
        assert_eq!(overview_content_height(600.0), OVERVIEW_MIN_CONTENT_HEIGHT);
        assert_eq!(overview_content_height(900.0), 900.0);
    }

    #[test]
    fn short_overview_moves_rendered_content_when_scrolled() {
        let context = egui::Context::default();
        let input = egui::RawInput {
            screen_rect: Some(Rect::from_min_size(Pos2::ZERO, Vec2::new(800.0, 400.0))),
            ..Default::default()
        };
        let frame = |scroll: f32| {
            let mut content_top = None;
            let mut output = context.run_ui(input.clone(), |ui| {
                show_overview(ui, |ui, rect| {
                    content_top = Some(rect.top());
                    ui.painter().rect_filled(rect, 0, egui::Color32::WHITE);
                    ui.scroll_with_delta_animation(
                        Vec2::new(0.0, scroll),
                        egui::style::ScrollAnimation::none(),
                    );
                });
            });
            // This headless geometry test has no GPU texture consumer.
            output.textures_delta.clear();
            content_top.expect("overview content was rendered")
        };
        let before = frame(0.0);
        frame(-150.0);
        // ScrollArea resolves the request, then projects it into the child UI.
        frame(0.0);
        let after = frame(0.0);
        assert!(
            after < before - 100.0,
            "content stayed at {after} after scrolling from {before}"
        );
    }
}
