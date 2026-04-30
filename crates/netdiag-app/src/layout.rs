use eframe::egui::{Pos2, Rect, Vec2};

pub const SUMMARY_CARD_COUNT: usize = 5;
pub const SUMMARY_CARD_GAP: f32 = 20.0;
pub const SUMMARY_CARD_HEIGHT: f32 = 104.0;
pub const HEADER_ACTION_WIDTH: f32 = 144.0;
pub const HEADER_ACTION_HEIGHT: f32 = 44.0;
pub const OVERVIEW_MIN_CONTENT_HEIGHT: f32 = 820.0;

pub fn summary_card_rects(bounds: Rect) -> Vec<Rect> {
    let total_gap = SUMMARY_CARD_GAP * (SUMMARY_CARD_COUNT.saturating_sub(1) as f32);
    let card_width = ((bounds.width() - total_gap) / SUMMARY_CARD_COUNT as f32)
        .floor()
        .max(1.0);
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
}
