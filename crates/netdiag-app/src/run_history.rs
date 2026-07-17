use netdiag_core::NetdiagError;

pub(super) fn apply_run_history_clear_state<T, U>(
    result: &Result<(), NetdiagError>,
    timeline: &mut Vec<T>,
    timeline_loaded: &mut bool,
    selected: &mut Option<U>,
) {
    if result.is_ok() {
        timeline.clear();
        *timeline_loaded = true;
        *selected = None;
    }
}
