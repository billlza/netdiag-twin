use crate::error::{NetdiagError, Result};

pub(crate) fn percent_delta(left: f64, right: f64) -> Result<Option<f64>> {
    if !left.is_finite() || !right.is_finite() {
        return Err(NetdiagError::InvalidTrace(
            "run comparison inputs must be finite".to_string(),
        ));
    }
    let baseline = left.abs();
    if baseline < f64::EPSILON {
        return Ok(None);
    }
    let normalized_right = right / baseline;
    let delta_ratio = normalized_right - left.signum();
    let delta_pct = delta_ratio * 100.0;
    if !normalized_right.is_finite() || !delta_ratio.is_finite() || !delta_pct.is_finite() {
        return Err(NetdiagError::InvalidTrace(
            "run comparison percentage delta is outside the supported finite range".to_string(),
        ));
    }
    Ok(Some(delta_pct))
}
