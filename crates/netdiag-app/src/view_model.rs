use crate::data_source::{FlowSummary, SourceSnapshot};
use netdiag_core::pipeline::PipelineResult;

#[derive(Debug, Clone)]
pub struct DashboardViewModel {
    pub current_trace: String,
    pub captured_label: String,
    pub protocol: String,
    pub flow_count: String,
    pub data_source: String,
    pub top_talkers: Vec<TalkerView>,
    pub total_traffic: String,
}

#[derive(Debug, Clone)]
pub struct TalkerView {
    pub label: String,
    pub detail: String,
    pub share: f64,
}

impl DashboardViewModel {
    pub fn build(result: &PipelineResult, source: &SourceSnapshot) -> anyhow::Result<Self> {
        let total_bytes = dashboard_total_bytes(&source.flow_summary)?;
        let top_talkers = source
            .flow_summary
            .top_talkers
            .iter()
            .map(|talker| {
                let share = match total_bytes {
                    Some(0) | None => 0.0,
                    Some(total_bytes) => talker.bytes as f64 / total_bytes as f64,
                };
                TalkerView {
                    label: talker.label.clone(),
                    detail: format!("{}  ({:.0}%)", format_bytes(talker.bytes), share * 100.0),
                    share,
                }
            })
            .collect();

        Ok(Self {
            current_trace: source.descriptor.name.clone(),
            captured_label: source.descriptor.captured_label.clone(),
            protocol: source
                .flow_summary
                .protocol
                .clone()
                .unwrap_or_else(|| "Unknown".to_string()),
            flow_count: source
                .flow_summary
                .flows
                .map(|value| value.to_string())
                .unwrap_or_else(|| "Unknown".to_string()),
            data_source: format!(
                "{} · {}",
                source.descriptor.kind, source.descriptor.data_source_label
            ),
            total_traffic: match total_bytes {
                Some(total_bytes) if total_bytes > 0 => format_bytes(total_bytes),
                Some(_) | None => format!("{} packets", result.telemetry.overall.samples),
            },
            top_talkers,
        })
    }
}

fn dashboard_total_bytes(flow_summary: &FlowSummary) -> anyhow::Result<Option<u64>> {
    flow_summary.validated_total_bytes()
}

pub fn format_bytes(bytes: u64) -> String {
    const KIB: f64 = 1024.0;
    const MIB: f64 = KIB * 1024.0;
    const GIB: f64 = MIB * 1024.0;
    let value = bytes as f64;
    if value >= GIB {
        format!("{:.1} GB", value / GIB)
    } else if value >= MIB {
        format!("{:.1} MB", value / MIB)
    } else if value >= KIB {
        format!("{:.1} KB", value / KIB)
    } else {
        format!("{bytes} B")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data_source::TopTalker;

    #[test]
    fn dashboard_requires_loader_validated_total_for_top_talkers() {
        let summary = FlowSummary {
            total_bytes: None,
            top_talkers: vec![
                TopTalker {
                    label: "maximum".to_string(),
                    bytes: u64::MAX,
                },
                TopTalker {
                    label: "one-more".to_string(),
                    bytes: 1,
                },
            ],
            ..FlowSummary::default()
        };

        let error = dashboard_total_bytes(&summary)
            .expect_err("the view must not aggregate unvalidated byte counts");

        assert!(error.to_string().contains("validated total"), "{error}");
    }

    #[test]
    fn dashboard_accepts_validated_u64_boundary() {
        let summary = FlowSummary {
            total_bytes: Some(u64::MAX),
            ..FlowSummary::default()
        };

        assert_eq!(
            dashboard_total_bytes(&summary).expect("validated total"),
            Some(u64::MAX)
        );
    }
}
