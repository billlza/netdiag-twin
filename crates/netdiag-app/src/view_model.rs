use crate::data_source::SourceSnapshot;
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
    pub fn build(result: &PipelineResult, source: &SourceSnapshot) -> Self {
        let total_bytes = source.flow_summary.total_bytes.unwrap_or_else(|| {
            source
                .flow_summary
                .top_talkers
                .iter()
                .map(|talker| talker.bytes)
                .sum()
        });
        let top_talkers = source
            .flow_summary
            .top_talkers
            .iter()
            .map(|talker| {
                let share = if total_bytes > 0 {
                    talker.bytes as f64 / total_bytes as f64
                } else {
                    0.0
                };
                TalkerView {
                    label: talker.label.clone(),
                    detail: format!("{}  ({:.0}%)", format_bytes(talker.bytes), share * 100.0),
                    share,
                }
            })
            .collect();

        Self {
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
            total_traffic: if total_bytes > 0 {
                format_bytes(total_bytes)
            } else {
                format!("{} packets", result.telemetry.overall.samples)
            },
            top_talkers,
        }
    }
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
