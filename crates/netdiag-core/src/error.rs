use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum NetdiagError {
    #[error("I/O error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("CSV parse error: {0}")]
    Csv(#[from] csv::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("timestamp parse error: {0}")]
    Timestamp(String),
    #[error("trace has no rows")]
    EmptyTrace,
    #[error("trace is missing required column: {0}")]
    MissingColumn(String),
    #[error("invalid numeric value at row {row}, column {column}: {value}")]
    InvalidNumber {
        row: usize,
        column: String,
        value: String,
    },
    #[error("invalid timestamp at row {row}: {value}")]
    InvalidTimestamp { row: usize, value: String },
    #[error("invalid trace: {0}")]
    InvalidTrace(String),
    #[error("unknown recommendation id: {0}")]
    UnknownRecommendation(String),
    #[error("unknown topology: {0}")]
    UnknownTopology(String),
    #[error("unknown what-if action: {0}")]
    UnknownAction(String),
    #[error("connector error: {0}")]
    Connector(String),
    #[error("ML training/inference error: {0}")]
    Ml(String),
}

pub type Result<T> = std::result::Result<T, NetdiagError>;

pub(crate) trait IoContext<T> {
    fn with_path(self, path: impl Into<PathBuf>) -> Result<T>;
}

impl<T> IoContext<T> for std::io::Result<T> {
    fn with_path(self, path: impl Into<PathBuf>) -> Result<T> {
        self.map_err(|source| NetdiagError::Io {
            path: path.into(),
            source,
        })
    }
}
