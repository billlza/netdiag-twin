use std::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirectoryPersistenceStage {
    Directory,
    ParentDirectory,
}

impl fmt::Display for DirectoryPersistenceStage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Directory => "trusted directory",
            Self::ParentDirectory => "trusted parent directory entry",
        })
    }
}
