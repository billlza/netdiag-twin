mod entry;
mod error;
mod execute;
mod noclobber;

#[cfg(all(test, unix))]
pub(crate) use entry::write_file_atomically_with;
pub(crate) use entry::{write_file_atomically, write_file_atomically_to_bound};
pub(crate) use noclobber::write_file_atomically_noclobber_or_existing_to_bound;

#[cfg(test)]
mod tests;
