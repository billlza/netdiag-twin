use super::{AtomicPublicationState, not_published};
use std::error::Error;
use std::io;

#[test]
fn not_published_preserves_an_unsupported_primary_error() {
    let error = not_published(io::Error::new(
        io::ErrorKind::Unsupported,
        "platform boundary unavailable",
    ));

    assert_eq!(error.state(), AtomicPublicationState::NotPublished);
    assert_eq!(error.kind(), io::ErrorKind::Unsupported);
    assert!(error.classification().is_none());
    let source = Error::source(&error)
        .and_then(|source| source.downcast_ref::<io::Error>())
        .expect("primary I/O source");
    assert!(std::ptr::eq(source, error.primary_io_error()));
}
