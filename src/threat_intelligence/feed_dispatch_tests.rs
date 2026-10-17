//! `extract_compressed_feed` picks an extractor from the output path's extension. Formats this
//! crate does not extract must fail loudly, never write the archive's bytes under a feed name.
use super::*;

async fn dispatch(name: &str, content: &[u8]) -> (tempfile::TempDir, PathBuf, String) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(name);
    let outcome = ThreatFeedManager::extract_compressed_feed(content, &path).await;
    let message = outcome.err().map(|e| e.to_string()).unwrap_or_default();
    (dir, path, message)
}

#[tokio::test]
async fn zip_feeds_are_refused_by_name_and_nothing_is_written() {
    // A real (empty) zip: the end-of-central-directory record only.
    let empty_zip = [
        0x50, 0x4b, 0x05, 0x06, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    let (dir, path, message) = dispatch("feed.zip", &empty_zip).await;
    assert!(
        message.to_lowercase().contains("zip") && message.contains("not supported"),
        "a .zip feed must be refused as unsupported, got: {message:?}"
    );
    assert!(
        !path.exists(),
        "the archive was written under the feed name"
    );
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
}

#[tokio::test]
async fn the_other_unsupported_formats_still_say_so() {
    for name in ["feed.bz2", "feed.xz"] {
        let (_dir, path, message) = dispatch(name, b"not really compressed").await;
        assert!(
            message.contains("not supported"),
            "{name}: expected a refusal, got: {message:?}"
        );
        assert!(!path.exists(), "{name}: bytes were written");
    }
}

#[tokio::test]
async fn unknown_extensions_are_saved_as_is() {
    let (_dir, path, message) = dispatch("feed.txt", b"1.2.3.4\n").await;
    assert_eq!(message, "");
    assert_eq!(std::fs::read(&path).unwrap(), b"1.2.3.4\n");
}
