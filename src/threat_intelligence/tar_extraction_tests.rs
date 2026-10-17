//! `extract_tar_gz` is the only archive path a downloaded feed reaches. A feed server (or
//! anything on the wire without TLS) chooses every byte of the archive, so extraction must be
//! confined to the destination and limited to the entry types a feed needs.
use super::*;

fn gzip(tar_bytes: Vec<u8>) -> Vec<u8> {
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    std::io::Write::write_all(&mut gz, &tar_bytes).unwrap();
    gz.finish().unwrap()
}

fn tar_gz(build: impl FnOnce(&mut tar::Builder<Vec<u8>>)) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    build(&mut builder);
    gzip(builder.into_inner().unwrap())
}

fn file_entry(builder: &mut tar::Builder<Vec<u8>>, name: &str, body: &[u8]) {
    let mut header = tar::Header::new_gnu();
    header.set_size(body.len() as u64);
    header.set_mode(0o644);
    builder.append_data(&mut header, name, body).unwrap();
}

#[cfg(unix)]
fn link_entry(
    builder: &mut tar::Builder<Vec<u8>>,
    kind: tar::EntryType,
    name: &str,
    target: &Path,
) {
    let mut header = tar::Header::new_gnu();
    header.set_entry_type(kind);
    header.set_size(0);
    header.set_mode(0o777);
    builder.append_link(&mut header, name, target).unwrap();
}

/// A one-file archive whose entry name is written into the raw header, bypassing the
/// builder's own refusal of `..` and absolute names.
fn raw_named_file(name: &str, body: &[u8]) -> Vec<u8> {
    let mut header = tar::Header::new_gnu();
    header.set_size(body.len() as u64);
    header.set_mode(0o644);
    header.as_old_mut().name[..name.len()].copy_from_slice(name.as_bytes());
    header.set_cksum();
    let mut builder = tar::Builder::new(Vec::new());
    builder.append(&header, body).unwrap();
    gzip(builder.into_inner().unwrap())
}

/// Extract as the downloader does; returns (scratch root, destination, result).
async fn extract(
    content: &[u8],
) -> (
    tempfile::TempDir,
    PathBuf,
    Result<(), Box<dyn std::error::Error>>,
) {
    let root = tempfile::tempdir().unwrap();
    let dest = root.path().join("feeds");
    std::fs::create_dir_all(&dest).unwrap();
    let result = ThreatFeedManager::extract_tar_gz(
        content,
        &dest.join("feed.tar.gz"),
        &ExtractionLimits::default(),
    )
    .await;
    (root, dest, result)
}

#[cfg(unix)]
fn is_empty_dir(path: &Path) -> bool {
    std::fs::read_dir(path).unwrap().next().is_none()
}

#[tokio::test]
async fn tar_extraction_extracts_files_and_directories() {
    let bytes = tar_gz(|b| {
        let mut dir = tar::Header::new_gnu();
        dir.set_entry_type(tar::EntryType::Directory);
        dir.set_size(0);
        dir.set_mode(0o755);
        b.append_data(&mut dir, "geo/", std::io::empty()).unwrap();
        file_entry(b, "geo/ips.txt", b"1.2.3.4");
        file_entry(b, "top.txt", b"x");
    });
    let (_root, dest, result) = extract(&bytes).await;
    result.unwrap();
    assert_eq!(std::fs::read(dest.join("geo/ips.txt")).unwrap(), b"1.2.3.4");
    assert_eq!(std::fs::read(dest.join("top.txt")).unwrap(), b"x");
}

#[cfg(unix)]
#[tokio::test]
async fn tar_extraction_confines_entries_to_the_destination() {
    let outside = tempfile::tempdir().unwrap();
    let bytes = tar_gz(|b| {
        link_entry(b, tar::EntryType::Symlink, "link", outside.path());
        file_entry(b, "link/pwn.txt", b"pwned");
    });
    let (_root, _dest, result) = extract(&bytes).await;
    assert!(result.is_err(), "an entry of another type must be refused");
    assert!(is_empty_dir(outside.path()), "a write left the destination");
}

#[cfg(unix)]
#[tokio::test]
async fn tar_extraction_accepts_only_files_and_directories() {
    let outside = tempfile::tempdir().unwrap();
    for (kind, label) in [
        (tar::EntryType::Symlink, "symlink"),
        (tar::EntryType::Link, "hardlink"),
    ] {
        let bytes = tar_gz(|b| link_entry(b, kind, "link", &outside.path().join("target")));
        let (_root, dest, result) = extract(&bytes).await;
        let err = result.expect_err(label).to_string();
        assert!(
            err.contains("link") && err.contains("unsupported"),
            "{label}: the error must name the entry and why, got: {err}"
        );
        assert!(
            dest.join("link").symlink_metadata().is_err(),
            "{label}: the entry was created"
        );
    }
}

#[tokio::test]
async fn tar_extraction_confines_entries_by_name() {
    let (root, _dest, result) = extract(&raw_named_file("../evil.txt", b"pwned")).await;
    assert!(result.is_err(), "a `..` entry must be refused");
    assert!(!root.path().join("evil.txt").exists());

    let outside = tempfile::tempdir().unwrap();
    let abs = outside.path().join("abs.txt");
    let (_root, _dest, result) = extract(&raw_named_file(abs.to_str().unwrap(), b"pwned")).await;
    assert!(result.is_err(), "an absolute entry must be refused");
    assert!(!abs.exists(), "an absolute entry was written");
}
