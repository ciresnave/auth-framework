//! A downloaded archive is attacker-sized input: a few kilobytes of gzip can declare gigabytes of
//! entry data. Extraction must refuse it by the sizes the archive *declares*, before anything is
//! written, and a refused archive must not leave its earlier entries behind.
use super::*;

fn gzip(tar_bytes: Vec<u8>) -> Vec<u8> {
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    std::io::Write::write_all(&mut gz, &tar_bytes).unwrap();
    gz.finish().unwrap()
}

fn tar_gz(entries: &[(&str, usize)]) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    for (name, len) in entries {
        let body = vec![0u8; *len];
        let mut header = tar::Header::new_gnu();
        header.set_size(body.len() as u64);
        header.set_mode(0o644);
        builder
            .append_data(&mut header, name, body.as_slice())
            .unwrap();
    }
    gzip(builder.into_inner().unwrap())
}

fn limits(max_entries: usize, max_entry_bytes: u64, max_total_bytes: u64) -> ExtractionLimits {
    ExtractionLimits {
        max_entries,
        max_entry_bytes,
        max_total_bytes,
    }
}

/// Extract as the downloader does; returns (scratch root, destination, error text or "").
async fn extract(
    content: &[u8],
    limits: &ExtractionLimits,
) -> (tempfile::TempDir, PathBuf, String) {
    let root = tempfile::tempdir().unwrap();
    let dest = root.path().join("feeds");
    std::fs::create_dir_all(&dest).unwrap();
    let outcome =
        ThreatFeedManager::extract_tar_gz(content, &dest.join("feed.tar.gz"), limits).await;
    let message = outcome.err().map(|e| e.to_string()).unwrap_or_default();
    (root, dest, message)
}

fn files_under(dir: &Path) -> Vec<String> {
    fn walk(dir: &Path, root: &Path, out: &mut Vec<String>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                walk(&path, root, out);
            } else {
                out.push(path.strip_prefix(root).unwrap().display().to_string());
            }
        }
    }
    let mut out = Vec::new();
    walk(dir, dir, &mut out);
    out.sort();
    out
}

#[tokio::test]
async fn an_archive_within_every_cap_extracts() {
    let bytes = tar_gz(&[("a.txt", 100), ("b.txt", 200), ("c.txt", 300)]);
    let (_root, dest, message) = extract(&bytes, &limits(3, 300, 600)).await;
    assert_eq!(message, "", "an archive exactly at the caps must extract");
    assert_eq!(files_under(&dest), ["a.txt", "b.txt", "c.txt"]);
}

#[tokio::test]
async fn an_entry_over_the_per_entry_cap_is_refused_before_anything_is_written() {
    let bytes = tar_gz(&[("big.bin", 2048)]);
    let (_root, dest, message) = extract(&bytes, &limits(10, 1024, 1 << 20)).await;
    assert!(
        message.contains("big.bin") && message.contains("per-entry"),
        "the error must name the entry and the cap, got: {message:?}"
    );
    assert!(files_under(&dest).is_empty(), "something was written");
}

#[tokio::test]
async fn a_total_over_the_cap_is_refused_and_earlier_files_are_removed() {
    let bytes = tar_gz(&[("a.txt", 600), ("b.txt", 600), ("c.txt", 600)]);
    let (_root, dest, message) = extract(&bytes, &limits(10, 1024, 1500)).await;
    assert!(
        message.contains("c.txt") && message.contains("total"),
        "the error must name the entry that crossed the total cap, got: {message:?}"
    );
    assert!(
        files_under(&dest).is_empty(),
        "a refused archive left files behind: {:?}",
        files_under(&dest)
    );
}

#[tokio::test]
async fn more_entries_than_the_count_cap_are_refused_and_nothing_is_left() {
    let bytes = tar_gz(&[("1", 1), ("2", 1), ("3", 1), ("4", 1), ("5", 1)]);
    let (_root, dest, message) = extract(&bytes, &limits(3, 1024, 1 << 20)).await;
    assert!(
        message.contains("entries"),
        "the error must name the entry-count cap, got: {message:?}"
    );
    assert!(files_under(&dest).is_empty());
}

#[tokio::test]
async fn a_planted_bomb_is_refused_but_an_honest_large_entry_is_not() {
    // 64 MiB of zeros gzips to a few tens of kilobytes: the shape of a decompression bomb.
    let bomb = tar_gz(&[("bomb.bin", 64 << 20)]);
    assert!(
        bomb.len() < 1 << 20,
        "the planted bomb must be small on the wire ({} bytes)",
        bomb.len()
    );
    let caps = limits(10, 16 << 20, 16 << 20);
    let (_root, dest, message) = extract(&bomb, &caps).await;
    assert!(message.contains("bomb.bin"), "got: {message:?}");
    assert!(files_under(&dest).is_empty(), "the bomb was written");

    let honest = tar_gz(&[("geo.bin", 1 << 20)]);
    let (_root, dest, message) = extract(&honest, &caps).await;
    assert_eq!(message, "");
    assert_eq!(
        std::fs::metadata(dest.join("geo.bin")).unwrap().len(),
        1 << 20
    );
}

#[test]
fn the_defaults_are_generous_for_real_feeds_and_old_configs_still_load() {
    let defaults = ExtractionLimits::default();
    assert_eq!(defaults.max_entries, 10_000);
    assert_eq!(defaults.max_entry_bytes, 512 << 20);
    assert_eq!(defaults.max_total_bytes, 1 << 30);

    // A config written before the limits existed must deserialize, with the defaults.
    let old = r#"{
        "auto_update_enabled": false,
        "update_interval_seconds": 3600,
        "feeds_directory": "feeds",
        "feeds": {},
        "download_timeout_seconds": 30
    }"#;
    let config: ThreatIntelConfig = serde_json::from_str(old).unwrap();
    assert_eq!(config.extraction_limits, defaults);
}
