/*
 * SPDX-FileCopyrightText: The Yasvara Project
 * SPDX-License-Identifier: Apache-2.0
 */

use super::*;
use std::fs::{FileTimes, Permissions};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

struct Fixture {
    dir: PathBuf,
    path: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "yasvara-cache-test-{}-{}-{}",
            std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&dir).unwrap();
        fs::create_dir(dir.join("installed")).unwrap();
        let path = dir.join("installed/keybox.xml");
        Self { dir, path }
    }

    fn write(&self, content: &[u8]) {
        fs::write(&self.path, content).unwrap();
    }

    fn set_mtime(&self, mtime: SystemTime) {
        File::open(&self.path).unwrap().set_times(FileTimes::new().set_modified(mtime)).unwrap();
    }

    fn replace(&self, content: &[u8], mtime: SystemTime) {
        let staged = self.path.with_extension("next");
        fs::write(&staged, content).unwrap();
        File::open(&staged).unwrap().set_times(FileTimes::new().set_modified(mtime)).unwrap();
        fs::rename(staged, &self.path).unwrap();
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.dir).unwrap();
    }
}

// Deliberately nonsensitive stand-in parser; all file/cache operations are production code.
fn parse(content: &str) -> Option<String> {
    content.strip_prefix("valid:").map(str::to_owned)
}

#[test]
fn unchanged_success_does_not_read_or_parse_again() {
    let fixture = Fixture::new();
    fixture.write(b"valid:first");
    let mut cache = FileCache::new();
    let now = Instant::now();
    let first = cache.current(&fixture.path, now, parse);
    assert!(first.loaded);
    assert!(first.diagnostic.is_none());
    assert_eq!(first.entry.map(String::as_str), Some("first"));
    let cached = cache.current_with_reader(
        &fixture.path,
        now + DIAGNOSTIC_INTERVAL,
        |_| panic!("unchanged success must not parse"),
        |_, _| panic!("unchanged success must not read"),
    );
    assert!(!cached.loaded);
    assert!(cached.diagnostic.is_none());
    assert_eq!(cached.entry.map(String::as_str), Some("first"));
}

#[test]
fn tombstone_zero_byte_clears_entry_without_error() {
    let fix = Fixture::new();
    fix.write(b"valid:secret");
    let mut cache = FileCache::new();
    let now = Instant::now();
    let res = cache.current(&fix.path, now, parse);
    assert!(res.loaded);
    assert_eq!(res.entry, Some(&"secret".to_string()));

    // Clear with 0-byte tombstone
    fix.replace(b"", SystemTime::now() + Duration::from_secs(1));
    let res2 = cache.current(&fix.path, now + Duration::from_secs(2), parse);
    assert!(!res2.loaded);
    assert_eq!(res2.entry, None);
    assert!(res2.diagnostic.is_none());
}

#[test]
fn atomic_replacement_with_identical_mtime_and_size_reloads() {
    let fixture = Fixture::new();
    fixture.write(b"valid:first");
    let mtime = UNIX_EPOCH + Duration::from_secs(123);
    fixture.set_mtime(mtime);
    let before = fingerprint(&fixture.path).unwrap();
    let mut cache = FileCache::new();
    let now = Instant::now();
    assert!(cache.current(&fixture.path, now, parse).loaded);

    fixture.replace(b"valid:other", mtime);
    let after = fingerprint(&fixture.path).unwrap();
    assert_eq!(before.mtime, after.mtime);
    assert_eq!(before.size, after.size);
    assert_ne!(before.ino, after.ino);
    let result = cache.current(&fixture.path, now, parse);
    assert!(result.loaded);
    assert_eq!(result.entry.map(String::as_str), Some("other"));
}

#[test]
fn in_place_same_size_edit_with_restored_mtime_reloads_via_ctime() {
    let fixture = Fixture::new();
    fixture.write(b"valid:first");
    let mtime = UNIX_EPOCH + Duration::from_secs(123);
    fixture.set_mtime(mtime);
    let before = fingerprint(&fixture.path).unwrap();
    let mut cache = FileCache::new();
    let now = Instant::now();
    assert!(cache.current(&fixture.path, now, parse).loaded);

    // Bound the wait for a new filesystem timestamp tick; no cache retry sleeps are needed.
    for _ in 0..1000 {
        fixture.write(b"valid:other");
        fixture.set_mtime(mtime);
        if fingerprint(&fixture.path).unwrap().ctime != before.ctime {
            break;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    let after = fingerprint(&fixture.path).unwrap();
    assert_eq!(before.ino, after.ino);
    assert_eq!(before.size, after.size);
    assert_eq!(before.mtime, after.mtime);
    assert_ne!(before.ctime, after.ctime);
    let result = cache.current(&fixture.path, now, parse);
    assert!(result.loaded);
    assert_eq!(result.entry.map(String::as_str), Some("other"));
}

#[test]
fn fingerprint_accounts_for_all_identity_and_repair_fields() {
    let fixture = Fixture::new();
    fixture.write(b"valid:first");
    let original = fingerprint(&fixture.path).unwrap();
    let different = [
        Fingerprint { dev: original.dev.wrapping_add(1), ..original },
        Fingerprint { ino: original.ino.wrapping_add(1), ..original },
        Fingerprint { size: original.size + 1, ..original },
        Fingerprint { mtime: (original.mtime.0 + 1, original.mtime.1), ..original },
        Fingerprint { mtime: (original.mtime.0, original.mtime.1 + 1), ..original },
        Fingerprint { ctime: (original.ctime.0 + 1, original.ctime.1), ..original },
        Fingerprint { ctime: (original.ctime.0, original.ctime.1 + 1), ..original },
        Fingerprint { mode: original.mode ^ 0o400, ..original },
        Fingerprint { uid: original.uid.wrapping_add(1), ..original },
        Fingerprint { gid: original.gid.wrapping_add(1), ..original },
    ];
    for changed in different {
        assert_ne!(original, changed);
    }
}

#[test]
fn deletion_drops_entry_and_recreation_is_seen_immediately() {
    let fixture = Fixture::new();
    fixture.write(b"valid:first");
    let mut cache = FileCache::new();
    let now = Instant::now();
    assert!(cache.current(&fixture.path, now, parse).entry.is_some());
    fs::remove_file(&fixture.path).unwrap();
    let deleted = cache.current(&fixture.path, now, parse);
    assert!(deleted.entry.is_none());
    assert!(matches!(
        deleted.diagnostic,
        Some(Failure::Io { operation: "lstat", kind: io::ErrorKind::NotFound, errno: Some(_) })
    ));
    fixture.write(b"valid:other");
    let restored = cache.current(&fixture.path, now, parse);
    assert!(restored.loaded);
    assert_eq!(restored.entry.map(String::as_str), Some("other"));
}

#[test]
fn metadata_error_drops_entry_and_reports_operation_kind_and_errno() {
    let fixture = Fixture::new();
    fixture.write(b"valid:first");
    let mut cache = FileCache::new();
    let now = Instant::now();
    assert!(cache.current(&fixture.path, now, parse).loaded);
    let installed = fixture.dir.join("installed");
    let saved = fixture.dir.join("saved");
    fs::rename(&installed, &saved).unwrap();
    fs::write(&installed, b"not a directory").unwrap();
    let expected = fs::metadata(&fixture.path).unwrap_err();
    let failed = cache.current(&fixture.path, now, parse);
    assert!(failed.entry.is_none());
    match failed.diagnostic.unwrap() {
        Failure::Io { operation, kind, errno } => {
            assert_eq!(operation, "lstat");
            assert_eq!(kind, expected.kind());
            assert_eq!(errno, expected.raw_os_error());
        }
        other => panic!("unexpected diagnostic: {:?}", other),
    }
    fs::remove_file(installed).unwrap();
    fs::rename(saved, fixture.dir.join("installed")).unwrap();
    assert!(cache.current(&fixture.path, now, parse).loaded);
}

#[test]
fn unchanged_transient_open_errors_retry_at_bounded_deadline() {
    // Inject only the OS failure; the production state machine and subsequent real read run
    // unchanged. This also works as root, unlike relying on DAC to produce EACCES in tests.
    for errno in [13, 5, 4] {
        let fixture = Fixture::new();
        fixture.write(b"valid:first");
        let identity = fingerprint(&fixture.path).unwrap();
        let mut cache = FileCache::new();
        let now = Instant::now();
        let failed = cache.current_with_reader(&fixture.path, now, parse, |_, _| {
            Err(Failure::io("open", io::Error::from_raw_os_error(errno)))
        });
        assert!(failed.entry.is_none());
        assert!(failed.diagnostic.is_some());
        let backed_off =
            cache.current(&fixture.path, now + RETRY_INTERVAL - Duration::from_nanos(1), |_| {
                panic!("failure must back off")
            });
        assert!(backed_off.entry.is_none());
        assert!(backed_off.diagnostic.is_none());
        assert_eq!(fingerprint(&fixture.path).unwrap(), identity);
        let recovered = cache.current(&fixture.path, now + RETRY_INTERVAL, parse);
        assert!(recovered.loaded);
        assert_eq!(recovered.entry.map(String::as_str), Some("first"));
    }
}

#[test]
fn permission_repair_bypasses_failure_backoff() {
    let fixture = Fixture::new();
    fixture.write(b"valid:first");
    fs::set_permissions(&fixture.path, Permissions::from_mode(0o0)).unwrap();
    let before = fingerprint(&fixture.path).unwrap();
    let mut cache = FileCache::new();
    let now = Instant::now();
    assert!(cache
        .current_with_reader(&fixture.path, now, parse, |_, _| {
            Err(Failure::io("open", io::Error::from_raw_os_error(13)))
        })
        .entry
        .is_none());
    fs::set_permissions(&fixture.path, Permissions::from_mode(0o600)).unwrap();
    let after = fingerprint(&fixture.path).unwrap();
    assert_eq!(before.ino, after.ino);
    assert_eq!(before.mtime, after.mtime);
    assert_eq!(before.size, after.size);
    assert_ne!(before.mode, after.mode);
    assert!(cache.current(&fixture.path, now, parse).loaded);
}

#[test]
fn real_read_failure_drops_previous_entry() {
    let fixture = Fixture::new();
    fixture.write(b"valid:first");
    let mut cache = FileCache::new();
    let now = Instant::now();
    assert!(cache.current(&fixture.path, now, parse).loaded);
    fixture.replace(&[0xff], UNIX_EPOCH);
    let failed = cache.current(&fixture.path, now, parse);
    assert!(failed.entry.is_none());
    assert!(matches!(
        failed.diagnostic,
        Some(Failure::Io { operation: "read", kind: io::ErrorKind::InvalidData, .. })
    ));
    fixture.replace(b"valid:other", UNIX_EPOCH);
    assert_eq!(cache.current(&fixture.path, now, parse).entry.map(String::as_str), Some("other"));
}

#[test]
fn unchanged_parse_failure_retries_without_caching_failure_forever() {
    let fixture = Fixture::new();
    fixture.write(b"valid:first");
    let mut cache = FileCache::new();
    let now = Instant::now();
    let failed = cache.current(&fixture.path, now, |_| None::<String>);
    assert!(failed.entry.is_none());
    assert!(matches!(failed.diagnostic, Some(Failure::InvalidKeybox)));
    assert!(cache.current(&fixture.path, now, |_| panic!("must back off")).entry.is_none());
    assert!(cache.current(&fixture.path, now + RETRY_INTERVAL, parse).loaded);
}

#[test]
fn invalid_replacement_drops_old_entry_and_valid_replacement_bypasses_backoff() {
    let fixture = Fixture::new();
    fixture.write(b"valid:first");
    let mut cache = FileCache::new();
    let now = Instant::now();
    assert!(cache.current(&fixture.path, now, parse).loaded);
    fixture.replace(b"malformed", UNIX_EPOCH);
    let failed = cache.current(&fixture.path, now, parse);
    assert!(failed.entry.is_none());
    assert!(matches!(failed.diagnostic, Some(Failure::InvalidKeybox)));
    fixture.replace(b"valid:other", UNIX_EPOCH);
    assert_eq!(cache.current(&fixture.path, now, parse).entry.map(String::as_str), Some("other"));
}

#[test]
fn replacement_between_stat_and_open_rejects_snapshot() {
    let fixture = Fixture::new();
    fixture.write(b"valid:first");
    let mut cache = FileCache::new();
    let now = Instant::now();
    let raced = cache.current_with_reader(&fixture.path, now, parse, |path, expected| {
        fixture.replace(b"valid:other", UNIX_EPOCH);
        read_snapshot(path, expected)
    });
    assert!(raced.entry.is_none());
    assert!(matches!(raced.diagnostic, Some(Failure::ChangedWhileReading)));
    assert_eq!(cache.current(&fixture.path, now, parse).entry.map(String::as_str), Some("other"));
}

#[test]
fn replacement_or_deletion_during_parse_never_installs_stale_entry() {
    for remove in [false, true] {
        let fixture = Fixture::new();
        fixture.write(b"valid:first");
        let mut cache = FileCache::new();
        let now = Instant::now();
        let raced = cache.current(&fixture.path, now, |content| {
            if remove {
                fs::remove_file(&fixture.path).unwrap();
            } else {
                fixture.replace(b"valid:other", UNIX_EPOCH);
            }
            parse(content)
        });
        assert!(raced.entry.is_none());
        assert!(!raced.loaded);
        if remove {
            assert!(matches!(raced.diagnostic, Some(Failure::Io { operation: "lstat", .. })));
        } else {
            assert!(matches!(raced.diagnostic, Some(Failure::ChangedWhileReading)));
            assert!(cache.current(&fixture.path, now, parse).loaded);
        }
    }
}

#[test]
fn missing_file_and_flapping_errors_are_rate_limited_even_across_recovery() {
    let fixture = Fixture::new();
    let mut cache = FileCache::new();
    let now = Instant::now();
    assert!(cache.current(&fixture.path, now, parse).diagnostic.is_some());
    assert!(cache.current(&fixture.path, now, parse).diagnostic.is_none());
    fixture.write(b"malformed");
    assert!(cache.current(&fixture.path, now + Duration::from_secs(1), parse).diagnostic.is_none());
    fixture.replace(b"valid:first", UNIX_EPOCH);
    assert!(cache.current(&fixture.path, now + Duration::from_secs(2), parse).loaded);
    fs::remove_file(&fixture.path).unwrap();
    assert!(cache.current(&fixture.path, now + Duration::from_secs(3), parse).diagnostic.is_none());
    let reminder = cache.current(&fixture.path, now + DIAGNOSTIC_INTERVAL, parse);
    assert!(reminder.entry.is_none());
    assert!(reminder.diagnostic.is_some());
}

#[test]
fn nonregular_file_is_rejected_without_attempting_read() {
    let fixture = Fixture::new();
    fs::create_dir(&fixture.path).unwrap();
    let mut cache = FileCache::new();
    let result = cache.current_with_reader(&fixture.path, Instant::now(), parse, |_, _| {
        panic!("must reject nonregular files before opening")
    });
    assert!(result.entry.is_none());
    assert!(matches!(result.diagnostic, Some(Failure::NotRegularFile)));
}

#[test]
fn diagnostic_never_retains_io_error_payload() {
    let marker = "nonsensitive test payload that must not enter diagnostics";
    let failure = Failure::io("read", io::Error::new(io::ErrorKind::InvalidData, marker));
    assert!(!failure.to_string().contains(marker));
    assert!(!format!("{failure:?}").contains(marker));
    assert!(failure.to_string().contains("read failed"));
    assert!(failure.to_string().contains("InvalidData"));
}
