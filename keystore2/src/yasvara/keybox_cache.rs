/*
 * SPDX-FileCopyrightText: The Yasvara Project
 * SPDX-License-Identifier: Apache-2.0
 */

// Keep file caching independent of Android and crypto so host tests exercise production logic.
use std::fmt;
use std::fs::{self, File, Metadata};
use std::io::{self, Read};
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::time::{Duration, Instant};

const RETRY_INTERVAL: Duration = Duration::from_secs(5);
const DIAGNOSTIC_INTERVAL: Duration = Duration::from_secs(60);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Fingerprint {
    dev: u64,
    ino: u64,
    size: u64,
    mtime: (i64, i64),
    ctime: (i64, i64),
    mode: u32,
    uid: u32,
    gid: u32,
}

impl Fingerprint {
    fn of(metadata: &Metadata) -> Self {
        Self {
            dev: metadata.dev(),
            ino: metadata.ino(),
            size: metadata.size(),
            mtime: (metadata.mtime(), metadata.mtime_nsec()),
            ctime: (metadata.ctime(), metadata.ctime_nsec()),
            mode: metadata.mode(),
            uid: metadata.uid(),
            gid: metadata.gid(),
        }
    }
}

#[derive(Debug)]
pub(crate) enum Failure {
    Io { operation: &'static str, kind: io::ErrorKind, errno: Option<i32> },
    NotRegularFile,
    ChangedWhileReading,
    InvalidKeybox,
}

impl Failure {
    fn io(operation: &'static str, error: io::Error) -> Self {
        // Retain only actionable OS diagnostics, never file contents or parser input.
        Self::Io { operation, kind: error.kind(), errno: error.raw_os_error() }
    }
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { operation, kind, errno } => {
                write!(f, "{operation} failed (kind={kind:?}, errno={errno:?})")
            }
            Self::NotRegularFile => f.write_str("not a regular file"),
            Self::ChangedWhileReading => {
                f.write_str("file changed while loading; snapshot rejected")
            }
            Self::InvalidKeybox => f.write_str("invalid keybox or no usable supported key/chain"),
        }
    }
}

pub(crate) struct Lookup<'a, T> {
    pub entry: Option<&'a T>,
    pub loaded: bool,
    pub diagnostic: Option<Failure>,
}

pub(crate) struct FileCache<T> {
    fingerprint: Option<Fingerprint>,
    entry: Option<T>,
    retry_at: Option<Instant>,
    last_diagnostic: Option<Instant>,
}

impl<T> FileCache<T> {
    pub fn new() -> Self {
        Self { fingerprint: None, entry: None, retry_at: None, last_diagnostic: None }
    }

    pub fn current(
        &mut self,
        path: &Path,
        now: Instant,
        parse: impl FnOnce(&str) -> Option<T>,
    ) -> Lookup<'_, T> {
        self.current_with_reader(path, now, parse, read_snapshot)
    }

    fn current_with_reader(
        &mut self,
        path: &Path,
        now: Instant,
        parse: impl FnOnce(&str) -> Option<T>,
        read: impl FnOnce(&Path, Fingerprint) -> Result<String, Failure>,
    ) -> Lookup<'_, T> {
        // Always stat, even during failure backoff: deletion, replacement and permission/label
        // repairs must invalidate cached state immediately, not wait for the retry deadline.
        let fingerprint = match fingerprint(path) {
            Ok(fingerprint) => fingerprint,
            Err(failure) => {
                self.fingerprint = None;
                self.entry = None;
                self.retry_at = None;
                return self.result(now, false, Some(failure));
            }
        };
        if fingerprint.size == 0 {
            self.fingerprint = Some(fingerprint);
            self.entry = None;
            self.retry_at = None;
            return self.result(now, false, None);
        }
        if self.fingerprint == Some(fingerprint)
            && (self.entry.is_some() || self.retry_at.is_some_and(|deadline| now < deadline))
        {
            return self.result(now, false, None);
        }

        // Never serve an earlier entry after a failed reload, including a racing replacement.
        self.entry = None;
        self.fingerprint = Some(fingerprint);
        self.retry_at = Some(now + RETRY_INTERVAL);
        let result = read(path, fingerprint).and_then(|content| {
            let entry = parse(&content).ok_or(Failure::InvalidKeybox)?;
            // Recheck the path after parsing too, so a renamed/deleted file is not installed.
            if self::fingerprint(path)? != fingerprint {
                return Err(Failure::ChangedWhileReading);
            }
            Ok(entry)
        });
        match result {
            Ok(entry) => {
                self.entry = Some(entry);
                self.retry_at = None;
                self.result(now, true, None)
            }
            Err(failure) => self.result(now, false, Some(failure)),
        }
    }

    fn result(&mut self, now: Instant, loaded: bool, failure: Option<Failure>) -> Lookup<'_, T> {
        // Keep the limit across failures, metadata changes and recoveries, not just identical
        // errors; a flapping file must not turn every request into a warning.
        let diagnostic = failure.filter(|_| {
            self.last_diagnostic
                .is_none_or(|last| now.saturating_duration_since(last) >= DIAGNOSTIC_INTERVAL)
        });
        if diagnostic.is_some() {
            self.last_diagnostic = Some(now);
        }
        Lookup { entry: self.entry.as_ref(), loaded, diagnostic }
    }
}

const MAX_BYTES: u64 = 800_000;

fn fingerprint(path: &Path) -> Result<Fingerprint, Failure> {
    let metadata = fs::symlink_metadata(path).map_err(|error| Failure::io("lstat", error))?;
    if !metadata.is_file() {
        return Err(Failure::NotRegularFile);
    }
    if metadata.len() > MAX_BYTES {
        return Err(Failure::InvalidKeybox);
    }
    Ok(Fingerprint::of(&metadata))
}

fn read_snapshot(path: &Path, expected: Fingerprint) -> Result<String, Failure> {
    let mut file = File::open(path).map_err(|error| Failure::io("open", error))?;
    let before = file.metadata().map_err(|error| Failure::io("fstat", error))?;
    if Fingerprint::of(&before) != expected {
        return Err(Failure::ChangedWhileReading);
    }
    let mut content = String::with_capacity(expected.size as usize);
    file.read_to_string(&mut content).map_err(|error| Failure::io("read", error))?;
    let after = file.metadata().map_err(|error| Failure::io("fstat", error))?;
    if Fingerprint::of(&after) != expected {
        return Err(Failure::ChangedWhileReading);
    }
    Ok(content)
}

#[cfg(test)]
#[path = "keybox_cache_tests.rs"]
mod tests;
