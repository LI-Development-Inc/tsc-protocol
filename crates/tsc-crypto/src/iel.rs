//! Identifier Event Log (IEL) persistence (RFC-002 §3, ADR-009).
//!
//! The IEL is a newline-delimited JSON file at
//! `$XDG_DATA_HOME/tsc/iel.jsonl`.
//!
//! Each line is one [`KeyEvent`] serialized as JSON.  The file is append-only:
//! new events are written to the end; reads load the entire file.

use std::io::{BufRead, Write};
use std::path::PathBuf;

use crate::{keri::KeyEvent, CryptoError};

/// Returns the IEL file path: `$XDG_DATA_HOME/tsc/iel.jsonl`.
pub fn iel_path() -> Result<PathBuf, CryptoError> {
    let base = dirs::data_dir()
        .ok_or_else(|| CryptoError::Io("XDG_DATA_HOME unavailable".into()))?;
    let dir = base.join("tsc");
    std::fs::create_dir_all(&dir)
        .map_err(|e| CryptoError::Io(e.to_string()))?;
    Ok(dir.join("iel.jsonl"))
}

/// Writes the entire IEL to disk, overwriting any existing file.
///
/// Called after `init` / `recover` to persist the single-event inception log.
pub fn save_iel(log: &[KeyEvent]) -> Result<(), CryptoError> {
    let path = iel_path()?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&path)
        .map_err(|e| CryptoError::Io(e.to_string()))?;

    for event in log {
        let line = serde_json::to_string(event)
            .map_err(|e| CryptoError::Serialization(e.to_string()))?;
        writeln!(file, "{}", line)
            .map_err(|e| CryptoError::Io(e.to_string()))?;
    }
    Ok(())
}

/// Appends a single new event to the IEL file.
///
/// Used by `rotate_key` to extend the log without rewriting the whole file.
pub fn append_event(event: &KeyEvent) -> Result<(), CryptoError> {
    let path = iel_path()?;
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(&path)
        .map_err(|e| CryptoError::Io(e.to_string()))?;

    let line = serde_json::to_string(event)
        .map_err(|e| CryptoError::Serialization(e.to_string()))?;
    writeln!(file, "{}", line)
        .map_err(|e| CryptoError::Io(e.to_string()))?;
    Ok(())
}

/// Loads and parses the IEL from disk.
///
/// Returns an empty `Vec` (not an error) if the file does not exist yet —
/// callers rebuilding from vault should call `save_iel` after `Persona::from_seed`.
pub fn load_iel() -> Result<Vec<KeyEvent>, CryptoError> {
    let path = match iel_path() {
        Ok(p)  => p,
        Err(e) => return Err(e),
    };

    if !path.exists() {
        return Ok(vec![]);
    }

    let file = std::fs::File::open(&path)
        .map_err(|e| CryptoError::Io(e.to_string()))?;

    let mut log = Vec::new();
    for (lineno, line) in std::io::BufReader::new(file).lines().enumerate() {
        let text = line.map_err(|e| CryptoError::Io(e.to_string()))?;
        if text.trim().is_empty() { continue; }
        let event: KeyEvent = serde_json::from_str(&text)
            .map_err(|e| CryptoError::Serialization(
                format!("IEL line {}: {}", lineno + 1, e)
            ))?;
        log.push(event);
    }
    Ok(log)
}
