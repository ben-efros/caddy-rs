//! Tests for NPM database import functionality.

use std::collections::BTreeMap;

use super::*;
use crate::npm_db::{import_from_npm_db, NpmDbError};

#[test]
fn npm_db_import_requires_online_dependency() {
    // This test verifies that the offline blocker is properly documented
    // The actual database import functionality cannot be tested offline
    // because rusqlite dependency is not available
    
    let result = import_from_npm_db("/fake/db.sqlite", &BTreeMap::new());
    assert!(result.is_err());
    let error = result.unwrap_err();
    assert!(matches!(error, NpmDbError::Database(_)));
    assert!(error.to_string().contains("rusqlite"));
    assert!(error.to_string().contains("offline"));
}

#[test]
fn npm_db_import_offline_blocker_documented() {
    // Verify that the offline blocker is clearly documented in the error message
    let result = import_from_npm_db("/some/path.db", &BTreeMap::new());
    let error_msg = result.unwrap_err().to_string();
    assert!(error_msg.contains("rusqlite"));
    assert!(error_msg.contains("offline"));
    assert!(error_msg.contains("dependency"));
}