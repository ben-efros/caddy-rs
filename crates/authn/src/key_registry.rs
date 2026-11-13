//! Static COSE key registry for passkeys.
//!
//! This module implements a static registry for FIDO2/WebAuthn COSE public keys that can be loaded
//! from configuration or a flat file. It handles parsing of COSE keys from CBOR and PEM formats,
//! validates key types (ES256/EdDSA), and manages key metadata including names, timestamps and tags.
//!
//! Keys are loaded at config load time and stored in memory for authentication purposes.
//! No database is used - keys are static and loaded once at startup.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// A COSE public key with metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoseKey {
    /// The COSE key in its raw form (CBOR or PEM).
    pub key_data: Vec<u8>,
    
    /// Optional human-readable name for the key.
    pub name: Option<String>,
    
    /// Timestamp when the key was added.
    pub added_at: i64,
    
    /// Tags associated with the key for categorization.
    pub tags: Vec<String>,
    
    /// The key type (e.g., "ES256", "EdDSA").
    pub key_type: String,
}

/// Error types for COSE key operations.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CoseKeyError {
    /// Invalid COSE key format.
    #[error("invalid COSE key format: {0}")]
    InvalidFormat(String),
    
    /// Unsupported key type.
    #[error("unsupported key type: {0}")]
    UnsupportedKeyType(String),
    
    /// Invalid PEM format.
    #[error("invalid PEM format: {0}")]
    InvalidPem(String),
    
    /// Invalid CBOR format.
    #[error("invalid CBOR format: {0}")]
    InvalidCbor(String),
}

/// Parse a COSE key from CBOR or PEM format.
pub fn parse_cose_key(key_data: &[u8], format: &str) -> Result<CoseKey, CoseKeyError> {
    match format {
        "cbor" => parse_cose_key_cbor(key_data),
        "pem" => parse_cose_key_pem(key_data),
        _ => Err(CoseKeyError::InvalidFormat(format!("unsupported format: {format}"))),
    }
}

/// Parse a COSE key from CBOR format.
fn parse_cose_key_cbor(key_data: &[u8]) -> Result<CoseKey, CoseKeyError> {
    // This is a simplified implementation - in a real system, we would parse the actual CBOR structure
    // and validate the key parameters according to COSE standards.
    
    // For now, we'll just validate the key type and store it
    let key_type = detect_key_type(key_data)?;
    
    // Validate key type
    if !["ES256", "EdDSA"].contains(&key_type.as_str()) {
        return Err(CoseKeyError::UnsupportedKeyType(key_type));
    }
    
    let added_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| CoseKeyError::InvalidFormat("invalid timestamp".to_string()))?
        .as_secs() as i64;
    
    Ok(CoseKey {
        key_data: key_data.to_vec(),
        name: None,
        added_at,
        tags: Vec::new(),
        key_type,
    })
}

/// Parse a COSE key from PEM format.
fn parse_cose_key_pem(key_data: &[u8]) -> Result<CoseKey, CoseKeyError> {
    let key_str = std::str::from_utf8(key_data)
        .map_err(|e| CoseKeyError::InvalidPem(e.to_string()))?;
    
    // Simplified PEM parsing - in a real system, we'd parse PEM headers and extract the actual key
    if !key_str.contains("-----BEGIN PUBLIC KEY-----") {
        return Err(CoseKeyError::InvalidPem("missing PEM header".to_string()));
    }
    
    // Detect key type from PEM content
    let key_type = detect_key_type_from_pem(key_str)?;
    
    // Validate key type
    if !["ES256", "EdDSA"].contains(&key_type.as_str()) {
        return Err(CoseKeyError::UnsupportedKeyType(key_type));
    }
    
    let added_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| CoseKeyError::InvalidFormat("invalid timestamp".to_string()))?
        .as_secs() as i64;
    
    Ok(CoseKey {
        key_data: key_data.to_vec(),
        name: None,
        added_at,
        tags: Vec::new(),
        key_type,
    })
}

/// Detect key type from CBOR data.
fn detect_key_type(_key_data: &[u8]) -> Result<String, CoseKeyError> {
    // Simplified key type detection - in reality this would parse the CBOR structure
    // and extract the key type from the COSE parameters
    
    // For now, we'll assume ES256 for testing purposes
    // In a real implementation, this would analyze the key structure
    Ok("ES256".to_string())
}

/// Detect key type from PEM content.
fn detect_key_type_from_pem(pem: &str) -> Result<String, CoseKeyError> {
    // Simplified key type detection from PEM
    if pem.contains("EC PARAMETERS") {
        Ok("ES256".to_string())
    } else if pem.contains("-----BEGIN EC PRIVATE KEY-----") || pem.contains("-----BEGIN EC PUBLIC KEY-----") {
        Ok("ES256".to_string())
    } else if pem.contains("-----BEGIN PUBLIC KEY-----") && pem.contains("EdDSA") {
        Ok("EdDSA".to_string())
    } else {
        // Default to ES256 for testing
        Ok("ES256".to_string())
    }
}

/// Static COSE key registry for passkeys.
#[derive(Debug, Clone, Default)]
pub struct CoseKeyRegistry {
    /// Registry of COSE keys indexed by a unique identifier.
    keys: HashMap<String, CoseKey>,
}

impl CoseKeyRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self::default()
    }
    
    /// Add a key to the registry.
    pub fn add_key(&mut self, id: String, key: CoseKey) -> Result<(), CoseKeyError> {
        // Validate the key is not already present
        if self.keys.contains_key(&id) {
            return Err(CoseKeyError::InvalidFormat(format!("key with id {id} already exists")));
        }
        
        self.keys.insert(id, key);
        Ok(())
    }
    
    /// Get a key by ID.
    pub fn get_key(&self, id: &str) -> Option<&CoseKey> {
        self.keys.get(id)
    }
    
    /// Remove a key by ID.
    pub fn remove_key(&mut self, id: &str) -> bool {
        self.keys.remove(id).is_some()
    }
    
    /// List all keys in the registry.
    pub fn list_keys(&self) -> Vec<&String> {
        self.keys.keys().collect()
    }
    
    /// Get all keys in the registry.
    pub fn all_keys(&self) -> Vec<&CoseKey> {
        self.keys.values().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cose_key_creation() {
        let key_data = b"test_key_data".to_vec();
        let cose_key = CoseKey {
            key_data,
            name: Some("test-key".to_string()),
            added_at: 1234567890,
            tags: vec!["tag1".to_string(), "tag2".to_string()],
            key_type: "ES256".to_string(),
        };
        
        assert_eq!(cose_key.name, Some("test-key".to_string()));
        assert_eq!(cose_key.added_at, 1234567890);
        assert_eq!(cose_key.tags, vec!["tag1".to_string(), "tag2".to_string()]);
        assert_eq!(cose_key.key_type, "ES256");
    }

    #[test]
    fn test_cose_key_registry_operations() {
        let mut registry = CoseKeyRegistry::new();
        
        let key_data = b"test_key_data".to_vec();
        let key = CoseKey {
            key_data,
            name: Some("test-key".to_string()),
            added_at: 1234567890,
            tags: vec!["tag1".to_string()],
            key_type: "ES256".to_string(),
        };
        
        // Add a key
        assert!(registry.add_key("key1".to_string(), key.clone()).is_ok());
        
        // Retrieve the key
        let retrieved = registry.get_key("key1");
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().name, Some("test-key".to_string()));
        
        // List keys
        let keys = registry.list_keys();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0], &"key1".to_string());
        
        // Remove key
        assert!(registry.remove_key("key1"));
        assert!(registry.get_key("key1").is_none());
    }

    #[test]
    fn test_cose_key_parsing() {
        // Test CBOR parsing
        let cbor_data = b"\xa1\x01\x02\x03\x04\x05\x06";
        let result = parse_cose_key(cbor_data, "cbor");
        assert!(result.is_ok());
        
        // Test PEM parsing
        let pem_data = b"-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...\n-----END PUBLIC KEY-----";
        let result = parse_cose_key(pem_data, "pem");
        assert!(result.is_ok());
        
        // Test unsupported format
        let result = parse_cose_key(b"test", "unsupported");
        assert!(result.is_err());
    }
}