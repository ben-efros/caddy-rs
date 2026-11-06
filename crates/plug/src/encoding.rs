//! Bounds-checked byte reader/writer for the stable ABI encodings.
//!
//! Encoding rules (part of the ABI, see the crate documentation):
//!
//! * every integer is little-endian and fixed width;
//! * byte strings and UTF-8 strings are a `u32` little-endian length followed by that many bytes;
//! * there is no padding and no implicit alignment;
//! * every decoder is bounds-checked and returns [`WireError`] instead of panicking;
//! * lengths that cannot fit the wire format are rejected with [`WireError::SizeOverflow`], and
//!   every length-limited field is checked against the caller's limit before allocation.

use crate::error::WireError;

/// Cursor over an ABI-encoded byte slice.
#[derive(Debug, Clone)]
pub struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    /// Start reading at the beginning of `bytes`.
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    /// Current byte offset.
    pub fn position(&self) -> usize {
        self.position
    }

    /// Bytes not yet consumed.
    pub fn remaining(&self) -> usize {
        self.bytes.len() - self.position
    }

    /// Raw bytes consumed on the wire so far.
    pub fn consumed(&self) -> &'a [u8] {
        &self.bytes[..self.position]
    }

    /// Take exactly `len` bytes.
    pub fn take(&mut self, len: usize) -> Result<&'a [u8], WireError> {
        if len > self.remaining() {
            return Err(WireError::UnexpectedEof {
                offset: self.position,
                needed: len,
                remaining: self.remaining(),
            });
        }
        let start = self.position;
        self.position += len;
        Ok(&self.bytes[start..self.position])
    }

    /// Read one byte.
    pub fn u8(&mut self) -> Result<u8, WireError> {
        Ok(self.take(1)?[0])
    }

    /// Read a little-endian `u16`.
    pub fn u16(&mut self) -> Result<u16, WireError> {
        let bytes = self.take(2)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    /// Read a little-endian `u32`.
    pub fn u32(&mut self) -> Result<u32, WireError> {
        let bytes = self.take(4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    /// Read a little-endian `u64`.
    pub fn u64(&mut self) -> Result<u64, WireError> {
        let bytes = self.take(8)?;
        Ok(u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    /// Read a length-prefixed byte string, rejecting lengths above `max`.
    pub fn bytes(&mut self, field: &'static str, max: usize) -> Result<&'a [u8], WireError> {
        let len = self.u32()? as usize;
        if len > max {
            return Err(WireError::LimitExceeded { field, len, max });
        }
        self.take(len)
    }

    /// Read a length-prefixed UTF-8 string, rejecting lengths above `max`.
    pub fn string(&mut self, field: &'static str, max: usize) -> Result<String, WireError> {
        let offset = self.position;
        let bytes = self.bytes(field, max)?;
        String::from_utf8(bytes.to_vec()).map_err(|_| WireError::InvalidUtf8 { offset })
    }

    /// Require that the input is fully consumed.
    pub fn finish(self) -> Result<(), WireError> {
        if self.remaining() == 0 {
            Ok(())
        } else {
            Err(WireError::TrailingBytes {
                count: self.remaining(),
            })
        }
    }
}

/// Byte sink for ABI encodings; always succeeds, but length-prefixed writers report overflow.
#[derive(Debug, Default, Clone)]
pub struct Writer {
    bytes: Vec<u8>,
}

impl Writer {
    /// Create an empty writer.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a writer with a preallocated capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(capacity),
        }
    }

    /// Number of bytes written so far.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Whether nothing has been written.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Consume the writer and return the encoded bytes.
    pub fn into_vec(self) -> Vec<u8> {
        self.bytes
    }

    /// Append one byte.
    pub fn u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    /// Append a little-endian `u16`.
    pub fn u16(&mut self, value: u16) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    /// Append a little-endian `u32`.
    pub fn u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    /// Append a little-endian `u64`.
    pub fn u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    /// Append a length-prefixed byte string.
    pub fn bytes(&mut self, field: &'static str, value: &[u8]) -> Result<(), WireError> {
        let len = u32::try_from(value.len()).map_err(|_| WireError::SizeOverflow { field })?;
        self.u32(len);
        self.bytes.extend_from_slice(value);
        Ok(())
    }

    /// Append a length-prefixed UTF-8 string.
    pub fn string(&mut self, field: &'static str, value: &str) -> Result<(), WireError> {
        self.bytes(field, value.as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn primitives_round_trip_little_endian() {
        let mut writer = Writer::new();
        writer.u8(0xAB);
        writer.u16(0x1234);
        writer.u32(0xDEAD_BEEF);
        writer.u64(0x0102_0304_0506_0708);
        let encoded = writer.into_vec();
        assert_eq!(
            encoded,
            vec![
                0xAB, 0x34, 0x12, 0xEF, 0xBE, 0xAD, 0xDE, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02,
                0x01
            ]
        );
        let mut reader = Reader::new(&encoded);
        assert_eq!(reader.u8().expect("u8"), 0xAB);
        assert_eq!(reader.u16().expect("u16"), 0x1234);
        assert_eq!(reader.u32().expect("u32"), 0xDEAD_BEEF);
        assert_eq!(reader.u64().expect("u64"), 0x0102_0304_0506_0708);
        reader.finish().expect("fully consumed");
    }

    #[test]
    fn length_prefixed_fields_round_trip_and_enforce_limits() {
        let mut writer = Writer::new();
        writer.string("name", "plugin").expect("write string");
        writer.bytes("blob", &[1, 2, 3]).expect("write bytes");
        let encoded = writer.into_vec();
        let mut reader = Reader::new(&encoded);
        assert_eq!(reader.string("name", 16).expect("read string"), "plugin");
        assert_eq!(reader.bytes("blob", 4).expect("read bytes"), &[1, 2, 3]);
        reader.finish().expect("fully consumed");

        let mut reader = Reader::new(&encoded);
        assert_eq!(
            reader.string("name", 3),
            Err(WireError::LimitExceeded {
                field: "name",
                len: 6,
                max: 3
            })
        );
    }

    #[test]
    fn truncated_input_is_an_eof_error_not_a_panic() {
        let mut reader = Reader::new(&[1, 2]);
        assert_eq!(
            reader.u32(),
            Err(WireError::UnexpectedEof {
                offset: 0,
                needed: 4,
                remaining: 2
            })
        );
    }

    #[test]
    fn invalid_utf8_is_rejected_with_its_offset() {
        let encoded = [2, 0, 0, 0, 0xFF, 0xFE];
        let mut reader = Reader::new(&encoded);
        assert_eq!(
            reader.string("name", 16),
            Err(WireError::InvalidUtf8 { offset: 0 })
        );
        // The position offset is where the length prefix started.
        assert_eq!(reader.position(), 6);
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        let reader = Reader::new(&[1, 2, 3]);
        assert_eq!(reader.finish(), Err(WireError::TrailingBytes { count: 3 }));
    }
}
