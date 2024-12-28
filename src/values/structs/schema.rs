use uuid::Uuid;

use crate::oid_prefix::OidPrefix;


#[derive(Clone, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PrefixMap {
    // num_entries: u32,
    // num_bytes: u32,
    prefixes: Vec<PrefixEntry>, // [PrefixEntry; num_entries]
}
impl PrefixMap {
    pub fn try_from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 8 {
            return None;
        }

        let num_entries = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
        let num_bytes = u32::from_le_bytes(bytes[4..8].try_into().unwrap());

        let num_bytes_usize: usize = num_bytes.try_into().unwrap();
        if num_bytes_usize != bytes.len() {
            // format might have changed; don't risk it
            return None;
        }

        let num_entries_usize: usize = num_entries.try_into().unwrap();
        let mut prefixes = Vec::with_capacity(num_entries_usize);
        let mut i = 8;
        for _ in 0..num_entries {
            if i + 4 > bytes.len() {
                return None;
            }

            let db_prefix = u16::from_le_bytes(bytes[i..i+2].try_into().unwrap());
            let ber_len = u16::from_le_bytes(bytes[i+2..i+4].try_into().unwrap());
            let ber_len_usize: usize = ber_len.into();
            i += 4;

            if i + ber_len_usize > bytes.len() {
                return None;
            }
            let ber_slice = &bytes[i..i+ber_len_usize];
            let oid_prefix = OidPrefix::from_ber_bytes(ber_slice);
            i += ber_len_usize;

            prefixes.push(PrefixEntry {
                db_prefix,
                oid_prefix,
            });
        }

        Some(Self {
            prefixes,
        })
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PrefixEntry {
    pub db_prefix: u16,
    // ber_prefix_length: u16,
    pub oid_prefix: OidPrefix, // [u8; ber_prefix_length]
}

#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SchemaInfo {
    pub identifier: u8,
    pub schema_version: u32,
    pub last_updater_invocation_id: Uuid,
}
impl SchemaInfo {
    pub fn try_from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 21 {
            return None;
        }

        let identifier = bytes[0];
        if identifier != 0xFF {
            // format might have changed; don't risk it
            return None;
        }

        // big endian!
        let schema_version = u32::from_be_bytes(bytes[1..5].try_into().unwrap());

        // little endian again
        let last_updater_invocation_id = Uuid::from_bytes_le(bytes[5..21].try_into().unwrap());

        Some(Self {
            identifier,
            schema_version,
            last_updater_invocation_id,
        })
    }
}
