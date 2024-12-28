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
