use std::sync::LazyLock;

use bitflags::bitflags;
use chrono::{DateTime, Utc};
use from_to_repr::from_to_other;
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::values::utc_ticks_relative_to_1601;


static BINARY_AND_DN_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(concat!(
    "^",
    "B",
    ":",
    "(?P<hexlength>[0-9]+)",
    ":",
    "(?P<hexstring>(?:[0-9A-F][0-9A-F])+)",
    ":",
    "(?P<dn>.*)",
    "$",
)).expect("failed to compile binary-and-DN regex"));


// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/f3f01e95-6d0c-4fe6-8b43-d585167658fa
#[derive(Clone, Debug, Deserialize, Hash, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct KeyCredentialLinkBlob {
    pub version: u32,
    pub entries: Vec<KeyCredentialLinkEntry>,
    pub dn: String,
}
impl KeyCredentialLinkBlob {
    pub fn try_from_str(string: &str) -> Option<Self> {
        let caps = BINARY_AND_DN_RE.captures(string)?;
        let hex_length: usize = caps
            .name("hexlength").expect("failed to capture hexlength")
            .as_str()
            .parse().ok()?;
        let hex_string = caps
            .name("hexstring").expect("failed to capture hexstring")
            .as_str();
        let dn = caps
            .name("dn").expect("failed to capture dn")
            .as_str();
        if hex_string.len() != hex_length {
            return None;
        }

        let mut bytes = Vec::with_capacity(hex_length / 2);
        // the regex has ensured that the hex string only contains single-byte characters
        for i in (0..hex_length).step_by(2) {
            let byte = u8::from_str_radix(&hex_string[i..i+2], 16).unwrap();
            bytes.push(byte);
        }

        if bytes.len() < 4 {
            return None;
        }

        let version = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
        if version != 0x00000200 {
            // structure might have changed
            return None;
        }

        let mut i = 4;
        let mut entries = Vec::new();
        while i < bytes.len() {
            let entry_length = KeyCredentialLinkEntry::get_length(&bytes[i..])?;
            let entry = KeyCredentialLinkEntry::try_from_bytes(&bytes[i..i+entry_length])?;
            i += entry_length;
            entries.push(entry);
        }

        Some(Self {
            version,
            entries,
            dn: dn.to_owned(),
        })
    }
}

// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/7dd677bd-9315-403c-8104-b6270350139e
// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a99409ea-4982-4f72-b7ef-8596013a36c7
#[derive(Clone, Debug, Deserialize, Hash, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub enum KeyCredentialLinkEntry {
    // data_length: u16,
    // identifier: u8,
    // data: [u8; data_length],

    KeyId(Vec<u8>),
    KeyHash(Vec<u8>),
    KeyMaterial(Vec<u8>),
    KeyUsage(KeyUsageType),
    KeySource(KeySourceType),
    DeviceId(Vec<u8>),
    CustomKeyInformationShort(CustomKeyInformationShort),
    CustomKeyInformationLong(CustomKeyInformationLong),
    KeyApproximateLastLogonTimeStamp(DateTime<Utc>),
    KeyCreationTime(DateTime<Utc>),
    Other { identifier: u8, data: Vec<u8> },
}
impl KeyCredentialLinkEntry {
    pub fn get_length(bytes: &[u8]) -> Option<usize> {
        if bytes.len() < 3 {
            return None;
        }
        let value_length = u16::from_le_bytes(bytes[0..2].try_into().unwrap());
        let value_length_usize: usize = value_length.into();
        let total_length = 3 + value_length_usize;
        if bytes.len() >= total_length {
            Some(total_length)
        } else {
            None
        }
    }

    pub fn try_from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 3 {
            return None;
        }

        let value_length = u16::from_le_bytes(bytes[0..2].try_into().unwrap());
        let value_length_usize: usize = value_length.into();
        if bytes.len() != 3 + value_length_usize {
            return None;
        }

        let identifier = bytes[2];
        let data_slice = &bytes[3..];
        match identifier {
            0x01 => Some(Self::KeyId(data_slice.to_owned())),
            0x02 => Some(Self::KeyHash(data_slice.to_owned())),
            0x03 => Some(Self::KeyMaterial(data_slice.to_owned())),
            0x04 => {
                if data_slice.len() != 1 {
                    None
                } else {
                    Some(Self::KeyUsage(KeyUsageType::from_base_type(data_slice[0])))
                }
            },
            0x05 => {
                if data_slice.len() != 1 {
                    None
                } else {
                    Some(Self::KeySource(KeySourceType::from_base_type(data_slice[0])))
                }
            },
            0x06 => Some(Self::DeviceId(data_slice.to_owned())),
            0x07 => {
                // custom key information
                if data_slice.len() < 2 {
                    return None;
                }
                let version = data_slice[0];
                let flags = CkiFlags::from_bits_retain(data_slice[1]);
                if data_slice.len() == 2 {
                    Some(Self::CustomKeyInformationShort(CustomKeyInformationShort {
                        version,
                        flags,
                    }))
                } else {
                    let volume_type = VolumeType::from_base_type(data_slice[2]);

                    let supports_notification = data_slice.get(3).copied()
                        .map(|b| Boolean8::from_base_type(b));
                    let fek_key_version = data_slice.get(4).copied();
                    let key_strength = data_slice.get(5).copied()
                        .map(|b| KeyStrength::from_base_type(b));
                    let reserved_length = (data_slice.len() - 6).min(10);
                    let reserved = data_slice[6..6+reserved_length].to_vec();
                    let encoded_extended_cki = if data_slice.len() > 17 {
                        let extended_version = data_slice[16];
                        let extended_size = data_slice[17];
                        let extended_size_usize: usize = extended_size.into();

                        if data_slice.len() != 18 + extended_size_usize {
                            None
                        } else {
                            let extended_data = data_slice[18..].to_vec();
                            Some(EncodedExtendedCki {
                                version: extended_version,
                                cbor_data: extended_data,
                            })
                        }
                    } else {
                        None
                    };
                    Some(Self::CustomKeyInformationLong(CustomKeyInformationLong {
                        version,
                        flags,
                        volume_type,
                        supports_notification,
                        fek_key_version,
                        key_strength,
                        reserved,
                        encoded_extended_cki,
                    }))
                }
            },
            0x08|0x09 => {
                if data_slice.len() != 8 {
                    None
                } else {
                    let timestamp = utc_ticks_relative_to_1601(i64::from_le_bytes(data_slice.try_into().unwrap()));
                    Some(match identifier {
                        0x08 => Self::KeyApproximateLastLogonTimeStamp(timestamp),
                        0x09 => Self::KeyCreationTime(timestamp),
                        _ => unreachable!(),
                    })
                }
            },
            other => Some(Self::Other { identifier: other, data: data_slice.to_owned() }),
        }
    }
}

// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/d4b9b239-dbe8-4475-b6f9-745612c64ed0
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[from_to_other(base_type = u8, derive_compare = "as_int")]
pub enum KeyUsageType {
    Ngc = 0x01,
    Fido = 0x07,
    Fek = 0x08,
    Other(u8),
}

// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/d4b9b239-dbe8-4475-b6f9-745612c64ed0
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[from_to_other(base_type = u8, derive_compare = "as_int")]
pub enum KeySourceType {
    Ad = 0x00,
    Other(u8),
}

// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/701a55dc-d062-4032-a2da-dbdfc384c8cf
// (introductory note)
#[derive(Clone, Debug, Deserialize, Hash, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct CustomKeyInformationShort {
    pub version: u8,
    pub flags: CkiFlags,
}

// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/701a55dc-d062-4032-a2da-dbdfc384c8cf
#[derive(Clone, Debug, Deserialize, Hash, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct CustomKeyInformationLong {
    pub version: u8,
    pub flags: CkiFlags,
    pub volume_type: VolumeType,
    pub supports_notification: Option<Boolean8>,
    pub fek_key_version: Option<u8>,
    pub key_strength: Option<KeyStrength>,
    pub reserved: Vec<u8>,
    pub encoded_extended_cki: Option<EncodedExtendedCki>,
}

// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/b2c0cb9b-e49e-4907-9235-f9fd7eee8c13
#[derive(Clone, Debug, Deserialize, Hash, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct EncodedExtendedCki {
    pub version: u8,
    // size: u8,
    pub cbor_data: Vec<u8>, // [u8; size]
}


// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/701a55dc-d062-4032-a2da-dbdfc384c8cf
bitflags! {
    #[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
    pub struct CkiFlags : u8 {
        const Attestation = 0b0000_0001;
        const MfaNotUsed = 0b0000_0010;
    }
}

// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/701a55dc-d062-4032-a2da-dbdfc384c8cf
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[from_to_other(base_type = u8, derive_compare = "as_int")]
pub enum VolumeType {
    None = 0x00,
    OperatingSystem = 0x01,
    FixedData = 0x02,
    RemovableData = 0x03,
    Other(u8),
}

// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/701a55dc-d062-4032-a2da-dbdfc384c8cf
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[from_to_other(base_type = u8, derive_compare = "as_int")]
pub enum Boolean8 {
    False = 0x00,
    True = 0x01,
    Other(u8),
}

// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/701a55dc-d062-4032-a2da-dbdfc384c8cf
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[from_to_other(base_type = u8, derive_compare = "as_int")]
pub enum KeyStrength {
    Unknown = 0x00,
    Weak = 0x01,
    Normal = 0x02,
    Other(u8),
}
