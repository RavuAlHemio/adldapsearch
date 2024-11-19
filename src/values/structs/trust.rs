use bitflags::bitflags;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::values::{structs::security::Sid, utc_ticks_relative_to_1601};


// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/96e44639-eb3e-48c3-a565-1d67cceb3bad
#[derive(Clone, Debug, Deserialize, Hash, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct TrustForestTrustInfo {
    pub version: u32,
    // record_count: u32,
    pub records: Vec<TrustInfoRecord>,
}
impl TrustForestTrustInfo {
    pub fn try_from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 8 {
            return None;
        }
        let version = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
        let record_count: usize = u32::from_le_bytes(bytes[4..8].try_into().unwrap()).try_into().unwrap();
        let mut position = 8;
        let mut records = Vec::with_capacity(record_count);
        for _ in 0..record_count {
            let record_length = TrustInfoRecord::get_length(&bytes[position..])?;
            let record = TrustInfoRecord::try_from_bytes(&bytes[position..position+record_length])?;
            position += record_length;
            records.push(record);
        }
        Some(Self {
            version,
            records,
        })
    }
}

// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/66387402-cb2b-490c-bf2a-f4ad687397e4
#[derive(Clone, Debug, Deserialize, Hash, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub enum TrustInfoRecord {
    TopLevelName(TopLevelNameTrustRecord),
    TopLevelNameEx(TopLevelNameTrustRecord),
    DomainInfo(DomainInfoTrustRecord),
    BinaryInfo(BinaryInfoTrustRecord),
    ScannerInfo(ScannerInfoTrustRecord),
    Other(OtherTrustRecord),
}
impl TrustInfoRecord {
    pub fn get_length(bytes: &[u8]) -> Option<usize> {
        if bytes.len() < 4 {
            return None;
        }
        let length: usize = u32::from_le_bytes(bytes[0..4].try_into().unwrap()).try_into().unwrap();
        // length does not include the length field itself; change that
        Some(length + 4)
    }

    fn try_header_from_bytes(bytes: &[u8]) -> Option<(usize, u32, i64, u8)> {
        if bytes.len() < 17 {
            return None;
        }
        let length: usize = u32::from_le_bytes(bytes[0..4].try_into().unwrap()).try_into().unwrap();
        let flags = u32::from_le_bytes(bytes[4..8].try_into().unwrap());

        // middle-endian timestamp...
        let timestamp_upper: i64 = i32::from_le_bytes(bytes[8..12].try_into().unwrap()).into();
        let timestamp_lower: i64 = u32::from_le_bytes(bytes[12..16].try_into().unwrap()).into();
        let timestamp = (timestamp_upper << 32) | timestamp_lower;

        let record_type = bytes[16];
        Some((length, flags, timestamp, record_type))
    }

    pub fn try_from_bytes(bytes: &[u8]) -> Option<Self> {
        let (length, flags, timestamp_ticks, record_type) = Self::try_header_from_bytes(bytes)?;
        if length != bytes.len() - 4 {
            return None;
        }
        let timestamp = utc_ticks_relative_to_1601(timestamp_ticks);

        match record_type {
            0x00|0x01 => {
                if bytes.len() < 21 {
                    return None;
                }
                let name_length: usize = u32::from_le_bytes(bytes[17..21].try_into().unwrap()).try_into().unwrap();
                if bytes.len() != 21 + name_length {
                    return None;
                }
                let name_vec = bytes[21..21+name_length].to_vec();
                let name = String::from_utf8(name_vec).ok()?;
                let data = TopLevelNameTrustRecord {
                    flags: NameFlags::from_bits_retain(flags),
                    timestamp,
                    name,
                };
                match record_type {
                    0x00 => Some(Self::TopLevelName(data)),
                    0x01 => Some(Self::TopLevelNameEx(data)),
                    _ => unreachable!(),
                }
            },
            0x02 => {
                let mut position = 17;

                if position + 4 > bytes.len() {
                    return None;
                }
                let sid_length: usize = u32::from_le_bytes(bytes[position..position+4].try_into().unwrap()).try_into().unwrap();
                position += 4;

                if position + sid_length > bytes.len() {
                    return None;
                }
                let sid_slice = &bytes[position..position+sid_length];
                let sid = Sid::try_from_bytes(sid_slice)?;
                position += sid_length;

                if position + 4 > bytes.len() {
                    return None;
                }
                let dns_name_length: usize = u32::from_le_bytes(bytes[position..position+4].try_into().unwrap()).try_into().unwrap();
                position += 4;

                if position + dns_name_length > bytes.len() {
                    return None;
                }
                let dns_name_vec = bytes[position..position+dns_name_length].to_vec();
                let dns_name = String::from_utf8(dns_name_vec).ok()?;
                position += dns_name_length;

                if position + 4 > bytes.len() {
                    return None;
                }
                let netbios_name_length: usize = u32::from_le_bytes(bytes[position..position+4].try_into().unwrap()).try_into().unwrap();
                position += 4;

                if position + netbios_name_length > bytes.len() {
                    return None;
                }
                let netbios_name_vec = bytes[position..position+netbios_name_length].to_vec();
                let netbios_name = String::from_utf8(netbios_name_vec).ok()?;
                position += netbios_name_length;

                if position != bytes.len() {
                    // trailing bytes
                    return None;
                }

                Some(Self::DomainInfo(DomainInfoTrustRecord {
                    flags: DomainFlags::from_bits_retain(flags),
                    timestamp,
                    sid,
                    dns_name,
                    netbios_name,
                }))
            },
            0x04 => {
                let mut position = 17;

                if position + 4 > bytes.len() {
                    return None;
                }
                let binary_data_length: usize = u32::from_le_bytes(bytes[position..position+4].try_into().unwrap()).try_into().unwrap();
                position += 4;

                if position + binary_data_length > bytes.len() {
                    // value doesn't fit
                    return None;
                }

                if position + 4 > bytes.len() {
                    return None;
                }
                let sub_record_type = u32::from_le_bytes(bytes[position..position+4].try_into().unwrap());
                position += 4;

                if position + 1 > bytes.len() {
                    return None;
                }
                let sid_length: usize = bytes[position].into();
                position += 1;

                let sid = if sid_length > 0 {
                    if position + sid_length > bytes.len() {
                        return None;
                    }
                    let sid_slice = &bytes[position..position+sid_length];
                    let sid = Sid::try_from_bytes(sid_slice)?;
                    position += sid_length;
                    Some(sid)
                } else {
                    None
                };

                if position + 4 > bytes.len() {
                    return None;
                }
                let dns_name_length: usize = u32::from_le_bytes(bytes[position..position+4].try_into().unwrap()).try_into().unwrap();
                position += 4;

                if position + dns_name_length > bytes.len() {
                    return None;
                }
                let dns_name_vec = bytes[position..position+dns_name_length].to_vec();
                let dns_name = String::from_utf8(dns_name_vec).ok()?;
                position += dns_name_length;

                if position + 4 > bytes.len() {
                    return None;
                }
                let netbios_name_length: usize = u32::from_le_bytes(bytes[position..position+4].try_into().unwrap()).try_into().unwrap();
                position += 4;

                if position + netbios_name_length > bytes.len() {
                    return None;
                }
                let netbios_name_vec = bytes[position..position+netbios_name_length].to_vec();
                let netbios_name = String::from_utf8(netbios_name_vec).ok()?;
                position += netbios_name_length;

                if position != bytes.len() {
                    // trailing bytes
                    return None;
                }

                Some(Self::ScannerInfo(ScannerInfoTrustRecord {
                    flags,
                    timestamp,
                    sub_record_type,
                    sid,
                    dns_name,
                    netbios_name,
                }))
            },
            other => {
                let mut position = 17;

                if position + 4 > bytes.len() {
                    return None;
                }
                let full_data_length: usize = u32::from_le_bytes(bytes[position..position+4].try_into().unwrap()).try_into().unwrap();
                if full_data_length < 4 {
                    // we need at least the sub_record_type
                    return None;
                }
                position += 4;

                if position + full_data_length > bytes.len() {
                    // value doesn't fit
                    return None;
                }

                if position + 4 > bytes.len() {
                    return None;
                }
                let sub_record_type = u32::from_le_bytes(bytes[position..position+4].try_into().unwrap());
                position += 4;

                let binary_data_length = full_data_length - 4;

                let binary_data = bytes[position..position+binary_data_length].to_vec();
                position += binary_data_length;

                if position != bytes.len() {
                    // trailing bytes
                    return None;
                }

                let binary_info = BinaryInfoTrustRecord {
                    flags,
                    timestamp,
                    sub_record_type,
                    binary_data,
                };
                match other {
                    0x03 => {
                        Some(Self::BinaryInfo(binary_info))
                    },
                    different => {
                        Some(Self::Other(OtherTrustRecord {
                            record_type: different,
                            binary_info,
                        }))
                    },
                }
            },
        }
    }
}

// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/66387402-cb2b-490c-bf2a-f4ad687397e4
bitflags! {
    #[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
    pub struct NameFlags : u32 {
        const DisabledNew = 0x0000_0001;
        const DisabledAdmin = 0x0000_0002;
        const DisabledConflict = 0x0000_0004;
    }
}

// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/66387402-cb2b-490c-bf2a-f4ad687397e4
bitflags! {
    #[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
    pub struct DomainFlags : u32 {
        const SidDisabledAdmin = 0x0000_0001;
        const SidDisabledConflict = 0x0000_0002;
        const NetBiosDisabledAdmin = 0x0000_0004;
        const NetBiosDisabledConflict = 0x0000_0008;
    }
}

// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/66387402-cb2b-490c-bf2a-f4ad687397e4
#[derive(Clone, Debug, Deserialize, Hash, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct TopLevelNameTrustRecord {
    // record_len: u32,
    pub flags: NameFlags, // u32
    pub timestamp: DateTime<Utc>, // u64(FILETIME)
    // record_type: u8
    // -
    // name_len: u32,
    pub name: String, // [u8; name_len]
}

// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/66387402-cb2b-490c-bf2a-f4ad687397e4
#[derive(Clone, Debug, Deserialize, Hash, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct DomainInfoTrustRecord {
    // record_len: u32,
    pub flags: DomainFlags, // u32
    pub timestamp: DateTime<Utc>, // u64(FILETIME)
    // record_type: u8
    // -
    // sid_len: u32
    pub sid: Sid, // [u8; sid_len]
    // dns_name_len: u32
    pub dns_name: String, // [u8; dns_name_len]
    // netbios_name_len: u32
    pub netbios_name: String, // [u8; netbios_name_len]
}

// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/66387402-cb2b-490c-bf2a-f4ad687397e4
#[derive(Clone, Debug, Deserialize, Hash, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct BinaryInfoTrustRecord {
    // record_len: u32,
    pub flags: u32,
    pub timestamp: DateTime<Utc>, // u64(FILETIME)
    // record_type: u8
    // -
    // binary_data_len: u32
    pub sub_record_type: u32,
    pub binary_data: Vec<u8>, // [u8; binary_data_len]
}

// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/66387402-cb2b-490c-bf2a-f4ad687397e4
#[derive(Clone, Debug, Deserialize, Hash, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct OtherTrustRecord {
    pub record_type: u8,
    pub binary_info: BinaryInfoTrustRecord,
}

// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/66387402-cb2b-490c-bf2a-f4ad687397e4
#[derive(Clone, Debug, Deserialize, Hash, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ScannerInfoTrustRecord {
    // record_len: u32,
    pub flags: u32,
    pub timestamp: DateTime<Utc>, // u64(FILETIME)
    // record_type: u8
    // -
    // record_len: u32,
    pub sub_record_type: u32,
    // sid_len: u32
    pub sid: Option<Sid>, // [u8; sid_len]
    // dns_name_len: u32
    pub dns_name: String, // [u8; dns_name_len]
    // netbios_name_len: u32
    pub netbios_name: String, // [u8; netbios_name_len]
}


#[cfg(test)]
mod tests {
    use super::{TrustForestTrustInfo, TrustInfoRecord};

    #[test]
    fn test_forest_trust_info() {
        const DATA: [u8; 185] = [
            0x01, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xEB, 0x53, 0xBF, 0x01, 0x80, 0xA9, 0xD4, 0x24, 0x00, 0x13, 0x00, 0x00, 0x00, 0x61, 0x64, 0x74,
            0x65, 0x73, 0x74, 0x73, 0x2E, 0x65, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65, 0x2E, 0x63, 0x6F, 0x6D,
            0x4A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xEB, 0x53, 0xBF, 0x01, 0x80, 0xA9, 0xD4, 0x24,
            0x02, 0x18, 0x00, 0x00, 0x00, 0x01, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x15, 0x00, 0x00,
            0x00, 0x4D, 0xE6, 0x40, 0xBB, 0xD6, 0x87, 0x27, 0x23, 0xB7, 0x60, 0x93, 0x1B, 0x13, 0x00, 0x00,
            0x00, 0x61, 0x64, 0x74, 0x65, 0x73, 0x74, 0x73, 0x2E, 0x65, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65,
            0x2E, 0x63, 0x6F, 0x6D, 0x06, 0x00, 0x00, 0x00, 0x41, 0x44, 0x54, 0x45, 0x53, 0x54, 0x37, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xEB, 0x53, 0xBF, 0x01, 0x80, 0xA9, 0xD4, 0x24, 0x04, 0x26,
            0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x13, 0x00, 0x00, 0x00, 0x61, 0x64, 0x74, 0x65,
            0x73, 0x74, 0x73, 0x2E, 0x65, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65, 0x2E, 0x63, 0x6F, 0x6D, 0x06,
            0x00, 0x00, 0x00, 0x41, 0x44, 0x54, 0x45, 0x53, 0x54,
        ];
        let trust_info = TrustForestTrustInfo::try_from_bytes(&DATA).unwrap();
        assert_eq!(trust_info.version, 1);
        assert_eq!(trust_info.records.len(), 3);
        if let TrustInfoRecord::TopLevelName(tln) = &trust_info.records[0] {
            assert_eq!(tln.flags.bits(), 0);
            assert_eq!(tln.timestamp.timestamp(), 946684799);
            assert_eq!(tln.name, "adtests.example.com");
        } else {
            panic!("records[0] is not a TopLevelName record");
        }
        if let TrustInfoRecord::DomainInfo(di) = &trust_info.records[1] {
            assert_eq!(di.flags.bits(), 0);
            assert_eq!(di.timestamp.timestamp(), 946684799);
            assert_eq!(di.sid.version, 1);
            assert_eq!(di.sid.authority, 5);
            assert_eq!(di.sid.subauthorities.len(), 4);
            assert_eq!(di.sid.subauthorities[0], 21);
            assert_eq!(di.sid.subauthorities[1], 3141592653);
            assert_eq!(di.sid.subauthorities[2], 589793238);
            assert_eq!(di.sid.subauthorities[3], 462643383);
            assert_eq!(di.dns_name, "adtests.example.com");
            assert_eq!(di.netbios_name, "ADTEST");
        } else {
            panic!("records[1] is not a DomainInfo record");
        }
        if let TrustInfoRecord::ScannerInfo(si) = &trust_info.records[2] {
            assert_eq!(si.flags, 0);
            assert_eq!(si.timestamp.timestamp(), 946684799);
            assert_eq!(si.sid, None);
            assert_eq!(si.dns_name, "adtests.example.com");
            assert_eq!(si.netbios_name, "ADTEST");
        } else {
            panic!("records[2] is not a ScannerInfo record");
        }
    }
}
