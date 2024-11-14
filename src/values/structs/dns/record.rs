use std::net::{Ipv4Addr, Ipv6Addr};

use bitmask_enum::bitmask;
use chrono::{DateTime, Utc};
use from_to_repr::from_to_other;
use serde::{Deserialize, Serialize};

use crate::values::utc_ticks_relative_to_1601;



#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[from_to_other(base_type = u16, derive_compare = "as_int")]
pub enum Rank {
    CacheBit = 0b0000_0001,
    RootHint = 0b0000_1000,
    OutsideGlue = 0b0010_0000,
    CacheNaAdditional = 0b0011_0001,
    CacheNaAuthority = 0b0100_0001,
    CacheAAdditional = 0b0101_0001,
    CacheNaAnswer = 0b0110_0001,
    CacheAAuthority = 0b0111_0001,
    Glue = 0b1000_0000,
    NsGlue = 0b1000_0010,
    CacheAAnswer = 0b1100_0001,
    Zone = 0b1111_0000,
    Other(u16),
}


// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/ac793981-1c60-43b8-be59-cdbb5c4ecb8a
#[bitmask(u16)]
#[bitmask_config(vec_debug)]
#[derive(Deserialize, Serialize)]
pub enum Flags {
    ZoneRoot = 0x4000,
    AuthZoneRoot = 0x2000,
    CacheData = 0x8000,
    RecordWireFormat = 0x0010,
}


// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/ac793981-1c60-43b8-be59-cdbb5c4ecb8a
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct DnsRecord {
    // length: u16,
    // type: u16,
    pub rank: Rank, // u16
    pub flags: Flags, // u16
    pub serial: u32,
    pub ttl_seconds: u32,
    pub timestamp: u32,
    pub reserved: u32,
    pub data: Data,
}
impl DnsRecord {
    pub fn try_from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 24 {
            return None;
        }
        let data_length: usize = u16::from_le_bytes(bytes[0..2].try_into().unwrap()).into();
        if bytes.len() != 24 + data_length {
            // wrong length
            return None;
        }
        let kind = u16::from_le_bytes(bytes[2..4].try_into().unwrap()).into();
        let rank: Rank = u16::from_le_bytes(bytes[4..6].try_into().unwrap()).into();
        let flags: Flags = u16::from_le_bytes(bytes[6..8].try_into().unwrap()).into();
        let serial = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
        let ttl_seconds = u32::from_le_bytes(bytes[12..16].try_into().unwrap());
        let timestamp = u32::from_le_bytes(bytes[16..20].try_into().unwrap());
        let reserved = u32::from_le_bytes(bytes[20..24].try_into().unwrap());
        let data = Data::try_from_bytes(kind, &bytes[24..])?;
        Some(Self {
            rank,
            flags,
            serial,
            ttl_seconds,
            timestamp,
            reserved,
            data,
        })
    }
}


#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct TombstoneData {
    pub entombed_time: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct Ipv4AddrData {
    pub address: Ipv4Addr,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct NodeNameData {
    pub name: String,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct PreferenceNameData {
    pub preference: u16,
    pub name: String,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct StartOfAuthorityData {
    pub serial_number: u32,
    pub refresh: u32,
    pub retry: u32,
    pub expire: u32,
    pub minimum_ttl: u32,
    pub primary_server_name: String,
    pub zone_admin_email: String,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct BytesData {
    pub value: Vec<u8>,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct WellKnownServiceData {
    pub address: Ipv4Addr,
    pub ip_protocol: u8,
    pub service_bitmask: Vec<u8>,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct StringData {
    pub values: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct MailboxData {
    pub mailbox: String,
    pub error_mailbox: String,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct SignatureData {
    pub type_covered: u16,
    pub algorithm: u8,
    pub label_count: u8,
    pub original_ttl: u32,
    pub signature_expiration: u32,
    pub signature_inception: u32,
    pub key_tag: u16,
    pub signer: String,
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct KeyData {
    pub flags: u16,
    pub protocol: u8,
    pub algorithm: u8,
    pub key: Vec<u8>,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct Ipv6AddrData {
    pub address: Ipv6Addr,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct NextDomainData {
    pub record_type_mask_bytes: [u8; 16],
    pub next_name: String,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ServiceData {
    pub priority: u16,
    pub weight: u16,
    pub port: u16,
    pub target: String,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct AtmaData {
    pub format: u8,
    pub address: Vec<u8>,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct NamingAuthorityPointerData {
    pub order: u16,
    pub preference: u16,
    pub flags: String,
    pub service: String,
    pub substitution: String,
    pub replacement: String,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct DelegationSignerData {
    pub key_tag: u16,
    pub algorithm: u8,
    pub digest_type: u8,
    pub digest: Vec<u8>,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct NextSecureRecordData {
    pub signer: String,
    pub nsec_bitmap: Vec<u8>,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct NextSecureRecord3Data {
    pub algorithm: u8,
    pub flags: u8,
    pub iterations: u16,
    // salt_length: u8
    // next_hashed_owner_name_length: u8
    pub salt: Vec<u8>,
    pub next_hashed_owner_name: Vec<u8>,
    pub bitmaps: Vec<u8>,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct NextSecureRecord3ParameterData {
    pub algorithm: u8,
    pub flags: u8,
    pub iterations: u16,
    // salt_length: u8
    pub salt: Vec<u8>,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct TlsAssociationData {
    pub cert_usage: u8,
    pub selector: u8,
    pub matching_type: u8,
    pub certificate_association_data: Vec<u8>,
}

#[bitmask(u32)]
#[bitmask_config(vec_debug)]
#[derive(Deserialize, Serialize)]
pub enum WinsMappingFlag {
    Scope = 0x8000_0000,
    Local = 0x0001_0000,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct WinsData {
    pub mapping_flag: WinsMappingFlag, // u32
    pub lookup_timeout: u32,
    pub cache_timeout: u32,
    // wins_server_count: u32,
    pub wins_servers: Vec<Ipv4Addr>,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct WinsReverseData {
    pub mapping_flag: WinsMappingFlag, // u32
    pub lookup_timeout: u32,
    pub cache_timeout: u32,
    pub name_result_domain: String,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct OtherRecordData {
    pub record_type: u16,
    pub data: Vec<u8>,
}


#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum Data {
    Tombstone(TombstoneData), // 0x00
    Address(Ipv4AddrData), // 0x01
    NameServer(NodeNameData), // 0x02
    LegacyMailDestination(NodeNameData), // 0x03
    LegacyMailForwarder(NodeNameData), // 0x04
    CanonicalName(NodeNameData), // 0x05
    StartOfAuthority(StartOfAuthorityData), // 0x06
    LegacyMailbox(NodeNameData), // 0x07
    LegacyMailGroupMember(NodeNameData), // 0x08
    LegacyMailRename(NodeNameData), // 0x09
    Null(BytesData), // 0x0A
    LegacyWellKnownServices(WellKnownServiceData), // 0x0B
    Pointer(NodeNameData), // 0x0C
    HostInfo(StringData), // 0x0D
    LegacyMailInfo(MailboxData), // 0x0E
    MailExchanger(PreferenceNameData), // 0x0F
    Text(StringData), // 0x10
    LegacyResponsiblePerson(MailboxData), // 0x11
    Afsdb(PreferenceNameData), // 0x12
    X25(StringData), // 0x13
    Isdn(StringData), // 0x14
    LegacyRouteThrough(PreferenceNameData), // 0x15
    LegacySignature(SignatureData), // 0x18
    LegacyKey(KeyData), // 0x19
    Ipv6Address(Ipv6AddrData), // 0x1C
    LegacyNextDomain(NextDomainData), // 0x1E
    Service(ServiceData), // 0x21
    LegacyAtma(AtmaData), // 0x22
    NamingAuthorityPointer(NamingAuthorityPointerData), // 0x23
    DelegationName(NodeNameData), // 0x27
    DelegationSigner(DelegationSignerData), // 0x2B
    ResourceRecordSignature(SignatureData), // 0x2E
    NextSecureRecord(NextSecureRecordData), // 0x2F
    DnsKey(KeyData), // 0x30
    DhcpIdentifier(BytesData), // 0x31
    NextSecureRecord3(NextSecureRecord3Data), // 0x32
    NextSecureRecord3Parameters(NextSecureRecord3ParameterData), // 0x33
    TlsAssociation(TlsAssociationData), // 0x34
    WinsRecord(WinsData), // 0xFF01
    WinsReverseRecord(WinsReverseData), // 0xFF02
    Other(OtherRecordData),
}
impl Data {
    fn decode_string(bytes: &[u8]) -> Option<(String, usize)> {
        if bytes.len() < 1 {
            return None;
        }
        let string_length: usize = bytes[0].into();
        if 1 + string_length > bytes.len() {
            return None;
        }
        let string_vec = bytes[1..1+string_length].to_vec();
        let string = String::from_utf8(string_vec).ok()?;
        Some((string, 1 + string_length))
    }

    fn decode_count_name(bytes: &[u8]) -> Option<(String, usize)> {
        // total_length: u8,
        // label_count: u8,
        // labels: [Label; label_count]
        // where Label:
        //   label_length: u8,
        //   label: [u8; label_length]
        if bytes.len() < 2 {
            return None;
        }
        let string_length_including_nul: usize = bytes[0].into();
        let label_count: usize = bytes[1].into();
        if 2 + string_length_including_nul > bytes.len() {
            return None;
        }
        let label_slice = &bytes[2..2+string_length_including_nul];
        let mut position = 0;
        let mut ret = String::with_capacity(string_length_including_nul);
        for _ in 0..label_count {
            if position >= label_slice.len() {
                return None;
            }
            let label_length: usize = label_slice[position].into();
            position += 1;
            if position + label_length > label_slice.len() {
                return None;
            }
            let label_bytes = &label_slice[position..position+label_length];
            position += label_length;
            let label_string = std::str::from_utf8(label_bytes).ok()?;
            ret.push_str(&label_string);
            ret.push('.');
        }
        if label_slice[position] != 0x00 {
            // not NUL-terminated
            return None;
        }
        position += 1;
        if position != label_slice.len() {
            // trailing data?!
            return None;
        }
        Some((ret, 2 + string_length_including_nul))
    }

    pub fn try_from_bytes(kind: u16, bytes: &[u8]) -> Option<Self> {
        let data = match kind {
            0x00 => {
                if bytes.len() != 8 {
                    return None;
                }
                let entombed_time_secs = i64::from_le_bytes(bytes.try_into().unwrap());
                let entombed_time = utc_ticks_relative_to_1601(entombed_time_secs);
                Self::Tombstone(TombstoneData {
                    entombed_time,
                })
            },
            0x01 => {
                if bytes.len() != 4 {
                    return None;
                }
                let ipv4_bytes: [u8; 4] = bytes.try_into().unwrap();
                let address = Ipv4Addr::from(ipv4_bytes);
                Self::Address(Ipv4AddrData {
                    address,
                })
            },
            0x02|0x03|0x04|0x05|0x07|0x08|0x09|0x0C|0x27 => {
                let (name, length_taken) = Self::decode_count_name(bytes)?;
                if length_taken != bytes.len() {
                    // trailing data? overshot?
                    return None;
                }
                let data = NodeNameData {
                    name,
                };
                match kind {
                    0x02 => Self::NameServer(data),
                    0x03 => Self::LegacyMailDestination(data),
                    0x04 => Self::LegacyMailForwarder(data),
                    0x05 => Self::CanonicalName(data),
                    0x07 => Self::LegacyMailbox(data),
                    0x08 => Self::LegacyMailGroupMember(data),
                    0x09 => Self::LegacyMailRename(data),
                    0x0C => Self::Pointer(data),
                    0x27 => Self::DelegationName(data),
                    _ => unreachable!(),
                }
            },
            0x06 => {
                if bytes.len() < 22 {
                    return None;
                }
                let serial_number = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
                let refresh = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
                let retry = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
                let expire = u32::from_le_bytes(bytes[12..16].try_into().unwrap());
                let minimum_ttl = u32::from_le_bytes(bytes[16..20].try_into().unwrap());

                let mut position = 20;
                let (primary_server_name, psn_consumed) = Self::decode_count_name(&bytes[position..])?;
                position += psn_consumed; 
                let (zone_admin_email, zae_consumed) = Self::decode_count_name(&bytes[position..])?;
                position += zae_consumed;
                if position != bytes.len() {
                    // trailing data? overshot?
                    return None;
                }
                Self::StartOfAuthority(StartOfAuthorityData {
                    serial_number,
                    refresh,
                    retry,
                    expire,
                    minimum_ttl,
                    primary_server_name,
                    zone_admin_email,
                })
            },
            0x0A|0x31 => {
                let data = BytesData {
                    value: bytes.to_vec(),
                };
                match kind {
                    0x0A => Self::Null(data),
                    0x31 => Self::DhcpIdentifier(data),
                    _ => unreachable!(),
                }
            },
            0x0B => {
                if bytes.len() < 5 {
                    return None;
                }
                let address_bytes: [u8; 4] = bytes[0..4].try_into().unwrap();
                let address = Ipv4Addr::from(address_bytes);
                let ip_protocol = bytes[4];
                let service_bitmask = bytes[5..].to_vec();
                Self::LegacyWellKnownServices(WellKnownServiceData {
                    address,
                    ip_protocol,
                    service_bitmask,
                })
            },
            0x0D|0x10|0x13|0x14 => {
                let mut position = 0;
                let mut values = Vec::new();
                while position < bytes.len() {
                    let (string, string_consumed) = Self::decode_string(&bytes[position..])?;
                    position += string_consumed;
                    values.push(string);
                }
                let data = StringData {
                    values,
                };
                match kind {
                    0x0D => Self::HostInfo(data),
                    0x10 => Self::Text(data),
                    0x13 => Self::X25(data),
                    0x14 => Self::Isdn(data),
                    _ => unreachable!(),
                }
            },
            0x0E|0x11 => {
                if bytes.len() < 2 {
                    return None;
                }
                let mut position = 0;
                let (mailbox, mailbox_consumed) = Self::decode_count_name(&bytes[position..])?;
                position += mailbox_consumed;
                let (error_mailbox, em_consumed) = Self::decode_count_name(&bytes[position..])?;
                position += em_consumed;
                if position != bytes.len() {
                    // trailing data? overshot?
                    return None;
                }
                let data = MailboxData {
                    mailbox,
                    error_mailbox,
                };
                match kind {
                    0x0E => Self::LegacyMailInfo(data),
                    0x11 => Self::LegacyResponsiblePerson(data),
                    _ => unreachable!(),
                }
            },
            0x0F|0x12|0x15 => {
                if bytes.len() < 3 {
                    return None;
                }
                let preference = u16::from_be_bytes(bytes[0..2].try_into().unwrap());
                let mut position = 2;
                let (name, name_consumed) = Self::decode_count_name(&bytes[position..])?;
                position += name_consumed;
                if position != bytes.len() {
                    // trailing data? overshot?
                    return None;
                }
                let data = PreferenceNameData {
                    preference,
                    name,
                };
                match kind {
                    0x0F => Self::MailExchanger(data),
                    0x12 => Self::Afsdb(data),
                    0x15 => Self::LegacyRouteThrough(data),
                    _ => unreachable!(),
                }
            },
            0x18|0x2E => {
                if bytes.len() < 19 {
                    return None;
                }
                let type_covered = u16::from_be_bytes(bytes[0..2].try_into().unwrap());
                let algorithm = bytes[2];
                let label_count = bytes[3];
                let original_ttl = u32::from_be_bytes(bytes[4..8].try_into().unwrap());
                let signature_expiration = u32::from_be_bytes(bytes[8..12].try_into().unwrap());
                let signature_inception = u32::from_be_bytes(bytes[12..16].try_into().unwrap());
                let key_tag = u16::from_be_bytes(bytes[16..18].try_into().unwrap());
                let mut position = 18;
                let (signer, signer_consumed) = Self::decode_count_name(&bytes[position..])?;
                position += signer_consumed;
                let signature = bytes[position..].to_vec();
                let data = SignatureData {
                    type_covered,
                    algorithm,
                    label_count,
                    original_ttl,
                    signature_expiration,
                    signature_inception,
                    key_tag,
                    signer,
                    signature,
                };
                match kind {
                    0x18 => Self::LegacySignature(data),
                    0x2E => Self::ResourceRecordSignature(data),
                    _ => unreachable!(),
                }
            },
            0x19|0x30 => {
                if bytes.len() < 4 {
                    return None;
                }
                let flags = u16::from_be_bytes(bytes[0..2].try_into().unwrap());
                let protocol = bytes[2];
                let algorithm = bytes[3];
                let key = bytes[4..].to_vec();
                let data = KeyData {
                    flags,
                    protocol,
                    algorithm,
                    key,
                };
                match kind {
                    0x19 => Self::LegacyKey(data),
                    0x30 => Self::DnsKey(data),
                    _ => unreachable!(),
                }
            },
            0x1C => {
                if bytes.len() != 16 {
                    return None;
                }
                let address_bytes: [u8; 16] = bytes.try_into().unwrap();
                let address = Ipv6Addr::from(address_bytes);
                Self::Ipv6Address(Ipv6AddrData {
                    address,
                })
            },
            0x1E => {
                if bytes.len() < 16 {
                    return None;
                }
                let record_type_mask_bytes = bytes[0..16].try_into().unwrap();
                let mut position = 16;
                let (next_name, nn_consumed) = Self::decode_count_name(&bytes[position..])?;
                position += nn_consumed;
                if position != bytes.len() {
                    // trailing data? overshot?
                    return None;
                }
                Self::LegacyNextDomain(NextDomainData {
                    record_type_mask_bytes,
                    next_name,
                })
            },
            0x21 => {
                if bytes.len() < 7 {
                    return None;
                }
                let priority = u16::from_be_bytes(bytes[0..2].try_into().unwrap());
                let weight = u16::from_be_bytes(bytes[2..4].try_into().unwrap());
                let port = u16::from_be_bytes(bytes[4..6].try_into().unwrap());
                let mut position = 6;
                let (target, target_consumed) = Self::decode_count_name(&bytes[position..])?;
                position += target_consumed;
                if position != bytes.len() {
                    // trailing data? overshot?
                    return None;
                }
                Self::Service(ServiceData {
                    priority,
                    weight,
                    port,
                    target,
                })
            },
            0x22 => {
                if bytes.len() < 1 {
                    return None;
                }
                let format = bytes[0];
                let address = bytes[1..].to_vec();
                Self::LegacyAtma(AtmaData {
                    format,
                    address,
                })
            },
            0x23 => {
                if bytes.len() < 8 {
                    return None;
                }
                let order = u16::from_le_bytes(bytes[0..2].try_into().unwrap());
                let preference = u16::from_le_bytes(bytes[2..4].try_into().unwrap());
                let mut position = 4;
                let (flags, flags_consumed) = Self::decode_string(&bytes[position..])?;
                position += flags_consumed;
                let (service, service_consumed) = Self::decode_string(&bytes[position..])?;
                position += service_consumed;
                let (substitution, sub_consumed) = Self::decode_string(&bytes[position..])?;
                position += sub_consumed;
                let (replacement, repl_consumed) = Self::decode_count_name(&bytes[position..])?;
                position += repl_consumed;
                if position != bytes.len() {
                    // trailing data? overshot?
                    return None;
                }
                Self::NamingAuthorityPointer(NamingAuthorityPointerData {
                    order,
                    preference,
                    flags,
                    service,
                    substitution,
                    replacement,
                })
            },
            0x2B => {
                if bytes.len() < 4 {
                    return None;
                }
                let key_tag = u16::from_be_bytes(bytes[0..2].try_into().unwrap());
                let algorithm = bytes[2];
                let digest_type = bytes[3];
                let digest = bytes[4..].to_vec();
                Self::DelegationSigner(DelegationSignerData {
                    key_tag,
                    algorithm,
                    digest_type,
                    digest,
                })
            },
            0x2F => {
                let (signer, signer_consumed) = Self::decode_count_name(bytes)?;
                let nsec_bitmap = bytes[signer_consumed..].to_vec();
                Self::NextSecureRecord(NextSecureRecordData {
                    signer,
                    nsec_bitmap,
                })
            },
            0x32 => {
                if bytes.len() < 6 {
                    return None;
                }
                let algorithm = bytes[0];
                let flags = bytes[1];
                let iterations = u16::from_be_bytes(bytes[2..4].try_into().unwrap());
                let salt_length: usize = bytes[4].into();
                let hash_length: usize = bytes[5].into();
                let mut position = 6;
                if position + salt_length > bytes.len() {
                    return None;
                }
                let salt = bytes[position..position+salt_length].to_vec();
                position += salt_length;
                if position + hash_length > bytes.len() {
                    return None;
                }
                let next_hashed_owner_name = bytes[position..position+hash_length].to_vec();
                position += hash_length;
                let bitmaps = bytes[position..].to_vec();
                Self::NextSecureRecord3(NextSecureRecord3Data {
                    algorithm,
                    flags,
                    iterations,
                    salt,
                    next_hashed_owner_name,
                    bitmaps,
                })
            },
            0x33 => {
                if bytes.len() < 5 {
                    return None;
                }
                let algorithm = bytes[0];
                let flags = bytes[1];
                let iterations = u16::from_be_bytes(bytes[2..4].try_into().unwrap());
                let salt_length: usize = bytes[4].into();
                let mut position = 5;
                if position + salt_length > bytes.len() {
                    return None;
                }
                let salt = bytes[position..position+salt_length].to_vec();
                position += salt_length;
                if position != bytes.len() {
                    // trailing data? overshot?
                    return None;
                }
                Self::NextSecureRecord3Parameters(NextSecureRecord3ParameterData {
                    algorithm,
                    flags,
                    iterations,
                    salt,
                })
            },
            0x34 => {
                if bytes.len() < 3 {
                    return None;
                }
                let cert_usage = bytes[0];
                let selector = bytes[1];
                let matching_type = bytes[2];
                let certificate_association_data = bytes[3..].to_vec();
                Self::TlsAssociation(TlsAssociationData {
                    cert_usage,
                    selector,
                    matching_type,
                    certificate_association_data,
                })
            },
            0xFF01 => {
                if bytes.len() < 16 {
                    return None;
                }
                let mapping_flag: WinsMappingFlag = u32::from_le_bytes(bytes[0..4].try_into().unwrap()).into();
                let lookup_timeout = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
                let cache_timeout = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
                let wins_server_count: usize = u32::from_le_bytes(bytes[12..16].try_into().unwrap()).try_into().unwrap();
                let mut position = 16;
                if position + wins_server_count*4 > bytes.len() {
                    return None;
                }
                let mut wins_servers = Vec::with_capacity(wins_server_count);
                for _ in 0..wins_server_count {
                    let ipv4_bytes: [u8; 4] = bytes[position..position+4].try_into().unwrap();
                    position += 4;
                    let address = Ipv4Addr::from(ipv4_bytes);
                    wins_servers.push(address);
                }
                if position != bytes.len() {
                    // trailing data? overshot?
                    return None;
                }
                Self::WinsRecord(WinsData {
                    mapping_flag,
                    lookup_timeout,
                    cache_timeout,
                    wins_servers,
                })
            },
            0xFF02 => {
                if bytes.len() < 13 {
                    return None;
                }
                let mapping_flag: WinsMappingFlag = u32::from_le_bytes(bytes[0..4].try_into().unwrap()).into();
                let lookup_timeout = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
                let cache_timeout = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
                let mut position = 12;
                let (name_result_domain, nrd_consumed) = Self::decode_string(&bytes[position..])?;
                position += nrd_consumed;
                if position != bytes.len() {
                    // trailing data? overshot?
                    return None;
                }
                Self::WinsReverseRecord(WinsReverseData {
                    mapping_flag,
                    lookup_timeout,
                    cache_timeout,
                    name_result_domain,
                })
            },
            other => {
                Self::Other(OtherRecordData {
                    record_type: other,
                    data: bytes.to_vec(),
                })
            },
        };
        Some(data)
    }
}
