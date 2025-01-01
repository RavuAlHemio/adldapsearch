use std::net::{Ipv4Addr, Ipv6Addr};

use bitflags::bitflags;
use chrono::{DateTime, Utc};
use from_to_repr::from_to_other;
use serde::{Deserialize, Serialize};

use crate::{bit_is_set, extract_bits};
use crate::values::utc_seconds_relative_to_1601;


// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/445c7843-e4a1-4222-8c0f-630c230a4c80
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub(crate) struct DnsProperty {
    // data_length: u32,
    pub name_length: u32,
    pub flag: u32,
    pub version: u32,
    pub is_default: bool,
    pub data: DnsPropertyData,
}
impl DnsProperty {
    pub fn try_from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 21 {
            return None;
        }

        let data_length = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
        let name_length = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
        let flag = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
        let version = u32::from_le_bytes(bytes[12..16].try_into().unwrap());
        let id = u32::from_le_bytes(bytes[16..20].try_into().unwrap());

        if version != 1 {
            // format might have changed; don't risk it
            return None;
        }

        let data_length_usize: usize = data_length.try_into().unwrap();
        if bytes.len() < 21 + data_length_usize {
            // data won't fit
            return None;
        }
        let data_bytes = &bytes[20..20+data_length_usize];
        let is_default = data_length_usize == 0;

        fn parse_ip4_array(bytes: &[u8]) -> Option<Vec<Ipv4Addr>> {
            if bytes.len() < 4 || bytes.len() % 4 != 0 {
                return None;
            }
            let addr_count = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
            let addr_count_usize: usize = addr_count.try_into().unwrap();
            if (bytes.len() / 4) - 1 < addr_count_usize {
                return None;
            }
            let mut ret = Vec::with_capacity(addr_count_usize);
            for chunk in bytes.chunks(4).skip(1) {
                // network byte order!
                let addr_bytes = u32::from_be_bytes(chunk.try_into().unwrap());
                ret.push(Ipv4Addr::from_bits(addr_bytes));
            }
            Some(ret)
        }

        fn parse_dns_addr_array(bytes: &[u8]) -> Option<Vec<DnsAddr>> {
            if bytes.len() < 32 {
                return None;
            }
            let max_count = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
            let addr_count = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
            if max_count != addr_count {
                return None;
            }
            // most of this structure is completely pointless
            if (bytes.len() - 32) % 64 != 0 {
                // won't fit
                return None;
            }

            let addr_count_usize: usize = addr_count.try_into().unwrap();
            if (bytes.len() - 32) / 64 < addr_count_usize {
                return None;
            }
            let mut ret = Vec::with_capacity(addr_count_usize);
            for chunk in bytes[32..].chunks(64) {
                let addr = DnsAddr::try_from_bytes(chunk)?;
                ret.push(addr);
            }
            Some(ret)
        }

        let data = match id {
            0x00000001 => {
                if is_default {
                    DnsPropertyData::ZoneType(ZoneType::Primary)
                } else if data_bytes.len() != 4 {
                    return None;
                } else {
                    DnsPropertyData::ZoneType(ZoneType::from_base_type(u32::from_le_bytes(data_bytes.try_into().unwrap())))
                }
            },
            0x00000002 => {
                if data_bytes.len() == 1 {
                    DnsPropertyData::AllowUpdate(AllowUpdate::from_base_type(u32::from(data_bytes[0])))
                } else if data_bytes.len() != 4 {
                    return None;
                } else {
                    DnsPropertyData::AllowUpdate(AllowUpdate::from_base_type(u32::from_le_bytes(data_bytes.try_into().unwrap())))
                }
            },
            0x00000008 => {
                if is_default {
                    DnsPropertyData::SecureTime(utc_seconds_relative_to_1601(0))
                } else if data_bytes.len() != 8 {
                    return None;
                } else {
                    // technically u64, but unlikely to make a difference
                    let seconds = i64::from_le_bytes(data_bytes.try_into().unwrap());
                    DnsPropertyData::SecureTime(utc_seconds_relative_to_1601(seconds))
                }
            },
            0x00000010 => {
                if is_default {
                    DnsPropertyData::NoRefreshInterval { hours: 168 }
                } else if data_bytes.len() != 4 {
                    return None;
                } else {
                    DnsPropertyData::NoRefreshInterval { hours: u32::from_le_bytes(data_bytes.try_into().unwrap()) }
                }
            },
            0x00000020 => {
                if is_default {
                    DnsPropertyData::   RefreshInterval { hours: 168 }
                } else if data_bytes.len() != 4 {
                    return None;
                } else {
                    DnsPropertyData::RefreshInterval { hours: u32::from_le_bytes(data_bytes.try_into().unwrap()) }
                }
            },
            0x00000040 => {
                if is_default {
                    DnsPropertyData::AgingState(Boolean::False)
                } else if data_bytes.len() != 4 {
                    return None;
                } else {
                    DnsPropertyData::AgingState(Boolean::from_base_type(u32::from_le_bytes(data_bytes.try_into().unwrap())))
                }
            },
            0x00000011 => {
                if is_default {
                    DnsPropertyData::ScavengingServers(Vec::with_capacity(0))
                } else {
                    let servers = parse_ip4_array(data_bytes)?;
                    DnsPropertyData::ScavengingServers(servers)
                }
            },
            0x00000012 => {
                if is_default {
                    DnsPropertyData::AgingEnabledTime { hours: 0 }
                } else if data_bytes.len() != 4 {
                    return None;
                } else {
                    DnsPropertyData::AgingEnabledTime { hours: u32::from_le_bytes(data_bytes.try_into().unwrap()) }
                }
            },
            0x00000080 => {
                if data_bytes.len() % 2 != 0 {
                    return None;
                }
                let mut words = Vec::with_capacity(data_bytes.len() % 2);
                for chunk in data_bytes.chunks(2) {
                    let word = u16::from_le_bytes(chunk.try_into().unwrap());
                    if word == 0x0000 {
                        break;
                    }
                    words.push(word);
                }
                let hostname = String::from_utf16(&words).ok()?;
                DnsPropertyData::DeletedFromHostname(hostname)
            },
            0x00000081 => {
                if is_default {
                    DnsPropertyData::MasterServers(Vec::with_capacity(0))
                } else {
                    let servers = parse_ip4_array(data_bytes)?;
                    DnsPropertyData::MasterServers(servers)
                }
            },
            0x00000082 => {
                if is_default {
                    DnsPropertyData::AutoNsServers(Vec::with_capacity(0))
                } else {
                    let servers = parse_ip4_array(data_bytes)?;
                    DnsPropertyData::AutoNsServers(servers)
                }
            },
            0x00000083 => {
                if data_bytes.len() != 4 {
                    return None;
                }
                DnsPropertyData::DcPromoConvert(DcPromoFlag::from_base_type(u32::from_le_bytes(data_bytes.try_into().unwrap())))
            },
            0x00000090 => {
                if is_default {
                    DnsPropertyData::ScavengingServersDa(Vec::with_capacity(0))
                } else {
                    let servers = parse_dns_addr_array(data_bytes)?;
                    DnsPropertyData::ScavengingServersDa(servers)
                }
            },
            0x00000091 => {
                if is_default {
                    DnsPropertyData::MasterServersDa(Vec::with_capacity(0))
                } else {
                    let servers = parse_dns_addr_array(data_bytes)?;
                    DnsPropertyData::MasterServersDa(servers)
                }
            },
            0x00000092 => {
                if is_default {
                    DnsPropertyData::AutoNsServersDa(Vec::with_capacity(0))
                } else {
                    let servers = parse_dns_addr_array(data_bytes)?;
                    DnsPropertyData::AutoNsServersDa(servers)
                }
            },
            0x00000100 => {
                if data_bytes.len() != 4 {
                    return None;
                }
                DnsPropertyData::DbFlags(DnsRpcNodeFlags::from_bits_retain(u32::from_le_bytes(data_bytes.try_into().unwrap())))
            },
            other => {
                DnsPropertyData::Other { id: other, data: data_bytes.to_vec() }
            },
        };
        Some(Self {
            name_length,
            flag,
            version,
            is_default,
            data,
        })
    }
}

// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/3af63871-0cc4-4179-916c-5caade55a8f3
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub(crate) enum DnsPropertyData {
    ZoneType(ZoneType),
    AllowUpdate(AllowUpdate),
    SecureTime(DateTime<Utc>),
    NoRefreshInterval { hours: u32 },
    RefreshInterval { hours: u32 },
    AgingState(Boolean),
    ScavengingServers(Vec<Ipv4Addr>),
    AgingEnabledTime { hours: u32 },
    DeletedFromHostname(String),
    MasterServers(Vec<Ipv4Addr>),
    AutoNsServers(Vec<Ipv4Addr>),
    DcPromoConvert(DcPromoFlag),
    ScavengingServersDa(Vec<DnsAddr>),
    MasterServersDa(Vec<DnsAddr>),
    AutoNsServersDa(Vec<DnsAddr>),
    DbFlags(DnsRpcNodeFlags),
    Other {
        id: u32,
        data: Vec<u8>,
    },
}

// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/27e138a7-110c-44a4-afcb-b95f35f00306
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[from_to_other(base_type = u32, derive_compare = "as_int")]
pub(crate) enum ZoneType {
    Cache = 0x00,
    Primary = 0x01,
    Secondary = 0x02,
    Stub = 0x03,
    Forwarder = 0x04,
    SecondaryCache = 0x05,
    Other(u32),
}

// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/e8651544-0fbb-4038-8232-375ff2d8a55e fAllowUpdate
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[from_to_other(base_type = u32, derive_compare = "as_int")]
pub(crate) enum AllowUpdate {
    Off = 0x00,
    Unsecure = 0x01,
    Secure = 0x02,
    Other(u32),
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[from_to_other(base_type = u32, derive_compare = "as_int")]
pub(crate) enum Boolean {
    False = 0,
    True = 1,
    Other(u32),
}
impl Default for Boolean {
    fn default() -> Self { Self::False }
}
impl From<Boolean> for bool {
    fn from(value: Boolean) -> Self { value.to_base_type() != 0 }
}

// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/4ec7bdf7-1807-4179-96af-ce1c1cd448b7
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[from_to_other(base_type = u32, derive_compare = "as_int")]
pub(crate) enum DcPromoFlag {
    ConvertNone = 0x00,
    ConvertDomain = 0x01,
    ConvertForest = 0x02,
    Other(u32),
}

// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/f448341f-512d-414a-aaa3-e303d592fcd2
bitflags! {
    #[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
    pub(crate) struct DnsRpcNodeFlags : u32 {
        const CacheData = 0x80000000;
        const ZoneRoot = 0x40000000;
        const AuthZoneRoot = 0x20000000;
        const ZoneDelegation = 0x10000000;
        const RecordDefaultTtl = 0x08000000;
        const RecordTtlChange = 0x04000000;
        const RecordCreatePtr = 0x02000000;
        const NodeSticky = 0x01000000;
        const NodeComplete = 0x00800000;
        const SuppressNotify = 0x00010000;
        const AgingOn = 0x00020000;
        const OpenAcl = 0x00040000;
        const RecordWireFormat = 0x00100000;
        const SuppressRecordUpdatePtr = 0x00200000;
    }
}

// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/e8651544-0fbb-4038-8232-375ff2d8a55e
// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/835c236a-4d35-4a1e-bc4c-f5eb27bfb06d
// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/aea3ba9b-de48-4f0e-a4c8-4f7c89404b99
// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/6e041c76-3b55-480a-84fb-feebcb0cc9db
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub(crate) struct DnsAddr {
    pub ip: DnsIpAddr,
    pub port: u16,
    pub subnet_length: u32,
    pub dns_over_tcp_available: bool,
    pub rtt_10ms: u16,
    pub validation_status: DnsValidationStatus,
}
impl DnsAddr {
    pub fn try_from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 44 {
            return None;
        }

        let address_family = u16::from_le_bytes(bytes[0..2].try_into().unwrap());
        // port numbers are network-endian (big-endian)!
        let port = u16::from_be_bytes(bytes[2..4].try_into().unwrap());
        let address_bytes = &bytes[4..32];
        let sockaddr_length = u32::from_le_bytes(bytes[32..36].try_into().unwrap());
        let subnet_length = u32::from_le_bytes(bytes[36..40].try_into().unwrap());
        let flags = u32::from_le_bytes(bytes[40..44].try_into().unwrap());

        if sockaddr_length < 4 || sockaddr_length > 32 {
            // cannot fit
            return None;
        }

        let ip = match address_family {
            0x0002 => {
                // IPv4
                if sockaddr_length < 8 {
                    // family(2) + port(2) + address(4)
                    return None;
                }
                let address_byte_array: [u8; 4] = address_bytes[0..4].try_into().unwrap();
                DnsIpAddr::V4(address_byte_array.into())
            },
            0x0017 => {
                // IPv6
                if sockaddr_length < 24 {
                    // family(2) + port(2) + skip_ipv4(4) + address(16)
                    return None;
                }
                // skip the 4 bytes that store the IPv4 address
                let address_byte_array: [u8; 16] = address_bytes[4..20].try_into().unwrap();
                DnsIpAddr::V6(address_byte_array.into())
            },
            family => {
                let address_length: usize = (sockaddr_length - 4).try_into().unwrap();
                let address = address_bytes[0..address_length].to_vec();
                DnsIpAddr::Other {
                    family,
                    address,
                }
            },
        };

        let dns_over_tcp_available = !bit_is_set!(flags, 31);
        let rtt_10ms = extract_bits!(flags, 12, 12);
        let validation_status_u16: u16 = extract_bits!(flags, 0, 12);
        let validation_status: DnsValidationStatus = validation_status_u16.into();

        Some(Self {
            ip,
            port,
            subnet_length,
            dns_over_tcp_available,
            rtt_10ms,
            validation_status,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub(crate) enum DnsIpAddr {
    V4(Ipv4Addr),
    V6(Ipv6Addr),
    Other {
        family: u16,
        address: Vec<u8>,
    },
}

// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dnsp/f9f3901a-862f-4bdb-a7c4-963dae44c13e
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[from_to_other(base_type = u16, derive_compare = "as_int")]
pub(crate) enum DnsValidationStatus {
    Success = 0x0000,
    InvalidAddr = 0x0001,
    Unreachable = 0x0002,
    NoResponse = 0x0003,
    NotAuthForZone = 0x0004,
    UnknownError = 0x00FF,
    Other(u16),
}


#[cfg(test)]
mod tests {
    use super::{DnsPropertyData, DnsIpAddr, DnsProperty, DnsValidationStatus};
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_master_servers_da() {
        const DATA: [u8; 440] = [
            0xA0, 0x01, 0x00, 0x00, 0x17, 0x00, 0x00, 0x35, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
            0x91, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x35, 0xC0, 0xA8, 0x0C, 0x22, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x17, 0x00, 0x00, 0x35, 0x00, 0x00, 0x00, 0x00, 0x20, 0x01, 0x0d, 0xb8,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x34, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x1C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x35, 0xC0, 0xA8, 0x0C, 0x59, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x17, 0x00, 0x00, 0x35, 0x00, 0x00, 0x00, 0x00, 0x20, 0x01, 0x0d, 0xb8,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x89, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x1C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x35, 0xC0, 0xA8, 0x0C, 0x2A, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x17, 0x00, 0x00, 0x35, 0x00, 0x00, 0x00, 0x00, 0x20, 0x01, 0x0d, 0xb8,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x42, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x1C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x80, 0x0F, 0x80, 0x0F,
        ];
        let dns_property = DnsProperty::try_from_bytes(&DATA).unwrap();
        assert_eq!(dns_property.version, 1);
        assert_eq!(dns_property.name_length, 889192471);
        assert_eq!(dns_property.flag, 0);
        let master_servers_da = match &dns_property.data {
            DnsPropertyData::MasterServersDa(msda) => msda,
            _ => panic!("incorrect DNS property"),
        };
        assert_eq!(master_servers_da.len(), 6);
        assert_eq!(master_servers_da[0].ip, DnsIpAddr::V4(Ipv4Addr::new(192, 168, 12, 34)));
        assert_eq!(master_servers_da[0].port, 53);
        assert_eq!(master_servers_da[0].dns_over_tcp_available, false);
        assert_eq!(master_servers_da[0].rtt_10ms, 0);
        assert_eq!(master_servers_da[0].subnet_length, 0);
        assert_eq!(master_servers_da[0].validation_status, DnsValidationStatus::Success);
        assert_eq!(master_servers_da[1].ip, DnsIpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0x34)));
        assert_eq!(master_servers_da[1].port, 53);
        assert_eq!(master_servers_da[1].dns_over_tcp_available, false);
        assert_eq!(master_servers_da[1].rtt_10ms, 0);
        assert_eq!(master_servers_da[1].subnet_length, 0);
        assert_eq!(master_servers_da[1].validation_status, DnsValidationStatus::Success);
        assert_eq!(master_servers_da[2].ip, DnsIpAddr::V4(Ipv4Addr::new(192, 168, 12, 89)));
        assert_eq!(master_servers_da[2].port, 53);
        assert_eq!(master_servers_da[2].dns_over_tcp_available, false);
        assert_eq!(master_servers_da[2].rtt_10ms, 0);
        assert_eq!(master_servers_da[2].subnet_length, 0);
        assert_eq!(master_servers_da[2].validation_status, DnsValidationStatus::Success);
        assert_eq!(master_servers_da[3].ip, DnsIpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0x89)));
        assert_eq!(master_servers_da[3].port, 53);
        assert_eq!(master_servers_da[3].dns_over_tcp_available, false);
        assert_eq!(master_servers_da[3].rtt_10ms, 0);
        assert_eq!(master_servers_da[3].subnet_length, 0);
        assert_eq!(master_servers_da[3].validation_status, DnsValidationStatus::Success);
        assert_eq!(master_servers_da[4].ip, DnsIpAddr::V4(Ipv4Addr::new(192, 168, 12, 42)));
        assert_eq!(master_servers_da[4].port, 53);
        assert_eq!(master_servers_da[4].dns_over_tcp_available, false);
        assert_eq!(master_servers_da[4].rtt_10ms, 0);
        assert_eq!(master_servers_da[4].subnet_length, 0);
        assert_eq!(master_servers_da[4].validation_status, DnsValidationStatus::Success);
        assert_eq!(master_servers_da[5].ip, DnsIpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0x42)));
        assert_eq!(master_servers_da[5].port, 53);
        assert_eq!(master_servers_da[5].dns_over_tcp_available, false);
        assert_eq!(master_servers_da[5].rtt_10ms, 0);
        assert_eq!(master_servers_da[5].subnet_length, 0);
        assert_eq!(master_servers_da[5].validation_status, DnsValidationStatus::Success);
    }
}
