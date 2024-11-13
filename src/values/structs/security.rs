use std::fmt::{self, Write as _};
use std::str::FromStr;

use bitmask_enum::bitmask;
use from_to_repr::from_to_other;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::values::nul_terminated_utf16le_string;


#[derive(Clone, Debug, Deserialize, Hash, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct Sid {
    pub version: u8,
    // subauthority_count: u8
    pub authority: u64, // actually u48
    pub subauthorities: Vec<u32>, // [u32; subauthority_count]
}
impl Sid {
    fn subauthority_count_from_slice(bytes: &[u8]) -> Option<usize> {
        if bytes.len() < 8 {
            // not enough space for even zero subauthorities
            return None;
        }
        let version = bytes[0];
        if version != 1 {
            // unsupported SID version
            return None;
        }
        let subauthority_count: usize = bytes[1].into();
        if bytes.len() < 8 + 4*subauthority_count {
            // not enough subauthority elements for this subauthority count
            return None;
        }
        Some(subauthority_count)
    }

    pub fn get_length(bytes: &[u8]) -> Option<usize> {
        let subauthority_count = Self::subauthority_count_from_slice(bytes)?;
        let total_size = 8 + 4*subauthority_count;
        if bytes.len() < total_size {
            return None;
        }
        Some(total_size)
    }

    pub fn try_from_bytes(bytes: &[u8]) -> Option<Self> {
        let subauthority_count = Self::subauthority_count_from_slice(bytes)?;
        let total_size = 8 + 4*subauthority_count;
        if bytes.len() != total_size {
            return None;
        }

        let authority: u64 =
            // big endian
            (u64::from(bytes[2]) << 40)
            | (u64::from(bytes[3]) << 32)
            | (u64::from(bytes[4]) << 24)
            | (u64::from(bytes[5]) << 16)
            | (u64::from(bytes[6]) <<  8)
            | (u64::from(bytes[7]) <<  0)
        ;

        let mut subauthorities = Vec::with_capacity(subauthority_count);
        for i in 0..subauthority_count {
            // little endian
            let sub_auth = u32::from_le_bytes(bytes[(8 + 4*i)..(8 + 4*i + 4)].try_into().unwrap());
            subauthorities.push(sub_auth);
        }
        Some(Self {
            version: 1, // ensured by Self::subauthority_count_from_slice
            authority,
            subauthorities,
        })
    }

    // https://learn.microsoft.com/en-us/windows/win32/secauthz/sid-strings
    // https://learn.microsoft.com/en-us/windows/win32/secauthz/well-known-sids
    pub fn as_well_known_sddl_sid_string(&self) -> Option<&'static str> {
        if self.version != 1 {
            return None;
        }

        match self.authority {
            1 => match self.subauthorities.len() { // world authority
                1 => match self.subauthorities[0] {
                    0 => Some("WD"),
                    _ => None,
                },
                _ => None,
            },
            3 => match self.subauthorities.len() { // creator authority
                1 => match self.subauthorities[0] {
                    0 => Some("CO"),
                    1 => Some("CG"),
                    4 => Some("OW"),
                    _ => None,
                },
                _ => None,
            },
            5 => match self.subauthorities.len() { // NT authority
                1 => match self.subauthorities[0] {
                    2 => Some("NU"),
                    4 => Some("IU"),
                    6 => Some("SU"),
                    7 => Some("AN"),
                    9 => Some("ED"),
                    10 => Some("PS"),
                    11 => Some("AU"),
                    12 => Some("RC"),
                    18 => Some("SY"),
                    19 => Some("LS"),
                    20 => Some("NS"),
                    33 => Some("WR"),
                    _ => None,
                },
                2 => match self.subauthorities[0] {
                    32 => match self.subauthorities[1] { // built-in domain
                        544 => Some("BA"),
                        545 => Some("BU"),
                        546 => Some("BG"),
                        547 => Some("PU"),
                        548 => Some("AO"),
                        549 => Some("SO"),
                        550 => Some("PO"),
                        551 => Some("BO"),
                        552 => Some("RE"),
                        553 => Some("RS"),
                        554 => Some("RU"),
                        555 => Some("RD"),
                        556 => Some("NO"),
                        558 => Some("MU"),
                        559 => Some("LU"),
                        568 => Some("IS"),
                        569 => Some("CY"),
                        573 => Some("ER"),
                        574 => Some("CD"),
                        575 => Some("RA"),
                        576 => Some("ES"),
                        578 => Some("HA"),
                        579 => Some("AA"),
                        584 => Some("HO"),
                        _ => None,
                    },
                    _ => None,
                }
                _ => None,
            },
            15 => match self.subauthorities.len() { // application package authority
                2 => match (self.subauthorities[0], self.subauthorities[1]) {
                    (2, 1) => Some("AC"),
                    _ => None,
                },
                _ => None,
            },
            16 => match self.subauthorities.len() { // mandatory label authority
                1 => match self.subauthorities[0] {
                    4096 => Some("LW"),
                    8192 => Some("ME"),
                    8448 => Some("MP"),
                    12288 => Some("HI"),
                    16384 => Some("SI"),
                    _ => None,
                },
                _ => None,
            },
            18 => match self.subauthorities.len() { // authentication authority
                1 => match self.subauthorities[0] {
                    2 => Some("SS"),
                    _ => None,
                },
                _ => None,
            },
            _ => None,
        }
    }

    pub fn to_sddl_sid_string(&self) -> String {
        match self.as_well_known_sddl_sid_string() {
            Some(s) => s.to_owned(),
            None => self.to_string(),
        }
    }
}
impl fmt::Display for Sid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "S-{}-{}", self.version, self.authority)?;
        for subauthority in &self.subauthorities {
            write!(f, "-{}", subauthority)?;
        }
        Ok(())
    }
}
impl FromStr for Sid {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if !s.starts_with("S-") {
            return Err("SID string does not start with \"S-\"");
        }
        let mut top_authority = None;
        let mut subauthorities = Vec::new();
        for (i, number_str) in s[2..].split("-").enumerate() {
            if i == 0 {
                if number_str != "1" {
                    return Err("not a version 1 SID");
                }
                continue;
            }

            let authority: u64 = match number_str.parse() {
                Ok(a) => a,
                Err(_) => return Err("one of the authorities is not parseable as u64"),
            };
            if i == 1 {
                if authority > 0x0000FFFF_FFFFFFFF {
                    return Err("top authority does not fit into 48 bits");
                }
                top_authority = Some(authority);
                continue;
            }

            if authority > 0xFFFFFFFF {
                return Err("subauthority does not fit into 32 bits");
            }
            subauthorities.push(u32::try_from(authority).unwrap());
        }
        match top_authority {
            Some(ta) => Ok(Self {
                version: 1,
                authority: ta,
                subauthorities,
            }),
            None => Err("no top authority specified"),
        }
    }
}

// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/7a53f60e-e730-4dfe-bbe9-b21b62eb790b
#[bitmask(u32)]
#[bitmask_config(vec_debug)]
#[derive(Deserialize, Serialize)]
pub enum AccessMask {
    WriteOwner = 0x0008_0000,
    WriteDacl = 0x0004_0000,
    ReadControl = 0x0002_0000,
    Delete = 0x0001_0000,

    DsCreateChild = 0x0000_0001,
    DsDeleteChild = 0x0000_0002,
    DsListChildren = 0x0000_0004,
    DsSelfWrite = 0x0000_0008,
    DsReadProp = 0x0000_0010,
    DsWriteProp = 0x0000_0020,
    DsDeleteTree = 0x0000_0040,
    DsListObject = 0x0000_0080,
    DsControlAccess = 0x0000_0100,
}

// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/25fa6565-6cb0-46ab-a30a-016b32c4939a
#[bitmask(u32)]
#[bitmask_config(vec_debug)]
#[derive(Deserialize, Serialize)]
pub enum MandatoryMask {
    NoWriteUp = 0x0000_0001,
    NoReadUp = 0x0000_0002,
    NoExecuteUp = 0x0000_0004,
}

// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/21f2b5f0-7376-45bb-bc31-eaa60841dbe9
#[bitmask(u32)]
#[bitmask_config(vec_debug)]
#[derive(Deserialize, Serialize)]
pub enum ClaimFlags {
    FciManual = 0x0001_0000,
    FciPolicyDerived = 0x0002_0000,

    NonInheritable = 0x0001,
    ValueCaseSensitive = 0x0002,
    UseForDenyOnly = 0x0004,
    DisabledByDefault = 0x0008,
    Disabled = 0x0010,
    Mandatory = 0x0020,
}

// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/21f2b5f0-7376-45bb-bc31-eaa60841dbe9
#[derive(Clone, Debug, Deserialize, Hash, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub enum ClaimValues {
    Int64s(Vec<i64>),
    Uint64s(Vec<u64>),
    Strings(Vec<String>),
    Sids(Vec<Sid>),
    Booleans(Vec<bool>),
    OctetStrings(Vec<Vec<u8>>),
}

// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/21f2b5f0-7376-45bb-bc31-eaa60841dbe9
#[derive(Clone, Debug, Deserialize, Hash, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ClaimSecurityAttribute1 {
    pub name: String,
    pub reserved: u16,
    pub flags: ClaimFlags,
    pub values: ClaimValues,
}
impl ClaimSecurityAttribute1 {
    pub fn try_from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 16 {
            return None;
        }
        let name_offset: usize = u32::from_le_bytes(bytes[0..4].try_into().unwrap()).try_into().unwrap();
        let value_type = u16::from_le_bytes(bytes[4..6].try_into().unwrap());
        let reserved = u16::from_le_bytes(bytes[6..8].try_into().unwrap());
        let flags: ClaimFlags = u32::from_le_bytes(bytes[8..12].try_into().unwrap()).into();
        let value_count: usize = u32::from_le_bytes(bytes[12..16].try_into().unwrap()).try_into().unwrap();

        if name_offset >= bytes.len() {
            return None;
        }
        let name = nul_terminated_utf16le_string(&bytes[name_offset..])?;

        let mut offsets = Vec::with_capacity(value_count);
        for i in 0..value_count {
            let offset_offset = 16 + 4*i;
            if offset_offset + 4 > bytes.len() {
                return None;
            }
            let offset: usize = u32::from_le_bytes(bytes[offset_offset..offset_offset+4].try_into().unwrap()).try_into().unwrap();
            if offset >= bytes.len() {
                return None;
            }
            offsets.push(offset);
        }

        let values = match value_type {
            0x0001 => {
                let mut values = Vec::with_capacity(offsets.len());
                for offset in offsets {
                    if offset + 8 > bytes.len() {
                        return None;
                    }
                    let value = i64::from_le_bytes(bytes[offset..offset+8].try_into().unwrap());
                    values.push(value);
                }
                ClaimValues::Int64s(values)
            },
            0x0002 => {
                let mut values = Vec::with_capacity(offsets.len());
                for offset in offsets {
                    if offset + 8 > bytes.len() {
                        return None;
                    }
                    let value = u64::from_le_bytes(bytes[offset..offset+8].try_into().unwrap());
                    values.push(value);
                }
                ClaimValues::Uint64s(values)
            },
            0x0003 => {
                let mut values = Vec::with_capacity(offsets.len());
                for offset in offsets {
                    if offset >= bytes.len() {
                        return None;
                    }
                    let value = nul_terminated_utf16le_string(&bytes[offset..])?;
                    values.push(value);
                }
                ClaimValues::Strings(values)
            },
            0x0005 => {
                let mut values = Vec::with_capacity(offsets.len());
                for offset in offsets {
                    if offset >= bytes.len() {
                        return None;
                    }
                    let sid_string = nul_terminated_utf16le_string(&bytes[offset..])?;
                    let value: Sid = sid_string.parse().ok()?;
                    values.push(value);
                }
                ClaimValues::Sids(values)
            },
            0x0006 => {
                let mut values = Vec::with_capacity(offsets.len());
                for offset in offsets {
                    if offset + 8 > bytes.len() {
                        return None;
                    }
                    let numeric_value = u64::from_le_bytes(bytes[offset..offset+8].try_into().unwrap());
                    let value = match numeric_value {
                        0x0000_0000_0000_0001 => true,
                        0x0000_0000_0000_0000 => false,
                        _ => return None,
                    };
                    values.push(value);
                }
                ClaimValues::Booleans(values)
            },
            0x0010 => {
                let mut values = Vec::with_capacity(offsets.len());
                for offset in offsets {
                    if offset + 4 > bytes.len() {
                        return None;
                    }
                    let data_length: usize = u32::from_le_bytes(bytes[offset..offset+4].try_into().unwrap()).try_into().unwrap();
                    if offset + 4 + data_length > bytes.len() {
                        return None;
                    }
                    let value = bytes[offset+4..offset+4+data_length].to_vec();
                    values.push(value);
                }
                ClaimValues::OctetStrings(values)
            },
            _ => return None,
        };
        Some(Self {
            name,
            reserved,
            flags,
            values,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Hash, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub enum AceData {
    // 0x00; https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/72e7c7ea-bc02-4c74-a619-818a16bf6adb
    AccessAllowed { mask: AccessMask, sid: Sid },

    // 0x01; https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/b1e1321d-5816-4513-be67-b65d8ae52fe8
    AccessDenied { mask: AccessMask, sid: Sid },

    // 0x02; https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/628ebb1d-c509-4ea0-a10f-77ef97ca4586
    SystemAudit { mask: AccessMask, sid: Sid },

    // 0x03 SystemAlarm, reserved
    // 0x04 AccessAllowedCompound, reserved

    // 0x05; https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/c79a383c-2b3f-4655-abe7-dcbb7ce0cfbe
    AccessAllowedObject { mask: AccessMask, flags: u32, object_type: Option<Uuid>, inherited_object_type: Option<Uuid>, sid: Sid },

    // 0x06; https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/8720fcf3-865c-4557-97b1-0b3489a6c270
    AccessDeniedObject { mask: AccessMask, flags: u32, object_type: Option<Uuid>, inherited_object_type: Option<Uuid>, sid: Sid },

    // 0x07; https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/c8da72ae-6b54-4a05-85f4-e2594936d3d5
    SystemAuditObject { mask: AccessMask, flags: u32, object_type: Option<Uuid>, inherited_object_type: Option<Uuid>, sid: Sid },

    // 0x08 SystemAlarmObject, reserved

    // 0x09; https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/c9579cf4-0f4a-44f1-9444-422dfb10557a
    AccessAllowedCallback { mask: AccessMask, sid: Sid },

    // 0x0A; https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/35adad6b-fda5-4cc1-b1b5-9beda5b07d2e
    AccessDeniedCallback { mask: AccessMask, sid: Sid },

    // 0x0B; https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/fe1838ea-ea34-4a5e-b40e-eb870f8322ae
    AccessAllowedCallbackObject { mask: AccessMask, flags: u32, object_type: Option<Uuid>, inherited_object_type: Option<Uuid>, sid: Sid },

    // 0x0C; https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/4652f211-82d5-4b90-bd58-43bf3b0fc48d
    AccessDeniedCallbackObject { mask: AccessMask, flags: u32, object_type: Option<Uuid>, inherited_object_type: Option<Uuid>, sid: Sid },

    // 0x0D; https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/bd6b6fd8-4bef-427e-9a43-b9b46457e934
    SystemAuditCallback { mask: AccessMask, sid: Sid },

    // 0x0E SystemAlarmCallback, reserved

    // 0x0F; https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/949b02e7-f55d-4c26-969f-52a009597469
    SystemAuditCallbackObject { mask: AccessMask, flags: u32, object_type: Option<Uuid>, inherited_object_type: Option<Uuid>, sid: Sid },

    // 0x10; SystemAlarmCallbackObject, reserved

    // 0x11; https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/25fa6565-6cb0-46ab-a30a-016b32c4939a
    SystemMandatoryLabel { mask: MandatoryMask, sid: Sid },

    // 0x12; https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/352944c7-4fb6-4988-8036-0a25dcedc730
    SystemResourceAttribute { mask: AccessMask, sid: Sid, attribute_data: ClaimSecurityAttribute1 },

    // 0x13; https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/352944c7-4fb6-4988-8036-0a25dcedc730
    SystemScopedPolicyId { mask: AccessMask, sid: Sid },

    // all data is stored in Ace::application_data
    Other { kind: u8 },
}
impl AceData {
    pub fn access_mask(&self) -> Option<AccessMask> {
        match self {
            AceData::AccessAllowed { mask, .. } => Some(*mask),
            AceData::AccessDenied { mask, .. } => Some(*mask),
            AceData::SystemAudit { mask, .. } => Some(*mask),
            AceData::AccessAllowedObject { mask, .. } => Some(*mask),
            AceData::AccessDeniedObject { mask, .. } => Some(*mask),
            AceData::SystemAuditObject { mask, .. } => Some(*mask),
            AceData::AccessAllowedCallback { mask, .. } => Some(*mask),
            AceData::AccessDeniedCallback { mask, .. } => Some(*mask),
            AceData::AccessAllowedCallbackObject { mask, .. } => Some(*mask),
            AceData::AccessDeniedCallbackObject { mask, .. } => Some(*mask),
            AceData::SystemAuditCallback { mask, .. } => Some(*mask),
            AceData::SystemAuditCallbackObject { mask, .. } => Some(*mask),
            AceData::SystemMandatoryLabel { .. } => None,
            AceData::SystemResourceAttribute { mask, .. } => Some(*mask),
            AceData::SystemScopedPolicyId { mask, .. } => Some(*mask),
            AceData::Other { .. } => None,
        }
    }

    pub fn object_guid(&self) -> Option<Uuid> {
        match self {
            AceData::AccessAllowed { .. } => None,
            AceData::AccessDenied { .. } => None,
            AceData::SystemAudit { .. } => None,
            AceData::AccessAllowedObject { object_type, .. } => *object_type,
            AceData::AccessDeniedObject { object_type, .. } => *object_type,
            AceData::SystemAuditObject { object_type, .. } => *object_type,
            AceData::AccessAllowedCallback { .. } => None,
            AceData::AccessDeniedCallback { .. } => None,
            AceData::AccessAllowedCallbackObject { object_type, .. } => *object_type,
            AceData::AccessDeniedCallbackObject { object_type, .. } => *object_type,
            AceData::SystemAuditCallback { .. } => None,
            AceData::SystemAuditCallbackObject { object_type, .. } => *object_type,
            AceData::SystemMandatoryLabel { .. } => None,
            AceData::SystemResourceAttribute { .. } => None,
            AceData::SystemScopedPolicyId { .. } => None,
            AceData::Other { .. } => None,
        }
    }

    pub fn inherit_object_guid(&self) -> Option<Uuid> {
        match self {
            AceData::AccessAllowed { .. } => None,
            AceData::AccessDenied { .. } => None,
            AceData::SystemAudit { .. } => None,
            AceData::AccessAllowedObject { inherited_object_type, .. } => *inherited_object_type,
            AceData::AccessDeniedObject { inherited_object_type, .. } => *inherited_object_type,
            AceData::SystemAuditObject { inherited_object_type, .. } => *inherited_object_type,
            AceData::AccessAllowedCallback { .. } => None,
            AceData::AccessDeniedCallback { .. } => None,
            AceData::AccessAllowedCallbackObject { inherited_object_type, .. } => *inherited_object_type,
            AceData::AccessDeniedCallbackObject { inherited_object_type, .. } => *inherited_object_type,
            AceData::SystemAuditCallback { .. } => None,
            AceData::SystemAuditCallbackObject { inherited_object_type, .. } => *inherited_object_type,
            AceData::SystemMandatoryLabel { .. } => None,
            AceData::SystemResourceAttribute { .. } => None,
            AceData::SystemScopedPolicyId { .. } => None,
            AceData::Other { .. } => None,
        }
    }

    pub fn sid(&self) -> Option<&Sid> {
        match self {
            AceData::AccessAllowed { sid, .. } => Some(sid),
            AceData::AccessDenied { sid, .. } => Some(sid),
            AceData::SystemAudit { sid, .. } => Some(sid),
            AceData::AccessAllowedObject { sid, .. } => Some(sid),
            AceData::AccessDeniedObject { sid, .. } => Some(sid),
            AceData::SystemAuditObject { sid, .. } => Some(sid),
            AceData::AccessAllowedCallback { sid, .. } => Some(sid),
            AceData::AccessDeniedCallback { sid, .. } => Some(sid),
            AceData::AccessAllowedCallbackObject { sid, .. } => Some(sid),
            AceData::AccessDeniedCallbackObject { sid, .. } => Some(sid),
            AceData::SystemAuditCallback { sid, .. } => Some(sid),
            AceData::SystemAuditCallbackObject { sid, .. } => Some(sid),
            AceData::SystemMandatoryLabel { sid, .. } => Some(sid),
            AceData::SystemResourceAttribute { sid, .. } => Some(sid),
            AceData::SystemScopedPolicyId { sid, .. } => Some(sid),
            AceData::Other { .. } => None,
        }
    }
}

// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/628ebb1d-c509-4ea0-a10f-77ef97ca4586
#[bitmask(u8)]
#[bitmask_config(vec_debug)]
#[derive(Deserialize, Serialize)]
pub enum AceFlags {
    ObjectInherit = 0x01,
    ContainerInherit = 0x02,
    NoPropagateInherit = 0x04,
    InheritOnly = 0x08,
    Inherited = 0x10,
    SuccessfulAccessFlag = 0x40,
    FailedAccessFlag = 0x80,
}

// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/628ebb1d-c509-4ea0-a10f-77ef97ca4586
#[derive(Clone, Debug, Deserialize, Hash, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct Ace {
    // type: u8
    pub flags: AceFlags,
    // size: u16
    pub data: AceData,
    pub application_data: Vec<u8>,
}
impl Ace {
    pub fn get_length(bytes: &[u8]) -> Option<usize> {
        if bytes.len() < 4 {
            // not even a complete header
            return None;
        }
        let ace_size = u16::from_le_bytes(bytes[2..4].try_into().unwrap());
        Some(ace_size.into())
    }

    pub fn try_from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 4 {
            // not even a complete header
            return None;
        }
        let ace_type = bytes[0];
        let flags: AceFlags = bytes[1].into();
        let ace_size: usize = u16::from_le_bytes(bytes[2..4].try_into().unwrap()).into();
        if ace_size != bytes.len() {
            // incorrect size
            return None;
        }

        let payload = &bytes[4..];
        match ace_type {
            0x00|0x01|0x02|0x09|0x0A|0x0D|0x13 => {
                // access mask and SID
                if payload.len() < 4 {
                    return None;
                }
                let mask: AccessMask = u32::from_le_bytes(payload[0..4].try_into().unwrap()).into();
                let sid_size = Sid::get_length(&payload[4..])?;
                let sid = Sid::try_from_bytes(&payload[4..4+sid_size])?;
                let application_data = payload[4+sid_size..].to_vec();
                let data = match ace_type {
                    0x00 => AceData::AccessAllowed { mask, sid },
                    0x01 => AceData::AccessDenied { mask, sid },
                    0x02 => AceData::SystemAudit { mask, sid },
                    0x09 => AceData::AccessAllowedCallback { mask, sid },
                    0x0A => AceData::AccessDeniedCallback { mask, sid },
                    0x0D => AceData::SystemAuditCallback { mask, sid },
                    0x13 => AceData::SystemScopedPolicyId { mask, sid },
                    _ => unreachable!(),
                };
                Some(Self {
                    flags,
                    data,
                    application_data,
                })
            },
            0x05|0x06|0x07|0x0B|0x0C|0x0F => {
                // access mask, flags, possibly object type, possibly inherited object type, SID
                if payload.len() < 8 {
                    return None;
                }
                let mask: AccessMask = u32::from_le_bytes(payload[0..4].try_into().unwrap()).into();
                let object_flags = u32::from_le_bytes(payload[4..8].try_into().unwrap());

                let mut payload_offset = 8;

                let object_type = if object_flags & 0b01 == 0 {
                    None
                } else {
                    if payload.len() - payload_offset < 16 {
                        return None;
                    }
                    let uuid = Uuid::from_slice_le(&payload[payload_offset..payload_offset+16]).unwrap();
                    payload_offset += 16;
                    Some(uuid)
                };

                let inherited_object_type = if object_flags & 0b10 == 0 {
                    None
                } else {
                    if payload.len() - payload_offset < 16 {
                        return None;
                    }
                    let uuid = Uuid::from_slice_le(&payload[payload_offset..payload_offset+16]).unwrap();
                    payload_offset += 16;
                    Some(uuid)
                };

                let sid_size = Sid::get_length(&payload[payload_offset..])?;
                let sid = Sid::try_from_bytes(&payload[payload_offset..payload_offset+sid_size])?;
                payload_offset += sid_size;

                let application_data = payload[payload_offset..].to_vec();

                let data = match ace_type {
                    0x05 => AceData::AccessAllowedObject { mask, flags: object_flags, object_type, inherited_object_type, sid },
                    0x06 => AceData::AccessDeniedObject { mask, flags: object_flags, object_type, inherited_object_type, sid },
                    0x07 => AceData::SystemAuditObject { mask, flags: object_flags, object_type, inherited_object_type, sid },
                    0x0B => AceData::AccessAllowedCallbackObject { mask, flags: object_flags, object_type, inherited_object_type, sid },
                    0x0C => AceData::AccessDeniedCallbackObject { mask, flags: object_flags, object_type, inherited_object_type, sid },
                    0x0F => AceData::SystemAuditCallbackObject { mask, flags: object_flags, object_type, inherited_object_type, sid },
                    _ => unreachable!(),
                };
                Some(Self {
                    flags,
                    data,
                    application_data,
                })
            },
            0x11 => {
                // mandatory mask and SID
                if payload.len() < 4 {
                    return None;
                }
                let mask: MandatoryMask = u32::from_le_bytes(payload[0..4].try_into().unwrap()).into();
                let sid_size = Sid::get_length(&payload[4..])?;
                let sid = Sid::try_from_bytes(&payload[4..4+sid_size])?;
                let application_data = payload[4+sid_size..].to_vec();
                let data = AceData::SystemMandatoryLabel { mask, sid };
                Some(Self {
                    flags,
                    data,
                    application_data,
                })
            },
            0x12 => {
                // mask, SID and ClaimSecurityAttribute1
                if payload.len() < 4 {
                    return None;
                }
                let mask: AccessMask = u32::from_le_bytes(payload[0..4].try_into().unwrap()).into();
                let sid_size = Sid::get_length(&payload[4..])?;
                let sid = Sid::try_from_bytes(&payload[4..4+sid_size])?;
                let attribute_data = ClaimSecurityAttribute1::try_from_bytes(&payload[4+sid_size..])?;
                let data = AceData::SystemResourceAttribute { mask, sid, attribute_data };
                let application_data = Vec::with_capacity(0);
                Some(Self {
                    flags,
                    data,
                    application_data,
                })
            },
            other => {
                let application_data = bytes[4..].to_vec();
                Some(Self {
                    flags,
                    data: AceData::Other { kind: other },
                    application_data,
                })
            },
        }
    }
}

// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/20233ed8-a6c6-4097-aafa-dd545ed24428
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[from_to_other(base_type = u8, derive_compare = "as_int")]
pub(crate) enum AclRevision {
    Revision = 0x02,
    Ds = 0x04,
    Other(u8),
}

// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/20233ed8-a6c6-4097-aafa-dd545ed24428
#[derive(Clone, Debug, Deserialize, Hash, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct Acl {
    pub revision: AclRevision,
    pub sbz1: u8,
    // acl_size: u16,
    // ace_count: u16,
    pub sbz2: u16,
    pub entries: Vec<Ace>,
}
impl Acl {
    pub fn get_length(bytes: &[u8]) -> Option<usize> {
        if bytes.len() < 8 {
            // not even a complete header
            return None;
        }
        let revision = AclRevision::from(bytes[0]);
        if let AclRevision::Other(_) = revision {
            // invalid revision
            return None;
        }
        let acl_size = u16::from_le_bytes(bytes[2..4].try_into().unwrap());
        Some(acl_size.into())
    }

    pub fn try_from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 8 {
            // not even a complete header
            return None;
        }
        let revision = AclRevision::from(bytes[0]);
        if let AclRevision::Other(_) = revision {
            // invalid revision
            return None;
        }
        let sbz1 = bytes[1];
        let acl_size: usize = u16::from_le_bytes(bytes[2..4].try_into().unwrap()).try_into().unwrap();
        if bytes.len() != acl_size {
            // wrong size
            return None;
        }
        let ace_count = u16::from_le_bytes(bytes[4..6].try_into().unwrap());
        let sbz2 = u16::from_le_bytes(bytes[6..8].try_into().unwrap());

        let mut current_offset = 8;
        let mut entries = Vec::new();
        for _ in 0..ace_count {
            let ace_size = Ace::get_length(&bytes[current_offset..])?;
            if current_offset + ace_size > bytes.len() {
                return None;
            }
            let ace = Ace::try_from_bytes(&bytes[current_offset..current_offset+ace_size])?;
            current_offset += ace_size;
            entries.push(ace);
        }
        Some(Self {
            revision,
            sbz1,
            sbz2,
            entries,
        })
    }

    pub fn try_to_string(&self) -> Option<String> {
        let mut ret = String::new();
        for ace in &self.entries {
            if ace.application_data.len() > 0 {
                // bail out early
                return None;
            }

            write!(ret, "(").unwrap();
            let ace_type = match &ace.data {
                AceData::AccessAllowed { .. } => "A",
                AceData::AccessDenied { .. } => "D",
                AceData::SystemAudit { .. } => "AU",
                AceData::AccessAllowedObject { .. } => "OA",
                AceData::AccessDeniedObject { .. } => "OD",
                AceData::SystemAuditObject { .. } => "OU",
                AceData::AccessAllowedCallback { .. } => "XA",
                AceData::AccessDeniedCallback { .. } => "XD",
                AceData::AccessAllowedCallbackObject { .. } => "ZA",
                AceData::AccessDeniedCallbackObject { .. } => return None, // unsupported!
                AceData::SystemAuditCallback { .. } => "XU",
                AceData::SystemAuditCallbackObject { .. } => return None, // unsupported!
                AceData::SystemMandatoryLabel { .. } => "ML",
                AceData::SystemResourceAttribute { .. } => "RA",
                AceData::SystemScopedPolicyId { .. } => "SP",
                AceData::Other { .. } => return None,
            };
            write!(ret, "{};", ace_type).unwrap();
            if ace.flags != ace.flags.truncate() {
                // some of the flags are not known
                return None;
            }
            if ace.flags.contains(AceFlags::ContainerInherit) {
                write!(ret, "CI").unwrap();
            }
            if ace.flags.contains(AceFlags::ObjectInherit) {
                write!(ret, "OI").unwrap();
            }
            if ace.flags.contains(AceFlags::NoPropagateInherit) {
                write!(ret, "NP").unwrap();
            }
            if ace.flags.contains(AceFlags::InheritOnly) {
                write!(ret, "IO").unwrap();
            }
            if ace.flags.contains(AceFlags::Inherited) {
                write!(ret, "ID").unwrap();
            }
            if ace.flags.contains(AceFlags::SuccessfulAccessFlag) {
                write!(ret, "SA").unwrap();
            }
            if ace.flags.contains(AceFlags::FailedAccessFlag) {
                write!(ret, "FA").unwrap();
            }
            write!(ret, ";").unwrap();
            if let Some(mask) = ace.data.access_mask() {
                if mask != mask.truncate() {
                    // contains unknown flags
                    return None;
                }
                if mask.contains(AccessMask::DsCreateChild) {
                    write!(ret, "CC").unwrap();
                }
                if mask.contains(AccessMask::DsDeleteChild) {
                    write!(ret, "DC").unwrap();
                }
                if mask.contains(AccessMask::DsListChildren) {
                    write!(ret, "LC").unwrap();
                }
                if mask.contains(AccessMask::DsSelfWrite) {
                    write!(ret, "SW").unwrap();
                }
                if mask.contains(AccessMask::DsReadProp) {
                    write!(ret, "RP").unwrap();
                }
                if mask.contains(AccessMask::DsWriteProp) {
                    write!(ret, "WP").unwrap();
                }
                if mask.contains(AccessMask::DsDeleteTree) {
                    write!(ret, "DT").unwrap();
                }
                if mask.contains(AccessMask::DsListObject) {
                    write!(ret, "LO").unwrap();
                }
                if mask.contains(AccessMask::DsControlAccess) {
                    write!(ret, "CR").unwrap();
                }
                if mask.contains(AccessMask::Delete) {
                    write!(ret, "SD").unwrap();
                }
                if mask.contains(AccessMask::ReadControl) {
                    write!(ret, "RC").unwrap();
                }
                if mask.contains(AccessMask::WriteDacl) {
                    write!(ret, "WD").unwrap();
                }
                if mask.contains(AccessMask::WriteOwner) {
                    write!(ret, "WO").unwrap();
                }
            } else if let AceData::SystemMandatoryLabel { mask, .. } = &ace.data {
                if *mask != mask.truncate() {
                    // contains unknown flags
                    return None;
                }
                if mask.contains(MandatoryMask::NoReadUp) {
                    write!(ret, "NR").unwrap();
                }
                if mask.contains(MandatoryMask::NoWriteUp) {
                    write!(ret, "NW").unwrap();
                }
                if mask.contains(MandatoryMask::NoExecuteUp) {
                    write!(ret, "NX").unwrap();
                }
            } else {
                return None;
            }
            write!(ret, ";").unwrap();
            if let Some(object_guid) = ace.data.object_guid() {
                write!(ret, "{}", object_guid).unwrap();
            }
            write!(ret, ";").unwrap();
            if let Some(inherit_object_guid) = ace.data.inherit_object_guid() {
                write!(ret, "{}", inherit_object_guid).unwrap();
            }
            write!(ret, ";").unwrap();
            if let Some(sid) = ace.data.sid() {
                let sid_string = sid.to_sddl_sid_string();
                write!(ret, "{}", sid_string).unwrap();
            } else {
                return None;
            }
            write!(ret, ")").unwrap();
        }
        Some(ret)
    }
}


#[bitmask(u16)]
#[bitmask_config(vec_debug)]
#[derive(Deserialize, Serialize)]
pub enum SecurityDescriptorControl {
    /// The owner SID is a default value.
    OwnerDefaulted = 0x0001,

    /// The group SID is a default value.
    GroupDefaulted = 0x0002,

    /// A DACL is present in this security descriptor.
    DaclPresent = 0x0004,

    /// The security descriptor has a DACL with default values.
    DaclDefaulted = 0x0008,

    /// A SACL is present in this security descriptor.
    SaclPresent = 0x0010,

    /// The security descriptor has a SACL with default values.
    SaclDefaulted = 0x0020,

    /// Inherit the DACL in this security descriptor to child objects.
    DaclAutoInheritReq = 0x0100,

    /// Inherit the SACL in this security descriptor to child objects.
    SaclAutoInheritReq = 0x0200,

    /// The DACL in this security descriptor has been inherited from an ancestor object.
    DaclAutoInherited = 0x0400,

    /// The SACL in this security descriptor has been inherited from an ancestor object.
    SaclAutoInherited = 0x0800,

    /// The DACL is protected against entries inherited from ancestor objects.
    DaclProtected = 0x1000,

    /// The SACL is protected against entries inherited from ancestor objects.
    SaclProtected = 0x2000,

    /// The resource manager control is valid.
    RmControlValid = 0x4000,

    /// The security descriptor is self-relative.
    ///
    /// This means that the `owner`, `group`, `sacl` and `dacl` fields are all offsets from the
    /// beginning of the structure. If this bit is not set, the security descriptor is absolute,
    /// meaning the four fields are pointers to these structures in memory.
    ///
    /// Serialized security descriptors must be self-relative.
    SelfRelative = 0x8000,
}


#[derive(Clone, Debug, Deserialize, Hash, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct SecurityDescriptor {
    pub revision: u8,
    pub sbz1: u8,
    pub control: SecurityDescriptorControl,
    pub owner: Option<Sid>,
    pub group: Option<Sid>,
    pub sacl: Option<Acl>,
    pub dacl: Option<Acl>,
}
impl SecurityDescriptor {
    pub fn try_from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 20 {
            // revision, sbz1, control and the four offset fields are always present
            return None;
        }

        let revision = bytes[0];
        if revision != 1 {
            return None;
        }
        let sbz1 = bytes[1];
        let control_word = u16::from_le_bytes(bytes[2..4].try_into().unwrap());
        let control = SecurityDescriptorControl::from(control_word);
        if !control.contains(SecurityDescriptorControl::SelfRelative) {
            // invalid serialization
            return None;
        }

        let offset_owner: usize = u32::from_le_bytes(bytes[4..8].try_into().unwrap()).try_into().unwrap();
        let offset_group: usize = u32::from_le_bytes(bytes[8..12].try_into().unwrap()).try_into().unwrap();
        let offset_sacl: usize = u32::from_le_bytes(bytes[12..16].try_into().unwrap()).try_into().unwrap();
        let offset_dacl: usize = u32::from_le_bytes(bytes[16..20].try_into().unwrap()).try_into().unwrap();

        let owner = if offset_owner == 0 {
            None
        } else {
            if offset_owner >= bytes.len() {
                return None;
            }

            let owner_sid_size = Sid::get_length(&bytes[offset_owner..])?;
            let owner = Sid::try_from_bytes(&bytes[offset_owner..offset_owner+owner_sid_size])?;
            Some(owner)
        };
        let group = if offset_group == 0 {
            None
        } else {
            if offset_group >= bytes.len() {
                return None;
            }

            let group_sid_size = Sid::get_length(&bytes[offset_group..])?;
            let group = Sid::try_from_bytes(&bytes[offset_group..offset_group+group_sid_size])?;
            Some(group)
        };

        let sacl = if offset_sacl == 0 {
            None
        } else {
            if offset_sacl >= bytes.len() {
                return None;
            }

            let sacl_size = Acl::get_length(&bytes[offset_sacl..])?;
            let sacl = Acl::try_from_bytes(&bytes[offset_sacl..offset_sacl+sacl_size])?;
            Some(sacl)
        };
        let dacl = if offset_dacl == 0 {
            None
        } else {
            if offset_dacl >= bytes.len() {
                return None;
            }

            let dacl_size = Acl::get_length(&bytes[offset_dacl..])?;
            let dacl = Acl::try_from_bytes(&bytes[offset_dacl..offset_dacl+dacl_size])?;
            Some(dacl)
        };

        Some(Self {
            revision,
            sbz1,
            control,
            owner,
            group,
            sacl,
            dacl,
        })
    }

    pub fn try_to_string(&self) -> Option<String> {
        if self.control.intersects(
                SecurityDescriptorControl::OwnerDefaulted
                | SecurityDescriptorControl::GroupDefaulted
                | SecurityDescriptorControl::DaclDefaulted
                | SecurityDescriptorControl::SaclDefaulted
                | SecurityDescriptorControl::RmControlValid
        ) {
            // SDDL cannot handle these flags
            return None;
        }

        let mut ret = String::new();
        if let Some(owner) = self.owner.as_ref() {
            write!(ret, "O:{}", owner.to_sddl_sid_string()).unwrap();
        }
        if let Some(group) = self.group.as_ref() {
            write!(ret, "G:{}", group.to_sddl_sid_string()).unwrap();
        }
        if let Some(dacl) = self.dacl.as_ref() {
            write!(ret, "D:").unwrap();
            if self.control.contains(SecurityDescriptorControl::DaclProtected) {
                write!(ret, "P").unwrap();
            }
            if self.control.contains(SecurityDescriptorControl::DaclAutoInheritReq) {
                write!(ret, "AR").unwrap();
            }
            if self.control.contains(SecurityDescriptorControl::DaclAutoInherited) {
                write!(ret, "AI").unwrap();
            }
            let acl_string = dacl.try_to_string()?;
            write!(ret, "{}", acl_string).unwrap();
        }
        if let Some(sacl) = self.sacl.as_ref() {
            write!(ret, "S:").unwrap();
            if self.control.contains(SecurityDescriptorControl::SaclProtected) {
                write!(ret, "P").unwrap();
            }
            if self.control.contains(SecurityDescriptorControl::SaclAutoInheritReq) {
                write!(ret, "AR").unwrap();
            }
            if self.control.contains(SecurityDescriptorControl::SaclAutoInherited) {
                write!(ret, "AI").unwrap();
            }
            let acl_string = sacl.try_to_string()?;
            write!(ret, "{}", acl_string).unwrap();
        }
        Some(ret)
    }
}
