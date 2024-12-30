pub mod exchange;


use from_to_repr::{from_to_other, FromToRepr};
use serde::{Deserialize, Serialize};


// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/b9475e91-f00f-4c25-9117-a48e70584625
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[from_to_other(base_type = u32, derive_compare = "as_int")]
pub(crate) enum Rid {
    GroupRidAdmins = 0x0200,
    GroupRidUsers = 0x0201,
    GroupRidGuests = 0x0202,
    GroupRidComputers = 0x0203,
    GroupRidControllers = 0x0204,
    GroupRidCertAdmins = 0x0205,
    GroupRidSchemaAdmins = 0x0206,
    GroupRidEnterpriseAdmins = 0x0207,
    GroupRidPolicyAdmins = 0x0208,
    GroupRidReadOnlyControllers = 0x0209,

    AliasRidAdmins = 0x0220,
    AliasRidUsers = 0x0221,
    AliasRidGuests = 0x0222,
    AliasRidPowerUsers = 0x0223,
    AliasRidAccountOps = 0x0224,
    AliasRidSystemOps = 0x0225,
    AliasRidPrintOps = 0x0226,
    AliasRidBackupOps = 0x0227,
    AliasRidReplicator = 0x0228,
    AliasRidRasServers = 0x0229,
    AliasRidPreW2kCompatAccess = 0x022A,
    AliasRidRemoteDesktopUsers = 0x022B,
    AliasRidNetworkConfigurationOps = 0x022C,
    AliasRidIncomingForestTrustBuilders = 0x022D,
    AliasRidMonitoringUsers = 0x022E,
    AliasRidLoggingUsers = 0x022F,
    AliasRidAuthorizationAccess = 0x0230,
    AliasRidTsLicenseServers = 0x0231,
    AliasRidDcomUsers = 0x0232,

    AliasRidIUsers = 0x0238,
    AliasRidCryptoOps = 0x0239,

    AliasRidCacheablePrincipalsGroup = 0x023B,
    AliasRidNonCacheablePrincipalsGroup = 0x023C,

    Other(u32),
}

// https://learn.microsoft.com/en-us/windows/win32/adschema/a-samaccounttype
#[derive(Clone, Copy, Debug, Deserialize, Eq, FromToRepr, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[repr(u32)]
pub(crate) enum SamAccountType {
    DomainObject = 0x0,
    GroupObject = 0x10000000,
    NonSecurityGroupObject = 0x10000001,
    AliasObject = 0x20000000,
    NonSecurityAliasObject = 0x20000001,
    UserObject = 0x30000000,
    MachineAccount = 0x30000001,
    TrustAccount = 0x30000002,
    AppBasicGroup = 0x40000000,
    AppQueryGroup = 0x40000001,
    AccountTypeMax = 0x7fffffff,
}


// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/d49624d0-9320-4368-8b0c-a7998ac2abdb
#[derive(Clone, Copy, Debug, Deserialize, Eq, FromToRepr, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[repr(u32)]
pub(crate) enum FunctionalityLevel {
    Win2000 = 0,
    Win2003Mixed = 1,
    Win2003 = 2,
    Win2008 = 3,
    Win2008R2 = 4,
    Win2012 = 5,
    Win2012R2 = 6,
    Win2016 = 7,
}

// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/36565693-b5e4-4f37-b0a8-c1b12138e18e
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[from_to_other(base_type = u32, derive_compare = "as_int")]
pub(crate) enum TrustType {
    Downlevel = 0x00000001,
    Uplevel = 0x00000002,
    Mit = 0x00000003,
    Dce = 0x00000004,
    AzureActiveDirectory = 0x00000005,
    Other(u32),
}

// https://learn.microsoft.com/en-us/windows/win32/ad/structural-abstract-and-auxiliary-classes
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[from_to_other(base_type = u32, derive_compare = "as_int")]
pub(crate) enum ObjectClassCategory {
    Structural = 1,
    Abstract = 2,
    Auxiliary = 3,
    Other(u32),
}

// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/7cda533e-d7a4-4aec-a517-91d02ff4a1aa
// mostly matches ASN.1 tags
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[from_to_other(base_type = u32, derive_compare = "as_int")]
pub(crate) enum OmSyntax {
    Boolean = 1,
    Integer = 2,
    BitString = 3,
    OctetString = 4,
    Null = 5,
    ObjectIdentifier = 6,
    ObjectDescriptor = 7,
    EncodingString = 8,

    Enumeration = 10,

    NumericString = 18,
    PrintableString = 19,
    TeletexString = 20,
    VideotexString = 21,
    Ia5String = 22,
    UtcTimeString = 23,
    GeneralizedTimeString = 24,
    GraphicString = 25,
    VisibleString = 26,
    GeneralString = 27,

    UnicodeString = 64,
    I8 = 65,
    ObjectSecurityDescriptor = 66,

    Object = 127,

    Other(u32),
}

// https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-replauthenticationmode
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[from_to_other(base_type = u32, derive_compare = "as_int")]
pub(crate) enum ReplAuthenticationMode {
    NegotiatePassThrough = 0x00000001,
    Negotiate = 0x00000002,
    MutualAuthRequired = 0x00000003,
    Other(u32),
}

// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/7cda533e-d7a4-4aec-a517-91d02ff4a1aa
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub(crate) enum AttributeSyntax {
    DistinguishedName,
    ObjectIdentifier,
    StringCase,
    StringTeletex,
    StringIa5,
    StringNumeric,
    DistinguishedNameBinary,
    Boolean,
    Integer,
    OctetString,
    Time,
    StringUnicode,
    Address,
    DistinguishedNameString,
    NtSecurityDescriptor,
    LargeInteger,
    Sid,
    Other(String),
}
impl AttributeSyntax {
    pub fn try_from_str(value: &str) -> Option<Self> {
        let variant = match value {
            "2.5.5.1" => Self::DistinguishedName,
            "2.5.5.2" => Self::ObjectIdentifier,
            "2.5.5.3" => Self::StringCase,
            "2.5.5.4" => Self::StringTeletex,
            "2.5.5.5" => Self::StringIa5,
            "2.5.5.6" => Self::StringNumeric,
            "2.5.5.7" => Self::DistinguishedNameBinary,
            "2.5.5.8" => Self::Boolean,
            "2.5.5.9" => Self::Integer,
            "2.5.5.10" => Self::OctetString,
            "2.5.5.11" => Self::Time,
            "2.5.5.12" => Self::StringUnicode,
            "2.5.5.13" => Self::Address,
            "2.5.5.14" => Self::DistinguishedNameString,
            "2.5.5.15" => Self::NtSecurityDescriptor,
            "2.5.5.16" => Self::LargeInteger,
            "2.5.5.17" => Self::Sid,
            other => Self::Other(other.to_owned()),
        };
        Some(variant)
    }

    #[allow(unused)]
    pub fn as_str(&self) -> &str {
        match self {
            Self::DistinguishedName => "2.5.5.1",
            Self::ObjectIdentifier => "2.5.5.2",
            Self::StringCase => "2.5.5.3",
            Self::StringTeletex => "2.5.5.4",
            Self::StringIa5 => "2.5.5.5",
            Self::StringNumeric => "2.5.5.6",
            Self::DistinguishedNameBinary => "2.5.5.7",
            Self::Boolean => "2.5.5.8",
            Self::Integer => "2.5.5.9",
            Self::OctetString => "2.5.5.10",
            Self::Time => "2.5.5.11",
            Self::StringUnicode => "2.5.5.12",
            Self::Address => "2.5.5.13",
            Self::DistinguishedNameString => "2.5.5.14",
            Self::NtSecurityDescriptor => "2.5.5.15",
            Self::LargeInteger => "2.5.5.16",
            Self::Sid => "2.5.5.17",
            Self::Other(o) => o,
        }
    }
}


// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/7cda533e-d7a4-4aec-a517-91d02ff4a1aa
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub(crate) enum OmObjectClass {
    OrName,
    AccessPoint,
    Other(Vec<u8>),
}
impl OmObjectClass {
    pub fn try_from_bytes(value: &[u8]) -> Option<Self> {
        let variant = if value == &[0x56, 0x06, 0x01, 0x02, 0x05, 0x0B, 0x1D] {
            Self::OrName
        } else if value == &[0x2B, 0x0C, 0x02, 0x87, 0x73, 0x1C, 0x00, 0x85, 0x3E] {
            Self::AccessPoint
        } else {
            Self::Other(value.to_vec())
        };
        Some(variant)
    }

    #[allow(unused)]
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Self::OrName => &[0x56, 0x06, 0x01, 0x02, 0x05, 0x0B, 0x1D],
            Self::AccessPoint => &[0x2B, 0x0C, 0x02, 0x87, 0x73, 0x1C, 0x00, 0x85, 0x3E],
            Self::Other(o) => o.as_slice(),
        }
    }
}


// https://learn.microsoft.com/en-us/windows/win32/adschema/a-serverstate
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[from_to_other(base_type = u32, derive_compare = "as_int")]
pub(crate) enum ServerState {
    Enabled = 1,
    Disabled = 2,
    Other(u32),
}
