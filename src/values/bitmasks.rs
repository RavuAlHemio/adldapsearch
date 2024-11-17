use bitmask_enum::bitmask;
use serde::{Deserialize, Serialize};


// https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/useraccountcontrol-manipulate-account-properties
// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/dd302fd1-0aa7-406b-ad91-2a6b35738557
#[bitmask(u32)]
#[bitmask_config(vec_debug)]
#[derive(Deserialize, Serialize)]
pub enum UserAccountControl {
    SCRIPT = 0x0001,
    ACCOUNTDISABLE = 0x0002,
    HOMEDIR_REQUIRED = 0x0008,
    LOCKOUT = 0x0010,
    PASSWD_NOTREQD = 0x0020,
    PASSWD_CANT_CHANGE = 0x0040,
    ENCRYPTED_TEXT_PWD_ALLOWED = 0x0080,
    TEMP_DUPLICATE_ACCOUNT = 0x0100,
    NORMAL_ACCOUNT = 0x0200,
    INTERDOMAIN_TRUST_ACCOUNT = 0x0800,
    WORKSTATION_TRUST_ACCOUNT = 0x1000,
    SERVER_TRUST_ACCOUNT = 0x2000,
    DONT_EXPIRE_PASSWORD = 0x10000,
    MNS_LOGON_ACCOUNT = 0x20000,
    SMARTCARD_REQUIRED = 0x40000,
    TRUSTED_FOR_DELEGATION = 0x80000,
    NOT_DELEGATED = 0x100000,
    USE_DES_KEY_ONLY = 0x200000,
    DONT_REQ_PREAUTH = 0x400000,
    PASSWORD_EXPIRED = 0x800000,
    TRUSTED_TO_AUTH_FOR_DELEGATION = 0x1000000,
    NO_AUTH_DATA_REQUIRED = 0x2000000,
    PARTIAL_SECRETS_ACCOUNT = 0x04000000,
}

// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/1e38247d-8234-4273-9de3-bbf313548631
#[bitmask(i32)]
#[bitmask_config(vec_debug)]
#[derive(Deserialize, Serialize)]
pub enum SystemFlags {
    AttrNotReplicated = 0x00000001,
    CrossrefNtdsNc = 0x00000001,
    AttrReqPartialSetMember = 0x00000002,
    CrossrefNtdsDomain = 0x00000002,
    AttrIsConstructed = 0x00000004,
    CrossrefNtdsNotGcReplicated = 0x00000004,
    AttrIsOperational = 0x00000008,
    SchemaBaseObject = 0x00000010,
    AttrIsRdn = 0x00000020,
    DisallowMoveOnDelete = 0x02000000,
    DomainDisallowMove = 0x04000000,
    DomainDisallowRename = 0x08000000,
    ConfigAllowLimitedMove = 0x10000000,
    ConfigAllowMove = 0x20000000,
    ConfigAllowRename = 0x40000000,
    DisallowDelete = -0x80000000,
}

// https://learn.microsoft.com/en-us/windows/win32/adschema/a-instancetype
#[bitmask(u32)]
#[bitmask_config(vec_debug)]
#[derive(Deserialize, Serialize)]
pub enum InstanceType {
    AttrNotReplicated = 0x00000001,
    CrossrefNtdsNc = 0x00000001,
    AttrReqPartialSetMember = 0x00000002,
    CrossrefNtdsDomain = 0x00000002,
    AttrIsConstructed = 0x00000004,
    CrossrefNtdsNotGcReplicated = 0x00000004,
    AttrIsOperational = 0x00000008,
    SchemaBaseObject = 0x00000010,
    AttrIsRdn = 0x00000020,
    DisallowMoveOnDelete = 0x02000000,
    DomainDisallowMove = 0x04000000,
    DomainDisallowRename = 0x08000000,
    ConfigAllowLimitedMove = 0x10000000,
    ConfigAllowMove = 0x20000000,
    ConfigAllowRename = 0x40000000,
    DisallowDelete = 0x80000000,
}

// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/5026a939-44ba-47b2-99cf-386a9e674b04
#[bitmask(u32)]
#[bitmask_config(vec_debug)]
#[derive(Deserialize, Serialize)]
pub enum TrustDirection {
    Inbound = 0x00000001,
    Outbound = 0x00000002,
}

// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/e9a2d23c-c31e-4a6f-88a0-6646fdb51a3c
#[bitmask(u32)]
#[bitmask_config(vec_debug)]
#[derive(Deserialize, Serialize)]
pub enum TrustAttributes {
    NonTransitive = 0x00000001,
    UplevelOnly = 0x00000002,
    QuarantinedDomain = 0x00000004,
    ForestTransitive = 0x00000008,
    CrossOrganization = 0x00000010,
    WithinForest = 0x00000020,
    TreatAsExternal = 0x00000040,
    UsesRc4Encryption = 0x00000080,
    CrossOrganizationNoTgtDelegation = 0x00000200,
    PrivilegedIdentityManagementTrust = 0x00000400,
    CrossOrganizationEnableTgtDelegation = 0x00000800,
    DisableAuthTargetValidation = 0x00001000,
}

// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/6cfc7b50-11ed-4b4d-846d-6f08f0812919
#[bitmask(u32)]
#[bitmask_config(vec_debug)]
#[derive(Deserialize, Serialize)]
pub enum SupportedEncryptionTypes {
    DesCbcCrc = 0x0000_0001,
    DesCbcMd5 = 0x0000_0002,
    Rc4Hmac = 0x0000_0004,
    Aes128CtsHmacSha1_96 = 0x0000_0008,
    Aes256CtsHmacSha1_96 = 0x0000_0010,
    Aes256CtsHmacSha1_96Sk = 0x0000_0020,

    FastSupported = 0x0001_0000,
    CompoundIdentitySupported = 0x0002_0000,
    ClaimsSupported = 0x0004_0000,
    ResourceSidCompressionDisabled = 0x0008_0000,
}
