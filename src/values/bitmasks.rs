use bitflags::bitflags;
use serde::{Deserialize, Serialize};


// https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/useraccountcontrol-manipulate-account-properties
// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/dd302fd1-0aa7-406b-ad91-2a6b35738557
bitflags! {
    #[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
    pub struct UserAccountControl : u32 {
        const SCRIPT = 0x0001;
        const ACCOUNTDISABLE = 0x0002;
        const HOMEDIR_REQUIRED = 0x0008;
        const LOCKOUT = 0x0010;
        const PASSWD_NOTREQD = 0x0020;
        const PASSWD_CANT_CHANGE = 0x0040;
        const ENCRYPTED_TEXT_PWD_ALLOWED = 0x0080;
        const TEMP_DUPLICATE_ACCOUNT = 0x0100;
        const NORMAL_ACCOUNT = 0x0200;
        const INTERDOMAIN_TRUST_ACCOUNT = 0x0800;
        const WORKSTATION_TRUST_ACCOUNT = 0x1000;
        const SERVER_TRUST_ACCOUNT = 0x2000;
        const DONT_EXPIRE_PASSWORD = 0x10000;
        const MNS_LOGON_ACCOUNT = 0x20000;
        const SMARTCARD_REQUIRED = 0x40000;
        const TRUSTED_FOR_DELEGATION = 0x80000;
        const NOT_DELEGATED = 0x100000;
        const USE_DES_KEY_ONLY = 0x200000;
        const DONT_REQ_PREAUTH = 0x400000;
        const PASSWORD_EXPIRED = 0x800000;
        const TRUSTED_TO_AUTH_FOR_DELEGATION = 0x1000000;
        const NO_AUTH_DATA_REQUIRED = 0x2000000;
        const PARTIAL_SECRETS_ACCOUNT = 0x04000000;
    }
}

// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/1e38247d-8234-4273-9de3-bbf313548631
bitflags! {
    #[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
    pub struct GenericSystemFlags : i32 {
        const DisallowMoveOnDelete = 0x02000000;
        const DomainDisallowMove = 0x04000000;
        const DomainDisallowRename = 0x08000000;
        const ConfigAllowLimitedMove = 0x10000000;
        const ConfigAllowMove = 0x20000000;
        const ConfigAllowRename = 0x40000000;
        const DisallowDelete = -0x80000000;
    }

    #[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
    pub struct CrossRefSystemFlags : i32 {
        const Nc = 0x00000001;
        const Domain = 0x00000002;
        const NotGcReplicated = 0x00000004;

        const DisallowMoveOnDelete = 0x02000000;
        const DomainDisallowMove = 0x04000000;
        const DomainDisallowRename = 0x08000000;
        const ConfigAllowLimitedMove = 0x10000000;
        const ConfigAllowMove = 0x20000000;
        const ConfigAllowRename = 0x40000000;
        const DisallowDelete = -0x80000000;
    }

    #[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
    pub struct ClassSchemaSystemFlags : i32 {
        const SchemaBaseObject = 0x00000010;

        const DisallowMoveOnDelete = 0x02000000;
        const DomainDisallowMove = 0x04000000;
        const DomainDisallowRename = 0x08000000;
        const ConfigAllowLimitedMove = 0x10000000;
        const ConfigAllowMove = 0x20000000;
        const ConfigAllowRename = 0x40000000;
        const DisallowDelete = -0x80000000;
    }

    #[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
    pub struct AttributeSchemaSystemFlags : i32 {
        const AttrNotReplicated = 0x00000001;
        const AttrReqPartialSetMember = 0x00000002;
        const AttrIsConstructed = 0x00000004;
        const AttrIsOperational = 0x00000008;
        const SchemaBaseObject = 0x00000010;
        const AttrIsRdn = 0x00000020;

        const DisallowMoveOnDelete = 0x02000000;
        const DomainDisallowMove = 0x04000000;
        const DomainDisallowRename = 0x08000000;
        const ConfigAllowLimitedMove = 0x10000000;
        const ConfigAllowMove = 0x20000000;
        const ConfigAllowRename = 0x40000000;
        const DisallowDelete = -0x80000000;
    }
}

// https://learn.microsoft.com/en-us/windows/win32/adschema/a-instancetype
bitflags! {
    #[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
    pub struct InstanceType : u32 {
        const AttrNotReplicated = 0x00000001;
        const CrossrefNtdsNc = 0x00000001;
        const AttrReqPartialSetMember = 0x00000002;
        const CrossrefNtdsDomain = 0x00000002;
        const AttrIsConstructed = 0x00000004;
        const CrossrefNtdsNotGcReplicated = 0x00000004;
        const AttrIsOperational = 0x00000008;
        const SchemaBaseObject = 0x00000010;
        const AttrIsRdn = 0x00000020;
        const DisallowMoveOnDelete = 0x02000000;
        const DomainDisallowMove = 0x04000000;
        const DomainDisallowRename = 0x08000000;
        const ConfigAllowLimitedMove = 0x10000000;
        const ConfigAllowMove = 0x20000000;
        const ConfigAllowRename = 0x40000000;
        const DisallowDelete = 0x80000000;
    }
}

// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/5026a939-44ba-47b2-99cf-386a9e674b04
bitflags! {
    #[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
    pub struct TrustDirection : u32 {
        const Inbound = 0x00000001;
        const Outbound = 0x00000002;
    }
}

// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/e9a2d23c-c31e-4a6f-88a0-6646fdb51a3c
bitflags! {
    #[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
    pub struct TrustAttributes : u32 {
        const NonTransitive = 0x00000001;
        const UplevelOnly = 0x00000002;
        const QuarantinedDomain = 0x00000004;
        const ForestTransitive = 0x00000008;
        const CrossOrganization = 0x00000010;
        const WithinForest = 0x00000020;
        const TreatAsExternal = 0x00000040;
        const UsesRc4Encryption = 0x00000080;
        const CrossOrganizationNoTgtDelegation = 0x00000200;
        const PrivilegedIdentityManagementTrust = 0x00000400;
        const CrossOrganizationEnableTgtDelegation = 0x00000800;
        const DisableAuthTargetValidation = 0x00001000;
    }
}

// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/6cfc7b50-11ed-4b4d-846d-6f08f0812919
bitflags! {
    #[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
    pub struct SupportedEncryptionTypes : u32 {
        const DesCbcCrc = 0x0000_0001;
        const DesCbcMd5 = 0x0000_0002;
        const Rc4Hmac = 0x0000_0004;
        const Aes128CtsHmacSha1_96 = 0x0000_0008;
        const Aes256CtsHmacSha1_96 = 0x0000_0010;
        const Aes256CtsHmacSha1_96Sk = 0x0000_0020;

        const FastSupported = 0x0001_0000;
        const CompoundIdentitySupported = 0x0002_0000;
        const ClaimsSupported = 0x0004_0000;
        const ResourceSidCompressionDisabled = 0x0008_0000;
    }
}
