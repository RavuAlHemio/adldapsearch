pub mod exchange;


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
        const USE_AES_KEYS = 0x08000000;
    }
}

// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/11972272-09ec-4a42-bf5e-3e99b321cf55
bitflags! {
    #[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
    pub struct GroupType : i32 {
        const BUILTIN_LOCAL_GROUP = 0x00000001;
        const ACCOUNT_GROUP = 0x00000002;
        const RESOURCE_GROUP = 0x00000004;
        const UNIVERSAL_GROUP = 0x00000008;
        const APP_BASIC_GROUP = 0x00000010;
        const APP_QUERY_GROUP = 0x00000020;
        const SECURITY_ENABLED = 0x80000000u32 as i32;
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
        const DisallowDelete = 0x80000000u32 as i32;
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
        const DisallowDelete = 0x80000000u32 as i32;
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
        const DisallowDelete = 0x80000000u32 as i32;
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
        const DisallowDelete = 0x80000000u32 as i32;
    }
}

// https://learn.microsoft.com/en-us/windows/win32/adschema/a-instancetype
bitflags! {
    #[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
    pub struct InstanceType : u32 {
        const NcHead = 0x0000_0001;
        const ReplicaNotInstantiated = 0x0000_0002;
        const Writable = 0x0000_0004;
        const NcAboveHeld = 0x0000_0008;
        const NcUnderConstruction = 0x0000_0010;
        const NcBeingRemoved = 0x0000_0020;
    }
}

// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/5170a98c-091c-4d34-8ca5-fe77630f112a
bitflags! {
    #[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
    pub struct OptionalFeatureFlags : u32 {
        const Forest = 0x0000_0001;
        const Domain = 0x0000_0002;
        const Disablable = 0x0000_0004;
        const Server = 0x0000_0008;
    }
}

// https://learn.microsoft.com/en-us/windows/win32/adschema/a-pwdproperties
bitflags! {
    #[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
    pub struct PasswordProperties : u32 {
        const Complex = 0x0000_0001;
        const NoAnonChange = 0x0000_0002;
        const NoClearChange = 0x0000_0004;
        const LockoutAdmins = 0x0000_0008;
        const StoreCleartext = 0x0000_0010;
        const RefuseChange = 0x0000_0020;
        const NoLwmOwfChange = 0x0000_0040;
    }
}

// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/7c1cdf82-1ecc-4834-827e-d26ff95fb207
bitflags! {
    #[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
    pub struct SearchFlags : u32 {
        const Index = 0x0000_0001;
        const ContainerIndex = 0x0000_0002;
        const AmbiguousNameResolution = 0x0000_0004;
        const PreserveOnDelete = 0x0000_0008;
        const Copy = 0x0000_0010;
        const TupleIndex = 0x0000_0020;
        const SubtreeIndex = 0x0000_0040;
        const Confidential = 0x0000_0080;
        const NeverAuditValue = 0x0000_0100;
        const RodcFiltered = 0x0000_0200;
        const ExtendedLinkTracking = 0x0000_0400;
        const BaseOnly = 0x0000_0800;
        const PartitionSecret = 0x0000_1000;
    }
}

// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/66db6a63-52d2-4980-b87b-7b2d598dba81
bitflags! {
    #[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
    pub struct InterSiteTransportOptions : u32 {
        const IgnoreSchedules = 0x0000_0001;
        const BridgesRequired = 0x0000_0002;
    }
}

// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/d6cca73b-9696-4700-9dab-7c4e54502960
bitflags! {
    #[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
    pub struct DsConnectionOptions : u32 {
        const Generated = 0x0000_0001;
        const TwoWaySync = 0x0000_0002;
        const OverrideNotifyDefault = 0x0000_0004;
        const UseNotify = 0x0000_0008;
        const DisableIntersiteCompression = 0x0000_0010;
        const UserOwnedSchedule = 0x0000_0020;
        const RodcTopology = 0x0000_0040;
    }
}

// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/8ebf2419-1169-4413-88e2-12a5ad499cf5
bitflags! {
    #[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
    pub struct DsaSettingsOptions : u32 {
        const IsGc = 0x0000_0001;
        const DisableInboundReplication = 0x0000_0002;
        const DisableOutboundReplication = 0x0000_0004;
        const DisableNtdsconnTranslation = 0x0000_0008;
        const DisableSpnRegistration = 0x0000_0010;
        const GenerateOwnTopology = 0x0000_0020;
    }
}

// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/d300c652-8873-41a4-a50c-90cc89d5bdd8
bitflags! {
    #[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
    pub struct SiteSettingsOptions : u32 {
        const AutoTopologyDisabled = 0x0000_0001;
        const TopologyCleanupDisabled = 0x0000_0002;
        const MinHopsTopologyDisabled = 0x0000_0004;
        const DetectStaleDisabled = 0x0000_0008;
        const InterSiteAutoTopologyDisabled = 0x0000_0010;
        const GroupCachingEnabled = 0x0000_0020;
        const ForceKccWhistlerBehavior = 0x0000_0040;
        const ForceKccW2kElection = 0x0000_0080;
        const RandomBridgeheadSelectionDisabled = 0x0000_0100;
        const ScheduleHashingEnabled = 0x0000_0200;
        const RedundantServerTopologyEnabled = 0x0000_0400;
    }
}

// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/f148e965-e4d7-413a-acfc-0e9a9e591708
bitflags! {
    #[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
    pub struct SiteConnectionOptions : u32 {
        const UseNotify = 0x0000_0001;
        const TwoWaySync = 0x0000_0002;
        const DisableCompression = 0x0000_0004;
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
