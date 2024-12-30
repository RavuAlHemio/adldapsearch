use bitflags::bitflags;
use serde::{Deserialize, Serialize};

bitflags! {
    #[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
    pub(crate) struct AddressBookFlags : i32 {
        const SHOW_GAL_AS_DEFAULT_VIEW = 0x0000_0001;
    }

    #[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
    pub(crate) struct ProvisioningFlags : u32 {
        const RESERVED_FLAG = 0x0001;
        const EXCLUDED_FROM_PROVISIONING = 0x0002;
        const SUSPENDED_FROM_PROVISIONING = 0x0004;
        const OUT_OF_SERVICE = 0x0008;
        const EXCLUDED_FROM_INITIAL_PROVISIONING = 0x0010;
        const EXCLUDED_FROM_PROVISIONING_BY_SPACE_MONITORING = 0x0020;
        const EXCLUDED_FROM_PROVISIONING_BY_SCHEMA_VERSION_MONITORING = 0x0040;
        const EXCLUDED_FROM_PROVISIONING_FOR_DRAINING = 0x0080;
        const EXCLUDED_FROM_PROVISIONING_BY_OPERATOR = 0x0100;
        const EXCLUDED_FROM_PROVISIONING_DUE_TO_LOGICAL_CORRUPTION = 0x0200;
    }

    // https://learn.microsoft.com/en-us/powershell/exchange/recipientfilter-properties
    #[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
    pub(crate) struct ElcMailboxFlags : u32 {
        const EXPIRATION_SUSPENDED = 0x0001;
        const ELC_V2 = 0x0002;
        const DISABLE_CALENDAR_LOGGING = 0x0004;
        const LITIGATION_HOLD = 0x0008;
        const SINGLE_ITEM_RECOVERY = 0x0010;
        const VALID_ARCHIVE_DATABASE = 0x0020;
        // 0x0040 missing
        const SHOULD_USE_DEFAULT_RETENTION_POLICY = 0x0080;
        const ENABLE_SITE_MAILBOX_MESSAGE_DEDUP = 0x0100;
        const ELC_PROCESSING_DISABLED = 0x0200;
        const COMPLIANCE_TAG_HOLD = 0x0400;
    }

    #[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
    pub(crate) struct SoftDeletedStatus : u32 {
        const REMOVED = 0x0001;
        const DISABLED = 0x0002;
        const INCLUDE_IN_GARBAGE_COLLECTION = 0x0004;
        const INACTIVE = 0x0008;
    }

    #[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
    pub(crate) struct RecipientTypeDetails : i64 {
        const USER_MAILBOX = 0x0000_0000_0000_0001;
        const LINKED_MAILBOX = 0x0000_0000_0000_0002;
        const SHARED_MAILBOX = 0x0000_0000_0000_0004;
        const LEGACY_MAILBOX = 0x0000_0000_0000_0008;
        const ROOM_MAILBOX = 0x0000_0000_0000_0010;
        const EQUIPMENT_MAILBOX = 0x0000_0000_0000_0020;
        const MAIL_CONTACT = 0x0000_0000_0000_0040;
        const MAIL_USER = 0x0000_0000_0000_0080;
        const MAIL_UNIVERSAL_DISTRIBUTION_GROUP = 0x0000_0000_0000_0100;
        const MAIL_NON_UNIVERSAL_GROUP = 0x0000_0000_0000_0200;
        const MAIL_UNIVERSAL_SECURITY_GROUP = 0x0000_0000_0000_0400;
        const DYNAMIC_DISTRIBUTION_GROUP = 0x0000_0000_0000_0800;
        const PUBLIC_FOLDER = 0x0000_0000_0000_1000;
        const SYSTEM_ATTENDANT_MAILBOX = 0x0000_0000_0000_2000;
        const SYSTEM_MAILBOX = 0x0000_0000_0000_4000;
        const MAIL_FOREST_CONTACT = 0x0000_0000_0000_8000;
        const USER = 0x0000_0000_0001_0000;
        const CONTACT = 0x0000_0000_0002_0000;
        const UNIVERSAL_DISTRIBUTION_GROUP = 0x0000_0000_0004_0000;
        const UNIVERSAL_SECURITY_GROUP = 0x0000_0000_0008_0000;
        const NON_UNIVERSAL_GROUP = 0x0000_0000_0010_0000;
        const DISABLED_USER = 0x0000_0000_0020_0000;
        const MICROSOFT_EXCHANGE = 0x0000_0000_0040_0000;
        const ARBITRATION_MAILBOX = 0x0000_0000_0080_0000;
        const MAILBOX_PLAN = 0x0000_0000_0100_0000;
        const LINKED_USER = 0x0000_0000_0200_0000;
        // 0x0400_0000 missing
        // 0x0800_0000 missing
        const ROOM_LIST = 0x0000_0000_1000_0000;
        const DISCOVERY_MAILBOX = 0x0000_0000_2000_0000;
        const ROLE_GROUP = 0x0000_0000_4000_0000;
        const REMOTE_USER_MAILBOX = 0x0000_0000_8000_0000;
        const COMPUTER = 0x0000_0001_0000_0000;
        const REMOTE_ROOM_MAILBOX = 0x0000_0002_0000_0000;
        const REMOTE_EQUIPMENT_MAILBOX = 0x0000_0004_0000_0000;
        const REMOTE_SHARED_MAILBOX = 0x0000_0008_0000_0000;
        const PUBLIC_FOLDER_MAILBOX = 0x0000_0010_0000_0000;
        const TEAM_MAILBOX = 0x0000_0020_0000_0000;
        const REMOTE_TEAM_MAILBOX = 0x0000_0040_0000_0000;
        const MONITORING_MAILBOX = 0x0000_0080_0000_0000;
        const GROUP_MAILBOX = 0x0000_0100_0000_0000;
        const LINKED_ROOM_MAILBOX = 0x0000_0200_0000_0000;
        const AUDIT_LOG_MAILBOX = 0x0000_0400_0000_0000;
        const REMOTE_GROUP_MAILBOX = 0x0000_0800_0000_0000;
        const SCHEDULING_MAILBOX = 0x0000_1000_0000_0000;
        const GUEST_MAIL_USER = 0x0000_2000_0000_0000;
        const AUX_AUDIT_LOG_MAILBOX = 0x0000_4000_0000_0000;
        const SUPERVISORY_REVIEW_POLICY_MAILBOX = 0x0000_8000_0000_0000;
        const EXCHANGE_SECURITY_GROUP = 0x0001_0000_0000_0000;
    }

    #[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
    pub(crate) struct ModerationFlags : i32 {
        /// Notify senders in the organization when their messages are rejected.
        const NOTIFY_INTERNAL = 0x0000_0002;

        /// Notify senders outside of the organization when their messages are rejected.
        const NOTIFY_EXTERNAL = 0x0000_0004;
    }

    #[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
    pub(crate) struct TransportSettingFlags : i32 {
        const MESSAGE_TRACKING_READ_STATUS_DISABLED = 0x0000_0004;
        const INTERNAL_ONLY = 0x0000_0008;
        const OPEN_DOMAIN_ROUTING_DISABLED = 0x0000_0010;
        const QUERY_BASE_DN_RESTRICTION_ENABLED = 0x0000_0020;
        const ALLOW_ARCHIVE_ADDRESS_SYNC = 0x0000_0040;
        const MESSAGE_COPY_FOR_SENT_AS_ENABLED = 0x0000_0080;
        const MESSAGE_COPY_FOR_SEND_ON_BEHALF_ENABLED = 0x0000_0100;
    }

    #[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
    pub(crate) struct MobileMailboxFlags : i32 {
        const HAS_DEVICE_PARTNERSHIP = 0x0000_0001;
        const ACTIVE_SYNC_SUPPRESS_READ_RECEIPT = 0x0000_0002;
    }
}
