use std::fmt;

use from_to_repr::FromToRepr;
use serde::{Deserialize, Serialize};

use crate::{bit_is_set, extract_bits};


#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub(crate) struct TextMessagingState {
    pub m2p_priority: u8,
    pub p2p_priority: u8,
    pub identity: u8,
    pub delivery_point_type: u8, // u4
    pub m2p_enabled: bool, // u1
    pub p2p_enabled: bool, // u1
    pub shared: bool, // u1
    // 1 bit reserved
}
impl TextMessagingState {
    pub fn try_from_str(value: &str) -> Option<Self> {
        // represented as a signed 32-bit integer interpreted as an unsigned 32-bit integer
        let signed: i32 = value.parse().ok()?;
        let unsigned = signed as u32;

        // if the topmost bit is set, the structure is unknown
        if bit_is_set!(unsigned, 31) {
            return None;
        }

        let m2p_priority = extract_bits!(unsigned, 0, 8);
        let p2p_priority = extract_bits!(unsigned, 8, 8);
        let identity = extract_bits!(unsigned, 16, 8);
        let delivery_point_type = extract_bits!(unsigned, 24, 4);
        let m2p_enabled = bit_is_set!(unsigned, 28);
        let p2p_enabled = bit_is_set!(unsigned, 29);
        let shared = bit_is_set!(unsigned, 30);

        Some(Self {
            m2p_priority,
            p2p_priority,
            identity,
            delivery_point_type,
            m2p_enabled,
            p2p_enabled,
            shared,
        })
    }
}


#[derive(Clone, Copy, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub(crate) struct ExchangeVersion {
    // do_not_care: u6
    pub major: u8,
    pub minor: u8,
    pub build_major: u8,
    pub build_minor: u8,
    pub build: u16,
    pub build_revision: u16, // u10
}
impl ExchangeVersion {
    pub fn try_from_str(value: &str) -> Option<Self> {
        // represented as a signed 64-bit integer interpreted as an unsigned 64-bit integer
        let signed: i64 = value.parse().ok()?;
        let unsigned = signed as u64;

        // xxxx xxAA AAAA AAII IIII IIaa aaaa aaii iiii iibb bbbb bbbb bbbb bbrr rrrr rrrr
        let build_revision = extract_bits!(unsigned, 0, 10);
        let build = extract_bits!(unsigned, 10, 16);
        let build_minor = extract_bits!(unsigned, 26, 8);
        let build_major = extract_bits!(unsigned, 34, 8);
        let minor = extract_bits!(unsigned, 42, 8);
        let major = extract_bits!(unsigned, 50, 8);

        Some(Self {
            major,
            minor,
            build_major,
            build_minor,
            build,
            build_revision,
        })
    }

    pub fn as_friendly_version(&self) -> Option<&'static str> {
        match (self.major, self.minor, self.build_major, self.build_minor, self.build, self.build_revision) {
            (0, 0, 6, 5, 6500, 0) => Some("Exchange2003"),
            (0, 1, 8, 0, 535, 0) => Some("Exchange2007"),
            (0, 10, 14, 0, 100, 0) => Some("Exchange2010"),
            (0, 20, 15, 0, 0, 0) => Some("Exchange2012"),
            (0, 30, 15, 1, 0, 0) => Some("Exchange2016"),
            (0, 40, 15, 2, 0, 0) => Some("Exchange2019"),
            (0, 50, 15, 20, 0, 0) => Some("Exchange2020"),
            _ => None,
        }
    }
}
impl fmt::Debug for ExchangeVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        if let Some(friendly_version) = self.as_friendly_version() {
            write!(f, "{}", friendly_version)
        } else {
            f.debug_struct("ExchangeVersion")
                .field("major", &self.major)
                .field("minor", &self.minor)
                .field("build_major", &self.build_major)
                .field("build_minor", &self.build_minor)
                .field("build", &self.build)
                .field("build_revision", &self.build_revision)
                .finish()
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub(crate) struct InternetEncoding {
    // do_not_care: u17
    pub use_preferred_message_format: bool, // u1
    pub message_format: MessageFormat, // u1
    pub body_format: BodyFormat, // u2
    pub mac_attachment_format: MacAttachmentFormat, // u2
    // do_not_care: u9
}
impl InternetEncoding {
    pub fn try_from_str(value: &str) -> Option<Self> {
        // represented as a signed 32-bit integer interpreted as an unsigned 32-bit integer
        let signed: i32 = value.parse().ok()?;
        let unsigned = signed as u32;

        // xxxx xxxx xAAB BMPx xxxx xxxx xxxx xxxx
        let use_preferred_message_format = bit_is_set!(unsigned, 17);
        let message_format_bool = bit_is_set!(unsigned, 18);
        let message_format = MessageFormat::from_is_mime(message_format_bool);
        let body_format_u8 = extract_bits!(unsigned, 19, 2);
        let body_format = BodyFormat::try_from_repr(body_format_u8)
            .unwrap_or(BodyFormat::TextAndHtml); // if both bits are set
        let mac_attachment_format_u8 = extract_bits!(unsigned, 21, 2);
        let mac_attachment_format = MacAttachmentFormat::try_from_repr(mac_attachment_format_u8).unwrap();

        Some(Self {
            use_preferred_message_format,
            message_format,
            body_format,
            mac_attachment_format,
        })
    }
}


#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum MessageFormat {
    Text,
    Mime,
}
impl MessageFormat {
    pub fn from_is_mime(is_mime: bool) -> Self {
        if is_mime { Self::Mime } else { Self::Text }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, FromToRepr, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[repr(u8)]
pub enum BodyFormat {
    Text = 0,
    Html = 1,
    TextAndHtml = 2,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, FromToRepr, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[repr(u8)]
pub enum MacAttachmentFormat {
    BinHex = 0,
    UuEncode = 1,
    AppleSingle = 2,
    AppleDouble = 3,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct GroupSecurityFlags {
    // u1 reserved
    pub access_type: GroupAccessType, // u2
    pub activity_status: bool, // u1
}
impl GroupSecurityFlags {
    pub fn try_from_str(value: &str) -> Option<Self> {
        // represented as a signed 32-bit integer interpreted as an unsigned 32-bit integer
        let signed: i32 = value.parse().ok()?;
        let unsigned = signed as u32;

        // xxxx xxxx xxxx xxxx xxxx xxxx xxxx STTx
        let access_type_u8 = extract_bits!(unsigned, 1, 2);
        let access_type = GroupAccessType::try_from_repr(access_type_u8).unwrap();
        let activity_status = bit_is_set!(unsigned, 3);

        Some(Self {
            access_type,
            activity_status,
        })
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, FromToRepr, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[repr(u8)]
pub enum GroupAccessType {
    None = 0,
    Private = 1,
    Secret = 2,
    Public = 3,
}


#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub(crate) struct MailboxFolderSet2 {
    pub force_save_attachment_filtering_enabled: bool, // u1 (0)
    pub silverlight_enabled: bool, // u1 (1)
    pub anonymous_features_enabled: bool, // u1 (2)
    pub unknown3: bool, // u1 (3)
    pub unknown4: bool, // u1 (4)
    pub owa_mini_enabled: bool, // u1 (5)
    pub places_enabled: bool, // u1 (6)
    pub allow_offline_on: AllowOfflineOn, // u2 (7:8)
    pub display_photos_enabled: bool, // u1 (9)
    pub set_photo_enabled: bool, // u1 (10)
    pub logon_page_light_selection_enabled: bool, // u1 (11)
    pub logon_page_public_private_selection_enabled: bool, // u1 (12)
    pub predicted_actions_enabled: bool, // u1 (13)
    pub integrated_features_enabled: bool, // u1 (14)
    pub user_diagnostic_enabled: bool, // u1 (15)
    pub facebook_enabled: bool, // u1 (16)
    pub linked_in_enabled: bool, // u1 (17)
    pub wac_external_services_enabled: bool, // u1 (18)
    pub wac_omex_enabled: bool, // u1 (19)
    pub web_parts_frame_options: WebPartsFrameOptions, // u2 (20:21)
    pub allow_copy_contacts_to_device_address_book: bool, // u1 (22)
    pub report_junk_mail_enabled: bool, // u1 (23)
    pub group_creation_enabled: bool, // u1 (24)
    pub skip_create_unified_group_custom_sharepoint_classification: bool, // u1 (25)
    pub weather_enabled: bool, // u1 (26)
    pub user_voice_enabled: bool, // u1 (27)
    pub satisfaction_enabled: bool, // u1 (28)
    pub fre_cards_enabled: bool, // u1 (29)
    pub unknown30: bool, // u1 (30)
    pub on_send_addins_disabled: bool, // u1 (31)
}
impl MailboxFolderSet2 {
    pub fn try_from_str(value: &str) -> Option<Self> {
        // represented as a signed 32-bit integer interpreted as an unsigned 32-bit integer
        let signed: i32 = value.parse().ok()?;
        let unsigned = signed as u32;

        let force_save_attachment_filtering_enabled = bit_is_set!(unsigned, 0);
        let silverlight_enabled = bit_is_set!(unsigned, 1);
        let anonymous_features_enabled = bit_is_set!(unsigned, 2);
        let unknown3 = bit_is_set!(unsigned, 3);
        let unknown4 = bit_is_set!(unsigned, 4);
        let owa_mini_enabled = bit_is_set!(unsigned, 5);
        let places_enabled = bit_is_set!(unsigned, 6);
        let allow_offline_on_u8 = extract_bits!(unsigned, 7, 2);
        let display_photos_enabled = bit_is_set!(unsigned, 9);
        let set_photo_enabled = bit_is_set!(unsigned, 10);
        let logon_page_light_selection_enabled = bit_is_set!(unsigned, 11);
        let logon_page_public_private_selection_enabled = bit_is_set!(unsigned, 12);
        let predicted_actions_enabled = bit_is_set!(unsigned, 13);
        let integrated_features_enabled = bit_is_set!(unsigned, 14);
        let user_diagnostic_enabled = bit_is_set!(unsigned, 15);
        let facebook_enabled = bit_is_set!(unsigned, 16);
        let linked_in_enabled = bit_is_set!(unsigned, 17);
        let wac_external_services_enabled = bit_is_set!(unsigned, 18);
        let wac_omex_enabled = bit_is_set!(unsigned, 19);
        let web_parts_frame_options_u8 = extract_bits!(unsigned, 20, 2);
        let allow_copy_contacts_to_device_address_book = bit_is_set!(unsigned, 22);
        let report_junk_mail_enabled = bit_is_set!(unsigned, 23);
        let group_creation_enabled = bit_is_set!(unsigned, 24);
        let skip_create_unified_group_custom_sharepoint_classification = bit_is_set!(unsigned, 25);
        let weather_enabled = bit_is_set!(unsigned, 26);
        let user_voice_enabled = bit_is_set!(unsigned, 27);
        let satisfaction_enabled = bit_is_set!(unsigned, 28);
        let fre_cards_enabled = bit_is_set!(unsigned, 29);
        let unknown30 = bit_is_set!(unsigned, 30);
        let on_send_addins_disabled = bit_is_set!(unsigned, 31);

        let allow_offline_on = AllowOfflineOn::try_from_repr(allow_offline_on_u8).unwrap();
        let web_parts_frame_options = WebPartsFrameOptions::try_from_repr(web_parts_frame_options_u8).unwrap(); // u2 (20:21);

        Some(Self {
            force_save_attachment_filtering_enabled,
            silverlight_enabled,
            anonymous_features_enabled,
            unknown3,
            unknown4,
            owa_mini_enabled,
            places_enabled,
            allow_offline_on,
            display_photos_enabled,
            set_photo_enabled,
            logon_page_light_selection_enabled,
            logon_page_public_private_selection_enabled,
            predicted_actions_enabled,
            integrated_features_enabled,
            user_diagnostic_enabled,
            facebook_enabled,
            linked_in_enabled,
            wac_external_services_enabled,
            wac_omex_enabled,
            web_parts_frame_options,
            allow_copy_contacts_to_device_address_book,
            report_junk_mail_enabled,
            group_creation_enabled,
            skip_create_unified_group_custom_sharepoint_classification,
            weather_enabled,
            user_voice_enabled,
            satisfaction_enabled,
            fre_cards_enabled,
            unknown30,
            on_send_addins_disabled,
        })
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, FromToRepr, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[repr(u8)]
pub enum AllowOfflineOn {
    Unknown = 0,
    PrivateComputersOnly = 1,
    NoComputers = 2,
    AllComputers = 3,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, FromToRepr, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[repr(u8)]
pub enum WebPartsFrameOptions {
    Deny = 0,
    AllowFrom = 1,
    None = 2,
    SameOrigin = 3,
}
