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
