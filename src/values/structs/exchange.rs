use std::fmt;

use from_to_repr::FromToRepr;
use serde::{Deserialize, Serialize};


#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
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
        // represented as a signed 32-bit integer
        let integer: i32 = value.parse().ok()?;

        // if the topmost bit is set (value < 0), the structure is unknown
        if integer < 0 {
            return None;
        }

        let m2p_priority = ((integer >>  0) & 0b1111_1111).try_into().unwrap();
        let p2p_priority = ((integer >>  8) & 0b1111_1111).try_into().unwrap();
        let identity = ((integer >> 16) & 0b1111_1111).try_into().unwrap();
        let delivery_point_type = ((integer >> 24) & 0b1111).try_into().unwrap();
        let m2p_enabled = (integer & (1 << 28)) != 0;
        let p2p_enabled = (integer & (1 << 29)) != 0;
        let shared = (integer & (1 << 30)) != 0;

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


#[derive(Clone, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
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
        let build_revision = ((unsigned >>  0) & ((1 << 10) - 1)).try_into().unwrap();
        let build = ((unsigned >> 10) & ((1 << 16) - 1)).try_into().unwrap();
        let build_minor = ((unsigned >> 26) & ((1 << 8) - 1)).try_into().unwrap();
        let build_major = ((unsigned >> 34) & ((1 << 8) - 1)).try_into().unwrap();
        let minor = ((unsigned >> 42) & ((1 << 8) - 1)).try_into().unwrap();
        let major = ((unsigned >> 50) & ((1 << 8) - 1)).try_into().unwrap();

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

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
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
        let use_preferred_message_format = (unsigned & (1 << 17)) != 0;
        let message_format_bool = (unsigned & (1 << 18)) != 0;
        let message_format = MessageFormat::from_is_mime(message_format_bool);
        let body_format_u8 = ((unsigned >> 19) & ((1 << 2) - 1)).try_into().unwrap();
        let body_format = BodyFormat::try_from_repr(body_format_u8)
            .unwrap_or(BodyFormat::TextAndHtml); // if both bits are set
        let mac_attachment_format_u8 = ((unsigned >> 21) & ((1 << 2) - 1)).try_into().unwrap();
        let mac_attachment_format = MacAttachmentFormat::try_from_repr(mac_attachment_format_u8).unwrap();

        Some(Self {
            use_preferred_message_format,
            message_format,
            body_format,
            mac_attachment_format,
        })
    }
}


#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum MessageFormat {
    Text,
    Mime,
}
impl MessageFormat {
    pub fn from_is_mime(is_mime: bool) -> Self {
        if is_mime { Self::Mime } else { Self::Text }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, FromToRepr, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[repr(u8)]
pub enum BodyFormat {
    Text = 0,
    Html = 1,
    TextAndHtml = 2,
}

#[derive(Clone, Debug, Deserialize, Eq, FromToRepr, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[repr(u8)]
pub enum MacAttachmentFormat {
    BinHex = 0,
    UuEncode = 1,
    AppleSingle = 2,
    AppleDouble = 3,
}
