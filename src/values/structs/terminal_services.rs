use bitflags::bitflags;
use chrono::TimeDelta;
use from_to_repr::from_to_other;
use serde::{Deserialize, Serialize};

use crate::extract_bits;


#[derive(Clone, Debug, Deserialize, Hash, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct UserParameters {
    pub legacy_data: Option<String>, // [utf16; 48]
    // signature: u16
    // property_count: u16
    pub parameters: Vec<UserParameter>,
}
impl UserParameters {
    pub fn try_from_bytes(value: &[u8]) -> Option<Self> {
        // okay, so this is funny
        // on pre-Active-Directory versions of WinNT, UserParameters was treated as a Unicode string
        // then Terminal Services started to be "efficient" and encode partially binary data there
        // however, LDAPv3 is UTF-8 => ADS takes it as UTF-16 from ntds.dit and converts it to UTF-8
        // so now we first have to convert it from UTF-8 to UTF-16
        // let's hope none of the length fields ever converts to a lone surrogate value

        let value_utf8: &str = std::str::from_utf8(value).ok()?;
        let value_utf16: Vec<u16> = value_utf8.encode_utf16().collect();

        if value_utf16.len() < 50 {
            return None;
        }
        let legacy_data = if value_utf16[0..48].iter().all(|v| *v == 0x0020) {
            // all spaces => no legacy data to mention
            None
        } else {
            String::from_utf16(&value_utf16[0..48]).ok()
        };
        if value_utf16[48] != 0x0050 {
            // capital letter P = valid signature
            return None;
        }
        let parameter_count = value_utf16[49];
        let parameter_count_usize: usize = parameter_count.into();
        let mut parameters = Vec::with_capacity(parameter_count_usize);
        let mut i = 50;
        for _ in 0..parameter_count {
            if i + 3 > value_utf16.len() {
                // fixed header won't fit
                return None;
            }
            let name_length_bytes: usize = value_utf16[i+0].into();
            let value_length_bytes: usize = value_utf16[i+1].into();
            let parameter_type = value_utf16[i+2];
            i += 3;

            if name_length_bytes % 2 != 0 {
                // invalid encoding of name
                return None;
            }
            if value_length_bytes % 2 != 0 {
                // invalid encoding of value
                return None;
            }
            let name_length_u16s = name_length_bytes / 2;
            let value_length_u16s = value_length_bytes / 2;
            if i + name_length_u16s + value_length_u16s > value_utf16.len() {
                // name and value won't fit
                return None;
            }

            let name_slice = &value_utf16[i..i+name_length_u16s];
            i += name_length_u16s;
            let value_slice = &value_utf16[i..i+value_length_u16s];
            i += value_length_u16s;

            let name = String::from_utf16(name_slice).ok()?;
            let value = Self::decode_squished_utf16_value(value_slice)?;

            let parameter = UserParameter::decode_from_name_and_value(parameter_type, name, value);
            parameters.push(parameter);
        }
        Some(Self {
            legacy_data,
            parameters,
        })
    }

    fn decode_squished_utf16_value(value_slice: &[u16]) -> Option<Vec<u8>> {
        let mut ret = Vec::with_capacity(value_slice.len());
        for word in value_slice {
            let top_byte: u8 = extract_bits!(*word, 0, 8);
            let bottom_byte: u8 = extract_bits!(*word, 8, 8);
            let top_nibble = Self::decode_squished_byte_nibble(top_byte)?;
            let bottom_nibble = Self::decode_squished_byte_nibble(bottom_byte)?;
            assert!(top_nibble <= 0xF && bottom_nibble <= 0xF);
            let byte = (top_nibble << 4) | bottom_nibble;
            ret.push(byte);
        }
        Some(ret)
    }

    fn decode_squished_byte_nibble(byte: u8) -> Option<u8> {
        if byte >= b'0' && byte <= b'9' {
            Some(byte - b'0')
        } else if byte >= b'a' && byte <= b'f' {
            Some(byte - b'a' + 10)
        } else if byte >= b'A' && byte <= b'F' {
            // be robust
            Some(byte - b'A' + 10)
        } else {
            None
        }
    }
}

#[derive(Clone, Debug, Deserialize, Hash, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub enum UserParameter {
    // name_length: u16
    // value_length: u16
    // value_type: u16 (always 0x01)
    // name: [u8; name_length]
    // value: [u8; value_length]

    CfgPresent { magic: u32 },
    CfgFlags1(CtxCfgFlags1),
    CallBack { class_id: u32 },
    KeyboardLayout { layout_id: u32 },
    MinEncryptionLevel(u8),
    NetwareLogonServer { server_name: u32 },
    WfHomeDir(String),
    WfHomeDirDrive(String),
    InitialProgram(String),
    MaxConnectionTime(TimeDelta),
    MaxDisconnectionTime(TimeDelta),
    MaxIdleTime(TimeDelta),
    WfProfilePath(String),
    Shadow(ShadowType),
    WorkDirectory(String),
    CallbackNumber(String),
    Other { name: String, value: Vec<u8> },
    OtherType { parameter_type: u16, name: String, value: Vec<u8> },
}
impl UserParameter {
    pub fn decode_from_name_and_value(parameter_type: u16, name: String, value: Vec<u8>) -> Self {
        if parameter_type != 0x0001 {
            return Self::OtherType { parameter_type, name, value };
        }

        match name.as_str() {
            "CtxCfgPresent"|"CtxCfgFlags1"|"CtxCallBack"|"CtxKeyboardLayout"
                    |"CtxNWLogonServer"|"CtxMaxConnectionTime"|"CtxMaxDisconnectionTime"
                    |"CtxMaxIdleTime"|"CtxShadow" => {
                // 32-bit integer
                if value.len() != 4 {
                    return Self::Other { name, value };
                }
                let numeric_value = u32::from_le_bytes(value.try_into().unwrap());
                match name.as_str() {
                    "CtxCfgPresent" => Self::CfgPresent { magic: numeric_value },
                    "CtxCfgFlags1" => Self::CfgFlags1(CtxCfgFlags1::from_bits_retain(numeric_value)),
                    "CtxCallBack" => Self::CallBack { class_id: numeric_value },
                    "CtxKeyboardLayout" => Self::KeyboardLayout { layout_id: numeric_value },
                    "CtxNWLogonServer" => Self::NetwareLogonServer { server_name: numeric_value },
                    "CtxMaxConnectionTime" => Self::MaxConnectionTime(TimeDelta::minutes(numeric_value.into())),
                    "CtxMaxDisconnectionTime" => Self::MaxDisconnectionTime(TimeDelta::minutes(numeric_value.into())),
                    "CtxMaxIdleTime" => Self::MaxIdleTime(TimeDelta::minutes(numeric_value.into())),
                    "CtxShadow" => Self::Shadow(ShadowType::from_base_type(numeric_value)),
                    _ => unreachable!(),
                }
            },
            "CtxMinEncryptionLevel" => {
                // 8-bit integer
                if value.len() != 1 {
                    return Self::Other { name, value };
                }
                Self::MinEncryptionLevel(value[0])
            },
            "CtxWFHomeDir"|"CtxWFHomeDirDrive"|"CtxInitialProgram"|"CtxWFProfilePath"
                    |"CtxWorkDirectory"|"CtxCallbackNumber" => {
                // ASCII string
                // try UTF-8
                let string = match String::from_utf8(value) {
                    Ok(s) => s,
                    Err(e) => return Self::Other { name, value: e.into_bytes() },
                };
                match name.as_str() {
                    "CtxWFHomeDir" => Self::WfHomeDir(string),
                    "CtxWFHomeDirDrive" => Self::WfHomeDirDrive(string),
                    "CtxInitialProgram" => Self::InitialProgram(string),
                    "CtxWFProfilePath" => Self::WfProfilePath(string),
                    "CtxWorkDirectory" => Self::WorkDirectory(string),
                    "CtxCallbackNumber" => Self::CallbackNumber(string),
                    _ => unreachable!(),
                }
            },
            _other => Self::Other { name, value },
        }
    }
}

bitflags! {
    // https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tsts/0bd1a91d-3cd6-4e97-b5fa-5cf35d90f005
    #[derive(Clone, Copy, Debug, Deserialize, Hash, Eq, Ord, PartialEq, PartialOrd, Serialize)]
    pub struct CtxCfgFlags1 : u32 {
        const DISABLE_AUDIO_REDIR = 0x0000_0004;
        const WALLPAPER_DISABLED = 0x0000_0008;
        const DISABLE_EXE = 0x0000_0010;
        const DISABLE_CLIPBOARD_REDIR = 0x0000_0020;
        const DISABLE_LPT_PORT_REDIR = 0x0000_0040;
        const DISABLE_COM_PORT_REDIR = 0x0000_0080;
        const DISABLE_DRIVE_REDIR = 0x0000_0100;
        const DISABLE_PRINTER_REDIR = 0x0000_0200;
        const USE_DEFAULT_GINA = 0x0000_0400;
        const HOME_DIRECTORY_MAP_ROOT = 0x0000_0800;
        const DISABLE_ENCRYPTION = 0x0000_1000;
        const FORCE_REDIRECTED_PRINTER_AS_DEFAULT = 0x0000_2000;
        const AUTO_REDIRECT_PRINTERS = 0x0000_4000;
        const AUTO_REDIRECT_DRIVES = 0x0000_8000;
        const LOGON_DISABLED = 0x0001_0000;
        const RECONNECT_SAME_SESSION_FROM_ANY_CLIENT = 0x0002_0000;
        const LOGOFF_NOT_DISCONNECT_IDLE_SESSION = 0x0004_0000;
        const IGNORE_CLIENT_CREDENTIALS_AND_PROMPT = 0x0008_0000;
        const INHERIT_SECURITY = 0x0010_0000;
        const INHERIT_AUTO_REDIRECT = 0x0020_0000;
        const INHERIT_MAX_IDLE_TIME = 0x0040_0000;
        const INHERIT_MAX_DISCONNECTION_TIME = 0x0080_0000;
        const INHERIT_MAX_SESSION_TIME = 0x0100_0000;
        const INHERIT_SHADOW = 0x0200_0000;
        const INHERIT_CALLBACK_NUMBER = 0x0400_0000;
        const INHERIT_CALLBACK = 0x0800_0000;
        const INHERIT_INITIAL_PROGRAM = 0x1000_0000;
        const INHERIT_RECONNECT_SAME_SESSION = 0x2000_0000;
        const INHERIT_LOGOFF_NOT_DISCONNECT_IDLE = 0x4000_0000;
        const INHERIT_AUTO_LOGON = 0x8000_0000;
    }
}

// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tsts/0bd1a91d-3cd6-4e97-b5fa-5cf35d90f005
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[from_to_other(base_type = u32, derive_compare = "as_int")]
pub enum ShadowType {
    Disable = 0,
    EnableInputNotify = 1,
    EnableInputNoNotify = 2,
    EnableNoInputNotify = 3,
    EnableNoInputNoNotify = 4,
    Other(u32),
}
impl ShadowType {
    #[allow(unused)]
    pub fn is_enabled(&self) -> Option<bool> {
        match self {
            Self::Disable => Some(false),
            Self::Other(_) => None,
            _ => Some(true),
        }
    }

    #[allow(unused)]
    pub fn allows_input(&self) -> Option<bool> {
        match self {
            Self::Disable|Self::Other(_) => None,
            Self::EnableInputNoNotify|Self::EnableInputNotify => Some(true),
            Self::EnableNoInputNotify|Self::EnableNoInputNoNotify => Some(false),
        }
    }

    #[allow(unused)]
    pub fn notifies_user(&self) -> Option<bool> {
        match self {
            Self::Disable|Self::Other(_) => None,
            Self::EnableNoInputNotify|Self::EnableInputNotify => Some(true),
            Self::EnableInputNoNotify|Self::EnableNoInputNoNotify => Some(false),
        }
    }
}
