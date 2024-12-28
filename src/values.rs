pub(crate) mod bitmasks;
pub(crate) mod enums;
pub(crate) mod oids;
pub(crate) mod structs;


use base64::prelude::{BASE64_STANDARD, Engine};
use chrono::{DateTime, Local, NaiveDate, TimeDelta, Utc};
use uuid::Uuid;

use crate::values::bitmasks::{
    InstanceType, SupportedEncryptionTypes, SystemFlags, TrustAttributes, TrustDirection,
    UserAccountControl,
};
use crate::values::enums::{FunctionalityLevel, SamAccountType, TrustType};
use crate::values::oids::KNOWN_OIDS;
use crate::values::structs::dfsr::dfsr_schedule_to_string;
use crate::values::structs::dns::property::DnsProperty;
use crate::values::structs::dns::record::DnsRecord;
use crate::values::structs::replication::{DsaSignatureState1, ReplUpToDateVector2, RepsFromTo};
use crate::values::structs::schema::PrefixMap;
use crate::values::structs::security::{logon_hours_to_string, SecurityDescriptor};
use crate::values::structs::trust::TrustForestTrustInfo;


#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum LdapValue {
    String(String),
    Binary(Vec<u8>),
}


fn is_safe_ldap_string(string: &str) -> bool {
    let first_char = match string.chars().nth(0) {
        Some(fc) => fc,
        None => return true, // empty strings are safe
    };
    if first_char == '\0' || first_char == '\n' || first_char == '\r' || first_char == ' ' || first_char == ':' || first_char == '<' {
        // unsafe first character
        return false;
    }
    for c in string.chars().skip(1) {
        if c == '\0' || c == '\n' || c == '\r' {
            // unsafe following character
            return false;
        }
    }
    true
}


pub(crate) fn output_string_value_as_string(key: &str, str_value: &str) {
    if is_safe_ldap_string(&str_value) {
        println!("{}: {}", key, str_value);
    } else {
        println!("{}:: {}", key, BASE64_STANDARD.encode(str_value));
    }
}


pub(crate) fn output_binary_value_as_hexdump(key: &str, bin_value: &[u8]) {
    println!("{}:::", key);
    let mut offset = 0;
    for chunk in bin_value.chunks(16) {
        print!(" {:08X}", offset);
        offset += 16;
        for (i, b) in chunk.iter().enumerate() {
            if i == 8 {
                print!(" ");
            }
            print!(" {:02X}", *b);
        }
        println!();
    }
}


fn output_timestamp_value(key: &str, value: &str) {
    let parsed = match i64::from_str_radix(value, 10) {
        Ok(p) => p,
        Err(_) => {
            output_string_value_as_string(key, value);
            return;
        },
    };
    let windows_epoch = NaiveDate::from_ymd_opt(1601, 1, 1)
        .unwrap()
        .and_hms_opt(0, 0, 0).unwrap()
        .and_utc();
    let microseconds = TimeDelta::microseconds(parsed / 10);
    let remaining_nanoseconds = TimeDelta::nanoseconds((parsed % 10) * 100);
    let timestamp_utc = windows_epoch + microseconds + remaining_nanoseconds;
    let timestamp_local = timestamp_utc.with_timezone(&Local);
    println!("{}: {} ({})", key, value, timestamp_local.format("%Y-%m-%dT%H:%M:%S%.f%z"));
}


fn output_negative_interval_value(key: &str, value: &str) {
    let parsed = match i64::from_str_radix(value, 10) {
        Ok(p) => p,
        Err(_) => {
            output_string_value_as_string(key, value);
            return;
        },
    };
    if parsed == i64::MIN {
        println!("{}: {} (never)", key, value);
        return;
    }

    let positive = -parsed;
    let microseconds = TimeDelta::microseconds(positive / 10);
    let remaining_nanoseconds = TimeDelta::nanoseconds((positive % 10) * 100);
    let delta = microseconds + remaining_nanoseconds;
    let rest = delta.num_seconds();

    let (seconds, rest) = (rest % 60, rest / 60);
    let (minutes, rest) = (rest % 60, rest / 60);
    let (hours, rest) = (rest % 24, rest / 24);
    let days = rest;

    println!("{}: {} ({}d {}h {}min {}s)", key, value, days, hours, minutes, seconds);
}


fn output_guid_value(key: &str, value: &[u8]) {
    let bytes: [u8; 16] = match value.try_into() {
        Ok(bs) => bs,
        Err(_) => {
            // wrong length for a GUID
            output_binary_value_as_hexdump(key, value);
            return;
        },
    };
    let uuid = Uuid::from_bytes_le(bytes);
    println!("{}: {}", key, uuid);
}


fn output_sid_value(key: &str, value: &[u8]) {
    if value.len() < 8 {
        output_binary_value_as_hexdump(key, value);
        return;
    }
    let version = value[0];
    if version != 0x01 {
        // we only know how to output version 1 SIDs
        output_binary_value_as_hexdump(key, value);
        return;
    }
    let num_subs: usize = value[1].into();
    if value.len() != 8 + 4*num_subs {
        // incorrect number of subauthority elements for this subauthority count
        output_binary_value_as_hexdump(key, value);
        return;
    }

    let authority: u64 =
        // big endian
        (u64::from(value[2]) << 40)
        | (u64::from(value[3]) << 32)
        | (u64::from(value[4]) << 24)
        | (u64::from(value[5]) << 16)
        | (u64::from(value[6]) <<  8)
        | (u64::from(value[7]) <<  0)
    ;

    print!("{}: S-{}-{}", key, version, authority);
    for i in 0..num_subs {
        let sub_auth = u32::from_le_bytes(value[(8 + 4*i)..(8 + 4*i + 4)].try_into().unwrap());
        print!("-{}", sub_auth);
    }
    println!();
}


fn output_oid(key: &str, str_value: &str) {
    if let Some(known_oid) = KNOWN_OIDS.get(str_value) {
        println!("{}: {} ({})", key, str_value, known_oid);
    } else {
        output_string_value_as_string(key, str_value);
    }
}


fn output_utf16_string_with_bom(key: &str, bin_value: &[u8]) {
    if bin_value.len() % 2 != 0 {
        // invalid UTF-16
        output_binary_value_as_hexdump(key, bin_value);
        return;
    }
    if bin_value.len() < 2 {
        // missing BOM
        output_binary_value_as_hexdump(key, bin_value);
        return;
    }

    let bom = u16::from_le_bytes(bin_value[0..2].try_into().unwrap());
    let little_endian = match bom {
        0xFEFF => true,
        0xFFFE => false,
        _ => {
            // invalid BOM
            output_binary_value_as_hexdump(key, bin_value);
            return;
        },
    };

    let mut words = Vec::with_capacity(bin_value.len() / 2);
    // skip the BOM
    for chunk in bin_value.chunks(2).skip(1) {
        let word = if little_endian {
            u16::from_le_bytes(chunk.try_into().unwrap())
        } else {
            u16::from_be_bytes(chunk.try_into().unwrap())
        };
        words.push(word);
    }
    let Ok(mut string) = String::from_utf16(&words) else {
        // invalid UTF-16
        output_binary_value_as_hexdump(key, bin_value);
        return;
    };
    string = string.replace("\r\n", "\n").replace("\r", "\n");
    println!("{}:::", key);
    for line in string.split("\n") {
        println!(" {}", line);
    }
}


macro_rules! output_as_enum {
    ($key:expr, $value:expr, $int_type:ty, $enum:ty) => {
        if let Ok(int_val) = <$int_type>::from_str_radix($value, 10) {
            #[allow(irrefutable_let_patterns)]
            if int_val == 0 {
                println!("{}: {}", $key, int_val);
            } else if let Ok(enum_val) = <$enum>::try_from(int_val) {
                println!("{}: {} ({:?})", $key, int_val, enum_val);
            } else {
                output_string_value_as_string($key, $value);
            }
        } else {
            output_string_value_as_string($key, $value);
        }
    };
}

macro_rules! output_as_bitflags {
    ($key:expr, $value:expr, $int_type:ty, $enum:ty) => {
        if let Ok(int_val) = <$int_type>::from_str_radix($value, 10) {
            #[allow(irrefutable_let_patterns)]
            if int_val == 0 {
                println!("{}: {}", $key, int_val);
            } else {
                let enum_val = <$enum>::from_bits_retain(int_val);
                println!("{}: {} ({:?})", $key, int_val, enum_val);
            }
        } else {
            output_string_value_as_string($key, $value);
        }
    };
}

macro_rules! output_as_struct {
    ($key:expr, $value:expr, $struct:ty) => {
        if let Some(struct_val) = <$struct>::try_from_bytes($value) {
            let formatted = format!("{:#?}", struct_val);
            println!("{}:::", $key);
            for line in formatted.split("\n") {
                println!(" {}", line);
            }
        } else {
            output_binary_value_as_hexdump($key, $value);
        }
    };
}

macro_rules! output_stringification_result {
    ($key:expr, $value:expr, $string_func:ident) => {
        if let Some(mut string_val) = $string_func($value) {
            string_val = string_val.replace("\r\n", "\n").replace("\r", "\n");
            println!("{}:::", $key);
            for line in string_val.split("\n") {
                println!(" {}", line);
            }
        } else {
            output_binary_value_as_hexdump($key, $value);
        }
    };
}

pub(crate) fn output_special_string_value(key: &str, value: &str) -> bool {
    if key == "userAccountControl" {
        output_as_bitflags!(key, value, u32, UserAccountControl);
        true
    } else if key == "sAMAccountType" {
        output_as_enum!(key, value, u32, SamAccountType);
        true
    } else if key == "domainControllerFunctionality" || key == "domainFunctionality" || key == "forestFunctionality" || key == "msDS-Behavior-Version" {
        output_as_enum!(key, value, u32, FunctionalityLevel);
        true
    } else if key == "systemFlags" {
        output_as_bitflags!(key, value, i32, SystemFlags);
        true
    } else if key == "instanceType" {
        output_as_bitflags!(key, value, u32, InstanceType);
        true
    } else if key == "msDS-SupportedEncryptionTypes" {
        output_as_bitflags!(key, value, u32, SupportedEncryptionTypes);
        true
    } else if key == "trustAttributes" {
        output_as_bitflags!(key, value, u32, TrustAttributes);
        true
    } else if key == "trustDirection" {
        output_as_bitflags!(key, value, u32, TrustDirection);
        true
    } else if key == "trustType" {
        output_as_enum!(key, value, u32, TrustType);
        true
    } else if key == "accountExpires" || key == "lastLogon" || key == "lastLogonTimestamp" || key == "badPasswordTime" || key == "pwdLastSet" || key == "creationTime" {
        output_timestamp_value(key, value);
        true
    } else if key == "supportedCapabilities" || key == "supportedControl" {
        output_oid(key, value);
        true
    } else if key == "lockoutDuration" || key == "lockOutObservationWindow" || key == "maxPwdAge" || key == "minPwdAge" || key == "forceLogoff" {
        output_negative_interval_value(key, value);
        true
    } else {
        false
    }
}


pub(crate) fn output_special_binary_value(key: &str, value: &[u8]) -> bool {
    if key == "objectGUID" || key == "mS-DS-ConsistencyGuid" || key == "msExchMailboxGuid" || key == "msDFS-GenerationGUIDv2" || key == "msDFS-NamespaceIdentityGUIDv2" {
        output_guid_value(key, value);
        true
    } else if key == "objectSid" || key == "securityIdentifier" || key == "msExchMasterAccountSid" {
        output_sid_value(key, value);
        true
    } else if key == "replUpToDateVector" {
        output_as_struct!(key, value, ReplUpToDateVector2);
        true
    } else if key == "repsFrom" || key == "repsTo" {
        output_as_struct!(key, value, RepsFromTo);
        true
    } else if key == "dNSProperty" {
        output_as_struct!(key, value, DnsProperty);
        true
    } else if key == "dnsRecord" {
        output_as_struct!(key, value, DnsRecord);
        true
    } else if key == "dSASignature" {
        output_as_struct!(key, value, DsaSignatureState1);
        true
    } else if key == "msDS-TrustForestTrustInfo" {
        output_as_struct!(key, value, TrustForestTrustInfo);
        true
    } else if key == "prefixMap" {
        output_as_struct!(key, value, PrefixMap);
        true
    } else if key == "nTSecurityDescriptor" || key == "msExchMailboxSecurityDescriptor" {
        if let Some(sd) = SecurityDescriptor::try_from_bytes(value) {
            if let Some(sd_string) = sd.try_to_string() {
                println!("{}: {}", key, sd_string);
            } else {
                output_binary_value_as_hexdump(key, value);
            }
        } else {
            output_binary_value_as_hexdump(key, value);
        }
        true
    } else if key == "msDFS-TargetListv2" {
        output_utf16_string_with_bom(key, value);
        true
    } else if key == "logonHours" {
        output_stringification_result!(key, value, logon_hours_to_string);
        true
    } else if key == "msDFSR-Schedule" {
        output_stringification_result!(key, value, dfsr_schedule_to_string);
        true
    } else {
        false
    }
}


pub(crate) fn output_values(key: &str, values: &[LdapValue]) {
    for value in values {
        match value {
            LdapValue::Binary(bin_value) => {
                if !output_special_binary_value(key, bin_value) {
                    output_binary_value_as_hexdump(key, bin_value);
                }
            },
            LdapValue::String(str_value) => {
                if !output_special_string_value(key, str_value) {
                    output_string_value_as_string(key, str_value);
                }
            },
        }
    }
}


pub(crate) fn utc_seconds_relative_to_1601(seconds: i64) -> DateTime<Utc> {
    let windows_epoch = NaiveDate::from_ymd_opt(1601, 1, 1)
        .unwrap()
        .and_hms_opt(0, 0, 0).unwrap()
        .and_utc();
    let delta = TimeDelta::seconds(seconds);
    windows_epoch + delta
}

// 1 tick = 100ns
pub(crate) fn utc_ticks_relative_to_1601(ticks: i64) -> DateTime<Utc> {
    let windows_epoch = NaiveDate::from_ymd_opt(1601, 1, 1)
        .unwrap()
        .and_hms_opt(0, 0, 0).unwrap()
        .and_utc();
    let microseconds = TimeDelta::microseconds(ticks / 10);
    let nanoseconds = TimeDelta::nanoseconds((ticks % 10) * 100);
    let delta = microseconds + nanoseconds;
    windows_epoch + delta
}

pub(crate) fn nul_terminated_utf16le_string(bytes: &[u8]) -> Option<String> {
    let mut words = Vec::with_capacity(bytes.len() / 2);
    for chunk in bytes.chunks(2) {
        let word = u16::from_le_bytes(chunk.try_into().unwrap());
        if word == 0 {
            break;
        }
        words.push(word);
    }
    String::from_utf16(&words).ok()
}

pub(crate) fn nul_terminated_utf16le_string_at_offset(bytes: &[u8], offset: usize, zero_offset_is_null: bool) -> Option<String> {
    if zero_offset_is_null && offset == 0 {
        return None;
    }
    nul_terminated_utf16le_string(&bytes[offset..])
}
