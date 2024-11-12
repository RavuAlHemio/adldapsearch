pub(crate) mod bitmasks;
pub(crate) mod enums;
pub(crate) mod oids;
pub(crate) mod structs;


use base64::prelude::{BASE64_STANDARD, Engine};
use chrono::{DateTime, Local, NaiveDate, TimeDelta, Utc};
use uuid::Uuid;

use crate::values::bitmasks::{InstanceType, SystemFlags, UserAccountControl};
use crate::values::enums::{FunctionalityLevel, SamAccountType};
use crate::values::oids::KNOWN_OIDS;
use crate::values::structs::dns::DnsProperty;
use crate::values::structs::replication::{DsaSignatureState1, ReplUpToDateVector2, RepsFromTo};


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


macro_rules! output_as_enum_or_bitflags {
    ($key:expr, $values:expr, $int_type:ty, $enum:ty) => {
        for str_value in $values {
            if let Ok(int_val) = <$int_type>::from_str_radix(&str_value, 10) {
                #[allow(irrefutable_let_patterns)]
                if int_val == 0 {
                    println!("{}: {}", $key, int_val);
                } else if let Ok(enum_val) = <$enum>::try_from(int_val) {
                    println!("{}: {} ({:?})", $key, int_val, enum_val);
                } else {
                    output_string_value_as_string($key, str_value);
                }
            } else {
                output_string_value_as_string($key, str_value);
            }
        }
    };
}

macro_rules! output_as_struct {
    ($key:expr, $values:expr, $struct:ty) => {
        for bin_value in $values {
            if let Some(struct_val) = <$struct>::try_from_bytes(bin_value) {
                let formatted = format!("{:#?}", struct_val);
                println!("{}:::", $key);
                for line in formatted.split("\n") {
                    println!(" {}", line);
                }
            } else {
                output_binary_value_as_hexdump($key, bin_value);
            }
        }
    };
}

pub(crate) fn handle_special_key(key: &str, values: &[String]) -> bool {
    if key == "userAccountControl" {
        output_as_enum_or_bitflags!(key, values, u32, UserAccountControl);
        true
    } else if key == "sAMAccountType" {
        output_as_enum_or_bitflags!(key, values, u32, SamAccountType);
        true
    } else if key == "domainControllerFunctionality" || key == "domainFunctionality" || key == "forestFunctionality" || key == "msDS-Behavior-Version" {
        output_as_enum_or_bitflags!(key, values, u32, FunctionalityLevel);
        true
    } else if key == "systemFlags" {
        output_as_enum_or_bitflags!(key, values, i32, SystemFlags);
        true
    } else if key == "instanceType" {
        output_as_enum_or_bitflags!(key, values, u32, InstanceType);
        true
    } else if key == "accountExpires" || key == "lastLogon" || key == "lastLogonTimestamp" || key == "badPasswordTime" || key == "pwdLastSet" || key == "creationTime" {
        for value in values {
            output_timestamp_value(key, value);
        }
        true
    } else if key == "supportedCapabilities" || key == "supportedControl" {
        for value in values {
            output_oid(key, value);
        }
        true
    } else if key == "lockoutDuration" || key == "lockOutObservationWindow" {
        for value in values {
            output_negative_interval_value(key, value);
        }
        true
    } else {
        false
    }
}


pub(crate) fn handle_special_binary_key(key: &str, bin_values: &[Vec<u8>]) -> bool {
    if key == "objectGUID" || key == "mS-DS-ConsistencyGuid" || key == "msExchMailboxGuid" {
        for value in bin_values {
            output_guid_value(key, value);
        }
        true
    } else if key == "objectSid" {
        for value in bin_values {
            output_sid_value(key, value);
        }
        true
    } else if key == "replUpToDateVector" {
        output_as_struct!(key, bin_values, ReplUpToDateVector2);
        true
    } else if key == "repsFrom" || key == "repsTo" {
        output_as_struct!(key, bin_values, RepsFromTo);
        true
    } else if key == "dNSProperty" {
        output_as_struct!(key, bin_values, DnsProperty);
        true
    } else if key == "dSASignature" {
        output_as_struct!(key, bin_values, DsaSignatureState1);
        true
    } else {
        false
    }
}


pub(crate) fn output_string_values(key: &str, values: &[String]) {
    if handle_special_key(key, values) {
        return;
    }

    for str_value in values {
        output_string_value_as_string(key, str_value);
    }
}


pub(crate) fn output_binary_values(key: &str, bin_values: &[Vec<u8>]) {
    if handle_special_binary_key(key, bin_values) {
        return;
    }

    for bin_value in bin_values {
        output_binary_value_as_hexdump(key, bin_value);
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
