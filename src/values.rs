pub(crate) mod bitmasks;
pub(crate) mod enums;


use base64::prelude::{BASE64_STANDARD, Engine};
use chrono::{Local, NaiveDate, TimeDelta};
use uuid::Uuid;

use crate::values::bitmasks::UserAccountControl;
use crate::values::enums::SamAccountType;



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


pub(crate) fn handle_special_key(key: &str, values: &[String]) -> bool {
    if key == "userAccountControl" {
        output_as_enum_or_bitflags!(key, values, u32, UserAccountControl);
        true
    } else if key == "sAMAccountType" {
        output_as_enum_or_bitflags!(key, values, u32, SamAccountType);
        true
    } else if key == "accountExpires" || key == "lastLogon" || key == "lastLogonTimestamp" || key == "badPasswordTime" || key == "pwdLastSet" {
        for value in values {
            output_timestamp_value(key, value);
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
