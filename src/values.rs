pub(crate) mod bitmasks;
pub(crate) mod enums;
pub(crate) mod oids;
pub(crate) mod structs;


use std::sync::LazyLock;

use base64::prelude::{BASE64_STANDARD, Engine};
use chrono::{DateTime, Local, NaiveDate, TimeDelta, Utc};
use regex::Regex;
use uuid::Uuid;

use crate::values::bitmasks::{
    AttributeSchemaSystemFlags, ClassSchemaSystemFlags, CrossRefSystemFlags, DsaSettingsOptions,
    DsConnectionOptions, GenericSystemFlags, GroupType, InstanceType, InterSiteTransportOptions,
    OptionalFeatureFlags, PasswordProperties, SearchFlags, SiteConnectionOptions,
    SiteSettingsOptions, SupportedEncryptionTypes, TrustAttributes, TrustDirection,
    UserAccountControl,
};
use crate::values::bitmasks::exchange::{
    AddressBookFlags, ElcMailboxFlags, ModerationFlags, MobileMailboxFlags, ProvisioningFlags,
    RecipientTypeDetails, SoftDeletedStatus, TransportSettingFlags,
};
use crate::values::enums::{
    AttributeSyntax, FunctionalityLevel, ObjectClassCategory, OmObjectClass, OmSyntax,
    ReplAuthenticationMode, Rid, SamAccountType, ServerState, TrustType,
};
use crate::values::enums::exchange::{CapabilityIdentifier, RecipientDisplayType, RoleGroupType};
use crate::values::oids::KNOWN_OIDS;
use crate::values::structs::dfsr::dfsr_schedule_to_string;
use crate::values::structs::dns::property::DnsProperty;
use crate::values::structs::dns::record::DnsRecord;
use crate::values::structs::exchange::{ExchangeVersion, InternetEncoding, TextMessagingState};
use crate::values::structs::replication::{
    DsaSignatureState1, DsCorePropagationData, PartialAttributeSet, ReplPropertyMetaData,
    ReplUpToDateVector2, RepsFromTo, SiteAffinity,
};
use crate::values::structs::schema::{PrefixMap, SchemaInfo};
use crate::values::structs::security::{
    CachedMembership, logon_hours_to_string, RidPool, SecurityDescriptor,
};
use crate::values::structs::security::key_credential_link::KeyCredentialLinkBlob;
use crate::values::structs::terminal_services::UserParameters;
use crate::values::structs::trust::TrustForestTrustInfo;


const TICKS_PER_SECOND: i64 = 10_000_000;
const WINDOWS_EPOCH: DateTime<Utc> = NaiveDate::from_ymd_opt(1601, 1, 1)
    .unwrap()
    .and_hms_opt(0, 0, 0).unwrap()
    .and_utc();
static AD_TIMESTAMP_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(concat!(
    "^",
    "(?P<year>[0-9]{4})",
    "(?P<month>[0-9]{2})",
    "(?P<day>[0-9]{2})",
    "(?P<hour>[0-9]{2})",
    "(?P<minute>[0-9]{2})",
    "(?P<second>[0-9]{2})",
    "\\.(?P<fracsec>[0-9]+)",
    "Z", // timezone indicator for UTC
    "$",
)).expect("failed to parse AD timestamp regex"));


#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum LdapValue {
    String(String),
    Binary(Vec<u8>),
}
impl LdapValue {
    pub fn is_string(&self, value: &str) -> bool {
        match self {
            Self::String(s) => value == s,
            Self::Binary(_) => false,
        }
    }
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
    let microseconds = TimeDelta::microseconds(parsed / 10);
    let remaining_nanoseconds = TimeDelta::nanoseconds((parsed % 10) * 100);
    let timestamp_utc = WINDOWS_EPOCH + microseconds + remaining_nanoseconds;
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
    (@bytes, $key:expr, $value:expr, $enum:ty) => {
        if let Some(enum_val) = <$enum>::try_from_bytes($value) {
            println!("{}: {:?}", $key, enum_val);
        } else {
            output_binary_value_as_hexdump($key, $value);
        }
    };
    (@string, $key:expr, $value:expr, $enum:ty) => {
        if let Some(enum_val) = <$enum>::try_from_str($value) {
            println!("{}: {} ({:?})", $key, $value, enum_val);
        } else {
            output_string_value_as_string($key, $value);
        }
    };
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
        output_as_struct!(@perform, try_from_bytes, output_binary_value_as_hexdump, $key, $value, $struct)
    };
    (@string, $key:expr, $value:expr, $struct:ty) => {
        output_as_struct!(@perform, try_from_str, output_string_value_as_string, $key, $value, $struct)
    };
    (@perform, $try_from_func:ident, $otherwise_output_func:ident, $key:expr, $value:expr, $struct:ty) => {
        if let Some(struct_val) = <$struct>::$try_from_func($value) {
            let formatted = format!("{:#?}", struct_val);
            println!("{}:::", $key);
            for line in formatted.split("\n") {
                println!(" {}", line);
            }
        } else {
            $otherwise_output_func($key, $value);
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

pub(crate) fn output_special_string_value(key: &str, value: &str, object_classes: &[LdapValue]) -> bool {
    if key == "userAccountControl" || key == "msDs-User-Account-Control-Computed"
            || key == "msExchUserAccountControl" {
        output_as_bitflags!(key, value, u32, UserAccountControl);
        true
    } else if key == "groupType" {
        output_as_bitflags!(key, value, i32, GroupType);
        true
    } else if key == "sAMAccountType" {
        output_as_enum!(key, value, u32, SamAccountType);
        true
    } else if key == "domainControllerFunctionality" || key == "domainFunctionality"
            || key == "forestFunctionality" || key == "msDS-Behavior-Version"
            || key == "msDS-RequiredDomainBehaviorVersion"
            || key == "msDS-RequiredForestBehaviorVersion" {
        output_as_enum!(key, value, u32, FunctionalityLevel);
        true
    } else if key == "systemFlags" {
        if object_classes.iter().any(|oc| oc.is_string("crossRef")) {
            output_as_bitflags!(key, value, i32, CrossRefSystemFlags);
        } else if object_classes.iter().any(|oc| oc.is_string("classSchema")) {
            output_as_bitflags!(key, value, i32, ClassSchemaSystemFlags);
        } else if object_classes.iter().any(|oc| oc.is_string("attributeSchema")) {
            output_as_bitflags!(key, value, i32, AttributeSchemaSystemFlags);
        } else {
            output_as_bitflags!(key, value, i32, GenericSystemFlags);
        }
        true
    } else if key == "instanceType" {
        output_as_bitflags!(key, value, u32, InstanceType);
        true
    } else if key == "msDS-ReplAuthenticationMode" {
        output_as_enum!(key, value, u32, ReplAuthenticationMode);
        true
    } else if key == "msDS-OptionalFeatureFlags" {
        output_as_bitflags!(key, value, u32, OptionalFeatureFlags);
        true
    } else if key == "objectClassCategory" {
        output_as_enum!(key, value, u32, ObjectClassCategory);
        true
    } else if key == "oMSyntax" {
        output_as_enum!(key, value, u32, OmSyntax);
        true
    } else if key == "attributeSyntax" {
        output_as_enum!(@string, key, value, AttributeSyntax);
        true
    } else if key == "options" {
        if object_classes.iter().any(|oc| oc.is_string("interSiteTransport")) {
            output_as_bitflags!(key, value, u32, InterSiteTransportOptions);
            true
        } else if object_classes.iter().any(|oc| oc.is_string("nTDSConnection")) {
            output_as_bitflags!(key, value, u32, DsConnectionOptions);
            true
        } else if object_classes.iter().any(|oc| oc.is_string("nTDSDSA")) {
            output_as_bitflags!(key, value, u32, DsaSettingsOptions);
            true
        } else if object_classes.iter().any(|oc| oc.is_string("ntDSSiteSettings")) {
            output_as_bitflags!(key, value, u32, SiteSettingsOptions);
            true
        } else if object_classes.iter().any(|oc| oc.is_string("siteConnection") || oc.is_string("siteLink")) {
            output_as_bitflags!(key, value, u32, SiteConnectionOptions);
            true
        } else {
            false
        }
    } else if key == "primaryGroupID" {
        output_as_enum!(key, value, u32, Rid);
        true
    } else if key == "pwdProperties" {
        output_as_bitflags!(key, value, u32, PasswordProperties);
        true
    } else if key == "searchFlags" {
        output_as_bitflags!(key, value, u32, SearchFlags);
        true
    } else if key == "serverState" {
        output_as_enum!(key, value, u32, ServerState);
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
    } else if key == "dSCorePropagationData" {
        output_as_struct!(@string, key, value, DsCorePropagationData);
        true
    } else if key == "msDS-KeyCredentialLink" {
        output_as_struct!(@string, key, value, KeyCredentialLinkBlob);
        true
    } else if key == "rIDAllocationPool" || key == "rIDAvailablePool"
            || key == "rIDPreviousAllocationPool" || key == "rIDUsedPool" {
        output_as_struct!(@string, key, value, RidPool);
        true
    } else if key == "msExchAddressBookFlags" {
        output_as_bitflags!(key, value, i32, AddressBookFlags);
        true
    } else if key == "msExchCapabilityIdentifiers" {
        output_as_enum!(key, value, u32, CapabilityIdentifier);
        true
    } else if key == "msExchELCMailboxFlags" {
        output_as_bitflags!(key, value, u32, ElcMailboxFlags);
        true
    } else if key == "msExchMobileMailboxFlags" {
        output_as_bitflags!(key, value, i32, MobileMailboxFlags);
        true
    } else if key == "msExchModerationFlags" {
        output_as_bitflags!(key, value, i32, ModerationFlags);
        true
    } else if key == "msExchProvisioningFlags" {
        output_as_bitflags!(key, value, u32, ProvisioningFlags);
        true
    } else if key == "msExchRecipientDisplayType" {
        output_as_enum!(key, value, i32, RecipientDisplayType);
        true
    } else if key == "msExchRecipientSoftDeletedStatus" {
        output_as_bitflags!(key, value, u32, SoftDeletedStatus);
        true
    } else if key == "msExchRecipientTypeDetails" || key == "msExchPreviousRecipientTypeDetails" {
        output_as_bitflags!(key, value, i64, RecipientTypeDetails);
        true
    } else if key == "msExchRoleGroupType" {
        output_as_enum!(key, value, i32, RoleGroupType);
        true
    } else if key == "msExchTextMessagingState" {
        output_as_struct!(@string, key, value, TextMessagingState);
        true
    } else if key == "msExchTransportRecipientSettingsFlags" {
        output_as_bitflags!(key, value, i32, TransportSettingFlags);
        true
    } else if key == "msExchVersion" {
        output_as_struct!(@string, key, value, ExchangeVersion);
        true
    } else if key == "internetEncoding" {
        // technically Exchange as well
        output_as_struct!(@string, key, value, InternetEncoding);
        true
    } else if key == "accountExpires" || key == "badPasswordTime" || key == "creationTime"
            || key == "lastLogoff" || key == "lastLogon" || key == "lastLogonTimestamp"
            || key == "msDS-ApproximateLastLogonTimeStamp"
            || key == "msDS-Cached-Membership-Time-Stamp"
            || key == "msDS-KeyApproximateLastLogonTimeStamp"
            || key == "msDS-LastSuccessfulInteractiveLogonTime"
            || key == "msDS-LastFailedInteractiveLogonTime"
            || key == "msDS-UserPasswordExpiryTimeComputed"
            || key == "pwdLastSet" {
        output_timestamp_value(key, value);
        true
    } else if key == "supportedCapabilities" || key == "supportedControl"
            || key == "supportedExtension" {
        output_oid(key, value);
        true
    } else if key == "lockoutDuration" || key == "lockOutObservationWindow" || key == "maxPwdAge"
            || key == "minPwdAge" || key == "msDS-LockoutDuration"
            || key == "msDS-LockoutObservationWindow" || key == "msDS-MaximumPasswordAge"
            || key == "msDS-MinimumPasswordAge" || key == "forceLogoff" {
        output_negative_interval_value(key, value);
        true
    } else {
        false
    }

    // TODO: possibly want to convert to local time?
    // key == "createTimeStamp" || key == "currentTime" || key == "modifyTimeStamp"
    // || key == "msDS-Entry-Time-To-Die" || key == "msDS-LocalEffectiveDeletionTime"
    // || key == "msDS-LocalEffectiveRecycleTime" || key == "schemaUpdate" || key == "whenChanged"
    // || key == "whenCreated"

    // TODO: LAPS time
    // key == "ms-Mcs-AdmPwdExpirationTime" || key == "msLaps-PasswordExpirationTime"
}


pub(crate) fn output_special_binary_value(key: &str, value: &[u8]) -> bool {
    if key == "attributeSecurityGUID" || key == "invocationId" || key == "mS-DS-ConsistencyGuid"
            || key == "msDFS-GenerationGUIDv2" || key == "msDFS-LinkIdentityGUIDv2"
            || key == "msDFS-NamespaceIdentityGUIDv2" || key == "msDFSR-ContentSetGuid"
            || key == "msDFSR-ReplicationGroupGuid" || key == "msDS-DeviceID"
            || key == "msDS-OptionalFeatureGuid" || key == "msExchMailboxGuid"
            || key == "netbootGuid" || key == "objectGUID" || key == "parentGUID"
            || key == "schemaIDGUID" || key == "serverClassID" {
        output_guid_value(key, value);
        true
    } else if key == "mS-DS-CreatorSID" || key == "msDS-LdapQosPolicyTarget"
            || key == "msDS-ServiceAccountSID" || key == "msDS-ShadowPrincipalSid"
            || key == "msExchMasterAccountSid" || key == "objectSid" || key == "securityIdentifier"
            || key == "sidHistory" || key == "tokenGroups" || key == "tokenGroupsGlobalAndUniversal"
            || key == "tokenGroupsNoGCAcceptable" {
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
    } else if key == "partialAttributeSet" {
        output_as_struct!(key, value, PartialAttributeSet);
        true
    } else if key == "msDS-Site-Affinity" {
        output_as_struct!(key, value, SiteAffinity);
        true
    } else if key == "msDS-Cached-Membership" {
        output_as_struct!(key, value, CachedMembership);
        true
    } else if key == "prefixMap" {
        output_as_struct!(key, value, PrefixMap);
        true
    } else if key == "replPropertyMetaData" {
        output_as_struct!(key, value, ReplPropertyMetaData);
        true
    } else if key == "schemaInfo" {
        output_as_struct!(key, value, SchemaInfo);
        true
    } else if key == "fRSRootSecurity" || key == "msExchLogonACL"
            || key == "msExchMailboxSecurityDescriptor" || key == "msExchPFDefaultAdminACL"
            || key == "msExchSubmitRelaySD" || key == "nTSecurityDescriptor"
            || key == "pKIEnrollmentAccess" {
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
    } else if key == "oMObjectClass" {
        output_as_enum!(@bytes, key, value, OmObjectClass);
        true
    } else if key == "userParameters" {
        output_as_struct!(key, value, UserParameters);
        true
    } else {
        false
    }
}


pub(crate) fn output_values(key: &str, values: &[LdapValue], object_classes: &[LdapValue]) {
    for value in values {
        match value {
            LdapValue::Binary(bin_value) => {
                if !output_special_binary_value(key, bin_value) {
                    output_binary_value_as_hexdump(key, bin_value);
                }
            },
            LdapValue::String(str_value) => {
                if !output_special_string_value(key, str_value, object_classes) {
                    // maybe a binary value was heuristically misdetected as a string
                    if !output_special_binary_value(key, str_value.as_bytes()) {
                        output_string_value_as_string(key, str_value);
                    }
                }
            },
        }
    }
}


pub(crate) fn utc_seconds_relative_to_1601(seconds: i64) -> DateTime<Utc> {
    let delta = TimeDelta::seconds(seconds);
    WINDOWS_EPOCH + delta
}

// 1 tick = 100ns
pub(crate) fn utc_ticks_relative_to_1601(ticks: i64) -> DateTime<Utc> {
    let microseconds = TimeDelta::microseconds(ticks / 10);
    let nanoseconds = TimeDelta::nanoseconds((ticks % 10) * 100);
    let delta = microseconds + nanoseconds;
    WINDOWS_EPOCH + delta
}

pub(crate) fn ad_time_to_ticks_relative_to_1601(time_str: &str) -> Option<i64> {
    let time_caps = AD_TIMESTAMP_RE.captures(time_str)?;
    let year: i32 = time_caps.name("year").unwrap().as_str().parse().ok()?;
    let month: u32 = time_caps.name("month").unwrap().as_str().parse().ok()?;
    let day: u32 = time_caps.name("day").unwrap().as_str().parse().ok()?;
    let hour: u32 = time_caps.name("hour").unwrap().as_str().parse().ok()?;
    let minute: u32 = time_caps.name("minute").unwrap().as_str().parse().ok()?;
    let second: u32 = time_caps.name("second").unwrap().as_str().parse().ok()?;
    let mut nanos_string = time_caps.name("fracsec").unwrap().as_str().to_owned();
    nanos_string.truncate(9);
    while nanos_string.len() < 9 {
        nanos_string.push('0');
    }
    let nanos: u32 = nanos_string.parse().ok()?;

    let encoded_time = NaiveDate::from_ymd_opt(year, month, day)?
        .and_hms_nano_opt(hour, minute, second, nanos)?
        .and_utc();
    let delta = encoded_time - WINDOWS_EPOCH;
    let delta_s_part = delta.num_seconds();
    let delta_ns_part = delta.subsec_nanos();
    let delta_tick_part = delta_ns_part / 100;

    delta_s_part
        .checked_mul(TICKS_PER_SECOND)?
        .checked_add(delta_tick_part.into())
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
