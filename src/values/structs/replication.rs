use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde::de::Error as _;
use uuid::Uuid;

use crate::values::{nul_terminated_utf16le_string_at_offset, utc_seconds_relative_to_1601};


// gleaned from ldp.exe
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub(crate) struct ReplUpToDateVector2 {
    pub version: u32,
    pub reserved1: u32,
    // num_cursors: u32,
    pub reserved2: u32,
    pub cursors: Vec<Repl2Cursor>,
}
impl ReplUpToDateVector2 {
    pub fn try_from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 16 {
            return None;
        }
        let version = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
        if version != 2 {
            return None;
        }
        let reserved1 = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
        let num_cursors = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
        let reserved2 = u32::from_le_bytes(bytes[12..16].try_into().unwrap());

        let num_cursors_usize: usize = num_cursors.try_into().ok()?;
        if bytes.len() != 16 + num_cursors_usize*32 {
            // mismatch between value size and number of cursors
            return None;
        }

        let mut cursors = Vec::with_capacity(num_cursors_usize);
        for i in 0..num_cursors_usize {
            let offset = 16 + i*32;
            let byte_slice = &bytes[offset..offset+32];
            let cursor = Repl2Cursor::try_from_bytes(byte_slice)?;
            cursors.push(cursor);
        }

        Some(Self {
            version,
            reserved1,
            reserved2,
            cursors,
        })
    }
}


// gleaned from ldp.exe
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub(crate) struct Repl2Cursor {
    pub uuid_dsa: Uuid,
    pub usn_high_prop_update: u64,
    pub time_last_sync_success: DateTime<Utc>,
}
impl Repl2Cursor {
    pub fn try_from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 32 {
            return None;
        }
        let uuid_dsa = Uuid::from_bytes_le(bytes[0..16].try_into().unwrap());
        let usn_high_prop_update = u64::from_le_bytes(bytes[16..24].try_into().unwrap());

        let time_seconds = i64::from_le_bytes(bytes[24..32].try_into().unwrap());
        let time_last_sync_success = utc_seconds_relative_to_1601(time_seconds);
        Some(Self {
            uuid_dsa,
            usn_high_prop_update,
            time_last_sync_success,
        })
    }
}


// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/f8e930ea-d847-4585-8d58-993e05f55e45
// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/b422aa87-7d07-4527-b070-c5d719696c43
// (structures are equivalent)
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub(crate) struct RepsFromTo {
    pub version: u32,
    pub reserved0: u32,
    // cb: u32,
    pub consecutive_failures: u32,
    pub time_last_success: DateTime<Utc>, // u64
    pub time_last_attempt: DateTime<Utc>, // u64
    pub result_last_attempt: u32,
    pub other_dra: OtherDra, // offset: u32, length: u32
    pub replica_flags: u32,
    pub schedule: ReplTimes, // [u8; 84]
    pub reserved1: u32,
    pub usn_vec: UsnVector, // [u64; 3]
    pub dsa_object: Uuid,
    pub invocation_id: Uuid,
    pub transport_object: Uuid,
    pub reserved2: u32,
}
impl RepsFromTo {
    pub fn try_from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 212 {
            return None;
        }

        let version = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
        if version < 1 || version > 2 {
            return None;
        }
        let reserved0 = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
        let cb = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
        let cb_usize: usize = cb.try_into().unwrap();
        if cb_usize > bytes.len() {
            // announced size too large
            return None;
        }
        let consecutive_failures = u32::from_le_bytes(bytes[12..16].try_into().unwrap());
        let secs_last_success = i64::from_le_bytes(bytes[16..24].try_into().unwrap());
        let secs_last_attempt = i64::from_le_bytes(bytes[24..32].try_into().unwrap());
        let result_last_attempt = u32::from_le_bytes(bytes[32..36].try_into().unwrap());
        let other_dra_offset = u32::from_le_bytes(bytes[36..40].try_into().unwrap());
        let other_dra_length = u32::from_le_bytes(bytes[40..44].try_into().unwrap());
        let replica_flags = u32::from_le_bytes(bytes[44..48].try_into().unwrap());
        let schedule = ReplTimes::try_from_bytes(&bytes[48..132])?;
        let reserved1 = u32::from_le_bytes(bytes[132..136].try_into().unwrap());
        let usn_vec = UsnVector::try_from_bytes(&bytes[136..160])?;
        let dsa_object = Uuid::from_slice_le(&bytes[160..176]).ok()?;
        let invocation_id = Uuid::from_slice_le(&bytes[176..192]).ok()?;
        let transport_object = Uuid::from_slice_le(&bytes[192..208]).ok()?;
        let reserved2 = u32::from_le_bytes(bytes[208..212].try_into().unwrap());

        let other_dra_offset_usize: usize = other_dra_offset.try_into().unwrap();
        let other_dra_length_usize: usize = other_dra_length.try_into().unwrap();
        if other_dra_offset_usize + other_dra_length_usize > bytes.len() {
            // out-of-bounds DRA
            return None;
        }
        let other_dra_slice = &bytes[other_dra_offset_usize..other_dra_offset_usize+other_dra_length_usize];

        let other_dra = if version == 1 {
            // assemble version 1 DRA
            let mtx_addr = MtxAddr::try_from_bytes(other_dra_slice)?;
            OtherDra::V1(mtx_addr)
        } else {
            assert_eq!(version, 2);
            let dsa_rpc_inst = DsaRpcInst::try_from_bytes(other_dra_slice)?;
            OtherDra::V2(dsa_rpc_inst)
        };

        let time_last_success = utc_seconds_relative_to_1601(secs_last_success);
        let time_last_attempt = utc_seconds_relative_to_1601(secs_last_attempt);

        Some(Self {
            version,
            reserved0,
            consecutive_failures,
            time_last_success,
            time_last_attempt,
            result_last_attempt,
            other_dra,
            replica_flags,
            schedule,
            reserved1,
            usn_vec,
            dsa_object,
            invocation_id,
            transport_object,
            reserved2,
        })
    }
}


#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct ReplTimes {
    pub times: [u8; 84],
}
impl ReplTimes {
    pub fn try_from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() == 84 {
            let times = bytes.try_into().unwrap();
            Some(Self {
                times,
            })
        } else {
            None
        }
    }
}
impl<'de> Deserialize<'de> for ReplTimes {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let deserialized: Vec<u8> = Vec::deserialize(deserializer)?;
        if deserialized.len() == 84 {
            let times = deserialized.try_into().unwrap();
            Ok(ReplTimes {
                times,
            })
        } else {
            Err(D::Error::custom("unexpected number of bytes (expected 84)"))
        }
    }
}
impl Serialize for ReplTimes {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let vector = self.times.to_vec();
        vector.serialize(serializer)
    }
}


// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/595d11b8-6ca7-4a61-bd56-3e6a2b99b76b
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub(crate) struct UsnVector {
    pub usn_high_obj_update: u64,
    pub usn_reserved: u64,
    pub usn_high_prop_update: u64,
}
impl UsnVector {
    pub fn try_from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 24 {
            return None;
        }
        let usn_high_obj_update = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
        let usn_reserved = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
        let usn_high_prop_update = u64::from_le_bytes(bytes[16..24].try_into().unwrap());
        Some(Self {
            usn_high_obj_update,
            usn_reserved,
            usn_high_prop_update,
        })
    }
}

// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/595d11b8-6ca7-4a61-bd56-3e6a2b99b76b
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum OtherDra {
    V1(MtxAddr),
    V2(DsaRpcInst),
}

// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/107b7c0e-0f0d-4fe2-8232-14ec3b78f40d
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct MtxAddr {
    pub name: Vec<u8>,
}
impl MtxAddr {
    pub fn try_from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 1 {
            return None;
        }
        let byte_count: usize = bytes[0].into();
        if byte_count > bytes.len() - 1 {
            return None;
        }
        let name = bytes[1..1+byte_count].to_vec();
        Some(Self {
            name,
        })
    }
}

// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/88a39619-6dbe-4ba1-8435-5966c1a490a7
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct DsaRpcInst {
    // cb: u32,
    pub server: Option<String>, // offset: u32, NUL-terminated
    pub annotation: Option<String>, // offset: u32, NUL-terminated
    pub instance: Option<String>, // offset: u32, MtxAddr?
    pub instance_guid: Option<Uuid>, // offset: u32
}
impl DsaRpcInst {
    pub fn try_from_bytes(bytes: &[u8]) -> Option<Self> {
        let byte_count: usize = u32::from_le_bytes(bytes[0..4].try_into().unwrap()).try_into().unwrap();
        if byte_count > bytes.len() {
            return None;
        }

        // minimum is: all four offsets zero
        if byte_count < 20 {
            return None;
        }

        let server_offset: usize = u32::from_le_bytes(bytes[4..8].try_into().unwrap()).try_into().unwrap();
        let annotation_offset: usize = u32::from_le_bytes(bytes[8..12].try_into().unwrap()).try_into().unwrap();
        let instance_offset: usize = u32::from_le_bytes(bytes[12..16].try_into().unwrap()).try_into().unwrap();
        let instance_guid_offset: usize = u32::from_le_bytes(bytes[16..20].try_into().unwrap()).try_into().unwrap();

        if server_offset >= bytes.len() {
            return None;
        }
        if annotation_offset >= bytes.len() {
            return None;
        }
        if instance_offset >= bytes.len() {
            return None;
        }
        // here we know the length a priori
        if instance_guid_offset > 0 && instance_guid_offset + 16 > bytes.len() {
            return None;
        }

        let server = nul_terminated_utf16le_string_at_offset(bytes, server_offset, true);
        let annotation = nul_terminated_utf16le_string_at_offset(bytes, annotation_offset, true);
        let instance = nul_terminated_utf16le_string_at_offset(bytes, instance_offset, true);
        let instance_guid = if instance_guid_offset > 0 {
            Uuid::from_slice_le(&bytes[instance_guid_offset..instance_guid_offset+16]).ok()
        } else {
            None
        };

        Some(Self {
            server,
            annotation,
            instance,
            instance_guid,
        })
    }
}

// MS KB2789917, lost to the sands of time
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct DsaSignatureState1 {
    pub version: u32,
    // cb_size: u32,
    pub flags: u32,
    pub padding0: u32,
    pub backup_error_latency_secs: u64,
    pub dsa_guid: Uuid,
}
impl DsaSignatureState1 {
    pub fn try_from_bytes(bytes: &[u8]) -> Option<Self> {
        let version = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
        if version != 1 {
            return None;
        }

        let byte_count: usize = u32::from_le_bytes(bytes[4..8].try_into().unwrap()).try_into().unwrap();
        if byte_count > bytes.len() {
            return None;
        }
        if byte_count < 40 {
            return None;
        }

        let flags = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
        let padding0 = u32::from_le_bytes(bytes[12..16].try_into().unwrap());
        let backup_error_latency_secs = u64::from_le_bytes(bytes[16..24].try_into().unwrap());
        let dsa_guid = Uuid::from_slice_le(&bytes[24..40]).unwrap();

        Some(Self {
            version,
            flags,
            padding0,
            backup_error_latency_secs,
            dsa_guid,
        })
    }
}


#[cfg(test)]
mod tests {
    use super::{OtherDra, RepsFromTo};
    use uuid::Uuid;

    #[test]
    fn test_reps_from_to() {
        const DATA1: [u8; 524] = [
            0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x9b, 0x0e, 0x43, 0x1d, 0x03, 0x00, 0x00, 0x00, 0x9b, 0x0e, 0x43, 0x1d, 0x03, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0xd8, 0x00, 0x00, 0x00, 0x34, 0x01, 0x00, 0x00, 0x70, 0x00, 0x00, 0x00,
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            0x11, 0x11, 0x11, 0x11, 0x00, 0x00, 0x00, 0x00, 0x91, 0x6b, 0xc4, 0x3b, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x91, 0x6b, 0xc4, 0x3b, 0x00, 0x00, 0x00, 0x00,
            0x70, 0x32, 0xef, 0x5f, 0x34, 0x39, 0xf3, 0x46, 0x8b, 0x63, 0xb5, 0xfc, 0x9c, 0x55, 0xf9, 0x81,
            0x0a, 0xa1, 0x3a, 0x74, 0xb6, 0x1f, 0x11, 0x45, 0xa8, 0xfe, 0x94, 0xe4, 0xc3, 0x78, 0x77, 0x8e,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x34, 0x01, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x98, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x35, 0x00, 0x66, 0x00, 0x65, 0x00, 0x66, 0x00, 0x33, 0x00, 0x32, 0x00, 0x37, 0x00, 0x30, 0x00,
            0x2d, 0x00, 0x33, 0x00, 0x39, 0x00, 0x33, 0x00, 0x34, 0x00, 0x2d, 0x00, 0x34, 0x00, 0x36, 0x00,
            0x66, 0x00, 0x33, 0x00, 0x2d, 0x00, 0x38, 0x00, 0x62, 0x00, 0x36, 0x00, 0x33, 0x00, 0x2d, 0x00,
            0x62, 0x00, 0x35, 0x00, 0x66, 0x00, 0x63, 0x00, 0x39, 0x00, 0x63, 0x00, 0x35, 0x00, 0x35, 0x00,
            0x66, 0x00, 0x39, 0x00, 0x38, 0x00, 0x31, 0x00, 0x2e, 0x00, 0x5f, 0x00, 0x6d, 0x00, 0x73, 0x00,
            0x64, 0x00, 0x63, 0x00, 0x73, 0x00, 0x2e, 0x00, 0x61, 0x00, 0x64, 0x00, 0x74, 0x00, 0x65, 0x00,
            0x73, 0x00, 0x74, 0x00, 0x73, 0x00, 0x2e, 0x00, 0x65, 0x00, 0x78, 0x00, 0x61, 0x00, 0x6d, 0x00,
            0x70, 0x00, 0x6c, 0x00, 0x65, 0x00, 0x2e, 0x00, 0x63, 0x00, 0x6f, 0x00, 0x6d, 0x00, 0x00, 0x00,
            0x35, 0x00, 0x66, 0x00, 0x65, 0x00, 0x66, 0x00, 0x33, 0x00, 0x32, 0x00, 0x37, 0x00, 0x30, 0x00,
            0x2d, 0x00, 0x33, 0x00, 0x39, 0x00, 0x33, 0x00, 0x34, 0x00, 0x2d, 0x00, 0x34, 0x00, 0x36, 0x00,
            0x66, 0x00, 0x33, 0x00, 0x2d, 0x00, 0x38, 0x00, 0x62, 0x00, 0x36, 0x00, 0x33, 0x00, 0x2d, 0x00,
            0x62, 0x00, 0x35, 0x00, 0x66, 0x00, 0x63, 0x00, 0x39, 0x00, 0x63, 0x00, 0x35, 0x00, 0x35, 0x00,
            0x66, 0x00, 0x39, 0x00, 0x38, 0x00, 0x31, 0x00, 0x2e, 0x00, 0x5f, 0x00, 0x6d, 0x00, 0x73, 0x00,
            0x64, 0x00, 0x63, 0x00, 0x73, 0x00, 0x2e, 0x00, 0x61, 0x00, 0x64, 0x00, 0x74, 0x00, 0x65, 0x00,
            0x73, 0x00, 0x74, 0x00, 0x73, 0x00, 0x2e, 0x00, 0x65, 0x00, 0x78, 0x00, 0x61, 0x00, 0x6d, 0x00,
            0x70, 0x00, 0x6c, 0x00, 0x65, 0x00, 0x2e, 0x00, 0x63, 0x00, 0x6f, 0x00, 0x6d, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        let reps1 = RepsFromTo::try_from_bytes(&DATA1).unwrap();
        assert_eq!(reps1.version, 2);
        assert_eq!(reps1.consecutive_failures, 0);
        assert_eq!(reps1.time_last_success.timestamp(), 1731362203);
        assert_eq!(reps1.time_last_attempt.timestamp(), 1731362203);
        assert_eq!(reps1.result_last_attempt, 0);
        assert_eq!(reps1.replica_flags, 112);
        assert_eq!(reps1.usn_vec.usn_high_obj_update, 1002728337);
        assert_eq!(reps1.usn_vec.usn_high_prop_update, 1002728337);
        assert_eq!(reps1.dsa_object, Uuid::try_parse_ascii(b"5fef3270-3934-46f3-8b63-b5fc9c55f981").unwrap());
        assert_eq!(reps1.invocation_id, Uuid::try_parse_ascii(b"743aa10a-1fb6-4511-a8fe-94e4c378778e").unwrap());
        assert_eq!(reps1.transport_object, Uuid::from_u128(0));

        let reps1_other_dra = match reps1.other_dra {
            OtherDra::V1(_) => panic!("V1 DRA?!"),
            OtherDra::V2(v2) => v2,
        };
        assert_eq!(reps1_other_dra.server.as_deref(), Some("5fef3270-3934-46f3-8b63-b5fc9c55f981._msdcs.adtests.example.com"));
        assert_eq!(reps1_other_dra.annotation, None);
        assert_eq!(reps1_other_dra.instance.as_deref(), Some("5fef3270-3934-46f3-8b63-b5fc9c55f981._msdcs.adtests.example.com"));
        assert_eq!(reps1_other_dra.instance_guid, None);

        const DATA2: [u8; 524] = [
            0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x96, 0x0e, 0x43, 0x1d, 0x03, 0x00, 0x00, 0x00, 0x96, 0x0e, 0x43, 0x1d, 0x03, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0xd8, 0x00, 0x00, 0x00, 0x34, 0x01, 0x00, 0x00, 0x70, 0x00, 0x00, 0x00,
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            0x11, 0x11, 0x11, 0x11, 0x00, 0x00, 0x00, 0x00, 0x20, 0x79, 0x35, 0x0e, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x79, 0x35, 0x0e, 0x00, 0x00, 0x00, 0x00,
            0xe2, 0x8a, 0x65, 0x40, 0x4f, 0x33, 0x1a, 0x46, 0x99, 0xbd, 0x63, 0xa4, 0x2a, 0x21, 0xed, 0xc4,
            0x41, 0x4a, 0xe0, 0x93, 0x77, 0x48, 0x3b, 0x48, 0xa8, 0x00, 0x06, 0x22, 0x38, 0x72, 0xc6, 0xef,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x34, 0x01, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x98, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x34, 0x00, 0x30, 0x00, 0x36, 0x00, 0x35, 0x00, 0x38, 0x00, 0x61, 0x00, 0x65, 0x00, 0x32, 0x00,
            0x2d, 0x00, 0x33, 0x00, 0x33, 0x00, 0x34, 0x00, 0x66, 0x00, 0x2d, 0x00, 0x34, 0x00, 0x36, 0x00,
            0x31, 0x00, 0x61, 0x00, 0x2d, 0x00, 0x39, 0x00, 0x39, 0x00, 0x62, 0x00, 0x64, 0x00, 0x2d, 0x00,
            0x36, 0x00, 0x33, 0x00, 0x61, 0x00, 0x34, 0x00, 0x32, 0x00, 0x61, 0x00, 0x32, 0x00, 0x31, 0x00,
            0x65, 0x00, 0x64, 0x00, 0x63, 0x00, 0x34, 0x00, 0x2e, 0x00, 0x5f, 0x00, 0x6d, 0x00, 0x73, 0x00,
            0x64, 0x00, 0x63, 0x00, 0x73, 0x00, 0x2e, 0x00, 0x61, 0x00, 0x64, 0x00, 0x74, 0x00, 0x65, 0x00,
            0x73, 0x00, 0x74, 0x00, 0x73, 0x00, 0x2e, 0x00, 0x65, 0x00, 0x78, 0x00, 0x61, 0x00, 0x6d, 0x00,
            0x70, 0x00, 0x6c, 0x00, 0x65, 0x00, 0x2e, 0x00, 0x63, 0x00, 0x6f, 0x00, 0x6d, 0x00, 0x00, 0x00,
            0x34, 0x00, 0x30, 0x00, 0x36, 0x00, 0x35, 0x00, 0x38, 0x00, 0x61, 0x00, 0x65, 0x00, 0x32, 0x00,
            0x2d, 0x00, 0x33, 0x00, 0x33, 0x00, 0x34, 0x00, 0x66, 0x00, 0x2d, 0x00, 0x34, 0x00, 0x36, 0x00,
            0x31, 0x00, 0x61, 0x00, 0x2d, 0x00, 0x39, 0x00, 0x39, 0x00, 0x62, 0x00, 0x64, 0x00, 0x2d, 0x00,
            0x36, 0x00, 0x33, 0x00, 0x61, 0x00, 0x34, 0x00, 0x32, 0x00, 0x61, 0x00, 0x32, 0x00, 0x31, 0x00,
            0x65, 0x00, 0x64, 0x00, 0x63, 0x00, 0x34, 0x00, 0x2e, 0x00, 0x5f, 0x00, 0x6d, 0x00, 0x73, 0x00,
            0x64, 0x00, 0x63, 0x00, 0x73, 0x00, 0x2e, 0x00, 0x61, 0x00, 0x64, 0x00, 0x74, 0x00, 0x65, 0x00,
            0x73, 0x00, 0x74, 0x00, 0x73, 0x00, 0x2e, 0x00, 0x65, 0x00, 0x78, 0x00, 0x61, 0x00, 0x6d, 0x00,
            0x70, 0x00, 0x6c, 0x00, 0x65, 0x00, 0x2e, 0x00, 0x63, 0x00, 0x6f, 0x00, 0x6d, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        let reps2 = RepsFromTo::try_from_bytes(&DATA2).unwrap();
        assert_eq!(reps2.version, 2);
        assert_eq!(reps2.consecutive_failures, 0);
        assert_eq!(reps2.time_last_success.timestamp(), 1731362198);
        assert_eq!(reps2.time_last_attempt.timestamp(), 1731362198);
        assert_eq!(reps2.result_last_attempt, 0);
        assert_eq!(reps2.replica_flags, 112);
        assert_eq!(reps2.usn_vec.usn_high_obj_update, 238385440);
        assert_eq!(reps2.usn_vec.usn_high_prop_update, 238385440);
        assert_eq!(reps2.dsa_object, Uuid::try_parse_ascii(b"40658ae2-334f-461a-99bd-63a42a21edc4").unwrap());
        assert_eq!(reps2.invocation_id, Uuid::try_parse_ascii(b"93e04a41-4877-483b-a800-06223872c6ef").unwrap());
        assert_eq!(reps2.transport_object, Uuid::from_u128(0));

        let reps2_other_dra = match reps2.other_dra {
            OtherDra::V1(_) => panic!("V1 DRA?!"),
            OtherDra::V2(v2) => v2,
        };
        assert_eq!(reps2_other_dra.server.as_deref(), Some("40658ae2-334f-461a-99bd-63a42a21edc4._msdcs.adtests.example.com"));
        assert_eq!(reps2_other_dra.annotation, None);
        assert_eq!(reps2_other_dra.instance.as_deref(), Some("40658ae2-334f-461a-99bd-63a42a21edc4._msdcs.adtests.example.com"));
        assert_eq!(reps2_other_dra.instance_guid, None);
    }
}
