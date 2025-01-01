use std::cmp::Ordering;
use std::fmt;
use std::ops::Range;

use num_bigint::BigUint;

use crate::{bit_is_set, extract_bits_noconvert};


#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct OidPrefix {
    fixed_arcs: Vec<BigUint>,
    final_range: Range<BigUint>,
}
impl OidPrefix {
    fn take_ber_integer_slice(bytes: &[u8]) -> (&[u8], &[u8]) {
        let mut split_index = 0;
        while split_index < bytes.len() {
            let is_continuation = bit_is_set!(bytes[split_index], 7);
            split_index += 1;
            if !is_continuation {
                return bytes.split_at(split_index);
            }
        }
        (bytes, &[])
    }

    fn is_terminated_ber_integer(bytes: &[u8]) -> bool {
        assert_ne!(bytes.len(), 0);
        for b in &bytes[0..bytes.len()-1] {
            if !bit_is_set!(*b, 7) {
                // all bytes in the middle must have the continuation bit set
                return false;
            }
        }

        // the final byte must have the continuation bit unset
        !bit_is_set!(bytes.last().unwrap(), 7)
    }

    fn extract_ber_integer(bytes: &[u8]) -> BigUint {
        assert!(Self::is_terminated_ber_integer(bytes));
        let mut value = BigUint::from(0u8);
        for b in bytes {
            let without_continuation_bit = extract_bits_noconvert!(*b, 0, 7);
            value <<= 7;
            value |= BigUint::from(without_continuation_bit);
        }
        value
    }

    pub fn from_ber_bytes(mut bytes: &[u8]) -> Self {
        let mut fixed_arcs = Vec::new();
        let forty = BigUint::from(40u8);
        let eighty = BigUint::from(80u8);

        while bytes.len() > 0 {
            let (arc_slice, rest) = Self::take_ber_integer_slice(bytes);
            bytes = rest;

            if Self::is_terminated_ber_integer(arc_slice) {
                // fixed arc
                let arc_value = Self::extract_ber_integer(arc_slice);
                if fixed_arcs.len() == 0 {
                    // special encoding of first two arcs
                    if arc_value < forty {
                        // 0.n
                        fixed_arcs.push(BigUint::from(0u8));
                        fixed_arcs.push(arc_value);
                    } else if arc_value < eighty {
                        // 1.(n-40)
                        fixed_arcs.push(BigUint::from(1u8));
                        fixed_arcs.push(&arc_value - &forty);
                    } else {
                        // 2.(n-80)
                        fixed_arcs.push(BigUint::from(2u8));
                        fixed_arcs.push(&arc_value - &eighty);
                    }
                } else {
                    fixed_arcs.push(arc_value);
                }
            } else {
                assert_eq!(bytes.len(), 0);
                // unterminated final arc
                // the smallest value is all zeroes (c000_0000 e000_0000)
                // the largest value is all ones (c111_1111 e111_1111)
                // where c = 1 (continue) and e = 0 (end)
                let mut smallest_bytes = arc_slice.to_vec();
                let mut largest_bytes = smallest_bytes.clone();
                smallest_bytes.push(0b1_000_0000);
                smallest_bytes.push(0b0_000_0000);
                let smallest_value = Self::extract_ber_integer(&smallest_bytes);
                largest_bytes.push(0b1_111_1111);
                largest_bytes.push(0b0_111_1111);
                let largest_value_plus_one = Self::extract_ber_integer(&largest_bytes) + BigUint::from(1u8);
                let final_range = smallest_value..largest_value_plus_one;
                return Self {
                    fixed_arcs,
                    final_range,
                }
            }
        }

        // the last arc was a fixed arc
        // => we have the standard range of [0b00_00_0000_0000_0000 to 0b00_11_1111_1111_1111]
        let range_start = BigUint::from(0b00_00_0000_0000_0000u16);
        // exclusive range
        let range_end = BigUint::from(0b01_00_0000_0000_0000u16);
        let final_range = range_start..range_end;
        Self {
            fixed_arcs,
            final_range,
        }
    }
}
impl Ord for OidPrefix {
    // pragmatic impl -- doesn't make mathematical sense
    // but allows OidPrefix to be used as a BTreeMap key etc.
    fn cmp(&self, other: &Self) -> Ordering {
        self.fixed_arcs.cmp(&other.fixed_arcs)
            .then_with(|| self.final_range.start.cmp(&other.final_range.start))
            .then_with(|| self.final_range.end.cmp(&other.final_range.end))
    }
}
impl PartialOrd for OidPrefix {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl fmt::Display for OidPrefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for fixed_arc in &self.fixed_arcs {
            write!(f, "{}.", fixed_arc)?;
        }
        write!(f, "({}..{})", self.final_range.start, self.final_range.end)
    }
}


#[cfg(test)]
mod tests {
    use super::OidPrefix;
    use num_bigint::BigUint;

    #[test]
    fn test_oid_prefix() {
        let pfx = OidPrefix::from_ber_bytes(&[0x2A, 0x03, 0x04]);
        assert_eq!(pfx.fixed_arcs.len(), 4);
        assert_eq!(pfx.fixed_arcs[0], BigUint::from(1u8));
        assert_eq!(pfx.fixed_arcs[1], BigUint::from(2u8));
        assert_eq!(pfx.fixed_arcs[2], BigUint::from(3u8));
        assert_eq!(pfx.fixed_arcs[3], BigUint::from(4u8));
        assert_eq!(pfx.final_range.start, BigUint::from(0u8));
        assert_eq!(pfx.final_range.end, BigUint::from(16384u16));

        let pfx = OidPrefix::from_ber_bytes(&[0x2A, 0x03, 0x04, 0x81]);
        assert_eq!(pfx.fixed_arcs.len(), 4);
        assert_eq!(pfx.fixed_arcs[0], BigUint::from(1u8));
        assert_eq!(pfx.fixed_arcs[1], BigUint::from(2u8));
        assert_eq!(pfx.fixed_arcs[2], BigUint::from(3u8));
        assert_eq!(pfx.fixed_arcs[3], BigUint::from(4u8));
        assert_eq!(pfx.final_range.start, BigUint::from(16384u16));
        assert_eq!(pfx.final_range.end, BigUint::from(32768u16));

        let pfx = OidPrefix::from_ber_bytes(&[0x2A, 0x03, 0x04, 0x82]);
        assert_eq!(pfx.fixed_arcs.len(), 4);
        assert_eq!(pfx.fixed_arcs[0], BigUint::from(1u8));
        assert_eq!(pfx.fixed_arcs[1], BigUint::from(2u8));
        assert_eq!(pfx.fixed_arcs[2], BigUint::from(3u8));
        assert_eq!(pfx.fixed_arcs[3], BigUint::from(4u8));
        assert_eq!(pfx.final_range.start, BigUint::from(32768u16));
        assert_eq!(pfx.final_range.end, BigUint::from(49152u16));
    }
}
