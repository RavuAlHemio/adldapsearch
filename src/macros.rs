#[macro_export]
macro_rules! bit_is_set {
    ($value:expr, $bit_index:expr) => {
        ($value & (1 << $bit_index)) != 0
    };
}

#[macro_export]
macro_rules! extract_bits_noconvert {
    ($value:expr, $lowest_bit_index:expr, $bit_count:expr) => {
        (($value >> $lowest_bit_index) & ((1 << $bit_count) - 1))
    };
}

#[macro_export]
macro_rules! extract_bits {
    ($value:expr, $lowest_bit_index:expr, $bit_count:expr) => {
        $crate::extract_bits_noconvert!($value, $lowest_bit_index, $bit_count).try_into().unwrap()
    };
}
