use crate::script_error::ScriptError;

const INT_MAX_LEN: usize = 5;

pub fn encode_int(n: i64) -> Box<[u8]> {
    if n == 0 {
        return Box::new([]);
    }

    let mut bytes = [0u8; INT_MAX_LEN];
    let mut len = 0;

    let neg = n < 0;
    let mut abs = n.abs();
    while abs != 0 {
        bytes[len] = abs as u8;
        len += 1;
        abs >>= 8;
    }

    if (bytes[len - 1] & 0x80) != 0 {
        bytes[len] = if neg { 0x80 } else { 0x00 };
        len += 1;
    } else if neg {
        bytes[len - 1] |= 0x80;
    }

    bytes[0..len].to_vec().into_boxed_slice()
}

pub fn check_int(bytes: &[u8], max_len: usize) -> Result<(), ScriptError> {
    debug_assert!(max_len <= INT_MAX_LEN);

    if bytes.len() > max_len {
        Err(ScriptError::SCRIPT_ERR_NUM_OVERFLOW)
    } else {
        Ok(())
    }
}

pub fn decode_int_unchecked(bytes: &[u8]) -> i64 {
    debug_assert!(bytes.len() <= INT_MAX_LEN);

    if bytes.is_empty() {
        return 0;
    }

    let neg = (bytes[bytes.len() - 1] & 0x80) != 0;

    let mut bytes_ = [0u8; INT_MAX_LEN];
    bytes_[0..bytes.len()].copy_from_slice(bytes);

    if neg {
        bytes_[bytes.len() - 1] &= 0x7f;
    }

    let mut n = 0u64;

    let mut i = 0;
    while i < bytes.len() {
        n |= (bytes_[i] as u64) << ((i * 8) as u64);
        i += 1;
    }

    if neg {
        -(n as i64)
    } else {
        n as i64
    }
}

pub fn decode_int(bytes: &[u8], max_len: usize) -> Result<i64, ScriptError> {
    check_int(bytes, max_len)?;

    Ok(decode_int_unchecked(bytes))
}

pub const FALSE: &[u8; 0] = &[];
pub const TRUE: &[u8; 1] = &[1];

pub fn encode_bool(b: bool) -> &'static [u8] {
    if b {
        TRUE
    } else {
        FALSE
    }
}

pub fn decode_bool(bytes: &[u8]) -> bool {
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != 0 {
            return i != bytes.len() - 1 || bytes[i] != 0x80;
        }
        i += 1;
    }

    false
}

#[cfg(test)]
mod tests {
    use super::{decode_bool, decode_int, encode_bool, encode_int};

    type TestCase<'a> = (i64, &'a [u8], bool);
    const TEST_CASES: &[TestCase] = &[
        (0, &[], false),
        (1, &[0x01], true),
        (3, &[0x03], true),
        (-5, &[0x85], true),
        (20, &[0x14], true),
        (32, &[0x20], true),
        (127, &[0x7f], true),
        (128, &[0x80, 0x00], true),
        (-127, &[0xff], true),
        (-128, &[0x80, 0x80], true),
        (1008, &[0xf0, 0x03], true),
        (2016, &[0xe0, 0x07], true),
        (i32::MIN as i64 + 1, &[0xff, 0xff, 0xff, 0xff], true),
        (i32::MAX as i64, &[0xff, 0xff, 0xff, 0x7f], true),
    ];

    #[test]
    fn test_int_encode() {
        for case in TEST_CASES {
            assert_eq!(*encode_int(case.0), *case.1);
            assert_eq!(case.0, decode_int(case.1, 4).unwrap());
        }

        // special case: -0
        assert_eq!(decode_int(&[0x80], 4).unwrap(), 0);
        assert_eq!(decode_int(&[0x00, 0x80], 4).unwrap(), 0);
        assert_eq!(decode_int(&[0x00, 0x00, 0x80], 4).unwrap(), 0);
        assert_eq!(decode_int(&[0x00, 0x00, 0x00, 0x80], 4).unwrap(), 0);
    }

    #[test]
    fn test_bool_encode() {
        assert_eq!(encode_bool(false), &[]);
        assert_eq!(encode_bool(true), &[1]);

        for case in TEST_CASES {
            assert_eq!(case.2, decode_bool(case.1));
        }

        // special case: -0 is falsy
        assert!(!decode_bool(&[0x80]));
        assert!(!decode_bool(&[0x00, 0x80]));
        assert!(!decode_bool(&[0x00, 0x00, 0x80]));
        assert!(!decode_bool(&[0x00, 0x00, 0x00, 0x80]));
    }
}
