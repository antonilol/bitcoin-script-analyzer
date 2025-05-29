use crate::expr::Expr;
use crate::script_error::ScriptError;

use alloc::boxed::Box;

pub const INT_MAX_LEN: usize = 5;

pub fn encode_int_expr(n: i64) -> Expr {
    Expr::bytes_owned(encode_int_box(n))
}

pub fn encode_int_box(n: i64) -> Box<[u8]> {
    encode_int(n, &mut [0; INT_MAX_LEN])
        .to_vec()
        .into_boxed_slice()
}

pub fn encode_int(n: i64, buf: &mut [u8; INT_MAX_LEN]) -> &[u8] {
    if n == 0 {
        return &buf[..0];
    }

    let mut len = 0;

    let neg = n < 0;
    let mut abs = n.abs();
    while abs != 0 {
        buf[len] = abs as u8;
        len += 1;
        abs >>= 8;
    }

    if (buf[len - 1] & 0x80) != 0 {
        buf[len] = if neg { 0x80 } else { 0x00 };
        len += 1;
    } else if neg {
        buf[len - 1] |= 0x80;
    }

    &buf[0..len]
}

pub fn check_int<T: AsRef<[u8]>>(bytes: T, max_len: usize) -> Result<(), ScriptError> {
    let bytes = bytes.as_ref();

    debug_assert!(max_len <= INT_MAX_LEN);

    if bytes.len() > max_len {
        Err(ScriptError::SCRIPT_ERR_NUM_OVERFLOW)
    } else {
        Ok(())
    }
}

pub fn decode_int_unchecked<T: AsRef<[u8]>>(bytes: T) -> i64 {
    let bytes = bytes.as_ref();

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

    if neg { -(n as i64) } else { n as i64 }
}

pub fn decode_int<T: AsRef<[u8]>>(bytes: T, max_len: usize) -> Result<i64, ScriptError> {
    let bytes = bytes.as_ref();

    check_int(bytes, max_len)?;

    Ok(decode_int_unchecked(bytes))
}

pub fn encode_bool_expr(b: bool) -> Expr {
    Expr::bytes_owned(if b { Box::new([1]) } else { Box::new([]) })
}

pub fn encode_bool_slice(b: bool) -> &'static [u8] {
    &[1][..b as usize]
}

pub fn decode_bool<T: AsRef<[u8]>>(bytes: T) -> bool {
    let bytes = bytes.as_ref();

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
    use super::{decode_bool, decode_int, encode_bool_expr, encode_int_box};
    use crate::expr::Expr;

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
            assert_eq!(*encode_int_box(case.0), *case.1);
            assert_eq!(case.0, decode_int(case.1, 4).unwrap());
        }

        // special case: -0
        assert_eq!(decode_int([0x80], 4).unwrap(), 0);
        assert_eq!(decode_int([0x00, 0x80], 4).unwrap(), 0);
        assert_eq!(decode_int([0x00, 0x00, 0x80], 4).unwrap(), 0);
        assert_eq!(decode_int([0x00, 0x00, 0x00, 0x80], 4).unwrap(), 0);
    }

    #[test]
    fn test_bool_encode() {
        assert_eq!(encode_bool_expr(false), Expr::bytes(&[]));
        assert_eq!(encode_bool_expr(true), Expr::bytes(&[1]));

        for case in TEST_CASES {
            assert_eq!(case.2, decode_bool(case.1));
        }

        // special case: -0 is falsy
        assert!(!decode_bool([0x80]));
        assert!(!decode_bool([0x00, 0x80]));
        assert!(!decode_bool([0x00, 0x00, 0x80]));
        assert!(!decode_bool([0x00, 0x00, 0x00, 0x80]));
    }
}
