use core::fmt;
use core::hint::unreachable_unchecked;

pub mod checksig;
pub mod locktime;

unsafe fn encode_hex_digit(n: u8) -> u8 {
    match n {
        0x0..=0x9 => n + b'0',
        0xa..=0xf => n - 0xa + b'a',
        _ => unsafe { unreachable_unchecked() },
    }
}

fn encode_byte_to_hex(byte: u8) -> [u8; 2] {
    let high = byte >> 4;
    let low = byte & 0xf;

    unsafe { [encode_hex_digit(high), encode_hex_digit(low)] }
}

pub fn encode_hex_easy(bytes: &[u8]) -> String {
    let mut ret = Vec::with_capacity(bytes.len() * 2);

    unsafe {
        let mut ret = ret.as_mut_ptr();
        for &byte in bytes {
            let [high, low] = encode_byte_to_hex(byte);
            *ret = high;
            ret = ret.add(1);
            *ret = low;
            ret = ret.add(1);
        }
    }

    unsafe {
        ret.set_len(bytes.len() * 2);
        String::from_utf8_unchecked(ret)
    }
}

fn decode_hex_digit(d: u8) -> Option<u8> {
    match d {
        b'0'..=b'9' => Some(d - b'0'),
        b'A'..=b'F' => Some(d - b'A' + 0xa),
        b'a'..=b'f' => Some(d - b'a' + 0xa),
        _ => None,
    }
}

pub fn decode_hex_in_place_easy(v: String) -> Result<Vec<u8>, HexDecodeError> {
    let mut bytes = v.into_bytes();
    let len = decode_hex_in_place(&mut bytes)?.len();
    bytes.truncate(len);
    Ok(bytes)
}

pub fn decode_hex_in_place(v: &mut [u8]) -> Result<&[u8], HexDecodeError> {
    let result_len = v.len() / 2;

    unsafe {
        let v = v.as_mut_ptr();
        for i in 0..result_len {
            let high = *v.add(2 * i);
            let low = *v.add(2 * i + 1);

            let high =
                decode_hex_digit(high).ok_or(HexDecodeError::InvalidCharacter(2 * i, high))?;
            let low =
                decode_hex_digit(low).ok_or(HexDecodeError::InvalidCharacter(2 * i + 1, low))?;

            *v.add(i) = (high << 4) | low;
        }
    }

    if v.len() % 2 == 0 {
        Ok(&v[..result_len])
    } else {
        Err(HexDecodeError::OddAmountOfHexCharacters(v.len()))
    }
}

pub fn decode_hex_in_place_ignore_whitespace_easy(v: String) -> Result<Vec<u8>, HexDecodeError> {
    let mut bytes = v.into_bytes();
    let len = decode_hex_in_place_ignore_whitespace(&mut bytes)?.len();
    bytes.truncate(len);
    Ok(bytes)
}

pub fn decode_hex_in_place_ignore_whitespace(v: &mut [u8]) -> Result<&[u8], HexDecodeError> {
    let mut result_len = 0;
    let len = v.len();

    let mut prev_hex_char = None;
    unsafe {
        let v = v.as_mut_ptr();
        for i in 0..len {
            let char = *v.add(i);
            if char.is_ascii_whitespace() {
                continue;
            }

            let n = decode_hex_digit(char).ok_or(HexDecodeError::InvalidCharacter(i, char))?;

            if let Some(high) = prev_hex_char {
                *v.add(result_len) = (high << 4) | n;
                result_len += 1;

                prev_hex_char = None;
            } else {
                prev_hex_char = Some(n);
            }
        }
    }

    if prev_hex_char.is_none() {
        Ok(&v[..result_len])
    } else {
        Err(HexDecodeError::OddAmountOfHexCharacters(2 * result_len + 1))
    }
}

#[derive(Debug, Clone)]
pub enum HexDecodeError {
    OddAmountOfHexCharacters(usize),
    InvalidCharacter(usize, u8),
}

impl fmt::Display for HexDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::OddAmountOfHexCharacters(amount) => write!(
                f,
                "string contains an odd amount ({amount}) of hex characters"
            ),
            Self::InvalidCharacter(pos, digit) => {
                write!(
                    f,
                    "invalid character \"{}\" (0x{digit:02x}) at byte {pos}",
                    match digit {
                        32..=126 => digit as char,
                        _ => char::REPLACEMENT_CHARACTER,
                    }
                )
            }
        }
    }
}

impl std::error::Error for HexDecodeError {}

#[cfg(test)]
mod tests {
    use super::{HexDecodeError, decode_hex_in_place, decode_hex_in_place_ignore_whitespace};

    #[test]
    fn test_hex_decode() {
        let mut hex = String::from("").into_bytes();
        let bytes = decode_hex_in_place(&mut hex).unwrap();
        assert_eq!(bytes, &[]);

        let mut hex =
            String::from("4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b")
                .into_bytes();
        let bytes = decode_hex_in_place(&mut hex).unwrap();
        assert_eq!(
            bytes,
            &[
                0x4a, 0x5e, 0x1e, 0x4b, 0xaa, 0xb8, 0x9f, 0x3a, 0x32, 0x51, 0x8a, 0x88, 0xc3, 0x1b,
                0xc8, 0x7f, 0x61, 0x8f, 0x76, 0x67, 0x3e, 0x2c, 0xc7, 0x7a, 0xb2, 0x12, 0x7b, 0x7a,
                0xfd, 0xed, 0xa3, 0x3b
            ]
        );

        let mut hex = String::from("123").into_bytes();
        let error = decode_hex_in_place(&mut hex).unwrap_err();
        assert!(matches!(error, HexDecodeError::OddAmountOfHexCharacters(3)));

        let mut hex = String::from("01234invalid").into_bytes();
        let error = decode_hex_in_place(&mut hex).unwrap_err();
        assert!(matches!(error, HexDecodeError::InvalidCharacter(5, b'i')));
    }

    #[test]
    fn test_hex_decode_ignore_whitespace() {
        let mut hex = String::from("").into_bytes();
        let bytes = decode_hex_in_place_ignore_whitespace(&mut hex).unwrap();
        assert_eq!(bytes, &[]);

        let mut hex = String::from(" \n").into_bytes();
        let bytes = decode_hex_in_place_ignore_whitespace(&mut hex).unwrap();
        assert_eq!(bytes, &[]);

        let mut hex = String::from("01 23 45 6\n7  \t").into_bytes();
        let bytes = decode_hex_in_place_ignore_whitespace(&mut hex).unwrap();
        assert_eq!(bytes, &[0x01, 0x23, 0x45, 0x67]);

        let mut hex =
            String::from("4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b")
                .into_bytes();
        let bytes = decode_hex_in_place_ignore_whitespace(&mut hex).unwrap();
        assert_eq!(
            bytes,
            &[
                0x4a, 0x5e, 0x1e, 0x4b, 0xaa, 0xb8, 0x9f, 0x3a, 0x32, 0x51, 0x8a, 0x88, 0xc3, 0x1b,
                0xc8, 0x7f, 0x61, 0x8f, 0x76, 0x67, 0x3e, 0x2c, 0xc7, 0x7a, 0xb2, 0x12, 0x7b, 0x7a,
                0xfd, 0xed, 0xa3, 0x3b
            ]
        );

        let mut hex = String::from("123").into_bytes();
        let error = decode_hex_in_place_ignore_whitespace(&mut hex).unwrap_err();
        assert!(matches!(error, HexDecodeError::OddAmountOfHexCharacters(3)));

        let mut hex = String::from("01234invalid").into_bytes();
        let error = decode_hex_in_place_ignore_whitespace(&mut hex).unwrap_err();
        assert!(matches!(error, HexDecodeError::InvalidCharacter(5, b'i')));
    }
}
