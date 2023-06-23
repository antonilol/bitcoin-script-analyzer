pub const SIGHASH_DEFAULT: u8 = 0;
pub const SIGHASH_ALL: u8 = 1;
pub const SIGHASH_NONE: u8 = 2;
pub const SIGHASH_SINGLE: u8 = 3;
pub const SIGHASH_ANYONECANPAY: u8 = 128;

/// hash types that can appear at the end of a signature (SIGHASH_DEFAULT can't)
pub const SIG_HASH_TYPES: [u8; 6] = [
    SIGHASH_ALL,
    SIGHASH_NONE,
    SIGHASH_SINGLE,
    SIGHASH_ALL | SIGHASH_ANYONECANPAY,
    SIGHASH_NONE | SIGHASH_ANYONECANPAY,
    SIGHASH_SINGLE | SIGHASH_ANYONECANPAY,
];

pub enum PubKeyCheckResult {
    Invalid,
    Valid { compressed: bool },
}

pub fn check_pub_key(pub_key: &[u8]) -> PubKeyCheckResult {
    if pub_key.len() == 33 && (pub_key[0] == 0x02 || pub_key[0] == 0x03) {
        PubKeyCheckResult::Valid { compressed: true }
    } else if pub_key.len() == 65 && pub_key[0] == 0x04 {
        PubKeyCheckResult::Valid { compressed: false }
    } else {
        PubKeyCheckResult::Invalid
    }
}

// The following function was copied from the Bitcoin Core source code, src/script/interpreter (lines 97-170) at b92d609fb25637ccda000e182da854d4b762eee9
// Edited for use in this software

// Orignal Bitcoin Core copyright header:
// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/// A canonical signature exists of: <30> <total len> <02> <len R> <R> <02> <len S> <S> <hashtype>
/// Where R and S are not negative (their first byte has its highest bit not set), and not
/// excessively padded (do not start with a 0 byte, unless an otherwise negative number follows,
/// in which case a single 0 byte is necessary and even required).
///
/// See https://bitcointalk.org/index.php?topic=8392.msg127623#msg127623
///
/// This function is consensus-critical since BIP66.
pub fn is_valid_signature_encoding(sig: &[u8]) -> bool {
    // Format: 0x30 [total-length] 0x02 [R-length] [R] 0x02 [S-length] [S] [sighash]
    // * total-length: 1-byte length descriptor of everything that follows,
    //   excluding the sighash byte.
    // * R-length: 1-byte length descriptor of the R value that follows.
    // * R: arbitrary-length big-endian encoded R value. It must use the shortest
    //   possible encoding for a positive integer (which means no null bytes at
    //   the start, except a single one when the next byte has its highest bit set).
    // * S-length: 1-byte length descriptor of the S value that follows.
    // * S: arbitrary-length big-endian encoded S value. The same rules apply.
    // * sighash: 1-byte value indicating what data is hashed (not part of the DER
    //   signature)

    // Minimum and maximum size constraints.
    if sig.len() < 9 {
        return false;
    }
    if sig.len() > 73 {
        return false;
    }

    // A signature is of type 0x30 (compound).
    if sig[0] != 0x30 {
        return false;
    }

    // Make sure the length covers the entire signature.
    if sig[1] != sig.len() as u8 - 3 {
        return false;
    }

    // Extract the length of the R element.
    let len_r = sig[3] as usize;

    // Make sure the length of the S element is still inside the signature.
    if 5 + len_r >= sig.len() {
        return false;
    }

    // Extract the length of the S element.
    let len_s = sig[5 + len_r] as usize;

    // Verify that the length of the signature matches the sum of the length
    // of the elements.
    if len_r + len_s + 7 != sig.len() {
        return false;
    }

    // Check whether the R element is an integer.
    if sig[2] != 0x02 {
        return false;
    }

    // Zero-length integers are not allowed for R.
    if len_r == 0 {
        return false;
    }

    // Negative numbers are not allowed for R.
    if (sig[4] & 0x80) != 0 {
        return false;
    }

    // Null bytes at the start of R are not allowed, unless R would
    // otherwise be interpreted as a negative number.
    if len_r > 1 && sig[4] == 0x00 && (sig[5] & 0x80) == 0 {
        return false;
    }

    // Check whether the S element is an integer.
    if sig[len_r + 4] != 0x02 {
        return false;
    }

    // Zero-length integers are not allowed for S.
    if len_s == 0 {
        return false;
    }

    // Negative numbers are not allowed for S.
    if (sig[len_r + 6] & 0x80) != 0 {
        return false;
    }

    // Null bytes at the start of S are not allowed, unless S would otherwise be
    // interpreted as a negative number.
    if len_s > 1 && sig[len_r + 6] == 0x00 && (sig[len_r + 7] & 0x80) == 0 {
        return false;
    }

    true
}
