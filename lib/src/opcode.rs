use core::fmt;

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
pub struct Opcode {
    pub opcode: u8,
}

impl fmt::Display for Opcode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name().unwrap_or("UNKNOWN"))
    }
}

macro_rules! opcodes {
    ($($k:ident: $v:literal),* $(,)?) => {
        pub mod opcodes {
            use super::Opcode;

            $(
                #[allow(dead_code)]
                pub const $k: Opcode = Opcode { opcode: $v };
            )*
        }

        impl Opcode {
            const LONGEST_NAME_LENGTH: usize = {
                let mut max = 0;

                $(
                    let len = stringify!($k).len();
                    if max < len {
                        max = len;
                    }
                )*

                max
            };

            pub fn from_name_exact_unprefixed(name_bytes: &[u8]) -> Option<Self> {
                $(
                    if name_bytes == &stringify!($k).as_bytes()[3..] {
                        let op = Opcode { opcode: $v };

                        if !op.is_internal() {
                            Some(op)
                        } else {
                            None
                        }
                    } else
                )* {
                    None
                }
            }

            pub fn name(self) -> Option<&'static str> {
                if self.is_internal() {
                    // TODO display internal opcodes?
                    return None;
                }
                match self.opcode {
                    $(
                        #[allow(unreachable_patterns)]
                        $v => Some(stringify!($k)),
                    )*
                    _ => None,
                }
            }
        }
    };
}

// Opcode names mapped to their opcode.
opcodes! {
    // https://github.com/bitcoin/bitcoin/blob/fa5c896724bb359b4b9a3f89580272bfe5980c1b/src/script/script.h#L65-L206

    // push value
    OP_0: 0x00,
    OP_FALSE: 0x00,
    OP_PUSHDATA1: 0x4c,
    OP_PUSHDATA2: 0x4d,
    OP_PUSHDATA4: 0x4e,
    OP_1NEGATE: 0x4f,
    OP_RESERVED: 0x50,
    OP_1: 0x51,
    OP_TRUE: 0x51,
    OP_2: 0x52,
    OP_3: 0x53,
    OP_4: 0x54,
    OP_5: 0x55,
    OP_6: 0x56,
    OP_7: 0x57,
    OP_8: 0x58,
    OP_9: 0x59,
    OP_10: 0x5a,
    OP_11: 0x5b,
    OP_12: 0x5c,
    OP_13: 0x5d,
    OP_14: 0x5e,
    OP_15: 0x5f,
    OP_16: 0x60,

    // control
    OP_NOP: 0x61,
    OP_VER: 0x62,
    OP_IF: 0x63,
    OP_NOTIF: 0x64,
    OP_VERIF: 0x65,
    OP_VERNOTIF: 0x66,
    OP_ELSE: 0x67,
    OP_ENDIF: 0x68,
    OP_VERIFY: 0x69,
    OP_RETURN: 0x6a,

    // stack ops
    OP_TOALTSTACK: 0x6b,
    OP_FROMALTSTACK: 0x6c,
    OP_2DROP: 0x6d,
    OP_2DUP: 0x6e,
    OP_3DUP: 0x6f,
    OP_2OVER: 0x70,
    OP_2ROT: 0x71,
    OP_2SWAP: 0x72,
    OP_IFDUP: 0x73,
    OP_DEPTH: 0x74,
    OP_DROP: 0x75,
    OP_DUP: 0x76,
    OP_NIP: 0x77,
    OP_OVER: 0x78,
    OP_PICK: 0x79,
    OP_ROLL: 0x7a,
    OP_ROT: 0x7b,
    OP_SWAP: 0x7c,
    OP_TUCK: 0x7d,

    // splice ops
    OP_CAT: 0x7e,
    OP_SUBSTR: 0x7f,
    OP_LEFT: 0x80,
    OP_RIGHT: 0x81,
    OP_SIZE: 0x82,

    // bit logic
    OP_INVERT: 0x83,
    OP_AND: 0x84,
    OP_OR: 0x85,
    OP_XOR: 0x86,
    OP_EQUAL: 0x87,
    OP_EQUALVERIFY: 0x88,
    OP_RESERVED1: 0x89,
    OP_RESERVED2: 0x8a,

    // numeric
    OP_1ADD: 0x8b,
    OP_1SUB: 0x8c,
    OP_2MUL: 0x8d,
    OP_2DIV: 0x8e,
    OP_NEGATE: 0x8f,
    OP_ABS: 0x90,
    OP_NOT: 0x91,
    OP_0NOTEQUAL: 0x92,

    OP_ADD: 0x93,
    OP_SUB: 0x94,
    OP_MUL: 0x95,
    OP_DIV: 0x96,
    OP_MOD: 0x97,
    OP_LSHIFT: 0x98,
    OP_RSHIFT: 0x99,

    OP_BOOLAND: 0x9a,
    OP_BOOLOR: 0x9b,
    OP_NUMEQUAL: 0x9c,
    OP_NUMEQUALVERIFY: 0x9d,
    OP_NUMNOTEQUAL: 0x9e,
    OP_LESSTHAN: 0x9f,
    OP_GREATERTHAN: 0xa0,
    OP_LESSTHANOREQUAL: 0xa1,
    OP_GREATERTHANOREQUAL: 0xa2,
    OP_MIN: 0xa3,
    OP_MAX: 0xa4,

    OP_WITHIN: 0xa5,

    // crypto
    OP_RIPEMD160: 0xa6,
    OP_SHA1: 0xa7,
    OP_SHA256: 0xa8,
    OP_HASH160: 0xa9,
    OP_HASH256: 0xaa,
    OP_CODESEPARATOR: 0xab,
    OP_CHECKSIG: 0xac,
    OP_CHECKSIGVERIFY: 0xad,
    OP_CHECKMULTISIG: 0xae,
    OP_CHECKMULTISIGVERIFY: 0xaf,

    // expansion
    OP_NOP1: 0xb0,
    OP_CHECKLOCKTIMEVERIFY: 0xb1,
    OP_NOP2: 0xb1,
    OP_CHECKSEQUENCEVERIFY: 0xb2,
    OP_NOP3: 0xb2,
    OP_NOP4: 0xb3,
    OP_NOP5: 0xb4,
    OP_NOP6: 0xb5,
    OP_NOP7: 0xb6,
    OP_NOP8: 0xb7,
    OP_NOP9: 0xb8,
    OP_NOP10: 0xb9,

    // Opcode added by BIP 342 (Tapscript)
    OP_CHECKSIGADD: 0xba,

    OP_INVALIDOPCODE: 0xff,

    // aliases
    OP_CLTV: 0xb1,
    OP_CSV: 0xb2,

    // internal opcodes (not used in bitcoin core)
    // Unlike OP_NOT, INTERNAL_NOT does not require the input to be max 4 bytes.
    // Equivalent to IF 0 ELSE 1 ENDIF without minimal if
    OP_INTERNAL_NOT: 0xfe,
}

impl Opcode {
    /// Negative numbers are used for _internal_ opcodes.
    /// These opcodes **do not** exist in bitcoin and are used in scriptanalyzer to accurately mimic the behavior of other opcodes.
    pub fn is_internal(&self) -> bool {
        matches!(*self, opcodes::OP_INTERNAL_NOT)
    }

    /// Opcodes that were disabled because of CVE-2010-5137
    pub fn is_disabled(&self) -> bool {
        matches!(
            *self,
            opcodes::OP_CAT
                | opcodes::OP_SUBSTR
                | opcodes::OP_LEFT
                | opcodes::OP_RIGHT
                | opcodes::OP_INVERT
                | opcodes::OP_AND
                | opcodes::OP_OR
                | opcodes::OP_XOR
                | opcodes::OP_2MUL
                | opcodes::OP_2DIV
                | opcodes::OP_MUL
                | opcodes::OP_DIV
                | opcodes::OP_MOD
                | opcodes::OP_LSHIFT
                | opcodes::OP_RSHIFT
        )
    }

    /// Opcodes that push data mapped to the length of the following number that indicated the push size.
    /// Returns Some(length) for OP_PUSHDATA(1|2|4) and None for others.
    pub fn pushdata_length(&self) -> Option<usize> {
        Some(match *self {
            opcodes::OP_PUSHDATA1 => 1,
            opcodes::OP_PUSHDATA2 => 2,
            opcodes::OP_PUSHDATA4 => 4,
            _ => return None,
        })
    }

    /// Opcodes that return <> or <01>
    pub fn returns_boolean(&self) -> bool {
        matches!(
            *self,
            opcodes::OP_EQUAL
                | opcodes::OP_NOT
                | opcodes::OP_0NOTEQUAL
                | opcodes::OP_BOOLAND
                | opcodes::OP_BOOLOR
                | opcodes::OP_NUMEQUAL
                | opcodes::OP_NUMNOTEQUAL
                | opcodes::OP_LESSTHAN
                | opcodes::OP_GREATERTHAN
                | opcodes::OP_LESSTHANOREQUAL
                | opcodes::OP_GREATERTHANOREQUAL
                | opcodes::OP_WITHIN
                | opcodes::OP_CHECKSIG
                | opcodes::OP_CHECKMULTISIG
                | opcodes::OP_INTERNAL_NOT
        )
    }

    /// Opcodes that return max a number (5 bytes)
    pub fn returns_number(&self) -> bool {
        if self.returns_boolean() {
            return true;
        }

        matches!(
            *self,
            opcodes::OP_SIZE
                | opcodes::OP_NEGATE
                | opcodes::OP_ABS
                | opcodes::OP_ADD
                | opcodes::OP_SUB
                | opcodes::OP_MIN
                | opcodes::OP_MAX
        )
    }

    pub fn can_reorder_args(&self) -> bool {
        !matches!(
            *self,
            opcodes::OP_SUB
                | opcodes::OP_LESSTHAN
                | opcodes::OP_GREATERTHAN
                | opcodes::OP_LESSTHANOREQUAL
                | opcodes::OP_GREATERTHANOREQUAL
                | opcodes::OP_WITHIN
                | opcodes::OP_CHECKSIG
                | opcodes::OP_CHECKMULTISIG
        )
    }

    pub fn from_name(name: &str) -> Option<Self> {
        const ASCII_UPPERCASE_MASK: u8 = !(1 << 5);

        let mut name = name.as_bytes();

        match name.split_first_chunk() {
            Some((&[a, b, c], tail))
                if a & ASCII_UPPERCASE_MASK == b'O'
                    && b & ASCII_UPPERCASE_MASK == b'P'
                    && c == b'_' =>
            {
                name = tail;
            }
            _ => {}
        }

        let mut buf = [0; Self::LONGEST_NAME_LENGTH - 3];
        let buf = buf.get_mut(..name.len())?;
        buf.copy_from_slice(name);
        buf.make_ascii_uppercase();

        Self::from_name_exact_unprefixed(buf)
    }
}

pub enum OpcodeType {
    Data,
    Number,
    Constant,
    Flow,
    Stack,
    Splice,
    Bitwise,
    Arithmetic,
    Crypto,
    Locktime,
    Disabled,
    Invalid,
}

impl Opcode {
    pub fn opcode_type(&self) -> OpcodeType {
        let op = *self;
        if op.is_disabled() {
            OpcodeType::Disabled
        } else if op == opcodes::OP_VER || op == opcodes::OP_VERIF || op == opcodes::OP_VERNOTIF {
            OpcodeType::Invalid
        } else if op >= opcodes::OP_0 && op <= opcodes::OP_PUSHDATA4 {
            OpcodeType::Constant
        } else if op >= opcodes::OP_NOP && op <= opcodes::OP_RETURN {
            OpcodeType::Flow
        } else if op >= opcodes::OP_TOALTSTACK && op <= opcodes::OP_TUCK {
            OpcodeType::Stack
        } else if op >= opcodes::OP_CAT && op <= opcodes::OP_SIZE {
            OpcodeType::Splice
        } else if op >= opcodes::OP_INVERT && op <= opcodes::OP_EQUALVERIFY {
            OpcodeType::Bitwise
        } else if op >= opcodes::OP_1ADD && op <= opcodes::OP_WITHIN {
            OpcodeType::Arithmetic
        } else if (op >= opcodes::OP_RIPEMD160 && op <= opcodes::OP_CHECKMULTISIGVERIFY)
            || op == opcodes::OP_CHECKSIGADD
        {
            OpcodeType::Crypto
        } else if op >= opcodes::OP_CHECKLOCKTIMEVERIFY && op <= opcodes::OP_CHECKSEQUENCEVERIFY {
            OpcodeType::Locktime
        } else {
            OpcodeType::Invalid
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_opcode_from_name() {
        use super::opcodes::*;

        let cases = &[
            ("", None),
            ("0", Some(OP_0)),
            ("1", Some(OP_1)),
            ("OP_0", Some(OP_0)),
            ("Op_0", Some(OP_0)),
            ("oP_0", Some(OP_0)),
            ("op_0", Some(OP_0)),
            (str::from_utf8(&[b'_'; 100]).unwrap(), None),
            ("false", Some(OP_0)),
            ("False", Some(OP_0)),
            ("FaLsE", Some(OP_0)),
            ("trUE", Some(OP_1)),
            ("OP_trUE", Some(OP_1)),
            ("3DUP", Some(OP_3DUP)),
            ("3Dup", Some(OP_3DUP)),
            ("fromaltstack", Some(OP_FROMALTSTACK)),
            ("csv", Some(OP_CHECKSEQUENCEVERIFY)),
            ("cltv", Some(OP_CHECKLOCKTIMEVERIFY)),
            ("OP_INTERNAL_NOT", None),
            ("OP_CHECKMULTISIGVERIFY", Some(OP_CHECKMULTISIGVERIFY)),
        ];

        for &(name, expected_opcode) in cases {
            assert_eq!(Opcode::from_name(name), expected_opcode, "name = {name}");
        }
    }
}
