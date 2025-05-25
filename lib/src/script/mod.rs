pub mod convert;
pub mod stack;

use self::convert::{INT_MAX_LEN, encode_int};
use crate::opcode::{Opcode, opcodes};
use crate::util::{HexDecodeError, decode_hex_in_place};
use core::fmt;
use core::num::IntErrorKind;
use core::ops::{Deref, DerefMut};
use core::str;

#[derive(Debug, Clone, Copy)]
pub enum ScriptElem<'a> {
    Op(Opcode),
    Bytes(&'a [u8]),
}

impl fmt::Display for ScriptElem<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Op(opcode) => write!(f, "{opcode}"),
            Self::Bytes(bytes) => {
                write!(f, "<")?;
                for &byte in bytes {
                    write!(f, "{byte:02x}")?;
                }
                write!(f, ">")
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct OwnedScript<'a>(Vec<ScriptElem<'a>>);

impl<'a> OwnedScript<'a> {
    pub fn parse_from_bytes(bytes: &'a [u8]) -> Result<Self, ParseScriptError> {
        let mut a = Vec::new();

        let mut offset = 0;
        while offset < bytes.len() {
            let b = bytes[offset];
            offset += 1;
            let opcode = Opcode { opcode: b };
            if opcode.name().is_some() {
                if let Some(n) = opcode.pushdata_length() {
                    let Some(push_size) = bytes.get(offset..offset + n) else {
                        return Err(ParseScriptError::UnexpectedEndPushdataLength(opcode));
                    };
                    let l = u32::from_le_bytes({
                        let mut buf = [0u8; 4];
                        buf[0..push_size.len()].copy_from_slice(push_size);
                        buf
                    }) as usize;
                    offset += n;
                    let Some(data) = bytes.get(offset..offset + l) else {
                        return Err(ParseScriptError::UnexpectedEnd(l, bytes.len() - offset));
                    };
                    offset += l;
                    a.push(ScriptElem::Bytes(data));
                } else {
                    a.push(ScriptElem::Op(opcode));
                }
            } else if b <= 75 {
                let Some(data) = bytes.get(offset..offset + b as usize) else {
                    return Err(ParseScriptError::UnexpectedEnd(
                        b as usize,
                        bytes.len() - offset,
                    ));
                };
                offset += b as usize;
                a.push(ScriptElem::Bytes(data));
            } else {
                return Err(ParseScriptError::Invalid(b));
            }
        }

        Ok(OwnedScript(a))
    }

    pub fn parse_from_asm_in_place(
        asm: &'a mut [u8],
    ) -> Result<(&'a [u8], Self), ParseAsmScriptError> {
        // TODO zero alloc
        let mut ret = Vec::new();

        let mut i = 0;
        while i < asm.len() {
            let mut token_end = i;
            while token_end < asm.len() {
                if asm[token_end].is_ascii_whitespace() {
                    break;
                }
                token_end += 1;
            }
            if i == token_end {
                i += 1;
                continue;
            }
            let op = &mut asm[i..token_end];
            match str::from_utf8(op)
                .expect("TODO")
                .parse::<i64>()
                .map_err(|err| err.kind().clone())
            {
                Ok(0) => {
                    // OP_0
                    ret.push(0x00);
                }
                Ok(n @ -1..=16) => {
                    // OP_1NEGATE (4f), OP_1 (51) ... OP_16 (60)
                    ret.push((0x50 + n) as u8);
                }
                Ok(n @ -0x7fffffff..=0x7fffffff) => {
                    let s = &mut [0; INT_MAX_LEN];
                    let s = encode_int(n, s);
                    ret.push(s.len() as u8);
                    ret.extend(s);
                }
                Ok(_) | Err(IntErrorKind::PosOverflow | IntErrorKind::NegOverflow) => {
                    return Err(ParseAsmScriptError::IntegerOutOfRange);
                }
                Err(_) => {
                    if let [b'<', hex @ .., b'>'] = op {
                        match hex.len() / 2 {
                            len @ 0..=75 => {
                                ret.push(len as u8);
                            }
                            len @ 76..=255 => {
                                // OP_PUSHDATA1
                                ret.push(0x4c);
                                ret.push(len as u8);
                            }
                            len @ 256..=520 => {
                                // OP_PUSHDATA2
                                ret.push(0x4d);
                                ret.extend(u16::to_le_bytes(len as u16));
                            }
                            521.. => {
                                return Err(ParseAsmScriptError::DataPushTooLarge);
                            }
                        }
                        ret.extend(decode_hex_in_place(hex)?);
                    } else if let Some(opcode) =
                        Opcode::from_name(str::from_utf8(op).expect("TODO"))
                    {
                        if opcode.pushdata_length().is_some() {
                            return Err(ParseAsmScriptError::ExplicitPushdata);
                        }
                        ret.push(opcode.opcode);
                    } else {
                        return Err(ParseAsmScriptError::UnknownOpcode);
                        // throw `Unknown opcode ${op.length > 50 ? op.slice(0, 50) + '..' : op}${
                        //     /^[0-9a-fA-F]+$/.test(op) ? '. Hex data pushes have to be between < and >' : ''
                        // }`;
                    }
                }
            }

            i = token_end + 1;
        }

        let asm = &mut asm[..ret.len()];
        asm.copy_from_slice(&ret);

        Ok((asm, Self::parse_from_bytes(asm).unwrap()))
    }
}

impl<'a> Deref for OwnedScript<'a> {
    type Target = Script<'a>;

    fn deref(&self) -> &Self::Target {
        Script::new(&self.0)
    }
}

impl DerefMut for OwnedScript<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        Script::new_mut(&mut self.0)
    }
}

impl fmt::Display for OwnedScript<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        <Script<'_> as fmt::Display>::fmt(self, f)
    }
}

#[derive(Debug)]
#[repr(transparent)]
pub struct Script<'a>(pub [ScriptElem<'a>]);

impl<'a> Script<'a> {
    pub fn new<'b>(slice: &'b [ScriptElem<'a>]) -> &'b Self {
        unsafe { &*(slice as *const [ScriptElem<'a>] as *const Self) }
    }

    pub fn new_mut<'b>(slice: &'b mut [ScriptElem<'a>]) -> &'b mut Self {
        unsafe { &mut *(slice as *mut [ScriptElem<'a>] as *mut Self) }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut ret = Vec::new();

        for &e in &**self {
            match e {
                ScriptElem::Op(op) => ret.push(op.opcode),
                ScriptElem::Bytes(bytes) => ret.extend(bytes),
            }
        }

        ret
    }

    pub fn fmt_space_separated(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        for &e in &**self {
            if first {
                first = false;
            } else {
                write!(f, " ")?;
            }
            write!(f, "{e}")?;
        }

        Ok(())
    }

    pub fn fmt_newline_separated(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        for &e in &**self {
            if first {
                first = false;
            } else {
                writeln!(f)?;
            }
            write!(f, "{e}")?;
        }

        Ok(())
    }

    pub fn fmt_newline_separated_indented(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut indent = 0usize;
        let mut first = true;
        for &e in &**self {
            if first {
                first = false;
            } else {
                if let ScriptElem::Op(opcodes::OP_ELSE | opcodes::OP_ENDIF) = e {
                    indent = indent.saturating_sub(1);
                }
                writeln!(f)?;
                for _ in 0..indent {
                    write!(f, "  ")?;
                }
            }
            write!(f, "{e}")?;
            if let ScriptElem::Op(opcodes::OP_IF | opcodes::OP_NOTIF | opcodes::OP_ELSE) = e {
                indent += 1;
            }
        }

        Ok(())
    }
}

impl<'a> Deref for Script<'a> {
    type Target = [ScriptElem<'a>];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Script<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl fmt::Display for Script<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.fmt_newline_separated_indented(f)
    }
}

#[derive(Debug, Clone)]
pub enum ParseScriptError {
    Invalid(u8),
    UnexpectedEndPushdataLength(Opcode),
    UnexpectedEnd(usize, usize),
}

impl fmt::Display for ParseScriptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(opcode) => write!(f, "invalid opcode 0x{opcode:02x}"),
            Self::UnexpectedEndPushdataLength(opcode) => write!(
                f,
                "{opcode} with incomplete push length (SCRIPT_ERR_BAD_OPCODE)"
            ),
            Self::UnexpectedEnd(expected, actual) => write!(
                f,
                "invalid length, expected {expected} but got {actual} (SCRIPT_ERR_BAD_OPCODE)"
            ),
        }
    }
}

impl std::error::Error for ParseScriptError {}

#[derive(Debug, Clone)]
pub enum ParseAsmScriptError {
    IntegerOutOfRange,
    DataPushTooLarge,
    UnknownOpcode,
    ExplicitPushdata,
    HexDecodeError(HexDecodeError),
}

impl From<HexDecodeError> for ParseAsmScriptError {
    fn from(value: HexDecodeError) -> Self {
        Self::HexDecodeError(value)
    }
}

impl fmt::Display for ParseAsmScriptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IntegerOutOfRange => write!(f, "integer out of range"),
            Self::DataPushTooLarge => write!(f, "data push too large"),
            Self::UnknownOpcode => write!(f, "unknown opcode"),
            Self::ExplicitPushdata => {
                write!(f, "OP_PUSHDATA opcodes are not allowed in asm script")
            }
            Self::HexDecodeError(err) => write!(f, "hex decode error: {err}"),
        }
    }
}

impl std::error::Error for ParseAsmScriptError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(match self {
            Self::HexDecodeError(err) => err,
            _ => return None,
        })
    }
}

/*

TODO maybe flags from bitcoin core

MANDATORY_SCRIPT_VERIFY_FLAGS = SCRIPT_VERIFY_P2SH

consensus:
MANDATORY_SCRIPT_VERIFY_FLAGS

relay:
MANDATORY_SCRIPT_VERIFY_FLAGS
SCRIPT_VERIFY_DERSIG
SCRIPT_VERIFY_STRICTENC
SCRIPT_VERIFY_MINIMALDATA
SCRIPT_VERIFY_NULLDUMMY
SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS
SCRIPT_VERIFY_CLEANSTACK
SCRIPT_VERIFY_MINIMALIF
SCRIPT_VERIFY_NULLFAIL
SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY
SCRIPT_VERIFY_CHECKSEQUENCEVERIFY
SCRIPT_VERIFY_LOW_S
SCRIPT_VERIFY_WITNESS
SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM
SCRIPT_VERIFY_WITNESS_PUBKEYTYPE
SCRIPT_VERIFY_CONST_SCRIPTCODE
SCRIPT_VERIFY_TAPROOT
SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION
SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS
SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_PUBKEYTYPE

*/
