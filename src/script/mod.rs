pub mod convert;
pub mod stack;

use crate::opcode::Opcode;
use core::fmt;

#[derive(Debug, Clone, Copy)]
pub enum ScriptElem<'a> {
    Op(Opcode),
    Bytes(&'a [u8]),
}

impl<'a> fmt::Display for ScriptElem<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Op(opcode) => write!(f, "{}", opcode.name().unwrap_or("UNKNOWN")),
            Self::Bytes(bytes) => {
                write!(f, "<")?;
                for byte in *bytes {
                    write!(f, "{:02x}", byte)?;
                }
                write!(f, ">")
            }
        }
    }
}

pub type Script<'a> = Vec<ScriptElem<'a>>;
pub type ScriptSlice<'a> = &'a [ScriptElem<'a>];

pub fn parse_script(bytes: &[u8]) -> Result<Script<'_>, ParseScriptError> {
    let mut a = Vec::new();

    let mut offset = 0;
    while offset < bytes.len() {
        let b = bytes[offset];
        offset += 1;
        let opcode = Opcode { opcode: b };
        if opcode.name().is_some() {
            if let Some(n) = opcode.pushdata_length() {
                let n = n;
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
                return Err(ParseScriptError::UnexpectedEnd(b as usize, bytes.len() - offset));
            };
            offset += b as usize;
            a.push(ScriptElem::Bytes(data));
        } else {
            return Err(ParseScriptError::Invalid(b));
        }
    }

    Ok(a)
}

#[derive(Debug)]
pub enum ParseScriptError {
    Invalid(u8),
    UnexpectedEndPushdataLength(Opcode),
    UnexpectedEnd(usize, usize),
}

impl fmt::Display for ParseScriptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(opcode) => write!(f, "Invalid opcode 0x{opcode:02x}"),
            Self::UnexpectedEndPushdataLength(opcode) => write!(
                f,
                "{opcode} with incomplete push length (SCRIPT_ERR_BAD_OPCODE)"
            ),
            Self::UnexpectedEnd(expected, actual) => write!(
                f,
                "Invalid length, expected {expected} but got {actual} (SCRIPT_ERR_BAD_OPCODE)"
            ),
        }
    }
}

// TODO serialization

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
