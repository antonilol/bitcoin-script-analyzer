// From the Bitcoin Core source code, files src/script/script_error.{h,cpp} at commit b1a2021f78099c17360dc2179cbcb948059b5969
// Edited for use in this software

// Orignal Bitcoin Core copyright header:
// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
pub enum ScriptError {
    SCRIPT_ERR_OK,
    SCRIPT_ERR_UNKNOWN_ERROR,
    SCRIPT_ERR_EVAL_FALSE,
    SCRIPT_ERR_OP_RETURN,

    /* Max sizes */
    SCRIPT_ERR_SCRIPT_SIZE,
    SCRIPT_ERR_PUSH_SIZE,
    SCRIPT_ERR_OP_COUNT,
    SCRIPT_ERR_STACK_SIZE,
    SCRIPT_ERR_SIG_COUNT,
    SCRIPT_ERR_PUBKEY_COUNT,

    /* Failed verify operations */
    SCRIPT_ERR_VERIFY,
    SCRIPT_ERR_EQUALVERIFY,
    SCRIPT_ERR_CHECKMULTISIGVERIFY,
    SCRIPT_ERR_CHECKSIGVERIFY,
    SCRIPT_ERR_NUMEQUALVERIFY,

    /* Logical/Format/Canonical errors */
    SCRIPT_ERR_BAD_OPCODE,
    SCRIPT_ERR_DISABLED_OPCODE,
    SCRIPT_ERR_INVALID_STACK_OPERATION,
    SCRIPT_ERR_INVALID_ALTSTACK_OPERATION,
    SCRIPT_ERR_UNBALANCED_CONDITIONAL,

    /* CHECKLOCKTIMEVERIFY and CHECKSEQUENCEVERIFY */
    SCRIPT_ERR_NEGATIVE_LOCKTIME,
    SCRIPT_ERR_UNSATISFIED_LOCKTIME,

    /* Malleability */
    SCRIPT_ERR_SIG_HASHTYPE,
    SCRIPT_ERR_SIG_DER,
    SCRIPT_ERR_MINIMALDATA,
    SCRIPT_ERR_SIG_PUSHONLY,
    SCRIPT_ERR_SIG_HIGH_S,
    SCRIPT_ERR_SIG_NULLDUMMY,
    SCRIPT_ERR_PUBKEYTYPE,
    SCRIPT_ERR_CLEANSTACK,
    SCRIPT_ERR_MINIMALIF,
    SCRIPT_ERR_SIG_NULLFAIL,

    /* softfork safeness */
    SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS,
    SCRIPT_ERR_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM,
    SCRIPT_ERR_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION,
    SCRIPT_ERR_DISCOURAGE_OP_SUCCESS,
    SCRIPT_ERR_DISCOURAGE_UPGRADABLE_PUBKEYTYPE,

    /* segregated witness */
    SCRIPT_ERR_WITNESS_PROGRAM_WRONG_LENGTH,
    SCRIPT_ERR_WITNESS_PROGRAM_WITNESS_EMPTY,
    SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH,
    SCRIPT_ERR_WITNESS_MALLEATED,
    SCRIPT_ERR_WITNESS_MALLEATED_P2SH,
    SCRIPT_ERR_WITNESS_UNEXPECTED,
    SCRIPT_ERR_WITNESS_PUBKEYTYPE,

    /* Taproot */
    SCRIPT_ERR_SCHNORR_SIG_SIZE,
    SCRIPT_ERR_SCHNORR_SIG_HASHTYPE,
    SCRIPT_ERR_SCHNORR_SIG,
    SCRIPT_ERR_TAPROOT_WRONG_CONTROL_SIZE,
    SCRIPT_ERR_TAPSCRIPT_VALIDATION_WEIGHT,
    SCRIPT_ERR_TAPSCRIPT_CHECKMULTISIG,
    SCRIPT_ERR_TAPSCRIPT_MINIMALIF,

    /* Constant scriptCode */
    SCRIPT_ERR_OP_CODESEPARATOR,
    SCRIPT_ERR_SIG_FINDANDDELETE,

    //SCRIPT_ERR_ERROR_COUNT,
    //SCRIPT_ERR_LAST = Self::SCRIPT_ERR_ERROR_COUNT,
    /// This error does not exists in Bitcoin Core, it uses SCRIPT_ERR_UNKNOWN_ERROR
    SCRIPT_ERR_NUM_OVERFLOW,
    /// This error does not exists in Bitcoin Core, this is a limitation of this program
    SCRIPT_ERR_UNKNOWN_DEPTH,
}

impl ScriptError {
    pub fn description(&self) -> &'static str {
        match self {
            ScriptError::SCRIPT_ERR_OK => "No error",
            ScriptError::SCRIPT_ERR_EVAL_FALSE => {
                "Script evaluated without error but finished with a false/empty top stack element"
            }
            ScriptError::SCRIPT_ERR_VERIFY => "Script failed an OP_VERIFY operation",
            ScriptError::SCRIPT_ERR_EQUALVERIFY => "Script failed an OP_EQUALVERIFY operation",
            ScriptError::SCRIPT_ERR_CHECKMULTISIGVERIFY => {
                "Script failed an OP_CHECKMULTISIGVERIFY operation"
            }
            ScriptError::SCRIPT_ERR_CHECKSIGVERIFY => {
                "Script failed an OP_CHECKSIGVERIFY operation"
            }
            ScriptError::SCRIPT_ERR_NUMEQUALVERIFY => {
                "Script failed an OP_NUMEQUALVERIFY operation"
            }
            ScriptError::SCRIPT_ERR_SCRIPT_SIZE => "Script is too big",
            ScriptError::SCRIPT_ERR_PUSH_SIZE => "Push value size limit exceeded",
            ScriptError::SCRIPT_ERR_OP_COUNT => "Operation limit exceeded",
            ScriptError::SCRIPT_ERR_STACK_SIZE => "Stack size limit exceeded",
            ScriptError::SCRIPT_ERR_SIG_COUNT => {
                "Signature count negative or greater than pubkey count"
            }
            ScriptError::SCRIPT_ERR_PUBKEY_COUNT => "Pubkey count negative or limit exceeded",
            ScriptError::SCRIPT_ERR_BAD_OPCODE => "Opcode missing or not understood",
            ScriptError::SCRIPT_ERR_DISABLED_OPCODE => "Attempted to use a disabled opcode",
            ScriptError::SCRIPT_ERR_INVALID_STACK_OPERATION => {
                "Operation not valid with the current stack size"
            }
            ScriptError::SCRIPT_ERR_INVALID_ALTSTACK_OPERATION => {
                "Operation not valid with the current altstack size"
            }
            ScriptError::SCRIPT_ERR_OP_RETURN => "OP_RETURN was encountered",
            ScriptError::SCRIPT_ERR_UNBALANCED_CONDITIONAL => "Invalid OP_IF construction",
            ScriptError::SCRIPT_ERR_NEGATIVE_LOCKTIME => "Negative locktime",
            ScriptError::SCRIPT_ERR_UNSATISFIED_LOCKTIME => "Locktime requirement not satisfied",
            ScriptError::SCRIPT_ERR_SIG_HASHTYPE => "Signature hash type missing or not understood",
            ScriptError::SCRIPT_ERR_SIG_DER => "Non-canonical DER signature",
            ScriptError::SCRIPT_ERR_MINIMALDATA => "Data push larger than necessary",
            ScriptError::SCRIPT_ERR_SIG_PUSHONLY => "Only push operators allowed in signatures",
            ScriptError::SCRIPT_ERR_SIG_HIGH_S => {
                "Non-canonical signature: S value is unnecessarily high"
            }
            ScriptError::SCRIPT_ERR_SIG_NULLDUMMY => "Dummy CHECKMULTISIG argument must be zero",
            ScriptError::SCRIPT_ERR_MINIMALIF => "OP_IF/NOTIF argument must be minimal",
            ScriptError::SCRIPT_ERR_SIG_NULLFAIL => {
                "Signature must be zero for failed CHECK(MULTI)SIG operation"
            }
            ScriptError::SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS => {
                "NOPx reserved for soft-fork upgrades"
            }
            ScriptError::SCRIPT_ERR_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM => {
                "Witness version reserved for soft-fork upgrades"
            }
            ScriptError::SCRIPT_ERR_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION => {
                "Taproot version reserved for soft-fork upgrades"
            }
            ScriptError::SCRIPT_ERR_DISCOURAGE_OP_SUCCESS => {
                "OP_SUCCESSx reserved for soft-fork upgrades"
            }
            ScriptError::SCRIPT_ERR_DISCOURAGE_UPGRADABLE_PUBKEYTYPE => {
                "Public key version reserved for soft-fork upgrades"
            }
            ScriptError::SCRIPT_ERR_PUBKEYTYPE => {
                "Public key is neither compressed or uncompressed"
            }
            ScriptError::SCRIPT_ERR_CLEANSTACK => "Stack size must be exactly one after execution",
            ScriptError::SCRIPT_ERR_WITNESS_PROGRAM_WRONG_LENGTH => {
                "Witness program has incorrect length"
            }
            ScriptError::SCRIPT_ERR_WITNESS_PROGRAM_WITNESS_EMPTY => {
                "Witness program was passed an empty witness"
            }
            ScriptError::SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH => "Witness program hash mismatch",
            ScriptError::SCRIPT_ERR_WITNESS_MALLEATED => "Witness requires empty scriptSig",
            ScriptError::SCRIPT_ERR_WITNESS_MALLEATED_P2SH => {
                "Witness requires only-redeemscript scriptSig"
            }
            ScriptError::SCRIPT_ERR_WITNESS_UNEXPECTED => "Witness provided for non-witness script",
            ScriptError::SCRIPT_ERR_WITNESS_PUBKEYTYPE => "Using non-compressed keys in segwit",
            ScriptError::SCRIPT_ERR_SCHNORR_SIG_SIZE => "Invalid Schnorr signature size",
            ScriptError::SCRIPT_ERR_SCHNORR_SIG_HASHTYPE => "Invalid Schnorr signature hash type",
            ScriptError::SCRIPT_ERR_SCHNORR_SIG => "Invalid Schnorr signature",
            ScriptError::SCRIPT_ERR_TAPROOT_WRONG_CONTROL_SIZE => {
                "Invalid Taproot control block size"
            }
            ScriptError::SCRIPT_ERR_TAPSCRIPT_VALIDATION_WEIGHT => {
                "Too much signature validation relative to witness weight"
            }
            ScriptError::SCRIPT_ERR_TAPSCRIPT_CHECKMULTISIG => {
                "OP_CHECKMULTISIG(VERIFY) is not available in tapscript"
            }
            ScriptError::SCRIPT_ERR_TAPSCRIPT_MINIMALIF => {
                "OP_IF/NOTIF argument must be minimal in tapscript"
            }
            ScriptError::SCRIPT_ERR_OP_CODESEPARATOR => {
                "Using OP_CODESEPARATOR in non-witness script"
            }
            ScriptError::SCRIPT_ERR_SIG_FINDANDDELETE => "Signature is found in scriptCode",
            // bitcoin core returns unknown error for this one so added it myself
            ScriptError::SCRIPT_ERR_NUM_OVERFLOW => "Script number overflow",
            ScriptError::SCRIPT_ERR_UNKNOWN_DEPTH => "Depth argument could not be evaluated",
            ScriptError::SCRIPT_ERR_UNKNOWN_ERROR /* _ */ => "unknown error",
        }
    }
}

impl fmt::Display for ScriptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.description())
    }
}

impl std::error::Error for ScriptError {}
