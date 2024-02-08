// maybe later
// #![cfg_attr(not(feature = "threads"), no_std)]
// extern crate alloc;

mod analyzer;
pub mod condition_stack;
mod context;
mod expr;
mod opcode;
mod script;
pub mod script_error;
mod threadpool;
pub mod util;

pub use crate::{
    analyzer::analyze_script,
    context::{ScriptContext, ScriptRules, ScriptVersion},
    script::{convert as script_convert, OwnedScript, ParseScriptError, Script, ScriptElem},
};
