#![cfg_attr(not(feature = "threads"), no_std)]

extern crate alloc;

mod analyzer;
pub mod condition_stack;
mod context;
mod expr;
mod opcode;
mod script;
pub mod script_error;
#[cfg(feature = "threads")]
mod threadpool;
pub mod util;

pub use crate::analyzer::analyze_script;
pub use crate::context::{ScriptContext, ScriptRules, ScriptVersion};
pub use crate::script::{
    OwnedScript, ParseScriptError, Script, ScriptElem, convert as script_convert,
};
