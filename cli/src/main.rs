mod cli;

use self::cli::Args;

use bitcoin_script_analyzer::util::{decode_hex_in_place, encode_hex_easy};
use bitcoin_script_analyzer::{
    OwnedScript, ScriptContext, ScriptRules, ScriptVersion, analyze_script,
};
use clap::Parser;
use cli::InputType;

fn unwrap_both<T>(res: Result<T, T>) -> T {
    match res {
        Ok(v) | Err(v) => v,
    }
}

pub fn main() {
    let args = Args::parse();

    let mut script = args.input.into_bytes();
    let (bytes, script) = match args.input_type {
        InputType::Hex => {
            let bytes = decode_hex_in_place(&mut script).unwrap();
            (bytes, OwnedScript::parse_from_bytes(bytes).unwrap())
        }
        InputType::Asm => OwnedScript::parse_from_asm_in_place(&mut script).unwrap(),
    };

    println!("hex: {}\nscript:\n{script}\n", encode_hex_easy(bytes));

    let res = analyze_script(
        &script,
        ScriptContext::new(ScriptVersion::SegwitV0, ScriptRules::All),
        0,
    );

    println!("{}", unwrap_both(res));
}
