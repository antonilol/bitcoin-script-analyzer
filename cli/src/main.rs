use bitcoin_script_analyzer::{
    analyze_script, util::decode_hex_in_place, OwnedScript, ScriptContext, ScriptRules,
    ScriptVersion,
};

fn unwrap_both<T>(res: Result<T, T>) -> T {
    match res {
        Ok(v) | Err(v) => v,
    }
}

pub fn main() {
    let script_hex = std::env::args()
        .nth(1)
        .expect("missing argument \"script\"");

    println!("hex: {script_hex}");
    let mut script_hex = script_hex.into_bytes();
    let script_bytes = decode_hex_in_place(&mut script_hex).unwrap();
    let script = OwnedScript::parse_from_bytes(script_bytes).unwrap();
    println!("script:\n{script}");
    println!();
    let res = analyze_script(
        &script,
        ScriptContext::new(ScriptVersion::SegwitV0, ScriptRules::All),
        0,
    );
    println!("{}", unwrap_both(res));
}
