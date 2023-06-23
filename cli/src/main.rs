use bitcoin_script_analyzer::{
    analyze_script, parse_script, ScriptContext, ScriptRules, ScriptVersion,
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
    let script_bytes = hex::decode(script_hex).unwrap();
    let script = parse_script(&script_bytes).unwrap();
    println!("script:");
    for a in &script {
        println!("{a}");
    }
    println!();
    let res = analyze_script(
        &script,
        ScriptContext::new(ScriptVersion::SegwitV0, ScriptRules::All),
        0,
    );
    println!("{}", unwrap_both(res));
}
