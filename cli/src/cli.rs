use clap::{Parser, ValueEnum};

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum InputType {
    Hex,
    Asm,
}

#[derive(Parser)]
#[command(version, about, long_about = None)]
pub struct Args {
    /// Script encoding
    pub input_type: InputType,

    /// Script
    pub input: String,
}
