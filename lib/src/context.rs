#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScriptVersion {
    Legacy,
    SegwitV0,
    SegwitV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScriptRules {
    ConsensusOnly,
    All,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScriptContext {
    pub version: ScriptVersion,
    pub rules: ScriptRules,
}

impl ScriptContext {
    pub fn new(version: ScriptVersion, rules: ScriptRules) -> Self {
        Self { version, rules }
    }
}
