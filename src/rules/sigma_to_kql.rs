//! Sigma detection-logic → KQL (Azure Sentinel) query converter.
//!
//! Parses the `logsource:`/`detection:` blocks of a Sigma YAML rule into a
//! small condition AST, then emits a KQL query string. Deliberately supports
//! only the common, well-defined subset of the Sigma spec (plain field
//! matches with contains/startswith/endswith/re modifiers, and/or/not/
//! parens condition expressions, `1 of`/`all of` block-group references);
//! anything outside that (aggregations, correlation rules, external list
//! files, `|base64`/`|cidr`/`|fieldref` modifiers, etc.) returns
//! `Err(reason)` so the caller can fall back to keeping the original Sigma
//! YAML rather than emit a silently-wrong query.
//!
//! Known limitation: the Sigma field -> KQL column mapping is a small,
//! best-effort static table (see `FIELD_MAP`), not derived from each
//! destination table's real schema. It covers common Sysmon-style fields as
//! they appear in Defender XDR tables; other tables (e.g. ASIM-normalized,
//! SecurityEvent) may use different column names and are not remapped.

/// One field:value selection block, e.g. `Image|endswith: '\powershell.exe'`.
#[derive(Debug, Clone, PartialEq)]
pub struct FieldMatch {
    pub field: String,
    pub modifier: Modifier,
    /// OR'd together: Sigma list values under one field are implicitly ORed.
    pub values: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Modifier {
    Equals,
    Contains,
    StartsWith,
    EndsWith,
    /// `|re` — Sigma regex modifier, mapped to KQL `matches regex`.
    Regex,
}

/// A named selection block (`selection`, `filter`, `selection1`, ...): all
/// FieldMatch entries inside one block are AND'd together (Sigma semantics).
#[derive(Debug, Clone, PartialEq)]
pub struct SelectionBlock {
    pub name: String,
    pub fields: Vec<FieldMatch>,
}

/// The parsed `condition:` expression, restricted to the supported subset:
/// bare block refs, `and`/`or`/`not`, parens, and `1 of <pattern>` /
/// `all of <pattern>` where `<pattern>` is a literal block name or `them`/
/// a `selection*`-style prefix wildcard.
#[derive(Debug, Clone, PartialEq)]
pub enum ConditionExpr {
    Block(String),
    Not(Box<ConditionExpr>),
    And(Vec<ConditionExpr>),
    Or(Vec<ConditionExpr>),
    OneOf(String),
    AllOf(String),
}

#[derive(Debug, Clone, PartialEq)]
pub struct SigmaDetection {
    pub title: String,
    pub table: String, // resolved KQL table name, e.g. "SigninLogs"
    pub blocks: Vec<SelectionBlock>,
    pub condition: ConditionExpr,
}

/// Parse a Sigma YAML rule's logsource+detection into a `SigmaDetection`, or
/// `Err(reason)` if it uses something outside the supported subset (multiple
/// logsource services with no single table mapping, unsupported condition
/// syntax, aggregation functions, correlation rules, etc).
pub fn parse_sigma_rule(_yaml: &str) -> Result<SigmaDetection, String> {
    unimplemented!("step 2")
}

/// Emit a KQL query string from a parsed `SigmaDetection`.
pub fn to_kql(_detection: &SigmaDetection) -> String {
    unimplemented!("step 3")
}

#[cfg(test)]
mod tests {
    use super::*;

    const SIGMA_SIMPLE: &str = r#"
title: Suspicious PowerShell EncodedCommand
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith: '\powershell.exe'
        CommandLine|contains: '-EncodedCommand'
    condition: selection
"#;

    #[test]
    fn parses_simple_and_block() {
        let d = parse_sigma_rule(SIGMA_SIMPLE).expect("should parse");
        assert_eq!(d.blocks.len(), 1);
        assert_eq!(d.blocks[0].fields.len(), 2);
        assert_eq!(d.condition, ConditionExpr::Block("selection".into()));
    }
}
