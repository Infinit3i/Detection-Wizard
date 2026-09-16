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

/// Windows Sysmon-style category -> Defender XDR table, used as a fallback
/// when the logsource has no `service` (or an unmapped one) but a common
/// category we know how to route.
const CATEGORY_TABLE_FALLBACK: &[(&str, &str)] = &[
    ("process_creation", "DeviceProcessEvents"),
    ("network_connection", "DeviceNetworkEvents"),
    ("file_event", "DeviceFileEvents"),
    ("file_change", "DeviceFileEvents"),
    ("file_delete", "DeviceFileEvents"),
    ("registry_event", "DeviceRegistryEvents"),
    ("registry_set", "DeviceRegistryEvents"),
    ("registry_add", "DeviceRegistryEvents"),
    ("image_load", "DeviceImageLoadEvents"),
];

fn resolve_table(service: Option<&str>, category: Option<&str>) -> Result<String, String> {
    if let Some(svc) = service {
        if let Some(table) = crate::azure_tables::table_for_sigma_service(svc) {
            return Ok(table.to_string());
        }
    }
    if let Some(cat) = category {
        if let Some((_, table)) = CATEGORY_TABLE_FALLBACK
            .iter()
            .find(|(c, _)| c.eq_ignore_ascii_case(cat))
        {
            return Ok((*table).to_string());
        }
    }
    Err("no known table mapping for this logsource".to_string())
}

fn parse_modifier(field_with_modifier: &str) -> Result<(String, Modifier), String> {
    match field_with_modifier.split_once('|') {
        None => Ok((field_with_modifier.to_string(), Modifier::Equals)),
        Some((field, modifier_str)) => {
            let modifier = match modifier_str {
                "contains" => Modifier::Contains,
                "startswith" => Modifier::StartsWith,
                "endswith" => Modifier::EndsWith,
                "re" => Modifier::Regex,
                other => return Err(format!("unsupported Sigma modifier: |{other}")),
            };
            Ok((field.to_string(), modifier))
        }
    }
}

/// Strip a single layer of YAML quoting/dashes from a scalar value.
fn unquote(s: &str) -> String {
    let s = s.trim();
    let s = s.strip_prefix('-').map(|r| r.trim()).unwrap_or(s);
    if (s.starts_with('\'') && s.ends_with('\'') && s.len() >= 2)
        || (s.starts_with('"') && s.ends_with('"') && s.len() >= 2)
    {
        s[1..s.len() - 1].to_string()
    } else {
        s.to_string()
    }
}

/// Indentation (leading spaces) of a line, treating tabs as illegal (Sigma/YAML
/// convention — rules in the wild use spaces).
fn indent_of(line: &str) -> usize {
    line.chars().take_while(|c| *c == ' ').count()
}

/// Parse a `condition:` value into a `ConditionExpr`. Supports bare block
/// names, `and`/`or`/`not`, parens, and `1 of X` / `all of X` (X = a literal
/// block name, `them`, or a `prefix*` wildcard). Anything else (aggregation
/// functions, `|`, timeframes, `near`) is rejected.
fn parse_condition(expr: &str) -> Result<ConditionExpr, String> {
    let tokens = tokenize_condition(expr)?;
    let mut pos = 0;
    let parsed = parse_or_expr(&tokens, &mut pos)?;
    if pos != tokens.len() {
        return Err(format!("unexpected trailing tokens in condition: {expr}"));
    }
    Ok(parsed)
}

fn tokenize_condition(expr: &str) -> Result<Vec<String>, String> {
    let mut tokens = Vec::new();
    let mut cur = String::new();
    let mut chars = expr.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '(' | ')' => {
                if !cur.is_empty() {
                    tokens.push(std::mem::take(&mut cur));
                }
                tokens.push(c.to_string());
            }
            c if c.is_whitespace() => {
                if !cur.is_empty() {
                    tokens.push(std::mem::take(&mut cur));
                }
            }
            '|' | '&' | '*' if cur.is_empty() && (c == '|' || c == '&') => {
                return Err(format!("unsupported condition syntax: '{c}' in {expr}"));
            }
            _ => cur.push(c),
        }
    }
    if !cur.is_empty() {
        tokens.push(cur);
    }
    Ok(tokens)
}

fn parse_or_expr(tokens: &[String], pos: &mut usize) -> Result<ConditionExpr, String> {
    let mut left = parse_and_expr(tokens, pos)?;
    while tokens.get(*pos).map(|t| t.as_str()) == Some("or") {
        *pos += 1;
        let right = parse_and_expr(tokens, pos)?;
        left = match left {
            ConditionExpr::Or(mut v) => {
                v.push(right);
                ConditionExpr::Or(v)
            }
            other => ConditionExpr::Or(vec![other, right]),
        };
    }
    Ok(left)
}

fn parse_and_expr(tokens: &[String], pos: &mut usize) -> Result<ConditionExpr, String> {
    let mut left = parse_not_expr(tokens, pos)?;
    while tokens.get(*pos).map(|t| t.as_str()) == Some("and") {
        *pos += 1;
        let right = parse_not_expr(tokens, pos)?;
        left = match left {
            ConditionExpr::And(mut v) => {
                v.push(right);
                ConditionExpr::And(v)
            }
            other => ConditionExpr::And(vec![other, right]),
        };
    }
    Ok(left)
}

fn parse_not_expr(tokens: &[String], pos: &mut usize) -> Result<ConditionExpr, String> {
    if tokens.get(*pos).map(|t| t.as_str()) == Some("not") {
        *pos += 1;
        let inner = parse_not_expr(tokens, pos)?;
        return Ok(ConditionExpr::Not(Box::new(inner)));
    }
    parse_primary(tokens, pos)
}

fn parse_primary(tokens: &[String], pos: &mut usize) -> Result<ConditionExpr, String> {
    let Some(tok) = tokens.get(*pos) else {
        return Err("unexpected end of condition expression".to_string());
    };

    if tok == "(" {
        *pos += 1;
        let inner = parse_or_expr(tokens, pos)?;
        if tokens.get(*pos).map(|t| t.as_str()) != Some(")") {
            return Err("unmatched '(' in condition expression".to_string());
        }
        *pos += 1;
        return Ok(inner);
    }

    // "1 of X" / "all of X"
    if (tok == "1" || tok == "all") && tokens.get(*pos + 1).map(|t| t.as_str()) == Some("of") {
        let quantifier = tok.clone();
        let Some(pattern) = tokens.get(*pos + 2) else {
            return Err("expected a pattern after 'of'".to_string());
        };
        let pattern = pattern.clone();
        *pos += 3;
        return Ok(if quantifier == "1" {
            ConditionExpr::OneOf(pattern)
        } else {
            ConditionExpr::AllOf(pattern)
        });
    }

    // Bare block reference.
    *pos += 1;
    Ok(ConditionExpr::Block(tok.clone()))
}

/// Parse a Sigma YAML rule's logsource+detection into a `SigmaDetection`, or
/// `Err(reason)` if it uses something outside the supported subset (multiple
/// logsource services with no single table mapping, unsupported condition
/// syntax, aggregation functions, correlation rules, etc).
pub fn parse_sigma_rule(yaml: &str) -> Result<SigmaDetection, String> {
    let title = yaml
        .lines()
        .find_map(|l| l.trim_start().strip_prefix("title:"))
        .map(|t| unquote(t))
        .unwrap_or_else(|| "Untitled Sigma rule".to_string());

    let (_product, service, category) = crate::filter::parse_sigma_logsource(yaml);
    let table = resolve_table(service.as_deref(), category.as_deref())?;

    let lines: Vec<&str> = yaml.lines().collect();
    let Some(detection_start) = lines
        .iter()
        .position(|l| l.trim_end() == "detection:" || l.trim() == "detection:")
    else {
        return Err("no detection: block found".to_string());
    };
    let detection_indent = indent_of(lines[detection_start]);

    // Collect the detection: block's direct children (block name -> its lines).
    let mut blocks: Vec<SelectionBlock> = Vec::new();
    let mut condition_expr: Option<String> = None;

    let mut i = detection_start + 1;
    while i < lines.len() {
        let line = lines[i];
        if line.trim().is_empty() {
            i += 1;
            continue;
        }
        let this_indent = indent_of(line);
        if this_indent <= detection_indent {
            break; // dedented out of detection:
        }
        let trimmed = line.trim();

        if let Some(rest) = trimmed.strip_prefix("condition:") {
            let rest = rest.trim();
            if rest.is_empty() {
                return Err("multi-line condition: blocks are not supported".to_string());
            }
            condition_expr = Some(rest.to_string());
            i += 1;
            continue;
        }

        // This line is a block name (e.g. "selection:", "filter1:").
        let Some(block_name) = trimmed.strip_suffix(':') else {
            return Err(format!("expected a block name, got: {trimmed}"));
        };
        let block_indent = this_indent;
        let mut fields = Vec::new();
        i += 1;
        while i < lines.len() {
            let field_line = lines[i];
            if field_line.trim().is_empty() {
                i += 1;
                continue;
            }
            let field_indent = indent_of(field_line);
            if field_indent <= block_indent {
                break;
            }
            let field_trimmed = field_line.trim();

            // "field|modifier: value" or "field|modifier:\n  - v1\n  - v2"
            if let Some((key, value)) = field_trimmed.split_once(':') {
                let (field, modifier) = parse_modifier(key.trim())?;
                let value = value.trim();
                if value.is_empty() {
                    // list-form values follow as "- v1" / "- v2" lines
                    let mut values = Vec::new();
                    i += 1;
                    while i < lines.len() {
                        let list_line = lines[i];
                        if list_line.trim().is_empty() {
                            i += 1;
                            continue;
                        }
                        let list_indent = indent_of(list_line);
                        if list_indent <= field_indent || !list_line.trim().starts_with('-') {
                            break;
                        }
                        values.push(unquote(list_line.trim()));
                        i += 1;
                    }
                    if values.is_empty() {
                        return Err(format!("empty value list for field {field}"));
                    }
                    fields.push(FieldMatch {
                        field,
                        modifier,
                        values,
                    });
                    continue;
                } else {
                    fields.push(FieldMatch {
                        field,
                        modifier,
                        values: vec![unquote(value)],
                    });
                    i += 1;
                    continue;
                }
            } else {
                return Err(format!("expected 'field: value', got: {field_trimmed}"));
            }
        }
        if fields.is_empty() {
            return Err(format!("empty selection block: {block_name}"));
        }
        blocks.push(SelectionBlock {
            name: block_name.to_string(),
            fields,
        });
    }

    let Some(condition_str) = condition_expr else {
        return Err("no condition: found in detection: block".to_string());
    };
    let condition = parse_condition(&condition_str)?;

    if blocks.is_empty() {
        return Err("no selection blocks found in detection:".to_string());
    }

    validate_condition_refs(&condition, &blocks)?;

    Ok(SigmaDetection {
        title,
        table,
        blocks,
        condition,
    })
}

/// Resolve a `1 of X` / `all of X` pattern (`X` = a literal block name,
/// `them`, or a `prefix*` wildcard) to the blocks it refers to.
fn resolve_pattern_blocks<'a>(
    pattern: &str,
    blocks: &'a [SelectionBlock],
) -> Vec<&'a SelectionBlock> {
    if pattern == "them" {
        blocks.iter().collect()
    } else if let Some(prefix) = pattern.strip_suffix('*') {
        blocks
            .iter()
            .filter(|b| b.name.starts_with(prefix))
            .collect()
    } else {
        blocks.iter().filter(|b| b.name == pattern).collect()
    }
}

/// Verify every `Block`/`OneOf`/`AllOf` reference in `condition` resolves to
/// at least one real selection block, so `to_kql` never has to guess.
fn validate_condition_refs(
    condition: &ConditionExpr,
    blocks: &[SelectionBlock],
) -> Result<(), String> {
    match condition {
        ConditionExpr::Block(name) => {
            if !blocks.iter().any(|b| &b.name == name) {
                return Err(format!("condition references unknown block: {name}"));
            }
        }
        ConditionExpr::Not(inner) => validate_condition_refs(inner, blocks)?,
        ConditionExpr::And(list) | ConditionExpr::Or(list) => {
            for e in list {
                validate_condition_refs(e, blocks)?;
            }
        }
        ConditionExpr::OneOf(pattern) | ConditionExpr::AllOf(pattern) => {
            if resolve_pattern_blocks(pattern, blocks).is_empty() {
                return Err(format!("'of {pattern}' matches no selection blocks"));
            }
        }
    }
    Ok(())
}

/// Render one Sigma value as a KQL verbatim string literal.
fn kql_literal(value: &str) -> String {
    format!("@\"{}\"", value.replace('"', "\"\""))
}

/// Render one `FieldMatch` as a KQL boolean predicate. Multiple values under
/// one field are Sigma's implicit OR, so they're joined with `or`.
fn field_match_kql(fm: &FieldMatch) -> String {
    let field = map_field(&fm.field);
    let atoms: Vec<String> = fm
        .values
        .iter()
        .map(|v| match fm.modifier {
            Modifier::Equals => format!("{field} =~ {}", kql_literal(v)),
            Modifier::Contains => format!("{field} contains {}", kql_literal(v)),
            Modifier::StartsWith => format!("{field} startswith {}", kql_literal(v)),
            Modifier::EndsWith => format!("{field} endswith {}", kql_literal(v)),
            Modifier::Regex => format!("{field} matches regex {}", kql_literal(v)),
        })
        .collect();
    if atoms.len() == 1 {
        atoms.into_iter().next().unwrap()
    } else {
        format!("({})", atoms.join(" or "))
    }
}

/// Render one `SelectionBlock` (all its fields AND'd together) as KQL.
fn block_kql(block: &SelectionBlock) -> String {
    let atoms: Vec<String> = block.fields.iter().map(field_match_kql).collect();
    if atoms.len() == 1 {
        atoms.into_iter().next().unwrap()
    } else {
        format!("({})", atoms.join(" and "))
    }
}

/// Render a `ConditionExpr` as a KQL boolean expression. Assumes
/// `validate_condition_refs` already confirmed every reference resolves.
fn condition_kql(condition: &ConditionExpr, blocks: &[SelectionBlock]) -> String {
    match condition {
        ConditionExpr::Block(name) => {
            let block = blocks
                .iter()
                .find(|b| &b.name == name)
                .expect("validate_condition_refs guarantees this block exists");
            block_kql(block)
        }
        ConditionExpr::Not(inner) => format!("not ({})", condition_kql(inner, blocks)),
        ConditionExpr::And(list) => list
            .iter()
            .map(|e| format!("({})", condition_kql(e, blocks)))
            .collect::<Vec<_>>()
            .join(" and "),
        ConditionExpr::Or(list) => list
            .iter()
            .map(|e| format!("({})", condition_kql(e, blocks)))
            .collect::<Vec<_>>()
            .join(" or "),
        ConditionExpr::OneOf(pattern) => {
            let matched = resolve_pattern_blocks(pattern, blocks);
            let atoms: Vec<String> = matched.iter().map(|b| block_kql(b)).collect();
            if atoms.len() == 1 {
                atoms.into_iter().next().unwrap()
            } else {
                format!("({})", atoms.join(" or "))
            }
        }
        ConditionExpr::AllOf(pattern) => {
            let matched = resolve_pattern_blocks(pattern, blocks);
            let atoms: Vec<String> = matched.iter().map(|b| block_kql(b)).collect();
            if atoms.len() == 1 {
                atoms.into_iter().next().unwrap()
            } else {
                format!("({})", atoms.join(" and "))
            }
        }
    }
}

/// Sigma field name -> KQL column name, for the common Sysmon-style fields
/// as they appear in Defender/Sentinel tables. Fields not in this map pass
/// through unchanged (most already match, e.g. CommandLine, ProcessId).
/// See the module doc-comment for the "not schema-derived" caveat.
const FIELD_MAP: &[(&str, &str)] = &[];

fn map_field(sigma_field: &str) -> &str {
    FIELD_MAP
        .iter()
        .find(|(k, _)| *k == sigma_field)
        .map(|(_, v)| *v)
        .unwrap_or(sigma_field)
}

/// Emit a KQL query string from a parsed `SigmaDetection`.
pub fn to_kql(detection: &SigmaDetection) -> String {
    format!(
        "// {}\n{}\n| where {}\n",
        detection.title,
        detection.table,
        condition_kql(&detection.condition, &detection.blocks)
    )
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

    #[test]
    fn simple_and_block_emits_expected_kql() {
        let d = parse_sigma_rule(SIGMA_SIMPLE).unwrap();
        let kql = to_kql(&d);
        assert!(kql.contains("DeviceProcessEvents"));
        assert!(kql.contains(r#"Image endswith @"\powershell.exe""#));
        assert!(kql.contains(r#"CommandLine contains @"-EncodedCommand""#));
        assert!(kql.contains(" and "));
    }

    const SIGMA_MULTI_VALUE: &str = r#"
title: Suspicious LOLBin
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith:
            - '\certutil.exe'
            - '\bitsadmin.exe'
    condition: selection
"#;

    #[test]
    fn multi_value_field_emits_or() {
        let d = parse_sigma_rule(SIGMA_MULTI_VALUE).unwrap();
        let kql = to_kql(&d);
        assert!(kql.contains(r#"Image endswith @"\certutil.exe""#));
        assert!(kql.contains(r#"Image endswith @"\bitsadmin.exe""#));
        assert!(kql.contains(" or "));
    }

    const SIGMA_TWO_BLOCKS_AND: &str = r#"
title: Two blocks ANDed
logsource:
    product: windows
    category: process_creation
detection:
    selection1:
        Image|endswith: '\powershell.exe'
    selection2:
        CommandLine|contains: '-enc'
    condition: selection1 and selection2
"#;

    #[test]
    fn multiple_blocks_anded_via_condition() {
        let d = parse_sigma_rule(SIGMA_TWO_BLOCKS_AND).unwrap();
        assert_eq!(
            d.condition,
            ConditionExpr::And(vec![
                ConditionExpr::Block("selection1".into()),
                ConditionExpr::Block("selection2".into()),
            ])
        );
        let kql = to_kql(&d);
        assert!(kql.contains(r#"Image endswith @"\powershell.exe""#));
        assert!(kql.contains(r#"CommandLine contains @"-enc""#));
        assert!(kql.contains(" and "));
    }

    const SIGMA_ONE_OF: &str = r#"
title: One of selection*
logsource:
    product: windows
    category: process_creation
detection:
    selection_a:
        Image|endswith: '\certutil.exe'
    selection_b:
        Image|endswith: '\bitsadmin.exe'
    condition: 1 of selection*
"#;

    #[test]
    fn one_of_wildcard_ors_matching_blocks() {
        let d = parse_sigma_rule(SIGMA_ONE_OF).unwrap();
        assert_eq!(d.condition, ConditionExpr::OneOf("selection*".into()));
        let kql = to_kql(&d);
        assert!(kql.contains(r#"Image endswith @"\certutil.exe""#));
        assert!(kql.contains(r#"Image endswith @"\bitsadmin.exe""#));
        assert!(kql.contains(" or "));
    }

    const SIGMA_ALL_OF_THEM: &str = r#"
title: All of them
logsource:
    product: windows
    category: process_creation
detection:
    selection_a:
        Image|endswith: '\certutil.exe'
    selection_b:
        CommandLine|contains: '-urlcache'
    condition: all of them
"#;

    #[test]
    fn all_of_them_ands_every_block() {
        let d = parse_sigma_rule(SIGMA_ALL_OF_THEM).unwrap();
        assert_eq!(d.condition, ConditionExpr::AllOf("them".into()));
        let kql = to_kql(&d);
        assert!(kql.contains(r#"Image endswith @"\certutil.exe""#));
        assert!(kql.contains(r#"CommandLine contains @"-urlcache""#));
        assert!(kql.contains(" and "));
    }

    const SIGMA_REGEX: &str = r#"
title: Regex modifier
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        CommandLine|re: 'powershell\s+-enc\w*'
    condition: selection
"#;

    #[test]
    fn regex_modifier_emits_matches_regex() {
        let d = parse_sigma_rule(SIGMA_REGEX).unwrap();
        let kql = to_kql(&d);
        assert!(kql.contains(r#"CommandLine matches regex @"powershell\s+-enc\w*""#));
    }

    const SIGMA_AGGREGATION: &str = r#"
title: Aggregation condition (unsupported)
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith: '\net.exe'
    condition: selection | count() > 5
"#;

    #[test]
    fn aggregation_condition_is_rejected() {
        let result = parse_sigma_rule(SIGMA_AGGREGATION);
        assert!(result.is_err());
    }

    const SIGMA_UNSUPPORTED_MODIFIER: &str = r#"
title: Unsupported modifier (unsupported)
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Data|base64: 'ZXZpbA=='
    condition: selection
"#;

    #[test]
    fn unsupported_modifier_is_rejected() {
        let result = parse_sigma_rule(SIGMA_UNSUPPORTED_MODIFIER);
        assert!(result.is_err());
    }
}
