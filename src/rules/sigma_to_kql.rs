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

    Ok(SigmaDetection {
        title,
        table,
        blocks,
        condition,
    })
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
