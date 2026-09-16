//! Cross-format detection-rule converter: Sigma YAML, KQL (Sentinel), Splunk
//! SPL, and QRadar AQL all parse into one shared `RuleAst` (a small field-
//! match/AND/OR/NOT condition tree), which any of the four formats can then
//! be re-emitted from. This lets the Rules screen support "output everything
//! as <language>" regardless of which formats the source rules were
//! originally written in.
//!
//! Deliberately supports only the common, well-defined subset each language
//! actually uses in practice (plain field matches with contains/startswith/
//! endswith/regex modifiers, and/or/not/parens condition expressions,
//! Sigma's `1 of`/`all of` block-group references); anything outside that
//! (aggregations, correlation rules, external list files, Sigma's
//! `|base64`/`|cidr`/`|fieldref` modifiers, SPL `stats`/`transaction`,
//! AQL `GROUP BY`, etc.) returns `Err(reason)` from the relevant `parse_*`
//! function so the caller can fall back to keeping the rule in its original
//! format rather than emit a silently-wrong query.
//!
//! Known limitation: the field-name mapping between formats is a small,
//! best-effort static table (see `FIELD_MAP`), not derived from each
//! destination's real schema. It covers common Sysmon-style fields as they
//! appear in Defender XDR KQL tables; other tables/formats may use
//! different field names and are not remapped.

/// One field:value selection block, e.g. `Image|endswith: '\powershell.exe'`.
#[derive(Debug, Clone, PartialEq)]
pub struct FieldMatch {
    pub field: String,
    pub modifier: Modifier,
    /// OR'd together: list values under one field are implicitly ORed.
    pub values: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Modifier {
    Equals,
    Contains,
    StartsWith,
    EndsWith,
    /// Regex match (Sigma `|re`, KQL `matches regex`, SPL `rex`/`match()`,
    /// AQL `MATCHES`).
    Regex,
}

/// A named selection block (`selection`, `filter`, `selection1`, ...): all
/// FieldMatch entries inside one block are AND'd together (Sigma semantics;
/// KQL/SPL/AQL rules that don't have named blocks are represented as one
/// block named "selection").
#[derive(Debug, Clone, PartialEq)]
pub struct SelectionBlock {
    pub name: String,
    pub fields: Vec<FieldMatch>,
}

/// The parsed condition expression, restricted to the supported subset:
/// bare block refs, `and`/`or`/`not`, parens, and `1 of <pattern>` /
/// `all of <pattern>` where `<pattern>` is a literal block name or `them`/
/// a `selection*`-style prefix wildcard (Sigma-only condition syntax; other
/// formats' parsers only ever produce Block/And/Or/Not nodes).
#[derive(Debug, Clone, PartialEq)]
pub enum ConditionExpr {
    Block(String),
    Not(Box<ConditionExpr>),
    And(Vec<ConditionExpr>),
    Or(Vec<ConditionExpr>),
    OneOf(String),
    AllOf(String),
}

/// A detection rule's logic, independent of which format it was parsed
/// from: a data source name (KQL table / Splunk sourcetype-ish label / AQL
/// event category), the named selection blocks, and how they combine.
#[derive(Debug, Clone, PartialEq)]
pub struct RuleAst {
    pub title: String,
    pub source: String, // e.g. KQL table "SigninLogs", or a generic source label
    pub blocks: Vec<SelectionBlock>,
    pub condition: ConditionExpr,
}

/// Back-compat alias: earlier revisions of this module called this type
/// `SigmaDetection` before it became format-agnostic.
pub type SigmaDetection = RuleAst;

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

    Ok(RuleAst {
        title,
        source: table,
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
const FIELD_MAP: &[(&str, &str)] = &[
    ("Image", "FolderPath"),
    ("ParentImage", "InitiatingProcessFolderPath"),
    ("TargetFilename", "FolderPath"),
    ("DestinationIp", "RemoteIP"),
    ("DestinationPort", "RemotePort"),
    ("User", "AccountName"),
];

fn map_field(sigma_field: &str) -> &str {
    FIELD_MAP
        .iter()
        .find(|(k, _)| *k == sigma_field)
        .map(|(_, v)| *v)
        .unwrap_or(sigma_field)
}

/// Emit a KQL query string from a parsed `RuleAst`.
pub fn to_kql(detection: &RuleAst) -> String {
    format!(
        "// {}\n{}\n| where {}\n",
        detection.title,
        detection.source,
        condition_kql(&detection.condition, &detection.blocks)
    )
}

/// Sigma modifier suffix for a `Modifier`, e.g. `|endswith` (Equals has no
/// suffix at all).
fn sigma_modifier_suffix(modifier: Modifier) -> &'static str {
    match modifier {
        Modifier::Equals => "",
        Modifier::Contains => "|contains",
        Modifier::StartsWith => "|startswith",
        Modifier::EndsWith => "|endswith",
        Modifier::Regex => "|re",
    }
}

/// Render one `FieldMatch` as Sigma YAML lines (`field|modifier: value` or a
/// value-list form for multi-value fields), indented by `indent` spaces.
fn field_match_sigma(fm: &FieldMatch, indent: usize) -> String {
    let pad = " ".repeat(indent);
    let key = format!("{}{}", fm.field, sigma_modifier_suffix(fm.modifier));
    if fm.values.len() == 1 {
        format!("{pad}{key}: '{}'\n", fm.values[0])
    } else {
        let mut out = format!("{pad}{key}:\n");
        for v in &fm.values {
            out.push_str(&format!("{pad}    - '{v}'\n"));
        }
        out
    }
}

/// Render a `ConditionExpr` as a Sigma `condition:` value string.
fn condition_sigma(condition: &ConditionExpr) -> String {
    match condition {
        ConditionExpr::Block(name) => name.clone(),
        ConditionExpr::Not(inner) => format!("not {}", condition_sigma_parenthesized(inner)),
        ConditionExpr::And(list) => list
            .iter()
            .map(condition_sigma_parenthesized)
            .collect::<Vec<_>>()
            .join(" and "),
        ConditionExpr::Or(list) => list
            .iter()
            .map(condition_sigma_parenthesized)
            .collect::<Vec<_>>()
            .join(" or "),
        ConditionExpr::OneOf(pattern) => format!("1 of {pattern}"),
        ConditionExpr::AllOf(pattern) => format!("all of {pattern}"),
    }
}

fn condition_sigma_parenthesized(condition: &ConditionExpr) -> String {
    match condition {
        ConditionExpr::And(_) | ConditionExpr::Or(_) => format!("({})", condition_sigma(condition)),
        _ => condition_sigma(condition),
    }
}

/// Emit a Sigma YAML rule string from a parsed `RuleAst`. Used when the
/// user's chosen target language is Sigma, so KQL/SPL/AQL source rules that
/// were successfully parsed into a `RuleAst` can be re-emitted as Sigma.
/// `product`/`category` populate the `logsource:` block since `RuleAst` only
/// carries a resolved source label, not the original Sigma logsource keys.
pub fn to_sigma(detection: &RuleAst, product: &str, category: &str) -> String {
    let mut out = String::new();
    out.push_str(&format!("title: {}\n", detection.title));
    out.push_str("logsource:\n");
    out.push_str(&format!("    product: {product}\n"));
    out.push_str(&format!("    category: {category}\n"));
    out.push_str("detection:\n");
    for block in &detection.blocks {
        out.push_str(&format!("    {}:\n", block.name));
        for fm in &block.fields {
            out.push_str(&field_match_sigma(fm, 8));
        }
    }
    out.push_str(&format!(
        "    condition: {}\n",
        condition_sigma(&detection.condition)
    ));
    out
}

/// Parse a KQL analytics-rule query (as emitted by `to_kql`, or a hand-
/// written Sentinel rule of the same shape) into a `RuleAst`.
///
/// Expected shape: optional leading `//` comment lines (the first becomes
/// the title), then a bare table name line, then one or more `| where
/// <expr>` lines (ANDed together if there's more than one). Any other pipe
/// stage (`| summarize`, `| project`, `| extend`, ...) is rejected rather
/// than silently ignored, since it could change the query's meaning.
pub fn parse_kql(kql: &str) -> Result<RuleAst, String> {
    let mut title = "Untitled rule".to_string();
    let mut table: Option<String> = None;
    let mut where_exprs: Vec<String> = Vec::new();
    let mut seen_table_line = false;

    for raw_line in kql.lines() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(comment) = line.strip_prefix("//") {
            if table.is_none() && title == "Untitled rule" {
                title = comment.trim().to_string();
            }
            continue;
        }
        if let Some(rest) = line.strip_prefix('|') {
            let rest = rest.trim();
            if let Some(where_expr) = rest.strip_prefix("where") {
                where_exprs.push(where_expr.trim().to_string());
            } else {
                return Err(format!("unsupported KQL pipe stage: | {rest}"));
            }
            continue;
        }
        if !seen_table_line {
            table = Some(line.to_string());
            seen_table_line = true;
            continue;
        }
        return Err(format!("unexpected KQL line: {line}"));
    }

    let Some(table) = table else {
        return Err("no table name found in KQL query".to_string());
    };
    if where_exprs.is_empty() {
        return Err("no | where clause found in KQL query".to_string());
    }

    // Each `| where` line is its own AND'd predicate expression; parse each
    // into a small selection block and AND the blocks together via an
    // ANDed condition (or a single Block reference if there's only one).
    let mut blocks = Vec::with_capacity(where_exprs.len());
    for (i, expr) in where_exprs.iter().enumerate() {
        let name = if where_exprs.len() == 1 {
            "selection".to_string()
        } else {
            format!("selection{}", i + 1)
        };
        let fields = parse_kql_predicate(expr)?;
        blocks.push(SelectionBlock { name, fields });
    }

    let condition = if blocks.len() == 1 {
        ConditionExpr::Block(blocks[0].name.clone())
    } else {
        ConditionExpr::And(
            blocks
                .iter()
                .map(|b| ConditionExpr::Block(b.name.clone()))
                .collect(),
        )
    };

    Ok(RuleAst {
        title,
        source: table,
        blocks,
        condition,
    })
}

/// Reverse of `map_field`: KQL column name -> Sigma-style field name, when
/// there's a unique FIELD_MAP entry for it. Falls through unchanged when
/// there's no mapping (or the column is ambiguous, e.g. FolderPath maps
/// from both Image and TargetFilename -- in that case the KQL column name
/// itself is kept as the field name).
fn unmap_field(kql_field: &str) -> String {
    let matches: Vec<&str> = FIELD_MAP
        .iter()
        .filter(|(_, v)| *v == kql_field)
        .map(|(k, _)| *k)
        .collect();
    if matches.len() == 1 {
        matches[0].to_string()
    } else {
        kql_field.to_string()
    }
}

/// Strip a single layer of fully-wrapping parentheses, e.g. `"(a and b)"` ->
/// `"a and b"`. Only strips when the outermost `(` and its matching `)`
/// actually wrap the entire string (not e.g. `"(a) and (b)"`).
fn strip_wrapping_parens(expr: &str) -> &str {
    let trimmed = expr.trim();
    if !trimmed.starts_with('(') || !trimmed.ends_with(')') {
        return trimmed;
    }
    let mut depth = 0i32;
    for (i, c) in trimmed.char_indices() {
        match c {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 && i != trimmed.len() - 1 {
                    // the first '(' closes before the end -> not a full wrap
                    return trimmed;
                }
            }
            _ => {}
        }
    }
    &trimmed[1..trimmed.len() - 1]
}

/// Parse one KQL `| where` predicate expression, split on top-level ` and `
/// (case-sensitive lowercase `and`, matching what `to_kql` emits), into the
/// FieldMatch list for one selection block. Each atom must be
/// `<field> <op> @"<value>"` (optionally `(atom or atom or ...)` for a
/// single field's multi-value OR group, as emitted by `field_match_kql`).
/// Anything else (KQL functions, `in~ (...)`, numeric comparisons, nested
/// AND/OR of different fields) is rejected.
fn parse_kql_predicate(expr: &str) -> Result<Vec<FieldMatch>, String> {
    let expr = strip_wrapping_parens(expr);
    let mut fields = Vec::new();
    for atom in split_top_level(expr, " and ") {
        fields.push(parse_kql_atom_or_or_group(atom.trim())?);
    }
    Ok(fields)
}

/// Split `expr` on a literal separator that isn't inside parentheses.
fn split_top_level<'a>(expr: &'a str, sep: &str) -> Vec<&'a str> {
    let mut parts = Vec::new();
    let mut depth = 0i32;
    let mut start = 0usize;
    let bytes = expr.as_bytes();
    let sep_bytes = sep.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        match bytes[i] {
            b'(' => depth += 1,
            b')' => depth -= 1,
            _ => {}
        }
        if depth == 0 && expr[i..].starts_with(sep) {
            parts.push(&expr[start..i]);
            i += sep_bytes.len();
            start = i;
            continue;
        }
        i += 1;
    }
    parts.push(&expr[start..]);
    parts
}

/// Parse one atom: either a single `field op @"value"` predicate, or a
/// `(field op @"v1" or field op @"v2" ...)` OR-group over the same field
/// (the shape `field_match_kql` emits for multi-value fields).
fn parse_kql_atom_or_or_group(atom: &str) -> Result<FieldMatch, String> {
    let inner = atom
        .strip_prefix('(')
        .and_then(|s| s.strip_suffix(')'))
        .unwrap_or(atom);
    let or_parts = split_top_level(inner, " or ");
    let mut field_name: Option<String> = None;
    let mut modifier: Option<Modifier> = None;
    let mut values = Vec::new();
    for part in or_parts {
        let (field, m, value) = parse_kql_single_predicate(part.trim())?;
        match (&field_name, modifier) {
            (None, None) => {
                field_name = Some(field);
                modifier = Some(m);
            }
            (Some(existing_field), Some(existing_modifier)) => {
                if *existing_field != field || existing_modifier != m {
                    return Err(format!("OR-group mixes different fields/operators: {atom}"));
                }
            }
            _ => unreachable!(),
        }
        values.push(value);
    }
    Ok(FieldMatch {
        field: unmap_field(&field_name.ok_or_else(|| format!("empty predicate: {atom}"))?),
        modifier: modifier.unwrap(),
        values,
    })
}

/// Parse `field OP @"value"` (single predicate, no `and`/`or`).
fn parse_kql_single_predicate(part: &str) -> Result<(String, Modifier, String), String> {
    const OPS: &[(&str, Modifier)] = &[
        (" matches regex ", Modifier::Regex),
        (" contains ", Modifier::Contains),
        (" startswith ", Modifier::StartsWith),
        (" endswith ", Modifier::EndsWith),
        (" =~ ", Modifier::Equals),
    ];
    for (op_str, modifier) in OPS {
        if let Some(idx) = part.find(op_str) {
            let field = part[..idx].trim().to_string();
            let value_part = part[idx + op_str.len()..].trim();
            let value = parse_kql_literal(value_part)?;
            return Ok((field, *modifier, value));
        }
    }
    Err(format!("unsupported KQL predicate: {part}"))
}

/// Parse a KQL verbatim string literal `@"..."` (with `""` as an escaped
/// quote inside), the only literal form `to_kql` emits.
fn parse_kql_literal(s: &str) -> Result<String, String> {
    let Some(rest) = s.strip_prefix("@\"") else {
        return Err(format!(
            "expected a verbatim string literal @\"...\", got: {s}"
        ));
    };
    let Some(rest) = rest.strip_suffix('"') else {
        return Err(format!("unterminated string literal: {s}"));
    };
    Ok(rest.replace("\"\"", "\""))
}

// ---------------------------------------------------------------------
// Splunk SPL (Search Processing Language)
// ---------------------------------------------------------------------

/// Render a value as an SPL double-quoted string literal (escaping `"`).
fn spl_literal(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\\\""))
}

/// Render one `FieldMatch` as an SPL boolean predicate suitable for a
/// `| where` clause: `field="value"` for Equals, `like(field, "%value%")`
/// for Contains/StartsWith/EndsWith (wildcard on the appropriate side), and
/// `match(field, "pattern")` for Regex. Multi-value fields OR their atoms
/// together in parens.
fn field_match_spl(fm: &FieldMatch) -> String {
    let field = &fm.field;
    let atoms: Vec<String> = fm
        .values
        .iter()
        .map(|v| match fm.modifier {
            Modifier::Equals => format!("{field}={}", spl_literal(v)),
            Modifier::Contains => format!("like({field}, {})", spl_literal(&format!("%{v}%"))),
            Modifier::StartsWith => format!("like({field}, {})", spl_literal(&format!("{v}%"))),
            Modifier::EndsWith => format!("like({field}, {})", spl_literal(&format!("%{v}"))),
            Modifier::Regex => format!("match({field}, {})", spl_literal(v)),
        })
        .collect();
    if atoms.len() == 1 {
        atoms.into_iter().next().unwrap()
    } else {
        format!("({})", atoms.join(" or "))
    }
}

/// Render one `SelectionBlock` (all its fields AND'd together) as SPL.
fn block_spl(block: &SelectionBlock) -> String {
    let atoms: Vec<String> = block.fields.iter().map(field_match_spl).collect();
    if atoms.len() == 1 {
        atoms.into_iter().next().unwrap()
    } else {
        format!("({})", atoms.join(" and "))
    }
}

/// Render a `ConditionExpr` as an SPL `| where` boolean expression. Assumes
/// `validate_condition_refs` already confirmed every reference resolves.
fn condition_spl(condition: &ConditionExpr, blocks: &[SelectionBlock]) -> String {
    match condition {
        ConditionExpr::Block(name) => {
            let block = blocks
                .iter()
                .find(|b| &b.name == name)
                .expect("validate_condition_refs guarantees this block exists");
            block_spl(block)
        }
        ConditionExpr::Not(inner) => format!("not ({})", condition_spl(inner, blocks)),
        ConditionExpr::And(list) => list
            .iter()
            .map(|e| format!("({})", condition_spl(e, blocks)))
            .collect::<Vec<_>>()
            .join(" and "),
        ConditionExpr::Or(list) => list
            .iter()
            .map(|e| format!("({})", condition_spl(e, blocks)))
            .collect::<Vec<_>>()
            .join(" or "),
        ConditionExpr::OneOf(pattern) => {
            let matched = resolve_pattern_blocks(pattern, blocks);
            let atoms: Vec<String> = matched.iter().map(|b| block_spl(b)).collect();
            if atoms.len() == 1 {
                atoms.into_iter().next().unwrap()
            } else {
                format!("({})", atoms.join(" or "))
            }
        }
        ConditionExpr::AllOf(pattern) => {
            let matched = resolve_pattern_blocks(pattern, blocks);
            let atoms: Vec<String> = matched.iter().map(|b| block_spl(b)).collect();
            if atoms.len() == 1 {
                atoms.into_iter().next().unwrap()
            } else {
                format!("({})", atoms.join(" and "))
            }
        }
    }
}

/// Emit a Splunk SPL search string from a parsed `RuleAst`: a `sourcetype=`
/// filter followed by a `| where` boolean expression built from
/// `field="value"`/`like(...)`/`match(...)` predicates.
pub fn to_spl(detection: &RuleAst) -> String {
    format!(
        "// {}\nsourcetype={}\n| where {}\n",
        detection.title,
        detection.source,
        condition_spl(&detection.condition, &detection.blocks)
    )
}

/// Parse a `field, "value"` pair out of a `like(...)`/`match(...)` call's
/// inner argument string.
fn split_call_args(inner: &str) -> Result<(String, String), String> {
    let Some(idx) = inner.find(',') else {
        return Err(format!("expected 'field, \"value\"', got: {inner}"));
    };
    let field = inner[..idx].trim().to_string();
    let value = inner[idx + 1..].trim().to_string();
    Ok((field, value))
}

/// Parse an SPL string literal `"..."` (with `\"` as an escaped quote).
fn parse_spl_literal(s: &str) -> Result<String, String> {
    let s = s.trim();
    if s.len() < 2 || !s.starts_with('"') || !s.ends_with('"') {
        return Err(format!("expected a quoted string literal, got: {s}"));
    }
    Ok(s[1..s.len() - 1].replace("\\\"", "\""))
}

/// Determine the wildcard modifier + bare value from a `like()` value
/// (`%value%` -> Contains, `value%` -> StartsWith, `%value` -> EndsWith).
fn classify_like_wildcard(literal: &str) -> Result<(Modifier, String), String> {
    let starts = literal.starts_with('%');
    let ends = literal.ends_with('%') && literal.len() > 1;
    match (starts, ends) {
        (true, true) => Ok((
            Modifier::Contains,
            literal[1..literal.len() - 1].to_string(),
        )),
        (false, true) => Ok((
            Modifier::StartsWith,
            literal[..literal.len() - 1].to_string(),
        )),
        (true, false) => Ok((Modifier::EndsWith, literal[1..].to_string())),
        (false, false) => Err(format!("like() value has no % wildcard: {literal}")),
    }
}

/// Parse `field="value"` / `like(field, "%value%")` / `match(field,
/// "pattern")` (single predicate, no `and`/`or`).
fn parse_spl_single_predicate(part: &str) -> Result<(String, Modifier, String), String> {
    let part = part.trim();
    if let Some(inner) = part.strip_prefix("like(").and_then(|s| s.strip_suffix(')')) {
        let (field, value_str) = split_call_args(inner)?;
        let literal = parse_spl_literal(&value_str)?;
        let (modifier, value) = classify_like_wildcard(&literal)?;
        return Ok((field, modifier, value));
    }
    if let Some(inner) = part
        .strip_prefix("match(")
        .and_then(|s| s.strip_suffix(')'))
    {
        let (field, value_str) = split_call_args(inner)?;
        let value = parse_spl_literal(&value_str)?;
        return Ok((field, Modifier::Regex, value));
    }
    if let Some(idx) = part.find('=') {
        let field = part[..idx].trim().to_string();
        let value = parse_spl_literal(part[idx + 1..].trim())?;
        return Ok((field, Modifier::Equals, value));
    }
    Err(format!("unsupported SPL predicate: {part}"))
}

/// Parse one atom: a single SPL predicate, or a `(pred or pred or ...)`
/// OR-group over the same field (the shape `field_match_spl` emits for
/// multi-value fields).
fn parse_spl_atom_or_or_group(atom: &str) -> Result<FieldMatch, String> {
    let inner = strip_wrapping_parens(atom);
    let or_parts = split_top_level(inner, " or ");
    let mut field_name: Option<String> = None;
    let mut modifier: Option<Modifier> = None;
    let mut values = Vec::new();
    for part in or_parts {
        let (field, m, value) = parse_spl_single_predicate(part.trim())?;
        match (&field_name, modifier) {
            (None, None) => {
                field_name = Some(field);
                modifier = Some(m);
            }
            (Some(existing_field), Some(existing_modifier)) => {
                if *existing_field != field || existing_modifier != m {
                    return Err(format!("OR-group mixes different fields/operators: {atom}"));
                }
            }
            _ => unreachable!(),
        }
        values.push(value);
    }
    Ok(FieldMatch {
        field: field_name.ok_or_else(|| format!("empty predicate: {atom}"))?,
        modifier: modifier.unwrap(),
        values,
    })
}

/// Parse one SPL `| where` predicate expression, split on top-level ` and `,
/// into the FieldMatch list for one selection block.
fn parse_spl_predicate(expr: &str) -> Result<Vec<FieldMatch>, String> {
    let expr = strip_wrapping_parens(expr);
    let mut fields = Vec::new();
    for atom in split_top_level(expr, " and ") {
        fields.push(parse_spl_atom_or_or_group(atom.trim())?);
    }
    Ok(fields)
}

/// Parse a Splunk SPL search string (as emitted by `to_spl`, or a hand-
/// written SPL rule of the same shape) into a `RuleAst`.
///
/// Expected shape: optional leading `//` comment (the title), a
/// `sourcetype=<name>` line (quoted or bare), then one or more `| where
/// <expr>` lines (ANDed together if there's more than one). Any other pipe
/// stage (`| stats`, `| table`, `| eval`, ...) is rejected rather than
/// silently ignored.
pub fn parse_spl(spl: &str) -> Result<RuleAst, String> {
    let mut title = "Untitled rule".to_string();
    let mut source: Option<String> = None;
    let mut where_exprs: Vec<String> = Vec::new();

    for raw_line in spl.lines() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(comment) = line.strip_prefix("//") {
            if source.is_none() && title == "Untitled rule" {
                title = comment.trim().to_string();
            }
            continue;
        }
        if let Some(rest) = line.strip_prefix('|') {
            let rest = rest.trim();
            if let Some(where_expr) = rest.strip_prefix("where") {
                where_exprs.push(where_expr.trim().to_string());
            } else {
                return Err(format!("unsupported SPL pipe stage: | {rest}"));
            }
            continue;
        }
        if let Some(rest) = line.strip_prefix("sourcetype=") {
            let rest = rest.trim();
            source = Some(if rest.starts_with('"') {
                parse_spl_literal(rest)?
            } else {
                rest.to_string()
            });
            continue;
        }
        return Err(format!("unexpected SPL line: {line}"));
    }

    let Some(source) = source else {
        return Err("no sourcetype= found in SPL search".to_string());
    };
    if where_exprs.is_empty() {
        return Err("no | where clause found in SPL search".to_string());
    }

    let mut blocks = Vec::with_capacity(where_exprs.len());
    for (i, expr) in where_exprs.iter().enumerate() {
        let name = if where_exprs.len() == 1 {
            "selection".to_string()
        } else {
            format!("selection{}", i + 1)
        };
        let fields = parse_spl_predicate(expr)?;
        blocks.push(SelectionBlock { name, fields });
    }

    let condition = if blocks.len() == 1 {
        ConditionExpr::Block(blocks[0].name.clone())
    } else {
        ConditionExpr::And(
            blocks
                .iter()
                .map(|b| ConditionExpr::Block(b.name.clone()))
                .collect(),
        )
    };

    Ok(RuleAst {
        title,
        source,
        blocks,
        condition,
    })
}

// ---------------------------------------------------------------------
// QRadar AQL (Ariel Query Language)
// ---------------------------------------------------------------------

/// Render a value as an AQL single-quoted string literal (escaping `'`).
fn aql_literal(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

/// Render one `FieldMatch` as an AQL boolean predicate suitable for a
/// `WHERE` clause: `field = 'value'` for Equals, `field LIKE '%value%'`
/// (wildcard on the appropriate side) for Contains/StartsWith/EndsWith,
/// and `field IMATCHES 'pattern'` for Regex. Multi-value fields OR their
/// atoms together in parens.
fn field_match_aql(fm: &FieldMatch) -> String {
    let field = &fm.field;
    let atoms: Vec<String> = fm
        .values
        .iter()
        .map(|v| match fm.modifier {
            Modifier::Equals => format!("{field} = {}", aql_literal(v)),
            Modifier::Contains => format!("{field} LIKE {}", aql_literal(&format!("%{v}%"))),
            Modifier::StartsWith => format!("{field} LIKE {}", aql_literal(&format!("{v}%"))),
            Modifier::EndsWith => format!("{field} LIKE {}", aql_literal(&format!("%{v}"))),
            Modifier::Regex => format!("{field} IMATCHES {}", aql_literal(v)),
        })
        .collect();
    if atoms.len() == 1 {
        atoms.into_iter().next().unwrap()
    } else {
        format!("({})", atoms.join(" OR "))
    }
}

/// Render one `SelectionBlock` (all its fields AND'd together) as AQL.
fn block_aql(block: &SelectionBlock) -> String {
    let atoms: Vec<String> = block.fields.iter().map(field_match_aql).collect();
    if atoms.len() == 1 {
        atoms.into_iter().next().unwrap()
    } else {
        format!("({})", atoms.join(" AND "))
    }
}

/// Render a `ConditionExpr` as an AQL `WHERE` boolean expression. Assumes
/// `validate_condition_refs` already confirmed every reference resolves.
fn condition_aql(condition: &ConditionExpr, blocks: &[SelectionBlock]) -> String {
    match condition {
        ConditionExpr::Block(name) => {
            let block = blocks
                .iter()
                .find(|b| &b.name == name)
                .expect("validate_condition_refs guarantees this block exists");
            block_aql(block)
        }
        ConditionExpr::Not(inner) => format!("NOT ({})", condition_aql(inner, blocks)),
        ConditionExpr::And(list) => list
            .iter()
            .map(|e| format!("({})", condition_aql(e, blocks)))
            .collect::<Vec<_>>()
            .join(" AND "),
        ConditionExpr::Or(list) => list
            .iter()
            .map(|e| format!("({})", condition_aql(e, blocks)))
            .collect::<Vec<_>>()
            .join(" OR "),
        ConditionExpr::OneOf(pattern) => {
            let matched = resolve_pattern_blocks(pattern, blocks);
            let atoms: Vec<String> = matched.iter().map(|b| block_aql(b)).collect();
            if atoms.len() == 1 {
                atoms.into_iter().next().unwrap()
            } else {
                format!("({})", atoms.join(" OR "))
            }
        }
        ConditionExpr::AllOf(pattern) => {
            let matched = resolve_pattern_blocks(pattern, blocks);
            let atoms: Vec<String> = matched.iter().map(|b| block_aql(b)).collect();
            if atoms.len() == 1 {
                atoms.into_iter().next().unwrap()
            } else {
                format!("({})", atoms.join(" AND "))
            }
        }
    }
}

/// Emit a QRadar AQL query string from a parsed `RuleAst`: a
/// `SELECT * FROM <source> WHERE <expr>` statement.
pub fn to_aql(detection: &RuleAst) -> String {
    format!(
        "-- {}\nSELECT * FROM {} WHERE {}\n",
        detection.title,
        detection.source,
        condition_aql(&detection.condition, &detection.blocks)
    )
}

/// Parse an AQL single-quoted string literal `'...'` (with `''` as an
/// escaped quote inside).
fn parse_aql_literal(s: &str) -> Result<String, String> {
    let s = s.trim();
    if s.len() < 2 || !s.starts_with('\'') || !s.ends_with('\'') {
        return Err(format!("expected a quoted string literal, got: {s}"));
    }
    Ok(s[1..s.len() - 1].replace("''", "'"))
}

/// Determine the wildcard modifier + bare value from a `LIKE` value
/// (`%value%` -> Contains, `value%` -> StartsWith, `%value` -> EndsWith).
fn classify_aql_like_wildcard(literal: &str) -> Result<(Modifier, String), String> {
    let starts = literal.starts_with('%');
    let ends = literal.ends_with('%') && literal.len() > 1;
    match (starts, ends) {
        (true, true) => Ok((
            Modifier::Contains,
            literal[1..literal.len() - 1].to_string(),
        )),
        (false, true) => Ok((
            Modifier::StartsWith,
            literal[..literal.len() - 1].to_string(),
        )),
        (true, false) => Ok((Modifier::EndsWith, literal[1..].to_string())),
        (false, false) => Err(format!("LIKE value has no % wildcard: {literal}")),
    }
}

/// Parse `field = 'value'` / `field LIKE '%value%'` / `field IMATCHES
/// 'pattern'` (single predicate, no `AND`/`OR`).
fn parse_aql_single_predicate(part: &str) -> Result<(String, Modifier, String), String> {
    const OPS: &[(&str, Modifier)] = &[
        (" IMATCHES ", Modifier::Regex),
        (" MATCHES ", Modifier::Regex),
        (" LIKE ", Modifier::Contains), // placeholder modifier, replaced below via wildcard classification
        (" = ", Modifier::Equals),
    ];
    for (op_str, modifier) in OPS {
        if let Some(idx) = part.find(op_str) {
            let field = part[..idx].trim().to_string();
            let value_str = part[idx + op_str.len()..].trim();
            let literal = parse_aql_literal(value_str)?;
            if op_str.trim() == "LIKE" {
                let (real_modifier, value) = classify_aql_like_wildcard(&literal)?;
                return Ok((field, real_modifier, value));
            }
            return Ok((field, *modifier, literal));
        }
    }
    Err(format!("unsupported AQL predicate: {part}"))
}

/// Parse one atom: a single AQL predicate, or a `(pred OR pred OR ...)`
/// OR-group over the same field (the shape `field_match_aql` emits for
/// multi-value fields).
fn parse_aql_atom_or_or_group(atom: &str) -> Result<FieldMatch, String> {
    let inner = strip_wrapping_parens(atom);
    let or_parts = split_top_level(inner, " OR ");
    let mut field_name: Option<String> = None;
    let mut modifier: Option<Modifier> = None;
    let mut values = Vec::new();
    for part in or_parts {
        let (field, m, value) = parse_aql_single_predicate(part.trim())?;
        match (&field_name, modifier) {
            (None, None) => {
                field_name = Some(field);
                modifier = Some(m);
            }
            (Some(existing_field), Some(existing_modifier)) => {
                if *existing_field != field || existing_modifier != m {
                    return Err(format!("OR-group mixes different fields/operators: {atom}"));
                }
            }
            _ => unreachable!(),
        }
        values.push(value);
    }
    Ok(FieldMatch {
        field: field_name.ok_or_else(|| format!("empty predicate: {atom}"))?,
        modifier: modifier.unwrap(),
        values,
    })
}

/// Parse one AQL `WHERE` predicate expression, split on top-level ` AND `,
/// into the FieldMatch list for one selection block.
fn parse_aql_predicate(expr: &str) -> Result<Vec<FieldMatch>, String> {
    let expr = strip_wrapping_parens(expr);
    let mut fields = Vec::new();
    for atom in split_top_level(expr, " AND ") {
        fields.push(parse_aql_atom_or_or_group(atom.trim())?);
    }
    Ok(fields)
}

/// Parse a QRadar AQL query (as emitted by `to_aql`, or a hand-written AQL
/// search of the same shape) into a `RuleAst`.
///
/// Expected shape: optional leading `-- ` comment (the title), then a
/// single `SELECT * FROM <source> WHERE <expr>` statement. Any other
/// SELECT clause (aggregate functions, GROUP BY, LAST N DAYS, ...) is
/// rejected rather than silently ignored, since it could change the
/// query's meaning.
pub fn parse_aql(aql: &str) -> Result<RuleAst, String> {
    let mut title = "Untitled rule".to_string();
    let mut statement_line: Option<&str> = None;

    for raw_line in aql.lines() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(comment) = line.strip_prefix("--") {
            if statement_line.is_none() && title == "Untitled rule" {
                title = comment.trim().to_string();
            }
            continue;
        }
        if statement_line.is_some() {
            return Err(format!("unexpected extra AQL line: {line}"));
        }
        statement_line = Some(line);
    }

    let Some(statement) = statement_line else {
        return Err("no SELECT statement found in AQL query".to_string());
    };

    let Some(rest) = statement.strip_prefix("SELECT * FROM ") else {
        return Err(format!(
            "unsupported AQL statement (only 'SELECT * FROM <source> WHERE <expr>' is supported): {statement}"
        ));
    };
    let Some(where_idx) = rest.find(" WHERE ") else {
        return Err("no WHERE clause found in AQL query".to_string());
    };
    let source = rest[..where_idx].trim().to_string();
    let expr = rest[where_idx + " WHERE ".len()..].trim();
    if expr.is_empty() {
        return Err("empty WHERE clause in AQL query".to_string());
    }

    let fields = parse_aql_predicate(expr)?;
    let block_name = "selection".to_string();
    let blocks = vec![SelectionBlock {
        name: block_name.clone(),
        fields,
    }];
    let condition = ConditionExpr::Block(block_name);

    Ok(RuleAst {
        title,
        source,
        blocks,
        condition,
    })
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
        assert!(kql.contains(r#"FolderPath endswith @"\powershell.exe""#));
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
        assert!(kql.contains(r#"FolderPath endswith @"\certutil.exe""#));
        assert!(kql.contains(r#"FolderPath endswith @"\bitsadmin.exe""#));
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
        assert!(kql.contains(r#"FolderPath endswith @"\powershell.exe""#));
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
        assert!(kql.contains(r#"FolderPath endswith @"\certutil.exe""#));
        assert!(kql.contains(r#"FolderPath endswith @"\bitsadmin.exe""#));
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
        assert!(kql.contains(r#"FolderPath endswith @"\certutil.exe""#));
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

    const SIGMA_MAPPED_FIELD: &str = r#"
title: Mapped field name
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith: '\mimikatz.exe'
        CommandLine|contains: 'sekurlsa'
    condition: selection
"#;

    #[test]
    fn mapped_field_uses_kql_column_name() {
        let d = parse_sigma_rule(SIGMA_MAPPED_FIELD).unwrap();
        let kql = to_kql(&d);
        // Image is mapped to FolderPath for Defender XDR tables.
        assert!(kql.contains(r#"FolderPath endswith @"\mimikatz.exe""#));
        assert!(!kql.contains("Image endswith"));
        // CommandLine has no mapping entry -> passes through unchanged.
        assert!(kql.contains(r#"CommandLine contains @"sekurlsa""#));
    }

    #[test]
    fn to_sigma_round_trips_through_reparse() {
        // Parse a Sigma rule with two AND'd blocks, re-emit as Sigma, parse
        // the re-emitted YAML again -> the condition/block shape survives.
        let d = parse_sigma_rule(SIGMA_TWO_BLOCKS_AND).unwrap();
        let regenerated_yaml = to_sigma(&d, "windows", "process_creation");
        let d2 = parse_sigma_rule(&regenerated_yaml).expect("re-emitted Sigma YAML should parse");
        assert_eq!(d.condition, d2.condition);
        assert_eq!(d.blocks.len(), d2.blocks.len());
        for (b1, b2) in d.blocks.iter().zip(d2.blocks.iter()) {
            assert_eq!(b1.name, b2.name);
            assert_eq!(b1.fields, b2.fields);
        }
    }

    const KQL_SIMPLE: &str = "// Suspicious PowerShell EncodedCommand\nDeviceProcessEvents\n| where FolderPath endswith @\"\\powershell.exe\" and CommandLine contains @\"-EncodedCommand\"\n";

    #[test]
    fn parses_simple_kql_where_clause() {
        let d = parse_kql(KQL_SIMPLE).expect("should parse");
        assert_eq!(d.source, "DeviceProcessEvents");
        assert_eq!(d.title, "Suspicious PowerShell EncodedCommand");
        assert_eq!(d.blocks.len(), 1);
        assert_eq!(d.blocks[0].fields.len(), 2);
    }

    #[test]
    fn kql_round_trip_from_sigma_preserves_logic() {
        // Sigma -> KQL -> parse_kql -> to_sigma -> parse_sigma_rule: the
        // field/modifier/value shape survives the full round trip.
        let sigma_ast = parse_sigma_rule(SIGMA_SIMPLE).unwrap();
        let kql = to_kql(&sigma_ast);
        let kql_ast = parse_kql(&kql).expect("emitted KQL should parse back");
        assert_eq!(kql_ast.source, "DeviceProcessEvents");
        let regenerated_sigma = to_sigma(&kql_ast, "windows", "process_creation");
        let sigma_ast2 =
            parse_sigma_rule(&regenerated_sigma).expect("regenerated Sigma should parse");
        // FolderPath is ambiguous (maps from both Image and TargetFilename),
        // so unmap_field intentionally leaves it as-is rather than guess.
        let fields: Vec<&str> = sigma_ast2.blocks[0]
            .fields
            .iter()
            .map(|f| f.field.as_str())
            .collect();
        assert!(
            fields.contains(&"FolderPath"),
            "fields were: {fields:?}, regenerated sigma was:\n{regenerated_sigma}"
        );
        assert!(fields.contains(&"CommandLine"));
    }

    #[test]
    fn kql_multi_value_or_group_round_trips() {
        let sigma_ast = parse_sigma_rule(SIGMA_MULTI_VALUE).unwrap();
        let kql = to_kql(&sigma_ast);
        let kql_ast = parse_kql(&kql).expect("should parse OR-group");
        assert_eq!(kql_ast.blocks[0].fields.len(), 1);
        assert_eq!(kql_ast.blocks[0].fields[0].values.len(), 2);
    }

    #[test]
    fn unsupported_kql_pipe_stage_is_rejected() {
        let kql = "DeviceProcessEvents\n| where FolderPath endswith @\"\\net.exe\"\n| summarize count() by FolderPath\n";
        assert!(parse_kql(kql).is_err());
    }

    #[test]
    fn unmap_field_reverses_unambiguous_mapping() {
        assert_eq!(unmap_field("RemoteIP"), "DestinationIp");
        assert_eq!(unmap_field("AccountName"), "User");
        // Not in the map at all -> passes through unchanged.
        assert_eq!(unmap_field("CommandLine"), "CommandLine");
    }

    #[test]
    fn to_spl_emits_where_clause_from_sigma() {
        let d = parse_sigma_rule(SIGMA_SIMPLE).unwrap();
        let spl = to_spl(&d);
        assert!(spl.contains("sourcetype=DeviceProcessEvents") || spl.contains("sourcetype="));
        assert!(spl.contains("like(Image, \"%\\powershell.exe\")"));
        assert!(spl.contains("like(CommandLine, \"%-EncodedCommand%\")"));
        assert!(spl.contains(" and "));
    }

    #[test]
    fn parse_spl_round_trips_simple_where() {
        let spl = "// Suspicious PowerShell EncodedCommand\nsourcetype=WinEventLog:Security\n| where like(Image, \"%\\\\powershell.exe\") and like(CommandLine, \"%-EncodedCommand%\")\n";
        let d = parse_spl(spl).expect("should parse");
        assert_eq!(d.source, "WinEventLog:Security");
        assert_eq!(d.title, "Suspicious PowerShell EncodedCommand");
        assert_eq!(d.blocks.len(), 1);
        assert_eq!(d.blocks[0].fields.len(), 2);
    }

    #[test]
    fn spl_round_trip_from_sigma_preserves_logic() {
        let sigma_ast = parse_sigma_rule(SIGMA_SIMPLE).unwrap();
        let spl = to_spl(&sigma_ast);
        let spl_ast = parse_spl(&spl).expect("emitted SPL should parse back");
        assert_eq!(spl_ast.blocks[0].fields.len(), 2);
        let regenerated_sigma = to_sigma(&spl_ast, "windows", "process_creation");
        let sigma_ast2 =
            parse_sigma_rule(&regenerated_sigma).expect("regenerated Sigma should parse");
        assert_eq!(sigma_ast2.blocks[0].fields.len(), 2);
    }

    #[test]
    fn spl_multi_value_or_group_round_trips() {
        let sigma_ast = parse_sigma_rule(SIGMA_MULTI_VALUE).unwrap();
        let spl = to_spl(&sigma_ast);
        let spl_ast = parse_spl(&spl).expect("should parse OR-group");
        assert_eq!(spl_ast.blocks[0].fields.len(), 1);
        assert_eq!(spl_ast.blocks[0].fields[0].values.len(), 2);
    }

    #[test]
    fn spl_equals_predicate_round_trips() {
        let spl = "sourcetype=auth\n| where User=\"admin\"\n";
        let d = parse_spl(spl).expect("should parse");
        assert_eq!(d.blocks[0].fields[0].modifier, Modifier::Equals);
        assert_eq!(d.blocks[0].fields[0].values[0], "admin");
    }

    #[test]
    fn spl_regex_predicate_round_trips() {
        let spl = "sourcetype=auth\n| where match(CommandLine, \"^net\\\\.exe .*\")\n";
        let d = parse_spl(spl).expect("should parse");
        assert_eq!(d.blocks[0].fields[0].modifier, Modifier::Regex);
    }

    #[test]
    fn unsupported_spl_pipe_stage_is_rejected() {
        let spl = "sourcetype=auth\n| where User=\"admin\"\n| stats count by User\n";
        assert!(parse_spl(spl).is_err());
    }

    #[test]
    fn spl_missing_sourcetype_is_rejected() {
        let spl = "| where User=\"admin\"\n";
        assert!(parse_spl(spl).is_err());
    }

    #[test]
    fn to_aql_emits_select_where_from_sigma() {
        let d = parse_sigma_rule(SIGMA_SIMPLE).unwrap();
        let aql = to_aql(&d);
        assert!(aql.contains("SELECT * FROM DeviceProcessEvents WHERE"));
        assert!(aql.contains("Image LIKE '%\\powershell.exe'"));
        assert!(aql.contains("CommandLine LIKE '%-EncodedCommand%'"));
        assert!(aql.contains(" AND "));
    }

    #[test]
    fn parse_aql_round_trips_simple_where() {
        let aql = "-- Suspicious PowerShell EncodedCommand\nSELECT * FROM WinEventLog WHERE (Image LIKE '%\\powershell.exe' AND CommandLine LIKE '%-EncodedCommand%')\n";
        let d = parse_aql(aql).expect("should parse");
        assert_eq!(d.source, "WinEventLog");
        assert_eq!(d.title, "Suspicious PowerShell EncodedCommand");
        assert_eq!(d.blocks[0].fields.len(), 2);
    }

    #[test]
    fn aql_round_trip_from_sigma_preserves_logic() {
        let sigma_ast = parse_sigma_rule(SIGMA_SIMPLE).unwrap();
        let aql = to_aql(&sigma_ast);
        let aql_ast = parse_aql(&aql).expect("emitted AQL should parse back");
        assert_eq!(aql_ast.blocks[0].fields.len(), 2);
        let regenerated_sigma = to_sigma(&aql_ast, "windows", "process_creation");
        let sigma_ast2 =
            parse_sigma_rule(&regenerated_sigma).expect("regenerated Sigma should parse");
        assert_eq!(sigma_ast2.blocks[0].fields.len(), 2);
    }

    #[test]
    fn aql_multi_value_or_group_round_trips() {
        let sigma_ast = parse_sigma_rule(SIGMA_MULTI_VALUE).unwrap();
        let aql = to_aql(&sigma_ast);
        let aql_ast = parse_aql(&aql).expect("should parse OR-group");
        assert_eq!(aql_ast.blocks[0].fields.len(), 1);
        assert_eq!(aql_ast.blocks[0].fields[0].values.len(), 2);
    }

    #[test]
    fn aql_equals_predicate_round_trips() {
        let aql = "SELECT * FROM auth WHERE User = 'admin'\n";
        let d = parse_aql(aql).expect("should parse");
        assert_eq!(d.blocks[0].fields[0].modifier, Modifier::Equals);
        assert_eq!(d.blocks[0].fields[0].values[0], "admin");
    }

    #[test]
    fn aql_regex_predicate_round_trips() {
        let aql = "SELECT * FROM auth WHERE CommandLine IMATCHES '^net\\.exe .*'\n";
        let d = parse_aql(aql).expect("should parse");
        assert_eq!(d.blocks[0].fields[0].modifier, Modifier::Regex);
    }

    #[test]
    fn unsupported_aql_statement_is_rejected() {
        let aql = "SELECT COUNT(*) FROM events WHERE User = 'admin'\n";
        assert!(parse_aql(aql).is_err());
    }

    #[test]
    fn aql_missing_where_is_rejected() {
        let aql = "SELECT * FROM events\n";
        assert!(parse_aql(aql).is_err());
    }
}
