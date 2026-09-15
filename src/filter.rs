//! Rule filtering: log-source/table targeting + APT-driven selection.
//!
//! Strict semantics: when a filter is active, a rule that cannot be
//! positively classified as matching is DROPPED (tight, curated output).
//! A filter with no selections is inactive and passes everything.

use regex::{Regex, RegexSet};

/// One selectable log source / table category.
pub struct LogSourceDef {
    pub id: &'static str,
    pub label: &'static str,
    /// sigma `logsource.product` values that map here
    pub sigma_products: &'static [&'static str],
    /// sigma `logsource.service` values that map here
    pub sigma_services: &'static [&'static str],
    /// sigma `logsource.category` values that map here
    pub sigma_categories: &'static [&'static str],
    /// lowercase keywords used to classify free-text rules (Splunk/QRadar)
    pub keywords: &'static [&'static str],
}

pub static LOG_SOURCES: &[LogSourceDef] = &[
    LogSourceDef {
        id: "windows",
        label: "Windows (Security / Sysmon / PowerShell)",
        sigma_products: &["windows"],
        sigma_services: &[
            "security",
            "sysmon",
            "system",
            "powershell",
            "application",
            "windefend",
            "taskscheduler",
            "wmi",
            "dns-server",
            "msexchange",
        ],
        sigma_categories: &[
            "process_creation",
            "registry_set",
            "registry_add",
            "registry_event",
            "registry_delete",
            "image_load",
            "file_event",
            "file_delete",
            "file_change",
            "file_access",
            "driver_load",
            "pipe_created",
            "wmi_event",
            "ps_script",
            "ps_module",
            "ps_classic_start",
            "create_remote_thread",
            "process_access",
            "network_connection",
            "dns_query",
            "create_stream_hash",
            "raw_access_thread",
            "sysmon_error",
            "sysmon_status",
            "process_tampering",
        ],
        keywords: &[
            "wineventlog",
            "sysmon",
            "windows",
            "eventcode",
            "powershell",
            "event_id",
            "eventid",
            "security.evtx",
            "winlog",
        ],
    },
    LogSourceDef {
        id: "linux",
        label: "Linux (auditd / syslog)",
        sigma_products: &["linux"],
        sigma_services: &["auditd", "sshd", "auth", "sudo", "cron", "syslog", "clamav"],
        sigma_categories: &[],
        keywords: &[
            "auditd",
            "linux",
            "syslog",
            "audit.log",
            "auth.log",
            "sshd",
            "bash_history",
        ],
    },
    LogSourceDef {
        id: "macos",
        label: "macOS",
        sigma_products: &["macos"],
        sigma_services: &[],
        sigma_categories: &[],
        keywords: &["macos", "osquery", "unifiedlog", "endpointsecurity"],
    },
    LogSourceDef {
        id: "network",
        label: "Network (Zeek / NetFlow / Firewall / DNS / IDS)",
        sigma_products: &[
            "zeek", "netflow", "cisco", "juniper", "huawei", "paloalto", "fortios",
        ],
        sigma_services: &["dns", "firewall", "netflow"],
        sigma_categories: &["dns", "firewall", "flow"],
        keywords: &[
            "zeek",
            "bro_",
            "netflow",
            "firewall",
            "suricata",
            "snort",
            "pan:traffic",
            "cisco",
            "conn.log",
            "dns.log",
            "pfsense",
            "opnsense",
        ],
    },
    LogSourceDef {
        id: "web_proxy",
        label: "Web / Proxy servers",
        sigma_products: &["apache", "nginx"],
        sigma_services: &["iis", "apache", "nginx"],
        sigma_categories: &["proxy", "webserver"],
        keywords: &[
            "proxy",
            "access_combined",
            "iis",
            "apache",
            "nginx",
            "useragent",
            "user-agent",
            "http_method",
        ],
    },
    LogSourceDef {
        id: "cloud_aws",
        label: "Cloud: AWS (CloudTrail / GuardDuty)",
        sigma_products: &["aws"],
        sigma_services: &["cloudtrail", "guardduty"],
        sigma_categories: &[],
        keywords: &["cloudtrail", "guardduty", "aws"],
    },
    LogSourceDef {
        id: "cloud_azure",
        label: "Cloud: Azure / M365 / Entra",
        sigma_products: &["azure", "m365", "microsoft365"],
        sigma_services: &[
            "azuread",
            "azureactivity",
            "exchange",
            "threat_management",
            "audit",
        ],
        sigma_categories: &[],
        keywords: &[
            "azure",
            "entra",
            "office 365",
            "o365",
            "m365",
            "exchangeonline",
            "azuread",
        ],
    },
    LogSourceDef {
        id: "cloud_gcp",
        label: "Cloud: GCP / Google Workspace",
        sigma_products: &["gcp", "google_workspace"],
        sigma_services: &["gcp.audit", "google_workspace.admin"],
        sigma_categories: &[],
        keywords: &[
            "gcp",
            "google cloud",
            "gsuite",
            "google_workspace",
            "stackdriver",
        ],
    },
    LogSourceDef {
        id: "idp",
        label: "Identity providers (Okta / OneLogin / Duo)",
        sigma_products: &["okta", "onelogin"],
        sigma_services: &["okta", "onelogin"],
        sigma_categories: &[],
        keywords: &["okta", "onelogin", "duo", "auth0", "identity provider"],
    },
    LogSourceDef {
        id: "edr_av",
        label: "Antivirus / EDR telemetry",
        sigma_products: &[],
        sigma_services: &["windefend", "sophos"],
        sigma_categories: &["antivirus", "edr"],
        keywords: &[
            "defender",
            "crowdstrike",
            "sentinelone",
            "carbon black",
            "antivirus",
            "falcon",
            "edr",
        ],
    },
];

/// Outcome of filtering one candidate file.
pub enum FilterOutcome {
    /// copy the file unchanged
    Keep,
    /// skip the file entirely
    Drop,
    /// write this filtered content instead (e.g. per-line Suricata filtering)
    Rewrite(String),
}

/// Why a rule was dropped — for the preview / filter report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DropReason {
    /// did not match any selected log source / Azure table / Splunk sourcetype
    Source,
    /// did not mention any selected threat actor / malware
    Apt,
    /// did not reference any selected ATT&CK technique
    Technique,
}

/// Traced outcome: like FilterOutcome but carries the drop reason.
pub enum TraceOutcome {
    Keep,
    Rewrite(String),
    Drop(DropReason),
}

/// Running tally of what the filter did, aggregated across all tools/files.
#[derive(Debug, Clone, Copy, Default)]
pub struct FilterStats {
    pub scanned: usize,
    pub kept: usize,
    pub rewritten: usize,
    pub dropped_source: usize,
    pub dropped_apt: usize,
    pub dropped_technique: usize,
    /// files that were not valid UTF-8 → unclassifiable → strict drop
    pub dropped_unreadable: usize,
}

impl FilterStats {
    pub fn record(&mut self, outcome: &TraceOutcome) {
        self.scanned += 1;
        match outcome {
            TraceOutcome::Keep => self.kept += 1,
            TraceOutcome::Rewrite(_) => self.rewritten += 1,
            TraceOutcome::Drop(DropReason::Source) => self.dropped_source += 1,
            TraceOutcome::Drop(DropReason::Apt) => self.dropped_apt += 1,
            TraceOutcome::Drop(DropReason::Technique) => self.dropped_technique += 1,
        }
    }

    pub fn record_unreadable(&mut self) {
        self.scanned += 1;
        self.dropped_unreadable += 1;
    }

    pub fn total_dropped(&self) -> usize {
        self.dropped_source + self.dropped_apt + self.dropped_technique + self.dropped_unreadable
    }

    pub fn total_kept(&self) -> usize {
        self.kept + self.rewritten
    }
}

/// Compiled, thread-safe filter built once per run.
pub struct CompiledFilter {
    /// selected LogSourceDef ids; empty = source filter inactive
    pub source_ids: Vec<String>,
    /// human-readable APT terms used (for logging)
    pub apt_terms: Vec<String>,
    /// case-insensitive word-boundary matcher over apt_terms; None = APT filter inactive
    apt_regex: Option<RegexSet>,
    /// selected Azure/M365 table names (granular targeting); empty = inactive
    pub azure_tables: Vec<String>,
    /// case-insensitive word-boundary matcher over azure_tables
    table_regex: Option<RegexSet>,
    /// sigma logsource.service values the selected tables map to
    table_sigma_services: Vec<String>,
    /// selected Splunk sourcetypes (granular targeting); empty = inactive
    pub splunk_sourcetypes: Vec<String>,
    /// case-insensitive boundary-aware matcher over splunk_sourcetypes
    sourcetype_regex: Option<RegexSet>,
    /// normalized MITRE ATT&CK technique IDs (e.g. "T1059", "T1566.001"); empty = inactive
    pub technique_ids: Vec<String>,
    /// matcher over technique_ids; parent codes also match their subtechniques
    technique_regex: Option<RegexSet>,
    /// live tally of what the filter did this run (interior-mutable, thread-safe)
    stats: FilterStatsAtomic,
}

/// Thread-safe interior-mutable counters, shared via the Arc<CompiledFilter>.
#[derive(Default)]
struct FilterStatsAtomic {
    scanned: std::sync::atomic::AtomicUsize,
    kept: std::sync::atomic::AtomicUsize,
    rewritten: std::sync::atomic::AtomicUsize,
    dropped_source: std::sync::atomic::AtomicUsize,
    dropped_apt: std::sync::atomic::AtomicUsize,
    dropped_technique: std::sync::atomic::AtomicUsize,
    dropped_unreadable: std::sync::atomic::AtomicUsize,
}

impl FilterStatsAtomic {
    fn record(&self, outcome: &TraceOutcome) {
        use std::sync::atomic::Ordering::Relaxed;
        self.scanned.fetch_add(1, Relaxed);
        match outcome {
            TraceOutcome::Keep => self.kept.fetch_add(1, Relaxed),
            TraceOutcome::Rewrite(_) => self.rewritten.fetch_add(1, Relaxed),
            TraceOutcome::Drop(DropReason::Source) => self.dropped_source.fetch_add(1, Relaxed),
            TraceOutcome::Drop(DropReason::Apt) => self.dropped_apt.fetch_add(1, Relaxed),
            TraceOutcome::Drop(DropReason::Technique) => {
                self.dropped_technique.fetch_add(1, Relaxed)
            }
        };
    }
}

/// Generic software/tool names that appear in MITRE "uses" relationships but
/// would match nearly every rule as keywords. Never used as filter terms.
const TERM_BLACKLIST: &[&str] = &[
    "at",
    "net",
    "cmd",
    "ping",
    "reg",
    "netsh",
    "tasklist",
    "systeminfo",
    "ipconfig",
    "whoami",
    "route",
    "arp",
    "ftp",
    "curl",
    "certutil",
    "esentutl",
    "schtasks",
    "sc",
    "query",
    "dsquery",
    "pwsh",
    "powershell",
    "cscript",
    "wscript",
    "mshta",
    "rundll32",
    "regsvr32",
    "msiexec",
    "installutil",
    "windows",
    "linux",
    "macos",
    "python",
    "java",
    "bash",
    "ssh",
];

/// Trim, drop too-short (<3 chars) and blacklisted generic terms. Shared by the
/// filter builder and the UI's mismatch guardrail so both agree on what "counts".
pub fn clean_apt_terms(terms: &[String]) -> Vec<String> {
    terms
        .iter()
        .map(|t| t.trim().to_string())
        .filter(|t| t.len() >= 3 && !TERM_BLACKLIST.contains(&t.to_lowercase().as_str()))
        .collect()
}

impl CompiledFilter {
    /// A filter that passes everything (both filters inactive).
    pub fn none() -> Self {
        Self {
            source_ids: Vec::new(),
            apt_terms: Vec::new(),
            apt_regex: None,
            azure_tables: Vec::new(),
            table_regex: None,
            table_sigma_services: Vec::new(),
            splunk_sourcetypes: Vec::new(),
            sourcetype_regex: None,
            technique_ids: Vec::new(),
            technique_regex: None,
            stats: FilterStatsAtomic::default(),
        }
    }

    /// Build from UI selections. `apt_terms` should already be the expanded
    /// list (group names + aliases + software) from the MITRE catalog.
    pub fn build(source_ids: Vec<String>, apt_terms: Vec<String>) -> Self {
        Self::build_full(source_ids, apt_terms, Vec::new(), Vec::new(), Vec::new())
    }

    /// Build including granular Azure/M365 table targeting.
    pub fn build_with_tables(
        source_ids: Vec<String>,
        apt_terms: Vec<String>,
        azure_tables: Vec<String>,
    ) -> Self {
        Self::build_full(source_ids, apt_terms, azure_tables, Vec::new(), Vec::new())
    }

    /// Build with every targeting dimension. `technique_ids` are raw user
    /// input ("t1059", "T1566.001 ") — normalized and validated here.
    pub fn build_full(
        source_ids: Vec<String>,
        apt_terms: Vec<String>,
        azure_tables: Vec<String>,
        splunk_sourcetypes: Vec<String>,
        technique_ids: Vec<String>,
    ) -> Self {
        let cleaned: Vec<String> = clean_apt_terms(&apt_terms);

        let apt_regex = if cleaned.is_empty() {
            None
        } else {
            // Custom boundary: rule names use '_' as a separator (APT28_zebrocy),
            // and \b treats '_' as a word char, so use explicit non-alnum boundaries.
            let patterns: Vec<String> = cleaned
                .iter()
                .map(|t| format!(r"(?i)(^|[^A-Za-z0-9]){}([^A-Za-z0-9]|$)", regex::escape(t)))
                .collect();
            RegexSet::new(&patterns).ok()
        };

        let table_regex = if azure_tables.is_empty() {
            None
        } else {
            let patterns: Vec<String> = azure_tables
                .iter()
                .map(|t| {
                    format!(
                        r"(?i)(^|[^A-Za-z0-9_]){}([^A-Za-z0-9_]|$)",
                        regex::escape(t)
                    )
                })
                .collect();
            RegexSet::new(&patterns).ok()
        };

        let table_sigma_services = crate::azure_tables::sigma_services_for(&azure_tables);

        // Sourcetypes contain ':' '/' ' ' — escape and use boundary classes
        // that exclude those chars so "pan:traffic" matches whole.
        let sourcetype_regex = if splunk_sourcetypes.is_empty() {
            None
        } else {
            let patterns: Vec<String> = splunk_sourcetypes
                .iter()
                .map(|t| format!(r#"(?i)(^|["'=\s(]){}($|["'\s)|,])"#, regex::escape(t)))
                .collect();
            RegexSet::new(&patterns).ok()
        };

        // Normalize + validate technique IDs: "t1059 " → "T1059"; parent codes
        // also match subtechniques (T1059 keeps attack.t1059.001).
        let tech_re = Regex::new(r"(?i)^t\d{4}(\.\d{3})?$").unwrap();
        let technique_ids: Vec<String> = technique_ids
            .into_iter()
            .map(|t| t.trim().to_uppercase())
            .filter(|t| tech_re.is_match(t))
            .collect();

        let technique_regex = if technique_ids.is_empty() {
            None
        } else {
            let patterns: Vec<String> = technique_ids
                .iter()
                .map(|t| {
                    if t.contains('.') {
                        // exact subtechnique
                        format!(r"(?i)(^|[^A-Za-z0-9]){}($|[^0-9])", regex::escape(t))
                    } else {
                        // parent: match itself and any .NNN subtechnique
                        format!(
                            r"(?i)(^|[^A-Za-z0-9]){}(\.\d{{3}})?($|[^0-9.])",
                            regex::escape(t)
                        )
                    }
                })
                .collect();
            RegexSet::new(&patterns).ok()
        };

        Self {
            source_ids,
            apt_terms: cleaned,
            apt_regex,
            azure_tables,
            table_regex,
            table_sigma_services,
            splunk_sourcetypes,
            sourcetype_regex,
            technique_ids,
            technique_regex,
            stats: FilterStatsAtomic::default(),
        }
    }

    pub fn source_filter_active(&self) -> bool {
        !self.source_ids.is_empty()
    }

    pub fn apt_filter_active(&self) -> bool {
        self.apt_regex.is_some()
    }

    pub fn table_filter_active(&self) -> bool {
        self.table_regex.is_some()
    }

    pub fn sourcetype_filter_active(&self) -> bool {
        self.sourcetype_regex.is_some()
    }

    pub fn technique_filter_active(&self) -> bool {
        self.technique_regex.is_some()
    }

    pub fn is_noop(&self) -> bool {
        !self.source_filter_active()
            && !self.apt_filter_active()
            && !self.table_filter_active()
            && !self.sourcetype_filter_active()
            && !self.technique_filter_active()
    }

    fn source_selected(&self, id: &str) -> bool {
        self.source_ids.iter().any(|s| s == id)
    }

    fn matches_apt(&self, text: &str) -> bool {
        match &self.apt_regex {
            Some(set) => set.is_match(text),
            None => true,
        }
    }

    /// Text references at least one selected ATT&CK technique (or filter inactive).
    fn matches_technique(&self, text: &str) -> bool {
        match &self.technique_regex {
            Some(set) => set.is_match(text),
            None => true,
        }
    }

    /// Text mentions at least one selected Azure table (or filter inactive).
    #[allow(dead_code)]
    fn matches_table(&self, text: &str) -> bool {
        match &self.table_regex {
            Some(set) => set.is_match(text),
            None => true,
        }
    }

    /// Decide what to do with one candidate rule file.
    /// `tool` is the ToolSpec name: "Yara", "Sigma", "Suricata", "Splunk", "QRadar", "Sysmon".
    pub fn filter_file(&self, tool: &str, content: &str) -> FilterOutcome {
        let traced = self.filter_file_traced(tool, content);
        self.stats.record(&traced);
        match traced {
            TraceOutcome::Keep => FilterOutcome::Keep,
            TraceOutcome::Rewrite(s) => FilterOutcome::Rewrite(s),
            TraceOutcome::Drop(_) => FilterOutcome::Drop,
        }
    }

    /// Record a file that could not be read as UTF-8 (strict drop).
    pub fn record_unreadable(&self) {
        use std::sync::atomic::Ordering::Relaxed;
        self.stats.scanned.fetch_add(1, Relaxed);
        self.stats.dropped_unreadable.fetch_add(1, Relaxed);
    }

    /// Snapshot the running tally.
    pub fn stats(&self) -> FilterStats {
        use std::sync::atomic::Ordering::Relaxed;
        FilterStats {
            scanned: self.stats.scanned.load(Relaxed),
            kept: self.stats.kept.load(Relaxed),
            rewritten: self.stats.rewritten.load(Relaxed),
            dropped_source: self.stats.dropped_source.load(Relaxed),
            dropped_apt: self.stats.dropped_apt.load(Relaxed),
            dropped_technique: self.stats.dropped_technique.load(Relaxed),
            dropped_unreadable: self.stats.dropped_unreadable.load(Relaxed),
        }
    }

    /// One-line human summary of the current tally, for the UI.
    pub fn stats_line(&self) -> String {
        let s = self.stats();
        if s.scanned == 0 {
            return "No rules scanned yet.".to_string();
        }
        format!(
            "Kept {} of {} rules — dropped {} (source {}, actor {}, technique {}, unreadable {}).",
            s.total_kept(),
            s.scanned,
            s.total_dropped(),
            s.dropped_source,
            s.dropped_apt,
            s.dropped_technique,
            s.dropped_unreadable,
        )
    }

    /// Full multi-line report body for `filter_report.txt`.
    pub fn report_text(&self) -> String {
        let s = self.stats();
        let mut out = String::new();
        out.push_str("Detection-Wizard filter report\n");
        out.push_str("==============================\n\n");

        out.push_str("Active filters:\n");
        if self.is_noop() {
            out.push_str("  (none — every downloaded rule was kept)\n");
        } else {
            if self.source_filter_active() {
                out.push_str(&format!("  Log sources : {}\n", self.source_ids.join(", ")));
            }
            if self.table_filter_active() {
                out.push_str(&format!(
                    "  Azure tables: {}\n",
                    self.azure_tables.join(", ")
                ));
            }
            if self.sourcetype_filter_active() {
                out.push_str(&format!(
                    "  Sourcetypes : {}\n",
                    self.splunk_sourcetypes.join(", ")
                ));
            }
            if self.apt_filter_active() {
                out.push_str(&format!("  Threat actors: {}\n", self.apt_terms.join(", ")));
            }
            if self.technique_filter_active() {
                out.push_str(&format!(
                    "  Techniques  : {}\n",
                    self.technique_ids.join(", ")
                ));
            }
        }

        out.push_str("\nResults:\n");
        out.push_str(&format!("  Rules scanned      : {}\n", s.scanned));
        out.push_str(&format!(
            "  Kept               : {} ({} rewritten in place)\n",
            s.total_kept(),
            s.rewritten
        ));
        out.push_str(&format!("  Dropped (total)    : {}\n", s.total_dropped()));
        out.push_str(&format!("    no source match  : {}\n", s.dropped_source));
        out.push_str(&format!("    no actor match   : {}\n", s.dropped_apt));
        out.push_str(&format!("    no technique     : {}\n", s.dropped_technique));
        out.push_str(&format!(
            "    unreadable/binary: {}\n",
            s.dropped_unreadable
        ));
        out.push_str(
            "\nStrict mode: any rule that could not be positively classified against an \
             active filter was dropped.\n",
        );
        out
    }

    /// Same decision as `filter_file`, but drops carry a reason for reporting.
    pub fn filter_file_traced(&self, tool: &str, content: &str) -> TraceOutcome {
        if self.is_noop() {
            return TraceOutcome::Keep;
        }

        match tool {
            "Sigma" => self.filter_sigma(content),
            "Yara" => {
                // YARA scans files/memory, not log tables: only the APT and
                // technique filters apply.
                if !self.matches_apt(content) {
                    TraceOutcome::Drop(DropReason::Apt)
                } else if !self.matches_technique(content) {
                    TraceOutcome::Drop(DropReason::Technique)
                } else {
                    TraceOutcome::Keep
                }
            }
            "Suricata" => self.filter_suricata(content),
            "Splunk" | "QRadar" => self.filter_text_rules(content),
            "Sysmon" => {
                // Sysmon configs are Windows collection configs, not APT detections:
                // only the source filter applies (APT filter would drop all of them).
                if self.source_filter_active() && !self.source_selected("windows") {
                    TraceOutcome::Drop(DropReason::Source)
                } else {
                    TraceOutcome::Keep
                }
            }
            _ => TraceOutcome::Keep,
        }
    }

    fn filter_sigma(&self, content: &str) -> TraceOutcome {
        // Source/table dimension: pass if the rule matches a selected coarse
        // source OR maps to a selected Azure/M365 table (when those filters
        // are active). Strict: no positive match on any active dimension → drop.
        if self.source_filter_active() || self.table_filter_active() {
            let (product, service, category) = parse_sigma_logsource(content);

            let mut source_ok = false;
            if self.source_filter_active() {
                for def in LOG_SOURCES {
                    if !self.source_selected(def.id) {
                        continue;
                    }
                    let p = product
                        .as_deref()
                        .map_or(false, |v| def.sigma_products.contains(&v));
                    let s = service
                        .as_deref()
                        .map_or(false, |v| def.sigma_services.contains(&v));
                    let c = category
                        .as_deref()
                        .map_or(false, |v| def.sigma_categories.contains(&v));
                    if p || s || c {
                        source_ok = true;
                        break;
                    }
                }
            }

            let mut table_ok = false;
            if self.table_filter_active() {
                // azure/m365 sigma rules: logsource.service must map to a
                // selected table; any rule mentioning a selected table name
                // in its content also qualifies.
                let is_azure = matches!(
                    product.as_deref(),
                    Some("azure") | Some("m365") | Some("microsoft365")
                );
                if is_azure {
                    if let Some(svc) = service.as_deref() {
                        table_ok = self.table_sigma_services.iter().any(|s| s == svc);
                    }
                }
                if !table_ok && self.table_regex.is_some() {
                    table_ok = self
                        .table_regex
                        .as_ref()
                        .map_or(false, |set| set.is_match(content));
                }
            }

            if !source_ok && !table_ok {
                return TraceOutcome::Drop(DropReason::Source);
            }
        }

        if !self.matches_apt(content) {
            return TraceOutcome::Drop(DropReason::Apt);
        }
        if !self.matches_technique(content) {
            return TraceOutcome::Drop(DropReason::Technique);
        }
        TraceOutcome::Keep
    }

    fn filter_suricata(&self, content: &str) -> TraceOutcome {
        // Suricata is inherently network telemetry.
        if self.source_filter_active() && !self.source_selected("network") {
            return TraceOutcome::Drop(DropReason::Source);
        }
        if !self.apt_filter_active() && !self.technique_filter_active() {
            return TraceOutcome::Keep;
        }
        // One rule per line: keep only matching rules (plus comments they sit under).
        let kept: Vec<&str> = content
            .lines()
            .filter(|line| {
                let t = line.trim();
                !t.is_empty()
                    && !t.starts_with('#')
                    && self.matches_apt(line)
                    && self.matches_technique(line)
            })
            .collect();
        if kept.is_empty() {
            let reason = if self.apt_filter_active() {
                DropReason::Apt
            } else {
                DropReason::Technique
            };
            TraceOutcome::Drop(reason)
        } else {
            TraceOutcome::Rewrite(kept.join("\n") + "\n")
        }
    }

    fn filter_text_rules(&self, content: &str) -> TraceOutcome {
        if self.source_filter_active()
            || self.table_filter_active()
            || self.sourcetype_filter_active()
        {
            let mut source_ok = false;
            if self.source_filter_active() {
                let lower = content.to_lowercase();
                source_ok = LOG_SOURCES
                    .iter()
                    .filter(|d| self.source_selected(d.id))
                    .any(|d| d.keywords.iter().any(|k| lower.contains(k)));
            }

            // Table filter: rule content must reference a selected table name.
            let table_ok = self.table_filter_active()
                && self
                    .table_regex
                    .as_ref()
                    .map_or(false, |set| set.is_match(content));

            // Sourcetype filter: rule content must reference a selected sourcetype.
            let sourcetype_ok = self.sourcetype_filter_active()
                && self
                    .sourcetype_regex
                    .as_ref()
                    .map_or(false, |set| set.is_match(content));

            // Strict: no positive match on any active dimension → drop.
            if !source_ok && !table_ok && !sourcetype_ok {
                return TraceOutcome::Drop(DropReason::Source);
            }
        }
        if !self.matches_apt(content) {
            return TraceOutcome::Drop(DropReason::Apt);
        }
        if !self.matches_technique(content) {
            return TraceOutcome::Drop(DropReason::Technique);
        }
        TraceOutcome::Keep
    }
}

/// Extract product/service/category from the first `logsource:` block of a sigma YAML.
/// Lightweight line scan — avoids pulling in a YAML parser for three keys.
fn parse_sigma_logsource(content: &str) -> (Option<String>, Option<String>, Option<String>) {
    let mut product = None;
    let mut service = None;
    let mut category = None;
    let mut in_block = false;

    for line in content.lines() {
        let trimmed = line.trim_end();
        if !in_block {
            if trimmed.trim_start() == "logsource:" || trimmed == "logsource:" {
                in_block = true;
            }
            continue;
        }
        // block ends at first non-indented, non-empty line
        if !trimmed.is_empty() && !trimmed.starts_with(' ') && !trimmed.starts_with('\t') {
            break;
        }
        let inner = trimmed.trim_start();
        for (key, slot) in [
            ("product:", &mut product),
            ("service:", &mut service),
            ("category:", &mut category),
        ] {
            if let Some(rest) = inner.strip_prefix(key) {
                let val = rest
                    .trim()
                    .trim_matches(|c| c == '\'' || c == '"')
                    .to_lowercase();
                if !val.is_empty() && slot.is_none() {
                    *slot = Some(val);
                }
            }
        }
    }
    (product, service, category)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SIGMA_WIN: &str = "title: test\nlogsource:\n    product: windows\n    category: process_creation\ndetection:\n    sel: x\n";
    const SIGMA_AWS: &str = "title: test\nlogsource:\n    product: aws\n    service: cloudtrail\ndetection:\n    sel: x\n";

    #[test]
    fn noop_filter_keeps_everything() {
        let f = CompiledFilter::none();
        assert!(matches!(
            f.filter_file("Sigma", SIGMA_WIN),
            FilterOutcome::Keep
        ));
        assert!(matches!(
            f.filter_file("Yara", "rule x {}"),
            FilterOutcome::Keep
        ));
    }

    #[test]
    fn sigma_source_filter_strict() {
        let f = CompiledFilter::build(vec!["windows".into()], vec![]);
        assert!(matches!(
            f.filter_file("Sigma", SIGMA_WIN),
            FilterOutcome::Keep
        ));
        assert!(matches!(
            f.filter_file("Sigma", SIGMA_AWS),
            FilterOutcome::Drop
        ));
        // no logsource at all → unclassifiable → drop
        assert!(matches!(
            f.filter_file("Sigma", "title: x\ndetection: y\n"),
            FilterOutcome::Drop
        ));
    }

    #[test]
    fn yara_apt_filter() {
        let f = CompiledFilter::build(vec![], vec!["Sandworm".into(), "BlackEnergy".into()]);
        assert!(matches!(
            f.filter_file("Yara", "rule BlackEnergy_dropper { condition: true }"),
            FilterOutcome::Keep
        ));
        assert!(matches!(
            f.filter_file("Yara", "rule generic_packer { condition: true }"),
            FilterOutcome::Drop
        ));
    }

    #[test]
    fn suricata_line_rewrite() {
        let f = CompiledFilter::build(vec!["network".into()], vec!["Emotet".into()]);
        let rules = "alert http any any -> any any (msg:\"Emotet C2\"; sid:1;)\nalert tcp any any -> any any (msg:\"generic scan\"; sid:2;)\n";
        match f.filter_file("Suricata", rules) {
            FilterOutcome::Rewrite(out) => {
                assert!(out.contains("Emotet"));
                assert!(!out.contains("generic scan"));
            }
            _ => panic!("expected rewrite"),
        }
    }

    #[test]
    fn suricata_dropped_when_network_not_selected() {
        let f = CompiledFilter::build(vec!["windows".into()], vec![]);
        assert!(matches!(
            f.filter_file("Suricata", "alert tcp ..."),
            FilterOutcome::Drop
        ));
    }

    #[test]
    fn sysmon_exempt_from_apt_filter() {
        let f = CompiledFilter::build(vec![], vec!["Turla".into()]);
        assert!(matches!(
            f.filter_file("Sysmon", "<Sysmon/>"),
            FilterOutcome::Keep
        ));
    }

    #[test]
    fn blacklisted_terms_ignored() {
        let f = CompiledFilter::build(vec![], vec!["cmd".into(), "net".into()]);
        assert!(!f.apt_filter_active());
    }

    #[test]
    fn word_boundary_matching() {
        let f = CompiledFilter::build(vec![], vec!["APT28".into()]);
        assert!(matches!(
            f.filter_file("Yara", "rule APT28_zebrocy {}"),
            FilterOutcome::Keep
        ));
        let f2 = CompiledFilter::build(vec![], vec!["Ke3chang".into()]);
        assert!(matches!(
            f2.filter_file("Yara", "rule unrelated {}"),
            FilterOutcome::Drop
        ));
    }

    #[test]
    fn azure_table_filter_text_rules() {
        let f = CompiledFilter::build_with_tables(
            vec![],
            vec![],
            vec!["SigninLogs".into(), "OfficeActivity".into()],
        );
        // KQL/Splunk-style rule referencing a selected table
        assert!(matches!(
            f.filter_file("Splunk", "SigninLogs | where ResultType != 0"),
            FilterOutcome::Keep
        ));
        // references an unselected table only
        assert!(matches!(
            f.filter_file(
                "Splunk",
                "DeviceProcessEvents | where FileName == \"mimikatz.exe\""
            ),
            FilterOutcome::Drop
        ));
        // no table reference at all → strict drop
        assert!(matches!(
            f.filter_file("QRadar", "SELECT * FROM events WHERE severity > 5"),
            FilterOutcome::Drop
        ));
    }

    #[test]
    fn azure_table_filter_sigma_service_mapping() {
        let f = CompiledFilter::build_with_tables(vec![], vec![], vec!["SigninLogs".into()]);
        let sigma_signin = "title: t\nlogsource:\n    product: azure\n    service: signinlogs\ndetection:\n    sel: x\n";
        assert!(matches!(
            f.filter_file("Sigma", sigma_signin),
            FilterOutcome::Keep
        ));
        let sigma_kv = "title: t\nlogsource:\n    product: azure\n    service: keyvault\ndetection:\n    sel: x\n";
        assert!(matches!(
            f.filter_file("Sigma", sigma_kv),
            FilterOutcome::Drop
        ));
    }

    #[test]
    fn splunk_sourcetype_filter() {
        let f = CompiledFilter::build_full(
            vec![],
            vec![],
            vec![],
            vec!["pan:traffic".into(), "WinEventLog:Security".into()],
            vec![],
        );
        // SPL referencing a selected sourcetype
        assert!(matches!(
            f.filter_file(
                "Splunk",
                "sourcetype=pan:traffic action=deny | stats count by src_ip"
            ),
            FilterOutcome::Keep
        ));
        assert!(matches!(
            f.filter_file(
                "Splunk",
                "sourcetype=\"WinEventLog:Security\" EventCode=4625"
            ),
            FilterOutcome::Keep
        ));
        // unselected sourcetype only → drop
        assert!(matches!(
            f.filter_file("Splunk", "sourcetype=aws:cloudtrail eventName=ConsoleLogin"),
            FilterOutcome::Drop
        ));
        // no sourcetype at all → strict drop
        assert!(matches!(
            f.filter_file("Splunk", "index=main | stats count"),
            FilterOutcome::Drop
        ));
        // sibling sourcetype must not match (boundary check)
        assert!(matches!(
            f.filter_file("Splunk", "sourcetype=pan:threat"),
            FilterOutcome::Drop
        ));
    }

    #[test]
    fn technique_filter() {
        // lowercase input is normalized; junk is dropped
        let f = CompiledFilter::build_full(
            vec![],
            vec![],
            vec![],
            vec![],
            vec!["t1059".into(), "T1566.001".into(), "banana".into()],
        );
        assert_eq!(f.technique_ids, vec!["T1059", "T1566.001"]);
        // sigma tag style: parent matches subtechnique
        let sigma = "title: t\ntags:\n    - attack.t1059.001\ndetection:\n    sel: x\n";
        assert!(matches!(f.filter_file("Sigma", sigma), FilterOutcome::Keep));
        // exact subtechnique match
        assert!(matches!(
            f.filter_file("Splunk", "annotations: mitre_attack: T1566.001"),
            FilterOutcome::Keep
        ));
        // sibling subtechnique of an exact selection must not match
        let f2 =
            CompiledFilter::build_full(vec![], vec![], vec![], vec![], vec!["T1566.001".into()]);
        assert!(matches!(
            f2.filter_file("Splunk", "mitre: T1566.002"),
            FilterOutcome::Drop
        ));
        // T1059 must not match T1059000-style garbage or unrelated codes
        assert!(matches!(
            f.filter_file("Splunk", "search for T1027 obfuscation"),
            FilterOutcome::Drop
        ));
        // yara: technique in metadata keeps the rule
        assert!(matches!(
            f.filter_file("Yara", "rule x { meta: mitre = \"T1059\" }"),
            FilterOutcome::Keep
        ));
        assert!(matches!(
            f.filter_file("Yara", "rule y { strings: $a = \"z\" }"),
            FilterOutcome::Drop
        ));
    }

    #[test]
    fn table_and_source_are_or_combined() {
        // Windows source + SigninLogs table: a windows sigma rule passes via
        // source, an azure signin rule passes via table.
        let f = CompiledFilter::build_with_tables(
            vec!["windows".into()],
            vec![],
            vec!["SigninLogs".into()],
        );
        assert!(matches!(
            f.filter_file("Sigma", SIGMA_WIN),
            FilterOutcome::Keep
        ));
        let sigma_signin = "title: t\nlogsource:\n    product: azure\n    service: signinlogs\ndetection:\n    sel: x\n";
        assert!(matches!(
            f.filter_file("Sigma", sigma_signin),
            FilterOutcome::Keep
        ));
        assert!(matches!(
            f.filter_file("Sigma", SIGMA_AWS),
            FilterOutcome::Drop
        ));
    }

    #[test]
    fn stats_and_report_track_outcomes() {
        let f = CompiledFilter::build(vec!["windows".into()], vec![]);
        // one keep, one source-drop
        let _ = f.filter_file("Sigma", SIGMA_WIN);
        let _ = f.filter_file("Sigma", SIGMA_AWS);
        f.record_unreadable();
        let s = f.stats();
        assert_eq!(s.scanned, 3);
        assert_eq!(s.kept, 1);
        assert_eq!(s.dropped_source, 1);
        assert_eq!(s.dropped_unreadable, 1);
        assert_eq!(s.total_kept(), 1);
        assert_eq!(s.total_dropped(), 2);
        let report = f.report_text();
        assert!(report.contains("Rules scanned      : 3"));
        assert!(report.contains("Log sources : windows"));
    }
}
