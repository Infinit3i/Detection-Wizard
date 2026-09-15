//! Rule filtering: log-source/table targeting + APT-driven selection.
//!
//! Strict semantics: when a filter is active, a rule that cannot be
//! positively classified as matching is DROPPED (tight, curated output).
//! A filter with no selections is inactive and passes everything.

use regex::RegexSet;

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
            "security", "sysmon", "system", "powershell", "application",
            "windefend", "taskscheduler", "wmi", "dns-server", "msexchange",
        ],
        sigma_categories: &[
            "process_creation", "registry_set", "registry_add", "registry_event",
            "registry_delete", "image_load", "file_event", "file_delete",
            "file_change", "file_access", "driver_load", "pipe_created",
            "wmi_event", "ps_script", "ps_module", "ps_classic_start",
            "create_remote_thread", "process_access", "network_connection",
            "dns_query", "create_stream_hash", "raw_access_thread", "sysmon_error",
            "sysmon_status", "process_tampering",
        ],
        keywords: &[
            "wineventlog", "sysmon", "windows", "eventcode", "powershell",
            "event_id", "eventid", "security.evtx", "winlog",
        ],
    },
    LogSourceDef {
        id: "linux",
        label: "Linux (auditd / syslog)",
        sigma_products: &["linux"],
        sigma_services: &["auditd", "sshd", "auth", "sudo", "cron", "syslog", "clamav"],
        sigma_categories: &[],
        keywords: &["auditd", "linux", "syslog", "audit.log", "auth.log", "sshd", "bash_history"],
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
        sigma_products: &["zeek", "netflow", "cisco", "juniper", "huawei", "paloalto", "fortios"],
        sigma_services: &["dns", "firewall", "netflow"],
        sigma_categories: &["dns", "firewall", "flow"],
        keywords: &[
            "zeek", "bro_", "netflow", "firewall", "suricata", "snort",
            "pan:traffic", "cisco", "conn.log", "dns.log", "pfsense", "opnsense",
        ],
    },
    LogSourceDef {
        id: "web_proxy",
        label: "Web / Proxy servers",
        sigma_products: &["apache", "nginx"],
        sigma_services: &["iis", "apache", "nginx"],
        sigma_categories: &["proxy", "webserver"],
        keywords: &["proxy", "access_combined", "iis", "apache", "nginx", "useragent", "user-agent", "http_method"],
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
        sigma_services: &["azuread", "azureactivity", "exchange", "threat_management", "audit"],
        sigma_categories: &[],
        keywords: &["azure", "entra", "office 365", "o365", "m365", "exchangeonline", "azuread"],
    },
    LogSourceDef {
        id: "cloud_gcp",
        label: "Cloud: GCP / Google Workspace",
        sigma_products: &["gcp", "google_workspace"],
        sigma_services: &["gcp.audit", "google_workspace.admin"],
        sigma_categories: &[],
        keywords: &["gcp", "google cloud", "gsuite", "google_workspace", "stackdriver"],
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
        keywords: &["defender", "crowdstrike", "sentinelone", "carbon black", "antivirus", "falcon", "edr"],
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

/// Compiled, thread-safe filter built once per run.
pub struct CompiledFilter {
    /// selected LogSourceDef ids; empty = source filter inactive
    pub source_ids: Vec<String>,
    /// human-readable APT terms used (for logging)
    pub apt_terms: Vec<String>,
    /// case-insensitive word-boundary matcher over apt_terms; None = APT filter inactive
    apt_regex: Option<RegexSet>,
}

/// Generic software/tool names that appear in MITRE "uses" relationships but
/// would match nearly every rule as keywords. Never used as filter terms.
const TERM_BLACKLIST: &[&str] = &[
    "at", "net", "cmd", "ping", "reg", "netsh", "tasklist", "systeminfo",
    "ipconfig", "whoami", "route", "arp", "ftp", "curl", "certutil", "esentutl",
    "schtasks", "sc", "query", "dsquery", "pwsh", "powershell", "cscript",
    "wscript", "mshta", "rundll32", "regsvr32", "msiexec", "installutil",
    "windows", "linux", "macos", "python", "java", "bash", "ssh",
];

impl CompiledFilter {
    /// A filter that passes everything (both filters inactive).
    pub fn none() -> Self {
        Self {
            source_ids: Vec::new(),
            apt_terms: Vec::new(),
            apt_regex: None,
        }
    }

    /// Build from UI selections. `apt_terms` should already be the expanded
    /// list (group names + aliases + software) from the MITRE catalog.
    pub fn build(source_ids: Vec<String>, apt_terms: Vec<String>) -> Self {
        let cleaned: Vec<String> = apt_terms
            .into_iter()
            .map(|t| t.trim().to_string())
            .filter(|t| {
                t.len() >= 3
                    && !TERM_BLACKLIST.contains(&t.to_lowercase().as_str())
            })
            .collect();

        let apt_regex = if cleaned.is_empty() {
            None
        } else {
            // Custom boundary: rule names use '_' as a separator (APT28_zebrocy),
            // and \b treats '_' as a word char, so use explicit non-alnum boundaries.
            let patterns: Vec<String> = cleaned
                .iter()
                .map(|t| {
                    format!(
                        r"(?i)(^|[^A-Za-z0-9]){}([^A-Za-z0-9]|$)",
                        regex::escape(t)
                    )
                })
                .collect();
            RegexSet::new(&patterns).ok()
        };

        Self {
            source_ids,
            apt_terms: cleaned,
            apt_regex,
        }
    }

    pub fn source_filter_active(&self) -> bool {
        !self.source_ids.is_empty()
    }

    pub fn apt_filter_active(&self) -> bool {
        self.apt_regex.is_some()
    }

    pub fn is_noop(&self) -> bool {
        !self.source_filter_active() && !self.apt_filter_active()
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

    /// Decide what to do with one candidate rule file.
    /// `tool` is the ToolSpec name: "Yara", "Sigma", "Suricata", "Splunk", "QRadar", "Sysmon".
    pub fn filter_file(&self, tool: &str, content: &str) -> FilterOutcome {
        if self.is_noop() {
            return FilterOutcome::Keep;
        }

        match tool {
            "Sigma" => self.filter_sigma(content),
            "Yara" => {
                // YARA scans files/memory, not log tables: only the APT filter applies.
                if self.matches_apt(content) {
                    FilterOutcome::Keep
                } else {
                    FilterOutcome::Drop
                }
            }
            "Suricata" => self.filter_suricata(content),
            "Splunk" | "QRadar" => self.filter_text_rules(content),
            "Sysmon" => {
                // Sysmon configs are Windows collection configs, not APT detections:
                // only the source filter applies (APT filter would drop all of them).
                if self.source_filter_active() && !self.source_selected("windows") {
                    FilterOutcome::Drop
                } else {
                    FilterOutcome::Keep
                }
            }
            _ => FilterOutcome::Keep,
        }
    }

    fn filter_sigma(&self, content: &str) -> FilterOutcome {
        if self.source_filter_active() {
            let (product, service, category) = parse_sigma_logsource(content);
            let mut matched = false;
            for def in LOG_SOURCES {
                if !self.source_selected(def.id) {
                    continue;
                }
                let p = product.as_deref().map_or(false, |v| def.sigma_products.contains(&v));
                let s = service.as_deref().map_or(false, |v| def.sigma_services.contains(&v));
                let c = category.as_deref().map_or(false, |v| def.sigma_categories.contains(&v));
                if p || s || c {
                    matched = true;
                    break;
                }
            }
            // Strict: unknown/unmapped logsource → drop.
            if !matched {
                return FilterOutcome::Drop;
            }
        }

        if !self.matches_apt(content) {
            return FilterOutcome::Drop;
        }
        FilterOutcome::Keep
    }

    fn filter_suricata(&self, content: &str) -> FilterOutcome {
        // Suricata is inherently network telemetry.
        if self.source_filter_active() && !self.source_selected("network") {
            return FilterOutcome::Drop;
        }
        if !self.apt_filter_active() {
            return FilterOutcome::Keep;
        }
        // One rule per line: keep only APT-matching rules (plus comments they sit under).
        let kept: Vec<&str> = content
            .lines()
            .filter(|line| {
                let t = line.trim();
                !t.is_empty() && !t.starts_with('#') && self.matches_apt(line)
            })
            .collect();
        if kept.is_empty() {
            FilterOutcome::Drop
        } else {
            FilterOutcome::Rewrite(kept.join("\n") + "\n")
        }
    }

    fn filter_text_rules(&self, content: &str) -> FilterOutcome {
        if self.source_filter_active() {
            let lower = content.to_lowercase();
            let matched = LOG_SOURCES
                .iter()
                .filter(|d| self.source_selected(d.id))
                .any(|d| d.keywords.iter().any(|k| lower.contains(k)));
            // Strict: no classifiable source keyword → drop.
            if !matched {
                return FilterOutcome::Drop;
            }
        }
        if !self.matches_apt(content) {
            return FilterOutcome::Drop;
        }
        FilterOutcome::Keep
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
        assert!(matches!(f.filter_file("Sigma", SIGMA_WIN), FilterOutcome::Keep));
        assert!(matches!(f.filter_file("Yara", "rule x {}"), FilterOutcome::Keep));
    }

    #[test]
    fn sigma_source_filter_strict() {
        let f = CompiledFilter::build(vec!["windows".into()], vec![]);
        assert!(matches!(f.filter_file("Sigma", SIGMA_WIN), FilterOutcome::Keep));
        assert!(matches!(f.filter_file("Sigma", SIGMA_AWS), FilterOutcome::Drop));
        // no logsource at all → unclassifiable → drop
        assert!(matches!(f.filter_file("Sigma", "title: x\ndetection: y\n"), FilterOutcome::Drop));
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
        assert!(matches!(f.filter_file("Suricata", "alert tcp ..."), FilterOutcome::Drop));
    }

    #[test]
    fn sysmon_exempt_from_apt_filter() {
        let f = CompiledFilter::build(vec![], vec!["Turla".into()]);
        assert!(matches!(f.filter_file("Sysmon", "<Sysmon/>"), FilterOutcome::Keep));
    }

    #[test]
    fn blacklisted_terms_ignored() {
        let f = CompiledFilter::build(vec![], vec!["cmd".into(), "net".into()]);
        assert!(!f.apt_filter_active());
    }

    #[test]
    fn word_boundary_matching() {
        let f = CompiledFilter::build(vec![], vec!["APT28".into()]);
        assert!(matches!(f.filter_file("Yara", "rule APT28_zebrocy {}"), FilterOutcome::Keep));
        let f2 = CompiledFilter::build(vec![], vec!["Ke3chang".into()]);
        assert!(matches!(f2.filter_file("Yara", "rule unrelated {}"), FilterOutcome::Drop));
    }
}
