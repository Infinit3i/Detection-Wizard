use crate::apt_catalog::APT_GROUPS;
use crate::azure_tables::AZURE_TABLES;
use crate::filter::LOG_SOURCES;
use crate::splunk_sourcetypes::SPLUNK_SOURCETYPES;
use crate::ttp_catalog::TTP_CATALOG;
use eframe::{App, Frame, egui};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};

/// The four tool checkboxes that also double as convertible rule-language
/// targets. When one of these is checked in `selected`, its output folder
/// receives every selected tool's filtered rules converted into that
/// format (via the shared `RuleAst` in `sigma_to_kql.rs`), in addition to
/// its own native rules. Rules that can't be confidently converted stay in
/// their original format/folder rather than risk a wrong translation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetLanguage {
    Sigma,
    Splunk,
    QRadar,
    Sentinel,
}

impl TargetLanguage {
    /// Maps a tool-checkbox name to its `TargetLanguage`, if that tool is
    /// one of the four convertible formats (Yara/Suricata/Sysmon/All are
    /// not rule-language targets, so they return `None`).
    pub fn from_tool_name(name: &str) -> Option<TargetLanguage> {
        match name {
            "Sigma" => Some(TargetLanguage::Sigma),
            "Splunk" => Some(TargetLanguage::Splunk),
            "QRadar" => Some(TargetLanguage::QRadar),
            "Sentinel" => Some(TargetLanguage::Sentinel),
            _ => None,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            TargetLanguage::Sigma => "Sigma (YAML)",
            TargetLanguage::Splunk => "Splunk (SPL)",
            TargetLanguage::QRadar => "QRadar (AQL)",
            TargetLanguage::Sentinel => "Sentinel (KQL)",
        }
    }
}

pub struct ToolSelectorApp {
    pub tool_names: Vec<&'static str>,
    pub selected: Vec<bool>,
    pub custom_path: Option<String>,
    pub progress: Arc<Mutex<Option<(usize, usize, String)>>>, // <-- triplet now
    pub cancel_flag: Arc<AtomicBool>,                         // <-- AtomicBool now

    // --- Targeting: log sources / tables ---
    /// parallel to crate::filter::LOG_SOURCES; all false = no source filter (grab everything)
    pub source_selected: Vec<bool>,

    // --- Targeting: APT groups ---
    /// parallel to crate::apt_catalog::APT_GROUPS; all false = no APT filter
    pub apt_selected: Vec<bool>,
    /// extra comma-separated free-text terms (actor/malware names not in the catalog)
    pub apt_custom_terms: String,

    // --- Targeting: granular Azure/M365 log tables ---
    /// parallel to crate::azure_tables::AZURE_TABLES; all false = table filter off
    pub azure_table_selected: Vec<bool>,

    // --- Targeting: granular Splunk sourcetypes ---
    /// parallel to crate::splunk_sourcetypes::SPLUNK_SOURCETYPES; all false = filter off
    pub sourcetype_selected: Vec<bool>,

    /// which of the three "log sources" sub-pickers is expanded (General
    /// categories / Azure tables / Splunk sourcetypes); only one at a time,
    /// None = all collapsed
    pub where_tab: Option<usize>,

    /// which top-level filter section is expanded (0=Log Sources, 1=APT,
    /// 2=TTPs); only one at a time, None = all collapsed
    pub filter_tab: Option<usize>,

    /// global search box next to the "Filter" heading: when non-empty,
    /// shows matches from every category (General/Azure/Splunk/APT/TTPs)
    /// labeled with which one they belong to, instead of the tabs
    pub filter_search: String,

    // --- Targeting: MITRE ATT&CK techniques ---
    /// parallel to crate::ttp_catalog::TTP_CATALOG; all false = no TTP filter
    pub ttp_selected: Vec<bool>,
    /// extra comma/space-separated T-codes not in the catalog
    pub technique_input: String,

    /// filter from the most recent run, kept so we can show live stats + write a report
    pub last_filter: Option<Arc<crate::filter::CompiledFilter>>,
    /// true once filter_report.txt has been written for the current run
    pub report_written: bool,
}

impl Default for ToolSelectorApp {
    fn default() -> Self {
        Self {
            selected: vec![false; 7],
            tool_names: vec![
                "Yara", "Suricata", "Sigma", "Splunk", "QRadar", "Sentinel", "All",
            ],
            progress: Arc::new(Mutex::new(None)),
            custom_path: None,
            cancel_flag: Arc::new(AtomicBool::new(false)),
            source_selected: vec![false; LOG_SOURCES.len()],
            apt_selected: vec![false; APT_GROUPS.len()],
            apt_custom_terms: String::new(),
            azure_table_selected: vec![false; AZURE_TABLES.len()],
            sourcetype_selected: vec![false; SPLUNK_SOURCETYPES.len()],
            where_tab: None,
            filter_tab: None,
            filter_search: String::new(),
            ttp_selected: vec![false; TTP_CATALOG.len()],
            technique_input: String::new(),
            last_filter: None,
            report_written: false,
        }
    }
}

impl App for ToolSelectorApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut Frame) {
        super::ui_rule::render_ui(self, ctx, || {});
    }
}
