use crate::apt_catalog::APT_GROUPS;
use crate::azure_tables::AZURE_TABLES;
use crate::filter::LOG_SOURCES;
use crate::splunk_sourcetypes::SPLUNK_SOURCETYPES;
use crate::ttp_catalog::TTP_CATALOG;
use eframe::{App, Frame, egui};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};

pub struct ToolSelectorApp {
    pub tool_names: Vec<&'static str>,
    pub selected: Vec<bool>,
    pub custom_path: Option<String>,
    pub progress: Arc<Mutex<Option<(usize, usize, String)>>>, // <-- triplet now
    pub cancel_flag: Arc<AtomicBool>,                         // <-- AtomicBool now

    // --- Targeting: log sources / tables ---
    /// parallel to crate::filter::LOG_SOURCES; all false = no source filter (grab everything)
    pub source_selected: Vec<bool>,
    /// live search box for the log source list
    pub source_search: String,

    // --- Targeting: APT groups ---
    /// parallel to crate::apt_catalog::APT_GROUPS; all false = no APT filter
    pub apt_selected: Vec<bool>,
    /// live search box for the APT list
    pub apt_search: String,
    /// extra comma-separated free-text terms (actor/malware names not in the catalog)
    pub apt_custom_terms: String,

    // --- Targeting: granular Azure/M365 log tables ---
    /// parallel to crate::azure_tables::AZURE_TABLES; all false = table filter off
    pub azure_table_selected: Vec<bool>,
    /// live search box for the table list
    pub azure_table_search: String,

    // --- Targeting: granular Splunk sourcetypes ---
    /// parallel to crate::splunk_sourcetypes::SPLUNK_SOURCETYPES; all false = filter off
    pub sourcetype_selected: Vec<bool>,
    /// live search box for the sourcetype list
    pub sourcetype_search: String,

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
    /// live search box for the TTP list
    pub ttp_search: String,
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
            source_search: String::new(),
            apt_selected: vec![false; APT_GROUPS.len()],
            apt_search: String::new(),
            apt_custom_terms: String::new(),
            azure_table_selected: vec![false; AZURE_TABLES.len()],
            azure_table_search: String::new(),
            sourcetype_selected: vec![false; SPLUNK_SOURCETYPES.len()],
            sourcetype_search: String::new(),
            where_tab: None,
            filter_tab: None,
            filter_search: String::new(),
            ttp_selected: vec![false; TTP_CATALOG.len()],
            ttp_search: String::new(),
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
