use crate::apt_catalog::APT_GROUPS;
use crate::azure_tables::AZURE_TABLES;
use crate::filter::LOG_SOURCES;
use crate::splunk_sourcetypes::SPLUNK_SOURCETYPES;
use eframe::{egui, App, Frame};
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
    /// show/hide the Azure table picker section
    pub azure_tables_open: bool,

    // --- Targeting: granular Splunk sourcetypes ---
    /// parallel to crate::splunk_sourcetypes::SPLUNK_SOURCETYPES; all false = filter off
    pub sourcetype_selected: Vec<bool>,
    /// live search box for the sourcetype list
    pub sourcetype_search: String,
    /// show/hide the Splunk sourcetype picker section
    pub sourcetypes_open: bool,

    // --- Targeting: MITRE ATT&CK techniques ---
    /// comma/space-separated T-codes, e.g. "T1059, T1566.001"
    pub technique_input: String,
}

impl Default for ToolSelectorApp {
    fn default() -> Self {
        Self {
            selected: vec![false; 6],
            tool_names: vec!["Yara", "Suricata", "Sigma", "Splunk", "QRadar", "All"],
            progress: Arc::new(Mutex::new(None)),
            custom_path: None,
            cancel_flag: Arc::new(AtomicBool::new(false)),
            source_selected: vec![false; LOG_SOURCES.len()],
            apt_selected: vec![false; APT_GROUPS.len()],
            apt_search: String::new(),
            apt_custom_terms: String::new(),
            azure_table_selected: vec![false; AZURE_TABLES.len()],
            azure_table_search: String::new(),
            azure_tables_open: false,
            sourcetype_selected: vec![false; SPLUNK_SOURCETYPES.len()],
            sourcetype_search: String::new(),
            sourcetypes_open: false,
            technique_input: String::new(),
        }
    }
}

impl App for ToolSelectorApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut Frame) {
        super::ui_rule::render_ui(self, ctx, || {});
    }
}
