use crate::apt_catalog::APT_GROUPS;
use crate::filter::LOG_SOURCES;
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
        }
    }
}

impl App for ToolSelectorApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut Frame) {
        super::ui_rule::render_ui(self, ctx, || {});
    }
}
