use eframe::{App, Frame, egui};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};

pub struct ToolSelectorApp {
    pub tool_names: Vec<&'static str>,
    pub selected: Vec<bool>,
    pub custom_path: Option<String>,
    pub progress: Arc<Mutex<Option<(usize, usize, String)>>>, // <-- triplet now
    pub cancel_flag: Arc<AtomicBool>,                         // <-- AtomicBool now
}

impl Default for ToolSelectorApp {
    fn default() -> Self {
        Self {
            selected: vec![false; 6],
            tool_names: vec!["Yara", "Suricata", "Sigma", "Splunk", "QRadar", "All"],
            progress: Arc::new(Mutex::new(None)),
            custom_path: None,
            cancel_flag: Arc::new(AtomicBool::new(false)),
        }
    }
}

impl App for ToolSelectorApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut Frame) {
        super::ui_rule::render_ui(self, ctx, || {});
    }
}
