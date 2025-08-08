use crate::ui_rule;
use eframe::{egui, App, Frame};
use std::sync::{Arc, Mutex};

pub struct ToolSelectorApp {
    pub tool_names: Vec<&'static str>,
    pub selected: Vec<bool>,
    pub custom_path: Option<String>,
    pub progress: Arc<Mutex<Option<(usize, usize)>>>,
    pub current_file: Arc<Mutex<Option<String>>>,
    pub cancel_flag: Arc<Mutex<bool>>,
}


impl Default for ToolSelectorApp {
    fn default() -> Self {
        Self {
            selected: vec![false; 6],
            tool_names: vec!["Yara", "Suricata", "Sigma", "Splunk", "QRadar", "All"],
            progress: Arc::new(Mutex::new(None)),
            current_file: Arc::new(Mutex::new(None)),
            custom_path: None,
            cancel_flag: Arc::new(Mutex::new(false)),
        }
    }
}


impl App for ToolSelectorApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut Frame) {
        ui_rule::render_ui(self, ctx, || {});
    }
}
