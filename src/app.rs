use crate::ui;
use crate::ui::load_icon;
use eframe::{egui, App, Frame, NativeOptions};
use std::sync::{Arc, Mutex};

pub struct ToolSelectorApp {
    pub selected: Vec<bool>,
    pub tool_names: Vec<&'static str>,
    pub progress: Arc<Mutex<Option<(usize, usize)>>>,
}

impl Default for ToolSelectorApp {
    fn default() -> Self {
        Self {
            selected: vec![false; 5],
            tool_names: vec!["Yara", "Suricata", "Sigma", "Splunk", "All"],
            progress: Arc::new(Mutex::new(None)),
        }
    }
}

impl App for ToolSelectorApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut Frame) {
        ui::render_ui(self, ctx, || {});
    }
}

pub fn run() -> eframe::Result<()> {
    let icon_data = load_icon("assets/icon.jpg");

    let mut viewport = egui::ViewportBuilder::default();

    if let Some(icon) = icon_data {
        viewport = viewport.with_icon(Arc::new(icon));
    }

    let options = NativeOptions {
        viewport,
        ..Default::default()
    };

    eframe::run_native(
        "Detection Wizard",
        options,
        Box::new(|_cc| Box::<ToolSelectorApp>::default()),
    )
}
