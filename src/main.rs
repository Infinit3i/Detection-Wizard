// src/main.rs

mod app;
mod ioc_menu;
mod menu;
mod ui;
mod ui_ioc;
mod yara;
mod suricata;
mod sigma;
mod splunk;

use eframe::{egui::ViewportBuilder, NativeOptions};
use crate::menu::MainApp;
use crate::ui::load_icon;
use std::sync::Arc;

fn main() -> eframe::Result<()> {
    let icon_data = load_icon("assets/icon.jpg");

    let mut viewport = ViewportBuilder::default();
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
        Box::new(|_cc| Box::<MainApp>::default()),
    )
}
