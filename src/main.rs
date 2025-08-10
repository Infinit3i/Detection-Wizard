#![cfg_attr(windows, windows_subsystem = "windows")]

mod rules;
mod ioc;
mod main_menu;
mod download;

use eframe::{egui::ViewportBuilder, NativeOptions};
use eframe::egui::IconData;            // <-- IconData is in egui
use detection_wizard::main_menu::MainApp;
use std::sync::Arc;
use image::ImageReader;
use image::GenericImageView;

// Runtime window/taskbar icon loader
fn load_icon(path: &str) -> Option<IconData> {
    let reader = ImageReader::open(path).ok()?;  // avoid error-type mismatch
    let img = reader.decode().ok()?;
    let (width, height) = img.dimensions();
    let rgba = img.into_rgba8().into_raw();
    Some(IconData { rgba, width, height })
}

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