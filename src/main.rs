use detection_wizard::main_menu::MainApp;
use eframe::egui::IconData;
use eframe::{
    NativeOptions,
    egui::{ViewportBuilder, vec2},
};
use image::{GenericImageView, ImageReader};
use std::sync::Arc;

fn load_icon(path: &str) -> Option<IconData> {
    let reader = ImageReader::open(path).ok()?;
    let img = reader.decode().ok()?;
    let (width, height) = img.dimensions();
    let rgba = img.into_rgba8().into_raw();
    Some(IconData {
        rgba,
        width,
        height,
    })
}

fn main() -> eframe::Result<()> {
    let icon_data = load_icon("assets/icon.jpg");

    // Set your preferred size
    let mut viewport = ViewportBuilder::default().with_inner_size(vec2(1100.0, 720.0));

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
        Box::new(|_cc| Ok(Box::<MainApp>::default())),
    )
}
