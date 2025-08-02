use chrono::Local;
use eframe::egui::Context;
use egui::Color32;
use std::fs;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::thread;
use eframe::egui;

#[derive(Clone)]
pub enum DownloadFormat {
    Txt,
    Csv,
}

pub fn start_download(
    all_urls: Vec<(String, String)>,
    format: DownloadFormat,
    output_path: String,
    progress: Arc<Mutex<Option<(usize, usize)>>>,
    ctx: Context,
) {
    let total = all_urls.len();
    *progress.lock().unwrap() = Some((0, total));

    thread::spawn(move || {
        let mut completed = 0;
        for (url, ioc_type) in all_urls {
            fetch_and_append_to_file(
                &url,
                &ioc_type,
                &format,
                &output_path,
                Some(&mut || {
                    completed += 1;
                    if let Ok(mut p) = progress.lock() {
                        *p = Some((completed, total));
                    }
                    ctx.request_repaint();
                }),
            );
        }
    });
}

pub fn fetch_and_append_to_file(
    url: &str,
    ioc_type: &str,
    format: &DownloadFormat,
    base_path: &str,
    mut progress_callback: Option<&mut dyn FnMut()>,
) {
    let date_str = Local::now().format("%Y-%m-%d").to_string();
    let extension = match format {
        DownloadFormat::Txt => "txt",
        DownloadFormat::Csv => "csv",
    };
    let filename = format!("{}-{}.{}", ioc_type.to_lowercase(), date_str, extension);
    let out_path = Path::new(base_path).join(&filename);

    if let Some(parent) = out_path.parent() {
        if let Err(e) = fs::create_dir_all(parent) {
            eprintln!("❌ Failed to create directory {}: {}", parent.display(), e);
            return;
        }
    }

    match reqwest::blocking::get(url) {
        Ok(response) => match response.text() {
            Ok(text) => {
                let mut existing = String::new();
                if out_path.exists() {
                    if let Ok(existing_text) = fs::read_to_string(&out_path) {
                        existing = existing_text;
                    }
                }

                let combined = match format {
                    DownloadFormat::Txt => format!("{}\n{}", existing.trim(), text.trim()),
                    DownloadFormat::Csv => {
                        format!("{},{}", existing.trim(), text.trim().replace('\n', ","))
                    }
                };

                if let Err(e) = fs::write(&out_path, combined.as_bytes()) {
                    eprintln!("❌ Failed to write to {}: {}", out_path.display(), e);
                } else {
                    println!("✅ Appended {} to {}", url, out_path.display());
                }
            }
            Err(e) => eprintln!("❌ Failed to read content from {}: {}", url, e),
        },
        Err(e) => eprintln!("❌ Failed to fetch {}: {}", url, e),
    }

    if let Some(cb) = progress_callback.as_mut() {
        cb();
    }
}

pub fn render_output_path_selector(
    ui: &mut egui::Ui,
    custom_path: &mut Option<String>,
    default_path: &str,
) {
    // Colored button with white text
    if ui
        .add(
            egui::Button::new(
                egui::RichText::new("Choose Output Folder").color(Color32::WHITE),
            )
            .fill(Color32::from_rgb(70, 130, 180)),
        )
        .clicked()
    {
        if let Some(path) = rfd::FileDialog::new().pick_folder() {
            *custom_path = Some(path.display().to_string());
        }
    }

    // Show the path below
    if let Some(path) = custom_path {
        ui.label(format!("Save path: {}", path));
    } else {
        ui.label(format!("Save path: {} (default)", default_path));
    }
}

