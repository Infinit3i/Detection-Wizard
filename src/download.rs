use chrono::Local;
use eframe::egui::Context;
use egui::Color32;
use std::path::PathBuf;
use std::fs;
use std::path::Path;
use std::sync::{Arc, Mutex};
use indicatif::{ProgressBar, ProgressStyle};
use std::thread;
use eframe::egui;
use reqwest::blocking::get;
use std::io;
use tempfile::tempdir;
use walkdir::WalkDir;

#[derive(Clone)]
pub enum DownloadFormat {
    Txt,
    Csv,
}

pub fn download_files_with_progress(
    urls: &[&str],
    output_path: &PathBuf,
    label: &str,
    extension_filter: Option<&str>,
) {
    let pb = ProgressBar::new(urls.len() as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("[{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} {msg}")
            .unwrap()
            .progress_chars("##-"),
    );

    for url in urls {
        let file_name = url.split('/').last().unwrap_or("downloaded.rules");
        pb.set_message(format!("{}: {}", label, file_name));

        if let Some(ext) = extension_filter {
            if !file_name.ends_with(ext) {
                pb.inc(1);
                continue;
            }
        }

        match get(*url) {
            Ok(resp) if resp.status().is_success() => {
                if let Ok(text) = resp.text() {
                    let dest_path = output_path.join(file_name);
                    if let Err(e) = fs::write(&dest_path, text) {
                        eprintln!("Failed to write {}: {}", dest_path.display(), e);
                    }
                } else {
                    eprintln!("Failed to read response text from: {}", url);
                }
            }
            Ok(resp) => {
                eprintln!("HTTP error for {}: {}", url, resp.status());
            }
            Err(e) => {
                eprintln!("Request error for {}: {}", url, e);
            }
        }

        pb.inc(1);
    }

    pb.finish_with_message(format!("Finished downloading {} rules", label));
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

pub fn download_and_extract_git_repo(

    repo_url: &str,
    output_path: &Path,
    extension: Option<&str>,
) -> io::Result<()> {
    let tmp_dir = tempdir()?;
    let tmp_path = tmp_dir.path();

    git2::Repository::clone(repo_url, tmp_path)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.message()))?;

    for entry in WalkDir::new(tmp_path) {
        let entry = entry?;
        let path = entry.path();

        if path.is_file() {
            if let Some(ext) = extension {
                if !path.extension().and_then(|e| e.to_str()).map_or(false, |e| e.ends_with(&ext[1..])) {
                    continue;
                }
            }

            let filename = path.file_name().unwrap_or_default();
            let dest = output_path.join(filename);
            fs::copy(path, dest)?;
        }
    }

    Ok(())
}
