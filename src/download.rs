use chrono::Local;
use eframe::egui::{self, Context};
use egui::Color32;
use git2::Repository;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::Duration;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::thread;
use tempfile::tempdir;
use walkdir::WalkDir;
use rfd::{MessageDialog, MessageButtons, MessageLevel, MessageDialogResult};

/// Output format for IOC text aggregations (kept for parity with your existing design)
#[derive(Clone, Copy)]
pub enum DownloadFormat {
    Txt,
    Csv,
}

pub struct ToolSpec {
    pub name: &'static str,
    pub dest_subfolder: &'static str,
    pub repo_urls: &'static [&'static str],
    pub page_urls: &'static [&'static str],
    pub allowed_exts: &'static [&'static str],
}

fn ext_allowed(file_name: &str, allowed_exts: &[&str]) -> bool {
    if allowed_exts.is_empty() {
        return true; // allow all if not specified
    }
    let Some(ext) = std::path::Path::new(file_name).extension().and_then(|e| e.to_str()) else {
        return false;
    };
    allowed_exts
        .iter()
        .any(|al| al.eq_ignore_ascii_case(ext))
}

pub fn process_tool(
    spec: &ToolSpec,
    output_root: &Path,
    progress: Arc<Mutex<Option<(usize, usize, String)>>>, // (done, total, current)
    ctx: Context,
    cancel_flag: Arc<AtomicBool>,
) -> io::Result<()> {
    // <output_root>/<tool_subfolder>
    let dest_dir = output_root.join(spec.dest_subfolder);
    fs::create_dir_all(&dest_dir)?;

    // repos + direct URLs
    let total = spec.repo_urls.len() + spec.page_urls.len();
    {
        let mut p = progress.lock().unwrap();
        *p = Some((0, total, String::new()));
    }
    ctx.request_repaint();

    let spec_name = spec.name;
    let allowed = spec.allowed_exts;
    let repos = spec.repo_urls;
    let pages = spec.page_urls;
    let dest_dir_clone = dest_dir.clone();

    thread::spawn(move || {
        let mut done = 0usize;

        // 1) Repos
        for repo_url in repos {
            if cancel_flag.load(Ordering::Relaxed) { break; }
            {
                let mut p = progress.lock().unwrap();
                *p = Some((done, total, repo_url.to_string()));
            }
            ctx.request_repaint();

            if let Err(e) = clone_and_copy_filtered(repo_url, &dest_dir_clone, allowed) {
                eprintln!("[{}] Repo failed {}: {}", spec_name, repo_url, e);
            }

            done += 1;
            {
                let mut p = progress.lock().unwrap();
                *p = Some((done, total, repo_url.to_string()));
            }
            ctx.request_repaint();
        }

        // 2) Direct URLs (“wget”)
        for page_url in pages {
            if cancel_flag.load(Ordering::Relaxed) { break; }
            {
                let mut p = progress.lock().unwrap();
                *p = Some((done, total, page_url.to_string()));
            }
            ctx.request_repaint();

            match download_url_to_dir(page_url, &dest_dir_clone, allowed) {
                Ok(Some(_path)) => {}
                Ok(None) => {} // filtered or skipped by overwrite
                Err(e) => eprintln!("[{}] URL failed {}: {}", spec_name, page_url, e),
            }

            done += 1;
            {
                let mut p = progress.lock().unwrap();
                *p = Some((done, total, page_url.to_string()));
            }
            ctx.request_repaint();
        }

        // Finish
        {
            let mut p = progress.lock().unwrap();
            *p = Some((done, total, String::new()));
        }
        ctx.request_repaint();
    });

    Ok(())
}

/// UI helper you already had — kept intact but simplified text
pub fn render_output_path_selector(
    ui: &mut egui::Ui,
    custom_path: &mut Option<String>,
    default_path: &str,
) {
    if ui
        .add(
            egui::Button::new(egui::RichText::new("Choose Output Folder").color(Color32::WHITE))
                .fill(Color32::from_rgb(70, 130, 180)),
        )
        .clicked()
    {
        if let Some(path) = rfd::FileDialog::new().pick_folder() {
            *custom_path = Some(path.display().to_string());
        }
    }

    if let Some(path) = custom_path {
        ui.label(format!("Save path: {}", path));
    } else {
        ui.label(format!("Save path: {} (default)", default_path));
    }
}

/// Clone repo to a temp dir and copy only files with allowed extensions into dest_dir
fn clone_and_copy_filtered(
    repo_url: &str,
    dest_dir: &Path,
    allowed_exts: &[&str],
) -> io::Result<()> {
    let tmp = tempdir()?;
    let tmp_path = tmp.path();

    Repository::clone(repo_url, tmp_path)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.message()))?;

    copy_filtered_files(tmp_path, dest_dir, allowed_exts)
}

fn copy_filtered_files(src: &Path, dest_dir: &Path, allowed_exts: &[&str]) -> io::Result<()> {
    fs::create_dir_all(dest_dir)?;

    for entry in WalkDir::new(src).into_iter().filter_map(Result::ok) {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }

        let fname = match path.file_name().and_then(|f| f.to_str()) {
            Some(f) => f,
            None => continue,
        };

        if !ext_allowed(fname, allowed_exts) {
            continue;
        }

        // Unique-ish name to avoid collisions: <topdir>_<filename>
        let repo_top = src.file_name().unwrap_or_default().to_string_lossy();
        let unique = format!("{}_{}", sanitize(&repo_top), fname);

        let dest = dest_dir.join(unique);

        if dest.exists() {
            if !should_overwrite(&dest) {
                continue; // Skip or Skip All
            }
            let _ = fs::remove_file(&dest);
        }

        if let Err(e) = fs::copy(path, &dest) {
            eprintln!("Failed to copy {:?} -> {:?}: {}", path, dest, e);
        }
    }

    Ok(())
}

/// Simple filename-safe sanitization
fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect()
}

/// Optional: still expose your TXT/CSV aggregation pipeline if you need it elsewhere
pub fn start_download_iocs(
    all_urls: Vec<(String, String)>,
    format: DownloadFormat,
    output_path: String,
    progress: Arc<Mutex<Option<(usize, usize)>>>,
    ctx: Context,
    cancel_flag: Arc<AtomicBool>,
) {
    let total = all_urls.len();
    *progress.lock().unwrap() = Some((0, total));

    thread::spawn(move || {
        let mut completed = 0;
        for (url, ioc_type) in all_urls {
            if cancel_flag.load(Ordering::Relaxed) {
                break;
            }
            fetch_and_append_to_file(&url, &ioc_type, &format, &output_path);
            completed += 1;
            if let Ok(mut p) = progress.lock() {
                *p = Some((completed, total));
            }
            ctx.request_repaint();
        }
    });
}

/// Kept simple: append mode aggregation
pub fn fetch_and_append_to_file(
    url: &str,
    ioc_type: &str,
    format: &DownloadFormat,
    base_path: &str,
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
        Ok(resp) if resp.status().is_success() => match resp.text() {
            Ok(text) => {
                let existing = fs::read_to_string(&out_path).unwrap_or_default();
                let combined = match format {
                    DownloadFormat::Txt => {
                        if existing.trim().is_empty() {
                            text.trim().to_string()
                        } else {
                            format!("{}\n{}", existing.trim(), text.trim())
                        }
                    }
                    DownloadFormat::Csv => {
                        let new_csv = text.trim().replace('\n', ",");
                        if existing.trim().is_empty() {
                            new_csv
                        } else {
                            format!("{},{}", existing.trim(), new_csv)
                        }
                    }
                };
                if let Err(e) = fs::write(&out_path, combined.as_bytes()) {
                    eprintln!("❌ Failed to write {}: {}", out_path.display(), e);
                }
            }
            Err(e) => eprintln!("❌ Failed to read content from {}: {}", url, e),
        },
        Ok(resp) => eprintln!("❌ HTTP error {} for {}", resp.status(), url),
        Err(e) => eprintln!("❌ Request error for {}: {}", url, e),
    }
}

/// Clone a repo and copy only files matching an optional extension filter (e.g., ".rules")
pub fn download_and_extract_git_repo(
    repo_url: &str,
    output_path: &std::path::Path,
    extension: Option<&str>,
) -> std::io::Result<()> {
    // Normalize ".ext" -> "ext"
    let allowed: Vec<&str> = extension
        .map(|e| e.trim_start_matches('.'))
        .into_iter()
        .collect();
    // Reuse the internal helper
    clone_and_copy_filtered(repo_url, output_path, &allowed)
}

pub fn download_files_with_progress(
    urls: &[&str],
    output_path: &PathBuf,
    _label: &str,
    extension_filter: Option<&str>,
) {
    // Map Option<".xml"> → ["xml"] etc.
    let allowed: Vec<&str> = extension_filter
        .map(|e| e.trim_start_matches('.'))
        .into_iter()
        .collect();

    for url in urls {
        if let Err(e) = download_url_to_dir(url, output_path, &allowed) {
            eprintln!("download {} failed: {}", url, e);
        }
    }
}

// Back-compat wrapper used by ui_ioc.rs; delegates to the generic pipeline.
pub fn start_download(
    all_urls: Vec<(String, String)>,
    format: DownloadFormat,
    output_path: String,
    progress: std::sync::Arc<std::sync::Mutex<Option<(usize, usize)>>>,
    ctx: eframe::egui::Context,
) {
    use std::sync::atomic::AtomicBool;
    let cancel_flag = std::sync::Arc::new(AtomicBool::new(false));
    start_download_iocs(all_urls, format, output_path, progress, ctx, cancel_flag);
}

use std::sync::OnceLock;

// ---------------- Overwrite Prompt + Memory ----------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OverwriteAction {
    Overwrite,
    Skip,
    OverwriteAll,
    SkipAll,
}

#[derive(Default, Debug)]
struct OverwritePolicy {
    overwrite_all: bool,
    skip_all: bool,
}

// Global, safe-once init container for policy
static OVERWRITE_POLICY: OnceLock<Mutex<OverwritePolicy>> = OnceLock::new();

fn overwrite_policy() -> &'static Mutex<OverwritePolicy> {
    OVERWRITE_POLICY.get_or_init(|| Mutex::new(OverwritePolicy::default()))
}

/// Default prompt implemented with rfd using two quick questions
/// (1) Overwrite this file?  (Yes/No)
/// (2) Apply this choice to all files? (Yes/No)
fn prompt_overwrite_native(path: &Path) -> OverwriteAction {

    let q1 = MessageDialog::new()
        .set_level(MessageLevel::Warning)
        .set_title("File already exists")
        .set_description(&format!("Overwrite?\n{}", path.display()))
        .set_buttons(MessageButtons::YesNo)
        .show();

    let first = if matches!(q1, MessageDialogResult::Yes) {
        OverwriteAction::Overwrite
    } else {
        OverwriteAction::Skip
    };

    let q2 = MessageDialog::new()
        .set_level(MessageLevel::Info)
        .set_title("Apply to all?")
        .set_description("Apply this choice to all subsequent conflicts?")
        .set_buttons(MessageButtons::YesNo)
        .show();

    match (first, q2) {
        (OverwriteAction::Overwrite, MessageDialogResult::Yes) => OverwriteAction::OverwriteAll,
        (OverwriteAction::Overwrite, MessageDialogResult::No) => OverwriteAction::Overwrite,
        (OverwriteAction::Skip, MessageDialogResult::Yes) => OverwriteAction::SkipAll,
        (OverwriteAction::Skip, MessageDialogResult::No) => OverwriteAction::Skip,
        _ => OverwriteAction::Skip, // fallback
    }
}

/// Decide whether to overwrite, honoring Skip All / Overwrite All once chosen.
fn should_overwrite(dest: &Path) -> bool {
    // Fast-path: apply remembered policy
    {
        let pol = overwrite_policy().lock().unwrap();
        if pol.overwrite_all {
            return true;
        }
        if pol.skip_all {
            return false;
        }
    }

    // Ask user for this file
    match prompt_overwrite_native(dest) {
        OverwriteAction::Overwrite => true,
        OverwriteAction::Skip => false,
        OverwriteAction::OverwriteAll => {
            let mut pol = overwrite_policy().lock().unwrap();
            pol.overwrite_all = true;
            true
        }
        OverwriteAction::SkipAll => {
            let mut pol = overwrite_policy().lock().unwrap();
            pol.skip_all = true;
            false
        }
    }
}

/// Create a temp dir *inside* dest_dir so rename won't cross filesystems
fn tempdir_in(dest_dir: &Path) -> io::Result<tempfile::TempDir> {
    if !dest_dir.exists() {
        fs::create_dir_all(dest_dir)?;
    }
    tempfile::TempDir::new_in(dest_dir)
}

/// Download a single URL with overwrite policy, extension filter, and temp staging.
/// Returns Ok(Some(path)) if written, Ok(None) if skipped (filtered or overwrite-skip).
fn download_url_to_dir(
    url: &str,
    dest_dir: &Path,
    allowed_exts: &[&str],
) -> io::Result<Option<PathBuf>> {
    fs::create_dir_all(dest_dir)?;

    let file_name = url.split('/').last().unwrap_or("download.bin");
    if !ext_allowed(file_name, allowed_exts) && !allowed_exts.is_empty() {
        return Ok(None);
    }

    let final_path = dest_dir.join(file_name);

    if final_path.exists() {
        if !should_overwrite(&final_path) {
            return Ok(None);
        }
        let _ = fs::remove_file(&final_path);
    }

    let resp = reqwest::blocking::get(url)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("GET {}: {}", url, e)))?;

    if !resp.status().is_success() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("HTTP {} for {}", resp.status(), url),
        ));
    }

    let tmp_dir = tempdir_in(dest_dir)?;
    let tmp_path = tmp_dir.path().join(format!("{}.part", file_name));
    let text = resp.text().map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    fs::write(&tmp_path, text.as_bytes())?;
    fs::rename(&tmp_path, &final_path)?;

    Ok(Some(final_path))
}

/// Run common workflow for any rule set:
/// - clone/copy from `repos` (with optional per-repo timeout)
/// - download direct `pages` (filtered by `allowed_exts`)
/// - report progress via `progress_callback`
/// `allowed_exts` should be like ["yml","yaml"] or ["rules","rule"] (no dots).
pub fn process_sources(
    repos: &[&str],
    pages: &[&str],
    allowed_exts: &[&str],
    dest_dir: &std::path::Path,
    mut progress_callback: Option<&mut dyn FnMut(usize, usize, String)>,
    repo_timeout_secs: Option<u64>,
) {
    let total = repos.len() + pages.len();
    let mut cur = 0usize;

    // Normalize to no-dot forms (for repo file copying)
    let allowed_no_dot: Vec<String> = allowed_exts
        .iter()
        .map(|e| e.trim_start_matches('.').to_string())
        .collect();

    // 1) GitHub repos (copy only matching extensions)
    for repo_url in repos {
        if let Some(cb) = progress_callback.as_deref_mut() {
            cb(cur + 1, total, (*repo_url).to_string());
        }

        let repo = (*repo_url).to_string();
        let dest = dest_dir.to_path_buf();
        let exts_owned = allowed_no_dot.clone();

        let finished = if let Some(secs) = repo_timeout_secs {
            run_with_timeout(Duration::from_secs(secs), move || {
                let exts_as_str: Vec<&str> = exts_owned.iter().map(|s| s.as_str()).collect();
                if let Err(e) = clone_and_copy_filtered(&repo, &dest, &exts_as_str) {
                    eprintln!("❌ Repo {} failed: {}", repo, e);
                }
            })
        } else {
            let exts_as_str: Vec<&str> = exts_owned.iter().map(|s| s.as_str()).collect();
            if let Err(e) = clone_and_copy_filtered(&repo, &dest, &exts_as_str) {
                eprintln!("❌ Repo {} failed: {}", repo, e);
            }
            true
        };

        if !finished {
            eprintln!("⏱️ Timed out cloning/copying: {}", repo_url);
        }

        cur += 1;
    }

    // 2) Direct URLs: try each allowed extension (non-matching ones are skipped)
    for url in pages {
        if let Some(cb) = progress_callback.as_deref_mut() {
            cb(cur + 1, total, (*url).to_string());
        }

        let out = dest_dir.to_path_buf();
        for ext in &allowed_no_dot {
            let dotted = format!(".{}", ext);
            download_files_with_progress(&[*url], &out, "direct", Some(&dotted));
        }

        cur += 1;
    }
}

/// Tiny utility to run a job with a timeout; returns true if completed in time.
fn run_with_timeout<F>(timeout: Duration, f: F) -> bool
where
    F: FnOnce() + Send + 'static,
{
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        f();
        let _ = tx.send(());
    });
    rx.recv_timeout(timeout).is_ok()
}