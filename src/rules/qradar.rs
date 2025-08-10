use crate::download::{process_tool, ToolSpec};
use eframe::egui::Context;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::sync::atomic::AtomicBool;

pub fn qradar_total_sources() -> usize {
    QRADAR_REPOS.len() + QRADAR_PAGES.len()
}

pub fn qradar_spec() -> ToolSpec {
    ToolSpec {
        name: "QRadar",
        dest_subfolder: "qradar",
        repo_urls: &QRADAR_REPOS,
        page_urls: &QRADAR_PAGES,
        allowed_exts: &["xml", "json", "aql", "txt"],
    }
}

pub fn process_qradar(
    output_root: &str,
    progress_triplet: Arc<Mutex<Option<(usize, usize, String)>>>,
    ctx: Context,
    cancel_flag: Arc<AtomicBool>,
) {
    let _ = process_tool(
        &qradar_spec(),
        Path::new(output_root),
        progress_triplet,
        ctx,
        cancel_flag,
    );
}

static QRADAR_REPOS: [&str; 1] = [
    "https://github.com/Xboarder56/QRCE-Rules.git",
];

static QRADAR_PAGES: [&str; 0] = [];
