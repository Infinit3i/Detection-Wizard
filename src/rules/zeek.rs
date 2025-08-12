use crate::download::{process_tool, ToolSpec};
use eframe::egui::Context;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::sync::atomic::AtomicBool;

pub fn sigma_total_sources() -> usize {
    ZEEK_REPOS.len() + ZEEK_PAGES.len()
}

pub fn sigma_spec() -> ToolSpec {
    ToolSpec {
        name: "Sigma",
        dest_subfolder: "sigma",
        repo_urls: &ZEEK_REPOS,
        page_urls: &ZEEK_PAGES,
        allowed_exts: &["yml", "yaml"],
    }
}

pub fn process_sigma(
    output_root: &str,
    progress_triplet: Arc<Mutex<Option<(usize, usize, String)>>>,
    ctx: Context,
    cancel_flag: Arc<AtomicBool>,
) {
    let _ = process_tool(
        &sigma_spec(),
        Path::new(output_root),
        progress_triplet,
        ctx,
        cancel_flag,
    );
}

static ZEEK_REPOS: &[&str] = &[
    "https://github.com/zeek/zeek.git",
];

static ZEEK_PAGES: &[&str] = &[
    "",
];
