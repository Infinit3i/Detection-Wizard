use crate::download::{ToolSpec, process_tool};
use eframe::egui::Context;
use std::path::Path;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};

pub fn sentinel_total_sources() -> usize {
    SENTINEL_REPOS.len() + SENTINEL_PAGES.len()
}

pub fn sentinel_spec() -> ToolSpec {
    ToolSpec {
        name: "Sentinel",
        dest_subfolder: "sentinel",
        repo_urls: &SENTINEL_REPOS,
        page_urls: &SENTINEL_PAGES,
        allowed_exts: &["yaml", "yml", "kql"],
    }
}

pub fn process_sentinel(
    output_root: &str,
    progress_triplet: Arc<Mutex<Option<(usize, usize, String)>>>,
    ctx: Context,
    cancel_flag: Arc<AtomicBool>,
    filter: Arc<crate::filter::CompiledFilter>,
) {
    let _ = process_tool(
        &sentinel_spec(),
        Path::new(output_root),
        progress_triplet,
        ctx,
        cancel_flag,
        filter,
    );
}

static SENTINEL_REPOS: &[&str] = &[
    "https://github.com/Azure/Azure-Sentinel.git",
    "https://github.com/SlimKQL/Hunting-Queries-Detection-Rules.git",
];
static SENTINEL_PAGES: [&str; 0] = [];
