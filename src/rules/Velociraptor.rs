use crate::download::{process_tool, ToolSpec};
use eframe::egui::Context;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::sync::atomic::AtomicBool;

pub fn suricata_total_sources() -> usize {
    SURICATA_REPOS.len() + SURICATA_PAGES.len()
}

pub fn suricata_spec() -> ToolSpec {
    ToolSpec {
        name: "Suricata",
        dest_subfolder: "suricata",
        repo_urls: &SURICATA_REPOS,
        page_urls: &SURICATA_PAGES,    // only direct .rules/.rule if you have them
        allowed_exts: &["rules", "rule"],
    }
}

pub fn process_suricata(
    output_root: &str,
    progress_triplet: Arc<Mutex<Option<(usize, usize, String)>>>,
    ctx: Context,
    cancel_flag: Arc<AtomicBool>,
) {
    let _ = process_tool(
        &suricata_spec(),
        Path::new(output_root),
        progress_triplet,
        ctx,
        cancel_flag,
    );
}

static SURICATA_REPOS: &[&str] = &[
    "https://github.com/mgreen27/DetectRaptor.git",
    "",
];

static SURICATA_PAGES: &[&str] = &[
    "",
];
