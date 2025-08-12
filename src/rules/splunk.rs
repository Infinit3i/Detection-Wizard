use crate::download::{process_tool, ToolSpec};
use eframe::egui::Context;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::sync::atomic::AtomicBool;

pub fn splunk_total_sources() -> usize {
    SPLUNK_REPOS.len() + SPLUNK_PAGES.len()
}

pub fn splunk_spec() -> ToolSpec {
    ToolSpec {
        name: "Splunk",
        dest_subfolder: "splunk",
        repo_urls: &SPLUNK_REPOS,
        page_urls: &SPLUNK_PAGES,
        allowed_exts: &["conf", "xml", "txt", "md"],
    }
}

pub fn process_splunk(
    output_root: &str,
    progress_triplet: Arc<Mutex<Option<(usize, usize, String)>>>,
    ctx: Context,
    cancel_flag: Arc<AtomicBool>,
) {
    let _ = process_tool(
        &splunk_spec(),
        Path::new(output_root),
        progress_triplet,
        ctx,
        cancel_flag,
    );
}

static SPLUNK_REPOS: &[&str] = &[
    "https://github.com/Infinit3i/Defensive-Rules.git",
    "https://github.com/mthcht/ThreatHunting-Keywords.git",
    "https://github.com/splunk/security_content.git",
    "https://github.com/anvilogic-forge/armory.git",
];
static SPLUNK_PAGES: [&str; 0] = [];
