use crate::download::{process_tool, ToolSpec};
use eframe::egui::Context;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::sync::atomic::AtomicBool;

pub fn sigma_total_sources() -> usize {
    SIGMA_REPOS.len() + SIGMA_PAGES.len()
}

pub fn sigma_spec() -> ToolSpec {
    ToolSpec {
        name: "Sigma",
        dest_subfolder: "sigma",
        repo_urls: &SIGMA_REPOS,
        page_urls: &SIGMA_PAGES,
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

static SIGMA_REPOS: &[&str] = &[
    "https://github.com/SigmaHQ/sigma.git",
    "https://github.com/center-for-threat-informed-defense/cloud-analytics.git",
    "https://github.com/joesecurity/sigma-rules.git",
    "https://github.com/magicsword-io/LOLDrivers.git",
    "https://github.com/mbabinski/Sigma-Rules.git",
    "https://github.com/mdecrevoisier/SIGMA-detection-rules.git",
    "https://github.com/mthcht/ThreatHunting-Keywords-sigma-rules.git",
    "https://github.com/P4T12ICK/Sigma-Rule-Repository.git",
    "https://github.com/tsale/Sigma_rules.git",
];

static SIGMA_PAGES: &[&str] = &[
    "https://raw.githubusercontent.com/delivr-to/detections/refs/heads/main/sigma-rules/file_event_win_pdf_html_smuggle.yml",
];
