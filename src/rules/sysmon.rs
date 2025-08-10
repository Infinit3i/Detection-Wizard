use crate::download::{process_tool, ToolSpec};
use eframe::egui::Context;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::sync::atomic::AtomicBool;

pub fn sysmon_total_sources() -> usize {
    SYSMON_REPOS.len() + SYSMON_PAGES.len()
}

pub fn sysmon_spec() -> ToolSpec {
    ToolSpec {
        name: "Sysmon",
        dest_subfolder: "sysmon",
        repo_urls: &SYSMON_REPOS,  // keep [] if you don’t have repos
        page_urls: &SYSMON_PAGES,  // direct XMLs if you have them
        allowed_exts: &["xml"],
    }
}

pub fn process_sysmon(
    output_root: &str,
    progress_triplet: Arc<Mutex<Option<(usize, usize, String)>>>,
    ctx: Context,
    cancel_flag: Arc<AtomicBool>,
) {
    let _ = process_tool(
        &sysmon_spec(),
        Path::new(output_root),
        progress_triplet,
        ctx,
        cancel_flag,
    );
}

static SYSMON_REPOS: [&str; 0] = [];

static SYSMON_PAGES: &[&str] = &[
    "https://raw.githubusercontent.com/Neo23x0/sysmon-config/refs/heads/master/sysmonconfig-trace.xml",
    "https://raw.githubusercontent.com/ion-storm/sysmon-config/refs/heads/master/sysmonconfig-export.xml",
    "https://raw.githubusercontent.com/MotiBa/Sysmon/refs/heads/master/config_v17.xml",
    "https://raw.githubusercontent.com/olafhartong/sysmon-modular/refs/heads/master/sysmonconfig.xml",
    "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/refs/heads/master/sysmonconfig-export.xml",
];
