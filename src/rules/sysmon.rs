use crate::download::download_files_with_progress;
use std::fs;
use std::path::PathBuf;

static SYSMON_REPOS: [&str; 5] = [
    "https://raw.githubusercontent.com/Neo23x0/sysmon-config/refs/heads/master/sysmonconfig-trace.xml",
    "https://raw.githubusercontent.com/ion-storm/sysmon-config/refs/heads/master/sysmonconfig-export.xml",
    "https://raw.githubusercontent.com/MotiBa/Sysmon/refs/heads/master/config_v17.xml",
    "https://raw.githubusercontent.com/olafhartong/sysmon-modular/refs/heads/master/sysmonconfig.xml",
    "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/refs/heads/master/sysmonconfig-export.xml",
];

pub fn sysmon_total_sources() -> usize {
    SYSMON_REPOS.len()
}

/// DRY: call the shared downloader once per URL so we can tick progress.
/// `on_progress(cur, total, file)` will be called after each file finishes.
pub fn process_sysmon(
    out_dir: &str,
    mut on_progress: Option<&mut dyn FnMut(usize, usize, String)>,
) {
    let dest = PathBuf::from(out_dir);
    let _ = fs::create_dir_all(&dest);

    let total = SYSMON_REPOS.len();
    for (i, url) in SYSMON_REPOS.iter().enumerate() {
        // Reuse the shared function; filter for .xml (optional but explicit)
        download_files_with_progress(&[*url], &dest, "Sysmon", Some(".xml"));

        if let Some(cb) = on_progress.as_deref_mut() {
            cb(i + 1, total, (*url).to_string());
        }
    }
}