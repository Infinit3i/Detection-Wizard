use std::path::{Path, PathBuf};

// Reuse the shared helpers from download.rs
use crate::download::{download_and_extract_git_repo, download_files_with_progress};

static SIGMA_GITHUB: &[&str] = &[
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

/// Count used by the UI to estimate work.
pub fn sigma_total_sources() -> usize {
    SIGMA_GITHUB.len() + SIGMA_PAGES.len()
}

pub fn process_sigma(
    output_path: &str,
    mut progress: Option<&mut dyn FnMut(usize, usize)>,
) {
    // Use the UI-provided folder, just like YARA
    let dest = Path::new(output_path);
    let dest_buf = PathBuf::from(output_path);

    let total = sigma_total_sources();
    let mut cur = 0usize;

    // 1) GitHub repos (copy only .yml/.yaml)
    for repo in SIGMA_GITHUB {
        let _ = download_and_extract_git_repo(repo, dest, Some(".yml"));
        let _ = download_and_extract_git_repo(repo, dest, Some(".yaml"));
        cur += 1;
        if let Some(cb) = progress.as_deref_mut() {
            cb(cur, total);
        }
    }

    // 2) Direct URLs (“wget”) — use the shared downloader; filter .yml/.yaml
    for url in SIGMA_PAGES {
        // Call once for each ext to keep the filters simple and explicit
        download_files_with_progress(&[*url], &dest_buf, "Sigma", Some(".yml"));
        download_files_with_progress(&[*url], &dest_buf, "Sigma", Some(".yaml"));
        cur += 1;
        if let Some(cb) = progress.as_deref_mut() {
            cb(cur, total);
        }
    }
}
