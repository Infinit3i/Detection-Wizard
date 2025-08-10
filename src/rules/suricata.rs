use crate::download::{download_and_extract_git_repo, download_files_with_progress};
use std::path::Path;

pub fn suricata_total_sources() -> usize {
    GITHUB_REPOS.len()
        + WEB_SOURCES.iter().filter(|s| !s.is_empty()).count()
}

pub fn process_suricata(
    output_path: &str,
    mut progress_callback: Option<&mut dyn FnMut(usize, usize, String)>,
) {
    let dest_dir = Path::new(output_path);
    let total = GITHUB_REPOS.len() + WEB_SOURCES.len();

    // GitHub repos (.rules)
    for (i, repo_url) in GITHUB_REPOS.iter().enumerate() {
        if let Some(cb) = progress_callback.as_mut() {
            cb(i + 1, total, (*repo_url).to_string());
        }
        if let Err(e) = download_and_extract_git_repo(repo_url, dest_dir, Some(".rules")) {
            eprintln!("❌ Failed to process repo {}: {}", repo_url, e);
        }
    }

    // Direct web sources (.rules)
    for (j, url) in WEB_SOURCES.iter().enumerate() {
        let idx = GITHUB_REPOS.len() + j;
        if let Some(cb) = progress_callback.as_mut() {
            cb(idx + 1, total, (*url).to_string());
        }
        let out = dest_dir.to_path_buf();
        download_files_with_progress(&[*url], &out, "Suricata", Some(".rules"));
    }
}

pub fn process_suricata_rules(
    _input_paths: Vec<std::path::PathBuf>,
    output_path: std::path::PathBuf,
    progress_callback: Option<&mut dyn FnMut(usize, usize, String)>,
) {
    if let Some(path_str) = output_path.to_str() {
        process_suricata(path_str, progress_callback);
    } else {
        eprintln!("Invalid output_path for Suricata");
    }
}


static WEB_SOURCES: [&str; 29] = [
    "https://ti.stamus-networks.io/open/stamus-lateral-rules.tar.gz",
    "https://rules.pawpatrules.fr/suricata/paw-patrules.tar.gz",
    "https://raw.githubusercontent.com/quadrantsec/suricata-rules/refs/heads/main/quadrant-suricata.rules",
    "https://raw.githubusercontent.com/Cluster25/detection/refs/heads/main/suricata/jester_stealer.rules",
    "https://raw.githubusercontent.com/travisbgreen/hunting-rules/refs/heads/master/hunting.rules",
    "https://raw.githubusercontent.com/travisbgreen/hunting-rules/refs/heads/master/most_abused_tld.rules",
    "https://raw.githubusercontent.com/travisbgreen/hunting-rules/refs/heads/master/pii.rules",
    "https://raw.githubusercontent.com/aleksibovellan/opnsense-suricata-nmaps/refs/heads/main/local.rules",
    "https://raw.githubusercontent.com/julioliraup/Antiphishing/refs/heads/main/antiphishing.rules",
    "https://sslbl.abuse.ch/blacklist/sslblacklist_tls_cert.rules",
    "https://sslbl.abuse.ch/blacklist/ja3_fingerprints.rules",
    "https://sslbl.abuse.ch/blacklist/sslipblacklist.rules",
    "https://urlhaus.abuse.ch/downloads/ids",
    "https://security.etnetera.cz/feeds/etn_aggressive.rules",
    "https://raw.githubusercontent.com/travisbgreen/hunting-rules/master/hunting.rules",
    "https://rules.emergingthreats.net/open/suricata/rules/",
    "https://openinfosecfoundation.org/rules/trafficid/trafficid.rules",
    "https://rules.emergingthreats.net/blockrules/emerging-compromised.rules",
    "https://rules.emergingthreats.net/blockrules/emerging-dshield.suricata.rules",
    "https://rules.emergingthreats.net/blockrules/emerging-ciarmy.suricata.rules",
    "https://rules.emergingthreats.net/blockrules/emerging-drop.suricata.rules",
    "https://feodotracker.abuse.ch/downloads/feodotracker_aggressive.rules",
    "https://rules.emergingthreats.net/blockrules/threatview_CS_c2.suricata.rules",
    "https://rules.emergingthreats.net/blockrules/emerging-tor.suricata.rules",
    "https://sslbl.abuse.ch/blacklist/sslblacklist.rules",
    "https://urlhaus.abuse.ch/downloads/ids/",
    "https://networkforensic.dk/SNORT/NF-local.zip",
    "https://networkforensic.dk/SNORT/NF-SCADA.zip",
    "https://networkforensic.dk/SNORT/NF-Scanners.zip",
];

static GITHUB_REPOS: [&str; 9] = [
    "https://github.com/ptresearch/AttackDetection.git",
    "https://github.com/beave/sagan-rules.git",
    "https://github.com/klingerko/nids-rule-library.git",
    "https://github.com/quadrantsec/suricata-rules.git",
    "https://github.com/Cluster25/detection.git",
    "https://github.com/fox-it/quantuminsert.git",
    "https://github.com/travisbgreen/hunting-rules.git",
    "https://github.com/aleksibovellan/opnsense-suricata-nmaps.git",
    "https://github.com/julioliraup/Antiphishing.git",
];
