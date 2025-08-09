use crate::download::{download_and_extract_git_repo, download_files_with_progress};
use std::fs;
use std::path::PathBuf;

pub fn suricata_web_sources() -> Vec<&'static str> {
    vec![
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
    ]
}

pub fn suricata_github_repos() -> Vec<&'static str> {
    vec![
        "https://github.com/ptresearch/AttackDetection.git",
        "https://github.com/beave/sagan-rules.git",
        "https://github.com/klingerko/nids-rule-library.git",
        "https://github.com/quadrantsec/suricata-rules.git",
        "https://github.com/Cluster25/detection.git",
        "https://github.com/fox-it/quantuminsert.git",
        "https://github.com/travisbgreen/hunting-rules.git",
        "https://github.com/aleksibovellan/opnsense-suricata-nmaps.git",
        "https://github.com/julioliraup/Antiphishing.git",
    ]
}

pub fn process_suricata_rules(
    _input_paths: Vec<PathBuf>,
    output_path: PathBuf,
    mut progress_callback: Option<&mut dyn FnMut(usize, usize, String)>,
) {
    let output_path = output_path.join("suricata");
    let github_repos = suricata_github_repos();
    let webpage_sources = suricata_web_sources();
    if let Err(e) = fs::create_dir_all(&output_path) {
        eprintln!(
            "Failed to create /suricata directory inside output path: {}",
            e
        );
        return;
    }

    let total = github_repos.len() + webpage_sources.len();

    for (i, repo_url) in github_repos.iter().enumerate() {
        if let Some(cb) = progress_callback.as_mut() {
            cb(i + 1, total, repo_url.to_string());
        }
        if let Err(e) = download_and_extract_git_repo(repo_url, &output_path, Some(".rules")) {
            eprintln!("❌ Failed to process {}: {}", repo_url, e);
        }
    }

    for (j, url) in webpage_sources.iter().enumerate() {
        let index = github_repos.len() + j;
        if let Some(cb) = progress_callback.as_mut() {
            cb(index + 1, total, url.to_string());
        }
        download_files_with_progress(&[*url], &output_path, "Suricata", Some(".rules"));
    }
}

pub fn suricata_total_sources() -> usize {
    suricata_github_repos().len()
        + suricata_web_sources()
            .iter()
            .filter(|s| !s.is_empty())
            .count()
}
