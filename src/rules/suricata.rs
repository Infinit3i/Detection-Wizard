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

static SURICATA_REPOS: [&str; 9] = [
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

static SURICATA_PAGES: [&str; 29] = [
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
