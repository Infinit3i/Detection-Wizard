pub fn yara_total_sources() -> usize {
    YARA_REPOS.len()
}

pub fn process_yara(
    output_path: &str,
    mut progress_callback: Option<&mut dyn FnMut(usize, usize, String)>,
) {
    use std::path::Path;
    let total = YARA_REPOS.len();
    let dest = Path::new(output_path);

    for (i, repo_url) in YARA_REPOS.iter().enumerate() {
        if let Some(cb) = progress_callback.as_mut() {
            cb(i + 1, total, (*repo_url).to_string());
        }
        let _ = crate::download::download_and_extract_git_repo(repo_url, dest, Some(".yar"));
        let _ = crate::download::download_and_extract_git_repo(repo_url, dest, Some(".yara"));
    }
}

static YARA_REPOS: [&str; 69] = [
    "https://github.com/advanced-threat-research/Yara-Rules.git",
    "https://github.com/avast/ioc.git",
    "https://github.com/chronicle/GCTI.git",
    "https://github.com/deadbits/yara-rules.git",
    "https://github.com/delivr-to/detections.git",
    "https://github.com/dr4k0nia/yara-rules.git",
    "https://github.com/elastic/protections-artifacts.git",
    "https://github.com/elceef/yara-rulz.git",
    "https://github.com/embee-research/Yara-detection-rules.git",
    "https://github.com/eset/malware-ioc.git",
    "https://github.com/fboldewin/YARA-rules.git",
    "https://github.com/JPCERTCC/MalConfScan.git",
    "https://github.com/kevoreilly/CAPEv2.git",
    "https://github.com/mthcht/ThreatHunting-Keywords-yara-rules.git",
    "https://github.com/Neo23x0/god-mode-rules.git",
    "https://github.com/pmelson/yara_rules.git",
    "https://github.com/reversinglabs/reversinglabs-yara-rules.git",
    "https://github.com/RussianPanda95/Yara-Rules.git",
    "https://github.com/sbousseaden/YaraHunts.git",
    "https://github.com/SIFalcon/Detection.git",
    "https://github.com/stairwell-inc/threat-research.git",
    "https://github.com/StrangerealIntel/DailyIOC.git",
    "https://github.com/telekom-security/malware_analysis.git",
    "https://github.com/volexity/threat-intel.git",
    "https://github.com/Yara-Rules/rules.git",
    "https://github.com/roadwy/DefenderYara.git",
    "https://github.com/SupportIntelligence/Icewater.git",
    "https://github.com/InQuest/yara-rules.git",
    "https://github.com/Neo23x0/signature-base.git",
    "https://github.com/AlienVault-Labs/AlienVaultLabs.git",
    "https://github.com/anyrun/YARA.git",
    "https://github.com/bartblaze/Yara-rules.git",
    "https://github.com/airbnb/binaryalert.git",
    "https://github.com/codewatchorg/Burp-Yara-Rules.git",
    "https://github.com/CyberDefenses/CDI_yara.git",
    "https://github.com/citizenlab/malware-signatures.git",
    "https://github.com/stvemillertime/ConventionEngine.git",
    "https://github.com/ditekshen/detection.git",
    "https://github.com/filescanio/fsYara.git",
    "https://github.com/mandiant/red_team_tool_countermeasures.git",
    "https://github.com/f0wl/yara_rules.git",
    "https://github.com/EmersonElectricCo/fsf.git",
    "https://github.com/godaddy/yara-rules.git",
    "https://github.com/mikesxrs/Open-Source-YARA-rules.git",
    "https://github.com/jipegit/yara-rules-public.git",
    "https://github.com/tylabs/qs_old.git",
    "https://github.com/rapid7/Rapid7-Labs.git",
    "https://github.com/h3x2b/yara-rules.git",
    "https://github.com/imp0rtp3/yara-rules.git",
    "https://github.com/intezer/yara-rules.git",
    "https://github.com/jeFF0Falltrades/YARA-Signatures.git",
    "https://github.com/kevthehermit/YaraRules.git",
    "https://github.com/Hestat/lw-yara.git",
    "https://github.com/nccgroup/Cyber-Defence.git",
    "https://github.com/MalGamy/YARA_Rules.git",
    "https://github.com/malice-plugins/yara.git",
    "https://github.com/malpedia/signator-rules.git",
    "https://github.com/advanced-threat-research/IOCs.git",
    "https://github.com/securitymagic/yara.git",
    "https://github.com/sophos/yaraml_rules.git",
    "https://github.com/SpiderLabs/malware-analysis.git",
    "https://github.com/t4d/PhishingKit-Yara-Rules.git",
    "https://github.com/tenable/yara-rules.git",
    "https://github.com/mthcht/ThreatHunting-Keywords-yara-rules.git",
    "https://github.com/tjnel/yara_repo.git",
    "https://github.com/VectraThreatLab/reyara.git",
    "https://github.com/x64dbg/yarasigs.git",
    "https://github.com/fr0gger/Yara-Unprotect.git",
    "https://github.com/chronicle/detection-rules.git",
];
