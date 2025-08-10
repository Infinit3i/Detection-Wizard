use std::path::PathBuf;
use crate::download::download_files_with_progress;

static SYSMON_URLS: &[&str] = &[
    "https://raw.githubusercontent.com/Neo23x0/sysmon-config/refs/heads/master/sysmonconfig-trace.xml",
    "https://raw.githubusercontent.com/ion-storm/sysmon-config/refs/heads/master/sysmonconfig-export.xml",
    "https://raw.githubusercontent.com/MotiBa/Sysmon/refs/heads/master/config_v17.xml",
    "https://raw.githubusercontent.com/olafhartong/sysmon-modular/refs/heads/master/sysmonconfig.xml",
    "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/refs/heads/master/sysmonconfig-export.xml",
];

pub fn process_sysmon_files(output_path: &str) {
    let dest = PathBuf::from(output_path).join("sysmon");
    download_files_with_progress(SYSMON_URLS, &dest, "sysmon", Some(".xml"));
}
