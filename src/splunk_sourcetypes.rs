//! Granular Splunk sourcetype catalog.
//!
//! Individually selectable sourcetypes commonly seen in Splunk detections
//! (SPL `sourcetype=...`). Selecting any sourcetype activates sourcetype
//! targeting: Splunk rules must reference a selected sourcetype (or match
//! another active dimension). Names follow Splunk add-on conventions
//! (Splunk TA docs / CIM add-on inputs).

pub struct SourcetypeDef {
    /// Exact sourcetype string as it appears in SPL (matched
    /// case-insensitively, boundary-aware, in rule content).
    pub name: &'static str,
    pub category: &'static str,
}

const fn s(name: &'static str, category: &'static str) -> SourcetypeDef {
    SourcetypeDef { name, category }
}

pub static SPLUNK_SOURCETYPES: &[SourcetypeDef] = &[
    // ---- Windows ----
    s("WinEventLog:Security", "Windows"),
    s("WinEventLog:System", "Windows"),
    s("WinEventLog:Application", "Windows"),
    s("XmlWinEventLog:Security", "Windows"),
    s(
        "WinEventLog:Microsoft-Windows-Sysmon/Operational",
        "Windows",
    ),
    s(
        "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
        "Windows",
    ),
    s(
        "WinEventLog:Microsoft-Windows-PowerShell/Operational",
        "Windows",
    ),
    s(
        "XmlWinEventLog:Microsoft-Windows-PowerShell/Operational",
        "Windows",
    ),
    s("WinEventLog:Windows PowerShell", "Windows"),
    s(
        "WinEventLog:Microsoft-Windows-TaskScheduler/Operational",
        "Windows",
    ),
    s(
        "WinEventLog:Microsoft-Windows-WMI-Activity/Operational",
        "Windows",
    ),
    s(
        "WinEventLog:Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
        "Windows",
    ),
    s(
        "WinEventLog:Microsoft-Windows-Windows Defender/Operational",
        "Windows",
    ),
    s("WinEventLog:DNS Server", "Windows"),
    s("MSAD:NT6:DNS", "Windows"),
    s("WinRegistry", "Windows"),
    s("fs_notification", "Windows"),
    // ---- Endpoint / EDR ----
    s("crowdstrike:events:sensor", "Endpoint / EDR"),
    s("CrowdStrike:Event:Streams:JSON", "Endpoint / EDR"),
    s("carbonblack:json", "Endpoint / EDR"),
    s("bit9:carbonblack:json", "Endpoint / EDR"),
    s("sentinelone:api", "Endpoint / EDR"),
    s("ms:defender:atp:alerts", "Endpoint / EDR"),
    s("symantec:ep:security:file", "Endpoint / EDR"),
    s("osquery:results", "Endpoint / EDR"),
    s("osquery_results", "Endpoint / EDR"),
    // ---- Linux / Unix ----
    s("linux_secure", "Linux / Unix"),
    s("linux_audit", "Linux / Unix"),
    s("syslog", "Linux / Unix"),
    s("auditd", "Linux / Unix"),
    s("bash_history", "Linux / Unix"),
    s("cron", "Linux / Unix"),
    s("aix_audit", "Linux / Unix"),
    // ---- Network: firewalls ----
    s("pan:traffic", "Network: firewall"),
    s("pan:threat", "Network: firewall"),
    s("pan:system", "Network: firewall"),
    s("pan_log", "Network: firewall"),
    s("cisco:asa", "Network: firewall"),
    s("cisco:fwsm", "Network: firewall"),
    s("cisco:pix", "Network: firewall"),
    s("cisco:ftd", "Network: firewall"),
    s("fortigate_traffic", "Network: firewall"),
    s("fortigate_utm", "Network: firewall"),
    s("fortinet:fortigate", "Network: firewall"),
    s("checkpoint:firewall", "Network: firewall"),
    s("opnsense:filterlog", "Network: firewall"),
    s("pfsense:filterlog", "Network: firewall"),
    s("juniper:junos:firewall", "Network: firewall"),
    // ---- Network: IDS / NSM ----
    s("suricata", "Network: IDS / NSM"),
    s("suricata:eve", "Network: IDS / NSM"),
    s("snort", "Network: IDS / NSM"),
    s("bro:conn:json", "Network: IDS / NSM"),
    s("bro:dns:json", "Network: IDS / NSM"),
    s("bro:http:json", "Network: IDS / NSM"),
    s("bro:ssl:json", "Network: IDS / NSM"),
    s("bro:files:json", "Network: IDS / NSM"),
    s("bro:notice:json", "Network: IDS / NSM"),
    s("zeek:conn:json", "Network: IDS / NSM"),
    s("zeek:dns:json", "Network: IDS / NSM"),
    s("zeek:http:json", "Network: IDS / NSM"),
    s("corelight_conn", "Network: IDS / NSM"),
    // ---- Network: flow / infra ----
    s("netflow", "Network: flow / infra"),
    s("stream:tcp", "Network: flow / infra"),
    s("stream:dns", "Network: flow / infra"),
    s("stream:http", "Network: flow / infra"),
    s("cisco:ios", "Network: flow / infra"),
    s("cisco:meraki", "Network: flow / infra"),
    s("infoblox:dns", "Network: flow / infra"),
    s("isc:bind:query", "Network: flow / infra"),
    // ---- Web / proxy ----
    s("access_combined", "Web / proxy"),
    s("access_combined_wcookie", "Web / proxy"),
    s("apache:access", "Web / proxy"),
    s("nginx:plus:access", "Web / proxy"),
    s("ms:iis:auto", "Web / proxy"),
    s("iis", "Web / proxy"),
    s("zscalernss-web", "Web / proxy"),
    s("zscaler:nss:web", "Web / proxy"),
    s("bluecoat:proxysg:access:syslog", "Web / proxy"),
    s("squid:access", "Web / proxy"),
    s("websense:cg:kv", "Web / proxy"),
    s("cisco:wsa:squid", "Web / proxy"),
    // ---- Cloud: AWS ----
    s("aws:cloudtrail", "Cloud: AWS"),
    s("aws:cloudwatchlogs", "Cloud: AWS"),
    s("aws:cloudwatchlogs:vpcflow", "Cloud: AWS"),
    s("aws:s3:accesslogs", "Cloud: AWS"),
    s("aws:elb:accesslogs", "Cloud: AWS"),
    s("aws:guardduty", "Cloud: AWS"),
    s("aws:config", "Cloud: AWS"),
    s("aws:securityhub", "Cloud: AWS"),
    // ---- Cloud: Azure / M365 ----
    s("azure:monitor:aad", "Cloud: Azure / M365"),
    s("azure:monitor:activity", "Cloud: Azure / M365"),
    s("azure:aad:signin", "Cloud: Azure / M365"),
    s("azure:aad:audit", "Cloud: Azure / M365"),
    s("mscs:azure:eventhub", "Cloud: Azure / M365"),
    s("o365:management:activity", "Cloud: Azure / M365"),
    s("o365:reporting:messagetrace", "Cloud: Azure / M365"),
    s("ms:o365:reporting:messagetrace", "Cloud: Azure / M365"),
    s("ms:aad:signin", "Cloud: Azure / M365"),
    s("ms:aad:audit", "Cloud: Azure / M365"),
    // ---- Cloud: GCP ----
    s("google:gcp:pubsub:message", "Cloud: GCP"),
    s("google:gcp:pubsub:audit", "Cloud: GCP"),
    s("gws:reports:admin", "Cloud: GCP"),
    s("gws:reports:login", "Cloud: GCP"),
    // ---- Identity / auth ----
    s("OktaIM2:log", "Identity / auth"),
    s("okta:im2:log", "Identity / auth"),
    s("okta", "Identity / auth"),
    s("duo:administrator", "Identity / auth"),
    s("duo:authentication", "Identity / auth"),
    s("cisco:duo:activity", "Identity / auth"),
    s("radius", "Identity / auth"),
    s("linux_secure", "Identity / auth"),
    // ---- Email security ----
    s("cisco:esa:textmail", "Email security"),
    s("proofpoint:tap:clicksPermitted", "Email security"),
    s("proofpoint:tap:messagesDelivered", "Email security"),
    s("mimecast:email", "Email security"),
    s("ms:o365:reporting", "Email security"),
    // ---- Vulnerability / scanning ----
    s("tenable:sc:vuln", "Vulnerability"),
    s("nessus:scan", "Vulnerability"),
    s("qualys:vm:detection", "Vulnerability"),
    // ---- Databases / apps ----
    s("mssql:audit", "Databases / apps"),
    s("mysql:audit", "Databases / apps"),
    s("postgresql", "Databases / apps"),
    s("vmware:vclog", "Databases / apps"),
    s("vmware:esxlog", "Databases / apps"),
    // ---- Splunk internal ----
    s("splunkd", "Splunk internal"),
    s("splunk_audit", "Splunk internal"),
    s("audittrail", "Splunk internal"),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_duplicate_name_category_pairs() {
        let mut pairs: Vec<(&str, &str)> = SPLUNK_SOURCETYPES
            .iter()
            .map(|d| (d.name, d.category))
            .collect();
        let before = pairs.len();
        pairs.sort();
        pairs.dedup();
        assert_eq!(before, pairs.len(), "duplicate sourcetype entries");
    }
}
