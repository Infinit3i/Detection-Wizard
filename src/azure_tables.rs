//! Granular Azure / M365 / Defender log table catalog.
//!
//! Every security-relevant Log Analytics / Sentinel / Defender Advanced
//! Hunting table, selectable individually. Selecting any table activates
//! table-level targeting: text rules (Splunk/QRadar/KQL) must reference a
//! selected table name; Sigma azure/m365 rules must map to one via
//! `sigma_services`. Source: Azure Monitor table reference + Sentinel
//! data-source schema reference + Defender XDR advanced hunting schema.

pub struct AzureTableDef {
    /// Exact Log Analytics table name (matched case-insensitively,
    /// word-bounded, in rule content).
    pub name: &'static str,
    pub category: &'static str,
    /// sigma `logsource.service` values (product azure/m365) that map here
    pub sigma_services: &'static [&'static str],
}

pub static AZURE_TABLES: &[AzureTableDef] = &[
    // ---- Entra ID (Azure AD) ----
    t("SigninLogs", "Entra ID", &["signinlogs"]),
    t("AADNonInteractiveUserSignInLogs", "Entra ID", &["signinlogs"]),
    t("AADServicePrincipalSignInLogs", "Entra ID", &["signinlogs"]),
    t("AADManagedIdentitySignInLogs", "Entra ID", &["signinlogs"]),
    t("ADFSSignInLogs", "Entra ID", &["signinlogs"]),
    t("AuditLogs", "Entra ID", &["auditlogs"]),
    t("AADProvisioningLogs", "Entra ID", &["auditlogs"]),
    t("AADRiskyUsers", "Entra ID", &["riskdetection"]),
    t("AADUserRiskEvents", "Entra ID", &["riskdetection"]),
    t("AADRiskyServicePrincipals", "Entra ID", &["riskdetection"]),
    t("AADServicePrincipalRiskEvents", "Entra ID", &["riskdetection"]),
    t("AADGraphActivityLogs", "Entra ID", &[]),
    t("MicrosoftGraphActivityLogs", "Entra ID", &[]),
    t("AADB2CRequestLogs", "Entra ID", &[]),
    // ---- Entra Domain Services ----
    t("AADDomainServicesAccountLogon", "Entra Domain Services", &[]),
    t("AADDomainServicesAccountManagement", "Entra Domain Services", &[]),
    t("AADDomainServicesDirectoryServiceAccess", "Entra Domain Services", &[]),
    t("AADDomainServicesLogonLogoff", "Entra Domain Services", &[]),
    t("AADDomainServicesPolicyChange", "Entra Domain Services", &[]),
    t("AADDomainServicesPrivilegeUse", "Entra Domain Services", &[]),
    t("AADDomainServicesSystemSecurity", "Entra Domain Services", &[]),
    t("AADDomainServicesDNSAuditsGeneral", "Entra Domain Services", &[]),
    t("AADDomainServicesDNSAuditsDynamicUpdates", "Entra Domain Services", &[]),
    // ---- Azure platform / control plane ----
    t("AzureActivity", "Azure platform", &["activitylogs", "azureactivity"]),
    t("AzureDiagnostics", "Azure platform", &[]),
    t("AzureMetrics", "Azure platform", &[]),
    t("LAQueryLogs", "Azure platform", &[]),
    t("MicrosoftAzureBastionAuditLogs", "Azure platform", &[]),
    t("AZKVAuditLogs", "Azure platform", &["keyvault"]),
    t("AZKVPolicyEvaluationDetailsLogs", "Azure platform", &["keyvault"]),
    t("NSPAccessLogs", "Azure platform", &[]),
    t("DNSQueryLogs", "Azure platform", &[]),
    t("AzureNetworkAnalytics", "Azure platform", &[]),
    // ---- Sentinel core / collected hosts ----
    t("SecurityEvent", "Sentinel core", &[]),
    t("WindowsEvent", "Sentinel core", &[]),
    t("Event", "Sentinel core", &[]),
    t("SecurityAlert", "Sentinel core", &[]),
    t("SecurityIncident", "Sentinel core", &[]),
    t("Syslog", "Sentinel core", &[]),
    t("CommonSecurityLog", "Sentinel core", &[]),
    t("Heartbeat", "Sentinel core", &[]),
    t("DnsEvents", "Sentinel core", &[]),
    t("DnsAuditEvents", "Sentinel core", &[]),
    t("WindowsFirewall", "Sentinel core", &[]),
    t("W3CIISLog", "Sentinel core", &[]),
    t("VMConnection", "Sentinel core", &[]),
    t("WireData", "Sentinel core", &[]),
    t("ThreatIntelligenceIndicator", "Sentinel core", &[]),
    t("ThreatIntelIndicators", "Sentinel core", &[]),
    t("SentinelBehaviorInfo", "Sentinel core", &[]),
    t("SentinelBehaviorEntities", "Sentinel core", &[]),
    // ---- Microsoft 365 ----
    t("OfficeActivity", "Microsoft 365", &["exchange", "sharepoint", "onedrive", "teams", "audit", "threat_management"]),
    t("EmailEvents", "Microsoft 365", &["threat_management"]),
    t("EmailAttachmentInfo", "Microsoft 365", &["threat_management"]),
    t("EmailUrlInfo", "Microsoft 365", &["threat_management"]),
    t("EmailPostDeliveryEvents", "Microsoft 365", &["threat_management"]),
    t("UrlClickEvents", "Microsoft 365", &["threat_management"]),
    t("CloudAppEvents", "Microsoft 365", &[]),
    // ---- Defender XDR (Advanced Hunting) ----
    t("DeviceEvents", "Defender XDR", &[]),
    t("DeviceProcessEvents", "Defender XDR", &[]),
    t("DeviceNetworkEvents", "Defender XDR", &[]),
    t("DeviceFileEvents", "Defender XDR", &[]),
    t("DeviceRegistryEvents", "Defender XDR", &[]),
    t("DeviceLogonEvents", "Defender XDR", &[]),
    t("DeviceImageLoadEvents", "Defender XDR", &[]),
    t("DeviceInfo", "Defender XDR", &[]),
    t("DeviceNetworkInfo", "Defender XDR", &[]),
    t("DeviceFileCertificateInfo", "Defender XDR", &[]),
    t("AlertInfo", "Defender XDR", &[]),
    t("AlertEvidence", "Defender XDR", &[]),
    t("IdentityLogonEvents", "Defender XDR", &[]),
    t("IdentityQueryEvents", "Defender XDR", &[]),
    t("IdentityDirectoryEvents", "Defender XDR", &[]),
    // ---- Azure Firewall / WAF ----
    t("AZFWNetworkRule", "Azure Firewall / WAF", &[]),
    t("AZFWApplicationRule", "Azure Firewall / WAF", &[]),
    t("AZFWNatRule", "Azure Firewall / WAF", &[]),
    t("AZFWThreatIntel", "Azure Firewall / WAF", &[]),
    t("AZFWIdpsSignature", "Azure Firewall / WAF", &[]),
    t("AZFWDnsQuery", "Azure Firewall / WAF", &[]),
    t("AZFWFlowTrace", "Azure Firewall / WAF", &[]),
    t("AZFWFatFlow", "Azure Firewall / WAF", &[]),
    t("AGWAccessLogs", "Azure Firewall / WAF", &[]),
    t("AGWFirewallLogs", "Azure Firewall / WAF", &[]),
    t("AGCAccessLogs", "Azure Firewall / WAF", &[]),
    t("AGCFirewallLogs", "Azure Firewall / WAF", &[]),
    // ---- Storage ----
    t("StorageBlobLogs", "Storage", &[]),
    t("StorageFileLogs", "Storage", &[]),
    t("StorageQueueLogs", "Storage", &[]),
    t("StorageTableLogs", "Storage", &[]),
    t("StorageMalwareScanningResults", "Storage", &[]),
    // ---- Containers / Kubernetes ----
    t("AKSAudit", "Containers / AKS", &["kubernetes"]),
    t("AKSAuditAdmin", "Containers / AKS", &["kubernetes"]),
    t("AKSControlPlane", "Containers / AKS", &["kubernetes"]),
    t("KubeEvents", "Containers / AKS", &["kubernetes"]),
    t("KubePodInventory", "Containers / AKS", &["kubernetes"]),
    t("ContainerLog", "Containers / AKS", &[]),
    t("ContainerLogV2", "Containers / AKS", &[]),
    t("ContainerRegistryLoginEvents", "Containers / AKS", &[]),
    t("ContainerRegistryRepositoryEvents", "Containers / AKS", &[]),
    // ---- App Services / Functions ----
    t("AppServiceHTTPLogs", "App Services", &[]),
    t("AppServiceAuditLogs", "App Services", &[]),
    t("AppServiceConsoleLogs", "App Services", &[]),
    t("AppServiceAppLogs", "App Services", &[]),
    t("AppServiceAuthenticationLogs", "App Services", &[]),
    t("AppServiceFileAuditLogs", "App Services", &[]),
    t("AppServiceIPSecAuditLogs", "App Services", &[]),
    t("AppServiceAntivirusScanAuditLogs", "App Services", &[]),
    t("AppServicePlatformLogs", "App Services", &[]),
    t("FunctionAppLogs", "App Services", &[]),
    // ---- Databases ----
    t("SQLSecurityAuditEvents", "Databases", &[]),
    t("MySqlAuditLogs", "Databases", &[]),
    t("CassandraAudit", "Databases", &[]),
    t("ACREntraAuthenticationAuditLog", "Databases", &[]),
    // ---- Virtual Desktop / Windows 365 ----
    t("WVDConnections", "AVD / Windows 365", &[]),
    t("WVDErrors", "AVD / Windows 365", &[]),
    t("WVDManagement", "AVD / Windows 365", &[]),
    t("WVDCheckpoints", "AVD / Windows 365", &[]),
    t("WVDHostRegistrations", "AVD / Windows 365", &[]),
    t("WVDAgentHealthStatus", "AVD / Windows 365", &[]),
    t("Windows365AuditLogs", "AVD / Windows 365", &[]),
    t("Windows365ConnectionLogs", "AVD / Windows 365", &[]),
    t("Windows365NetworkLogs", "AVD / Windows 365", &[]),
    // ---- Power Platform / Dynamics ----
    t("PowerBIActivity", "Power Platform", &[]),
    t("PowerAppsActivity", "Power Platform", &[]),
    t("PowerAutomateActivity", "Power Platform", &[]),
    t("PowerPlatformAdminActivity", "Power Platform", &[]),
    t("PowerPlatformConnectorActivity", "Power Platform", &[]),
    t("PowerPlatformDlpActivity", "Power Platform", &[]),
    t("DynamicsActivity", "Power Platform", &[]),
    t("DataverseActivity", "Power Platform", &[]),
    t("ProjectActivity", "Power Platform", &[]),
    // ---- Purview / compliance ----
    t("PurviewScanStatusLogs", "Purview", &[]),
    t("PurviewDataSensitivityLogs", "Purview", &[]),
    t("PurviewSecurityLogs", "Purview", &[]),
    t("MicrosoftPurviewInformationProtection", "Purview", &[]),
    // ---- ASIM normalized ----
    t("ASimProcessEventLogs", "ASIM normalized", &[]),
    t("ASimNetworkSessionLogs", "ASIM normalized", &[]),
    t("ASimDnsActivityLogs", "ASIM normalized", &[]),
    t("ASimAuthenticationEventLogs", "ASIM normalized", &[]),
    t("ASimAuditEventLogs", "ASIM normalized", &[]),
    t("ASimFileEventLogs", "ASIM normalized", &[]),
    t("ASimRegistryEventLogs", "ASIM normalized", &[]),
    t("ASimUserManagementActivityLogs", "ASIM normalized", &[]),
    t("ASimWebSessionLogs", "ASIM normalized", &[]),
    t("ASimDhcpEventLogs", "ASIM normalized", &[]),
    t("ASimAgentEventLogs", "ASIM normalized", &[]),
    t("ASimAlertEventLogs", "ASIM normalized", &[]),
];

const fn t(
    name: &'static str,
    category: &'static str,
    sigma_services: &'static [&'static str],
) -> AzureTableDef {
    AzureTableDef {
        name,
        category,
        sigma_services,
    }
}

/// Union of sigma services for a set of selected table names.
pub fn sigma_services_for(selected_names: &[String]) -> Vec<String> {
    let mut out: Vec<String> = AZURE_TABLES
        .iter()
        .filter(|d| selected_names.iter().any(|n| n == d.name))
        .flat_map(|d| d.sigma_services.iter().map(|s| s.to_string()))
        .collect();
    out.sort();
    out.dedup();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_duplicate_tables() {
        let mut names: Vec<&str> = AZURE_TABLES.iter().map(|d| d.name).collect();
        let before = names.len();
        names.sort();
        names.dedup();
        assert_eq!(before, names.len(), "duplicate table names in catalog");
    }

    #[test]
    fn service_union() {
        let s = sigma_services_for(&["SigninLogs".to_string(), "AuditLogs".to_string()]);
        assert!(s.contains(&"signinlogs".to_string()));
        assert!(s.contains(&"auditlogs".to_string()));
    }
}
