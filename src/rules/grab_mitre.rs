use reqwest;
use scraper::{Html, Selector};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::path::Path;
use chrono::{DateTime, Utc};
use anyhow::{Result, anyhow};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalyticQuery {
    pub description: String,
    pub query: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitreTechniqueDetails {
    pub id: String,
    pub name: String,
    pub subtechnique: String,
    pub tactics: Vec<String>,
    pub hunting_trigger: String,
    pub mitre_category: String,
    pub analytics: Vec<AnalyticQuery>,
    pub apts: Vec<String>,
    pub url: String,
    pub technique_id: String,
    pub subtechnique_id: String,
}

pub struct MitreClient {
    client: reqwest::Client,
}

impl MitreClient {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::new(),
        }
    }

    pub async fn get_mitre_technique_details(&self, technique_id: &str) -> Result<MitreTechniqueDetails> {
        let url = self.build_technique_url(technique_id);
        
        let response = self.client.get(&url).send().await?;
        
        if !response.status().is_success() {
            return Err(anyhow!("Failed to fetch details for Technique ID {}", technique_id));
        }

        let html_content = response.text().await?;
        let document = Html::parse_document(&html_content);

        let name_subtechnique = self.extract_name_and_subtechnique(&document)?;
        let tactics = self.extract_tactics(&document);
        let hunting_trigger = self.extract_hunting_trigger(&document);
        let mitre_category = self.extract_mitre_category(&document);
        let analytics = self.extract_analytics(&document);
        let apts = self.extract_unique_apts(&html_content);

        let (technique_id_clean, subtechnique_id) = if technique_id.contains('.') {
            let parts: Vec<&str> = technique_id.split('.').collect();
            (format!("T{}", parts[0]), format!("T{}", technique_id))
        } else {
            (format!("T{}", technique_id), String::new())
        };

        Ok(MitreTechniqueDetails {
            id: format!("T{}", technique_id),
            name: name_subtechnique.0,
            subtechnique: name_subtechnique.1,
            tactics,
            hunting_trigger,
            mitre_category,
            analytics,
            apts,
            url,
            technique_id: technique_id_clean,
            subtechnique_id,
        })
    }

    fn build_technique_url(&self, technique_id: &str) -> String {
        if technique_id.contains('.') {
            let parts: Vec<&str> = technique_id.split('.').collect();
            let base_id = parts[0];
            let sub_id = parts[1].parse::<u32>().unwrap_or(0);
            format!("https://attack.mitre.org/techniques/T{}/{:03}/", base_id, sub_id)
        } else {
            format!("https://attack.mitre.org/techniques/T{}/", technique_id)
        }
    }

    fn extract_name_and_subtechnique(&self, document: &Html) -> Result<(String, String)> {
        let h1_selector = Selector::parse("h1").unwrap();
        
        if let Some(h1_element) = document.select(&h1_selector).next() {
            let raw_name = h1_element.text().collect::<Vec<_>>().join("").trim().to_string();
            
            if raw_name.contains(':') {
                let parts: Vec<&str> = raw_name.splitn(2, ':').collect();
                Ok((parts[0].trim().to_string(), parts[1].trim().to_string()))
            } else {
                Ok((raw_name, String::new()))
            }
        } else {
            Ok(("Unknown".to_string(), String::new()))
        }
    }

    fn extract_tactics(&self, document: &Html) -> Vec<String> {
        let tactics_selector = Selector::parse("div.card-tactics a").unwrap();
        document
            .select(&tactics_selector)
            .map(|element| element.text().collect::<Vec<_>>().join("").trim().to_string())
            .collect()
    }

    fn extract_hunting_trigger(&self, document: &Html) -> String {
        let description_selector = Selector::parse("div.description-body").unwrap();
        
        if let Some(description_element) = document.select(&description_selector).next() {
            let full_text = description_element.text().collect::<Vec<_>>().join(" ").trim().to_string();
            
            if let Some(first_sentence_end) = full_text.find('.') {
                format!("{}.", &full_text[..first_sentence_end])
            } else {
                full_text
            }
        } else {
            "Description not found.".to_string()
        }
    }

    fn extract_mitre_category(&self, document: &Html) -> String {
        let tactics_selector = Selector::parse("div#card-tactics a").unwrap();
        
        if let Some(tactic_element) = document.select(&tactics_selector).next() {
            tactic_element.text().collect::<Vec<_>>().join("").trim().to_string()
        } else {
            "Unknown".to_string()
        }
    }

    fn extract_analytics(&self, document: &Html) -> Vec<AnalyticQuery> {
        let mut analytics = Vec::new();
        let p_selector = Selector::parse("p").unwrap();
        let code_selector = Selector::parse("code").unwrap();

        for p_element in document.select(&p_selector) {
            let p_text = p_element.text().collect::<Vec<_>>().join("");
            
            if p_text.contains("Analytic") {
                if let Some(code_element) = p_element.select(&code_selector).next() {
                    let mut query_text = code_element.text().collect::<Vec<_>>().join("").trim().to_string();
                    
                    // Replace sourcetypes with more readable macros
                    query_text = query_text.replace(
                        "sourcetype=WinEventLog:Microsoft-Windows-Sysmon/Operational",
                        "`sysmon`"
                    );
                    query_text = query_text.replace(
                        "sourcetype=WinEventLog:Security",
                        "`windows-security`"
                    );

                    // Remove "Analytic # -" prefix from description
                    let mut description = p_text.trim().to_string();
                    if description.starts_with("Analytic") {
                        if let Some(dash_pos) = description.find('-') {
                            description = description[dash_pos + 1..].trim().to_string();
                        }
                    }

                    analytics.push(AnalyticQuery {
                        description,
                        query: query_text,
                    });
                }
            }
        }

        analytics
    }

    fn extract_unique_apts(&self, html: &str) -> Vec<String> {
        let document = Html::parse_document(html);
        let mut apts = HashSet::new();

        let table_selector = Selector::parse("div.tables-mobile table tbody tr").unwrap();
        let td_selector = Selector::parse("td").unwrap();

        for row in document.select(&table_selector) {
            let columns: Vec<_> = row.select(&td_selector).collect();
            
            if columns.len() > 2 {
                let apt_id = columns[0].text().collect::<Vec<_>>().join("").trim().to_string();
                let apt_name = columns[1].text().collect::<Vec<_>>().join("").trim().to_string();
                
                if apt_id.starts_with('G') && apt_id.len() == 5 && apt_id[1..].chars().all(|c| c.is_ascii_digit()) {
                    apts.insert(apt_name);
                }
            }
        }

        let mut sorted_apts: Vec<String> = apts.into_iter().collect();
        sorted_apts.sort();
        sorted_apts
    }

    pub async fn save_analytics_to_files(
        &self,
        technique_id: &str,
        details: &MitreTechniqueDetails,
        today_date: &str,
    ) -> Result<()> {
        let base_folder = "MITRE_Alerts";
        fs::create_dir_all(base_folder)?;

        let mitre_category = &details.mitre_category;
        if mitre_category == "Unknown" {
            println!("Skipping analytics save for Technique ID {} due to unknown category.", technique_id);
            return Ok(());
        }

        let category_folder = format!("{}/{}", base_folder, mitre_category.replace(", ", "_"));
        fs::create_dir_all(&category_folder)?;

        let apts_joined = details.apts.join("\",\"");

        for (index, analytic) in details.analytics.iter().enumerate() {
            let file_title = format!("[T{}] {}_Analytic_{}.txt", technique_id, details.name, index + 1);
            let file_path = format!("{}/{}", category_folder, file_title);

            let content = self.build_splunk_query(analytic, details, &apts_joined, today_date);
            fs::write(&file_path, content)?;
        }

        println!("Analytics saved in folder: {}", category_folder);
        Ok(())
    }

    fn build_splunk_query(
        &self,
        analytic: &AnalyticQuery,
        details: &MitreTechniqueDetails,
        apts_joined: &str,
        today_date: &str,
    ) -> String {
        format!(
            r#"`indextime` {}
| eval hash_sha256=lower(hash_sha256),
hunting_trigger="{}",
mitre_category="{}",
mitre_technique="{}",
mitre_technique_id="{}",
mitre_subtechnique="{}",
mitre_subtechnique_id="{}",
apt=mvappend("{}"),
mitre_link="{}",
creator="Cpl Iverson",
upload_date="{}",
last_modify_date="{}",
mitre_version="v16",
priority="medium"
| `process_create_whitelist`
| eval indextime = _indextime
| convert ctime(indextime)
| table _time indextime event_description hash_sha256 host_fqdn user_name original_file_name process_path process_guid process_parent_path process_id process_parent_id process_command_line process_parent_command_line process_parent_guid mitre_category mitre_technique mitre_technique_id hunting_trigger mitre_subtechnique mitre_subtechnique_id apt mitre_link creator upload_date last_modify_date mitre_version priority
| collect `jarvis_index`
"#,
            analytic.query,
            analytic.description,
            details.mitre_category,
            details.name,
            details.technique_id,
            details.subtechnique,
            details.subtechnique_id,
            apts_joined,
            details.url,
            today_date,
            today_date
        )
    }
}

// Convenience function for single technique processing
pub async fn process_mitre_technique(technique_id: &str) -> Result<()> {
    let client = MitreClient::new();
    let today_date = Utc::now().format("%Y-%m-%d").to_string();
    
    let details = client.get_mitre_technique_details(technique_id).await?;
    
    if details.analytics.is_empty() {
        println!("No Analytics Queries Found for {}", technique_id);
        return Ok(());
    }
    
    client.save_analytics_to_files(technique_id, &details, &today_date).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_mitre_client_creation() {
        let client = MitreClient::new();
        // Just test that we can create a client
        assert!(true);
    }

    #[tokio::test]
    async fn test_url_building() {
        let client = MitreClient::new();
        
        // Test main technique
        let url1 = client.build_technique_url("1055");
        assert_eq!(url1, "https://attack.mitre.org/techniques/T1055/");
        
        // Test subtechnique
        let url2 = client.build_technique_url("1055.001");
        assert_eq!(url2, "https://attack.mitre.org/techniques/T1055/001/");
    }
}