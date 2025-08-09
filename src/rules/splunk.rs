use std::fs;
use std::path::Path;
use git2::Repository;
use regex::Regex;
use walkdir::WalkDir;
use reqwest::blocking as reqwest;
use std::collections::HashSet;
use scraper::{Html, Selector};
use serde::{Deserialize, Serialize};
use chrono::Utc;
use anyhow::{Result, anyhow};

// MITRE ATT&CK Integration
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

    pub fn get_mitre_technique_details(&self, technique_id: &str) -> Result<MitreTechniqueDetails> {
        let url = self.build_technique_url(technique_id);
        
        let response = self.client.get(&url).send()?;
        
        if !response.status().is_success() {
            return Err(anyhow!("Failed to fetch details for Technique ID {}", technique_id));
        }

        let html_content = response.text()?;
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

    pub fn save_analytics_to_files(
        &self,
        technique_id: &str,
        details: &MitreTechniqueDetails,
        today_date: &str,
        output_path: &str,
    ) -> Result<()> {
        let base_folder = format!("{}/MITRE_Alerts", output_path);
        fs::create_dir_all(&base_folder)?;

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
pub fn process_mitre_technique(technique_id: &str, output_path: &str) -> Result<()> {
    let client = MitreClient::new();
    let today_date = Utc::now().format("%Y-%m-%d").to_string();
    
    let details = client.get_mitre_technique_details(technique_id)?;
    
    if details.analytics.is_empty() {
        println!("No Analytics Queries Found for {}", technique_id);
        return Ok(());
    }
    
    client.save_analytics_to_files(technique_id, &details, &today_date, output_path)?;
    Ok(())
}

// Process multiple MITRE techniques
pub fn process_mitre_techniques(technique_ids: &[&str], output_path: &str, mut progress_callback: Option<&mut dyn FnMut(usize, usize, String)>) {    let total = technique_ids.len();
    
    for (index, technique_id) in technique_ids.iter().enumerate() {
        if let Some(cb) = progress_callback.as_mut() {
            cb(index + 1, total, format!("MITRE T{}", technique_id));
        }
        
        if let Err(e) = process_mitre_technique(technique_id, output_path) {
            eprintln!("Failed to process MITRE technique T{}: {}", technique_id, e);
        }
    }
}

pub fn splunk_github_sources() -> Vec<&'static str> {
    vec![
        "https://github.com/Infinit3i/Defensive-Rules.git",
    ]
}

pub fn splunk_web_sources() -> Vec<&'static str> {
    vec![
        "",
    ]
}

pub fn splunk_total_sources() -> usize {
    let base_sources = splunk_github_sources().len() + splunk_web_sources().iter().filter(|s| !s.is_empty()).count();
    base_sources
}

/// Process Splunk rules by cloning GitHub repositories, downloading web sources,
/// and processing MITRE ATT&CK techniques for Splunk analytics.
/// All files go into the specified output_path directory.
pub fn process_splunk(
    output_path: &str,
    mut progress_callback: Option<&mut dyn FnMut(usize, usize, String)>,
) {
    println!("Processing Splunk rules and MITRE techniques...");

    let github_repos = splunk_github_sources();
    let web_sources: Vec<&str> = splunk_web_sources().into_iter().filter(|s| !s.is_empty()).collect();
    let total = github_repos.len() + web_sources.len();
    let mut current_index = 0;

    // Process GitHub repositories
    for repo_url in github_repos.iter() {
        current_index += 1;
        if let Some(cb) = progress_callback.as_mut() {
            cb(current_index, total, repo_url.to_string());
        }
        if !repo_url.is_empty() {
            process_splunk_github_repo(repo_url, output_path);
        }
    }

    // Process web sources
    for page_url in web_sources.iter() {
        current_index += 1;
        if let Some(cb) = progress_callback.as_mut() {
            cb(current_index, total, page_url.to_string());
        }
        process_splunk_webpage_source(page_url, output_path);
    }

    
    println!("Completed Splunk processing!");
}

/// Process an additional Splunk GitHub repository.
fn process_splunk_github_repo(repo_url: &str, output_path: &str) {
    println!("Processing Splunk GitHub repository: {}", repo_url);
    let repo_folder = format!("./tmp_splunk/{}", extract_repo_name(repo_url));
    
    if let Err(e) = Repository::clone(repo_url, &repo_folder) {
        eprintln!("Failed to clone {}: {}", repo_url, e);
        return;
    }
    
    copy_splunk_rule_files(&repo_folder, output_path);
    
    // Clean up the temporary clone
    if let Err(e) = fs::remove_dir_all(&repo_folder) {
        eprintln!("Failed to clean up cloned repo {}: {}", repo_folder, e);
    }
}

/// Process an additional Splunk webpage source.
/// If the URL ends with .conf, .xml, .md or .spl, download it as a rule file;
/// otherwise treat it as an HTML page and extract further links.
fn process_splunk_webpage_source(url: &str, output_path: &str) {
    println!("Processing Splunk webpage source: {}", url);
    if url.ends_with(".conf") || url.ends_with(".xml") || url.ends_with(".md") || url.ends_with(".spl") {
        let response = reqwest::get(url);
        match response {
            Ok(resp) => {
                if !resp.status().is_success() {
                    eprintln!("Failed to fetch {}: Status {}", url, resp.status());
                    return;
                }
                let content = match resp.text() {
                    Ok(text) => text,
                    Err(e) => {
                        eprintln!("Error reading content from {}: {}", url, e);
                        return;
                    }
                };
                let file_name = url.split('/').last().unwrap_or("downloaded.conf");
                
                if let Err(e) = fs::create_dir_all(output_path) {
                    eprintln!("Failed to create directory {}: {}", output_path, e);
                    return;
                }
                
                let dest_path = Path::new(output_path).join(file_name);
                if let Err(e) = fs::write(&dest_path, content) {
                    eprintln!("Failed to write file {:?}: {}", dest_path, e);
                } else {
                    println!("Saved Splunk rule file to {:?}", dest_path);
                }
            },
            Err(e) => eprintln!("Error fetching {}: {}", url, e),
        }
    } else {
        // Assume HTML page and extract further links.
        let response = reqwest::get(url);
        match response {
            Ok(resp) => {
                if !resp.status().is_success() {
                    eprintln!("Failed to fetch {}: Status {}", url, resp.status());
                    return;
                }
                let content = match resp.text() {
                    Ok(text) => text,
                    Err(e) => {
                        eprintln!("Error reading content from {}: {}", url, e);
                        return;
                    }
                };
                let rule_links = parse_links_from_html(&content);
                println!("Found {} Splunk rule links on webpage.", rule_links.len());
                for link in rule_links {
                    process_splunk_webpage_source(&link, output_path);
                }
            },
            Err(e) => eprintln!("Error fetching {}: {}", url, e),
        }
    }
}

/// Parse HTML content to extract links (basic implementation).
fn parse_links_from_html(html: &str) -> Vec<String> {
    let mut links = Vec::new();
    let re = Regex::new(r#"href="(https?://[^"]+)""#).unwrap();
    for cap in re.captures_iter(html) {
        links.push(cap[1].to_string());
    }
    links
}

/// Extract a simple repository name from its URL.
fn extract_repo_name(repo_url: &str) -> String {
    repo_url.trim_end_matches('/')
            .split('/')
            .last()
            .unwrap_or("repo")
            .replace(".git", "")
}

/// Recursively search for Splunk rule files (.conf, .xml, .spl, or .md) in `src_dir`
/// and copy them into the single `dest_dir` folder.
fn copy_splunk_rule_files(src_dir: &str, dest_dir: &str) {
    if let Err(e) = fs::create_dir_all(dest_dir) {
        eprintln!("Failed to create destination directory {}: {}", dest_dir, e);
        return;
    }
    
    for entry in WalkDir::new(src_dir) {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                eprintln!("Error reading entry: {}", e);
                continue;
            }
        };
        
        if entry.file_type().is_file() {
            let path = entry.path();
            if let Some(ext) = path.extension() {
                if ext == "conf" || ext == "xml" || ext == "spl" || ext == "md" {
                    let file_name = match path.file_name() {
                        Some(name) => name,
                        None => continue,
                    };

                    // Avoid overwriting duplicates by prefixing with repo name
                    let unique_name = format!(
                        "{}_{}",
                        extract_repo_name(src_dir),
                        file_name.to_string_lossy()
                    );

                    let dest_path = Path::new(dest_dir).join(unique_name);

                    if let Err(e) = fs::copy(path, &dest_path) {
                        eprintln!("Failed to copy file {:?}: {}", path, e);
                    } else {
                        println!("Copied Splunk rule file: {:?}", dest_path);
                    }
                }
            }
        }
    }
}