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