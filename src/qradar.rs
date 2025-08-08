use git2::Repository;
use regex::Regex;
use reqwest::blocking as reqwest;
use std::fs;
use std::path::Path;
use walkdir::WalkDir;

pub fn qradar_github_sources() -> Vec<&'static str> {
    vec![
        "https://github.com/IBM/qradar-sample-apps.git",
        "https://github.com/IBM/qradar-contrib.git", 
        "https://github.com/IBM/qradar-mitre-attack.git",
        "https://github.com/usama-r/QRadar.git",
        "https://github.com/zrquan/QRadar-Rule.git",
    ]
}

pub fn qradar_web_sources() -> Vec<&'static str> {
    vec![
        "https://raw.githubusercontent.com/IBM/qradar-sample-apps/main/sample_rules.xml",
        "",
    ]
}

/// Process QRadar rules by cloning GitHub repositories and processing web sources.
pub fn process_qradar(_progress_callback: Option<&mut dyn FnMut(usize, usize)>) {
    println!("Processing QRadar rules...");

    for repo_url in qradar_github_sources() {
        if !repo_url.is_empty() {
            process_qradar_github_repo(repo_url);
        }
    }

    for page_url in qradar_web_sources() {
        if !page_url.is_empty() {
            process_qradar_webpage_source(page_url);
        }
    }
}

/// Process a QRadar GitHub repository.
fn process_qradar_github_repo(repo_url: &str) {
    println!("Processing QRadar GitHub repository: {}", repo_url);
    let repo_folder = format!("./qradar/{}", extract_repo_name(repo_url));
    if let Err(e) = Repository::clone(repo_url, &repo_folder) {
        eprintln!("Failed to clone {}: {}", repo_url, e);
        return;
    }
    copy_qradar_rule_files(&repo_folder, "./qradar");
}

/// Process a QRadar webpage source.
/// If the URL ends with .xml, .json, .rules, or .aql, download it as a rule file;
/// otherwise treat it as an HTML page and extract further links.
fn process_qradar_webpage_source(url: &str) {
    println!("Processing QRadar webpage source: {}", url);
    if url.ends_with(".xml") || url.ends_with(".json") || url.ends_with(".rules") || url.ends_with(".aql") {
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
                let file_name = url.split('/').last().unwrap_or("downloaded.xml");
                let dest_dir = "./qradar";
                if let Err(e) = fs::create_dir_all(dest_dir) {
                    eprintln!("Failed to create directory {}: {}", dest_dir, e);
                    return;
                }
                let dest_path = Path::new(dest_dir).join(file_name);
                if let Err(e) = fs::write(&dest_path, content) {
                    eprintln!("Failed to write file {:?}: {}", dest_path, e);
                } else {
                    println!("Saved QRadar rule file to {:?}", dest_path);
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
                println!("Found {} QRadar rule links on webpage.", rule_links.len());
                for link in rule_links {
                    process_qradar_webpage_source(&link);
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
            .to_string()
}

/// Recursively search for QRadar rule files (.xml, .json, .rules, .aql) in `src_dir`
/// and copy them into `dest_dir`.
fn copy_qradar_rule_files(src_dir: &str, dest_dir: &str) {
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
                if ext == "xml" || ext == "json" || ext == "rules" || ext == "aql" {
                    let file_name = path.file_name().unwrap();
                    let dest_path = Path::new(dest_dir).join(file_name);
                    if let Err(e) = fs::copy(path, &dest_path) {
                        eprintln!("Failed to copy file {:?}: {}", path, e);
                    } else {
                        println!("Copied QRadar rule file {:?}", path);
                    }
                }
            }
        }
    }
}

pub fn qradar_total_sources() -> usize {
    qradar_github_sources().len() + qradar_web_sources().iter().filter(|s| !s.is_empty()).count()
}