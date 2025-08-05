use std::fs;
use std::path::Path;
use git2::Repository;
use regex::Regex;
use walkdir::WalkDir;
use reqwest::blocking as reqwest;

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

pub fn process_splunk(progress_callback: Option<&mut dyn FnMut(usize, usize)>) {
    println!("Processing Splunk rules...");

    for repo in splunk_github_sources() {
        if !repo.is_empty() {
            process_splunk_github_repo(repo);
        }
    }

    for page in splunk_web_sources() {
        if !page.is_empty() {
            process_splunk_webpage_source(page);
        }
    }
}

/// Process an additional Splunk GitHub repository.
fn process_splunk_github_repo(repo_url: &str) {
    println!("Processing Splunk GitHub repository: {}", repo_url);
    let repo_folder = format!("./splunk/{}", extract_repo_name(repo_url));
    if let Err(e) = Repository::clone(repo_url, &repo_folder) {
        eprintln!("Failed to clone {}: {}", repo_url, e);
        return;
    }
    copy_splunk_rule_files(&repo_folder, "./splunk");
}

/// Process an additional Splunk webpage source.
/// If the URL ends with .conf, .xml, .md or .spl, download it as a rule file;
/// otherwise treat it as an HTML page and extract further links.
fn process_splunk_webpage_source(url: &str) {
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
                let dest_dir = "./splunk";
                if let Err(e) = fs::create_dir_all(dest_dir) {
                    eprintln!("Failed to create directory {}: {}", dest_dir, e);
                    return;
                }
                let dest_path = Path::new(dest_dir).join(file_name);
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
                    process_splunk_webpage_source(&link);
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

/// Recursively search for Splunk rule files (.conf, .xml, or .spl) in `src_dir`
/// and copy them into `dest_dir`.
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
                if ext == "conf" || ext == "xml" || ext == "spl" {
                    let file_name = path.file_name().unwrap();
                    let dest_path = Path::new(dest_dir).join(file_name);
                    if let Err(e) = fs::copy(path, &dest_path) {
                        eprintln!("Failed to copy file {:?}: {}", path, e);
                    } else {
                        println!("Copied Splunk rule file {:?}", path);
                    }
                }
            }
        }
    }
}

pub fn splunk_total_sources() -> usize {
    1 + splunk_github_sources().len() + splunk_web_sources().iter().filter(|s| !s.is_empty()).count()
}
