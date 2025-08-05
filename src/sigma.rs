use std::fs;
use std::path::Path;
use git2::Repository;
use regex::Regex;
use walkdir::WalkDir;
use reqwest::blocking as reqwest;

/// Process Sigma rules by cloning a base Sigma repository, and then processing additional sources.
pub fn process_sigma(progress_callback: Option<&mut dyn FnMut(usize, usize)>) {
    println!("Processing Sigma rules...");

    // Base Sigma repository (for example, the official sigma repository).
    let repo_url = "https://github.com/SigmaHQ/sigma.git";
    let sigma_repo_path = "./sigma";
    println!("Cloning Sigma repository from {}...", repo_url);
    if let Err(e) = Repository::clone(repo_url, sigma_repo_path) {
        eprintln!("Failed to clone sigma repo: {}", e);
    } else {
        copy_sigma_rule_files(sigma_repo_path, "./sigma");
    }

    // Additional Sigma GitHub repositories.
    let sigma_github_repos = vec![
        // Add additional Sigma GitHub repository URLs here.
        "https://github.com/example/sigma-rules-1.git",
        "https://github.com/example/sigma-rules-2.git",
    ];
    for repo_url in sigma_github_repos {
        if !repo_url.is_empty() {
            process_sigma_github_repo(repo_url);
        }
    }

    // Additional Sigma webpage sources.
    let sigma_webpage_sources = vec![
        // Add additional Sigma webpage URLs here.
        "https://example.com/sigma/rules_page.html",
        "https://raw.githubusercontent.com/example/sigma/main/sample.yml",
    ];
    for page_url in sigma_webpage_sources {
        if !page_url.is_empty() {
            process_sigma_webpage_source(page_url);
        }
    }
}

/// Process an additional Sigma GitHub repository.
fn process_sigma_github_repo(repo_url: &str) {
    println!("Processing Sigma GitHub repository: {}", repo_url);
    let repo_folder = format!("./sigma/{}", extract_repo_name(repo_url));
    if let Err(e) = Repository::clone(repo_url, &repo_folder) {
        eprintln!("Failed to clone {}: {}", repo_url, e);
        return;
    }
    copy_sigma_rule_files(&repo_folder, "./central-sigma-rules");
}

/// Process an additional Sigma webpage source.  
/// If the URL ends with .yml or .yaml, download it as a rule file; otherwise treat it as an HTML page.
fn process_sigma_webpage_source(url: &str) {
    println!("Processing Sigma webpage source: {}", url);
    if url.ends_with(".yml") || url.ends_with(".yaml") {
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
                let file_name = url.split('/').last().unwrap_or("downloaded.yml");
                let dest_dir = "./sigma";
                if let Err(e) = fs::create_dir_all(dest_dir) {
                    eprintln!("Failed to create directory {}: {}", dest_dir, e);
                    return;
                }
                let dest_path = Path::new(dest_dir).join(file_name);
                if let Err(e) = fs::write(&dest_path, content) {
                    eprintln!("Failed to write file {:?}: {}", dest_path, e);
                } else {
                    println!("Saved Sigma rule file to {:?}", dest_path);
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
                println!("Found {} Sigma rule links on webpage.", rule_links.len());
                for link in rule_links {
                    process_sigma_webpage_source(&link);
                }
            },
            Err(e) => eprintln!("Error fetching {}: {}", url, e),
        }
    }
}

/// Parse HTML content to extract links (a basic implementation).
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

/// Recursively search for files ending with .yml or .yaml in `src_dir`
/// and copy them into `dest_dir`.
fn copy_sigma_rule_files(src_dir: &str, dest_dir: &str) {
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
                if ext == "yml" || ext == "yaml" {
                    let file_name = path.file_name().unwrap();
                    let dest_path = Path::new(dest_dir).join(file_name);
                    if let Err(e) = fs::copy(path, &dest_path) {
                        eprintln!("Failed to copy file {:?}: {}", path, e);
                    } else {
                        println!("Copied Sigma rule file {:?}", path);
                    }
                }
            }
        }
    }
}
