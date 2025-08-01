use std::fs;
use std::path::Path;
use git2::Repository;
use regex::Regex;
use walkdir::WalkDir;
use reqwest::blocking as reqwest;



/// Process YARA rules by cloning the awesome-yara repo, parsing out rule links,
/// and then processing additional lists defined for GitHub repos and webpage sources.
pub fn process_yara(mut progress_callback: Option<&mut dyn FnMut(usize, usize)>) {
    println!("Processing YARA rules...");

    // Process the awesome-yara repository.
    process_awesome_yara();

    // Additional YARA GitHub repositories.
    let yara_github_repos = vec![
        // Add additional YARA GitHub repository URLs here.
        "https://github.com/advanced-threat-research/Yara-Rules.git",
        "https://github.com/airbnb/binaryalert/tree/master/rules/public",
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
        "https://github.com/malpedia/signator-rules.git",
        "https://github.com/mandiant/red_team_tool_countermeasures.git",
        "https://github.com/mikesxrs/Open-Source-YARA-rules.git",
        "https://github.com/mthcht/ThreatHunting-Keywords-yara-rules.git",
        "https://github.com/Neo23x0/god-mode-rules.git",
        "https://github.com/Neo23x0/signature-base.git",
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
    ];
    let total = yara_github_repos.len();
    for (index, repo_url) in yara_github_repos.iter().enumerate() {
        if let Some(cb) = progress_callback.as_mut() {
            cb(index + 1, total);
        }
        println!("Processing YARA GitHub repository: {}", repo_url);
        if !repo_url.is_empty() {
            process_yara_github_repo(repo_url);
        }
    }

    // Additional YARA webpage sources.
    let yara_webpage_sources = vec![
        // Add additional YARA webpage URLs here.
        "",
    ];
    for page_url in yara_webpage_sources {
        if !page_url.is_empty() {
            process_yara_webpage_source(page_url);
        }
    }
}

/// Clone and process the awesome-yara repository.
fn process_awesome_yara() {
    let repo_url = "https://github.com/InQuest/awesome-yara.git";
    let awesome_yara_path = "";
    println!("Cloning awesome-yara repository from {}...", repo_url);
    if let Err(e) = Repository::clone(repo_url, awesome_yara_path) {
        eprintln!("Failed to clone awesome-yara repo: {}", e);
        return;
    }

    // Read the README file from the cloned repository.
    let readme_path = format!("{}/README.md", awesome_yara_path);
    let contents = match fs::read_to_string(&readme_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to read README.md: {}", e);
            return;
        }
    };

    // Extract rule links between the '## Rules' and '## Tools' sections.
    let rule_links = parse_links_from_markdown(&contents);
    println!("Found {} rule links in awesome-yara.", rule_links.len());

    // For each rule link, clone the repository and copy YARA rule files.
    for link in rule_links {
        println!("Processing repository: {}", link);
        let repo_folder = format!("./yara/{}", extract_repo_name(&link));
        if let Err(e) = Repository::clone(&link, &repo_folder) {
            eprintln!("Failed to clone {}: {}", link, e);
            continue;
        }
        copy_rule_files(&repo_folder, "");
    }
}

/// Process an additional YARA GitHub repository.
fn process_yara_github_repo(repo_url: &str) {
    println!("Processing YARA GitHub repository: {}", repo_url);
    let repo_folder = format!("./yara/{}", extract_repo_name(repo_url));
    if let Err(e) = Repository::clone(repo_url, &repo_folder) {
        eprintln!("Failed to clone {}: {}", repo_url, e);
        return;
    }
    copy_rule_files(&repo_folder, "");

    if let Err(e) = fs::remove_dir_all(&repo_folder) {
        eprintln!("Failed to clean up cloned repo {}: {}", repo_folder, e);
    }
}

/// Process an additional YARA webpage source. Depending on the URL, this function
/// either downloads a raw .yar/.yara file or treats the URL as an HTML page and extracts links.
fn process_yara_webpage_source(url: &str) {
    println!("Processing YARA webpage source: {}", url);
    if url.ends_with(".yar") || url.ends_with(".yara") {
        // Process raw YARA file.
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
                let file_name = url.split('/').last().unwrap_or("downloaded.yar");
                let dest_dir = "";
                if let Err(e) = fs::create_dir_all(dest_dir) {
                    eprintln!("Failed to create directory {}: {}", dest_dir, e);
                    return;
                }
                let dest_path = Path::new(dest_dir).join(file_name);
                if let Err(e) = fs::write(&dest_path, content) {
                    eprintln!("Failed to write file {:?}: {}", dest_path, e);
                } else {
                    println!("Saved YARA rule file to {:?}", dest_path);
                }
            },
            Err(e) => eprintln!("Error fetching {}: {}", url, e),
        }
    } else {
        // Assume it's an HTML page and extract links.
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
                println!("Found {} rule links on webpage.", rule_links.len());
                for link in rule_links {
                    process_yara_webpage_source(&link);
                }
            },
            Err(e) => eprintln!("Error fetching {}: {}", url, e),
        }
    }
}

/// Parse markdown content to extract links between the '## Rules' and '## Tools' sections.
fn parse_links_from_markdown(markdown: &str) -> Vec<String> {
    let mut links = Vec::new();
    let rules_marker = "## Rules";
    let tools_marker = "## Tools";
    let mut in_rules_section = false;
    let re = Regex::new(r"\[.*?\]\((https?://.*?)\)").unwrap();
    for line in markdown.lines() {
        if line.contains(rules_marker) {
            in_rules_section = true;
            continue;
        }
        if line.contains(tools_marker) {
            break;
        }
        if in_rules_section {
            for cap in re.captures_iter(line) {
                links.push(cap[1].to_string());
            }
        }
    }
    links
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

/// Extracts a simple repository name from its URL.
fn extract_repo_name(repo_url: &str) -> String {
    repo_url.trim_end_matches('/')
            .split('/')
            .last()
            .unwrap_or("repo")
            .to_string()
}

/// Recursively search for files ending with '.yar' or '.yara' in `src_dir`
/// and copy them into the central `./yara` folder.
fn copy_rule_files(src_dir: &str, _unused_dest_dir: &str) {
    let dest_dir = "./yara";
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
                if ext == "yar" || ext == "yara" {
                    let file_name = match path.file_name() {
                        Some(name) => name,
                        None => continue,
                    };

                    // Avoid overwriting duplicates by prefixing with a hash or repo name
                    let unique_name = format!(
                        "{}_{}",
                        extract_repo_name(src_dir),
                        file_name.to_string_lossy()
                    );

                    let dest_path = Path::new(dest_dir).join(unique_name);

                    if let Err(e) = fs::copy(path, &dest_path) {
                        eprintln!("Failed to copy file {:?}: {}", path, e);
                    } else {
                        println!("Copied: {:?}", dest_path);
                    }
                }
            }
        }
    }
}
