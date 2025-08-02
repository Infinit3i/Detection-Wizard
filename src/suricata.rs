use std::fs;
use std::path::Path;
use std::io::Cursor;
use git2::Repository;
use regex::Regex;
use walkdir::WalkDir;
use reqwest::blocking as reqwest;
use zip::ZipArchive;
use flate2::read::GzDecoder;
use tar::Archive;

/// Process Suricata rules from various sources: the awesome‑Suricata repo,
/// additional GitHub repositories, webpage sources, ZIP files, and tar.gz archives.
/// All rule files are copied into one central directory.
pub fn process_suricata(mut progress_callback: Option<&mut dyn FnMut(usize, usize)>) {
    println!("Processing Suricata rules...");

    // Process the awesome‑Suricata repository first.
    process_awesome_suricata();

    // Additional GitHub repositories.
    let github_repos = vec![
        "https://github.com/ptresearch/AttackDetection.git",
        "https://github.com/beave/sagan-rules.git",
        "https://openinfosecfoundation.org/rules/trafficid/trafficid.rules",
        "https://rules.emergingthreats.net/blockrules/emerging-compromised.rules",
        "https://rules.emergingthreats.net/blockrules/emerging-dshield.suricata.rules",
        "https://rules.emergingthreats.net/blockrules/emerging-ciarmy.suricata.rules",
        "https://rules.emergingthreats.net/blockrules/emerging-drop.suricata.rules",
        "https://feodotracker.abuse.ch/downloads/feodotracker_aggressive.rules",
        "https://rules.emergingthreats.net/blockrules/threatview_CS_c2.suricata.rules",
        "https://rules.emergingthreats.net/blockrules/emerging-tor.suricata.rules",
        "https://sslbl.abuse.ch/blacklist/sslblacklist.rules",
        "https://sslbl.abuse.ch/blacklist/sslblacklist_tls_cert.rules",
        "https://sslbl.abuse.ch/blacklist/ja3_fingerprints.rules",
        "https://urlhaus.abuse.ch/downloads/ids/",
    ];
    for repo_url in github_repos {
        if !repo_url.is_empty() {
            process_github_repo(repo_url);
        }
    }

    // Additional webpage sources.
    let webpage_sources = vec![
        "https://ti.stamus-networks.io/open/stamus-lateral-rules.tar.gz",
        "https://rules.pawpatrules.fr/suricata/paw-patrules.tar.gz",
        "https://raw.githubusercontent.com/quadrantsec/suricata-rules/refs/heads/main/quadrant-suricata.rules",
        "https://raw.githubusercontent.com/Cluster25/detection/refs/heads/main/suricata/jester_stealer.rules",
        "https://raw.githubusercontent.com/travisbgreen/hunting-rules/refs/heads/master/hunting.rules",
        "https://raw.githubusercontent.com/travisbgreen/hunting-rules/refs/heads/master/most_abused_tld.rules",
        "https://raw.githubusercontent.com/travisbgreen/hunting-rules/refs/heads/master/pii.rules",
        "https://raw.githubusercontent.com/aleksibovellan/opnsense-suricata-nmaps/refs/heads/main/local.rules",
        "https://raw.githubusercontent.com/julioliraup/Antiphishing/refs/heads/main/antiphishing.rules",
        "https://sslbl.abuse.ch/blacklist/sslblacklist_tls_cert.rules",
        "https://sslbl.abuse.ch/blacklist/ja3_fingerprints.rules",
        "https://sslbl.abuse.ch/blacklist/sslipblacklist.rules",
        "https://urlhaus.abuse.ch/downloads/ids",
        "https://security.etnetera.cz/feeds/etn_aggressive.rules",
        "https://raw.githubusercontent.com/travisbgreen/hunting-rules/master/hunting.rules",
        "https://rules.emergingthreats.net/open/suricata/rules/",
    ];
    for page_url in webpage_sources {
        if !page_url.is_empty() {
            process_webpage_source(page_url);
        }
    }
}

/// Process the awesome‑Suricata repository by cloning it, parsing its README,
/// and then processing each rule repository link.
fn process_awesome_suricata() {
    let repo_url = "https://github.com/satta/awesome-suricata.git";
    let awesome_suricata_path = "./awesome-suricata";
    println!("Cloning awesome-suricata repository from {}...", repo_url);
    if let Err(e) = Repository::clone(repo_url, awesome_suricata_path) {
        eprintln!("Failed to clone awesome-suricata repo: {}", e);
        return;
    }
    let readme_path = format!("{}/README.md", awesome_suricata_path);
    let contents = match fs::read_to_string(&readme_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to read README.md: {}", e);
            return;
        }
    };

    // Extract rule links between the "## Rules" and "## Tools" sections.
    let rule_links = parse_links_from_markdown(&contents);
    println!("Found {} rule links in awesome-suricata.", rule_links.len());
    for link in rule_links {
        println!("Processing repository: {}", link);
        let repo_folder = format!("./suricata/{}", extract_repo_name(&link));
        if let Err(e) = Repository::clone(&link, &repo_folder) {
            eprintln!("Failed to clone {}: {}", link, e);
            continue;
        }
        copy_rule_files(&repo_folder, "./suricata");
    }
}

/// Process a GitHub repository URL: clone it and copy any Suricata rule files.
fn process_github_repo(repo_url: &str) {
    println!("Processing GitHub repository: {}", repo_url);
    let repo_folder = format!("./suricata/{}", extract_repo_name(repo_url));
    if let Err(e) = Repository::clone(repo_url, &repo_folder) {
        eprintln!("Failed to clone {}: {}", repo_url, e);
        return;
    }
    copy_rule_files(&repo_folder, "./suricata");
}

/// Process a webpage source URL. Depending on the URL extension, treat it as:
/// - A ZIP file to unzip.
/// - A tar.gz archive to extract.
/// - A raw rules file (.rules) to download directly.
/// - An HTML page to extract further links.
fn process_webpage_source(url: &str) {
    println!("Processing webpage source: {}", url);

    if url.ends_with(".zip") {
        // Process ZIP files.
        let response = reqwest::get(url);
        match response {
            Ok(resp) => {
                if !resp.status().is_success() {
                    eprintln!("Failed to fetch {}: Status {}", url, resp.status());
                    return;
                }
                let bytes = match resp.bytes() {
                    Ok(b) => b,
                    Err(e) => {
                        eprintln!("Error reading bytes from {}: {}", url, e);
                        return;
                    }
                };
                process_zip_file(url, &bytes);
            },
            Err(e) => eprintln!("Error fetching {}: {}", url, e),
        }
    } else if url.ends_with(".tar.gz") {
        // Process tar.gz archives.
        let response = reqwest::get(url);
        match response {
            Ok(resp) => {
                if !resp.status().is_success() {
                    eprintln!("Failed to fetch {}: Status {}", url, resp.status());
                    return;
                }
                let bytes = match resp.bytes() {
                    Ok(b) => b,
                    Err(e) => {
                        eprintln!("Error reading bytes from {}: {}", url, e);
                        return;
                    }
                };
                process_tar_gz_file(url, &bytes);
            },
            Err(e) => eprintln!("Error fetching {}: {}", url, e),
        }
    } else if url.ends_with(".rules") {
        // Process raw .rules file.
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
                let file_name = url.split('/').last().unwrap_or("downloaded.rules");
                let dest_dir = "./suricata";
                if let Err(e) = fs::create_dir_all(dest_dir) {
                    eprintln!("Failed to create directory {}: {}", dest_dir, e);
                    return;
                }
                let dest_path = Path::new(dest_dir).join(file_name);
                if let Err(e) = fs::write(&dest_path, content) {
                    eprintln!("Failed to write file {:?}: {}", dest_path, e);
                } else {
                    println!("Saved rules file to {:?}", dest_path);
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
                // Recursively process each extracted link.
                for link in rule_links {
                    process_webpage_source(&link);
                }
            },
            Err(e) => eprintln!("Error fetching {}: {}", url, e),
        }
    }
}

/// Process a ZIP file by unzipping its content and then copying any .rules files.
fn process_zip_file(url: &str, zip_data: &[u8]) {
    println!("Processing ZIP file from {}", url);
    let temp_dir = "./temp_zip_extraction";
    let _ = fs::remove_dir_all(temp_dir);
    if let Err(e) = fs::create_dir_all(temp_dir) {
        eprintln!("Failed to create temp directory {}: {}", temp_dir, e);
        return;
    }
    let reader = Cursor::new(zip_data);
    let mut archive = match ZipArchive::new(reader) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("Failed to read ZIP archive: {}", e);
            return;
        }
    };
    for i in 0..archive.len() {
        let mut file = match archive.by_index(i) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("Failed to access file in ZIP: {}", e);
                continue;
            }
        };
        let outpath = match file.enclosed_name() {
            Some(path) => Path::new(temp_dir).join(path),
            None => continue,
        };
        if file.name().ends_with('/') {
            if let Err(e) = fs::create_dir_all(&outpath) {
                eprintln!("Failed to create directory {:?}: {}", outpath, e);
            }
        } else {
            if let Some(p) = outpath.parent() {
                if !p.exists() {
                    if let Err(e) = fs::create_dir_all(p) {
                        eprintln!("Failed to create directory {:?}: {}", p, e);
                        continue;
                    }
                }
            }
            let mut outfile = match fs::File::create(&outpath) {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("Failed to create extracted file {:?}: {}", outpath, e);
                    continue;
                }
            };
            if let Err(e) = std::io::copy(&mut file, &mut outfile) {
                eprintln!("Failed to extract file {:?}: {}", outpath, e);
            } else {
                println!("Extracted file {:?}", outpath);
            }
        }
    }
    println!("ZIP extraction complete to {}", temp_dir);
    copy_rule_files(temp_dir, "./suricata");
}

/// Process a tar.gz file by uncompressing and unpacking its content, then copying any .rules files.
fn process_tar_gz_file(url: &str, tar_data: &[u8]) {
    println!("Processing tar.gz file from {}", url);
    let temp_dir = "./temp_tar_extraction";
    let _ = fs::remove_dir_all(temp_dir);
    if let Err(e) = fs::create_dir_all(temp_dir) {
        eprintln!("Failed to create temp directory {}: {}", temp_dir, e);
        return;
    }
    let tar_cursor = Cursor::new(tar_data);
    let decompressor = GzDecoder::new(tar_cursor);
    let mut archive = Archive::new(decompressor);
    if let Err(e) = archive.unpack(temp_dir) {
        eprintln!("Failed to unpack tar.gz archive: {}", e);
        return;
    }
    println!("tar.gz extraction complete to {}", temp_dir);
    copy_rule_files(temp_dir, "./suricata");
}

/// Parse markdown content to extract links between "## Rules" and "## Tools".
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
    repo_url
        .trim_end_matches('/')
        .split('/')
        .last()
        .unwrap_or("repo")
        .to_string()
}

/// Recursively search for files ending with ".rules" and copy them to dest_dir.
fn copy_rule_files(src_dir: &str, dest_dir: &str) {
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
                if ext == "rules" {
                    let file_name = path.file_name().unwrap();
                    let dest_path = Path::new(dest_dir).join(file_name);
                    if let Err(e) = fs::copy(path, &dest_path) {
                        eprintln!("Failed to copy file {:?}: {}", path, e);
                    } else {
                        println!("Copied file {:?}", path);
                    }
                }
            }
        }
    }
}
