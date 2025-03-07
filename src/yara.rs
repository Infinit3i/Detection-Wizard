use std::fs;
use std::path::Path;
use git2::Repository;
use regex::Regex;
use walkdir::WalkDir;

/// Process YARA rules by cloning the awesome-yara repo,
/// parsing out rule links, and copying YARA rule files.
pub fn process_yara() {
    println!("Processing YARA rules...");

    // Clone the awesome-yara repository.
    let repo_url = "https://github.com/InQuest/awesome-yara.git";
    let awesome_yara_path = "./awesome-yara";
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
    println!("Found {} rule links.", rule_links.len());

    // For each rule link, clone the repository and copy YARA rule files.
    for link in rule_links {
        println!("Processing repository: {}", link);
        let repo_folder = format!("./yara/{}", extract_repo_name(&link));
        if let Err(e) = Repository::clone(&link, &repo_folder) {
            eprintln!("Failed to clone {}: {}", link, e);
            continue;
        }
        copy_rule_files(&repo_folder, "./central-yara-rules");
    }
}

/// Parse the markdown content to extract links between the '## Rules' and '## Tools' sections.
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

/// Extracts a simple repository name from its URL.
fn extract_repo_name(repo_url: &str) -> String {
    repo_url.trim_end_matches('/')
            .split('/')
            .last()
            .unwrap_or("repo")
            .to_string()
}

/// Recursively search for files ending with '.yar' or '.yara' in `src_dir`
/// and copy them into `dest_dir`.
fn copy_rule_files(src_dir: &str, dest_dir: &str) {
    // Create destination directory if it doesn't exist.
    if let Err(e) = fs::create_dir_all(dest_dir) {
        eprintln!("Failed to create destination directory: {}", e);
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
