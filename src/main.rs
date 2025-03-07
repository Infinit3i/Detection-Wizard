use std::fs;
use std::path::Path;
use dialoguer::Select;
use git2::Repository;
use regex::Regex;
use walkdir::WalkDir;

fn main() {
    // Present a menu for tool selection.
    let options = vec!["Yara", "Suricata"];
    let selection = Select::new()
        .with_prompt("Select a tool")
        .items(&options)
        .default(0)
        .interact()
        .unwrap();

    match options[selection] {
        "Yara" => process_yara(),
        "Suricata" => process_suricata(),
        _ => println!("Invalid selection"),
    }
}

/// Process YARA rules by cloning the awesome-yara repo,
/// extracting links under the 'Rules' section, and then cloning
/// each repo and copying rule files into a central folder.
fn process_yara() {
    // Clone the awesome-yara repository.
    let repo_url = "https://github.com/InQuest/awesome-yara.git";
    let awesome_yara_path = "./awesome-yara";
    println!("Cloning awesome-yara repository...");
    if let Err(e) = Repository::clone(repo_url, awesome_yara_path) {
        eprintln!("Failed to clone awesome-yara repo: {}", e);
        return;
    }

    // Read the README file from the cloned repository.
    let readme_path = format!("{}/README.md", awesome_yara_path);
    let contents = fs::read_to_string(&readme_path)
        .expect("Failed to read README.md");

    // Parse only the links under the 'Rules' section.
    let rule_links = parse_links_from_markdown(&contents);
    println!("Found {} rule links.", rule_links.len());

    // Process each link: clone and then copy YARA rule files.
    for link in rule_links {
        println!("Processing repo: {}", link);
        // For simplicity, assume the repo can be cloned directly.
        // In a real-world scenario you might need to adjust the URL (e.g. append .git).
        let repo_folder = format!("./yara/{}", extract_repo_name(&link));
        if let Err(e) = Repository::clone(&link, &repo_folder) {
            eprintln!("Failed to clone {}: {}", link, e);
            continue;
        }
        // Copy rule files from the cloned repo to your central folder.
        copy_rule_files(&repo_folder, "./central-yara-rules");
    }
}

/// Parse the markdown content to extract links between the 'Rules' and 'Tools' sections.
fn parse_links_from_markdown(markdown: &str) -> Vec<String> {
    let mut links = Vec::new();
    // Adjust these markers if your markdown uses different header levels.
    let rules_marker = "## Rules";
    let tools_marker = "## Tools";
    let mut in_rules_section = false;

    // Regular expression to capture markdown links: [text](URL)
    let re = Regex::new(r"\[.*?\]\((https?://.*?)\)").unwrap();

    for line in markdown.lines() {
        if line.contains(rules_marker) {
            in_rules_section = true;
            continue;
        }
        if line.contains(tools_marker) {
            break; // Stop processing once we hit the Tools section.
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
    // This takes the last path segment of the URL.
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

/// Stub for processing Suricata; implementation would be similar.
fn process_suricata() {
    println!("Suricata processing is not implemented yet.");
}
