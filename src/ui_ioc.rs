use crate::download::render_output_path_selector;
use crate::download::{DownloadFormat, start_download};
use crate::ioc_menu::{IOCSelectorApp, OutputFormat};
use eframe::egui;
use egui::Margin;
use git2::Repository;
use regex::Regex;
use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::sync::Arc;
use walkdir::WalkDir;

pub fn render_ui_ioc(
    app: &mut IOCSelectorApp,
    ctx: &egui::Context,
    mut back_to_menu: impl FnMut(),
) {
    egui::CentralPanel::default()
        .frame(
            egui::Frame::default()
                .inner_margin(Margin::same(30.0))
                .outer_margin(Margin::same(20.0)),
        )
        .show(ctx, |ui| {
            if !app.overwrite_queue.is_empty() && app.overwrite_index < app.overwrite_queue.len() {
                egui::Window::new("⚠️ Overwrite Confirmation")
                    .collapsible(false)
                    .resizable(false)
                    .show(ctx, |ui| {
                        let (_url, ioc_type) = &app.overwrite_queue[app.overwrite_index];
                        let date_str = chrono::Local::now().format("%Y-%m-%d").to_string();
                        let ext = match app.output_format {
                            OutputFormat::Txt => "txt",
                            OutputFormat::Csv => "csv",
                        };
                        let _filename = format!("{}-{}.{}", ioc_type.to_lowercase(), date_str, ext);

                        ui.label("Some files already exist. What do you want to do?");
                        ui.horizontal(|ui| {
                            if ui.button("Overwrite").clicked() {
                                app.pending_urls
                                    .get_or_insert(Vec::new())
                                    .extend(app.overwrite_queue.drain(..));
                                app.overwrite_queue.clear();
                                app.overwrite_index = 0;
                                app.confirm_overwrite = false;
                            }
                            if ui.button("Overwrite All").clicked() {
                                app.yes_all = true;
                                app.pending_urls
                                    .get_or_insert(Vec::new())
                                    .extend(app.overwrite_queue.drain(..));
                                app.overwrite_index = 0;
                                app.overwrite_queue.clear();
                                app.confirm_overwrite = false;
                            }
                            if ui.button("Skip").clicked() {
                                app.overwrite_index += 1;
                            }
                            if ui.button("Skip All").clicked() {
                                app.skip_all = true;
                                app.overwrite_index = app.overwrite_queue.len();
                            }
                        });

                        if app.overwrite_index >= app.overwrite_queue.len() {
                            let format = match app.output_format {
                                OutputFormat::Txt => DownloadFormat::Txt,
                                OutputFormat::Csv => DownloadFormat::Csv,
                            };

                            let output_path = app
                                .custom_path
                                .clone()
                                .unwrap_or_else(|| "ioc_output".to_string());
                            let urls = app.pending_urls.take().unwrap_or_default();
                            app.overwrite_queue.clear();
                            app.overwrite_index = 0;
                            app.confirm_overwrite = false;
                            start_download(
                                urls,
                                format,
                                output_path,
                                Arc::clone(&app.progress),
                                ctx.clone(),
                            );
                        }
                    });
                return;
            }

            let mut show_progress = false;

            if let Ok(mut guard) = app.progress.lock() {
                if let Some((current, total)) = *guard {
                    show_progress = true;

                    let percent = (current as f32 / total as f32) * 100.0;
                    ui.label(format!("Progress: {}/{} ({:.0}%)", current, total, percent));
                    ui.add(egui::ProgressBar::new(percent / 100.0).show_percentage());

                    if current >= total {
                        *guard = None;
                        show_progress = false; // Reset for next render
                    }
                }
            }

            if !show_progress {
                ui.heading("Select IOC types to download:");

                for (i, name) in app.ioc_types.iter().enumerate() {
                    let _was_checked = app.selected[i];
                    let checkbox = ui.checkbox(&mut app.selected[i], *name);

                    if checkbox.clicked() {
                        if *name == "All" && app.selected[i] {
                            // Turn ON all others
                            for j in 0..app.ioc_types.len() {
                                app.selected[j] = true;
                            }
                        } else if *name == "All" && !app.selected[i] {
                            // Turn OFF all others
                            for j in 0..app.ioc_types.len() {
                                app.selected[j] = false;
                            }
                        } else {
                            // If any individual is unchecked, disable All
                            let all_index = app.ioc_types.iter().position(|&x| x == "All");
                            if let Some(idx) = all_index {
                                app.selected[idx] = false;
                            }

                            // If all individual are now selected, check All
                            let all_selected =
                                app.selected[..app.ioc_types.len() - 1].iter().all(|&v| v);
                            if all_selected {
                                if let Some(idx) = all_index {
                                    app.selected[idx] = true;
                                }
                            }
                        }
                    }
                }

                ui.separator();
                ui.label("Output format:");
                ui.radio_value(&mut app.output_format, OutputFormat::Txt, "TXT");
                ui.radio_value(&mut app.output_format, OutputFormat::Csv, "CSV");

                ui.add_space(10.0);
                ui.separator();
                ui.add_space(10.0);
                render_output_path_selector(ui, &mut app.custom_path, "./ioc_output");
                
                ui.add_space(20.0);
                if ui.button("Run Selected").clicked() {
                    let git_repos = vec![
                        "https://github.com/avast/ioc.git",
                        "https://github.com/DoctorWebLtd/malware-iocs.git",
                        "https://github.com/eset/malware-ioc.git",
                        "https://github.com/mandiant/iocs.git",
                        "https://github.com/GoSecure/malware-ioc.git",
                        "https://github.com/Neo23x0/signature-base.git",
                        "https://github.com/advanced-threat-research/IOCs.git",
                        "https://github.com/pan-unit42/iocs.git",
                        "https://github.com/prodaft/malware-ioc.git",
                        "https://github.com/RedDrip7/APT_Digital_Weapon.git",
                        "https://github.com/sophoslabs/IoCs.git",
                        "https://github.com/StrangerealIntel/DailyIOC.git",
                        "https://github.com/Infinit3i/IOC-Detections.git",
                    ];

                    let selected_types = app
                        .ioc_types
                        .iter()
                        .enumerate()
                        .filter_map(|(i, &name)| if app.selected[i] { Some(name) } else { None })
                        .collect::<Vec<_>>();

                    let git_types = vec!["MD5", "SHA1", "SHA256", "Domain", "IP"];
                    let selected_git_types: Vec<&str> = selected_types
                        .iter()
                        .cloned()
                        .filter(|ty| git_types.contains(ty))
                        .collect();

                    let output_path = app
                        .custom_path
                        .clone()
                        .unwrap_or_else(|| "ioc_output".to_string());

                    for repo in &git_repos {
                        process_git_iocs(repo, &output_path, &selected_git_types);
                    }

                    let date_str = chrono::Local::now().format("%Y-%m-%d").to_string();
                    let mut overwrite_conflict = false;

                    let mut all_urls: Vec<(String, String)> = Vec::new();
                    for &ioc_type in &selected_types {
                        let urls = get_urls_for_ioc_type(ioc_type);
                        for url in urls {
                            all_urls.push((url.to_string(), ioc_type.to_string()));
                        }
                    }

                    app.overwrite_queue.clear();
                    let ext = match app.output_format {
                        OutputFormat::Txt => "txt",
                        OutputFormat::Csv => "csv",
                    };

                    let download_format = match app.output_format {
                        OutputFormat::Txt => DownloadFormat::Txt,
                        OutputFormat::Csv => DownloadFormat::Csv,
                    };

                    for (url, ioc_type) in &all_urls {
                        let filename = format!("{}-{}.{}", ioc_type.to_lowercase(), date_str, ext);
                        let path = Path::new(&output_path).join(filename);
                        if path.exists() {
                            overwrite_conflict = true;
                            app.overwrite_queue.push((url.clone(), ioc_type.clone()));
                        }
                    }

                    if overwrite_conflict {
                        app.pending_urls = Some(all_urls);
                        app.confirm_overwrite = true;
                    } else {
                        start_download(
                            all_urls,
                            download_format,
                            output_path,
                            Arc::clone(&app.progress),
                            ctx.clone(),
                        );
                    }
                }
            }

            ui.add_space(30.0);
            ui.separator();
            ui.add_space(40.0);
            if ui
                .add(
                    egui::Button::new(
                        egui::RichText::new("⬅ Back to Menu").color(egui::Color32::WHITE),
                    )
                    .fill(egui::Color32::from_rgb(255, 140, 0)),
                )
                .clicked()
            {
                back_to_menu();
            }
        });
}

pub fn process_git_iocs(repo_url: &str, output_path: &str, _selected_types: &[&str]) {
    let repo_name = repo_url
        .split('/')
        .last()
        .unwrap_or("repo")
        .replace(".git", "");
    let clone_path = format!("./tmp_git_iocs/{}", repo_name);

    if let Err(e) = Repository::clone(repo_url, &clone_path) {
        eprintln!("❌ Failed to clone {}: {}", repo_url, e);
        return;
    }

    let mut domains = HashSet::new();
    let mut ips = HashSet::new();
    let mut sha256s = HashSet::new();
    let mut sha1s = HashSet::new();
    let mut md5s = HashSet::new();

    let domain_re =
        Regex::new(r"(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b").unwrap();
    let ip_re = Regex::new(r"\b\d{1,3}(?:\.\d{1,3}){3}\b").unwrap();
    let sha256_re = Regex::new(r"\b[a-fA-F0-9]{64}\b").unwrap();
    let sha1_re = Regex::new(r"\b[a-fA-F0-9]{40}\b").unwrap();
    let md5_re = Regex::new(r"\b[a-fA-F0-9]{32}\b").unwrap();

    for entry in WalkDir::new(&clone_path).into_iter().filter_map(Result::ok) {
        let path = entry.path();
        if path.is_file() {
            if let Ok(content) = std::fs::read_to_string(path) {
                for line in content.lines() {
                    for m in domain_re.find_iter(line) {
                        domains.insert(m.as_str().to_string());
                    }
                    for m in ip_re.find_iter(line) {
                        ips.insert(m.as_str().to_string());
                    }
                    for m in sha256_re.find_iter(line) {
                        sha256s.insert(m.as_str().to_string());
                    }
                    for m in sha1_re.find_iter(line) {
                        sha1s.insert(m.as_str().to_string());
                    }
                    for m in md5_re.find_iter(line) {
                        md5s.insert(m.as_str().to_string());
                    }
                }
            }
        }
    }

    let date_str = chrono::Local::now().format("%Y-%m-%d").to_string();
    let save = |name: &str, data: &HashSet<String>| {
        if !data.is_empty() {
            let path = Path::new(output_path).join(format!("{}-{}.txt", name, date_str));
            let joined = data.iter().cloned().collect::<Vec<_>>().join("\n");
            if let Err(e) = fs::write(&path, joined) {
                eprintln!("❌ Failed to write {}: {}", name, e);
            } else {
                println!("✅ Saved {} IOCs to {}", name, path.display());
            }
        }
    };

    save("domain", &domains);
    save("ip", &ips);
    save("sha256", &sha256s);
    save("sha1", &sha1s);
    save("md5", &md5s);
}

fn get_urls_for_ioc_type(ioc_type: &str) -> Vec<&'static str> {
    match ioc_type {
        "Filename" => vec!["https://www.botvrij.eu/data/ioclist.filename"],
        "SHA256" => vec!["https://www.botvrij.eu/data/ioclist.sha256"],
        "SHA1" => vec![
            "https://www.botvrij.eu/data/ioclist.sha1",
            "https://raw.githubusercontent.com/bitdefender/malware-ioc/refs/heads/master/dark_nexus/all_bots.txt",
        ],
        "MD5" => vec!["https://www.botvrij.eu/data/ioclist.md5"],
        "IP" => vec![
            "https://www.binarydefense.com/banlist.txt",
            "https://www.botvrij.eu/data/ioclist.ip-dst",
            "https://cinsscore.com/list/ci-badguys.txt",
            "https://osint.bambenekconsulting.com/feeds/c2-ipmasterlist.txt",
            "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt",
            "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
            "https://feodotracker.abuse.ch/downloads/ipblocklist_aggressive.txt",
            "https://iplists.firehol.org/files/firehol_level1.netset",
            "https://iplists.firehol.org/files/firehol_level2.netset",
            "https://iplists.firehol.org/files/firehol_level3.netset",
            "https://lists.blocklist.de/lists/all.txt",
            "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
            "https://gist.githubusercontent.com/BBcan177/bf29d47ea04391cb3eb0/raw/",
            "https://danger.rulez.sk/projects/bruteforceblocker/blist.php",
            "https://blocklist.greensnow.co/greensnow.txt",
            "https://raw.githubusercontent.com/LinuxTracker/Blocklists/master/HancitorIPs.txt",
            "https://www.dan.me.uk/torlist/",
            "https://zerodot1.deteque.com/main/ipfeeds/bad/ZeroDot1sBadIPs.txt",
            "https://zerodot1.deteque.com/main/ipfeeds/mining/ZeroDot1sMinerIPsLATEST.txt",
            "https://raw.githubusercontent.com/tesla-consulting/ioc-list/refs/heads/main/iplist.csv",
            "https://raw.githubusercontent.com/securityscorecard/SSC-Threat-Intel-IoCs/refs/heads/master/KillNet-DDoS-Blocklist/ipblocklist.txt",
        ],
        "Domain" => vec![
            "https://www.botvrij.eu/data/ioclist.domain",
            "https://gist.githubusercontent.com/BBcan177/4a8bf37c131be4803cb2/raw",
            "https://www.joewein.net/dl/bl/dom-bl.txt",
            "https://gist.githubusercontent.com/BBcan177/bf29d47ea04391cb3eb0/raw/",
            "https://raw.githubusercontent.com/Hestat/minerchk/master/hostslist.txt",
            "https://isc.sans.edu/feeds/suspiciousdomains_High.txt",
            "https://isc.sans.edu/feeds/suspiciousdomains_Medium.txt",
            "https://raw.githubusercontent.com/bitdefender/malware-ioc/refs/heads/master/metamorfo_malware/domains.txt",
        ],
        "URL" => vec![
            "https://www.botvrij.eu/data/ioclist.url",
            "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt",
            "https://urlhaus.abuse.ch/downloads/text/",
            "https://urlhaus.abuse.ch/downloads/text_recent/",
        ],
        "Email" => vec![
            "https://www.botvrij.eu/data/ioclist.email-src",
            "https://raw.githubusercontent.com/WSTNPHX/scripts-n-tools/master/malware-email-addresses.txt",
        ],
        "Registry" => vec!["https://www.botvrij.eu/data/ioclist.regkey"],
        _ => vec![],
    }
}
