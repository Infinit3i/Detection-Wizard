use crate::ioc_menu::{IOCSelectorApp, OutputFormat};
use eframe::egui;
use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::sync::Mutex;
use std::thread;

fn start_download(
    all_urls: Vec<(String, String)>,
    format: OutputFormat,
    output_path: String,
    progress: Arc<Mutex<Option<(usize, usize)>>>,
    ctx: egui::Context,
) {
    let total = all_urls.len();
    *progress.lock().unwrap() = Some((0, total));

    thread::spawn(move || {
        let mut completed = 0;
        for (url, ioc_type) in all_urls {
            fetch_and_append_to_file(
                &url,
                &ioc_type,
                &format,
                &output_path,
                Some(&mut || {
                    completed += 1;
                    if let Ok(mut p) = progress.lock() {
                        *p = Some((completed, total));
                    }
                    ctx.request_repaint();
                }),
            );
        }
    });
}

fn fetch_and_append_to_file(
    url: &str,
    ioc_type: &str,
    format: &OutputFormat,
    base_path: &str,
    mut progress_callback: Option<&mut dyn FnMut()>,
) {
    let date_str = chrono::Local::now().format("%Y-%m-%d").to_string();

    // Correct extension
    let extension = match format {
        OutputFormat::Txt => "txt",
        OutputFormat::Csv => "csv",
    };

    // Correct output filename and path
    let filename = format!("{}-{}.{}", ioc_type.to_lowercase(), date_str, extension);
    let out_path = Path::new(base_path).join(filename);

    // Ensure output directory exists
    if let Some(parent) = out_path.parent() {
        if let Err(e) = fs::create_dir_all(parent) {
            eprintln!("❌ Failed to create directory {}: {}", parent.display(), e);
            return;
        }
    }

    // Download content
    match reqwest::blocking::get(url) {
        Ok(response) => match response.text() {
            Ok(text) => {
                let mut existing = String::new();
                if out_path.exists() {
                    if let Ok(existing_text) = fs::read_to_string(&out_path) {
                        existing = existing_text;
                    }
                }

                let combined = match format {
                    OutputFormat::Txt => format!("{}\n{}", existing.trim(), text.trim()),
                    OutputFormat::Csv => {
                        // Rough CSV concat — customize if needed
                        format!("{},{}", existing.trim(), text.trim().replace('\n', ","))
                    }
                };

                if let Err(e) = fs::write(&out_path, combined.as_bytes()) {
                    eprintln!("❌ Failed to write to {}: {}", out_path.display(), e);
                } else {
                    println!("✅ Appended {} to {}", url, out_path.display());
                }
            }
            Err(e) => eprintln!("❌ Failed to read content from {}: {}", url, e),
        },
        Err(e) => eprintln!("❌ Failed to fetch {}: {}", url, e),
    }

    // Progress callback
    if let Some(cb) = progress_callback.as_mut() {
        cb();
    }
}

pub fn render_ui_ioc(
    app: &mut IOCSelectorApp,
    ctx: &egui::Context,
    mut back_to_menu: impl FnMut(),
) {
    egui::CentralPanel::default().show(ctx, |ui| {
        if !app.overwrite_queue.is_empty() && app.overwrite_index < app.overwrite_queue.len() {
            egui::Window::new("⚠️ Overwrite Confirmation")
                .collapsible(false)
                .resizable(false)
                .show(ctx, |ui| {
                    let (url, ioc_type) = &app.overwrite_queue[app.overwrite_index];
                    let date_str = chrono::Local::now().format("%Y-%m-%d").to_string();
                    let ext = match app.output_format {
                        OutputFormat::Txt => "txt",
                        OutputFormat::Csv => "csv",
                    };
                    let filename = format!("{}-{}.{}", ioc_type.to_lowercase(), date_str, ext);

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
                        let format = app.output_format.clone();
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
                ui.checkbox(&mut app.selected[i], *name);
            }

            ui.separator();
            ui.label("Output format:");
            ui.radio_value(&mut app.output_format, OutputFormat::Txt, "TXT");
            ui.radio_value(&mut app.output_format, OutputFormat::Csv, "CSV");

            ui.separator();
            if ui.button("Choose Output Folder").clicked() {
                if let Some(path) = rfd::FileDialog::new().pick_folder() {
                    app.custom_path = Some(path.display().to_string());
                }
            }

            if let Some(path) = &app.custom_path {
                ui.label(format!("Save path: {}", path));
            } else {
                ui.label("Save path: ./ioc_output (default)");
            }

            if ui.button("Run Selected").clicked() {
                let selected_types = app
                    .ioc_types
                    .iter()
                    .enumerate()
                    .filter_map(|(i, &name)| if app.selected[i] { Some(name) } else { None })
                    .collect::<Vec<_>>();

                if selected_types.is_empty() {
                    return;
                }

                let output_path = app
                    .custom_path
                    .clone()
                    .unwrap_or_else(|| "ioc_output".to_string());

                let format = app.output_format.clone();
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
                for (url, ioc_type) in &all_urls {
                    let ext = match format {
                        OutputFormat::Txt => "txt",
                        OutputFormat::Csv => "csv",
                    };
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
                        format,
                        output_path,
                        Arc::clone(&app.progress),
                        ctx.clone(),
                    );
                }
            }

            ui.separator();
        }

        if ui.button("⬅ Back to Menu").clicked() {
            back_to_menu();
        }
    });
}

fn get_urls_for_ioc_type(ioc_type: &str) -> Vec<&'static str> {
    match ioc_type {
        "Filename" => vec!["https://www.botvrij.eu/data/ioclist.filename"],
        "SHA256" => vec!["https://www.botvrij.eu/data/ioclist.sha256"],
        "SHA1" => vec!["https://www.botvrij.eu/data/ioclist.sha1"],
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

fn fetch(url: &str, mut progress_callback: Option<&mut dyn FnMut()>) {
    let filename = match url {
        "https://www.botvrij.eu/data/ioclist.filename" => "filename.txt",
        "https://www.botvrij.eu/data/ioclist.sha256" => "sha256.txt",
        "https://www.botvrij.eu/data/ioclist.sha1" => "sha1.txt",
        "https://www.botvrij.eu/data/ioclist.md5" => "md5.txt",
        "https://www.binarydefense.com/banlist.txt" => "ip1_binarydefense.txt",
        "https://www.botvrij.eu/data/ioclist.ip-dst" => "ip2_botvrij.txt",
        "https://cinsscore.com/list/ci-badguys.txt" => "ip3_cins.txt",
        "https://www.botvrij.eu/data/ioclist.domain" => "domain.txt",
        "https://www.botvrij.eu/data/ioclist.url" => "url.txt",
        "https://www.botvrij.eu/data/ioclist.email-src" => "email.txt",
        "https://www.botvrij.eu/data/ioclist.regkey" => "registry.txt",
        _ => "unknown.txt",
    };

    let out_dir = Path::new("ioc_output");
    let out_path = out_dir.join(filename);

    fs::create_dir_all(out_dir).unwrap();

    match reqwest::blocking::get(url) {
        Ok(response) => match response.text() {
            Ok(text) => {
                fs::write(&out_path, text.as_bytes()).unwrap();
                println!("✅ Saved {} to {}", filename, out_path.display());
            }
            Err(e) => println!("Failed to read text from {}: {}", url, e),
        },
        Err(e) => println!("Failed to fetch from {}: {}", url, e),
    }
    println!("✅ Saved {} to {}", filename, out_path.display());
    if let Some(cb) = progress_callback.as_mut() {
        cb();
    }
}
