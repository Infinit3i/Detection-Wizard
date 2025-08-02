use crate::ioc_menu::IOCSelectorApp;
use eframe::egui;
use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::thread;

fn get_current_date_string() -> String {
    chrono::Local::now().format("%Y-%m-%d").to_string()
}

fn fetch_and_append_to_file(
    url: &str,
    ioc_type: &str,
    mut progress_callback: Option<&mut dyn FnMut()>,
) {
    let date_str = chrono::Local::now().format("%Y-%m-%d").to_string();
    let filename = format!("{}-{}.txt", ioc_type.to_lowercase(), date_str);
    let out_dir = Path::new("ioc_output");
    let out_path = out_dir.join(filename);

    fs::create_dir_all(out_dir).unwrap();

    match reqwest::blocking::get(url) {
        Ok(response) => match response.text() {
            Ok(text) => {
                let mut existing = String::new();
                if out_path.exists() {
                    if let Ok(existing_text) = fs::read_to_string(&out_path) {
                        existing = existing_text;
                    }
                }

                let combined = format!("{}\n{}", existing.trim(), text.trim());
                if let Err(e) = fs::write(&out_path, combined.as_bytes()) {
                    eprintln!("❌ Failed to write to {}: {}", out_path.display(), e);
                } else {
                    println!("✅ Appended {} to {}", url, out_path.display());
                }
            }
            Err(e) => println!("❌ Failed to read text from {}: {}", url, e),
        },
        Err(e) => println!("❌ Failed to fetch from {}: {}", url, e),
    }

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

                let mut all_urls: Vec<(&str, &str)> = Vec::new();
                for &ioc_type in &selected_types {
                    for &url in get_urls_for_ioc_type(ioc_type).iter() {
                        all_urls.push((url, ioc_type));
                    }
                }

                let total = all_urls.len();
                let progress = Arc::clone(&app.progress);
                *progress.lock().unwrap() = Some((0, total));
                let ctx = ctx.clone();

                thread::spawn(move || {
                    let mut completed = 0;
                    for (url, ioc_type) in all_urls {
                        fetch_and_append_to_file(
                            url,
                            ioc_type,
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
