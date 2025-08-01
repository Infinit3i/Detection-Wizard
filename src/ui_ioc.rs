use crate::ioc_menu::IOCSelectorApp;
use eframe::egui;
use std::sync::Arc;
use std::thread;
use std::fs;
use std::path::Path;

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

                let ctx = ctx.clone();
                let progress = Arc::clone(&app.progress);
                let total = selected_types.len();

                *progress.lock().unwrap() = Some((0, total));

                thread::spawn(move || {
                    for (i, ioc_type) in selected_types.iter().enumerate() {
                        download_ioc(ioc_type);
                        if let Ok(mut p) = progress.lock() {
                            *p = Some((i + 1, total));
                        }
                        ctx.request_repaint();
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


fn download_ioc(ioc_type: &str) {
    match ioc_type {
        "Filename" => fetch("https://www.botvrij.eu/data/ioclist.filename"),
        "SHA256" => fetch("https://www.botvrij.eu/data/ioclist.sha256"),
        "SHA1" => fetch("https://www.botvrij.eu/data/ioclist.sha1"),
        "MD5" => fetch("https://www.botvrij.eu/data/ioclist.md5"),
        "IP" => {
            fetch("https://www.binarydefense.com/banlist.txt");
            fetch("https://www.botvrij.eu/data/ioclist.ip-dst");
            fetch("https://cinsscore.com/list/ci-badguys.txt");
            fetch("https://osint.bambenekconsulting.com/feeds/c2-ipmasterlist.txt");
            fetch("https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt");
            fetch("https://feodotracker.abuse.ch/downloads/ipblocklist.txt");
            fetch("https://feodotracker.abuse.ch/downloads/ipblocklist_aggressive.txt");
            fetch("https://iplists.firehol.org/files/firehol_level1.netset");
            fetch("https://iplists.firehol.org/files/firehol_level2.netset");
            fetch("https://iplists.firehol.org/files/firehol_level3.netset");
            fetch("https://lists.blocklist.de/lists/all.txt");
            fetch("https://rules.emergingthreats.net/blockrules/compromised-ips.txt");
            fetch("https://gist.githubusercontent.com/BBcan177/bf29d47ea04391cb3eb0/raw/");
            fetch("https://danger.rulez.sk/projects/bruteforceblocker/blist.php");
            fetch("https://blocklist.greensnow.co/greensnow.txt");
            fetch("https://raw.githubusercontent.com/LinuxTracker/Blocklists/master/HancitorIPs.txt");
            fetch("https://www.dan.me.uk/torlist/");
            fetch("https://zerodot1.deteque.com/main/ipfeeds/bad/ZeroDot1sBadIPs.txt");
            fetch("https://zerodot1.deteque.com/main/ipfeeds/mining/ZeroDot1sMinerIPsLATEST.txt");
            fetch("");
            fetch("");
            fetch("");
            fetch("https://raw.githubusercontent.com/securityscorecard/SSC-Threat-Intel-IoCs/refs/heads/master/KillNet-DDoS-Blocklist/ipblocklist.txt");
        }
        "Domain" => {
        fetch("https://www.botvrij.eu/data/ioclist.domain");
        fetch("https://gist.githubusercontent.com/BBcan177/4a8bf37c131be4803cb2/raw");
        fetch("https://www.joewein.net/dl/bl/dom-bl.txt");
        fetch("https://gist.githubusercontent.com/BBcan177/bf29d47ea04391cb3eb0/raw/");
        fetch("https://raw.githubusercontent.com/Hestat/minerchk/master/hostslist.txt");
        fetch("https://raw.githubusercontent.com/Hestat/minerchk/master/hostslist.txt");
        }
        "URL" => { 
        fetch("https://www.botvrij.eu/data/ioclist.url");
        fetch("https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt");
        fetch("https://urlhaus.abuse.ch/downloads/text/");
        fetch("https://urlhaus.abuse.ch/downloads/text_recent/");
        }
        "Email" => {
        fetch("https://www.botvrij.eu/data/ioclist.email-src");
        fetch("https://raw.githubusercontent.com/WSTNPHX/scripts-n-tools/master/malware-email-addresses.txt");
        }
        "Registry" => fetch("https://www.botvrij.eu/data/ioclist.regkey"),
        _ => {}
    }
}



fn fetch(url: &str) {
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
}
