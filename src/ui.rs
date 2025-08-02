use crate::app::ToolSelectorApp;
use crate::{sigma, splunk, suricata, yara};
use eframe::egui;
use eframe::egui::IconData;
use std::sync::{Arc, Mutex};
use std::thread;
use egui::Margin;


pub fn load_icon(path: &str) -> Option<IconData> {
    let img = image::open(path).ok()?.into_rgba8();
    let (width, height) = img.dimensions();
    let rgba = img.into_raw();
    Some(IconData {
        rgba,
        width,
        height,
    })
}

pub fn render_ui(app: &mut ToolSelectorApp, ctx: &egui::Context, mut back_to_menu: impl FnMut()) {
    egui::CentralPanel::default()
        .frame(egui::Frame::default().inner_margin(Margin::same(30.0)).outer_margin(Margin::same(20.0)))
        .show(ctx, |ui| {
            let show_progress = false;

            if let Ok(mut guard) = app.progress.lock() {
                if let Some((current, total)) = *guard {
                    let percent = (current as f32 / total as f32) * 100.0;
                    ui.label(format!("Progress: {}/{} ({:.0}%)", current, total, percent));
                    ui.add(egui::ProgressBar::new(percent / 100.0).show_percentage());

                    if current >= total {
                        *guard = None; // Reset progress after completion
                    } else {
                        return; // Don't show selection UI while running
                    }
                }
            }

            // Only show selectors if not showing progress
            if !show_progress {
                ui.heading("Select tools to run:");

                for (i, name) in app.tool_names.iter().enumerate() {
                    let was_checked = app.selected[i];
                    let checkbox = ui.checkbox(&mut app.selected[i], *name);

                    if checkbox.clicked() {
                        if *name == "All" && app.selected[i] {
                            for j in 0..app.tool_names.len() - 1 {
                                app.selected[j] = false;
                            }
                        } else if *name != "All" && app.selected[i] {
                            app.selected[app.tool_names.len() - 1] = false;
                        }
                    }

                    if *name == "All" && !was_checked && app.selected[i] {
                        for j in 0..app.tool_names.len() - 1 {
                            app.selected[j] = false;
                        }
                    }
                }

                if ui.button("Run Selected").clicked() {
                    // Create new progress tracker and assign to app before it gets borrowed
                    let progress = Arc::new(Mutex::new(Some((0, 1))));
                    app.progress = Arc::clone(&progress);

                    let ctx = ctx.clone();

                    if app.selected[4] {
                        // Run All
                        thread::spawn({
                            let ctx = ctx.clone();
                            let progress = Arc::clone(&progress);
                            move || {
                                yara::process_yara(Some(&mut |current, total| {
                                    if let Ok(mut p) = progress.lock() {
                                        *p = Some((current, total));
                                    }
                                    ctx.request_repaint();
                                }));
                                suricata::process_suricata();
                                sigma::process_sigma();
                                splunk::process_splunk();
                            }
                        });
                    } else {
                        for (i, selected) in app.selected.iter().enumerate() {
                            if *selected {
                                match app.tool_names[i] {
                                    "Yara" => {
                                        let ctx = ctx.clone();
                                        let progress = Arc::clone(&progress);
                                        thread::spawn(move || {
                                            yara::process_yara(Some(&mut |current, total| {
                                                if let Ok(mut p) = progress.lock() {
                                                    *p = Some((current, total));
                                                }
                                                ctx.request_repaint();
                                            }));
                                        });
                                    }
                                    "Suricata" => {
                                        thread::spawn(|| {
                                            suricata::process_suricata();
                                        });
                                    }
                                    "Sigma" => {
                                        thread::spawn(|| {
                                            sigma::process_sigma();
                                        });
                                    }
                                    "Splunk" => {
                                        thread::spawn(|| {
                                            splunk::process_splunk();
                                        });
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }
                }
            }
            ui.separator();

            if ui.button("⬅ Back to Menu").clicked() {
                back_to_menu();
                return;
            }
        });
}
