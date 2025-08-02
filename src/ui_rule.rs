use crate::download::render_output_path_selector;
use crate::download::{start_download, DownloadFormat};
use crate::rule_menu::ToolSelectorApp;
use crate::{sigma, splunk, suricata, yara};
use eframe::egui;
use eframe::egui::IconData;
use egui::Margin;
use std::sync::{Arc, Mutex};
use std::thread;

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

fn run_tool_with_progress<F>(
    ctx: egui::Context,
    progress: Arc<Mutex<Option<(usize, usize)>>>,
    mut tool_fn: F,
) where
    F: FnMut(&mut dyn FnMut(usize, usize)) + Send + 'static,
{
    thread::spawn(move || {
        let mut update_progress = |current: usize, total: usize| {
            if let Ok(mut guard) = progress.lock() {
                *guard = Some((current, total));
            }
            ctx.request_repaint();
        };

        tool_fn(&mut update_progress);
    });
}

pub fn render_ui(app: &mut ToolSelectorApp, ctx: &egui::Context, mut back_to_menu: impl FnMut()) {
    egui::CentralPanel::default()
        .frame(
            egui::Frame::default()
                .inner_margin(Margin::same(30.0))
                .outer_margin(Margin::same(20.0)),
        )
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
                            // Turn ON all
                            for j in 0..app.tool_names.len() {
                                app.selected[j] = true;
                            }
                        } else if *name == "All" && !app.selected[i] {
                            // Turn OFF all
                            for j in 0..app.tool_names.len() {
                                app.selected[j] = false;
                            }
                        } else {
                            // If any individual is toggled off, uncheck All
                            let all_index = app.tool_names.iter().position(|&x| x == "All");
                            if let Some(idx) = all_index {
                                app.selected[idx] = false;
                            }

                            // If all individuals are now selected, check All
                            let all_selected =
                                app.selected[..app.tool_names.len() - 1].iter().all(|&v| v);
                            if all_selected {
                                if let Some(idx) = app.tool_names.iter().position(|&x| x == "All") {
                                    app.selected[idx] = true;
                                }
                            }
                        }
                    }
                }

                render_output_path_selector(ui, &mut app.custom_path, "./rule_output");
                ui.separator();

                if ui.button("Run Selected").clicked() {
                    let ctx = ctx.clone();
                    let progress = Arc::clone(&app.progress);


                    if app.selected[4] {
                        run_tool_with_progress(ctx.clone(), Arc::clone(&progress), |cb| {
                            yara::process_yara(Some(cb));
                        });
                        run_tool_with_progress(ctx.clone(), Arc::clone(&progress), |cb| {
                            sigma::process_sigma(Some(cb));
                        });
                        run_tool_with_progress(ctx.clone(), Arc::clone(&progress), |cb| {
                            suricata::process_suricata(Some(cb));
                        });
                        run_tool_with_progress(ctx.clone(), Arc::clone(&progress), |cb| {
                            splunk::process_splunk(Some(cb));
                        });
                    } else {
                        for (i, selected) in app.selected.iter().enumerate() {
                            if *selected {
                                let ctx = ctx.clone();
                                let progress = Arc::clone(&progress);
                                match app.tool_names[i] {
                                    "Yara" => run_tool_with_progress(ctx, progress, |cb| {
                                        yara::process_yara(Some(cb));
                                    }),
                                    "Sigma" => run_tool_with_progress(ctx, progress, |cb| {
                                        sigma::process_sigma(Some(cb));
                                    }),
                                    "Suricata" => run_tool_with_progress(ctx, progress, |cb| {
                                        suricata::process_suricata(Some(cb));
                                    }),
                                    "Splunk" => run_tool_with_progress(ctx, progress, |cb| {
                                        splunk::process_splunk(Some(cb));
                                    }),
                                    _ => {}
                                }
                            }
                        }
                    }
                }
            }

            ui.separator();

            if ui
                .add(
                    egui::Button::new(
                        egui::RichText::new("⬅ Back to Menu").color(egui::Color32::WHITE),
                    )
                    .fill(egui::Color32::from_rgb(255, 140, 0)), // Orange
                )
                .clicked()
            {
                back_to_menu();
                return;
            }
        });
}
