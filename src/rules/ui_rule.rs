use super::rule_menu::ToolSelectorApp;
use super::{qradar, sigma, splunk, suricata, sysmon, yara};
use crate::download::render_output_path_selector;
use eframe::egui;
use egui::Margin;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::thread;

fn run_tool_with_progress<F>(
    ctx: egui::Context,
    progress: Arc<Mutex<Option<(usize, usize)>>>,
    current_file: Arc<Mutex<Option<String>>>,
    cancel_flag: Arc<Mutex<bool>>, // ← ADD
    mut tool_fn: F,
) where
    F: FnMut(&mut dyn FnMut(usize, usize, String) -> bool) + Send + 'static, // ← returns bool now
{
    thread::spawn(move || {
        let mut update_progress = |current: usize, total: usize, file: String| -> bool {
            if let Ok(cancelled) = cancel_flag.lock() {
                if *cancelled {
                    return false;
                }
            }

            if let Ok(mut p) = progress.lock() {
                *p = Some((current, total));
            }
            if let Ok(mut f) = current_file.lock() {
                *f = Some(file);
            }
            ctx.request_repaint();
            true
        };

        tool_fn(&mut update_progress);
    });
}

pub fn render_ui(app: &mut ToolSelectorApp, ctx: &egui::Context, mut back_to_menu: impl FnMut()) {
    egui::CentralPanel::default()
        .frame(
            egui::Frame::default()
                .inner_margin(Margin::same(30))
                .outer_margin(Margin::same(20)),
        )
        .show(ctx, |ui| {
            let show_progress = false;

            if let Ok(mut guard) = app.progress.lock() {
                if let Some((current, total, ref current_name)) = *guard {
                    let percent = (current as f32 / total.max(1) as f32) * 100.0;
                    ui.label(format!("Progress: {}/{} ({:.0}%)", current, total, percent));
                    ui.add(egui::ProgressBar::new(percent / 100.0).show_percentage());
                    if !current_name.is_empty() {
                        ui.label(format!("Currently processing: {}", current_name));
                    }

                    if current >= total {
                        ui.vertical_centered(|ui| {
                            ui.add_space(20.0);
                            ui.heading(egui::RichText::new("✅ COMPLETE ✅").size(60.0));
                            ui.add_space(20.0);
                            if ui
                                .add(
                                    egui::Button::new(
                                        egui::RichText::new("Done")
                                            .size(24.0)
                                            .color(egui::Color32::WHITE),
                                    )
                                    .fill(egui::Color32::from_rgb(0, 128, 0)),
                                )
                                .clicked()
                            {
                                *guard = None;
                                app.cancel_flag.store(true, Ordering::Relaxed);
                            }
                        });

                        return;
                    } else {
                        return;
                    }
                }
            }

            // Only show selectors if not showing progress
            if !show_progress {
                ui.heading("Select tools to run:");

                for (i, name) in app.tool_names.iter().enumerate() {
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
                ui.add_space(10.0);
                ui.separator();
                ui.add_space(10.0);
                render_output_path_selector(ui, &mut app.custom_path, "./rule_output");

                ui.add_space(20.0);
                let any_selected = app.selected.iter().any(|&v| v);

                if ui
                    .add_enabled(any_selected, egui::Button::new("Run Selected"))
                    .clicked()
                {
                    let ctx = ctx.clone();
                    let custom_path = app
                        .custom_path
                        .clone()
                        .unwrap_or_else(|| "./rule_output".to_string());

                    // Find the "All" index dynamically
                    let all_index = app.tool_names.iter().position(|&x| x == "All");

                    // Get all available tools (excluding "All")
                    let available_tools: Vec<&str> = app
                        .tool_names
                        .iter()
                        .filter(|&&name| name != "All")
                        .cloned()
                        .collect();

                    // Filter selected tools based on individual selection or "All" selection
                    let selected_tools: Vec<&str> = available_tools
                        .iter()
                        .enumerate()
                        .filter(|(i, _)| {
                            // Check if this specific tool is selected OR if "All" is selected
                            app.selected[*i]
                                || (all_index.is_some() && app.selected[all_index.unwrap()])
                        })
                        .map(|(_, &tool)| tool)
                        .collect();

                    // Estimate total work by summing counts for selected tools
                    let mut total_work = 0;
                    for &tool in &selected_tools {
                        match tool {
                            "Yara" => total_work += yara::yara_total_sources(),
                            "Suricata" => total_work += suricata::suricata_total_sources(),
                            "Sigma" => total_work += sigma::sigma_total_sources(),
                            "Splunk" => total_work += splunk::splunk_total_sources(),
                            "QRadar" => total_work += qradar::qradar_total_sources(),
                            "Sysmon" => total_work += sysmon::sysmon_total_sources(),
                            _ => {}
                        }
                    }

                    // Reset progress state (triplet!)
                    if let Ok(mut p) = app.progress.lock() {
                        *p = Some((0, total_work, String::new()));
                    }

                    // spawn one thread per tool
                    for tool in selected_tools {
                        let out_path = custom_path.clone();
                        let progress_triplet = Arc::clone(&app.progress);
                        let cancel_flag = Arc::clone(&app.cancel_flag);
                        let ctx_clone = ctx.clone();

                        std::thread::spawn(move || match tool {
                            "Yara" => yara::process_yara(
                                &out_path,
                                Arc::clone(&progress_triplet),
                                ctx_clone.clone(),
                                Arc::clone(&cancel_flag),
                            ),
                            "Suricata" => suricata::process_suricata(
                                &out_path,
                                Arc::clone(&progress_triplet),
                                ctx_clone.clone(),
                                Arc::clone(&cancel_flag),
                            ),
                            "Sigma" => sigma::process_sigma(
                                &out_path,
                                Arc::clone(&progress_triplet),
                                ctx_clone.clone(),
                                Arc::clone(&cancel_flag),
                            ),
                            "Splunk" => splunk::process_splunk(
                                &out_path,
                                Arc::clone(&progress_triplet),
                                ctx_clone.clone(),
                                Arc::clone(&cancel_flag),
                            ),
                            "QRadar" => qradar::process_qradar(
                                &out_path,
                                Arc::clone(&progress_triplet),
                                ctx_clone.clone(),
                                Arc::clone(&cancel_flag),
                            ),
                            "Sysmon" => sysmon::process_sysmon(
                                &out_path,
                                Arc::clone(&progress_triplet),
                                ctx_clone.clone(),
                                Arc::clone(&cancel_flag),
                            ),
                            _ => {}
                        });
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
