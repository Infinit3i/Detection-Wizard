use crate::download::render_output_path_selector;
use crate::rule_menu::ToolSelectorApp;
use crate::{qradar, sigma, splunk, suricata, yara};
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
                    if let Ok(f) = app.current_file.lock() {
                        if let Some(name) = &*f {
                            ui.label(format!("Currently processing: {}", name));
                        }
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
                                if let Ok(mut cancel) = app.cancel_flag.lock() {
                                    *cancel = true;
                                }
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
                if ui.button("Run Selected").clicked() {
                    let ctx = ctx.clone();
                    let custom_path = app
                        .custom_path
                        .clone()
                        .unwrap_or_else(|| "./rule_output".to_string());
                    let selected_tools: Vec<&str> = ["Yara", "Suricata", "Sigma", "Splunk"]
                        .iter()
                        .enumerate()
                        .filter(|(i, _)| app.selected[*i] || app.selected[4])
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
                            _ => {}
                        }
                    }

                    // Reset progress state
                    if let Ok(mut p) = app.progress.lock() {
                        *p = Some((0, total_work));
                    }

                    // Then spawn each tool in parallel
                    for tool in selected_tools {
                        let ctx = ctx.clone();
                        let progress = Arc::clone(&app.progress);
                        let current_file = Arc::clone(&app.current_file);
                        let cancel_flag = Arc::new(Mutex::new(false));
                        let out_path = format!("{}/{}", custom_path, tool.to_lowercase());

                        run_tool_with_progress(
                            ctx,
                            Arc::clone(&progress),
                            Arc::clone(&current_file),
                            Arc::clone(&cancel_flag),
                            move |cb| match tool {
                                "Yara" => {
                                    yara::process_yara(
                                        &out_path,
                                        Some(&mut |cur, _total, file| {
                                            cb(cur, total_work, file);
                                        }),
                                    );
                                }
                                "Suricata" => {
                                    suricata::process_suricata_rules(
                                        vec![out_path.clone().into()],
                                        out_path.clone().into(),
                                        Some(&mut |cur, _total, file| {
                                            cb(cur, total_work, file);
                                        }),
                                    );
                                }
                                "Sigma" => {
                                    sigma::process_sigma(Some(&mut |cur, _| {
                                        cb(cur, total_work, "sigma".to_string());
                                    }));
                                }
                                "Splunk" => {
                                    splunk::process_splunk(Some(&mut |cur, _| {
                                        cb(cur, total_work, "splunk".to_string());
                                    }));
                                }
                                "QRadar" => {
                                    // Add this case
                                    qradar::process_qradar(Some(&mut |cur, _| {
                                        cb(cur, total_work, "qradar".to_string());
                                    }));
                                }
                                _ => {}
                            },
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
