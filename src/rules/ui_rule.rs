use super::rule_menu::ToolSelectorApp;
use super::{qradar, sigma, splunk, suricata, sysmon, yara};
use crate::apt_catalog::{expand_terms, APT_GROUPS};
use crate::azure_tables::AZURE_TABLES;
use crate::download::render_output_path_selector;
use crate::filter::{CompiledFilter, LOG_SOURCES};
use crate::splunk_sourcetypes::SPLUNK_SOURCETYPES;
use crate::ttp_catalog::TTP_CATALOG;
use eframe::egui;
use egui::Margin;
use std::sync::atomic::Ordering;
use std::sync::Arc;

pub fn render_ui(app: &mut ToolSelectorApp, ctx: &egui::Context, mut back_to_menu: impl FnMut()) {
    egui::CentralPanel::default()
        .frame(
            egui::Frame::default()
                .inner_margin(Margin::same(30))
                .outer_margin(Margin::same(20)),
        )
        .show(ctx, |ui| {
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
                    }
                    return;
                }
            }

            egui::ScrollArea::vertical().show(ui, |ui| {
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

                // ---------- Log source targeting ----------
                ui.add_space(10.0);
                ui.separator();
                ui.add_space(10.0);
                let src_count = app.source_selected.iter().filter(|&&v| v).count();
                let src_header = if src_count > 0 {
                    format!("Log sources ({} selected)", src_count)
                } else {
                    "Log sources (all included)".to_string()
                };
                egui::CollapsingHeader::new(src_header)
                    .id_salt("log_sources_header")
                    .show(ui, |ui| {
                        ui.label(
                            egui::RichText::new(
                                "Nothing selected = all log sources included. Selecting sources \
                                 keeps only rules that positively match them; unclassifiable \
                                 rules are dropped (strict).",
                            )
                            .size(12.0)
                            .color(egui::Color32::GRAY),
                        );
                        ui.add_space(6.0);
                        ui.horizontal(|ui| {
                            ui.label("Search:");
                            ui.text_edit_singleline(&mut app.source_search);
                            if src_count > 0 && ui.small_button("Clear").clicked() {
                                for v in app.source_selected.iter_mut() {
                                    *v = false;
                                }
                            }
                        });
                        ui.add_space(4.0);

                        let src_needle = app.source_search.to_lowercase();
                        for (i, def) in LOG_SOURCES.iter().enumerate() {
                            if !src_needle.is_empty()
                                && !def.label.to_lowercase().contains(&src_needle)
                                && !def.id.to_lowercase().contains(&src_needle)
                            {
                                continue;
                            }
                            ui.checkbox(&mut app.source_selected[i], def.label);
                        }
                    });

                // ---------- Granular Azure / M365 table targeting ----------
                ui.add_space(10.0);
                ui.separator();
                ui.add_space(10.0);
                let table_count = app.azure_table_selected.iter().filter(|&&v| v).count();
                let header = if table_count > 0 {
                    format!("Azure / M365 log tables ({} selected)", table_count)
                } else {
                    "Azure / M365 log tables (all included)".to_string()
                };
                egui::CollapsingHeader::new(header)
                    .id_salt("azure_tables_header")
                    .default_open(app.azure_tables_open)
                    .show(ui, |ui| {
                        ui.label(
                            egui::RichText::new(
                                "Pick the exact Log Analytics / Sentinel / Defender tables you \
                                 ingest. Selecting any table keeps only rules that reference a \
                                 selected table (or whose sigma logsource maps to one).",
                            )
                            .size(12.0)
                            .color(egui::Color32::GRAY),
                        );
                        ui.add_space(6.0);
                        ui.horizontal(|ui| {
                            ui.label("Search:");
                            ui.text_edit_singleline(&mut app.azure_table_search);
                            if table_count > 0 && ui.small_button("Clear").clicked() {
                                for v in app.azure_table_selected.iter_mut() {
                                    *v = false;
                                }
                            }
                        });
                        ui.add_space(4.0);

                        let needle = app.azure_table_search.to_lowercase();
                        egui::ScrollArea::vertical()
                            .id_salt("azure_table_scroll")
                            .max_height(260.0)
                            .show(ui, |ui| {
                                let mut last_category = "";
                                for (i, def) in AZURE_TABLES.iter().enumerate() {
                                    if !needle.is_empty()
                                        && !def.name.to_lowercase().contains(&needle)
                                        && !def.category.to_lowercase().contains(&needle)
                                    {
                                        continue;
                                    }
                                    if def.category != last_category {
                                        ui.add_space(6.0);
                                        ui.label(
                                            egui::RichText::new(def.category)
                                                .strong()
                                                .size(13.0),
                                        );
                                        last_category = def.category;
                                    }
                                    // "Select all in category" convenience row
                                    ui.checkbox(&mut app.azure_table_selected[i], def.name);
                                }
                            });

                        ui.add_space(4.0);
                        ui.horizontal(|ui| {
                            if ui.small_button("Select all visible").clicked() {
                                for (i, def) in AZURE_TABLES.iter().enumerate() {
                                    if needle.is_empty()
                                        || def.name.to_lowercase().contains(&needle)
                                        || def.category.to_lowercase().contains(&needle)
                                    {
                                        app.azure_table_selected[i] = true;
                                    }
                                }
                            }
                        });
                    });

                // ---------- Granular Splunk sourcetype targeting ----------
                ui.add_space(10.0);
                ui.separator();
                ui.add_space(10.0);
                let st_count = app.sourcetype_selected.iter().filter(|&&v| v).count();
                let st_header = if st_count > 0 {
                    format!("Splunk sourcetypes ({} selected)", st_count)
                } else {
                    "Splunk sourcetypes (all included)".to_string()
                };
                egui::CollapsingHeader::new(st_header)
                    .id_salt("splunk_sourcetypes_header")
                    .default_open(app.sourcetypes_open)
                    .show(ui, |ui| {
                        ui.label(
                            egui::RichText::new(
                                "Pick the exact sourcetypes you ingest in Splunk. Selecting any \
                                 sourcetype keeps only rules that reference a selected sourcetype.",
                            )
                            .size(12.0)
                            .color(egui::Color32::GRAY),
                        );
                        ui.add_space(6.0);
                        ui.horizontal(|ui| {
                            ui.label("Search:");
                            ui.text_edit_singleline(&mut app.sourcetype_search);
                            if st_count > 0 && ui.small_button("Clear").clicked() {
                                for v in app.sourcetype_selected.iter_mut() {
                                    *v = false;
                                }
                            }
                        });
                        ui.add_space(4.0);

                        let st_needle = app.sourcetype_search.to_lowercase();
                        egui::ScrollArea::vertical()
                            .id_salt("sourcetype_scroll")
                            .max_height(260.0)
                            .show(ui, |ui| {
                                let mut last_category = "";
                                for (i, def) in SPLUNK_SOURCETYPES.iter().enumerate() {
                                    if !st_needle.is_empty()
                                        && !def.name.to_lowercase().contains(&st_needle)
                                        && !def.category.to_lowercase().contains(&st_needle)
                                    {
                                        continue;
                                    }
                                    if def.category != last_category {
                                        ui.add_space(6.0);
                                        ui.label(
                                            egui::RichText::new(def.category).strong().size(13.0),
                                        );
                                        last_category = def.category;
                                    }
                                    ui.checkbox(&mut app.sourcetype_selected[i], def.name);
                                }
                            });

                        ui.add_space(4.0);
                        ui.horizontal(|ui| {
                            if ui.small_button("Select all visible").clicked() {
                                for (i, def) in SPLUNK_SOURCETYPES.iter().enumerate() {
                                    if st_needle.is_empty()
                                        || def.name.to_lowercase().contains(&st_needle)
                                        || def.category.to_lowercase().contains(&st_needle)
                                    {
                                        app.sourcetype_selected[i] = true;
                                    }
                                }
                            }
                        });
                    });

                // ---------- APT targeting ----------
                ui.add_space(10.0);
                ui.separator();
                ui.add_space(10.0);
                let apt_count = app.apt_selected.iter().filter(|&&v| v).count();
                let apt_header = if apt_count > 0 {
                    format!("Threat actors / APT groups ({} selected)", apt_count)
                } else {
                    "Threat actors / APT groups (all included)".to_string()
                };
                egui::CollapsingHeader::new(apt_header)
                    .id_salt("apt_header")
                    .show(ui, |ui| {
                        ui.label(
                            egui::RichText::new(
                                "Nothing selected = all actors included. Selecting groups keeps \
                                 only rules mentioning the group, its aliases, or its malware \
                                 families.",
                            )
                            .size(12.0)
                            .color(egui::Color32::GRAY),
                        );
                        ui.add_space(6.0);

                        ui.horizontal(|ui| {
                            ui.label("Search:");
                            ui.text_edit_singleline(&mut app.apt_search);
                            if apt_count > 0 && ui.small_button("Clear").clicked() {
                                for v in app.apt_selected.iter_mut() {
                                    *v = false;
                                }
                            }
                        });
                        ui.add_space(4.0);

                        let needle = app.apt_search.to_lowercase();
                        egui::ScrollArea::vertical()
                            .id_salt("apt_scroll")
                            .max_height(220.0)
                            .show(ui, |ui| {
                                for (i, g) in APT_GROUPS.iter().enumerate() {
                                    if !g.matches_search(&needle) {
                                        continue;
                                    }
                                    let label =
                                        format!("{} ({}) — {}", g.name, g.mitre_id, g.origin);
                                    ui.checkbox(&mut app.apt_selected[i], label)
                                        .on_hover_text(format!(
                                            "Aliases: {}\nSoftware: {}",
                                            g.aliases.join(", "),
                                            g.software.join(", ")
                                        ));
                                }
                            });

                        ui.add_space(6.0);
                        ui.horizontal(|ui| {
                            ui.label("Extra terms (comma-separated):");
                            ui.text_edit_singleline(&mut app.apt_custom_terms).on_hover_text(
                                "Actor or malware names not in the list, e.g. Vidar, RedLine",
                            );
                        });
                    });

                // ---------- ATT&CK technique (TTP) targeting ----------
                ui.add_space(10.0);
                ui.separator();
                ui.add_space(10.0);
                let ttp_count = app.ttp_selected.iter().filter(|&&v| v).count();
                let extra_codes = !app.technique_input.trim().is_empty();
                let ttp_header = if ttp_count > 0 || extra_codes {
                    format!(
                        "MITRE ATT&CK techniques ({} selected{})",
                        ttp_count,
                        if extra_codes { " + custom" } else { "" }
                    )
                } else {
                    "MITRE ATT&CK techniques (all included)".to_string()
                };
                egui::CollapsingHeader::new(ttp_header)
                    .id_salt("ttp_header")
                    .show(ui, |ui| {
                        ui.label(
                            egui::RichText::new(
                                "Nothing selected = all techniques included. Selecting techniques \
                                 keeps only rules that reference them; a parent code also keeps \
                                 its subtechniques (T1059 keeps T1059.001).",
                            )
                            .size(12.0)
                            .color(egui::Color32::GRAY),
                        );
                        ui.add_space(6.0);
                        ui.horizontal(|ui| {
                            ui.label("Search:");
                            ui.text_edit_singleline(&mut app.ttp_search);
                            if ttp_count > 0 && ui.small_button("Clear").clicked() {
                                for v in app.ttp_selected.iter_mut() {
                                    *v = false;
                                }
                            }
                        });
                        ui.add_space(4.0);

                        let ttp_needle = app.ttp_search.to_lowercase();
                        egui::ScrollArea::vertical()
                            .id_salt("ttp_scroll")
                            .max_height(260.0)
                            .show(ui, |ui| {
                                let mut last_tactic = "";
                                for (i, def) in TTP_CATALOG.iter().enumerate() {
                                    if !ttp_needle.is_empty()
                                        && !def.id.to_lowercase().contains(&ttp_needle)
                                        && !def.name.to_lowercase().contains(&ttp_needle)
                                        && !def.tactic.to_lowercase().contains(&ttp_needle)
                                    {
                                        continue;
                                    }
                                    if def.tactic != last_tactic {
                                        ui.add_space(6.0);
                                        ui.label(
                                            egui::RichText::new(def.tactic).strong().size(13.0),
                                        );
                                        last_tactic = def.tactic;
                                    }
                                    let indent = if def.id.contains('.') { "    " } else { "" };
                                    ui.checkbox(
                                        &mut app.ttp_selected[i],
                                        format!("{}{} — {}", indent, def.id, def.name),
                                    );
                                }
                            });

                        ui.add_space(6.0);
                        ui.horizontal(|ui| {
                            ui.label("Extra T-codes (comma-separated):");
                            ui.text_edit_singleline(&mut app.technique_input)
                                .on_hover_text("Codes not in the list, e.g. T1621, T1651");
                        });
                    });

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

                    // Build the compiled filter once for this run
                    let source_ids: Vec<String> = LOG_SOURCES
                        .iter()
                        .enumerate()
                        .filter(|(i, _)| app.source_selected[*i])
                        .map(|(_, d)| d.id.to_string())
                        .collect();

                    let mut apt_terms = expand_terms(&app.apt_selected);
                    for t in app.apt_custom_terms.split(',') {
                        let t = t.trim();
                        if !t.is_empty() {
                            apt_terms.push(t.to_string());
                        }
                    }

                    let selected_tables: Vec<String> = AZURE_TABLES
                        .iter()
                        .enumerate()
                        .filter(|(i, _)| app.azure_table_selected[*i])
                        .map(|(_, d)| d.name.to_string())
                        .collect();

                    let selected_sourcetypes: Vec<String> = SPLUNK_SOURCETYPES
                        .iter()
                        .enumerate()
                        .filter(|(i, _)| app.sourcetype_selected[*i])
                        .map(|(_, d)| d.name.to_string())
                        .collect();

                    let mut technique_ids: Vec<String> = TTP_CATALOG
                        .iter()
                        .enumerate()
                        .filter(|(i, _)| app.ttp_selected[*i])
                        .map(|(_, d)| d.id.to_string())
                        .collect();
                    for t in app.technique_input.split([',', ' ', ';']) {
                        let t = t.trim();
                        if !t.is_empty() {
                            technique_ids.push(t.to_string());
                        }
                    }

                    let filter = Arc::new(CompiledFilter::build_full(
                        source_ids,
                        apt_terms,
                        selected_tables,
                        selected_sourcetypes,
                        technique_ids,
                    ));

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
                        let filter_clone = Arc::clone(&filter);

                        std::thread::spawn(move || match tool {
                            "Yara" => yara::process_yara(
                                &out_path,
                                Arc::clone(&progress_triplet),
                                ctx_clone.clone(),
                                Arc::clone(&cancel_flag),
                                filter_clone,
                            ),
                            "Suricata" => suricata::process_suricata(
                                &out_path,
                                Arc::clone(&progress_triplet),
                                ctx_clone.clone(),
                                Arc::clone(&cancel_flag),
                                filter_clone,
                            ),
                            "Sigma" => sigma::process_sigma(
                                &out_path,
                                Arc::clone(&progress_triplet),
                                ctx_clone.clone(),
                                Arc::clone(&cancel_flag),
                                filter_clone,
                            ),
                            "Splunk" => splunk::process_splunk(
                                &out_path,
                                Arc::clone(&progress_triplet),
                                ctx_clone.clone(),
                                Arc::clone(&cancel_flag),
                                filter_clone,
                            ),
                            "QRadar" => qradar::process_qradar(
                                &out_path,
                                Arc::clone(&progress_triplet),
                                ctx_clone.clone(),
                                Arc::clone(&cancel_flag),
                                filter_clone,
                            ),
                            "Sysmon" => sysmon::process_sysmon(
                                &out_path,
                                Arc::clone(&progress_triplet),
                                ctx_clone.clone(),
                                Arc::clone(&cancel_flag),
                                filter_clone,
                            ),
                            _ => {}
                        });
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
        });
}
