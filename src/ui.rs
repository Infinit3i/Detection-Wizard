use crate::app::ToolSelectorApp;
use crate::{yara, suricata, sigma, splunk};
use eframe::egui;
use eframe::egui::IconData;
use image::GenericImageView;

pub fn load_icon(path: &str) -> Option<IconData> {
    let img = image::open(path).ok()?.into_rgba8();
    let (width, height) = img.dimensions();
    let rgba = img.into_raw();
    Some(IconData { rgba, width, height })
}

pub fn render_ui(app: &mut ToolSelectorApp, ctx: &egui::Context) {
    egui::CentralPanel::default().show(ctx, |ui| {
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
            if app.selected[4] {
                yara::process_yara();
                suricata::process_suricata();
                sigma::process_sigma();
                splunk::process_splunk();
            } else {
                for (i, selected) in app.selected.iter().enumerate() {
                    if *selected {
                        match app.tool_names[i] {
                            "Yara" => yara::process_yara(),
                            "Suricata" => suricata::process_suricata(),
                            "Sigma" => sigma::process_sigma(),
                            "Splunk" => splunk::process_splunk(),
                            _ => {}
                        }
                    }
                }
            }
        }
    });
}
