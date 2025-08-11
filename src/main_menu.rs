use crate::ioc::ioc_menu::IOCSelectorApp;
use crate::ioc::ui_ioc;
use crate::rules::rule_menu::ToolSelectorApp;
use crate::rules::ui_rule;
use eframe::{App, Frame, egui};
use egui::Color32;
use egui::Margin;

pub enum Screen {
    Menu,
    ToolSelector(ToolSelectorApp),
    IOCDownloader(IOCSelectorApp),
}

pub struct MainApp {
    pub screen: Screen,
    did_center: bool,
}

impl Default for MainApp {
    fn default() -> Self {
        Self {
            screen: Screen::Menu,
            did_center: false,
        }
    }
}

impl App for MainApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut Frame) {
        if !self.did_center {
            self.did_center = true;

            // Set initial size first (pick whatever you want)
            ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(egui::vec2(1100.0, 720.0)));

            // Then center on the current screen (0.32 API)
            if let Some(cmd) = egui::ViewportCommand::center_on_screen(ctx) {
                ctx.send_viewport_cmd(cmd);
            }
        }
        // Take ownership of screen so we can mutate it safely
        let mut screen = std::mem::replace(&mut self.screen, Screen::Menu);

        // Temp variable to hold screen update request
        let mut new_screen = None;

        match &mut screen {
            Screen::ToolSelector(tool_app) => {
                ui_rule::render_ui(tool_app, ctx, || {
                    new_screen = Some(Screen::Menu);
                });
            }

            Screen::IOCDownloader(ioc_app) => {
                ui_ioc::render_ui_ioc(ioc_app, ctx, || {
                    new_screen = Some(Screen::Menu);
                });
            }

            Screen::Menu => {
                egui::CentralPanel::default()
                    .frame(
                        egui::Frame::default()
                            .inner_margin(Margin::same(30))
                            .outer_margin(Margin::same(20)),
                    )
                    .show(ctx, |ui| {
                        ui.heading("🔧 Detection Wizard");
                        ui.separator();
                        ui.add_space(10.0);
                        ui.label("Choose IOA or IOC:");
                        ui.add_space(15.0);
                        if ui
                            .add(
                                egui::Button::new(
                                    egui::RichText::new("🛠 Rules").color(Color32::WHITE),
                                )
                                .fill(Color32::from_rgb(70, 130, 180)), // SteelBlue
                            )
                            .clicked()
                        {
                            new_screen = Some(Screen::ToolSelector(Default::default()));
                        }
                        ui.add_space(5.0);

                        if ui
                            .add(
                                egui::Button::new(
                                    egui::RichText::new("📥 IOCs").color(Color32::WHITE),
                                )
                                .fill(Color32::from_rgb(60, 179, 113)), // MediumSeaGreen
                            )
                            .clicked()
                        {
                            new_screen = Some(Screen::IOCDownloader(Default::default()));
                        }
                        ui.add_space(40.0);
                        if ui
                            .add(
                                egui::Button::new(
                                    egui::RichText::new("❌ Quit").color(Color32::WHITE),
                                )
                                .fill(Color32::from_rgb(220, 20, 60)), // Crimson
                            )
                            .clicked()
                        {
                            std::process::exit(0);
                        }
                    });
            }
        }

        // Apply screen change if requested
        self.screen = new_screen.unwrap_or(screen);
    }
}
