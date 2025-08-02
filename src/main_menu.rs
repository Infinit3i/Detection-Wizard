use crate::{ioc_menu::IOCSelectorApp, rule_menu::ToolSelectorApp, ui_ioc, ui_rule};
use eframe::{egui, App, Frame};
use egui::Color32;
use egui::Margin;

pub enum Screen {
    Menu,
    ToolSelector(ToolSelectorApp),
    IOCDownloader(IOCSelectorApp),
}

pub struct MainApp {
    pub screen: Screen,
}

impl Default for MainApp {
    fn default() -> Self {
        Self {
            screen: Screen::Menu,
        }
    }
}

impl App for MainApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut Frame) {
        // Take ownership of screen so we can mutate it safely
        let mut screen = std::mem::replace(&mut self.screen, Screen::Menu);

        // Temp variable to hold screen update request
        let mut new_screen = None;

        match &mut screen {
            Screen::ToolSelector(ref mut tool_app) => {
                ui_rule::render_ui(tool_app, ctx, || {
                    new_screen = Some(Screen::Menu);
                });
            }

            Screen::IOCDownloader(ref mut ioc_app) => {
                ui_ioc::render_ui_ioc(ioc_app, ctx, || {
                    new_screen = Some(Screen::Menu);
                });
            }

            Screen::Menu => {
                egui::CentralPanel::default()
                    .frame(
                        egui::Frame::default()
                            .inner_margin(Margin::same(30.0))
                            .outer_margin(Margin::same(20.0)),
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
