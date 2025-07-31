// src/menu.rs

use crate::{app::ToolSelectorApp, ioc_menu::IOCSelectorApp, ui, ui_ioc};
use eframe::{egui, App, Frame};

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
                ui::render_ui(tool_app, ctx, || {
                    new_screen = Some(Screen::Menu);
                });
            }

            Screen::IOCDownloader(ref mut ioc_app) => {
                ui_ioc::render_ui_ioc(ioc_app, ctx, || {
                    new_screen = Some(Screen::Menu);
                });
            }

            Screen::Menu => {
                egui::CentralPanel::default().show(ctx, |ui| {
                    ui.heading("🔧 Detection Wizard");
                    ui.separator();
                    ui.label("Choose a toolset to begin:");

                    if ui.button("🛠 Tool Selector").clicked() {
                        new_screen = Some(Screen::ToolSelector(Default::default()));
                    }

                    if ui.button("📥 IOC Downloader").clicked() {
                        new_screen = Some(Screen::IOCDownloader(Default::default()));
                    }

                    if ui.button("❌ Quit").clicked() {
                        std::process::exit(0);
                    }
                });
            }
        }

        // Apply screen change if requested
        self.screen = new_screen.unwrap_or(screen);
    }
}
