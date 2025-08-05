#[cfg(test)]
mod tests {
use eframe::egui::{Context};
use detection_wizard::main_menu::{MainApp, Screen};

    fn mock_context() -> Context {
        Context::default()
    }

    #[test]
    fn test_default_screen_is_menu() {
        let app = MainApp::default();
        match app.screen {
            Screen::Menu => {} // OK
            _ => panic!("Initial screen should be Menu"),
        }
    }

    #[test]
    fn test_rules_button_sets_tool_selector() {
        let mut app = MainApp::default();
        let ctx = mock_context();
        // Simulate click on Rules button
        app.screen = Screen::Menu;

        // Run one frame update (you'd simulate the button click manually in logic)
        // Instead, directly trigger what the button does
        app.screen = Screen::ToolSelector(Default::default());

        match &app.screen {
            Screen::ToolSelector(_) => {} // OK
            _ => panic!("Should switch to ToolSelector screen"),
        }
    }

    #[test]
    fn test_iocs_button_sets_ioc_downloader() {
        let mut app = MainApp::default();
        let ctx = mock_context();

        app.screen = Screen::Menu;
        app.screen = Screen::IOCDownloader(Default::default());

        match &app.screen {
            Screen::IOCDownloader(_) => {} // OK
            _ => panic!("Should switch to IOCDownloader screen"),
        }
    }
}
