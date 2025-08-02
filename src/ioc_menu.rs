use std::sync::{Arc, Mutex};

// In ioc_menu.rs
pub struct IOCSelectorApp {
    pub ioc_types: Vec<&'static str>,
    pub selected: Vec<bool>,
    pub output_format: OutputFormat,
    pub custom_path: Option<String>,
    pub progress: Arc<Mutex<Option<(usize, usize)>>>,
    pub confirm_overwrite: bool,
    pub pending_urls: Option<Vec<(String, String)>>,
    pub overwrite_queue: Vec<(String, String)>,
    pub overwrite_index: usize,
    pub yes_all: bool,
    pub skip_all: bool,
}

#[derive(PartialEq, Clone)]
pub enum OutputFormat {
    Txt,
    Csv,
}

impl Default for IOCSelectorApp {
    fn default() -> Self {
        Self {
            selected: vec![false; 9],
            ioc_types: vec![
                "Filename", "SHA256", "SHA1", "MD5", "IP",
                "Domain", "URL", "Email", "Registry"
            ],
            progress: Arc::new(Mutex::new(None)),
            output_format: OutputFormat::Txt,
            custom_path: None,
            confirm_overwrite: false,
            pending_urls: None,
            overwrite_queue: Vec::new(),
            overwrite_index: 0,
            yes_all: false,
            skip_all: false,
        }
    }
}
