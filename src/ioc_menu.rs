use std::sync::{Arc, Mutex};

pub struct IOCSelectorApp {
    pub selected: Vec<bool>,
    pub ioc_types: Vec<&'static str>,
    pub progress: Arc<Mutex<Option<(usize, usize)>>>,
}

impl Default for IOCSelectorApp {
    fn default() -> Self {
        Self {
            selected: vec![false; 9],
            ioc_types: vec![
                "Filename",
                "SHA256",
                "SHA1",
                "MD5",
                "IP",
                "Domain",
                "URL",
                "Email",
                "Registry",
            ],
            progress: Arc::new(Mutex::new(None)),
        }
    }
}
