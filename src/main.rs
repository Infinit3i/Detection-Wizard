mod app;
mod ui;
mod yara;
mod suricata;
mod sigma;
mod splunk;


fn main() -> eframe::Result<()> {
    app::run()
}
