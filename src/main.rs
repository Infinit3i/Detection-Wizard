mod yara;
mod suricata;
mod sigma;
mod splunk;

use dialoguer::Select;

fn main() {
    let options = vec!["Yara", "Suricata","Sigma","Splunk"];
    let selection = Select::new()
        .with_prompt("Select a tool")
        .items(&options)
        .default(0)
        .interact()
        .unwrap();

    match options[selection] {
        "Yara" => yara::process_yara(),
        "Suricata" => suricata::process_suricata(),
        "Sigma" => sigma::process_sigma(),
        "Splunk" => splunk::process_splunk(),
        _ => println!("Invalid selection"),
    }
}
