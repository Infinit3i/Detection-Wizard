mod yara;
mod suricata;

use dialoguer::Select;

fn main() {
    let options = vec!["Yara", "Suricata"];
    let selection = Select::new()
        .with_prompt("Select a tool")
        .items(&options)
        .default(0)
        .interact()
        .unwrap();

    match options[selection] {
        "Yara" => yara::process_yara(),
        "Suricata" => suricata::process_suricata(),
        _ => println!("Invalid selection"),
    }
}
