mod yara;
mod suricata;
mod sigma;
mod splunk;

use dialoguer::MultiSelect;

fn main() {
    let options = vec!["Yara", "Suricata", "Sigma", "Splunk", "All"];
    
    let selections = MultiSelect::new()
        .with_prompt("Select one or more tools (use space to select, enter to confirm):")
        .items(&options)
        .interact()
        .unwrap();

    // If "All" is selected (last option) then run all modules.
    if selections.contains(&(options.len() - 1)) {
        println!("Processing all tools...");
        yara::process_yara();
        suricata::process_suricata();
        sigma::process_sigma();
        splunk::process_splunk();
    } else {
        for i in selections {
            match options[i] {
                "Yara" => yara::process_yara(),
                "Suricata" => suricata::process_suricata(),
                "Sigma" => sigma::process_sigma(),
                "Splunk" => splunk::process_splunk(),
                _ => println!("Invalid selection"),
            }
        }
    }
}
