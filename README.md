# Detection-Wizard 🧙‍♂️🔍

**Detection-Wizard** is a powerful, command-line tool that consolidates detection rules from multiple sources into a single central repository. Whether you're working with **YARA**, **Suricata**, **Sigma**, or **Splunk**, Detection-Wizard makes it easy to pull and manage rule sets from various public repositories and resources.

## Features ✨

- **Multi-Tool Support:**  
  Easily pull and process rules for:
  - **YARA**: Rule sets for malware and threat detection. 🦠
  - **Suricata**: IDS/IPS rules for network security. 🌐
  - **Sigma**: Generic signatures that can be converted to various SIEM formats. 📊
  - **Splunk**: Detection configurations for Splunk environments. 📈

- **Automated Repository Pulling:**  
  Clone and update rule repositories automatically from curated sources, including:
  - [awesome-yara](https://github.com/InQuest/awesome-yara) 📂
  - [awesome-suricata](https://github.com/satta/awesome-suricata) 🔗
  - Plus, many additional GitHub and web-based resources. 🌍

- **Flexible Source Integration:**  
  Add new sources easily! Detection-Wizard supports pulling rules from raw files, HTML pages, ZIP archives, tar.gz files, and more. 📦

- **Interactive CLI:**  
  Use an intuitive multi-select menu to run one, multiple, or all rule processing modules at once. 🎛️

## How It Works ⚙️

Detection-Wizard leverages a variety of Rust libraries:
- **Git2:** For cloning Git repositories. 🔄
- **Dialoguer:** For building interactive command-line menus. 🖥️
- **Reqwest:** For fetching remote content. 🌐
- **WalkDir & Regex:** For parsing and recursively processing rule files. 🔍
- **Zip, Flate2, and Tar:** For handling compressed archives. 📚

### Workflow 🚀
1. **Menu Selection:**  
   Choose which tool(s) to run via an interactive menu. Options include YARA, Suricata, Sigma, Splunk, or "All". 🗳️

2. **Repository Cloning:**  
   The tool clones base repositories (e.g., awesome-yara and awesome-suricata) along with additional sources provided by the user. 🛠️

3. **Rule Extraction:**  
   After cloning, Detection-Wizard scans for rule files (such as `.yar`, `.yara`, `.rules`, `.yml`, `.yaml`, `.conf`, `.xml`, `.spl`) and consolidates them into central directories for easy management. 📁

4. **Extensibility:**  
   Easily extend the tool by adding new source URLs to the respective modules. 🔧

## Installation 🛠️

### Prerequisites
- [Rust](https://www.rust-lang.org/) (latest stable version recommended) 🦀
- [Git](https://git-scm.com/) 🔧

### Setup
1. **Clone the Repository:**
   ```bash
   git clone https://github.com/yourusername/Detection-Wizard.git
   cd Detection-Wizard
   ```

2. **Build the Project:**
   ```bash
   cargo build --release
   ```

3. **Run the Tool:**
   ```bash
   cargo run --release
   ```

## Contributing 🤝

Contributions are welcome! Whether you have suggestions for new sources, improvements in parsing logic, or additional features, please feel free to open an issue or submit a pull request. 💡

## License 📄

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Resources & Acknowledgements 🙏

- [awesome-yara](https://github.com/InQuest/awesome-yara) by InQuest. 📂
- [awesome-suricata](https://github.com/satta/awesome-suricata) by satta. 🔗
- Additional rule sets and contributions from the open-source community. 🌍

---

**Detection-Wizard** is designed to simplify rule management and enhance threat detection capabilities. Enjoy using the tool, and happy hunting! 🎯👀