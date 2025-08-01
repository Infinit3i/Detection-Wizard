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

---

**Detection-Wizard** is designed to simplify rule management and enhance threat detection capabilities. Enjoy using the tool, and happy hunting! 🎯👀
