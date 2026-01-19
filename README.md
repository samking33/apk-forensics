# fSOC APK Forensics

<div align="center">

```
          ░░░░░░░░░░░░░              
          ░░░░▒▒▒▒▒▒▒▒▒▒▒▒░░░░          
        ░░▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒░░        
       ░▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒░       
      ░▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒░      
     ░▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒░     
    ░▒▒▒▒▒███▒▒▒▒▒▒▒▒▒▒▒▒▒███▒▒▒▒▒░    
    ░▒▒▒▒█████▒▒▒▒▒▒▒▒▒▒▒█████▒▒▒▒░    
    ░▒▒▒▒▒███▒▒▒▒▒▒▒▒▒▒▒▒▒███▒▒▒▒▒░    
     ░▒▒▒▒▒▒▒▒▒▒▒▒███▒▒▒▒▒▒▒▒▒▒▒▒░     
      ░▒▒▒▒▒▒▒▒▒▒███▒▒▒▒▒▒▒▒▒▒▒▒░      
        ░▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒░        
         ░▒▒▒▒░░░▒▒▒▒▒░░░▒▒▒▒░         
```

**Professional CLI Forensic Analysis Tool for APK Files**

*"Hello, friend. Time to expose the truth."*

[![Version](https://img.shields.io/badge/version-1.0.0-green.svg)](https://github.com/fsoc/apk-forensics)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)

</div>

---

## 🎯 Overview

**fSOC APK Forensics** is a professional command-line tool for deep manual forensic analysis of Android APK files using Claude AI. It provides comprehensive malware analysis, threat detection, and security assessment capabilities with a Mr. Robot-inspired aesthetic.

### Key Features

- 💀 **Deep Manual Forensics** - Comprehensive APK analysis using Claude AI
- 🔍 **Malware Detection** - Identifies trojans, miners, spyware, and droppers
- 🌐 **Network IoC Extraction** - URLs, IPs, domains, C2 infrastructure
- 🔐 **Behavioral Analysis** - Persistence, data theft, evasion techniques
- 📊 **YARA Rule Generation** - Automatic detection signature creation
- 🚨 **IDS Rules** - Snort/Suricata rule suggestions
- 🎨 **Professional CLI** - Beautiful terminal interface with colored output
- 📝 **Detailed Reports** - Comprehensive forensic documentation
- ⚙️ **Production Ready** - Error handling, logging, configuration management

---

## 📦 Installation

### Quick Install (Recommended)

```bash
git clone https://github.com/fsoc/apk-forensics.git
cd apk-forensics
chmod +x install.sh
./install.sh
```

The installation script will:
- Check system requirements
- Install forensic tools (apktool, jadx)
- Create virtual environment
- Install Python dependencies
- Set up configuration files

### Manual Installation

```bash
# Clone repository
git clone https://github.com/fsoc/apk-forensics.git
cd apk-forensics

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Make executable
chmod +x apk_forensics.py
```

### System Requirements

- **Python**: 3.8 or higher
- **Claude CLI**: Required for analysis ([Installation Guide](https://docs.anthropic.com/claude/docs/cli))
- **Forensic Tools** (recommended):
  - `apktool` - APK decompilation
  - `jadx` - Java decompiler
  - `grep`, `strings`, `openssl` - Analysis utilities

**Install forensic tools:**

```bash
# macOS
brew install apktool jadx

# Linux (Debian/Ubuntu)
sudo apt-get install apktool
# jadx: Download from https://github.com/skylot/jadx/releases
```

---

## 🚀 Usage

### Interactive Mode

```bash
source venv/bin/activate
python apk_forensics.py
```

The tool will display the banner and prompt you for an APK file or directory path.

### Command Line Arguments

```bash
# Analyze specific APK
python apk_forensics.py --apk /path/to/suspicious.apk

# Quiet mode (no banner)
python apk_forensics.py --apk /path/to/app.apk --quiet

# Verbose logging
python apk_forensics.py --apk /path/to/app.apk --verbose

# Disable colors
python apk_forensics.py --apk /path/to/app.apk --no-color

# Custom config file
python apk_forensics.py --config custom_config.yaml

# Show version
python apk_forensics.py --version

# Show help
python apk_forensics.py --help
```

### Batch Processing

```bash
# Analyze all APKs in a directory
python apk_forensics.py --apk /path/to/apk_directory/
```

---

## 📋 CLI Arguments

| Argument | Description |
|----------|-------------|
| `--apk PATH` | Path to APK file or directory containing APKs |
| `--config FILE` | Path to configuration file (default: config.yaml) |
| `--quiet` | Suppress banner and progress messages |
| `--verbose` | Enable debug logging |
| `--no-color` | Disable colored output |
| `--version` | Show version information |
| `--help` | Display help message |

---

## ⚙️ Configuration

The tool uses a YAML configuration file (`config.yaml`) for customization:

```yaml
claude:
  model: claude-3-5-sonnet-20241022
  timeout: 600
  auto_approve: true

output:
  directory: apk_analysis
  format: text
  save_logs: true

logging:
  level: INFO
  directory: logs
  max_size_mb: 100
  backup_count: 5

forensic_tools:
  apktool: apktool
  jadx: jadx
```

### Configuration Options

- **claude.model**: Claude model to use for analysis
- **claude.timeout**: Maximum analysis time in seconds
- **output.directory**: Where to save analysis reports
- **logging.level**: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
- **logging.directory**: Log file location

---

## 📊 Output

### Report Structure

Reports are saved in the following structure:

```
apk_analysis/
├── app1.apk/
│   └── report_app1.apk.txt
├── app2.apk/
│   └── report_app2.apk.txt
└── ...
```

### Report Contents

Each forensic report includes:

1. **Executive Summary** - Malware type and risk level
2. **Metadata** - SHA-256 hash, package name, version info
3. **Permissions Analysis** - Critical/High/Medium permissions table
4. **Attack Surface** - Exported components and entry points
5. **Malicious Behaviors** - Persistence, data theft, C2 communication
6. **Network IoCs** - URLs, IPs, domains, API endpoints
7. **File/Payload IoCs** - Embedded files and payloads
8. **Attribution** - Phone numbers, emails, API keys
9. **YARA Rules** - Detection signatures
10. **Snort/Suricata Rules** - IDS rules
11. **Recommendations** - Remediation steps

---

## 🔍 Example Analysis

```bash
$ python apk_forensics.py --apk malware.apk

================================================================================
[Skull ASCII Art Banner]
    A P K   F O R E N S I C S   T O O L K I T
================================================================================
          "Hello, friend. Time to expose the truth."
================================================================================

[*] Initializing fsociety forensic protocols...
[*] Loading exploit detection signatures...
[*] Establishing anonymous analysis environment...
[+] System compromised. Ready for analysis.

Found 1 APK file(s) for analysis.
Analyzing APK(s)... Please wait.

================================================================================
ANALYSIS COMPLETE
================================================================================

FORENSIC ANALYSIS REPORT: malware.apk
================================================================================

EXECUTIVE SUMMARY
-----------------
Malware Type: Banking Trojan + Cryptominer Hybrid
Risk Level: CRITICAL

[... detailed analysis ...]

Report saved to: apk_analysis/malware.apk/report_malware.apk.txt
================================================================================
```

---

## 📝 Logging

Logs are saved to the `logs/` directory with automatic rotation:

```
logs/
├── apk_forensics_2026-01-19.log
├── apk_forensics_2026-01-18.log
└── ...
```

Log files include:
- Application events
- Analysis progress
- Errors and warnings
- Debug information (when --verbose is enabled)

---

## 🛠️ Troubleshooting

### "Claude CLI not found"

Ensure Claude CLI is installed and accessible:

```bash
which claude
claude --version
```

Install from: https://docs.anthropic.com/claude/docs/cli

### "No APK files found"

- Verify the path is correct
- Ensure files have `.apk` extension
- Check file permissions

### Analysis Timeout

Increase timeout in `config.yaml`:

```yaml
claude:
  timeout: 1200  # 20 minutes
```

### Missing Forensic Tools

Install apktool and jadx:

```bash
# macOS
brew install apktool jadx

# Linux
sudo apt-get install apktool
```

---

## 🔐 Security Notice

This tool is designed for **legitimate security research and forensic analysis only**. Always ensure you have proper authorization before analyzing APK files.

**Use Cases:**
- Malware analysis and reverse engineering
- Security research and threat intelligence
- Incident response and digital forensics
- Mobile application security assessment

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## 📞 Support

For issues, questions, or suggestions:
- Open an issue on GitHub
- Check the [troubleshooting](#-troubleshooting) section
- Review the [documentation](#-usage)

---

## 🙏 Acknowledgments

- Inspired by Mr. Robot and fsociety
- Built with Claude AI for deep forensic analysis
- Uses apktool and jadx for APK decompilation

---

<div align="center">

**APK Forensics by fSOC** | Version 1.0.0

*"Control is an illusion. But analysis is real."*

</div>
