@@ -0,0 +1,481 @@
#!/usr/bin/env python3
"""
fSOC APK Forensics - Professional CLI Forensic Analysis Tool
Author: APK Forensics by fSOC
Version: 1.0.0
"""

import os
import sys
import glob
import subprocess
import argparse
import logging
import yaml
from pathlib import Path
from typing import List, Optional
from datetime import datetime
import platform

try:
    import pyfiglet
    from termcolor import colored
except ImportError:
    print("Error: Required dependencies not installed. Run: pip install -r requirements.txt")
    sys.exit(1)

# Import version
try:
    from __version__ import __version__
except ImportError:
    __version__ = "1.0.0"

# Forensic Analysis Prompt (EXACT - DO NOT MODIFY)
FORENSIC_ANALYSIS_PROMPT = """Role: You are a Senior Mobile Malware Analyst and Digital Forensics Expert.

Task: You must perform a FULL, MANUAL, and EXHAUSTIVE FORENSIC ANALYSIS on the APK file: {apk_path}

Operational Constraints (CRITICAL):

- NO AUTOMATION SCRIPTS: You are FORBIDDEN from writing Python scripts, Bash scripts, or batch files to automate this workflow.
- MANUAL ANALYSIS ONLY: You must manually use forensic tools such as apktool, jadx, grep, strings, openssl, etc.
- DEEP DIVE REQUIRED: You must inspect decompiled Java/Smali code, trace logic paths, and correlate permissions with behaviors.
- SILENT EXECUTION: Do NOT explain intermediate steps or show terminal output unless explicitly asked.

For this APK, you MUST perform:

1. Identification & Hashing
   - SHA-256 hash
   - Package Name
   - Version Code
   - Version Name
   - Application Label

2. Manifest & Attack Surface Analysis
   - Decode AndroidManifest.xml
   - List all permissions (Critical / High / Medium)
   - Identify exported Activities, Services, Receivers
   - Identify malicious entry points (BOOT_COMPLETED, SMS_RECEIVED, etc.)

3. Code & Behavioral Analysis
   - Decompile using apktool and jadx
   - Persistence mechanisms
   - Data theft logic (SMS, contacts, files)
   - C2 communication logic
   - Evasion techniques
   - Dropper behavior and nested payload analysis

4. Network Infrastructure & IoCs
   - Extract URLs, IPs, domains
   - Identify malicious infrastructure
   - Extract API endpoints

5. Cryptocurrency & Financial Fraud Check
   - Wallet addresses
   - Mining configs
   - Bank overlay targeting

6. Identity & Attribution
   - Phone numbers
   - Emails
   - Telegram / Discord / WhatsApp IDs
   - API keys

REPORT FORMAT (MANDATORY):

- Executive Summary (Malware Type + Risk Level)
- Metadata
- Permissions Analysis Table
- Malicious Behaviors (technical)
- Network IoCs
- File/Payload IoCs
- Attribution
- YARA / Detection Suggestions (optional)

Save the complete report to:
{report_path}

Begin analysis now."""


class APKForensics:
    """Main APK Forensics application class."""
    
    def __init__(self, config_path: str = "config.yaml"):
        """Initialize the forensics tool with configuration."""
        self.config = self.load_config(config_path)
        self.setup_logging()
        self.logger = logging.getLogger(__name__)
        
    def load_config(self, config_path: str) -> dict:
        """Load configuration from YAML file."""
        default_config = {
            'claude': {'model': 'claude-3-5-sonnet-20241022', 'timeout': 600, 'auto_approve': True},
            'output': {'directory': 'apk_analysis', 'format': 'text', 'save_logs': True},
            'logging': {'level': 'INFO', 'directory': 'logs', 'max_size_mb': 100, 'backup_count': 5},
            'forensic_tools': {'apktool': 'apktool', 'jadx': 'jadx'}
        }
        
        if os.path.exists(config_path):
            try:
                with open(config_path, 'r') as f:
                    loaded_config = yaml.safe_load(f)
                    if loaded_config:
                        default_config.update(loaded_config)
            except Exception as e:
                print(f"Warning: Could not load config file: {e}. Using defaults.")
        
        return default_config
    
    def setup_logging(self):
        """Set up logging with rotating file handler."""
        log_dir = self.config['logging']['directory']
        os.makedirs(log_dir, exist_ok=True)
        
        log_level = getattr(logging, self.config['logging']['level'].upper(), logging.INFO)
        log_file = os.path.join(log_dir, f"apk_forensics_{datetime.now().strftime('%Y-%m-%d')}.log")
        
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler(sys.stdout) if log_level == logging.DEBUG else logging.NullHandler()
            ]
        )
    
    def display_banner(self, quiet: bool = False, no_color: bool = False):
        """Display the fSOC APK Forensics ASCII banner."""
        if quiet:
            return
            
        skull_art = """
          ░░░░░░░░░░░░░              
          ░░░░▒▒▒▒▒▒▒▒▒▒▒▒░░░░          
        ░░▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒░░        
       ░▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒░       
      ░▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒░      
     ░▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒░     
     ░▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒░     
    ░▒▒▒▒▒███▒▒▒▒▒▒▒▒▒▒▒▒▒███▒▒▒▒▒░    
    ░▒▒▒▒█████▒▒▒▒▒▒▒▒▒▒▒█████▒▒▒▒░    
    ░▒▒▒▒█████▒▒▒▒▒▒▒▒▒▒▒█████▒▒▒▒░    
    ░▒▒▒▒▒███▒▒▒▒▒▒▒▒▒▒▒▒▒███▒▒▒▒▒░    
    ░▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒░    
    ░▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒░    
    ░▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒░    
     ░▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒░     
     ░▒▒▒▒▒▒▒▒▒▒▒▒███▒▒▒▒▒▒▒▒▒▒▒▒░     
     ░▒▒▒▒▒▒▒▒▒▒█████▒▒▒▒▒▒▒▒▒▒▒▒░     
      ░▒▒▒▒▒▒▒▒▒▒███▒▒▒▒▒▒▒▒▒▒▒▒░      
      ░▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒░      
      ░▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒░      
       ░▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒░       
       ░▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒░       
       ░▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒░       
        ░▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒░        
        ░▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒░        
        ░▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒░        
         ░▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒░         
         ░▒▒▒▒░░░▒▒▒▒▒░░░▒▒▒▒░         
         ░▒▒░   ░▒▒▒▒▒░   ░▒▒░         
        ░▒▒░     ░▒▒▒░     ░▒▒░        
        ░▒░       ░▒░       ░▒░        
        ░░         ░         ░░
    """
        
        fsociety_banner = """
    ███████╗███████╗ ██████╗  ██████╗
    ██╔════╝██╔════╝██╔═══██╗██╔════╝
    █████╗  ███████╗██║   ██║██║     
    ██╔══╝  ╚════██║██║   ██║██║     
    ██║     ███████║╚██████╔╝╚██████╗
    ╚═╝     ╚══════╝ ╚═════╝  ╚═════╝
    """
        
        apk_forensics = "    A P K   F O R E N S I C S   T O O L K I T"
        quote = '"Hello, friend. Time to expose the truth."'
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        system_info = f"[{platform.system()} {platform.machine()}] | [{timestamp}]"
        
        def color_print(text, color, attrs=None):
            if no_color:
                print(text)
            else:
                print(colored(text, color, attrs=attrs or []))
        
        color_print("\n" + "=" * 80, "red", ["bold"])
        color_print(skull_art, "green", ["dark"])
        color_print(fsociety_banner, "red", ["bold"])
        color_print(apk_forensics, "green", ["bold"])
        color_print("\n" + "=" * 80, "red", ["bold"])
        color_print(f"{'':>10}{quote}", "cyan")
        color_print("=" * 80, "red", ["bold"])
        color_print(f"{'':>5}MOBILE MALWARE ANALYSIS | THREAT INTELLIGENCE", "yellow")
        color_print(f"{'':>5}{system_info}", "white", ["dark"])
        color_print("=" * 80 + "\n", "red", ["bold"])
        
        color_print("[*] Initializing fsociety forensic protocols...", "green")
        color_print("[*] Loading exploit detection signatures...", "green")
        color_print("[*] Establishing anonymous analysis environment...", "green")
        color_print("[+] System compromised. Ready for analysis.\n", "green", ["bold"])
        color_print("=" * 80, "red", ["bold"])
        print()
    
    def check_dependencies(self) -> bool:
        """Check if required dependencies are installed."""
        missing = []
        
        # Check Claude CLI
        try:
            result = subprocess.run(["claude", "--version"], capture_output=True, text=True, timeout=5)
            if result.returncode != 0:
                missing.append("claude")
        except (subprocess.SubprocessError, FileNotFoundError):
            missing.append("claude")
            
        # Check forensic tools
        for tool in ['apktool', 'jadx']:
            try:
                subprocess.run([tool, "--version"], capture_output=True, timeout=5)
            except (subprocess.SubprocessError, FileNotFoundError):
                self.logger.warning(f"Forensic tool '{tool}' not found. Analysis capabilities will be limited.")
        
        if missing:
            self.logger.error(f"Missing required dependencies: {', '.join(missing)}")
            return False
        return True
    
    def get_apk_path(self) -> Optional[str]:
        """Prompt user for APK file or directory path and validate it."""
        while True:
            print("Enter full path to APK file or directory containing APKs:")
            path = input("> ").strip()
            
            if not path:
                self.logger.warning("Empty path provided")
                print(colored("Error: Path cannot be empty. Please try again.\n", "red"))
                continue
            
            path = os.path.expanduser(path)
            
            if not os.path.exists(path):
                self.logger.warning(f"Path does not exist: {path}")
                print(colored(f"Error: Path '{path}' does not exist. Please try again.\n", "red"))
                continue
            
            return path
    
    def discover_apks(self, path: str) -> List[str]:
        """Discover all APK files from the given path."""
        apks = []
        
        try:
            if os.path.isfile(path):
                if path.lower().endswith('.apk'):
                    apks.append(path)
            elif os.path.isdir(path):
                apks = glob.glob(os.path.join(path, "**/*.apk"), recursive=True)
            
            self.logger.info(f"Discovered {len(apks)} APK file(s) at {path}")
        except Exception as e:
            self.logger.error(f"Error discovering APKs: {e}")
        
        return sorted(apks)
    
    def create_report_directory(self, apk_path: str) -> str:
        """Create directory structure for APK analysis report."""
        apk_name = os.path.basename(apk_path)
        output_dir = self.config['output']['directory']
        report_dir = os.path.join(output_dir, apk_name)
        
        try:
            os.makedirs(report_dir, exist_ok=True)
            self.logger.info(f"Created report directory: {report_dir}")
        except Exception as e:
            self.logger.error(f"Failed to create report directory: {e}")
            raise
        
        return report_dir
    
    def analyze_apk_with_claude(self, apk_path: str) -> str:
        """Analyze APK using Claude CLI with auto-approved tool execution."""
        apk_name = os.path.basename(apk_path)
        self.logger.info(f"Starting analysis of {apk_name}")
        
        try:
            report_dir = self.create_report_directory(apk_path)
            report_path = os.path.join(report_dir, f"report_{apk_name}.txt")
            
            abs_apk_path = os.path.abspath(apk_path)
            abs_report_path = os.path.abspath(report_path)
            
            analysis_prompt = FORENSIC_ANALYSIS_PROMPT.format(
                apk_path=abs_apk_path,
                report_path=abs_report_path
            )
            
            cmd = [
                "claude",
                "--print",
                "--dangerously-skip-permissions",
                "--output-format", "text"
            ]
            
            self.logger.debug(f"Executing Claude CLI: {' '.join(cmd)}")
            
            process = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            stdout_data, stderr_data = process.communicate(
                input=analysis_prompt,
                timeout=self.config['claude']['timeout']
            )
            
            if process.returncode != 0:
                self.logger.error(f"Claude CLI failed: {stderr_data}")
                raise Exception(f"Claude CLI failed with error: {stderr_data}")
            
            if os.path.exists(abs_report_path):
                self.logger.info(f"Report created by Claude at {abs_report_path}")
                return abs_report_path
            else:
                with open(abs_report_path, 'w', encoding='utf-8') as f:
                    f.write(stdout_data)
                self.logger.info(f"Report saved to {abs_report_path}")
                return abs_report_path
                
        except subprocess.TimeoutExpired:
            self.logger.error(f"Analysis timeout for {apk_name}")
            raise Exception(f"Analysis timeout after {self.config['claude']['timeout']} seconds")
        except Exception as e:
            self.logger.error(f"Analysis failed for {apk_name}: {e}")
            raise
    
    def display_report(self, report_path: str, no_color: bool = False):
        """Display the forensic report in the terminal."""
        apk_name = os.path.basename(os.path.dirname(report_path))
        
        def color_print(text, color, attrs=None):
            if no_color:
                print(text)
            else:
                print(colored(text, color, attrs=attrs or []))
        
        print("\n" + "=" * 80)
        color_print(f"FORENSIC ANALYSIS REPORT: {apk_name}", "cyan", ["bold"])
        print("=" * 80 + "\n")
        
        if os.path.exists(report_path):
            with open(report_path, 'r', encoding='utf-8') as f:
                print(f.read())
        else:
            color_print("Report file not found.", "red")
        
        print("\n" + "=" * 80)
        color_print(f"Report saved to: {report_path}", "green")
        print("=" * 80 + "\n")
    
    def run(self, apk_path: Optional[str] = None, quiet: bool = False, no_color: bool = False):
        """Main execution method."""
        try:
            self.display_banner(quiet=quiet, no_color=no_color)
            
            if not self.check_dependencies():
                sys.exit(1)
            
            if not apk_path:
                apk_path = self.get_apk_path()
            
            apks = self.discover_apks(apk_path)
            
            if not apks:
                msg = "No APK files found at the specified path."
                self.logger.warning(msg)
                print(colored(msg, "red") if not no_color else msg)
                sys.exit(0)
            
            msg = f"\nFound {len(apks)} APK file(s) for analysis."
            print(colored(msg, "yellow") if not no_color else msg)
            msg = "Analyzing APK(s)... Please wait.\n"
            print(colored(msg, "yellow") if not no_color else msg)
            
            reports = []
            for apk in apks:
                try:
                    report_path = self.analyze_apk_with_claude(apk)
                    reports.append(report_path)
                except Exception as e:
                    error_msg = f"Error analyzing {os.path.basename(apk)}: {str(e)}"
                    print(colored(error_msg, "red") if not no_color else error_msg)
                    continue
            
            if reports:
                msg = "\n" + "=" * 80
                print(colored(msg, "green") if not no_color else msg)
                msg = "ANALYSIS COMPLETE"
                print(colored(msg, "green", attrs=["bold"]) if not no_color else msg)
                msg = "=" * 80 + "\n"
                print(colored(msg, "green") if not no_color else msg)
                
                for report_path in reports:
                    self.display_report(report_path, no_color=no_color)
            else:
                msg = "No reports generated. Analysis failed."
                print(colored(msg, "red") if not no_color else msg)
                
        except KeyboardInterrupt:
            self.logger.info("Analysis interrupted by user")
            print(colored("\n\nAnalysis interrupted by user.", "yellow") if not no_color else "\n\nAnalysis interrupted by user.")
            sys.exit(0)
        except Exception as e:
            self.logger.exception("Fatal error occurred")
            print(colored(f"\nFatal error: {str(e)}", "red") if not no_color else f"\nFatal error: {str(e)}")
            sys.exit(1)


def main():
    """Entry point for the CLI application."""
    parser = argparse.ArgumentParser(
        description="fSOC APK Forensics - Professional CLI forensic analysis tool for APK files",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Interactive mode
  python apk_forensics.py
  
  # Analyze specific APK
  python apk_forensics.py --apk /path/to/app.apk
  
  # Quiet mode (no banner)
  python apk_forensics.py --apk /path/to/app.apk --quiet
  
  # Verbose logging
  python apk_forensics.py --apk /path/to/app.apk --verbose
        """
    )
    
    parser.add_argument('--apk', type=str, help='Path to APK file or directory')
    parser.add_argument('--config', type=str, default='config.yaml', help='Path to configuration file')
    parser.add_argument('--quiet', action='store_true', help='Suppress banner and progress messages')
    parser.add_argument('--verbose', action='store_true', help='Enable debug logging')
    parser.add_argument('--no-color', action='store_true', help='Disable colored output')
    parser.add_argument('--version', action='version', version=f'fSOC APK Forensics v{__version__}')
    
    args = parser.parse_args()
    
    # Override config logging level if verbose
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    app = APKForensics(config_path=args.config)
    app.run(apk_path=args.apk, quiet=args.quiet, no_color=args.no_color)


if __name__ == "__main__":
 main()
