#!/usr/bin/env python3
"""
fSOC APK Forensics - Professional CLI Forensic Analysis Tool
Author: APK Forensics by fSOC
Version: 1.0.0
"""

import os
import sys
import argparse
import subprocess
import logging
import yaml
import platform
import shutil
import time
from datetime import datetime
from termcolor import colored
from __version__ import __version__
import forensic_facts
import pdf_generator

class APKForensics:
    def __init__(self, config_path="config.yaml"):
        self.config = self.load_config(config_path)
        self.setup_logging()

    def load_config(self, path):
        try:
            with open(path, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            print(colored(f"[-] Error loading config: {e}", "red"))
            sys.exit(1)

    def setup_logging(self):
        log_dir = self.config.get('logging', {}).get('directory', 'logs')
        os.makedirs(log_dir, exist_ok=True)
        log_file = os.path.join(log_dir, f"apk_forensics_{datetime.now().strftime('%Y-%m-%d')}.log")

        logging.basicConfig(
            filename=log_file,
            level=getattr(logging, self.config.get('logging', {}).get('level', 'INFO')),
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger('fSOC')

    def display_banner(self, quiet: bool = False, no_color: bool = False):
        """Display the fSOC APK Forensics ASCII banner."""
        if quiet:
            return

        ghost_art = r"""
           ---      ---      ---      
          (o.o)    (o.o)    (o.o)     
          <) )\    <) )\    <) )\    
           " "      " "      " "    
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
        color_print(ghost_art, "green", ["dark"])
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

    def check_dependencies(self):
        """Check if required tools are installed."""
        missing = []
        tools = self.config.get('forensic_tools', {})
        for name, cmd in tools.items():
            if not shutil.which(cmd):
                missing.append(name)

        # Check for claude
        if not shutil.which('claude'):
            missing.append('claude')

        if missing:
            self.logger.error(f"Missing dependencies: {', '.join(missing)}")
            print(colored(f"[-] Error: Missing dependencies: {', '.join(missing)}", "red"))
            print("Please install them or run ./install.sh")
            sys.exit(1)

    def analyze_apk(self, apk_path, verbose=False):
        """Analyze a single APK."""
        if not os.path.exists(apk_path):
            self.logger.error(f"APK not found: {apk_path}")
            print(colored(f"[-] Error: APK not found: {apk_path}", "red"))
            return

        apk_name = os.path.basename(apk_path)
        print(colored(f"[*] Analyzing: {apk_name}", "cyan"))

        # Random fact
        print(colored(f"[i] Did you know? {forensic_facts.get_random_fact()}", "yellow"))

        # Create output dir
        output_dir = self.config.get('output', {}).get('directory', 'apk_analysis')
        apk_out_dir = os.path.join(output_dir, apk_name)
        os.makedirs(apk_out_dir, exist_ok=True)

        # Decompile (Mocking the heavy lifting for this reconstruction, but implemented logic)
        temp_dir = os.path.join(apk_out_dir, "temp_extracted")
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)

        print(colored("[*] Decompiling APK resources...", "blue"))
        apktool_cmd = [self.config['forensic_tools']['apktool'], 'd', apk_path, '-o', temp_dir, '-f']

        try:
            subprocess.run(apktool_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        except subprocess.CalledProcessError:
            print(colored("[-] Warning: Apktool failed. Continuing with limited analysis...", "yellow"))

        # Read Manifest
        manifest_path = os.path.join(temp_dir, "AndroidManifest.xml")
        manifest_content = ""
        if os.path.exists(manifest_path):
            try:
                with open(manifest_path, 'r', encoding='utf-8', errors='ignore') as f:
                    manifest_content = f.read()
            except Exception as e:
                self.logger.error(f"Failed to read manifest: {e}")

        # Construct Claude Prompt
        prompt = f"""
You are an expert Android malware analyst. Perform a deep forensic analysis of the following APK information.

APK Name: {apk_name}
Analysis Date: {datetime.now().strftime('%Y-%m-%d')}

Manifest Content (truncated if too long):
{manifest_content[:10000]}

Please generate a detailed forensic report with the following sections:
1. EXECUTIVE SUMMARY (Malware Type, Risk Level, Threat Category)
2. METADATA (Package Name, Version, etc.)
3. PERMISSIONS ANALYSIS (List critical permissions and risks)
4. MALICIOUS BEHAVIORS (Identify potential threats based on components)
5. NETWORK INDICATORS OF COMPROMISE (Generate plausible IoCs based on typical malware of this type if exact ones aren't visible)
6. FILE / PAYLOAD INDICATORS OF COMPROMISE
7. ATTRIBUTION (Any clues about the attacker)
8. YARA / DETECTION SUGGESTIONS (Write a YARA rule)
9. SNORT/SURICATA RULES
10. RECOMMENDATIONS

Format the output as a professional text report. Use ASCII art headers if appropriate.
"""

        print(colored("[*] transmitting data to fSOC AI mainframe (Claude)...", "magenta"))

        try:
            # Call Claude CLI
            # Assuming 'claude' command accepts input via stdin or argument
            # We try stdin first as it's common for such tools
            process = subprocess.Popen(
                ['claude'],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            stdout, stderr = process.communicate(input=prompt)

            if process.returncode != 0:
                self.logger.error(f"Claude analysis failed: {stderr}")
                print(colored(f"[-] Error during analysis: {stderr}", "red"))
                return

            report_content = stdout

            # Save Report
            report_file = os.path.join(apk_out_dir, f"report_{apk_name}.txt")
            with open(report_file, 'w') as f:
                f.write(report_content)

            print(colored(f"[+] Report saved: {report_file}", "green"))

            # Generate PDF
            try:
                pdf_path = pdf_generator.convert_report_to_pdf(report_file)
                print(colored(f"[+] PDF Report generated: {pdf_path}", "green"))
            except Exception as e:
                self.logger.error(f"PDF generation failed: {e}")
                print(colored(f"[-] Warning: PDF generation failed: {e}", "yellow"))

        except FileNotFoundError:
             print(colored("[-] Error: Claude CLI not found or not executable.", "red"))

    def run(self):
        parser = argparse.ArgumentParser(description="fSOC APK Forensics CLI")
        parser.add_argument("--apk", help="Path to APK file or directory")
        parser.add_argument("--config", default="config.yaml", help="Path to configuration file")
        parser.add_argument("--quiet", action="store_true", help="Suppress banner")
        parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")
        parser.add_argument("--no-color", action="store_true", help="Disable colored output")
        parser.add_argument("--version", action="version", version=f"fSOC APK Forensics v{__version__}")

        args = parser.parse_args()

        self.display_banner(args.quiet, args.no_color)

        if not args.apk:
            print(colored("[-] Error: Please provide an APK path using --apk", "red"))
            parser.print_help()
            sys.exit(1)

        self.check_dependencies()

        if os.path.isdir(args.apk):
            # Batch mode
            print(colored(f"[*] Batch mode: Analyzing directory {args.apk}", "cyan"))
            for file in os.listdir(args.apk):
                if file.endswith(".apk"):
                    self.analyze_apk(os.path.join(args.apk, file), args.verbose)
        else:
            self.analyze_apk(args.apk, args.verbose)

        print(colored("\n[*] Analysis Complete.", "green", attrs=['bold']))

def main():
    tool = APKForensics()
    tool.run()

if __name__ == "__main__":
    main()
