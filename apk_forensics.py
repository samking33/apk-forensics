"""
Update CLI banner to replace ghost figure with multiple smaller ghost-like figures
"""
#!/usr/bin/env python3
"""
fSOC APK Forensics - Professional CLI Forensic Analysis Tool
Author: APK Forensics by fSOC
Version: 1.0.0
"""

# The rest of the code remains unchanged...

    def display_banner(self, quiet: bool = False, no_color: bool = False):
        """Display the fSOC APK Forensics ASCII banner."""
        if quiet:
            return

        ghost_art = """
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