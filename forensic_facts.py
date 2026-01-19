# APK Forensics Facts Database
# 100 interesting facts about APK forensics, malware analysis, and mobile security

FORENSIC_FACTS = [
    "APK files are actually ZIP archives that can be extracted with standard tools",
    "The AndroidManifest.xml file contains all app permissions and components",
    "DEX (Dalvik Executable) files contain compiled Java/Kotlin code",
    "JADX can decompile DEX files back to readable Java source code",
    "Apktool is essential for decoding resources and AndroidManifest.xml",
    "Most Android malware requests INTERNET and READ_SMS permissions",
    "The classes.dex file is the main executable code in an APK",
    "APK signing certificates can reveal the developer's identity",
    "Obfuscation tools like ProGuard make reverse engineering harder",
    "Native libraries (.so files) often contain malicious payloads",
    
    "YARA rules can detect malware patterns in APK files",
    "The META-INF folder contains signature and certificate files",
    "Dynamic analysis runs APK in sandbox to observe behavior",
    "Static analysis examines code without executing the app",
    "Frida enables runtime instrumentation of Android apps",
    "APKs can contain multiple DEX files (multidex)",
    "The resources.arsc file contains compiled app resources",
    "Malware often uses reflection to hide malicious API calls",
    "String encryption is common in malicious APKs",
    "Certificate pinning prevents man-in-the-middle attacks",
    
    "Android banking trojans often use overlay attacks",
    "Dropper apps download and install additional malware",
    "C2 (Command & Control) servers communicate with malware",
    "Persistence mechanisms ensure malware survives reboots",
    "Root detection helps malware avoid analysis environments",
    "Emulator detection is common in sophisticated malware",
    "APK repackaging adds malicious code to legitimate apps",
    "The lib/ folder contains native ARM/x86 libraries",
    "Cryptominers drain battery and CPU for cryptocurrency",
    "SMS trojans intercept and send premium-rate messages",
    
    "Firebase is often abused for C2 communication",
    "Telegram bots are popular for malware control channels",
    "APK version codes help track malware evolution",
    "Package names starting with 'com' are most common",
    "Exported components are entry points for attackers",
    "Intent filters define how apps respond to actions",
    "Broadcast receivers can trigger on system events",
    "Services run in background without user interface",
    "Content providers can leak sensitive data",
    "Deep links can be exploited for phishing attacks",
    
    "SHA-256 hashes uniquely identify APK files",
    "VirusTotal aggregates scans from 70+ antivirus engines",
    "MobSF provides automated APK security analysis",
    "APKiD detects compilers, packers, and obfuscators",
    "Androguard is a Python framework for APK analysis",
    "Ghidra can reverse engineer native ARM code",
    "IDA Pro is the gold standard for binary analysis",
    "Burp Suite intercepts app network traffic",
    "Wireshark captures all network communications",
    "ADB (Android Debug Bridge) enables device debugging",
    
    "Malware families have unique behavioral signatures",
    "IoCs (Indicators of Compromise) help detect threats",
    "MITRE ATT&CK documents mobile attack techniques",
    "Google Play Protect scans 100+ billion apps daily",
    "Side-loading APKs bypasses Play Store security",
    "Permissions can be requested at runtime (Android 6+)",
    "Dangerous permissions require explicit user consent",
    "Normal permissions are granted automatically",
    "Signature permissions require same signing key",
    "System permissions are only for system apps",
    
    "WebView components can execute JavaScript code",
    "JavaScript bridges expose native functions to web",
    "SQL injection can exploit database queries",
    "Path traversal attacks access unauthorized files",
    "Intent spoofing tricks apps into malicious actions",
    "Tapjacking overlays fake UI over legitimate apps",
    "Accessibility services are abused by malware",
    "Device admin privileges enable remote wipe/lock",
    "VPN services can intercept all network traffic",
    "Notification listeners read all notifications",
    
    "Android 11+ restricts background location access",
    "Scoped storage limits file system access",
    "App sandboxing isolates apps from each other",
    "SELinux enforces mandatory access control",
    "SafetyNet detects rooted/modified devices",
    "Play Integrity API replaces SafetyNet",
    "Code obfuscation renames classes and methods",
    "String encryption hides malicious URLs/commands",
    "Control flow obfuscation confuses decompilers",
    "Packing compresses and encrypts DEX files",
    
    "Anti-debugging checks detect analysis tools",
    "Timing attacks detect debugger presence",
    "PTRACE checks prevent process tracing",
    "Native code is harder to analyze than Java",
    "JNI (Java Native Interface) bridges Java and C/C++",
    "ARM assembly is the native Android instruction set",
    "Smali is the assembly language for DEX files",
    "Baksmali disassembles DEX to Smali code",
    "APK Analyzer in Android Studio shows file sizes",
    "Logcat reveals runtime debug messages",
    
    "Xposed framework hooks into app methods",
    "Magisk provides systemless root access",
    "Lucky Patcher modifies apps to remove restrictions",
    "APK signature schemes v1, v2, v3, v4 exist",
    "v1 signing (JAR) is vulnerable to Janus attack",
    "v2+ signing protects entire APK from modification",
    "Certificate transparency logs track signing certs",
    "Code signing ensures app authenticity",
    "Self-signed certificates are common for malware",
    "Google Play requires apps to target recent API levels"
]

def get_random_fact():
    """Get a random forensic fact."""
    import random
    return random.choice(FORENSIC_FACTS)

def get_all_facts():
    """Get all forensic facts."""
    return FORENSIC_FACTS.copy()

