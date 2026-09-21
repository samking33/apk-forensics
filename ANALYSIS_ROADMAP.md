# fSOC — Analysis Capability Roadmap

Gap analysis against **androguard**, **MobSF**, **jadx**, **Exodus**, **Quark**, and the
commercial sandboxes — scoped to **TGCSB banking-trojan / OTP-theft investigations**.

Goal: replicate every capability those tools have, then beat them on the things that
actually matter for Indian banking-malware casework (accessibility abuse, SMS/OTP theft,
overlay phishing, C2 victim extraction, court-ready evidence).

---

## Legend

- ✅ **Have** — already in the codebase
- 🔶 **Partial** — exists but shallow vs. competitors
- ❌ **Missing** — competitors have it, we don't
- ⭐ **Edge** — capability that beats MobSF/androguard for *our* casework

Priority: **P0** = credibility gap, do first · **P1** = strong differentiator · **P2** = polish.

---

## 1. Static Analysis Core

### What MobSF / androguard do & how
- **androguard** parses the DEX into Dalvik objects, builds **cross-references (xrefs)**,
  **call graphs**, and control-flow graphs; decompiles methods to smali/pseudo-Java.
  It's the parsing engine — MobSF sits on top of it.
- **MobSF** layers a **security scorecard** on top: manifest audit, exported-component
  analysis, insecure-API pattern matching over decompiled code, certificate checks,
  tracker detection, secret hunting, and a CVSS-style score.
- **jadx** is the best-in-class DEX→Java decompiler (better output than androguard's).

### Our current state
| Capability | Status | Notes |
|---|---|---|
| APK metadata / manifest parse | ✅ | `apk_parser.py` via androguard |
| Permissions (dangerous set) | 🔶 | flat allowlist in `config.py`; no Android descriptions, no malware mapping |
| DEX + resource string extraction | ✅ | `apk_parser.py` |
| Regex string mining | ✅ | `string_miner.py` — 9 patterns |
| Firebase detection | ⭐ | `firebase_detector.py` — deeper than MobSF here |
| IOC extraction | ✅ | `ioc_extractor.py` |
| YARA scan | ✅ | `yara_scanner.py` |
| **Decompilation (smali/Java)** | ❌ | we extract strings but never decompile code |
| **Xref / call graph** | ❌ | androguard gives this free — we don't use it |
| **Manifest security audit + score** | ❌ | no exported-component / debuggable / backup / cleartext checks |
| **Insecure-API code scan** | ❌ | no crypto-misuse / WebView-bridge / SQL detection |
| **Certificate vuln analysis** | 🔶 | we grab cert SHA/serial/subject; no v1/v2/v3 scheme or weak-algo check |
| **Tracker / ad-SDK detection** | ❌ | Exodus-style tracker list |
| **Native `.so` ELF analysis** | ❌ | banking trojans hide loaders in native libs |
| **Third-party lib / SBOM** | ❌ | no library fingerprinting |

### To do
- **[P0] Add jadx decompilation.** Shell out to `jadx` (or `androguard decompile`) to get Java
  source, cache it per-APK. Everything below (code scanning) depends on this. — *jadx CLI / androguard*
- **[P0] Manifest security audit + scorecard.** Parse for: `exported=true` components, missing
  permissions on exported providers, `android:debuggable`, `allowBackup`, `usesCleartextTraffic`,
  `networkSecurityConfig`, custom permission protection levels, `taskAffinity`, launch modes.
  Emit a weighted risk score. — *androguard manifest API, our own rules*
- **[P0] Permission intelligence.** Map every requested permission → human description →
  malware-relevance tag (e.g. `BIND_ACCESSIBILITY_SERVICE` → CRITICAL for banking trojans).
  Replace the flat `DANGEROUS_PERMISSIONS` set with a scored table.
- **[P1] Insecure-code pattern scanner** over decompiled source: weak crypto (ECB, hardcoded
  IV/key), `MessageDigest MD5/SHA1`, `Random` for tokens, `WebView.addJavascriptInterface`,
  raw SQL, world-readable files, exported `Runtime.exec`. Ship as a YARA-on-source + regex ruleset.
- **[P1] Certificate deep analysis:** signing scheme (v1/v2/v3), self-signed check, validity,
  weak signature algo, and **cert-reuse clustering across cases** (developer attribution ⭐).
- **[P1] Tracker / ad-SDK fingerprinting** using the Exodus Privacy signature list (bundle offline).
- **[P2] Native `.so` triage:** ELF parse, exported symbols, embedded strings, packer strings
  (UPX etc.), `JNI_OnLoad` presence. — *lief / pyelftools*
- **[P2] Library / SBOM fingerprinting** by package-prefix + known class hashes.

---

## 2. Banking-Trojan-Specific Detection ⭐ (our real moat)

> MobSF is a **generic** app-security scanner. It does **not** specialize in the exact TTPs of
> Indian OTP-theft trojans. This section is where we go beyond every existing tool.

All of these are **❌ Missing** today and are the highest-value additions.

### To do
- **[P0] Accessibility-service abuse detection.** Detect `BIND_ACCESSIBILITY_SERVICE` +
  `accessibilityService` config + code that reads `AccessibilityEvent` / performs
  `performGlobalAction` / auto-clicks. This is the #1 mechanism modern banking trojans use to
  auto-grant permissions and read screen content. — *manifest + decompiled-code scan*
- **[P0] SMS/OTP interception logic.** Beyond the SMS permission: find `SmsReceiver` /
  `BroadcastReceiver` on `SMS_RECEIVED`, code that reads `pdus`, regex-extracts OTPs, and
  forwards them (HTTP/Firebase/SMS/Telegram). Classify the **exfil channel**.
- **[P0] Overlay / phishing-screen detection.** `SYSTEM_ALERT_WINDOW` + `TYPE_APPLICATION_OVERLAY`
  + WebView loading a bank-lookalike asset. Extract and **screenshot the embedded phishing HTML**
  for the evidence pack.
- **[P1] C2 channel classifier.** We nail Firebase already ⭐. Add: **Telegram bot tokens**
  (`bot<digits>:<35 chars>` + `api.telegram.org`), raw HTTP C2, Pastebin/GitHub dead-drops,
  hardcoded IPs. Output a normalized `c2_channel` per sample.
- **[P1] Dropper / second-stage detection.** DEX/APK/JAR hidden in `assets/` or `res/raw`,
  `DexClassLoader` / `PathClassLoader` dynamic loading, reflection-based invocation. Recursively
  analyze the dropped payload.
- **[P1] String-decryption / deobfuscation.** Banking trojans encrypt C2 strings. Detect the
  decrypt routine (common AES/XOR wrappers), and where feasible **emulate it** to recover
  plaintext C2. — *frida on-device, or unicorn/androguard emulation for offline*
- **[P2] Anti-analysis detection.** Emulator checks (`ro.build.fingerprint`, `qemu`), root
  checks, debugger checks, Frida/Xposed detection — flag them so analysts know the sample fights back.
- **[P2] Packer detection.** Known packer signatures (Jiagu, Bangcle, etc.) → route to unpacking
  workflow before deep analysis.

---

## 3. Dynamic / Sandbox Analysis

### What MobSF dynamic does & how
Boots an Android VM, installs the app, uses **Frida** for runtime instrumentation
(API monitor, TLS pinning bypass, hooked crypto/filesystem/network calls), captures
**logcat, screenshots, TLS traffic (mitmproxy), and exercises exported activities**.

### Our current state
| Capability | Status | Notes |
|---|---|---|
| Emulator / AVD management | ✅ | `emulator.py` |
| Frida hooks | 🔶 | `frida_hooks.py` — verify coverage |
| Traffic capture (mitmproxy) | ✅ | `traffic_capture.py` |
| **Runtime API monitor** | 🔶 | confirm we log crypto/SMS/file/network API calls |
| **Auto-exercise UI / exported activities** | ❌ | MobSF pokes every exported activity |
| **Runtime screenshots** | ❌ | huge for evidence packs |
| **TLS-pinning bypass** | 🔶 | Frida script needed |
| **Runtime OTP/SMS exfil capture** | ⭐❌ | send a fake SMS, watch it get stolen — killer demo for court |

### To do
- **[P0] Frida API-monitor suite:** hook crypto (`Cipher`, `MessageDigest`), SMS
  (`SmsManager`, receivers), file I/O, `HttpURLConnection`/OkHttp, `DexClassLoader`,
  accessibility calls. Log every call with args → timeline.
- **[P1] Runtime screenshot capture** at intervals + on overlay trigger → into evidence pack.
- **[P1] Automated OTP-theft proof:** inject a synthetic bank SMS via `adb`, observe the app
  read + forward it, capture the exfil request. **This single artifact is worth more in court
  than any static finding.** ⭐
- **[P1] Auto-exercise exported activities/receivers** to trigger hidden behavior.
- **[P2] TLS-pinning auto-bypass** Frida script bundled and auto-injected.

> Scaling note: sandbox runs cannot go inline in a web request — keep them on the async worker
> path (already the right instinct). ponytail: one AVD worker is fine until throughput demands a pool.

---

## 4. Intelligence & Correlation ⭐

### Our current state
| Capability | Status | Notes |
|---|---|---|
| Cross-APK correlation | 🔶 | `cross_apk.py` — extend to actor clustering |
| Financial quantum | ⭐ | `financial_quantum.py` — nobody else has this |
| Money-flow graph | ⭐ | `money_flow.py` |
| Geo victim map | ⭐ | `geo_map.py` |
| Firebase victim extraction | ⭐ | `firebase_probe.py` — our signature capability |

### To do
- **[P1] Fuzzy hashing + family clustering.** TLSH / ssdeep on the APK + DEX-method fuzzy hashes.
  Cluster incoming samples into **campaigns/families**; one upload lights up all related cases. — *tlsh, ssdeep, python-tlsh*
- **[P1] Threat-actor graph.** Cluster by shared Firebase project + signing cert + C2 + string
  constants + asset hashes → "same actor as March batch." Extend `cross_apk.py`.
- **[P1] Cross-campaign victim dedup + mule-network centrality.** Dedup victims across all cases;
  run PageRank/betweenness on the money-flow graph to rank mule accounts. — *networkx*
- **[P2] IOC enrichment fan-out:** VirusTotal, MalwareBazaar, abuse.ch, URLhaus on every IOC.
- **[P2] ML risk score** (permissions + API-call + opcode n-gram features → gradient boosting)
  as a scoring input, not the headline. — *scikit-learn / lightgbm*

---

## 5. Reporting & Evidence ⭐ (already a strength — extend it)

| Capability | Status |
|---|---|
| Forensic report | ✅ `forensic_report.py` |
| Victim register | ✅ `victim_register.py` |
| Leads report | ✅ `leads_report.py` |
| Encrypted evidence pack + chain-of-custody | ⭐ `evidence_pack.py` |

### To do
- **[P1] Section 65B (Indian Evidence Act) certificate** auto-generated per evidence pack —
  directly usable in Indian court. ⭐
- **[P1] MobSF-style HTML/PDF scorecard report** so analysts get the familiar visual scorecard
  competitors have, plus our victim/financial intel on top.
- **[P2] STIX 2.1 / MISP export** for sharing IOCs with CERT-In and other agencies.
- **[P2] Timeline reconstruction** (install → permission grant → first exfil → last activity)
  from static + dynamic + C2 timestamps.

---

## 6. Baseline hardening (do alongside)

- **[P0] Replace `config.py` flat sets with data files** — permission map, tracker signatures,
  malware-family YARA, C2 patterns all belong in versioned rule files, not Python constants.
- **[P1] Regression corpus** — a folder of known samples + expected findings, one `pytest` that
  fails if detection regresses. Non-negotiable once detection logic grows.

---

## Suggested execution order

1. **jadx decompilation + manifest audit + permission intelligence** (P0, §1) — unlocks all code scanning, closes the biggest credibility gap vs MobSF.
2. **Banking-trojan detectors: accessibility, SMS/OTP, overlay** (P0, §2) — our moat, and exactly what TGCSB casework needs.
3. **Frida API-monitor + runtime OTP-theft proof** (P0–P1, §3) — the courtroom artifact.
4. **Fuzzy hashing + actor clustering** (P1, §4) — turns one-off scans into campaign intelligence.
5. **65B certificate + scorecard report + STIX export** (P1, §5) — makes output court- and agency-ready.

---

*Principle: reuse the ecosystem — androguard for parsing, jadx for decompilation, Frida for
runtime, Exodus list for trackers, tlsh/ssdeep for similarity. We write the banking-trojan
intelligence and the victim/financial/evidence layer no one else has.*
