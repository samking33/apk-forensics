"""
Native Library Triage — ELF parsing of lib/**/*.so without external tooling.

Banking trojans increasingly hide the interesting logic (string decryption, C2,
anti-analysis) in native code. Full symbol/disassembly analysis needs lief; we
deliberately stay stdlib-only (struct + ASCII strings) and extract the forensic
signals that matter: architecture, packer markers, native entrypoints,
anti-debug/anti-Frida strings, and embedded URLs/IPs.

ponytail: strings + header parsing, not disassembly. Add lief-based symbol
analysis only if a case needs to reverse a specific .so.
"""

import re
import struct
import zipfile

_ELF_MAGIC = b"\x7fELF"

# e_machine → arch name (subset relevant to Android)
_MACHINES = {0x28: "arm", 0xB7: "arm64", 0x03: "x86", 0x3E: "x86_64", 0x08: "mips"}

_STRING_RE = re.compile(rb"[\x20-\x7e]{5,}")
_URL_RE    = re.compile(r"https?://[^\s'\"<>]+")
_IP_RE     = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

_PACKER_MARKERS   = [b"UPX!", b"$Info: This file is packed with the UPX",
                     b"jiagu", b"libjiagu", b"bangcle", b"libsecmain", b"libDexHelper"]
_ANTI_ANALYSIS    = ["ptrace", "anti_debug", "antidebug", "frida", "xposed",
                     "TracerPid", "/proc/self/status", "isDebuggerConnected"]


def _arch(data: bytes) -> str:
    try:
        machine = struct.unpack_from("<H", data, 18)[0]  # e_machine @ offset 18
        return _MACHINES.get(machine, f"0x{machine:x}")
    except struct.error:
        return "unknown"


def scan(apk_path: str) -> tuple[list[dict], list[dict]]:
    """Returns (findings, native_libs). native_libs = [{name, arch, size}]."""
    findings: list[dict] = []
    libs: list[dict] = []

    def add(sev, title, detail, where):
        findings.append({"category": "NATIVE", "severity": sev, "title": title,
                         "detail": detail, "found_at": where})

    try:
        z = zipfile.ZipFile(apk_path)
    except (zipfile.BadZipFile, OSError):
        return findings, libs

    with z:
        so_names = [n for n in z.namelist() if n.startswith("lib/") and n.endswith(".so")]
        for name in so_names:
            try:
                data = z.read(name)
            except (OSError, zipfile.BadZipFile):
                continue
            if data[:4] != _ELF_MAGIC:
                continue

            libs.append({"name": name, "arch": _arch(data), "size": len(data)})

            # Packer markers.
            for marker in _PACKER_MARKERS:
                if marker in data:
                    add("HIGH", "Packed/protected native library",
                        f"Packer marker '{marker.decode(errors='replace')}' in {name}", name)
                    break

            # ASCII strings (cap to keep memory bounded on big libs).
            strings = [m.group().decode("ascii", "replace")
                       for m in _STRING_RE.finditer(data[:5_000_000])]
            joined = "\n".join(strings)
            low = joined.lower()

            if "JNI_OnLoad" in joined:
                add("INFO", "Native entrypoint (JNI_OnLoad)",
                    f"{name} runs code at load time via JNI_OnLoad", name)

            hits = sorted({a for a in _ANTI_ANALYSIS if a.lower() in low})
            if hits:
                add("MEDIUM", "Anti-analysis strings in native lib",
                    f"{name}: {', '.join(hits)}", name)

            urls = sorted(set(_URL_RE.findall(joined)))[:10]
            ips  = sorted(set(ip for ip in _IP_RE.findall(joined)
                              if not ip.startswith(("0.", "127.", "255."))))[:10]
            if urls:
                add("MEDIUM", f"URLs embedded in native lib ({len(urls)})",
                    f"{name}: {', '.join(urls[:5])}", name)
            if ips:
                add("MEDIUM", f"IPs embedded in native lib ({len(ips)})",
                    f"{name}: {', '.join(ips[:5])}", name)

    return findings, libs


if __name__ == "__main__":
    import sys
    apk = sys.argv[1] if len(sys.argv) > 1 else None
    if not apk:
        # ponytail self-check: an ELF blob with a UPX marker must flag as packed.
        import io, zipfile as zf, tempfile, os
        blob = _ELF_MAGIC + b"\x01\x01\x01" + b"\x00" * 11 + struct.pack("<H", 0xB7) + \
               b"\x00" * 40 + b"UPX!padding JNI_OnLoad frida http://evil.example/c2"
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "t.apk")
            with zf.ZipFile(p, "w") as z:
                z.writestr("lib/arm64-v8a/libx.so", blob)
            f, libs = scan(p)
        titles = {x["title"] for x in f}
        assert libs and libs[0]["arch"] == "arm64", libs
        assert any("Packed" in t for t in titles), titles
        assert any("JNI_OnLoad" in t for t in titles), titles
        print(f"OK — libs={libs} findings={sorted(titles)}")
    else:
        f, libs = scan(apk)
        print(f"libs={len(libs)} findings={len(f)}")
