"""
Decompiler — wraps jadx to produce Java source for code-level scanning.

jadx gives far better output than androguard's built-in decompiler, and every
insecure-API / behaviour scanner works over its `sources/` tree. Output is
cached under evidence_output/<sha16>/jadx so re-runs are free.

If jadx is not installed the pipeline degrades gracefully: analyzers that need
source simply report nothing rather than crashing.
"""

import os
import shutil
import subprocess

from config import EVIDENCE_DIR


def decompile(apk_path: str, sha256: str, timeout: int = 300) -> str | None:
    """
    Decompile APK to Java with jadx. Returns the sources directory path, or None
    if jadx is unavailable or produced nothing.

    A jadx timeout is NOT fatal — partial output is still worth scanning, so we
    return whatever sources exist. ponytail: single shared cache dir per sample;
    add per-analyzer isolation only if two analyzers ever need different jadx flags.
    """
    out_dir = os.path.join(EVIDENCE_DIR, sha256[:16], "jadx")
    src_dir = os.path.join(out_dir, "sources")

    # Cache hit — already decompiled this sample.
    if _has_sources(src_dir):
        return src_dir

    jadx = shutil.which("jadx")
    if not jadx:
        return None

    os.makedirs(out_dir, exist_ok=True)
    try:
        subprocess.run(
            [jadx, "--no-res", "-q", "--output-dir", out_dir, apk_path],
            timeout=timeout, capture_output=True, check=False,
        )
    except subprocess.TimeoutExpired:
        pass  # keep partial output
    except OSError:
        return None

    return src_dir if _has_sources(src_dir) else None


def _has_sources(src_dir: str) -> bool:
    return os.path.isdir(src_dir) and any(os.scandir(src_dir))


def iter_java_files(src_dir: str):
    """Yield every .java file path under a decompiled sources tree."""
    for root, _dirs, files in os.walk(src_dir):
        for f in files:
            if f.endswith(".java"):
                yield os.path.join(root, f)


if __name__ == "__main__":
    # ponytail self-check: decompile a system APK and confirm we get .java out.
    import sys
    apk = sys.argv[1] if len(sys.argv) > 1 else (
        "/opt/homebrew/share/android-commandlinetools/emulator/resources/skins/"
        "android-36/user/pixel_10/SystemUIEmulationPixel10Overlay.apk"
    )
    from core.static.apk_parser import sha256_file
    src = decompile(apk, sha256_file(apk))
    assert src is None or _has_sources(src), "decompile returned a non-existent dir"
    n = len(list(iter_java_files(src))) if src else 0
    print(f"OK — sources={src} java_files={n}")
