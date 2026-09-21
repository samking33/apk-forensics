"""
AnalysisContext — parse an APK exactly once with androguard and share the
resulting objects across every static analyzer.

Before this existed the pipeline called AnalyzeAPK 2-3 times per sample (once in
parse_apk, again for DEX strings). AnalyzeAPK is the slowest step in the whole
run, so every new analyzer that needs the parsed objects takes them from here
instead of re-parsing.

Decompiled Java source is exposed lazily via `.source_dir` — jadx only runs when
an analyzer actually asks for source, and the result is cached on disk.
"""

import os

from core.static.apk_parser import sha256_file
from core.static import decompiler


class AnalysisContext:
    def __init__(self, apk_path: str):
        self.apk_path = os.path.abspath(apk_path)
        self.sha256   = sha256_file(self.apk_path)

        # Single, shared androguard analysis. a=APK, d=DEX list, dx=Analysis.
        from androguard.misc import AnalyzeAPK
        self.a, self.d, self.dx = AnalyzeAPK(self.apk_path)

        self._source_dir = False  # sentinel: not yet attempted
        self._class_names = None

    @property
    def class_names(self) -> list[str]:
        """Internal class names in slash form (e.g. 'com/google/firebase/X'),
        L…; stripped. Cached — used by tracker/SBOM/behaviour detection."""
        if self._class_names is None:
            names = []
            for dex in (self.d if isinstance(self.d, list) else [self.d]):
                if dex is None:
                    continue
                try:
                    for c in dex.get_classes():
                        n = c.get_name()            # 'Lcom/foo/Bar;'
                        names.append(n[1:-1] if n.startswith("L") and n.endswith(";") else n)
                except Exception:
                    continue
            self._class_names = names
        return self._class_names

    @property
    def source_dir(self):
        """Path to decompiled Java sources (jadx), or None if unavailable.
        Runs jadx once on first access, then caches the result for the run."""
        if self._source_dir is False:
            self._source_dir = decompiler.decompile(self.apk_path, self.sha256)
        return self._source_dir
