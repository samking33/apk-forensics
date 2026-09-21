"""
APK Similarity & Family Clustering — dependency-free fuzzy matching.

Instead of pulling in tlsh/ssdeep (C-extension deps), we fingerprint each APK as
a set of stable, app-specific tokens (non-framework class names + normalised
string constants) and compare with Jaccard similarity. This is robust to the
superficial repackaging that campaigns use — new cert, new package name, tweaked
resources — because the code token set barely moves.

fingerprint() → a compact set of hashed shingles (store per APK).
similarity()  → Jaccard overlap of two fingerprints, 0.0–1.0.
cluster()     → group samples whose pairwise similarity ≥ threshold (families).
"""

import re

# Framework / library prefixes that carry no campaign signal — dropped from the
# fingerprint so two unrelated apps don't look similar just for using AndroidX.
_FRAMEWORK = (
    "android/", "androidx/", "kotlin/", "kotlinx/", "java/", "javax/", "org/json",
    "com/google/android/", "com/google/gson", "org/apache/", "dagger/", "io/reactivex",
    "okhttp3/", "okio/", "retrofit2/", "com/squareup/", "org/intellij/", "org/jetbrains/",
)

_TOKEN_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_./]{3,}")


def _h(s: str) -> int:
    # Stable 32-bit hash (Python's hash() is salted per-process → unusable across runs).
    import hashlib
    return int.from_bytes(hashlib.blake2b(s.encode("utf-8", "replace"), digest_size=4).digest(), "big")


def fingerprint(class_names: list[str], dex_strings: list[str], max_tokens: int = 2000) -> set[int]:
    """Compact app-identity fingerprint: hashed set of app-specific class names +
    salient string constants. Deterministic across processes/runs."""
    tokens: set[str] = set()

    for cn in class_names:
        if not cn.startswith(_FRAMEWORK):
            tokens.add("C:" + cn)

    for s in dex_strings:
        s = s.strip()
        # Keep identifier-like / URL-ish constants; drop noise and huge blobs.
        if 5 <= len(s) <= 120 and _TOKEN_RE.fullmatch(s.replace(":", "/").replace("-", "_")):
            tokens.add("S:" + s)

    # Cap for memory determinism on giant apps — take the lexically-smallest slice
    # so the selection itself is deterministic (not insertion-order dependent).
    if len(tokens) > max_tokens:
        tokens = set(sorted(tokens)[:max_tokens])

    return {_h(t) for t in tokens}


def similarity(fp_a: set[int], fp_b: set[int]) -> float:
    if not fp_a or not fp_b:
        return 0.0
    inter = len(fp_a & fp_b)
    union = len(fp_a | fp_b)
    return inter / union if union else 0.0


def cluster(items: list[tuple], threshold: float = 0.6) -> list[list]:
    """items = [(id, fingerprint_set), …]. Returns lists of ids grouped into
    families by single-linkage on pairwise Jaccard ≥ threshold.
    ponytail: O(n²) pairwise + union-find — fine for the hundreds of samples a
    unit holds; switch to LSH banding only if the corpus reaches tens of thousands."""
    parent = {i: i for i, _ in items}

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(x, y):
        parent[find(x)] = find(y)

    for i in range(len(items)):
        id_i, fp_i = items[i]
        for j in range(i + 1, len(items)):
            id_j, fp_j = items[j]
            if similarity(fp_i, fp_j) >= threshold:
                union(id_i, id_j)

    groups: dict = {}
    for id_, _ in items:
        groups.setdefault(find(id_), []).append(id_)
    return [g for g in groups.values() if len(g) > 1] + \
           [g for g in groups.values() if len(g) == 1]


if __name__ == "__main__":
    # ponytail self-check: a repackaged variant clusters with its base; an
    # unrelated app stays separate.
    base    = [f"com/evil/mod{i}" for i in range(50)]
    variant = base[:45] + ["com/evil/extra1", "com/evil/extra2"]     # 90%+ overlap
    other   = [f"com/legit/app{i}" for i in range(50)]
    strings = ["http://c2.example/gate", "admin/number", "otp_code"]

    fp_base = fingerprint(base, strings)
    fp_var  = fingerprint(variant, strings)
    fp_oth  = fingerprint(other, [])

    assert similarity(fp_base, fp_var) > 0.6, similarity(fp_base, fp_var)
    assert similarity(fp_base, fp_oth) < 0.2, similarity(fp_base, fp_oth)

    fams = cluster([("base", fp_base), ("variant", fp_var), ("other", fp_oth)])
    family = [g for g in fams if len(g) > 1]
    assert family and set(family[0]) == {"base", "variant"}, fams
    print(f"OK — sim(base,variant)={similarity(fp_base, fp_var):.2f} "
          f"sim(base,other)={similarity(fp_base, fp_oth):.2f} families={family}")
