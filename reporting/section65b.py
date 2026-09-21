"""
Section 65B Certificate — Indian Evidence Act, 1872 (§65B(4)) / BSA 2023 §63.

Electronic evidence is inadmissible in Indian courts without a §65B(4)
certificate identifying the record, the computer that produced it, and certifying
its integrity. This generates that certificate for an analysed APK / evidence
pack, ready for an examiner to date and sign — a concrete court-readiness edge
no generic malware scanner ships.

The examiner details are left as fill-in lines: the certificate must be signed by
the person occupying a responsible official position in relation to the device.
"""

from datetime import datetime, timezone


def generate(apk_meta: dict, sha256: str, *, case_ref: str = "",
             examiner_name: str = "", examiner_designation: str = "",
             tool_version: str = "fSOC 2.0") -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    pkg = apk_meta.get("package_name") or "unknown"
    fname = apk_meta.get("filename") or "sample.apk"

    lines = [
        "=" * 74,
        "  CERTIFICATE UNDER SECTION 65B(4) OF THE INDIAN EVIDENCE ACT, 1872",
        "  (read with Section 63 of the Bharatiya Sakshya Adhiniyam, 2023)",
        "=" * 74,
        "",
        f"  Case Reference   : {case_ref or '____________________'}",
        f"  Date of Issue    : {now}",
        "",
        "  1. IDENTIFICATION OF THE ELECTRONIC RECORD",
        f"     Filename        : {fname}",
        f"     Package name    : {pkg}",
        f"     SHA-256 hash    : {sha256}",
        f"     Certificate hash: {apk_meta.get('cert_sha256') or 'n/a'}",
        "",
        "  2. PRODUCTION OF THE RECORD",
        "     The above electronic record and the accompanying analysis reports",
        "     were produced by a computer system used regularly to store and",
        f"     process information for the purposes of forensic examination, using",
        f"     the automated analysis tool '{tool_version}'.",
        "",
        "  3. REGULAR USE",
        "     Throughout the material period the computer was operating properly",
        "     (or, if not, any malfunction did not affect the accuracy or",
        "     integrity of the electronic record produced).",
        "",
        "  4. INTEGRITY",
        "     The SHA-256 hash recorded above uniquely identifies the electronic",
        "     record. Any alteration of the record would change this hash value,",
        "     thereby establishing that the evidence has not been tampered with.",
        "",
        "  5. CERTIFICATION",
        "     I, occupying a responsible official position in relation to the",
        "     operation of the said device, certify that the contents of this",
        "     certificate are true to the best of my knowledge and belief.",
        "",
        f"     Examiner Name   : {examiner_name or '_________________________________'}",
        f"     Designation     : {examiner_designation or '_________________________________'}",
        "     Badge / ID No.  : _________________________________",
        "     Date & Place    : _________________________________",
        "     Signature       : _________________________________",
        "",
        "=" * 74,
    ]
    return "\n".join(lines)


if __name__ == "__main__":
    cert = generate(
        {"filename": "fake_bank.apk", "package_name": "com.evil.app", "cert_sha256": "abc123"},
        sha256="d" * 64, case_ref="TGCSB/2026/CYB/001",
        examiner_name="Insp. R. Rao", examiner_designation="Inspector, TGCSB",
    )
    assert "SECTION 65B(4)" in cert
    assert "d" * 64 in cert
    assert "com.evil.app" in cert
    assert "TGCSB/2026/CYB/001" in cert
    print(cert[:200])
    print("...\nOK — 65B certificate generated")
