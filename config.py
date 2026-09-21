import os

BASE_DIR        = os.path.dirname(os.path.abspath(__file__))
DB_PATH         = os.path.join(BASE_DIR, "tgcsb_cases.db")
EVIDENCE_DIR    = os.path.join(BASE_DIR, "evidence_output")
YARA_RULES_DIR  = os.path.join(BASE_DIR, "yara_rules")

# Firebase Firestore REST API
FIRESTORE_BASE  = "https://firestore.googleapis.com/v1/projects/{project_id}/databases/(default)/documents"
FIREBASE_AUTH   = "https://identitytoolkit.googleapis.com/v1/accounts:signInAnonymously?key={api_key}"

# Known banking trojan patterns (from AppointmentBookingTrojan investigation)
KNOWN_MALWARE_PACKAGES = {
    "com.app.customersupport",
    "com.appointment.booking",
    "com.bank.support",
    "com.customer.care",
}

DANGEROUS_PERMISSIONS = {
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_SMS",
    "android.permission.SEND_SMS",
    "android.permission.READ_CONTACTS",
    "android.permission.READ_CALL_LOG",
    "android.permission.READ_PHONE_STATE",
    "android.permission.RECEIVE_BOOT_COMPLETED",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.CAMERA",
    "android.permission.RECORD_AUDIO",
    "android.permission.BIND_DEVICE_ADMIN",
    "android.permission.READ_PHONE_NUMBERS",
}

# Regex patterns for string mining
PATTERNS = {
    "firebase_api_key" : r'AIza[0-9A-Za-z\-_]{35}',
    "firebase_project" : r'[a-z0-9\-]+-[0-9a-f]{4,8}(?:\.firebaseapp\.com|\.web\.app)?',
    "google_services"  : r'"project_id"\s*:\s*"([^"]+)"',
    "phone_in"         : r'(?<!\d)(?:\+91|91)?[6-9]\d{9}(?!\d)',
    "url_http"         : r'https?://[^\s\'"<>]+',
    "ip_address"       : r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
    "email"            : r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}',
    "aes_key"          : r'(?i)(?:key|secret|aes|encrypt)["\s:=]+([A-Za-z0-9+/=]{16,})',
    "package_name"     : r'com\.[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+',
}

os.makedirs(EVIDENCE_DIR, exist_ok=True)
