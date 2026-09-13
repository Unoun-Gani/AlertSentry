"""
Configuration for the SOC L1 Alert Monitoring & Reporting Tool.
Tune these lists/thresholds to your environment.
"""

# --- Directories ---
LOGS_DIR = "sample_logs"          # JSON/CSV alert files land here
EMAILS_DIR = "sample_emails"      # .eml files land here
REPORTS_DIR = "reports"           # generated case reports go here
INDEX_FILE = "reports/_index.md"  # master index of all cases

# --- Suspicious attachment extensions (common malware droppers) ---
SUSPICIOUS_ATTACHMENT_EXTENSIONS = [
    ".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar",
    ".hta", ".msi", ".dll", ".iso", ".lnk", ".chm",
    ".docm", ".xlsm", ".pptm",  # macro-enabled Office docs
]

# --- Keywords in email subject/body that often indicate phishing ---
PHISHING_KEYWORDS = [
    "verify your account", "urgent action required", "password expires",
    "click here immediately", "suspended", "confirm your identity",
    "invoice attached", "wire transfer", "gift card", "unusual sign-in",
    "your account will be closed", "act now", "payment overdue",
]

# --- Free / high-risk mail providers often abused for spoofing display names ---
SUSPICIOUS_SENDER_DOMAINS = [
    "mail.ru", "yandex.com", "protonmail.com",  # not inherently malicious, just higher scrutiny
]

# --- Known-bad / test indicator lists (replace with real threat intel feeds) ---
BLACKLISTED_IPS = set()      # e.g. {"185.220.101.1"}
BLACKLISTED_DOMAINS = set()  # e.g. {"evil-domain.example"}

# --- Alert severity from log 'severity' or 'risk_score' field ---
SEVERITY_ORDER = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}

# --- Log field names (adjust to match your SIEM export schema) ---
# Expected JSON alert shape (one object per line, JSONL) or CSV with these headers:
# timestamp, alert_id, source, src_ip, dst_ip, user, event_type, description, severity
