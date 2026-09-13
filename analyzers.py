"""
Analysis engines:
  - analyze_log_alert(alert)   -> findings for a SIEM-style JSON/CSV alert
  - analyze_email(eml_path)    -> findings for a raw .eml email file
"""

import re
from email import policy
from email.parser import BytesParser

import config


def _bump(findings, indicator, severity, weight):
    findings["indicators"].append(indicator)
    findings["score"] += weight
    if config.SEVERITY_ORDER[severity] > config.SEVERITY_ORDER[findings["severity"]]:
        findings["severity"] = severity


def analyze_log_alert(alert: dict) -> dict:
    """Rule-based analysis of a single SIEM/log alert dict."""
    findings = {"score": 0, "severity": "Low", "indicators": []}

    src_ip = str(alert.get("src_ip", ""))
    dst_ip = str(alert.get("dst_ip", ""))
    description = str(alert.get("description", "")).lower()
    event_type = str(alert.get("event_type", "")).lower()
    reported_sev = alert.get("severity")

    if src_ip in config.BLACKLISTED_IPS or dst_ip in config.BLACKLISTED_IPS:
        _bump(findings, f"Communication with blacklisted IP ({src_ip or dst_ip})", "Critical", 40)

    for kw in ("malware", "ransomware", "trojan", "exploit", "privilege escalation"):
        if kw in description or kw in event_type:
            _bump(findings, f"Description/event type contains high-risk term: '{kw}'", "High", 25)

    for kw in ("brute force", "failed login", "multiple failed attempts"):
        if kw in description or kw in event_type:
            _bump(findings, "Possible brute-force / credential attack pattern", "Medium", 15)

    if "lateral movement" in description or "lateral movement" in event_type:
        _bump(findings, "Possible lateral movement activity", "High", 25)

    # Respect the SIEM's own severity if it's higher than what we've derived
    if reported_sev in config.SEVERITY_ORDER:
        if config.SEVERITY_ORDER[reported_sev] > config.SEVERITY_ORDER[findings["severity"]]:
            findings["severity"] = reported_sev
            findings["indicators"].append(f"Source SIEM reported severity: {reported_sev}")

    if not findings["indicators"]:
        findings["indicators"].append("No rule matches — appears benign or requires manual review")

    return findings


def analyze_email(eml_path: str) -> dict:
    """Parse a .eml file and flag phishing / malicious-attachment indicators."""
    findings = {"score": 0, "severity": "Low", "indicators": [], "meta": {}}

    with open(eml_path, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)

    sender = msg.get("From", "")
    subject = msg.get("Subject", "") or ""
    reply_to = msg.get("Reply-To", "")

    findings["meta"] = {"from": sender, "subject": subject, "reply_to": reply_to}

    body_text = ""
    for part in msg.walk():
        if part.get_content_type() == "text/plain":
            try:
                body_text += part.get_content()
            except Exception:
                pass

    combined_text = f"{subject} {body_text}".lower()

    # Keyword-based phishing detection
    hit_keywords = [kw for kw in config.PHISHING_KEYWORDS if kw in combined_text]
    if hit_keywords:
        _bump(findings, f"Phishing keyword(s) found: {', '.join(hit_keywords)}", "Medium", 15 * len(hit_keywords))

    # Sender/Reply-To mismatch (classic spoofing indicator)
    sender_domain_match = re.search(r"@([\w.-]+)", sender)
    reply_domain_match = re.search(r"@([\w.-]+)", reply_to) if reply_to else None
    if sender_domain_match and reply_domain_match:
        if sender_domain_match.group(1).lower() != reply_domain_match.group(1).lower():
            _bump(findings, f"Sender/Reply-To domain mismatch ({sender_domain_match.group(1)} vs {reply_domain_match.group(1)})", "High", 25)

    if sender_domain_match and sender_domain_match.group(1).lower() in config.SUSPICIOUS_SENDER_DOMAINS:
        _bump(findings, f"Sender domain on watch-list: {sender_domain_match.group(1)}", "Low", 5)

    # URLs in body
    urls = re.findall(r"https?://[^\s\"'>]+", body_text)
    if urls:
        findings["meta"]["urls"] = urls
        for domain in config.BLACKLISTED_DOMAINS:
            if any(domain in u for u in urls):
                _bump(findings, f"Body contains link to blacklisted domain: {domain}", "Critical", 40)

    # Attachments
    attachments = []
    for part in msg.iter_attachments():
        fname = part.get_filename() or "unnamed"
        attachments.append(fname)
        ext = "." + fname.rsplit(".", 1)[-1].lower() if "." in fname else ""
        if ext in config.SUSPICIOUS_ATTACHMENT_EXTENSIONS:
            _bump(findings, f"Suspicious attachment type: {fname} ({ext})", "Critical", 35)

    findings["meta"]["attachments"] = attachments

    if not findings["indicators"]:
        findings["indicators"].append("No rule matches — appears benign or requires manual review")

    return findings
