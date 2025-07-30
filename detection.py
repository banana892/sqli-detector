import re
from datetime import datetime

# Track failed attempts
failed_attempts = {}
blocked_ips = set()

SQLI_PATTERNS = [
    r"(?i)(\bor\b|\band\b).*(=|>|<|like)",
    r"(?i)(union(.*?)select)",
    r"(?i)(\bselect\b.*\bfrom\b)",
    r"(?i)(\binsert\b|\bupdate\b|\bdelete\b).*\binto\b",
    r"(--|#|/\*|\*/|;)",
    r"(?i)(\bdrop\b|\btruncate\b|\balter\b).*\btable\b",
    r"(?i)(sleep\s*\()",
    r"(?i)(benchmark\s*\()",
    r"(?i)(\bwhere\b.*[!=<>]+)"
]

NOSQL_PATTERNS = [
    r"(?i)\$ne", r"\$eq", r"\$gt", r"\$lt", r"\$regex", r"\$where",
    r"(?i)\{.*:.*\}",
    r'(?i)\{"username":.*\}'   # injection through json object
]

def detect_sqli(input_str):
    combined_patterns = SQLI_PATTERNS + NOSQL_PATTERNS
    return any(re.search(pattern, input_str) for pattern in combined_patterns)

def log_attack(ip, username, payload):
    with open("logs/sqli.log", "a") as log_file:
        log_file.write(f"[{datetime.now()}] SQLi Attempt from {ip} | Username: {username} | Payload: {payload}\n")

def register_failed_attempt(ip):
    failed_attempts[ip] = failed_attempts.get(ip, 0) + 1
    if failed_attempts[ip] >= 3:
        blocked_ips.add(ip)

def is_ip_blocked(ip):
    return ip in blocked_ips

def register_failed_attempt(ip):
    failed_attempts[ip] = failed_attempts.get(ip, 0) + 1
    if failed_attempts[ip] >= 3:
        blocked_ips.add(ip)
        with open("logs/sqli.log", "a") as log_file:
            log_file.write(f"[{datetime.now()}] IP BLOCKED: {ip}\n")
