import re
from urllib.parse import unquote_plus

ATTACK_PATTERNS = {
    "XSS": [
        r"<script[^>]*>.*?</script>",
        r"javascript:",
        r"onerror\s*=",
        r"onload\s*=",
        r"onclick\s*=",
        r"<img[^>]+src[^>]*>",
        r"<svg[^>]*>",
        r"<iframe[^>]*>"
    ],
    "Local File Inclusion": [
        r"(file|page|include|template|doc|folder|root|path)\s*=\s*.*(\.\./|\.\.\\|/etc/passwd|/proc/self/environ|boot\.ini)",
    ],
    "Path Traversal": [
        r"\.\./",
        r"\.\.\\",
        r"%2e%2e%2f",
        r"%2e%2e%5c",
        r"/etc/passwd",
        r"/proc/self/environ",
        r"boot\.ini"
    ],
    "Command Injection": [
        r"(;|\|\||&&)\s*(whoami|id|uname|cat|ls|pwd|curl|wget|bash|sh)\b",
        r"`.*?`",
        r"\$\((.*?)\)"
    ],
    "SQL Injection": [
        r"'\s*or\s*1=1",
        r'"\s*or\s*"1"\s*=\s*"1',
        r"\bunion\b\s+\bselect\b",
        r"\bselect\b.+\bfrom\b",
        r"\bdrop\b\s+\btable\b",
        r"\binsert\b\s+\binto\b",
        r"\bdelete\b\s+\bfrom\b",
        r"\bupdate\b\s+\w+\s+\bset\b"
    ]
}

ATTACK_ORDER = [
    "XSS",
    "Local File Inclusion",
    "Path Traversal",
    "Command Injection",
    "SQL Injection"
]

def normalize_payload(payload: str) -> str:
    if not payload:
        return ""
    payload = unquote_plus(payload)
    return payload.strip().lower()

def detect_attack(payload: str):
    text = normalize_payload(payload)

    for attack_type in ATTACK_ORDER:
        for pattern in ATTACK_PATTERNS[attack_type]:
            if re.search(pattern, text, re.IGNORECASE | re.DOTALL):
                return attack_type
    return None