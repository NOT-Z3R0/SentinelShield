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
    "Path Traversal": [
        r"\.\./",
        r"\.\.\\",
        r"/etc/passwd",
        r"boot\.ini",
        r"/proc/self/environ"
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
    ],
    "Local File Inclusion": [
        r"(file|page|include|template)\s*=\s*.*(\.\./|/etc/passwd|/proc/self/environ)"
    ]
}

ATTACK_ORDER = [
    "XSS",
    "Path Traversal",
    "Command Injection",
    "SQL Injection",
    "Local File Inclusion"
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