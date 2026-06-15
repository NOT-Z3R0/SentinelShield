import re

ATTACK_PATTERNS = {
    "SQL Injection": [
        r"(\bUNION\b.*\bSELECT\b)",
        r"(\bSELECT\b.*\bFROM\b)",
        r"(\bOR\b\s+1=1)",
        r"(--|#|/\*)",
        r"(\bDROP\b|\bINSERT\b|\bDELETE\b|\bUPDATE\b)"
    ],
    "XSS": [
        r"(<script.*?>.*?</script>)",
        r"(javascript:)",
        r"(onerror=|onload=|onclick=)",
        r"(<img.*?src=)",
        r"(<svg.*?>)"
    ],
    "Command Injection": [
        r"(\|\||&&|;)",
        r"(\bcat\b|\bls\b|\bwhoami\b|\bpwd\b)",
        r"(\bcurl\b|\bwget\b|\bbash\b|\bsh\b)"
    ],
    "Directory Traversal": [
        r"(\.\./|\.\.\\)",
        r"(/etc/passwd)",
        r"(boot\.ini)"
    ],
    "LFI": [
        r"(\bfile=)",
        r"(\bpage=)",
        r"(/proc/self/environ)",
        r"(/etc/passwd)"
    ]
}

def detect_attack(payload: str):
    if not payload:
        return None

    for attack_type, patterns in ATTACK_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, payload, re.IGNORECASE):
                return attack_type

    return None