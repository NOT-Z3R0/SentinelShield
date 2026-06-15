import json
import os
from datetime import datetime

LOG_FILE = "logs/security_logs.json"

def ensure_log_file():
    os.makedirs("logs", exist_ok=True)
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, "w") as f:
            json.dump([], f)

def log_event(ip, method, path, payload, attack_type, action):
    ensure_log_file()

    entry = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "ip": ip,
        "method": method,
        "path": path,
        "payload": payload,
        "attack_type": attack_type,
        "action": action
    }

    with open(LOG_FILE, "r") as f:
        data = json.load(f)

    data.append(entry)

    with open(LOG_FILE, "w") as f:
        json.dump(data, f, indent=4)

def read_logs():
    ensure_log_file()
    with open(LOG_FILE, "r") as f:
        return json.load(f)