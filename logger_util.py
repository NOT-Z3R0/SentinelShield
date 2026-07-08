import json
import os
from datetime import datetime

CURRENT_LOG_FILE = "logs/current_session_logs.json"
ALL_LOG_FILE = "logs/all_logs.json"

def ensure_log_files():
    os.makedirs("logs", exist_ok=True)

    for log_file in [CURRENT_LOG_FILE, ALL_LOG_FILE]:
        if not os.path.exists(log_file):
            with open(log_file, "w") as f:
                json.dump([], f)

def reset_current_session_logs():
    ensure_log_files()
    with open(CURRENT_LOG_FILE, "w") as f:
        json.dump([], f, indent=4)

def log_event(ip, method, path, payload, attack_type, action):
    ensure_log_files()

    entry = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "ip": ip,
        "method": method,
        "path": path,
        "payload": payload,
        "attack_type": attack_type,
        "action": action
    }

    for log_file in [CURRENT_LOG_FILE, ALL_LOG_FILE]:
        with open(log_file, "r") as f:
            data = json.load(f)

        data.append(entry)

        with open(log_file, "w") as f:
            json.dump(data, f, indent=4)

def read_logs(view="current"):
    ensure_log_files()
    log_file = CURRENT_LOG_FILE if view == "current" else ALL_LOG_FILE

    with open(log_file, "r") as f:
        return json.load(f)