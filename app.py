from flask import Flask, request, render_template, jsonify
from rules import detect_attack
from rate_limiter import is_rate_limited, get_ip_stats
from logger_util import log_event, read_logs

app = Flask(__name__)

def extract_payload(req):
    parts = []

    parts.append(req.path or "")
    parts.append(req.query_string.decode("utf-8", errors="ignore"))

    for key, value in req.args.items():
        parts.append(f"{key}={value}")

    for key, value in req.form.items():
        parts.append(f"{key}={value}")

    if req.data:
        parts.append(req.data.decode("utf-8", errors="ignore"))

    return " | ".join(parts)

@app.route("/", methods=["GET", "POST"])
def home():
    message = ""
    status = "safe"

    if request.method == "POST":
        ip = request.remote_addr or "127.0.0.1"
        payload = extract_payload(request)

        if is_rate_limited(ip):
            log_event(ip, request.method, request.path, payload, "Rate Limit Exceeded", "BLOCKED")
            return render_template("index.html", message="Too many requests from this IP. Request blocked.", status="blocked")

        attack_type = detect_attack(payload)

        if attack_type:
            log_event(ip, request.method, request.path, payload, attack_type, "BLOCKED")
            message = f"Malicious request detected: {attack_type}. Request blocked."
            status = "blocked"
        else:
            log_event(ip, request.method, request.path, payload, "None", "ALLOWED")
            message = "Normal request allowed."
            status = "safe"

    return render_template("index.html", message=message, status=status)

@app.route("/dashboard")
def dashboard():
    logs = read_logs()
    attack_summary = {
        "SQL Injection": 0,
        "XSS": 0,
        "Directory Traversal": 0,
        "Command Injection": 0,
        "LFI": 0,
        "Rate Limit Exceeded": 0
    }
    blocked_ips = {}
    allowed_count = 0
    blocked_count = 0

    for entry in logs:
        attack = entry.get("attack_type", "None")
        ip = entry.get("ip", "unknown")
        action = entry.get("action", "")

        if action == "ALLOWED":
            allowed_count += 1
        elif action == "BLOCKED":
            blocked_count += 1

        if attack in attack_summary:
            attack_summary[attack] += 1

        if action == "BLOCKED":
            blocked_ips[ip] = blocked_ips.get(ip, 0) + 1

    return render_template(
        "dashboard.html",
        logs=logs[::-1],
        attack_summary=attack_summary,
        blocked_ips=blocked_ips,
        ip_stats=get_ip_stats(),
        allowed_count=allowed_count,
        blocked_count=blocked_count
    )

@app.route("/health")
def health():
    return jsonify({"status": "running", "project": "SentinelShield"})

if __name__ == "__main__":
    app.run(debug=True)