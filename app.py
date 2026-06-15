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

    for key, value in req.headers.items():
        parts.append(f"{key}: {value}")

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
    attack_summary = {}
    blocked_ips = {}

    for entry in logs:
        attack = entry["attack_type"]
        ip = entry["ip"]

        if attack != "None":
            attack_summary[attack] = attack_summary.get(attack, 0) + 1
            blocked_ips[ip] = blocked_ips.get(ip, 0) + 1

    return render_template(
        "dashboard.html",
        logs=logs[::-1],
        attack_summary=attack_summary,
        blocked_ips=blocked_ips,
        ip_stats=get_ip_stats()
    )

@app.route("/health")
def health():
    return jsonify({"status": "running", "project": "SentinelShield"})

if __name__ == "__main__":
    app.run(debug=True)