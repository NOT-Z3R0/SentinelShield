from flask import Flask, request, render_template, jsonify, redirect, url_for, make_response
from datetime import datetime
from io import StringIO
import csv

from rules import detect_attack
from rate_limiter import (
    check_and_update_attack_limit,
    get_ip_stats,
    get_blocked_ips,
    reset_rate_limiter,
    is_ip_blocked
)
from logger_util import log_event, read_logs, reset_current_session_logs

app = Flask(__name__)
app.secret_key = "sentinelshield-demo-key"

SESSION_START = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

reset_current_session_logs()
reset_rate_limiter()

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

def calculate_dashboard_metrics(logs):
    attack_summary = {
        "SQL Injection": 0,
        "XSS": 0,
        "Path Traversal": 0,
        "Local File Inclusion": 0,
        "Command Injection": 0,
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
            blocked_ips[ip] = blocked_ips.get(ip, 0) + 1

        if attack in attack_summary:
            attack_summary[attack] += 1

    top_attack_type = max(attack_summary, key=attack_summary.get) if any(attack_summary.values()) else "None"
    top_attack_count = attack_summary[top_attack_type] if top_attack_type != "None" else 0

    top_attacker_ip = max(blocked_ips, key=blocked_ips.get) if blocked_ips else "None"
    top_attacker_count = blocked_ips[top_attacker_ip] if top_attacker_ip != "None" else 0

    return {
        "attack_summary": attack_summary,
        "blocked_ips": blocked_ips,
        "allowed_count": allowed_count,
        "blocked_count": blocked_count,
        "top_attack_type": top_attack_type,
        "top_attack_count": top_attack_count,
        "top_attacker_ip": top_attacker_ip,
        "top_attacker_count": top_attacker_count
    }

@app.route("/", methods=["GET", "POST"])
def home():
    message = ""
    status = "safe"
    detected_type = "None"

    if request.method == "POST":
        ip = request.remote_addr or "127.0.0.1"
        payload = extract_payload(request)

        blocked, remaining = is_ip_blocked(ip)
        if blocked:
            minutes = remaining // 60
            seconds = remaining % 60
            log_event(ip, request.method, request.path, payload, "Rate Limit Exceeded", "BLOCKED")
            return render_template(
                "index.html",
                message=f"This IP is temporarily blocked for {minutes}m {seconds}s due to repeated malicious activity.",
                status="blocked",
                detected_type="Rate Limit Exceeded",
                session_start=SESSION_START
            )

        attack_type = detect_attack(payload)

        if attack_type:
            blocked_now, remaining, attack_count = check_and_update_attack_limit(ip, attack_type)

            if blocked_now and attack_count > 3:
                minutes = remaining // 60
                seconds = remaining % 60
                log_event(ip, request.method, request.path, payload, "Rate Limit Exceeded", "BLOCKED")
                message = f"Repeated {attack_type} attempts detected. IP blocked for {minutes}m {seconds}s."
                status = "blocked"
                detected_type = "Rate Limit Exceeded"
            else:
                log_event(ip, request.method, request.path, payload, attack_type, "BLOCKED")
                message = f"Malicious request detected: {attack_type}. Attempt {attack_count}/3 before temporary IP block."
                status = "blocked"
                detected_type = attack_type
        else:
            log_event(ip, request.method, request.path, payload, "None", "ALLOWED")
            message = "Normal request allowed."
            status = "safe"

    return render_template(
        "index.html",
        message=message,
        status=status,
        detected_type=detected_type,
        session_start=SESSION_START
    )

@app.route("/dashboard")
def dashboard():
    view = request.args.get("view", "current")
    ip_filter = request.args.get("ip", "").strip()
    attack_filter = request.args.get("attack", "").strip()
    action_filter = request.args.get("action", "").strip()

    logs = read_logs(view=view)

    if ip_filter:
        logs = [log for log in logs if log.get("ip", "") == ip_filter]

    if attack_filter:
        logs = [log for log in logs if log.get("attack_type", "") == attack_filter]

    if action_filter:
        logs = [log for log in logs if log.get("action", "") == action_filter]

    metrics = calculate_dashboard_metrics(logs)

    return render_template(
        "dashboard.html",
        logs=logs[::-1],
        ip_stats=get_ip_stats(),
        blocked_ip_times=get_blocked_ips(),
        session_start=SESSION_START,
        current_view=view,
        ip_filter=ip_filter,
        attack_filter=attack_filter,
        action_filter=action_filter,
        **metrics
    )

@app.route("/clear-session", methods=["POST"])
def clear_session():
    reset_current_session_logs()
    reset_rate_limiter()
    return redirect(url_for("dashboard"))

@app.route("/export-logs")
def export_logs():
    view = request.args.get("view", "current")
    logs = read_logs(view=view)

    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(["timestamp", "ip", "method", "path", "payload", "attack_type", "action"])

    for log in logs:
        writer.writerow([
            log.get("timestamp", ""),
            log.get("ip", ""),
            log.get("method", ""),
            log.get("path", ""),
            log.get("payload", ""),
            log.get("attack_type", ""),
            log.get("action", "")
        ])

    response = make_response(output.getvalue())
    response.headers["Content-Disposition"] = f"attachment; filename={view}_logs.csv"
    response.headers["Content-type"] = "text/csv"
    return response

@app.route("/health")
def health():
    return jsonify({"status": "running", "project": "SentinelShield"})

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)