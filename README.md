# SentinelShield

SentinelShield is a small educational web security project built with Flask. It works like a lightweight request inspection and detection tool that checks user input for common attack patterns such as SQL injection, XSS, directory traversal, command injection, and local file inclusion.

The goal of the project is to show how a simple web protection workflow works in practice: inspect input, detect suspicious patterns, log the event, and display useful details on a dashboard for review.

## Features

- Detects common web attack patterns:
  - SQL Injection
  - Cross-Site Scripting (XSS)
  - Directory Traversal
  - Command Injection
  - Local File Inclusion (LFI)
- Basic rate limiting for repeated requests from the same IP
- Logs allowed and blocked requests
- Dashboard for viewing:
  - total allowed requests
  - total blocked requests
  - top attack type
  - top attacker IP
  - attack summary
  - recent security logs
- Clear current session option
- Export logs option (if enabled in the current version)

## Project Structure

```text
SentinelShield/
├── app.py
├── rules.py
├── rate_limiter.py
├── logger_util.py
├── requirements.txt
├── README.md
├── .gitignore
├── logs/
│   └── security_logs.json
├── templates/
│   ├── index.html
│   └── dashboard.html
└── static/
    └── style.css
```

## Requirements

- Python 3.10 or above recommended
- pip
- Git

## Installation

Clone the repository and move into the project folder:

```bash
git clone <https://github.com/NOT-Z3R0/SentinelShield>
cd SentinelShield
```

Create a virtual environment:

### Windows
```bash
python -m venv venv
venv\Scripts\activate
```

### Linux / Kali / macOS
```bash
python3 -m venv venv
source venv/bin/activate
```

Install the required package:

```bash
python -m pip install -r requirements.txt
```

## Running the Project

Start the Flask application:

```bash
python app.py
```

After the server starts, open this address in your browser:

```text
http://127.0.0.1:5000
```

## How to Test

On the home page, enter one payload at a time in the input box and submit it.

### Normal input
```text
hello world
```

Expected result: request should be allowed.

### SQL Injection test
```text
' OR 1=1 --
```

Expected result: request should be blocked as SQL Injection.

### XSS test
```text
<script>alert(1)</script>
```

Expected result: request should be blocked as XSS.

### Directory Traversal test
```text
../../etc/passwd
```

Expected result: request should be blocked as Directory Traversal.

### Command Injection test
```text
; whoami
```

Expected result: request should be blocked as Command Injection.

### LFI test
```text
page=../../etc/passwd
```

Expected result: request should be blocked as LFI or file access related attack, depending on the matching rule.

## Dashboard

The dashboard shows a summary of activity recorded by the application. It can be used to review:

- allowed requests
- blocked requests
- most common attack type
- most active attacker IP
- attack counts by category
- request activity by IP
- security log entries

## Notes

- This project is built for learning and local testing.
- It uses rule-based pattern matching, so it may still produce false positives or false negatives in some cases.
- It is not intended for production deployment as a real web application firewall.
- The Flask development server is used only for local testing.

## Possible Improvements

Some future improvements that can be added:

- better rule tuning to reduce false positives
- persistent database logging
- authentication for dashboard access
- data visualization charts
- deployment using a production WSGI server
- more advanced request analysis

## Author

Project developed as part of a cybersecurity practical project submission.