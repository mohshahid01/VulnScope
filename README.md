# VulnScope 1.0

VulnScope is a Python-based, non-destructive web and
network assessment tool.

## Features

- HTTP and HTTPS response checks
- Security-header analysis
- Server banner detection
- Common-path discovery
- TLS certificate validation
- Optional Nmap service detection
- Risk ranking
- Terminal findings
- HTML reports
- JSON reports
- CSV reports
- Configurable target scope and request limits

## Requirements

- Python 3.11+
- pip
- Nmap (optional)

## Linux / Kali installation

Install dependencies:

    sudo apt update
    sudo apt install -y python3 python3-pip python3-venv nmap

Create virtual environment:

    python3 -m venv .venv

Activate it:

    source .venv/bin/activate

Install Python packages:

    pip install -r requirements.txt

Run tests:

    python -m unittest discover -s tests -v

## Local test

Terminal 1:

    python3 -m http.server 8000 --bind 127.0.0.1

Terminal 2:

    python main.py http://localhost:8000

Skip Nmap:

    python main.py http://localhost:8000 --no-nmap

## Reports

Reports are generated in:

    reports/

The application generates:

- HTML
- JSON
- CSV

## Scope configuration

The default configuration permits localhost only.

For a public website you own or have explicit permission to
assess, add its exact hostname to allowed_hosts and enable
allow_public_ips_for_allowlisted_hosts in scope.json.

Use only ports and checks included in the approved assessment plan.

## Limitations

This version does not perform exploitation, brute force,
authentication bypass, recursive crawling, or verified CVE matching.

A missing security header, discovered path, or open port is
not automatically a vulnerability.

It does not guarantee complete vulnerability coverage.

DNS resolution is checked during validation, but the current
HTTP transport resolves the hostname again when making requests.
Production deployment should pin connections to validated IPs
while preserving hostname verification and TLS SNI.
