# Port Scanner Toolkit

A lightweight, multithreaded TCP port scanner with banner grabbing and automated reporting, built in pure Python with zero external dependencies.

Designed as a hands-on project to explore core network security concepts: TCP connection scanning, service fingerprinting, and basic vulnerability signature matching.

---

## Table of contents

- [Overview](#overview)
- [Features](#features)
- [Legal and ethical use](#legal-and-ethical-use)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [CLI options](#cli-options)
- [Sample output](#sample-output)
- [How it works](#how-it-works)
- [Project structure](#project-structure)
- [Limitations](#limitations)
- [Roadmap](#roadmap)
- [License](#license)

---

## Overview

`port-scanner-toolkit` scans a target host for open TCP ports, attempts to identify the service running on each open port via banner grabbing, and flags known outdated service signatures. Results are exported as text, HTML, and JSON reports.

The project was built to practice core networking and security concepts hands-on rather than to compete with production-grade tools like Nmap — it favors readable, well-documented code over feature completeness.

## Features

- **Multithreaded scanning** — configurable worker pool for fast scans of large port ranges
- **Banner grabbing** — reads service banners (SSH, FTP, SMTP, HTTP, etc.) to identify what's actually running behind an open port
- **Signature matching** — flags a small set of known outdated / historically vulnerable service versions
- **Multi-format reporting** — plain text, styled HTML, and machine-readable JSON
- **Flexible port selection** — single port, numeric range, comma-separated list, or a curated default set of common ports
- **No external dependencies** — runs on any standard Python 3.8+ installation

## Legal and ethical use

> **This tool must only be used against systems you own or are explicitly authorized to test** — e.g. your own machines, local virtual machines, or platforms built for security training (TryHackMe, HackTheBox, etc.).

Scanning systems without authorization is illegal in most jurisdictions (in Italy, for example, under Art. 615-ter of the Penal Code and related regulations) and may violate the terms of service of your ISP or hosting provider. The author assumes no responsibility for misuse of this software. Use it to learn, not to attack.

## Requirements

- Python 3.8 or later
- No third-party packages required (standard library only — see `requirements.txt`)

## Installation

```bash
git clone https://github.com/<your-username>/port-scanner-toolkit.git
cd port-scanner-toolkit
```

No virtual environment or `pip install` is strictly necessary, since the project has no external dependencies. If you prefer an isolated environment anyway:

```bash
python3 -m venv venv
source venv/bin/activate   # on Windows: venv\Scripts\activate
pip install -r requirements.txt
```

## Usage

Scan a target using the default set of common ports:

```bash
python3 port_scanner.py 127.0.0.1
```

Scan a specific port range:

```bash
python3 port_scanner.py 127.0.0.1 -p 1-1024
```

Scan a specific list of ports:

```bash
python3 port_scanner.py 192.168.1.10 -p 22,80,443,3306
```

Tune concurrency and timeout for faster or more reliable scans:

```bash
python3 port_scanner.py 127.0.0.1 -p 1-65535 -w 300 -t 0.5
```

Skip banner grabbing (port discovery only, faster):

```bash
python3 port_scanner.py 127.0.0.1 -p 1-1024 --no-banner
```

Choose which report formats to generate:

```bash
python3 port_scanner.py 127.0.0.1 --formats txt,html,json
```

## CLI options

| Flag | Description | Default |
|---|---|---|
| `host` | Target IP address or hostname (positional argument) | required |
| `-p`, `--ports` | Ports to scan: single (`80`), range (`1-1024`), or list (`22,80,443`) | curated list of common ports |
| `-t`, `--timeout` | Per-connection timeout, in seconds | `1.0` |
| `-w`, `--workers` | Number of parallel scanning threads | `100` |
| `--no-banner` | Disable banner grabbing | disabled by default (banner grabbing on) |
| `-o`, `--output-dir` | Directory where reports are saved | `reports` |
| `--formats` | Comma-separated report formats to generate (`txt`, `html`, `json`) | `txt,html` |

Run `python3 port_scanner.py --help` for the full list at any time.

## Sample output

Console output during a scan:

```
[*] Target: 127.0.0.1 (127.0.0.1)
[*] Scanning 127.0.0.1 on 21 ports (timeout=1.0s, threads=100)...

[+] Port    22 OPEN  (expected service: SSH)
[+] Port   445 OPEN  (expected service: SMB)

[*] Grabbing banners on open ports...

    Port    22: SSH-2.0-OpenSSH_10.0
    Port   445: (no banner received)

[*] Scan completed in 0.42s. Open ports found: 2
```

Generated report excerpt (`reports/scan_<host>_<timestamp>.txt`):

```
============================================================
PORT SCAN REPORT
============================================================
Host:           127.0.0.1
Scan date:      2026-08-11 13:19:25
Duration:       3.11s
Open ports:     2
------------------------------------------------------------
Port 22 (SSH)
  Banner:  SSH-2.0-OpenSSH_10.0

Port 445 (SMB)
  Banner:  (no banner received)
============================================================
```

An HTML version of the same report is also generated, with a dark, readable layout suitable for sharing or archiving scan results.

## How it works

1. **Port scan** — for every port in the target list, the script attempts a TCP `connect()` (via `socket.connect_ex`) with a short timeout. A successful connection marks the port as open. This is a standard TCP connect scan — no raw sockets or elevated privileges required, unlike a SYN stealth scan.
2. **Banner grabbing** — for each open port, the script reconnects and reads whatever data the service sends. For services that wait for a request before responding (like HTTP), it sends a minimal probe to trigger a reply.
3. **Signature check** — each banner is compared against a small local dictionary of known outdated version strings, flagging potential concerns for manual follow-up.
4. **Reporting** — results are written to the `reports/` directory as timestamped text, HTML, and/or JSON files, so scans can be archived and compared over time.

## Project structure

```
port-scanner-toolkit/
├── README.md
├── LICENSE
├── requirements.txt
├── .gitignore
├── port_scanner.py
└── reports/              # generated reports land here (gitignored)
```

## Limitations

- TCP connect scan only — no SYN/stealth scanning, no UDP support
- No TLS handshake for banner grabbing on HTTPS-like ports (reported as unavailable rather than guessed)
- The vulnerable-signature database is intentionally minimal and meant for learning — it is **not** a substitute for a real vulnerability feed (e.g. NVD, Vulners)
- Scans a single host at a time; no CIDR/subnet sweeping yet

## Roadmap

- [ ] CIDR range support (scan multiple hosts in one run)
- [ ] Async implementation using `asyncio` as an alternative to threading
- [ ] Integration with a real vulnerability database (e.g. NVD API)
- [ ] UDP scanning support
- [ ] Automated "risk summary" section in reports (plain-language recommendations per finding)

## License

Released under the [MIT License](LICENSE) — free to use, modify, and distribute.

---

*Built as a personal project to learn network security fundamentals. Feedback and pull requests are welcome.*
