# Architecture & Network Isolation Design

## CVE-2021-41773 / CVE-2021-42013 Validation Lab

---

## 1. Network Topology

```
┌─────────────────────────────────────────────────────────────────┐
│                        HOST MACHINE                             │
│                                                                 │
│   ┌─────────────────────────────────────────────────────────┐  │
│   │              Docker Bridge: lab_isolated_net             │  │
│   │                                                          │  │
│   │   ┌──────────────────────┐   ┌───────────────────────┐  │  │
│   │   │  cve_lab_vulnerable  │   │   cve_lab_patched     │  │  │
│   │   │  Apache 2.4.49       │   │   Apache 2.4.51       │  │  │
│   │   │  Image: httpd:2.4.49 │   │   Image: httpd:2.4.51 │  │  │
│   │   │  Internal port: 80   │   │   Internal port: 80   │  │  │
│   │   └──────────┬───────────┘   └──────────┬────────────┘  │  │
│   │              │                           │               │  │
│   └──────────────┼───────────────────────────┼───────────────┘  │
│                  │                           │                  │
│          127.0.0.1:8080              127.0.0.1:8081             │
│                  │                           │                  │
│   ┌──────────────▼───────────────────────────▼────────────────┐ │
│   │                  Scripts / CLI (Host)                      │ │
│   │   detect_cve.py  validate_traversal.py  validate_cgi_...  │ │
│   └────────────────────────────────────────────────────────────┘ │
│                                                                 │
│   ❌ NOT EXPOSED TO: 0.0.0.0 / LAN / Internet                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## 2. Container Isolation Specifics

### Port Binding

| Container | Internal Port | Host Binding | Accessible From |
|:----------|:-------------|:-------------|:----------------|
| cve_lab_vulnerable | 80 | `127.0.0.1:8080` | Localhost only |
| cve_lab_patched | 80 | `127.0.0.1:8081` | Localhost only |

The `127.0.0.1` binding in `docker-compose.yml` is the critical isolation guardrail.
Compare with the insecure alternative (`0.0.0.0:8080:80`) which would expose
the vulnerable container to the host's LAN and any firewall-accessible network.

### Linux Capability Hardening

Both containers drop all Linux capabilities (`cap_drop: ALL`) and re-add only
the minimum set needed to run Apache:

| Capability | Purpose |
|:-----------|:--------|
| `CHOWN` | Set file ownership |
| `SETUID` / `SETGID` | Drop privileges from root to daemon user |
| `NET_BIND_SERVICE` | Bind to port 80 (< 1024) |

All other capabilities (e.g., `SYS_ADMIN`, `NET_RAW`, `SYS_PTRACE`) are
explicitly dropped, limiting post-exploitation lateral movement potential.

### Filesystem Isolation

- Container filesystem is otherwise unchanged from the base httpd image.
- `/tmp` and `/var/run/apache2` are mounted as `tmpfs` (in-memory, cleared on stop).
- The canary secret file at `/var/secret/confidential_token.txt` is written
  during the Docker build and contains only a synthetic lab flag.

---

## 3. Component Responsibilities

| Component | File | Role |
|:----------|:-----|:-----|
| Vulnerable Target | `env/vulnerable/Dockerfile` + `httpd.conf` | Reference known-vulnerable environment |
| Patched Target | `env/patched/Dockerfile` + `httpd.conf` | Reference remediated environment |
| Orchestrator | `docker-compose.yml` | Runs both containers, enforces 127.0.0.1 binding |
| Traversal Validator | `scripts/validate_traversal.py` | Sends documented path-traversal patterns, checks response |
| CGI Validator | `scripts/validate_cgi_handling.py` | Sends POST via traversal path to `/bin/sh`, checks CGI output |
| Detection Scanner | `scripts/detect_cve.py` | Passive banner check + active non-destructive probe, PASS/FAIL output |
| Automation | `scripts/setup.bat` / `setup.sh` | One-command build/start/evidence generation |

---

## 4. Data Flow: Traversal Request

```
validate_traversal.py
    │
    │  Uses http.client directly
    │  (NOT urllib.request — avoids automatic path normalisation)
    │
    ├─ Builds raw path: /icons/.%2e/%2e%2e/%2e%2e/etc/passwd
    │
    ├─ Sends raw GET request to 127.0.0.1:8080
    │
    │    [ Apache 2.4.49 — vulnerable ]
    │    ap_normalize_path():
    │      Input:  /icons/.%2e/%2e%2e/%2e%2e/etc/passwd
    │      Decode: .%2e -> .. (but traversal re-check skipped)
    │      Result: /etc/passwd
    │    <Directory /> Require all granted → serve file
    │    Response: HTTP 200 + /etc/passwd content
    │
    └─ Analyse response → VERDICT: VULNERABLE
```

---

## 5. Security Boundaries

| Boundary | Enforced By | Status |
|:---------|:------------|:-------|
| Internet isolation | `127.0.0.1` port binding | ✅ Enforced |
| LAN isolation | `127.0.0.1` port binding | ✅ Enforced |
| Capability restriction | `cap_drop: ALL` + selective `cap_add` | ✅ Enforced |
| No real credentials | Lab uses synthetic canary flag only | ✅ Confirmed |
| No external dependencies | Scripts use Python stdlib only | ✅ Confirmed |

---

## 6. Threat Model Summary

**Assets in scope (lab-controlled, not real):**
- Synthetic canary flag: `FLAG{CVE_2021_41773_PATH_TRAVERSAL_ACHIEVED}`
- `/etc/passwd` (standard OS file, no real user credentials)
- CGI command output (`id`, `uname -a` — read-only system enumeration)

**Out of scope (explicitly excluded):**
- Any host filesystem paths outside the container
- Any real credentials or secrets
- Any external network targets
- Any persistence mechanisms or backdoors
