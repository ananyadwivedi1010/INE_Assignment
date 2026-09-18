#!/usr/bin/env python3
"""
detect_cve.py — CVE-2021-41773 / CVE-2021-42013 Defensive Detection Scanner
=============================================================================
Apache HTTP Server 2.4.49 / 2.4.50 Path Traversal & CGI Routing

PURPOSE
-------
This is a two-phase defensive detection scanner that inspects an Apache
HTTP server and outputs a clear VULNERABLE / PATCHED verdict along with
structured JSON evidence. It is suitable for use in CI/CD pipelines,
automated vulnerability management workflows, or manual auditing.

DETECTION PHASES
----------------
Phase 1 — Passive Banner Inspection:
  Sends a normal GET / request and inspects the Server: response header.
  If the header reveals "Apache/2.4.49" or "Apache/2.4.50", the server
  is immediately flagged as potentially vulnerable (version in known-
  vulnerable range).

  Note: If ServerTokens is set to Prod/Min/OS, the version may not appear.
  Phase 2 will still run regardless of Phase 1 outcome.

Phase 2 — Active Non-Destructive Traversal Probe:
  Sends a carefully crafted traversal request that targets a known-benign
  path (/etc/issue) rather than sensitive files. The probe is designed to
  detect anomalous server behavior (returning file content when it should
  not) without actually retrieving sensitive system data.

  Probe path: GET /icons/.%2e/%2e%2e/etc/issue
  - On a vulnerable server: HTTP 200 with /etc/issue content
  - On a patched server:    HTTP 400 Bad Request

OUTPUT
------
  - Colourised terminal output with structured findings
  - JSON report saved to detect_cve_report.json
  - Process exit code: 0 = SECURE, 1 = VULNERABLE, 2 = ERROR

USAGE
-----
  python detect_cve.py [OPTIONS]

  Options:
    --url URL          Target base URL (default: http://127.0.0.1:8080)
    --timeout SECS     Request timeout in seconds (default: 10)
    --output FILE      JSON report output file (default: detect_cve_report.json)
    --no-json          Skip writing JSON report
    --verbose          Print full response headers and body snippets

  Examples:
    python detect_cve.py --url http://127.0.0.1:8080
    python detect_cve.py --url http://127.0.0.1:8081
    python detect_cve.py --url http://127.0.0.1:8080 --output evidence/detection_pre_patch.json

DEPENDENCIES
------------
  Standard library only — no pip install required.
"""

import argparse
import http.client
import json
import sys
import urllib.parse
from datetime import datetime, timezone


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
# Known-vulnerable version set
# =============================================================================
VULNERABLE_VERSIONS = {"2.4.49", "2.4.50"}

# =============================================================================
# Phase 1 — Passive banner check
# =============================================================================

def phase1_banner_check(host: str, port: int, timeout: int,
                         use_tls: bool) -> dict:
    """
    Send GET / and inspect the Server: header.

    Returns a finding dict:
      {
        "phase": "1-banner",
        "server_header": str,
        "detected_version": str | None,
        "vulnerable": bool,
        "confidence": str,    # "HIGH" | "LOW" | "UNKNOWN"
        "note": str
      }
    """
    finding = {
        "phase": "1-banner",
        "server_header": "",
        "detected_version": None,
        "vulnerable": False,
        "confidence": "UNKNOWN",
        "note": "",
    }
    try:
        ConnClass = http.client.HTTPSConnection if use_tls else http.client.HTTPConnection
        conn = ConnClass(host, port, timeout=timeout)
        conn.request("GET", "/", headers={
            "Host": f"{host}:{port}",
            "User-Agent": "CVE-Lab-Scanner/1.0 (Security Research)",
            "Connection": "close",
        })
        resp = conn.getresponse()
        resp.read()  # drain
        server_hdr = resp.getheader("Server", "")
        conn.close()

        finding["server_header"] = server_hdr

        # Parse version from "Apache/X.Y.Z (Unix)" format
        detected_version = None
        if server_hdr.startswith("Apache/"):
            parts = server_hdr.split("/", 1)
            if len(parts) == 2:
                version_part = parts[1].split()[0]  # e.g. "2.4.49"
                detected_version = version_part

        finding["detected_version"] = detected_version

        if detected_version in VULNERABLE_VERSIONS:
            finding["vulnerable"] = True
            finding["confidence"] = "HIGH"
            finding["note"] = (
                f"Server header explicitly declares Apache/{detected_version}, "
                "which is in the known-vulnerable range (2.4.49, 2.4.50)."
            )
        elif detected_version:
            finding["vulnerable"] = False
            finding["confidence"] = "HIGH"
            finding["note"] = (
                f"Server header declares Apache/{detected_version}, "
                "not in the known-vulnerable range."
            )
        else:
            finding["confidence"] = "LOW"
            finding["note"] = (
                "Server header absent or version suppressed (ServerTokens Prod/Min). "
                "Cannot confirm or exclude vulnerability from banner alone. "
                "Relying on Phase 2 active probe."
            )

    except ConnectionRefusedError:
        finding["note"] = "Connection refused — target not reachable."
        raise
    except OSError as exc:
        finding["note"] = f"Network error: {exc}"
        raise

    return finding


# =============================================================================
# Phase 2 — Active non-destructive traversal probe
# =============================================================================

def phase2_active_probe(host: str, port: int, timeout: int,
                         use_tls: bool) -> dict:
    """
    Send a carefully crafted traversal request targeting /etc/issue.

    /etc/issue is chosen because:
      - It is present on virtually all Linux systems.
      - Its contents are not sensitive (just OS identification text).
      - A 200 response with its content is unambiguous proof of traversal.
      - It is not targeted by normal web scanner false positives.

    Returns a finding dict:
      {
        "phase": "2-active-probe",
        "probe_path": str,
        "http_status": int,
        "response_body_snippet": str,
        "vulnerable": bool,
        "confidence": str,
        "note": str
      }
    """
    # Traversal path: /icons/ is 1 level deep, need 2 x ../ to reach /
    probe_path = "/icons/.%2e/.%2e/.%2e/.%2e/etc/issue"

    finding = {
        "phase": "2-active-probe",
        "probe_path": probe_path,
        "http_status": 0,
        "response_body_snippet": "",
        "vulnerable": False,
        "confidence": "UNKNOWN",
        "note": "",
    }

    try:
        ConnClass = http.client.HTTPSConnection if use_tls else http.client.HTTPConnection
        conn = ConnClass(host, port, timeout=timeout)
        conn.request("GET", probe_path, headers={
            "Host": f"{host}:{port}",
            "User-Agent": "CVE-Lab-Scanner/1.0 (Security Research)",
            "Connection": "close",
        })
        resp = conn.getresponse()
        body = resp.read().decode("utf-8", errors="replace")
        conn.close()

        finding["http_status"] = resp.status

        if resp.status == 200 and len(body.strip()) > 0:
            # Traversal succeeded — file content returned
            finding["vulnerable"] = True
            finding["confidence"] = "HIGH"
            snippet = " | ".join(
                l.strip() for l in body.splitlines() if l.strip()
            )[:200]
            finding["response_body_snippet"] = snippet
            finding["note"] = (
                f"HTTP 200 returned with body content — traversal succeeded. "
                f"Server resolved the path outside the document root."
            )
        elif resp.status == 400:
            finding["vulnerable"] = False
            finding["confidence"] = "HIGH"
            finding["note"] = (
                "HTTP 400 Bad Request — Apache 2.4.51 rejects the malformed "
                "encoded traversal path at the normalization stage."
            )
        elif resp.status == 403:
            finding["vulnerable"] = False
            finding["confidence"] = "MEDIUM"
            finding["note"] = (
                "HTTP 403 Forbidden — traversal path resolved but blocked by ACL. "
                "The server may or may not be vulnerable; Directory policy is enforced."
            )
        elif resp.status == 404:
            finding["vulnerable"] = False
            finding["confidence"] = "MEDIUM"
            finding["note"] = (
                "HTTP 404 Not Found — the traversal path was not resolved "
                "to a readable file. Likely patched or /icons/ alias absent."
            )
        else:
            finding["note"] = f"Unexpected HTTP status {resp.status}. Manual review recommended."

    except ConnectionRefusedError:
        finding["note"] = "Connection refused."
        raise
    except OSError as exc:
        finding["note"] = f"Network error during probe: {exc}"
        raise

    return finding


# =============================================================================
# Report builder
# =============================================================================

def build_report(url: str, phase1: dict, phase2: dict) -> dict:
    """
    Combine Phase 1 and Phase 2 findings into a final structured report.
    """
    # Overall vulnerable if EITHER phase flagged it
    overall_vulnerable = phase1.get("vulnerable", False) or phase2.get("vulnerable", False)

    # Confidence is the highest of the two phases
    confidence_rank = {"HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}
    c1 = confidence_rank.get(phase1.get("confidence", "UNKNOWN"), 0)
    c2 = confidence_rank.get(phase2.get("confidence", "UNKNOWN"), 0)
    overall_confidence = (
        phase1["confidence"] if c1 >= c2 else phase2["confidence"]
    )

    if overall_vulnerable:
        verdict = "VULNERABLE"
        recommendation = (
            "Upgrade Apache HTTP Server to version 2.4.51 or higher immediately. "
            "As an interim measure: set 'Require all denied' on <Directory />, "
            "disable mod_cgi if CGI is not required, and restrict alias directories."
        )
    else:
        verdict = "PATCHED / SECURE"
        recommendation = (
            "Target does not appear vulnerable to CVE-2021-41773/42013. "
            "Continue to monitor for future Apache security advisories."
        )

    return {
        "scan_metadata": {
            "tool": "CVE-Lab detect_cve.py",
            "target_url": url,
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "cves_checked": ["CVE-2021-41773", "CVE-2021-42013"],
        },
        "findings": {
            "phase1_banner": phase1,
            "phase2_active_probe": phase2,
        },
        "verdict": verdict,
        "overall_confidence": overall_confidence,
        "recommendation": recommendation,
    }


# =============================================================================
# Terminal output
# =============================================================================

def print_report(report: dict) -> None:
    verdict   = report["verdict"]
    p1        = report["findings"]["phase1_banner"]
    p2        = report["findings"]["phase2_active_probe"]
    meta      = report["scan_metadata"]

    print(f"\n{BOLD}{'='*65}{RESET}")
    print(f"{BOLD}  CVE-2021-41773 / CVE-2021-42013 — Detection Scanner{RESET}")
    print(f"{BOLD}{'='*65}{RESET}")
    print(f"  Target    : {meta['target_url']}")
    print(f"  Timestamp : {meta['timestamp_utc']}")
    print(f"{BOLD}{'='*65}{RESET}")

    # Phase 1
    print(f"\n  {BOLD}PHASE 1 — Passive Banner Inspection{RESET}")
    print(f"  Server header    : {CYAN}{p1['server_header'] or '(absent / suppressed)'}{RESET}")
    print(f"  Detected version : {p1['detected_version'] or 'N/A'}")
    vuln_colour = RED if p1["vulnerable"] else GREEN
    print(f"  Phase 1 result   : {vuln_colour}{BOLD}{'VULNERABLE' if p1['vulnerable'] else 'SECURE / INCONCLUSIVE'}{RESET}")
    print(f"  Confidence       : {p1['confidence']}")
    print(f"  Note             : {p1['note']}")

    # Phase 2
    print(f"\n  {BOLD}PHASE 2 — Active Non-Destructive Traversal Probe{RESET}")
    print(f"  Probe path  : {CYAN}{p2['probe_path']}{RESET}")
    print(f"  HTTP status : {p2['http_status']}")
    vuln_colour = RED if p2["vulnerable"] else GREEN
    print(f"  Phase 2 result : {vuln_colour}{BOLD}{'VULNERABLE' if p2['vulnerable'] else 'SECURE / PATCHED'}{RESET}")
    print(f"  Confidence     : {p2['confidence']}")
    print(f"  Note           : {p2['note']}")
    if p2.get("response_body_snippet"):
        print(f"  Body snippet   : {YELLOW}{p2['response_body_snippet']}{RESET}")

    # Final verdict
    print(f"\n{BOLD}{'='*65}{RESET}")
    if verdict == "VULNERABLE":
        print(f"  {RED}{BOLD}[!!] FINAL VERDICT: VULNERABLE{RESET}")
    else:
        print(f"  {GREEN}{BOLD}[OK] FINAL VERDICT: PATCHED / SECURE{RESET}")
    print(f"  Confidence  : {report['overall_confidence']}")
    print(f"  Recommendation:")
    # Word-wrap recommendation to 60 chars
    words = report["recommendation"].split()
    line, lines = [], []
    for w in words:
        if sum(len(x) + 1 for x in line) + len(w) > 58:
            lines.append(" ".join(line))
            line = [w]
        else:
            line.append(w)
    if line:
        lines.append(" ".join(line))
    for l in lines:
        print(f"    {l}")
    print(f"{BOLD}{'='*65}{RESET}\n")


# =============================================================================
# Main
# =============================================================================

def main() -> int:
    parser = argparse.ArgumentParser(
        description="CVE-2021-41773/42013 Defensive Detection Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python detect_cve.py --url http://127.0.0.1:8080
  python detect_cve.py --url http://127.0.0.1:8081
  python detect_cve.py --url http://127.0.0.1:8080 --output evidence/detection_pre_patch.json
        """,
    )
    parser.add_argument(
        "--url", default="http://127.0.0.1:8080",
        help="Target base URL (default: http://127.0.0.1:8080)"
    )
    parser.add_argument(
        "--timeout", type=int, default=10,
        help="Request timeout in seconds (default: 10)"
    )
    parser.add_argument(
        "--output", default="detect_cve_report.json",
        help="JSON report output path (default: detect_cve_report.json)"
    )
    parser.add_argument(
        "--no-json", action="store_true",
        help="Skip writing JSON report file"
    )
    parser.add_argument(
        "--verbose", action="store_true",
        help="Print additional debug output"
    )
    args = parser.parse_args()

    parsed = urllib.parse.urlparse(args.url)
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    use_tls = parsed.scheme == "https"

    try:
        print(f"\n  Running Phase 1: Banner inspection ...")
        p1 = phase1_banner_check(host, port, args.timeout, use_tls)

        print(f"  Running Phase 2: Active traversal probe ...")
        p2 = phase2_active_probe(host, port, args.timeout, use_tls)

    except (ConnectionRefusedError, OSError) as exc:
        print(f"\n{RED}[ERROR] Cannot reach target: {exc}{RESET}")
        print(f"  Make sure the container is running: docker compose up -d")
        return 2

    report = build_report(args.url, p1, p2)
    print_report(report)

    if not args.no_json:
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2)
            print(f"  JSON report saved to: {args.output}\n")
        except OSError as exc:
            print(f"{YELLOW}[WARN] Could not write JSON report: {exc}{RESET}")

    return 1 if report["verdict"] == "VULNERABLE" else 0


if __name__ == "__main__":
    sys.exit(main())
