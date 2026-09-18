#!/bin/sh
# =============================================================================
# test_cgi.sh — Legitimate CGI Script (Baseline Verification)
#
# PURPOSE:
#   This is an intentionally benign CGI script placed in the cgi-bin directory
#   for baseline verification. It proves that the CGI handler is working
#   on the vulnerable container (for normal, in-scope requests), and that
#   it is correctly disabled on the patched container.
#
#   validate_cgi_handling.py uses the path-traversal documented request
#   pattern to route to /bin/sh (not this script). This script is only
#   used as a sanity-check for direct CGI execution.
# =============================================================================

echo "Content-Type: text/plain"
echo ""
echo "CGI Handler: Active"
echo "Script: test_cgi.sh"
echo "Time: $(date)"
echo "Server: Apache Lab Container"
