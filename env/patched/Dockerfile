# =============================================================================
# Dockerfile — Patched Reference Environment
# Apache HTTP Server 2.4.51 (CVE-2021-41773 fix verified)
#
# PURPOSE:
#   This image builds the remediated reference target running Apache 2.4.51,
#   the first release that fully fixed both CVE-2021-41773 (2.4.49 flaw)
#   and CVE-2021-42013 (2.4.50 incomplete-fix bypass).
#
#   The detection scanner is run against this container to confirm the
#   PATCHED / SECURE verdict. Validation scripts confirm requests that
#   succeeded against 2.4.49 are correctly rejected here (400 / 403).
#
# ISOLATION GUARANTEE:
#   This container is only reachable at 127.0.0.1:8081 on the host via the
#   lab_isolated_net Docker bridge.
# =============================================================================

FROM httpd:2.4.51

LABEL maintainer="CVE Research Lab"
LABEL description="Patched Apache 2.4.51 — CVE-2021-41773 remediation reference"
LABEL cve="CVE-2021-41773-FIXED, CVE-2021-42013-FIXED"
LABEL version="2.4.51"

# ---------------------------------------------------------------------------
# 1. Replace the default Apache config with the hardened lab config.
#    The patched httpd.conf uses secure defaults:
#      - Require all denied on /
#      - No ExecCGI on sensitive paths
#      - ServerTokens Prod (suppressed version in Server header)
# ---------------------------------------------------------------------------
COPY env/patched/httpd.conf /usr/local/apache2/conf/httpd.conf

# ---------------------------------------------------------------------------
# 2. Create the same canary secret file as the vulnerable image.
#    On the patched server the traversal request to this file is rejected,
#    so the file content should never be returned — this is the expected result.
# ---------------------------------------------------------------------------
RUN mkdir -p /var/secret && \
    echo "FLAG{CVE_2021_41773_PATH_TRAVERSAL_ACHIEVED}" > /var/secret/confidential_token.txt && \
    chmod 644 /var/secret/confidential_token.txt

# ---------------------------------------------------------------------------
# 3. Create a known-good index page for baseline health checks.
# ---------------------------------------------------------------------------
RUN echo '<html><body><h1>Apache 2.4.51 Lab Server (Patched)</h1></body></html>' \
    > /usr/local/apache2/htdocs/index.html

# ---------------------------------------------------------------------------
# 4. CGI-bin directory is present but ExecCGI is NOT enabled in httpd.conf.
#    The CGI test script exists so the patched scanner check can confirm
#    the CGI routing path is blocked even when the script file exists.
# ---------------------------------------------------------------------------
RUN mkdir -p /usr/local/apache2/cgi-bin
COPY data/cgi-bin/test_cgi.sh /usr/local/apache2/cgi-bin/test_cgi.sh
RUN chmod +x /usr/local/apache2/cgi-bin/test_cgi.sh

RUN echo "Apache 2.4.51 Lab Container - Patched Reference" > /etc/issue

EXPOSE 80
