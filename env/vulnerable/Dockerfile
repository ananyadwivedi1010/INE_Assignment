# =============================================================================
# Dockerfile — Vulnerable Reference Environment
# Apache HTTP Server 2.4.49 (CVE-2021-41773 / CVE-2021-42013)
#
# PURPOSE:
#   This image builds a controlled reference target that reproduces the
#   misconfiguration conditions under which CVE-2021-41773 was actively
#   exploited in the wild:
#     - Apache 2.4.49 binary (the vulnerable version)
#     - mod_cgi enabled (required for the CGI handler routing vector)
#     - Permissive Directory config (Require all granted on /)
#
# ISOLATION GUARANTEE:
#   This container is only reachable at 127.0.0.1:8080 on the host via the
#   lab_isolated_net Docker bridge. It is NEVER exposed to 0.0.0.0 or any
#   external interface. See docker-compose.yml for port binding details.
#
# WARNING:
#   This image is intentionally vulnerable for lab/research purposes only.
#   Do NOT run this in any production or internet-accessible environment.
# =============================================================================

FROM httpd:2.4.49

LABEL maintainer="CVE Research Lab"
LABEL description="Vulnerable Apache 2.4.49 — CVE-2021-41773 reference environment"
LABEL cve="CVE-2021-41773, CVE-2021-42013"
LABEL version="2.4.49"

# ---------------------------------------------------------------------------
# 1. Replace the default Apache config with our lab config.
#    The custom httpd.conf enables mod_cgi and loosens Directory restrictions
#    to reproduce the historically documented vulnerable configuration.
# ---------------------------------------------------------------------------
COPY env/vulnerable/httpd.conf /usr/local/apache2/conf/httpd.conf

# ---------------------------------------------------------------------------
# 2. Create the canary secret file.
#    This token sits outside the Apache document root (/usr/local/apache2/htdocs).
#    On the vulnerable server, path traversal allows it to be read via HTTP.
#    On the patched server, the same request is rejected with 400/403.
#    Confirming whether this file is readable is the core regression check.
# ---------------------------------------------------------------------------
RUN mkdir -p /var/secret && \
    echo "FLAG{CVE_2021_41773_PATH_TRAVERSAL_ACHIEVED}" > /var/secret/confidential_token.txt && \
    chmod 644 /var/secret/confidential_token.txt

# ---------------------------------------------------------------------------
# 3. Create a minimal document root with a known-good index page.
#    This gives the scanner something to probe as a baseline 200 response.
# ---------------------------------------------------------------------------
RUN echo '<html><body><h1>Apache 2.4.49 Lab Server</h1></body></html>' \
    > /usr/local/apache2/htdocs/index.html

# ---------------------------------------------------------------------------
# 4. Set up the CGI-bin directory and copy the legitimate test CGI script.
#    The CGI directory must be executable to enable the handler routing check.
# ---------------------------------------------------------------------------
RUN mkdir -p /usr/local/apache2/cgi-bin
COPY data/cgi-bin/test_cgi.sh /usr/local/apache2/cgi-bin/test_cgi.sh
RUN chmod +x /usr/local/apache2/cgi-bin/test_cgi.sh

# ---------------------------------------------------------------------------
# 5. Add /etc/issue content so validate_traversal can read a second safe file
#    (supplements /etc/passwd as a traversal evidence target).
# ---------------------------------------------------------------------------
RUN echo "Apache 2.4.49 Lab Container - Vulnerable Reference" > /etc/issue

# Expose HTTP port (actual binding to 127.0.0.1 is enforced by docker-compose)
EXPOSE 80
