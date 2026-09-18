#!/usr/bin/env bash
# =============================================================================
# setup.sh — Linux / macOS Lab Automation Helper
# CVE-2021-41773 / CVE-2021-42013 Validation Lab
#
# USAGE:
#   ./scripts/setup.sh build        Build Docker images
#   ./scripts/setup.sh start        Start both containers
#   ./scripts/setup.sh stop         Stop and remove containers
#   ./scripts/setup.sh status       Show running containers and port bindings
#   ./scripts/setup.sh logs         Tail container logs
#   ./scripts/setup.sh run-all      Full automated run: start + all validators
#   ./scripts/setup.sh evidence     Run all validators and save output to evidence/
#   ./scripts/setup.sh clean        Remove images and all containers
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
COMPOSE="docker compose"

# ---- Colour helpers ----
RED="\033[91m"; GREEN="\033[92m"; YELLOW="\033[93m"
BOLD="\033[1m"; RESET="\033[0m"
info()    { echo -e "${BOLD}[*]${RESET} $*"; }
ok()      { echo -e "${GREEN}[OK]${RESET} $*"; }
warn()    { echo -e "${YELLOW}[WARN]${RESET} $*"; }
error()   { echo -e "${RED}[ERROR]${RESET} $*" >&2; }

# Change to project root
cd "${ROOT_DIR}"

CMD="${1:-}"

case "${CMD}" in

# ---------------------------------------------------------------------------
build)
  info "Building Docker images ..."
  ${COMPOSE} build --no-cache
  ok "Build complete."
  ;;

# ---------------------------------------------------------------------------
start)
  info "Starting lab containers ..."
  ${COMPOSE} up -d
  info "Waiting 5 seconds for Apache to initialise ..."
  sleep 5
  ${COMPOSE} ps
  ok "Vulnerable : http://127.0.0.1:8080"
  ok "Patched    : http://127.0.0.1:8081"
  ;;

# ---------------------------------------------------------------------------
stop)
  info "Stopping containers ..."
  ${COMPOSE} down
  ok "Containers stopped."
  ;;

# ---------------------------------------------------------------------------
status)
  info "Container status:"
  ${COMPOSE} ps
  echo ""
  info "Port bindings:"
  docker ps --format "table {{.Names}}\t{{.Ports}}\t{{.Status}}"
  ;;

# ---------------------------------------------------------------------------
logs)
  info "Tailing container logs (Ctrl+C to stop) ..."
  ${COMPOSE} logs -f
  ;;

# ---------------------------------------------------------------------------
run-all)
  bash "${BASH_SOURCE[0]}" start
  echo ""
  info "Detection scanner — VULNERABLE container ..."
  python3 scripts/detect_cve.py --url http://127.0.0.1:8080
  echo ""
  info "Path traversal validator — VULNERABLE container ..."
  python3 scripts/validate_traversal.py --url http://127.0.0.1:8080
  echo ""
  info "CGI handler validator — VULNERABLE container ..."
  python3 scripts/validate_cgi_handling.py --url http://127.0.0.1:8080 --cmd "id; uname -a"
  echo ""
  info "Detection scanner — PATCHED container ..."
  python3 scripts/detect_cve.py --url http://127.0.0.1:8081
  echo ""
  info "Path traversal validator — PATCHED container ..."
  python3 scripts/validate_traversal.py --url http://127.0.0.1:8081
  echo ""
  info "CGI handler validator — PATCHED container ..."
  python3 scripts/validate_cgi_handling.py --url http://127.0.0.1:8081 --cmd "id"
  echo ""
  ok "All validation runs complete."
  ;;

# ---------------------------------------------------------------------------
evidence)
  mkdir -p evidence

  info "Starting containers ..."
  ${COMPOSE} up -d
  sleep 5

  info "Capturing vulnerable container boot log ..."
  ${COMPOSE} logs apache-vulnerable > evidence/vulnerable_server_boot.txt 2>&1
  ok "evidence/vulnerable_server_boot.txt"

  info "Running traversal validator (vulnerable) ..."
  python3 scripts/validate_traversal.py --url http://127.0.0.1:8080 --file /etc/passwd \
      > evidence/validate_traversal_output.txt 2>&1
  python3 scripts/validate_traversal.py --url http://127.0.0.1:8080 --file /var/secret/confidential_token.txt \
      >> evidence/validate_traversal_output.txt 2>&1
  ok "evidence/validate_traversal_output.txt"

  info "Running CGI handler validator (vulnerable) ..."
  python3 scripts/validate_cgi_handling.py --url http://127.0.0.1:8080 --cmd "id; uname -a; whoami" \
      > evidence/validate_cgi_output.txt 2>&1
  python3 scripts/validate_cgi_handling.py --url http://127.0.0.1:8080 --cmd "cat /var/secret/confidential_token.txt" \
      >> evidence/validate_cgi_output.txt 2>&1
  ok "evidence/validate_cgi_output.txt"

  info "Running detection scanner (pre-patch) ..."
  python3 scripts/detect_cve.py --url http://127.0.0.1:8080 \
      --output evidence/detection_pre_patch.json \
      > evidence/detection_pre_patch.txt 2>&1
  ok "evidence/detection_pre_patch.txt"

  info "Capturing patched container boot log ..."
  ${COMPOSE} logs apache-patched > evidence/patched_server_boot.txt 2>&1
  ok "evidence/patched_server_boot.txt"

  info "Running traversal validator (patched) ..."
  python3 scripts/validate_traversal.py --url http://127.0.0.1:8081 --file /etc/passwd \
      > evidence/validate_post_patch.txt 2>&1
  python3 scripts/validate_traversal.py --url http://127.0.0.1:8081 --file /var/secret/confidential_token.txt \
      >> evidence/validate_post_patch.txt 2>&1
  python3 scripts/validate_cgi_handling.py --url http://127.0.0.1:8081 --cmd "id" \
      >> evidence/validate_post_patch.txt 2>&1
  ok "evidence/validate_post_patch.txt"

  info "Running detection scanner (post-patch) ..."
  python3 scripts/detect_cve.py --url http://127.0.0.1:8081 \
      --output evidence/detection_post_patch.json \
      > evidence/detection_post_patch.txt 2>&1
  ok "evidence/detection_post_patch.txt"

  echo ""
  ok "All evidence files captured to evidence/"
  ls -1 evidence/
  ;;

# ---------------------------------------------------------------------------
clean)
  warn "This will remove all lab Docker images and containers."
  read -r -p "Type YES to confirm: " CONFIRM
  if [[ "${CONFIRM}" == "YES" ]]; then
      ${COMPOSE} down --rmi all --volumes
      ok "Cleanup complete."
  else
      echo "Cancelled. No changes made."
  fi
  ;;

# ---------------------------------------------------------------------------
*)
  echo ""
  echo "  CVE Lab Setup Script"
  echo "  ====================="
  echo "  Usage: ./scripts/setup.sh [command]"
  echo ""
  echo "  Commands:"
  echo "    build      Build Docker images"
  echo "    start      Start both vulnerable and patched containers"
  echo "    stop       Stop and remove containers"
  echo "    status     Show running containers and port bindings"
  echo "    logs       Tail container logs"
  echo "    run-all    Start containers, run all validators, show results"
  echo "    evidence   Generate all evidence files to evidence/ directory"
  echo "    clean      Remove all containers and images"
  echo ""
  exit 1
  ;;
esac
