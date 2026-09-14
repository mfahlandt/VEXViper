#!/usr/bin/env bash
# End-to-end test: BOMHort (docker compose) ⇄ VEXViper.
#
# 1. Starts an isolated BOMHort stack (auth on, writable SBOM dir) from
#    hack/docker-compose.e2e.yml using BOMHort's images.
# 2. Drops BOMHort's own release SBOM (testdata/bomhort-0.6.1.spdx.json) into
#    the SBOM dir and waits for ingestion + OSV scan.
# 3. Runs `vexviper generate --upload --wait` (heuristic provider by default,
#    clones github.com/seebom-labs/bomhort and runs govulncheck).
# 4. Verifies via the API that BOMHort ingested the VEX document and that the
#    vulnerabilities now carry a vex_status; runs the Go integration tests.
#
# Usage:
#   BOMHORT_SRC=~/GolandProjects/seebom hack/e2e-bomhort.sh [--keep] [--provider openai]
#
# Env:
#   BOMHORT_SRC            path to a BOMHort checkout (db/ migrations, sboms/ policy files) [required]
#   BOMHORT_IMAGE_PREFIX   image prefix (default "seebom-" = images built by BOMHort's compose;
#                          use "ghcr.io/seebom-labs/seebom/" for published images)
#   BOMHORT_IMAGE_TAG      image tag (default latest; "dev" for ghcr)
#   E2E_API_PORT           host port for the api-gateway (default 18080)
#   VEXVIPER_LLM_PROVIDER  heuristic|openai|mcptool (default heuristic)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

: "${BOMHORT_SRC:?set BOMHORT_SRC to a BOMHort checkout}"
BOMHORT_SRC="$(cd "$BOMHORT_SRC" && pwd)"
export BOMHORT_SRC
export BOMHORT_IMAGE_PREFIX="${BOMHORT_IMAGE_PREFIX:-seebom-}"
export BOMHORT_IMAGE_TAG="${BOMHORT_IMAGE_TAG:-latest}"
export E2E_API_PORT="${E2E_API_PORT:-18080}"
export E2E_CH_PORT="${E2E_CH_PORT:-18123}"
export E2E_API_KEY="${E2E_API_KEY:-vexviper-e2e-key}"
export E2E_SERVICE_TOKEN="${E2E_SERVICE_TOKEN:-vexviper-e2e-service-token}"
PROJECT="${E2E_PROJECT:-vexviper-e2e}"
COMPOSE=(docker compose -p "$PROJECT" -f hack/docker-compose.e2e.yml)
KEEP=0
for arg in "$@"; do
  case "$arg" in
    --keep) KEEP=1 ;;
    --provider) shift; export VEXVIPER_LLM_PROVIDER="$1" ;;
  esac
done

WORK="${E2E_WORK:-$ROOT/.e2e}"
export E2E_SBOM_DIR="$WORK/sboms"
OUT="$WORK/out"
rm -rf "$WORK"
mkdir -p "$E2E_SBOM_DIR/pushed" "$OUT"
# api-gateway runs as nobody and must create files under SBOM_DIR/pushed.
chmod -R 0777 "$E2E_SBOM_DIR"
cp testdata/bomhort-0.6.1.spdx.json "$E2E_SBOM_DIR/"
# SELinux: label the bind mount so the containers may read/write it.
if command -v chcon >/dev/null 2>&1 && [ "$(getenforce 2>/dev/null || echo Disabled)" = "Enforcing" ]; then
  chcon -Rt container_file_t "$E2E_SBOM_DIR" 2>/dev/null || true
fi

cleanup() {
  if [ "$KEEP" = "1" ]; then
    echo "--keep: leaving stack '$PROJECT' running (API http://localhost:$E2E_API_PORT, key $E2E_API_KEY)"
    return
  fi
  "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

API="http://localhost:$E2E_API_PORT"
echo "==> starting BOMHort e2e stack ($PROJECT) with images ${BOMHORT_IMAGE_PREFIX}*:${BOMHORT_IMAGE_TAG}"
"${COMPOSE[@]}" up -d --quiet-pull

echo "==> waiting for api-gateway"
for i in $(seq 1 60); do
  if curl -fsS "$API/healthz" >/dev/null 2>&1; then break; fi
  sleep 2
  [ "$i" = 60 ] && { echo "api-gateway did not become healthy"; "${COMPOSE[@]}" logs api-gateway | tail -50; exit 1; }
done

echo "==> waiting for SBOM ingestion (OSV scan included)"
SBOM_ID=""
for i in $(seq 1 90); do
  SBOM_ID=$(curl -fsS -H "X-API-Key: $E2E_API_KEY" "$API/api/v1/sboms?page_size=50" \
    | python3 -c 'import sys,json; d=json.load(sys.stdin); print(next((s["sbom_id"] for s in d["data"] if s["source_file"].endswith("bomhort-0.6.1.spdx.json") and s["vuln_count"]>0), ""))' 2>/dev/null || true)
  [ -n "$SBOM_ID" ] && break
  sleep 2
done
if [ -z "$SBOM_ID" ]; then
  echo "SBOM was not ingested (or has no vulnerabilities)"; "${COMPOSE[@]}" logs --tail 40 parsing-worker ingestion-watcher; exit 1
fi
echo "    sbom_id=$SBOM_ID"
BEFORE=$(curl -fsS -H "X-API-Key: $E2E_API_KEY" "$API/api/v1/sboms/$SBOM_ID/vulnerabilities" | python3 -c 'import sys,json; d=json.load(sys.stdin); print(len(d), sum(1 for v in d if v.get("vex_status")))')
echo "    vulnerabilities (total, with vex_status) before: $BEFORE"

echo "==> building vexviper"
GO="${GO:-go}"
$GO build -o "$WORK/vexviper" ./cmd/vexviper

export GIT_CONFIG_GLOBAL="${GIT_CONFIG_GLOBAL:-/dev/null}"
export VEXVIPER_BOMHORT_URL="$API"
export VEXVIPER_BOMHORT_API_KEY="$E2E_API_KEY"
export VEXVIPER_LLM_PROVIDER="${VEXVIPER_LLM_PROVIDER:-heuristic}"
export VEXVIPER_REPO_CACHE_DIR="$WORK/cache"
export VEXVIPER_VEX_AUTHOR="VEXViper e2e"

echo "==> vexviper generate --upload (provider=$VEXVIPER_LLM_PROVIDER)"
"$WORK/vexviper" generate --sbom "$SBOM_ID" --out "$OUT" --upload --wait 3m --log-level info

DOC="$OUT/bomhort-0.6.1.vexviper.openvex.json"
[ -s "$DOC" ] || { echo "no document written"; exit 1; }

echo "==> verifying BOMHort applied the VEX"
for i in $(seq 1 60); do
  AFTER=$(curl -fsS -H "X-API-Key: $E2E_API_KEY" "$API/api/v1/sboms/$SBOM_ID/vulnerabilities" | python3 -c 'import sys,json; d=json.load(sys.stdin); print(sum(1 for v in d if v.get("vex_status")))')
  [ "$AFTER" != "0" ] && break
  sleep 2
done
STATEMENTS=$(curl -fsS -H "X-API-Key: $E2E_API_KEY" "$API/api/v1/vex/statements?page_size=100" | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d["total"])')
echo "    vex statements in BOMHort: $STATEMENTS; vulnerabilities with vex_status: $AFTER"
[ "$AFTER" != "0" ] || { echo "vex_status was not applied"; exit 1; }

echo "==> running Go integration tests against the stack"
BOMHORT_URL="$API" BOMHORT_API_KEY="$E2E_API_KEY" BOMHORT_E2E_SBOM="$SBOM_ID" \
  $GO test -tags integration -count=1 -v ./test/integration/ 2>&1 | grep -E "^(=== RUN|--- |PASS|FAIL|ok|\s+integration)" || true

mkdir -p examples
cp "$DOC" examples/bomhort-0.6.1.openvex.json
echo "==> example written to examples/bomhort-0.6.1.openvex.json"
echo "E2E OK"
