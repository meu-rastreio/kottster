#!/usr/bin/env bash
set -uo pipefail

SEMGREP_IMAGE="semgrep/semgrep:1.182.0"
HOUNDDOG_IMAGE="hounddogai/hounddog:3.11.0"
OSV_IMAGE="ghcr.io/google/osv-scanner:v2.6.0"
SOCKET_CLI="@socketsecurity/cli@1.9.0"
SOCKET_ORG="${SOCKET_ORG:-meu-rastreio}"

ROOT="$(git rev-parse --show-toplevel)"
COMMIT="$(git -C "$ROOT" rev-parse HEAD)"
DIRTY=false
[[ -n "$(git -C "$ROOT" status --porcelain)" ]] && DIRTY=true
OUT="$ROOT/.security-reports/${COMMIT:0:12}$([[ $DIRTY == true ]] && echo -dirty)"
RAW="$OUT/raw"
SECURITY_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_NAME="$(basename "$(git -C "$ROOT" remote get-url origin 2>/dev/null || echo "$ROOT")" .git)"
BRANCH="${GITHUB_HEAD_REF:-$(git -C "$ROOT" rev-parse --abbrev-ref HEAD)}"

rm -rf "$OUT"
mkdir -p "$RAW"
STATUS_FILE="$RAW/status.json"
echo "{}" > "$STATUS_FILE"

record() {
  node -e '
    const fs = require("fs");
    const [file, tool, status, detail] = process.argv.slice(1);
    const s = JSON.parse(fs.readFileSync(file, "utf8"));
    s[tool] = { status, detail: detail || undefined };
    fs.writeFileSync(file, JSON.stringify(s, null, 2));
  ' "$STATUS_FILE" "$1" "$2" "${3:-}"
}

SRC="$(mktemp -d)"
trap 'rm -rf "$SRC"' EXIT
(cd "$ROOT" && git ls-files -z -co --exclude-standard | tar --null -T - -cf - 2>/dev/null) | tar -xf - -C "$SRC"
mkdir -p "$SRC/.git"

docker_run() { docker run --rm -e HOME=/tmp -v "$SRC:/src:ro" -v "$RAW:/out" -w /src "$@"; }

if [[ "${SKIP_SEMGREP:-}" == "1" ]]; then
  record semgrep skipped "SKIP_SEMGREP=1"
else
  echo "==> Semgrep ($SEMGREP_IMAGE)"
  if docker_run "$SEMGREP_IMAGE" semgrep scan \
      --config p/default --config p/secrets --config /src/security/semgrep-rules.yml \
      --metrics off --disable-version-check --quiet \
      --json --output /out/semgrep.json; then
    record semgrep ok "$SEMGREP_IMAGE"
  else
    record semgrep failed "$SEMGREP_IMAGE"
  fi
fi

if [[ "${SKIP_HOUNDDOG:-}" == "1" ]]; then
  record hounddog skipped "SKIP_HOUNDDOG=1"
else
  echo "==> HoundDog.ai ($HOUNDDOG_IMAGE)"
  if docker_run -v "$(git -C "$ROOT" rev-parse --path-format=absolute --git-common-dir):/src/.git:ro" \
      -e HOUNDDOG_GIT_BRANCH="$BRANCH" -e HOUNDDOG_GIT_COMMIT="$COMMIT" "$HOUNDDOG_IMAGE" hounddog scan \
      --no-ai-review --no-tips --no-color --no-cache \
      --output-format json --output-path /out/hounddog.json . >/dev/null 2>"$RAW/hounddog.log"; then
    record hounddog ok "$HOUNDDOG_IMAGE"
  else
    record hounddog failed "$HOUNDDOG_IMAGE"
  fi
fi

if [[ "${SKIP_OSV:-}" == "1" ]]; then
  record osv skipped "SKIP_OSV=1"
else
  echo "==> OSV-Scanner ($OSV_IMAGE)"
  docker_run "$OSV_IMAGE" scan source -r --format json --output-file /out/osv.json /src >/dev/null 2>"$RAW/osv.log"
  code=$?
  if [[ $code -le 1 ]] && grep -qE "failed resolution|Error during extraction" "$RAW/osv.log"; then
    # Resolução de dependências falhou (ex.: pom.xml com versão RELEASE/LATEST): o resultado cobre só parte
    # dos pacotes, então não pode ser tratado como limpo nem fechar achados no Faraday
    record osv partial "$(grep -m1 -E "failed resolution|Error during extraction" "$RAW/osv.log" | sed 's#/src/##' | cut -c1-240)"
  elif [[ $code -le 1 ]]; then
    record osv ok "$OSV_IMAGE"
  elif grep -q "No package sources found" "$RAW/osv.log"; then
    record osv skipped "no package manifests in this repository"
  else
    record osv failed "exit $code"
  fi
fi

if [[ "${SKIP_SOCKET:-}" == "1" ]]; then
  record socket skipped "SKIP_SOCKET=1"
elif [[ -z "${SOCKET_CLI_API_TOKEN:-}" ]]; then
  record socket skipped "SOCKET_CLI_API_TOKEN not set"
else
  echo "==> Socket ($SOCKET_CLI)"
  (cd "$SRC" && npx -y "$SOCKET_CLI" scan create --json --report --report-level warn --no-interactive --org "$SOCKET_ORG" \
      --repo "$REPO_NAME" --branch "$BRANCH" --commit-hash "$COMMIT" . >"$RAW/socket.json" 2>"$RAW/socket.log")
  socket_result="$(node -e '
    try {
      const r = JSON.parse(require("fs").readFileSync(process.argv[1], "utf8"));
      if (r.ok === false) {
        const lines = String(r.data || r.message).split("\n").filter(Boolean);
        console.log((lines.find((l) => l.includes("✖")) ?? lines.pop()).replace("✖", "").trim());
      } else {
        console.log(`ok ${r.data?.scanId ?? r.scanId ?? ""}`);
      }
    } catch { console.log("no JSON output, see raw/socket.log"); }
  ' "$RAW/socket.json")"
  if [[ "$socket_result" == ok\ ?* ]]; then
    if (cd "$SRC" && npx -y "$SOCKET_CLI" scan view "${socket_result#ok }" --json --no-interactive --org "$SOCKET_ORG" \
        >"$RAW/socket-scan.json" 2>>"$RAW/socket.log"); then
      record socket ok "$SOCKET_CLI"
    else
      record socket failed "scan view failed, see raw/socket.log"
    fi
  elif [[ "$socket_result" == ok* ]]; then
    record socket failed "scan created without scanId, see raw/socket.json"
  else
    record socket failed "$socket_result"
  fi
fi

echo "==> Normalizing findings"
node "$SECURITY_DIR/normalize.mjs" \
  --root "$ROOT" --raw "$RAW" --out "$OUT" \
  --project "$REPO_NAME" --commit "$COMMIT" --branch "$BRANCH" --dirty "$DIRTY"
