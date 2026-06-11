#!/usr/bin/env bash
set -euo pipefail

# Apply repository rulesets from .github/rulesets/*.json.
# Idempotent: updates an existing ruleset with the same name instead of creating duplicates.
# Requires: gh CLI authenticated with admin access to the repository.
#
# Usage:
#   ./scripts/enable-branch-protection.sh
#   ./scripts/enable-branch-protection.sh MCP-Audit/MCTS
#   ./scripts/enable-branch-protection.sh MCP-Audit/MCTS --dry-run

GH_CONFIG="${GH_CONFIG_DIR:-${XDG_CONFIG_HOME:-$HOME/.config}/gh}/config.yml"
if [[ ! -r "${GH_CONFIG}" ]]; then
  echo "error: cannot read gh config at ${GH_CONFIG}" >&2
  echo "Fix ownership (run in your terminal, enter your password):" >&2
  echo "  sudo chown -R \"\$(whoami)\":staff \"\${XDG_CONFIG_HOME:-\$HOME/.config}/gh\"" >&2
  echo "  chmod 700 \"\${XDG_CONFIG_HOME:-\$HOME/.config}/gh\"" >&2
  echo "  chmod 600 \"\${XDG_CONFIG_HOME:-\$HOME/.config}/gh\"/*.yml" >&2
  echo "Or apply rulesets manually: Settings → Rules → see .github/rulesets/README.md" >&2
  exit 1
fi

REPO="${1:-$(gh repo view --json nameWithOwner -q .nameWithOwner)}"
DRY_RUN=false
if [[ "${2:-}" == "--dry-run" ]]; then
  DRY_RUN=true
elif [[ "${1:-}" == "--dry-run" ]]; then
  DRY_RUN=true
  REPO="$(gh repo view --json nameWithOwner -q .nameWithOwner)"
fi

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RULESETS_DIR="${ROOT}/.github/rulesets"

if [[ ! -d "${RULESETS_DIR}" ]]; then
  echo "Rulesets directory not found: ${RULESETS_DIR}" >&2
  exit 1
fi

RULESET_FILES=()
while IFS= read -r ruleset_file; do
  RULESET_FILES+=("${ruleset_file}")
done < <(find "${RULESETS_DIR}" -maxdepth 1 -name '*.json' -print | sort)
if [[ "${#RULESET_FILES[@]}" -eq 0 ]]; then
  echo "No ruleset JSON files found in ${RULESETS_DIR}" >&2
  exit 1
fi

echo "Checking existing rulesets on ${REPO}..."
EXISTING_JSON="$(
  gh api "repos/${REPO}/rulesets" --paginate 2>/dev/null || echo '[]'
)"

apply_ruleset() {
  local ruleset_file="$1"
  local ruleset_name
  ruleset_name="$(python3 -c "import json,sys; print(json.load(open(sys.argv[1]))['name'])" "${ruleset_file}")"

  local existing_id
  existing_id="$(
    python3 -c "
import json, sys
name = sys.argv[1]
rows = json.loads(sys.argv[2])
for row in rows:
    if row.get('name') == name:
        print(row.get('id', ''))
        break
" "${ruleset_name}" "${EXISTING_JSON}"
  )"

  if [[ -n "${existing_id}" ]]; then
    echo "Updating ruleset \"${ruleset_name}\" (id=${existing_id}) from ${ruleset_file##*/}..."
    if [[ "${DRY_RUN}" == true ]]; then
      echo "[dry-run] Would PUT repos/${REPO}/rulesets/${existing_id}"
      return 0
    fi
    gh api "repos/${REPO}/rulesets/${existing_id}" \
      --method PUT \
      --input "${ruleset_file}"
  else
    echo "Creating ruleset \"${ruleset_name}\" from ${ruleset_file##*/}..."
    if [[ "${DRY_RUN}" == true ]]; then
      echo "[dry-run] Would POST repos/${REPO}/rulesets"
      return 0
    fi
    gh api "repos/${REPO}/rulesets" \
      --method POST \
      --input "${ruleset_file}"
  fi
}

for ruleset_file in "${RULESET_FILES[@]}"; do
  apply_ruleset "${ruleset_file}"
done

echo "Done. Verify at: https://github.com/${REPO}/settings/rules"
