#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

log() { echo "[yara-update] $*"; }
warn() { echo "[yara-update][WARN] $*" >&2; }
die() { echo "[yara-update][ERROR] $*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

REPO_DIR="${REPO_DIR:-/usr/local/signature-base}"          # signature-base clone
RULES_DIR="$REPO_DIR/yara"
RULE_LIST_FILE="$REPO_DIR/yara_rules_list.yar"
COMPILED_OUT="$REPO_DIR/yara_base_ruleset_compiled.yar"
YARAC_BIN="${YARAC_BIN:-$(command -v yarac || true)}"

# External identifiers some rules expect (filename, filepath, etc.).
# Allow overrides via environment variables (EXTERNAL_FILENAME, etc.).
EXTERNAL_FILENAME="${EXTERNAL_FILENAME:-sample.sys}"
EXTERNAL_FILEPATH="${EXTERNAL_FILEPATH:-/drivers/sample.sys}"
EXTERNAL_ORIGINAL_FILENAME="${EXTERNAL_ORIGINAL_FILENAME:-sample.sys}"
EXTERNAL_EXTENSION="${EXTERNAL_EXTENSION:-.sys}"

EXT_DEFAULTS=( \
  "filename=${EXTERNAL_FILENAME}" \
  "filepath=${EXTERNAL_FILEPATH}" \
  "original_filename=${EXTERNAL_ORIGINAL_FILENAME}" \
  "extension=${EXTERNAL_EXTENSION}" \
)

# Skip very large / problematic rule bundle if desired
SKIP_VULN_RENAMED="${SKIP_VULN_RENAMED:-false}" # set true to skip *vuln_drivers_strict_renamed.yar

# Additional prune list (rules known historically to cause issues). Keep minimal.
PRUNE=(
  generic_anomalies.yar
  general_cloaking.yar
  thor_inverse_matches.yar
  yara_mixed_ext_vars.yar
  configured_vulns_ext_vars.yar
  gen_webshells_ext_vars.yar
  gen_susp_js_obfuscatorio.yar
  apt_cobaltstrike.yar
  apt_tetris.yar
)

[[ -d "$REPO_DIR" ]] || die "Repository not found: $REPO_DIR"
[[ -d "$RULES_DIR" ]] || die "Rules directory missing: $RULES_DIR"
[[ -n "$YARAC_BIN" ]] || die "yarac not in PATH"

log "Updating signature-base repository (git pull)"
git -C "$REPO_DIR" pull --ff-only || warn "Git pull failed; continuing with existing rules"

log "Pruning incompatible rule files"
for p in "${PRUNE[@]}"; do
  f="$RULES_DIR/$p"
  if [[ -f "$f" ]]; then
    rm -f -- "$f" && log "Removed $p"
  fi
done

log "Generating include list $RULE_LIST_FILE"
rm -f "$RULE_LIST_FILE"
touch "$RULE_LIST_FILE"

# Collect rule files
mapfile -t RULE_FILES < <(find "$RULES_DIR" -type f -name '*.yar' -printf '%p\n' | sort)
count_total=0
count_skipped=0
for rf in "${RULE_FILES[@]}"; do
  ((count_total++)) || true
  if [[ "$SKIP_VULN_RENAMED" == "true" && "$rf" == *"vuln_drivers_strict_renamed.yar" ]]; then
    ((count_skipped++)) || true
    log "Skipping (SKIP_VULN_RENAMED=true): $(basename "$rf")"
    continue
  fi
  echo "include \"$rf\"" >> "$RULE_LIST_FILE"
done

log "Files total: $count_total | skipped: $count_skipped | included: $(wc -l < "$RULE_LIST_FILE")"

log "Compiling -> $COMPILED_OUT"
YARAC_CMD=("$YARAC_BIN" -w)
for ev in "${EXT_DEFAULTS[@]}"; do
  YARAC_CMD+=( -d "$ev" )
done
YARAC_CMD+=( "$RULE_LIST_FILE" "$COMPILED_OUT" )

if ! "${YARAC_CMD[@]}" 2> >(tee /tmp/yarac_errors.log >&2); then
  if grep -q 'undefined identifier' /tmp/yarac_errors.log; then
    warn "Compilation failed due to undefined identifiers even after providing externals. Consider increasing prune/skip set."
  fi
  die "Compilation failed"
fi

log "Compiled successfully ($(stat -c %s "$COMPILED_OUT" 2>/dev/null || echo 0) bytes)"
exit 0