#!/bin/bash
# Wazuh - YARA Active Response (organized version)
# Safe parsing, validation, logging, quarantine

set -euo pipefail

LOG_FILE="/var/ossec/logs/active-responses.log"
QUARANTINE_PATH="/tmp/quarantined"
DEFAULT_YARA_BIN="/usr/bin/yara"

INPUT_JSON="$(cat)"

if ! command -v jq >/dev/null 2>&1; then
    echo "wazuh-yara: ERROR msg=\"jq not installed\"" >>"$LOG_FILE" 2>/dev/null || true
    exit 0
fi

FILENAME=$(echo "$INPUT_JSON" | jq -r '.parameters.alert.syscheck.path // empty')
mapfile -t EXTRA_ARGS < <(echo "$INPUT_JSON" | jq -r '.parameters.extra_args[]?') || true
YARA_PATH=""
YARA_RULES=""
if ((${#EXTRA_ARGS[@]})); then
    for ((i=0; i<${#EXTRA_ARGS[@]}; i++)); do
        case "${EXTRA_ARGS[i]}" in
            -yara_path) (( i+1 < ${#EXTRA_ARGS[@]} )) && YARA_PATH="${EXTRA_ARGS[i+1]}" ;;
            -yara_rules) (( i+1 < ${#EXTRA_ARGS[@]} )) && YARA_RULES="${EXTRA_ARGS[i+1]}" ;;
        esac
    done
fi

if [[ -n "$YARA_PATH" ]]; then
    if [[ -d "$YARA_PATH" ]]; then
        YARA_BIN="${YARA_PATH%/}/yara"
    else
        YARA_BIN="$YARA_PATH"
    fi
else
    YARA_BIN="$DEFAULT_YARA_BIN"
fi

if [[ -z "$YARA_RULES" || -z "$FILENAME" ]]; then
    echo "wazuh-yara: ERROR msg=\"Missing rules or filename\"" >>"$LOG_FILE" 2>/dev/null || true
    exit 0
fi
if [[ ! -x "$YARA_BIN" ]]; then
    echo "wazuh-yara: ERROR msg=\"YARA binary not executable: $YARA_BIN\"" >>"$LOG_FILE" 2>/dev/null || true
    exit 0
fi
if [[ ! -f "$YARA_RULES" ]]; then
    echo "wazuh-yara: ERROR msg=\"Rules file not found: $YARA_RULES\"" >>"$LOG_FILE" 2>/dev/null || true
    exit 0
fi
if [[ ! -f "$FILENAME" ]]; then
    echo "wazuh-yara: ERROR msg=\"File not found (possibly deleted before scan): $FILENAME\"" >>"$LOG_FILE" 2>/dev/null || true
    exit 0
fi

prev_size=-1
for _ in {1..10}; do
    cur_size=$(stat -c %s "$FILENAME" 2>/dev/null || echo -1)
    if [[ "$cur_size" -ge 0 && "$cur_size" == "$prev_size" ]]; then
        break
    fi
    prev_size="$cur_size"
    sleep 1
done

mkdir -p "$QUARANTINE_PATH" || true
chmod 750 "$QUARANTINE_PATH" || true

SCAN_OUTPUT=$("$YARA_BIN" -C -w -r -f -m "$YARA_RULES" "$FILENAME" 2>&1 || true)

if [[ -n "$SCAN_OUTPUT" ]]; then
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        # Expected YARA line format: <RULE_NAME> <FLAGS> <FILEPATH>
        rule=$(echo "$line" | awk '{print $1}')
        filepart=$(echo "$line" | awk '{print $NF}')
        echo "wazuh-yara: MATCH rule=${rule} file=${filepart}" >>"$LOG_FILE"
    done <<<"$SCAN_OUTPUT"
    base=$(basename -- "$FILENAME")
    if mv -f "$FILENAME" "$QUARANTINE_PATH/$base" 2>/dev/null; then
        chattr +i "$QUARANTINE_PATH/$base" 2>/dev/null || true
        echo "wazuh-yara: QUARANTINE src=$FILENAME dst=$QUARANTINE_PATH/$base" >>"$LOG_FILE"
    else
        echo "wazuh-yara: ERROR msg=\"Failed to quarantine $FILENAME\"" >>"$LOG_FILE"
    fi
else
    echo "wazuh-yara: NOMATCH file=$FILENAME" >>"$LOG_FILE"
fi

exit 0