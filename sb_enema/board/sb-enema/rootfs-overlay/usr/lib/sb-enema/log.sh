#!/usr/bin/env bash
# log.sh — Structured logging for SB-ENEMA runtime scripts.
# Requires common.sh to be sourced first (provides color codes and LOG_BASE_DIR).
set -euo pipefail
[[ -n "${_SB_ENEMA_LOG_SH:-}" ]] && return 0
readonly _SB_ENEMA_LOG_SH=1

# Audit log path — set by log_init() alongside LOG_FILE.
AUDIT_LOG_FILE=""

# ---------------------------------------------------------------------------
# log_init() — create the log directory and set the LOG_FILE global.
#   Enables file-backed logging; log_* may be called before this, but will
#   only emit to stdout until LOG_FILE is set.
#   Also initializes the machine-parseable audit log on the same volume.
# ---------------------------------------------------------------------------
log_init() {
    mkdir -p "${LOG_BASE_DIR}"
    LOG_FILE="${LOG_BASE_DIR}/sb-enema-$(date -u +%Y%m%d-%H%M%S).log"
    touch "${LOG_FILE}"
    AUDIT_LOG_FILE="${LOG_BASE_DIR}/audit.log"
    touch "${AUDIT_LOG_FILE}"
}

# ---------------------------------------------------------------------------
# _log_raw() — internal helper: write a pre-formatted line to LOG_FILE.
# ---------------------------------------------------------------------------
_log_raw() {
    local line="$1"
    if [[ -n "${LOG_FILE:-}" ]]; then
        echo "${line}" >> "${LOG_FILE}"
    fi
}

# ---------------------------------------------------------------------------
# _log() — internal helper: emit a log line to stdout (with color) and to
#   the log file (without ANSI escape sequences).
#   Usage: _log <COLOR> <LEVEL> <message…>
# ---------------------------------------------------------------------------
_log() {
    local color="$1"; shift
    local level="$1"; shift
    local msg="$*"
    local ts
    ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    # Colored output to stdout
    echo -e "${color}[${ts}] [${level}] ${msg}${RESET}"
    # Plain output to log file
    _log_raw "[${ts}] [${level}] ${msg}"
}

# ---------------------------------------------------------------------------
# log_info() — informational message.
# ---------------------------------------------------------------------------
log_info() {
    _log "${RESET}" "INFO " "$@"
}

# ---------------------------------------------------------------------------
# log_warn() — warning message (yellow).
# ---------------------------------------------------------------------------
log_warn() {
    _log "${YELLOW}" "WARN " "$@"
}

# ---------------------------------------------------------------------------
# log_error() — error message (red).
# ---------------------------------------------------------------------------
log_error() {
    _log "${RED}" "ERROR" "$@"
}

# ---------------------------------------------------------------------------
# log_success() — success message (green).
# ---------------------------------------------------------------------------
log_success() {
    _log "${GREEN}" "OK   " "$@"
}

# ---------------------------------------------------------------------------
# log_action() — record a provisioning action with structured fields.
#   Usage: log_action <action> <target> <status> <detail>
#   Example: log_action "ENROLL" "PK" "SUCCESS" "SHA256=abc123...,certs=1"
#   Writes to both the human-readable log and the machine-parseable audit log.
#   Audit log format (pipe-delimited):
#     2026-02-26T14:30:00Z|ENROLL|db|SUCCESS|SHA256=abc123...,certs=4
# ---------------------------------------------------------------------------
log_action() {
    local action="$1"
    local target="$2"
    local status="$3"
    local detail="${4:-}"
    local ts
    ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    local line="[${ts}] [ACTION] action=${action} target=${target} status=${status} detail=${detail}"
    echo -e "${BOLD}${line}${RESET}"
    _log_raw "${line}"
    # Machine-parseable audit log (pipe-delimited)
    if [[ -n "${AUDIT_LOG_FILE:-}" ]]; then
        echo "${ts}|${action}|${target}|${status}|${detail}" >> "${AUDIT_LOG_FILE}"
    fi
}
