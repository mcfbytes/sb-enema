#!/usr/bin/env bash
# preview.sh — Display/confirmation module for SB-ENEMA.
# Shows a diff-style preview of planned Secure Boot changes and asks for
# user confirmation before any variables are modified.
# Requires bash 4.3+ (for nameref variables and associative arrays).
# Requires common.sh, log.sh, efivar.sh, certdb.sh, and update.sh to be
# sourced first (provides color codes, log_* helpers, and the ADD_*/REMOVE_*/
# KEEP_* result arrays populated by update_compute()).
# This is a display/confirmation module — it does NOT apply changes.
set -euo pipefail

# ---------------------------------------------------------------------------
# Variable display names
# ---------------------------------------------------------------------------
declare -A _PREVIEW_VAR_LABELS=(
    [PK]="PK (Platform Key)"
    [KEK]="KEK (Key Exchange Key)"
    [db]="db (Allowed Signatures Database)"
    [dbx]="dbx (Forbidden Signatures Database)"
)

# ---------------------------------------------------------------------------
# _preview_format_entry <json_entry>
#   Parse a JSON certificate entry and print a formatted string.
# ---------------------------------------------------------------------------
_preview_format_entry() {
    local entry="$1"
    local subj fp
    subj=$(printf '%s' "${entry}" | jq -r '.subject')
    fp=$(printf '%s' "${entry}" | jq -r '.fingerprint')
    echo "${subj} (SHA256: ${fp})"
}

# ---------------------------------------------------------------------------
# _preview_has_changes()
#   Return 0 if any variable has additions or removals, 1 otherwise.
# ---------------------------------------------------------------------------
_preview_has_changes() {
    local varname
    for varname in PK KEK db dbx; do
        local -n a="ADD_${varname}"
        local -n r="REMOVE_${varname}"
        if [[ ${#a[@]} -gt 0 ]] || [[ ${#r[@]} -gt 0 ]]; then
            return 0
        fi
    done
    return 1
}

# ---------------------------------------------------------------------------
# _preview_display_var <varname>
#   Print the diff-style summary for a single variable.
# ---------------------------------------------------------------------------
_preview_display_var() {
    local varname="$1"
    local label="${_PREVIEW_VAR_LABELS[${varname}]:-${varname}}"

    local -n add_arr="ADD_${varname}"
    local -n remove_arr="REMOVE_${varname}"
    local -n keep_arr="KEEP_${varname}"

    if [[ ${#add_arr[@]} -eq 0 ]] && [[ ${#remove_arr[@]} -eq 0 ]] && [[ ${#keep_arr[@]} -eq 0 ]]; then
        return
    fi

    echo -e "${BOLD}${label}:${RESET}"

    local entry
    for entry in "${remove_arr[@]+"${remove_arr[@]}"}"; do
        [[ -z "${entry}" ]] && continue
        echo -e "  ${RED}− [REMOVE] $(_preview_format_entry "${entry}")${RESET}"
    done

    for entry in "${add_arr[@]+"${add_arr[@]}"}"; do
        [[ -z "${entry}" ]] && continue
        echo -e "  ${GREEN}+ [ADD]    $(_preview_format_entry "${entry}")${RESET}"
    done

    for entry in "${keep_arr[@]+"${keep_arr[@]}"}"; do
        [[ -z "${entry}" ]] && continue
        echo -e "  ${DIM}= [KEEP]   $(_preview_format_entry "${entry}")${RESET}"
    done

    echo
}

# ---------------------------------------------------------------------------
# _preview_display_impl()
#   Internal: write the full change preview with ANSI colours to stdout.
# ---------------------------------------------------------------------------
_preview_display_impl() {
    echo
    echo -e "${BOLD}══════════════════════════════════════════════════════════════${RESET}"
    echo -e "${BOLD}  What Will Change?${RESET}"
    echo -e "${BOLD}══════════════════════════════════════════════════════════════${RESET}"
    echo

    if ! _preview_has_changes; then
        echo -e "${GREEN}  No changes needed — current state matches target.${RESET}"
        echo
        return
    fi

    local varname
    for varname in PK KEK db dbx; do
        _preview_display_var "${varname}"
    done

    echo -e "${YELLOW}⚠️  Warning:${RESET}"
    echo -e "${YELLOW}  • BitLocker will prompt for recovery key on next Windows boot${RESET}"
    echo -e "${YELLOW}  • OEM-specific Secure Boot features may stop working${RESET}"
    echo -e "${YELLOW}  • These changes are reversible via BIOS 'Restore Factory Keys'${RESET}"
    echo
}

# ---------------------------------------------------------------------------
# preview_display()
#   Render the full preview showing planned changes for all variables.
#   With dialog: shown in a scrollable textbox (via /dev/tty).
#   Without dialog: plain stdout.
# ---------------------------------------------------------------------------
preview_display() {
    if [[ "${HAS_DIALOG:-0}" -eq 1 ]]; then
        local tmpfile
        tmpfile=$(mktemp /tmp/sb-enema-XXXXXX.txt)
        chmod 600 "${tmpfile}"
        _preview_display_impl | sed 's/\x1b\[[0-9;]*m//g' > "${tmpfile}"
        dialog --title "What Will Change?" --textbox "${tmpfile}" 24 80 \
               >/dev/tty </dev/tty || true
        rm -f "${tmpfile}"
    else
        _preview_display_impl
    fi
}

# ---------------------------------------------------------------------------
# preview_confirm()
#   Prompt the user to confirm applying changes.
#   Returns 0 for confirmed, 1 for declined.
# ---------------------------------------------------------------------------
preview_confirm() {
    log_info "Prompting user to confirm changes"
    if ui_yesno "Apply these changes?"; then
        log_info "User confirmed changes"
        return 0
    else
        log_info "User declined changes"
        return 1
    fi
}

# ---------------------------------------------------------------------------
# _preview_log_var <varname>
#   Write the plain-text (no color) summary for a single variable to the log.
# ---------------------------------------------------------------------------
_preview_log_var() {
    local varname="$1"
    local label="${_PREVIEW_VAR_LABELS[${varname}]:-${varname}}"

    local -n add_arr="ADD_${varname}"
    local -n remove_arr="REMOVE_${varname}"
    local -n keep_arr="KEEP_${varname}"

    if [[ ${#add_arr[@]} -eq 0 ]] && [[ ${#remove_arr[@]} -eq 0 ]] && [[ ${#keep_arr[@]} -eq 0 ]]; then
        return
    fi

    _log_raw "${label}:"

    local entry
    for entry in "${remove_arr[@]+"${remove_arr[@]}"}"; do
        [[ -z "${entry}" ]] && continue
        _log_raw "  - [REMOVE] $(_preview_format_entry "${entry}")"
    done

    for entry in "${add_arr[@]+"${add_arr[@]}"}"; do
        [[ -z "${entry}" ]] && continue
        _log_raw "  + [ADD]    $(_preview_format_entry "${entry}")"
    done

    for entry in "${keep_arr[@]+"${keep_arr[@]}"}"; do
        [[ -z "${entry}" ]] && continue
        _log_raw "  = [KEEP]   $(_preview_format_entry "${entry}")"
    done

    _log_raw ""
}

# ---------------------------------------------------------------------------
# preview_log()
#   Write the full preview (without color) to the action log file.
# ---------------------------------------------------------------------------
preview_log() {
    _log_raw "============================================================"
    _log_raw "  What Will Change?"
    _log_raw "============================================================"
    _log_raw ""

    if ! _preview_has_changes; then
        _log_raw "  No changes needed — current state matches target."
        _log_raw ""
        return
    fi

    local varname
    for varname in PK KEK db dbx; do
        _preview_log_var "${varname}"
    done

    _log_raw "Warning:"
    _log_raw "  - BitLocker will prompt for recovery key on next Windows boot"
    _log_raw "  - OEM-specific Secure Boot features may stop working"
    _log_raw "  - These changes are reversible via BIOS 'Restore Factory Keys'"
    _log_raw ""
}
