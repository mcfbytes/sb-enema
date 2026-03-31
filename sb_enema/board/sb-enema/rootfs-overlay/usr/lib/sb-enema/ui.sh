#!/usr/bin/env bash
# ui.sh — Dialog-based TUI wrapper functions for SB-ENEMA.
# Provides ncurses-backed UI functions with plain-text fallbacks when dialog
# is not available or HAS_DIALOG=0.
# Must be sourced after common.sh (provides BOLD, DIM, RESET color codes).
set -euo pipefail

# Detect dialog availability at source time.
HAS_DIALOG=0
command -v dialog >/dev/null 2>&1 && HAS_DIALOG=1

# ---------------------------------------------------------------------------
# ui_menu <title> <text> <height> <width> <menu_height> <tag1> <label1> [...]
#   Display a selection menu and print the chosen tag to stdout.
#   Returns 0 on selection, 1 if the user cancels (ESC/Cancel).
# ---------------------------------------------------------------------------
ui_menu() {
    local title="$1" text="$2" height="$3" width="$4" menu_height="$5"
    shift 5
    local -a items=("$@")

    if [[ "${HAS_DIALOG}" -eq 1 ]]; then
        local rc=0
        local selection
        # dialog writes UI to stdout (>/dev/tty) and the chosen tag to stderr
        # (captured via 2>&1).  stdin is explicitly /dev/tty so that keyboard
        # input reaches dialog even when called inside a $() subshell.
        selection=$(dialog --title "${title}" --menu "${text}" \
                           "${height}" "${width}" "${menu_height}" \
                           "${items[@]}" 2>&1 >/dev/tty </dev/tty) || rc=$?
        if [[ "${rc}" -eq 0 ]]; then
            printf '%s\n' "${selection}"
        fi
        return "${rc}"
    else
        # Fallback: render menu on /dev/tty and read selection from it.
        {
            echo -e "${BOLD}  ${title}${RESET}"
            [[ -n "${text}" ]] && echo "  ${text}"
            echo
            local i=0
            while [[ $((i + 1)) -lt ${#items[@]} ]]; do
                printf "  [%s]  %s\n" "${items[$i]}" "${items[$((i + 1))]}"
                (( i += 2 ))
            done
            echo
        } >/dev/tty
        local choice
        printf 'Enter your choice: ' >/dev/tty
        read -r choice </dev/tty
        printf '%s\n' "${choice}"
    fi
}

# ---------------------------------------------------------------------------
# ui_yesno <text> [height] [width]
#   Ask a yes/no question.
#   Returns 0 for Yes, 1 for No/Cancel/ESC.
# ---------------------------------------------------------------------------
ui_yesno() {
    local text="$1"
    local height="${2:-7}"
    local width="${3:-60}"

    if [[ "${HAS_DIALOG}" -eq 1 ]]; then
        local rc=0
        dialog --yesno "${text}" "${height}" "${width}" \
               >/dev/tty </dev/tty || rc=$?
        return "${rc}"
    else
        local response
        printf '%s [y/N] ' "${text}" >/dev/tty
        read -r response </dev/tty
        case "${response}" in
            y|Y|yes|YES|Yes) return 0 ;;
            *) return 1 ;;
        esac
    fi
}

# ---------------------------------------------------------------------------
# ui_msgbox <title> <text> [height] [width]
#   Display a message and wait for the user to dismiss it.
# ---------------------------------------------------------------------------
ui_msgbox() {
    local title="$1" text="$2"
    local height="${3:-10}"
    local width="${4:-60}"

    if [[ "${HAS_DIALOG}" -eq 1 ]]; then
        dialog --title "${title}" --msgbox "${text}" \
               "${height}" "${width}" >/dev/tty </dev/tty || true
    else
        {
            echo -e "${BOLD}${title}${RESET}"
            echo "${text}"
            echo
        } >/dev/tty
        local _reply
        printf 'Press Enter to continue...' >/dev/tty
        read -r _reply </dev/tty
    fi
}

# ---------------------------------------------------------------------------
# ui_textbox <file> [height] [width]
#   Display a file in a scrollable text viewer.
# ---------------------------------------------------------------------------
ui_textbox() {
    local file="$1"
    local height="${2:-24}"
    local width="${3:-80}"

    if [[ "${HAS_DIALOG}" -eq 1 ]]; then
        dialog --title "${file}" --textbox "${file}" \
               "${height}" "${width}" >/dev/tty </dev/tty || true
    else
        cat "${file}" >/dev/tty
        echo >/dev/tty
        local _reply
        printf 'Press Enter to continue...' >/dev/tty
        read -r _reply </dev/tty
    fi
}

# ---------------------------------------------------------------------------
# ui_capture_and_show <title> [height] [width] <cmd> [args...]
#   Run a command, capture its combined stdout+stderr, strip ANSI colour
#   codes, and display the result in a scrollable textbox.
#   Falls back to running the command directly (output to stdout) when
#   dialog is not available.
#   Returns the exit code of the command.
# ---------------------------------------------------------------------------
ui_capture_and_show() {
    local title="$1"
    local height="${2:-24}"
    local width="${3:-80}"
    shift 3

    if [[ "${HAS_DIALOG}" -eq 1 ]]; then
        local tmpfile plain rc=0
        tmpfile=$(mktemp /tmp/sb-enema-XXXXXX)
        chmod 600 "${tmpfile}"
        "$@" >"${tmpfile}" 2>&1 || rc=$?
        plain=$(mktemp /tmp/sb-enema-XXXXXX)
        chmod 600 "${plain}"
        sed 's/\x1b\[[0-9;]*m//g' < "${tmpfile}" > "${plain}"
        rm -f "${tmpfile}"
        dialog --title "${title}" --textbox "${plain}" "${height}" "${width}" \
               >/dev/tty </dev/tty || true
        rm -f "${plain}"
        return "${rc}"
    else
        "$@"
    fi
}

# ---------------------------------------------------------------------------
# ui_inputbox <title> <text> <init_value> [height] [width]
#   Prompt the user for text input.
#   Prints the entered text to stdout.
#   Returns init_value unchanged on Cancel/ESC or if the field is left empty.
# ---------------------------------------------------------------------------
ui_inputbox() {
    local title="$1" text="$2" init="$3"
    local height="${4:-9}"
    local width="${5:-60}"

    if [[ "${HAS_DIALOG}" -eq 1 ]]; then
        local rc=0
        local input
        input=$(dialog --title "${title}" --inputbox "${text}" \
                       "${height}" "${width}" "${init}" \
                       2>&1 >/dev/tty </dev/tty) || rc=$?
        if [[ "${rc}" -eq 0 ]]; then
            printf '%s\n' "${input}"
        else
            printf '%s\n' "${init}"
        fi
    else
        {
            echo -e "${BOLD}  ${title}${RESET}"
            echo "  ${text}"
            echo
        } >/dev/tty
        local input
        printf '  [%s]: ' "${init}" >/dev/tty
        read -r input </dev/tty
        if [[ -n "${input}" ]]; then
            printf '%s\n' "${input}"
        else
            printf '%s\n' "${init}"
        fi
    fi
}
