#!/usr/bin/env bash
# test-stage-filter-pca2011.sh — Unit tests for _stage_filter_x509_sha256_lists_from_esl()
#
# Validates the ESL filter that strips EFI_CERT_X509_SHA256_GUID signature
# lists (introduced by DBX2024 to revoke entire CAs) while preserving all
# other signature list types (e.g. EFI_CERT_SHA256_GUID hash lists).  This
# is the filter used by _stage_dbx_apply_pca2011_gate() to safely exclude
# the DBX2024 PCA 2011 CA-revocation entries when an installed bootloader
# is still signed by Microsoft Windows Production PCA 2011.
#
# Scenarios covered:
#   1. Empty input → empty output (no crash).
#   2. Single EFI_CERT_SHA256_GUID list → preserved verbatim.
#   3. Single EFI_CERT_X509_SHA256_GUID list → entirely removed.
#   4. Mixed lists → only X509_SHA256 lists removed, SHA256 lists preserved
#      in original order.
#   5. Multiple X509_SHA256 lists interleaved with SHA256 lists →
#      all X509_SHA256 removed; remaining SHA256 lists in original order.
#   6. Trailing malformed bytes (truncated header) → preserved (graceful).
#   7. Malformed list_size that overflows input length → remainder preserved
#      and parser does not loop forever.
#
# Requirements on the host:
#   - bash 4+
#   - python3
#
# Usage:
#   bash scripts/test-stage-filter-pca2011.sh
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

export SB_ENEMA_LIB_DIR="${REPO_ROOT}/sb_enema/board/sb-enema/rootfs-overlay/usr/lib/sb-enema"
export CERTDB_DIR="${SB_ENEMA_LIB_DIR}/known-certs"

# ---------------------------------------------------------------------------
# Mock environment
# ---------------------------------------------------------------------------
MOCK_EFIVARS="$(mktemp -d)"
MOCK_DATA="$(mktemp -d)"
WORK_DIR="$(mktemp -d -t sb-enema-eslfilter-XXXXXX)"
trap 'rm -rf "${MOCK_EFIVARS}" "${MOCK_DATA}" "${WORK_DIR}"' EXIT

export EFIVARS_DIR="${MOCK_EFIVARS}"
export DATA_MOUNT="${MOCK_DATA}"

PASS_COUNT=0
FAIL_COUNT=0

pass() { echo "PASS: $*"; PASS_COUNT=$((PASS_COUNT + 1)); }
fail() { echo "FAIL: $*" >&2; FAIL_COUNT=$((FAIL_COUNT + 1)); }

# ---------------------------------------------------------------------------
# Source libraries (same minimal set used by other unit-test scripts)
# ---------------------------------------------------------------------------
# shellcheck source=../sb_enema/board/sb-enema/rootfs-overlay/usr/lib/sb-enema/common.sh
source "${SB_ENEMA_LIB_DIR}/common.sh"
# shellcheck source=../sb_enema/board/sb-enema/rootfs-overlay/usr/lib/sb-enema/log.sh
source "${SB_ENEMA_LIB_DIR}/log.sh"
# shellcheck source=../sb_enema/board/sb-enema/rootfs-overlay/usr/lib/sb-enema/efivar.sh
source "${SB_ENEMA_LIB_DIR}/efivar.sh"
# shellcheck source=../sb_enema/board/sb-enema/rootfs-overlay/usr/lib/sb-enema/certdb.sh
source "${SB_ENEMA_LIB_DIR}/certdb.sh"
export PAYLOAD_DIR="${MOCK_DATA}/sb-enema/payloads"
# shellcheck source=../sb_enema/board/sb-enema/rootfs-overlay/usr/lib/sb-enema/update.sh
source "${SB_ENEMA_LIB_DIR}/update.sh"
# shellcheck source=../sb_enema/board/sb-enema/rootfs-overlay/usr/lib/sb-enema/preview.sh
source "${SB_ENEMA_LIB_DIR}/preview.sh"
# shellcheck source=../sb_enema/board/sb-enema/rootfs-overlay/usr/lib/sb-enema/keygen.sh
source "${SB_ENEMA_LIB_DIR}/keygen.sh"
# shellcheck source=../sb_enema/board/sb-enema/rootfs-overlay/usr/lib/sb-enema/stage.sh
source "${SB_ENEMA_LIB_DIR}/stage.sh"

log_init

if ! command -v python3 >/dev/null 2>&1; then
    echo "SKIP: python3 not available; _stage_filter_x509_sha256_lists_from_esl requires python3" >&2
    exit 0
fi

echo "=== SB-ENEMA _stage_filter_x509_sha256_lists_from_esl() test ==="
echo

# ---------------------------------------------------------------------------
# Fixture builder — emit synthetic ESL bytes via python3.
#
# Build directives understood by _make_esl():
#   sha256:<count>     N hash entries under EFI_CERT_SHA256_GUID
#                      (signature size = 16 GUID + 32 hash = 48; entries
#                      are filled with deterministic dummy data).
#   x509:<count>       N TBS-hash entries under EFI_CERT_X509_SHA256_GUID
#                      (signature size = 16 GUID + 32 TBS-hash + 16
#                      ToBeSignedTime = 64 bytes per UEFI 2.10).
#   raw:<hex>          Raw bytes appended verbatim (used to inject malformed
#                      trailing data for negative tests).
# ---------------------------------------------------------------------------
_make_esl() {
    local out="$1"; shift
    python3 - "${out}" "$@" <<'PYEOF'
import sys, struct

# GUIDs in little-endian wire format, per UEFI 2.x signature list headers.
SHA256_GUID = bytes.fromhex('261614c14c509240aca941f936934328')   # c1c41626-504c-4092-aca9-41f936934328
X509_SHA256_GUID = bytes.fromhex('92a4d23bc0967940b420fcf98ef103ed')  # 3bd2a492-96c0-4079-b420-fcf98ef103ed

def make_list(guid: bytes, sig_size: int, count: int, fill: int) -> bytes:
    header_size = 0
    list_size = 28 + header_size + sig_size * count
    hdr = guid + struct.pack('<III', list_size, header_size, sig_size)
    body = bytearray()
    for i in range(count):
        # 16 bytes owner GUID + (sig_size - 16) bytes payload
        owner = bytes([fill ^ i] * 16)
        payload = bytes([(fill + i) & 0xff] * (sig_size - 16))
        body += owner + payload
    return hdr + bytes(body)

out = sys.argv[1]
chunks = []
fill_byte = 0x10
for spec in sys.argv[2:]:
    kind, _, value = spec.partition(':')
    if kind == 'sha256':
        chunks.append(make_list(SHA256_GUID, 48, int(value), fill_byte))
    elif kind == 'x509':
        chunks.append(make_list(X509_SHA256_GUID, 64, int(value), fill_byte))
    elif kind == 'raw':
        chunks.append(bytes.fromhex(value))
    else:
        raise SystemExit('unknown spec: ' + spec)
    fill_byte = (fill_byte + 1) & 0xff

with open(out, 'wb') as f:
    f.write(b''.join(chunks))
PYEOF
}

# Compute the SHA-256 of a file (portable across busybox/coreutils).
_file_sha() { sha256sum "$1" | awk '{print $1}'; }

# Run the filter and exit if it returns non-zero (caller decides what to do).
_run_filter() {
    local in="$1" out="$2"
    _stage_filter_x509_sha256_lists_from_esl "${in}" "${out}"
}

# ---------------------------------------------------------------------------
# Test 1: Empty input → empty output, no crash
# ---------------------------------------------------------------------------
echo "--- Test 1: empty input ESL ---"
: > "${WORK_DIR}/empty.in.esl"
if _run_filter "${WORK_DIR}/empty.in.esl" "${WORK_DIR}/empty.out.esl" 2>/dev/null; then
    if [[ ! -s "${WORK_DIR}/empty.out.esl" ]]; then
        pass "empty input produced empty output"
    else
        fail "empty input produced non-empty output ($(wc -c < "${WORK_DIR}/empty.out.esl") bytes)"
    fi
else
    fail "filter failed on empty input"
fi

# ---------------------------------------------------------------------------
# Test 2: Single SHA256 hash list → preserved verbatim
# ---------------------------------------------------------------------------
echo "--- Test 2: single EFI_CERT_SHA256_GUID list preserved ---"
_make_esl "${WORK_DIR}/sha256.in.esl" "sha256:3"
if _run_filter "${WORK_DIR}/sha256.in.esl" "${WORK_DIR}/sha256.out.esl" 2>/dev/null; then
    if [[ "$(_file_sha "${WORK_DIR}/sha256.in.esl")" == "$(_file_sha "${WORK_DIR}/sha256.out.esl")" ]]; then
        pass "SHA256 hash list preserved byte-for-byte"
    else
        fail "SHA256 hash list was modified by filter"
    fi
else
    fail "filter failed on SHA256-only input"
fi

# ---------------------------------------------------------------------------
# Test 3: Single X509_SHA256 list → entirely removed (output empty)
# ---------------------------------------------------------------------------
echo "--- Test 3: single EFI_CERT_X509_SHA256_GUID list removed ---"
_make_esl "${WORK_DIR}/x509.in.esl" "x509:2"
if _run_filter "${WORK_DIR}/x509.in.esl" "${WORK_DIR}/x509.out.esl" 2>/dev/null; then
    if [[ ! -s "${WORK_DIR}/x509.out.esl" ]]; then
        pass "X509_SHA256-only input produced empty output"
    else
        fail "X509_SHA256 list not stripped (output is $(wc -c < "${WORK_DIR}/x509.out.esl") bytes)"
    fi
else
    fail "filter failed on X509_SHA256-only input"
fi

# ---------------------------------------------------------------------------
# Test 4: Mixed lists [SHA256, X509_SHA256, SHA256] → only X509 removed,
#         SHA256 lists preserved in original order.
# ---------------------------------------------------------------------------
echo "--- Test 4: mixed lists — X509 removed, SHA256 preserved in order ---"
_make_esl "${WORK_DIR}/mixed.in.esl" "sha256:1" "x509:2" "sha256:2"
# Expected output is the concatenation of just the two SHA256 lists.
_make_esl "${WORK_DIR}/mixed.expect.esl" "sha256:1" "sha256:2"
# fill_byte for the second SHA256 list differs from the input because the
# expected fixture skips the X509 list, which in the input bumped the seed.
# Compare structure (list types and per-list sizes) instead of raw bytes.
_summarize_esl() {
    python3 - "$1" <<'PYEOF'
import sys, struct
SHA256 = bytes.fromhex('261614c14c509240aca941f936934328')
X509   = bytes.fromhex('92a4d23bc0967940b420fcf98ef103ed')
def name(g):
    if g == SHA256: return 'SHA256'
    if g == X509:   return 'X509_SHA256'
    return 'OTHER'
with open(sys.argv[1], 'rb') as f:
    data = f.read()
off = 0
out = []
while off + 28 <= len(data):
    g = data[off:off+16]
    size = struct.unpack_from('<I', data, off+16)[0]
    if size < 28 or off + size > len(data):
        out.append(f'TRAILING:{len(data)-off}')
        break
    out.append(f'{name(g)}:{size}')
    off += size
if off < len(data):
    out.append(f'TRAILING:{len(data)-off}')
print(';'.join(out))
PYEOF
}

if _run_filter "${WORK_DIR}/mixed.in.esl" "${WORK_DIR}/mixed.out.esl" 2>/dev/null; then
    in_summary="$(_summarize_esl "${WORK_DIR}/mixed.in.esl")"
    out_summary="$(_summarize_esl "${WORK_DIR}/mixed.out.esl")"
    expect_summary="SHA256:76;SHA256:124"   # 28 + 48*1 ; 28 + 48*2
    if [[ "${out_summary}" == "${expect_summary}" ]]; then
        pass "mixed lists: X509_SHA256 stripped, SHA256 preserved (in=${in_summary}, out=${out_summary})"
    else
        fail "mixed lists output structure mismatch (in=${in_summary}, out=${out_summary}, expect=${expect_summary})"
    fi
else
    fail "filter failed on mixed input"
fi

# ---------------------------------------------------------------------------
# Test 5: Multiple X509 lists interleaved → all X509 removed
# ---------------------------------------------------------------------------
echo "--- Test 5: multiple X509 lists interleaved with SHA256 ---"
_make_esl "${WORK_DIR}/multi.in.esl" "x509:1" "sha256:1" "x509:3" "sha256:2" "x509:1"
if _run_filter "${WORK_DIR}/multi.in.esl" "${WORK_DIR}/multi.out.esl" 2>/dev/null; then
    out_summary="$(_summarize_esl "${WORK_DIR}/multi.out.esl")"
    expect_summary="SHA256:76;SHA256:124"
    if [[ "${out_summary}" == "${expect_summary}" ]]; then
        pass "all interleaved X509_SHA256 lists removed (out=${out_summary})"
    else
        fail "interleaved filter mismatch (out=${out_summary}, expect=${expect_summary})"
    fi
else
    fail "filter failed on interleaved input"
fi

# ---------------------------------------------------------------------------
# Test 6: Trailing truncated header (< 28 bytes after a valid SHA256 list) →
#         preserved as-is (parser must not crash or loop)
# ---------------------------------------------------------------------------
echo "--- Test 6: trailing truncated header is preserved ---"
# Append 10 raw garbage bytes after a single SHA256 list.
_make_esl "${WORK_DIR}/trunc.in.esl" "sha256:1" "raw:00112233445566778899"
if _run_filter "${WORK_DIR}/trunc.in.esl" "${WORK_DIR}/trunc.out.esl" 2>/dev/null; then
    in_size="$(wc -c < "${WORK_DIR}/trunc.in.esl")"
    out_size="$(wc -c < "${WORK_DIR}/trunc.out.esl")"
    # Output must equal input (no X509 lists to strip; trailing bytes preserved).
    if [[ "${in_size}" == "${out_size}" ]] \
       && [[ "$(_file_sha "${WORK_DIR}/trunc.in.esl")" == "$(_file_sha "${WORK_DIR}/trunc.out.esl")" ]]; then
        pass "trailing truncated header preserved verbatim (${out_size} bytes)"
    else
        fail "trailing truncated header not preserved (in=${in_size}, out=${out_size})"
    fi
else
    fail "filter failed on truncated trailing input"
fi

# ---------------------------------------------------------------------------
# Test 7: Malformed list_size that overflows input length → remainder
#         preserved and parser exits cleanly (no infinite loop).
# ---------------------------------------------------------------------------
echo "--- Test 7: malformed list_size (overflow) handled gracefully ---"
# Build a header with X509_SHA256 GUID but list_size = 0xFFFF that does not
# fit in the 30-byte buffer.  GUID + size(LE 0xFFFF=ff ff 00 00) +
# header_size(0) + sig_size(0) = 28 bytes header, then 2 bytes of padding.
_make_esl "${WORK_DIR}/bad.in.esl" \
    "raw:92a4d23bc0967940b420fcf98ef103edffff0000000000000000000000000000"
# Run with a generous timeout so an infinite loop would be detected by CI.
if timeout 10 bash -c '_stage_filter_x509_sha256_lists_from_esl "$1" "$2"' \
        _ "${WORK_DIR}/bad.in.esl" "${WORK_DIR}/bad.out.esl" 2>/dev/null; then
    in_size="$(wc -c < "${WORK_DIR}/bad.in.esl")"
    out_size="$(wc -c < "${WORK_DIR}/bad.out.esl")"
    if [[ "${in_size}" == "${out_size}" ]]; then
        pass "malformed list_size handled gracefully (preserved ${out_size} bytes, no loop)"
    else
        fail "malformed list_size mishandled (in=${in_size}, out=${out_size})"
    fi
else
    fail "filter failed or timed out on malformed list_size input"
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo
echo "Results: ${PASS_COUNT} passed, ${FAIL_COUNT} failed"
if [[ "${FAIL_COUNT}" -gt 0 ]]; then
    exit 1
fi
exit 0
