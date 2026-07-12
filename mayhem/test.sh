#!/usr/bin/env bash
#
# mayhem/test.sh — RUN the functional oracle (never builds; build.sh built it).
#
# Upstream fpart ships NO automated test suite: tests/ contains only two manual,
# unwired helpers (print-only test-parent_path.c and an LD_PRELOAD fake_readdir.c),
# no `make check`, no assertions. So the oracle here is the AUTHORED known-answer
# selftest /mayhem/kat_selftest (see mayhem/kat_selftest.c) over src/utils.c's
# documented contracts (tests_found=0, oracle authored).
#
# Behavioral: results come from the KATDONE marker the selftest prints AFTER its
# assertions; a neutered program (exit-0 no-op) prints no marker and FAILS here.
# Emits a CTRF summary to ${CTRF_REPORT:-$SRC/ctrf-report.json} + stdout marker;
# exits non-zero iff failed > 0.
set -uo pipefail

: "${SRC:=/mayhem}"

emit_ctrf() { # emit_ctrf <passed> <failed> <total>
    local passed="$1" failed="$2" total="$3"
    local report="${CTRF_REPORT:-$SRC/ctrf-report.json}"
    local summary
    summary=$(printf '{"results":{"tool":{"name":"fpart-kat-selftest"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":0,"skipped":0,"other":0}}}' \
        "$total" "$passed" "$failed")
    echo "$summary" > "$report" 2>/dev/null || true
    echo "CTRF $summary"
    [ "$failed" -eq 0 ]
}

out="$(/mayhem/kat_selftest 2>&1)"; rc=$?
echo "$out"

marker="$(echo "$out" | grep -E '^KATDONE passed=[0-9]+ failed=[0-9]+ total=[0-9]+$' | tail -1)"
if [ -z "$marker" ]; then
    # No completion marker: the selftest never ran its assertions (crashed, or was
    # neutered into an exit-0 no-op). That is a FAILURE, regardless of exit code.
    echo "test.sh: kat_selftest produced no KATDONE marker (rc=$rc) — treating as failure"
    emit_ctrf 0 1 1
    exit 1
fi

passed="$(echo "$marker" | sed -E 's/.*passed=([0-9]+).*/\1/')"
failed="$(echo "$marker" | sed -E 's/.*failed=([0-9]+).*/\1/')"
total="$(echo "$marker" | sed -E 's/.*total=([0-9]+).*/\1/')"

[ "$rc" -ne 0 ] && [ "$failed" -eq 0 ] && failed=1   # inconsistent: nonzero rc must not pass

emit_ctrf "$passed" "$failed" "$total"
exit $?
