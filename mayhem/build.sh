#!/usr/bin/env bash
#
# mayhem/build.sh — build fpart's fuzz targets + the KAT oracle.
#
# Targets (parity with the archived integration, same NAMES so run history isn't orphaned):
#   * fpart     — in-process libFuzzer harness (mayhem/fuzz_fpart.c) driving fpart's
#                 read-file-list + fixed-partition dispatch path (file_entry.c/partition.c/
#                 dispatch.c), the same code the archived `fpart -n 5 -i -` CLI target ran.
#                 The raw-CLI form reports 0 edges on the commit-image base (no in-binary
#                 coverage), so it's converted to a libFuzzer harness (SanitizerCoverage).
#                 Binaries: /mayhem/fuzz_fpart (+ -standalone reproducer).
#   * abs-path  — in-process libFuzzer harness over src/utils.c:abs_path().
#                 Binaries: /mayhem/fuzz_abs_path (+ -standalone reproducer).
#
# Also builds /mayhem/kat_selftest (KAT oracle over utils.c) with the project's NORMAL flags,
# so mayhem/test.sh only RUNS it.
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

# ---------------------------------------------------------------------------
# 1) Build the fpart project instrumented (ASan+UBSan+DWARF-3). Produces the
#    per-source objects (src/fpart-*.o) the harnesses link against. Autotools;
#    no network fetches (idempotent + air-gapped).
# ---------------------------------------------------------------------------
autoreconf -if
./configure CC="$CC" CFLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS"
make -j"$MAYHEM_JOBS"

# Project objects minus the one holding main() — link these into the harnesses.
PROJ_OBJS=$(ls src/fpart-*.o | grep -v 'fpart-fpart\.o$')

# ---------------------------------------------------------------------------
# 2) fpart libFuzzer harness — drives the file-list/partition/dispatch path.
# ---------------------------------------------------------------------------
$CC $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE -I"$SRC/src" \
    "$SRC/mayhem/fuzz_fpart.c" $PROJ_OBJS -lm \
    -o /mayhem/fuzz_fpart

$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o /tmp/standalone_main.o
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -I"$SRC/src" \
    "$SRC/mayhem/fuzz_fpart.c" /tmp/standalone_main.o $PROJ_OBJS -lm \
    -o /mayhem/fuzz_fpart-standalone

# ---------------------------------------------------------------------------
# 3) abs-path libFuzzer harness over src/utils.c:abs_path() (C++ harness linked
#    against the instrumented utils object).
# ---------------------------------------------------------------------------
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE -I"$SRC/src" \
    "$SRC/mayhem/fuzz_abs_path.cpp" src/fpart-utils.o \
    -o /mayhem/fuzz_abs_path

$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -I"$SRC/src" \
    "$SRC/mayhem/fuzz_abs_path.cpp" /tmp/standalone_main.o src/fpart-utils.o \
    -o /mayhem/fuzz_abs_path-standalone

# ---------------------------------------------------------------------------
# 4) KAT oracle (mayhem/kat_selftest.c over utils.c) with NORMAL flags — an honest
#    functional oracle for test.sh / PATCH grading (NOT the fuzz sanitizer build).
# ---------------------------------------------------------------------------
$CC -O2 $COVERAGE_FLAGS -I"$SRC/src" \
    "$SRC/mayhem/kat_selftest.c" "$SRC/src/utils.c" -lm \
    -o /mayhem/kat_selftest

echo "build.sh: done — /mayhem/fuzz_fpart /mayhem/fuzz_abs_path (+ -standalone) /mayhem/kat_selftest"
