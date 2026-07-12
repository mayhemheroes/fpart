/*
 * kat_selftest.c — authored known-answer / behavioral oracle for fpart's utils.c.
 *
 * Upstream ships no automated pass/fail test suite: tests/ holds only two manual
 * helpers (a print-only test-parent_path.c and an LD_PRELOAD fake_readdir.c), neither
 * wired into the build system and neither asserting anything. This oracle asserts the
 * DOCUMENTED contracts of the pure helper functions in src/utils.c — the same code the
 * abs-path fuzz harness exercises — so a PATCH that no-ops the program (or a neutered
 * exit(0) build) FAILS it. Known answers come from the function contracts documented in
 * src/utils.c (e.g. the parent_path() "Examples" block).
 *
 * Prints one line per check and a final "KATDONE passed=P failed=F total=T" marker.
 * Exits non-zero iff any check failed. mayhem/test.sh parses the marker (its ABSENCE,
 * as under the sabotage neuter, is treated as a failure).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include "utils.h"

static int g_passed = 0;
static int g_failed = 0;

static void check_str(const char *name, const char *got, const char *want)
{
    int ok;
    if (want == NULL)
        ok = (got == NULL);
    else
        ok = (got != NULL && strcmp(got, want) == 0);
    if (ok) {
        g_passed++;
        printf("PASS %s => [%s]\n", name, got ? got : "(null)");
    } else {
        g_failed++;
        printf("FAIL %s: got [%s] want [%s]\n", name,
            got ? got : "(null)", want ? want : "(null)");
    }
}

static void check_u(const char *name, uintmax_t got, uintmax_t want)
{
    if (got == want) {
        g_passed++;
        printf("PASS %s => %ju\n", name, got);
    } else {
        g_failed++;
        printf("FAIL %s: got %ju want %ju\n", name, got, want);
    }
}

/* parent_path(path, keep_ending_slash) — returns a freshly-allocated parent. */
static void kat_parent_path(const char *in, unsigned char keep, const char *want)
{
    char *p = parent_path(in, keep);
    char name[512];
    snprintf(name, sizeof(name), "parent_path(\"%s\",%u)", in, keep);
    check_str(name, p, want);
    free(p);
}

static void kat_abs_path(const char *in, const char *want)
{
    char *p = abs_path(in);
    char name[512];
    snprintf(name, sizeof(name), "abs_path(\"%s\")", in);
    check_str(name, p, want);
    free(p);
}

int main(void)
{
    /* parent_path — documented examples (keep_ending_slash = 1 keeps the single
       trailing slash; the doc "Examples" block in utils.c). */
    kat_parent_path("/foo/bar///baz///",   1, "/foo/bar/");
    kat_parent_path("/foo///bar///baz///", 1, "/foo///bar/");
    kat_parent_path("foo/bar///baz///",    1, "foo/bar/");
    kat_parent_path("foo///",              1, "");
    kat_parent_path("///foo",              1, "/");
    kat_parent_path("foo",                 1, "");
    kat_parent_path("",                    1, "");

    /* parent_path — keep_ending_slash = 0 strips the trailing slash (leaving the
       initial '/' intact); matches upstream tests/test-parent_path.c usage. */
    kat_parent_path("/foo/bar///baz///",   0, "/foo/bar");
    kat_parent_path("///foo",              0, "/");
    kat_parent_path("/abcd///abcd///",     0, "/abcd");
    kat_parent_path("abcd//abcd///",       0, "abcd");
    kat_parent_path("/",                   0, "/");

    /* abs_path — absolute paths and the "-" stdin marker pass through unchanged;
       the empty string returns NULL (ENOENT). Relative paths prepend getcwd() and
       are intentionally NOT asserted (cwd-dependent). */
    kat_abs_path("/abs/path", "/abs/path");
    kat_abs_path("/",         "/");
    kat_abs_path("-",         "-");
    kat_abs_path("",          NULL);

    /* str_to_uintmax — base-10 parse with optional human multiplier; 0/negative/
       non-numeric are rejected (return 0). */
    check_u("str_to_uintmax(\"10\",0)",  str_to_uintmax("10", 0),   10);
    check_u("str_to_uintmax(\"2K\",1)",  str_to_uintmax("2K", 1),   2048);
    check_u("str_to_uintmax(\"1M\",1)",  str_to_uintmax("1M", 1),   1048576);
    check_u("str_to_uintmax(\"-5\",0)",  str_to_uintmax("-5", 0),   0);
    check_u("str_to_uintmax(\"0\",0)",   str_to_uintmax("0", 0),    0);
    check_u("str_to_uintmax(\"abc\",0)", str_to_uintmax("abc", 0),  0);
    check_u("str_to_uintmax(\"2K\",0)",  str_to_uintmax("2K", 0),   0); /* unit refused */

    /* char_to_multiplier — K/M/G/T/P powers of 1024; unknown unit => 0. */
    check_u("char_to_multiplier('K')", char_to_multiplier('K'), (uintmax_t)1 << 10);
    check_u("char_to_multiplier('M')", char_to_multiplier('M'), (uintmax_t)1 << 20);
    check_u("char_to_multiplier('G')", char_to_multiplier('G'), (uintmax_t)1 << 30);
    check_u("char_to_multiplier('x')", char_to_multiplier('x'), 0);

    /* get_num_digits — base-10 digit count. */
    check_u("get_num_digits(0)",    get_num_digits(0),    1);
    check_u("get_num_digits(9)",    get_num_digits(9),    1);
    check_u("get_num_digits(10)",   get_num_digits(10),   2);
    check_u("get_num_digits(999)",  get_num_digits(999),  3);
    check_u("get_num_digits(1000)", get_num_digits(1000), 4);

    /* str_is_negative — leading blanks skipped, then '-' test. */
    check_u("str_is_negative(\"  -3\")", (uintmax_t)str_is_negative("  -3"), 1);
    check_u("str_is_negative(\"3\")",    (uintmax_t)str_is_negative("3"),    0);

    int total = g_passed + g_failed;
    printf("KATDONE passed=%d failed=%d total=%d\n", g_passed, g_failed, total);
    fflush(stdout);
    return g_failed == 0 ? 0 : 1;
}
