/*
 * fuzz_fpart.c — in-process libFuzzer harness for the `fpart` target.
 *
 * The archived integration fuzzed the fpart CLI as a raw file-input command
 * (`fpart -n 5 -i -`, list of paths on stdin). Rebuilt on the commit-image base
 * that raw-CLI target reports ZERO edge coverage in Mayhem (no in-binary coverage
 * instrumentation for a plain command target), so per the porting policy it is
 * converted to an in-process libFuzzer harness that drives the SAME code path with
 * SanitizerCoverage instrumentation.
 *
 * It reproduces fpart's "read a file list, then partition into a fixed number of
 * parts" flow exactly as src/fpart.c main() does for `-a -n 5 -i -`:
 *   - arbitrary-values mode (-a): each input line is "<size> <path>", parsed with
 *     the same sscanf() fpart uses, then added via handle_file_entry(). This keeps
 *     the harness filesystem-independent and deterministic (no stat() of fuzzer
 *     bytes) while exercising the real file_entry / partition / dispatch code
 *     (file_entry.c, partition.c, dispatch.c) — where fpart's logic (and bugs) live.
 *   - then the fixed-partition dispatch: init_file_entry_p + qsort(sort_file_entry_p)
 *     + add_partitions + dispatch_file_entry_p_by_size + dispatch_empty_file_entries,
 *     matching fpart.c:820-881.
 *
 * All state is per-input and fully freed (uninit_partitions / uninit_file_entries /
 * uninit_options + the pointer array), so the harness itself leaks nothing; any
 * ASan/UBSan report is a genuine finding in fpart's own code.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include "types.h"
#include "utils.h"
#include "fpart.h"
#include "options.h"
#include "file_entry.h"
#include "partition.h"
#include "dispatch.h"

#define FUZZ_NUM_PARTS 5
#define FUZZ_MAX_LINES 4096

/* Mirror fpart's handle_argument() arbitrary-values branch (that function is static
 * in fpart.c, so we replicate its body against the exported handle_file_entry()). */
static int add_arbitrary(char *argument, struct file_entry **head,
    struct program_options *options, struct program_status *status)
{
    fsize_t input_size = 0;
    char *input_path = malloc(strlen(argument) + 1);
    if (input_path == NULL)
        return 1;
    int rc = 0;
    if (sscanf(argument, "%ju %[^\n]", &input_size, input_path) == 2) {
        if (handle_file_entry(head, input_path, input_size, 0, options, status) < 0)
            rc = 1;
    }
    free(input_path);
    return rc;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    struct program_options options;
    struct program_status status = { 0, 0, 0 };
    struct file_entry *head = NULL;

    init_options(&options);
    options.arbitrary_values = OPT_ARBITRARYVALUES;   /* -a: no filesystem access */
    options.num_parts = FUZZ_NUM_PARTS;               /* -n 5 */

    /* Split the input into NUL-terminated lines and feed each to the parser, exactly
     * as the CLI's stdin loop (fpart.c "Handle stdin") does with fgets(). */
    size_t start = 0, lines = 0;
    for (size_t i = 0; i <= size && lines < FUZZ_MAX_LINES; i++) {
        if (i == size || data[i] == '\n') {
            size_t len = i - start;
            char *line = malloc(len + 1);
            if (line == NULL)
                break;
            memcpy(line, data + start, len);
            line[len] = '\0';
            add_arbitrary(line, &head, &options, &status);
            free(line);
            start = i + 1;
            lines++;
        }
    }

    /* Fixed-number-of-partitions dispatch (fpart.c:820-881). */
    if (status.total_num_files > 0 && options.num_parts != DFLT_OPT_NUM_PARTS) {
        struct partition *part_head = NULL;
        struct file_entry **file_entry_p =
            malloc(sizeof(struct file_entry *) * status.total_num_files);
        if (file_entry_p != NULL) {
            init_file_entry_p(file_entry_p, status.total_num_files, head);
            qsort(&file_entry_p[0], status.total_num_files,
                sizeof(struct file_entry *), &sort_file_entry_p);
            if (add_partitions(&part_head, options.num_parts, &options, &status) == 0) {
                rewind_list(part_head);
                dispatch_file_entry_p_by_size(file_entry_p,
                    status.total_num_files, part_head, options.num_parts);
                dispatch_empty_file_entries(head,
                    status.total_num_files, part_head, options.num_parts);
            }
            uninit_partitions(part_head);
            free(file_entry_p);
        }
    }

    uninit_file_entries(head, &options, &status);
    uninit_options(&options);
    return 0;
}
