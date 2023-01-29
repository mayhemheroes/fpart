/*-
 * Copyright (c) 2011-2023 Ganael LAPLANCHE <ganael.laplanche@martymac.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef _PARTITION_H
#define _PARTITION_H

#include "types.h"
#include "options.h"

#include <sys/types.h>

/* A partition (group of file entries) */
struct partition;
struct partition {
    fsize_t size;               /* size in bytes */
    fnum_t num_files;           /* number of files */

    struct partition* nextp;    /* next partition */
    struct partition* prevp;    /* previous one */
};

int add_partitions(struct partition **head, pnum_t num_parts,
    struct program_options *options);
int remove_partition(struct partition *part);
void uninit_partitions(struct partition *head);
pnum_t find_smallest_partition_index(struct partition *head);
struct partition * get_partition_at(struct partition *head, pnum_t index);
pnum_t adapt_partition_index(pnum_t index, const struct program_options *options);
#define PARTITION_DISPLAY_TYPE_STANDARD 0
#define PARTITION_DISPLAY_TYPE_ERRNO    1
void display_partition_summary(pnum_t partition_index,
    const fsize_t partition_size, const fnum_t partition_num_files,
    int partition_errno, const unsigned char partition_display_type);
void print_partitions(struct partition *head, struct program_options *options);

#endif /* _PARTITION_H */
