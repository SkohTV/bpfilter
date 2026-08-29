/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2026 Meta Platforms, Inc. and affiliates.
 */

#include <linux/bpf.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <stddef.h>

#include "cgen/runtime.h"

#define BF_TIME_S 1000000000

__u8 bf_ratelimit(void *map, const __u16 limit, __u8 letter)
{
    struct bf_ratelimit *ratelimit;
    __u64 current_time_ns = bpf_ktime_get_ns();
    __u32 key = 0; // NTODO: should not be 0, but dynamic (WIP)

    ratelimit = bpf_map_lookup_elem(map, &key);
    if (!ratelimit) {
        bpf_printk("failed to fetch the rule's ratelimit");
        return 1;
    }

    switch (letter) {
    case 's':
        if (current_time_ns > ratelimit->last_time + BF_TIME_S) {
            ratelimit->current = 0;
            ratelimit->last_time = current_time_ns;
        }
        break;
    default:
        bpf_printk("the time unit '%c' is not recognized", letter);
        return 1;
    }

    ratelimit->current++;
    return (ratelimit->current > limit);
}
