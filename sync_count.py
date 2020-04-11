#!/usr/bin/python
#
# sync_timing.py    Trace time between syncs.
#                   For Linux, uses BCC, eBPF. Embedded C.
#
# Written as a basic example of tracing time between events.
#
# Copyright 2016 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

from __future__ import print_function
from bcc import BPF
from bcc.utils import printb

# load BPF program
b = BPF(text="""
#include <uapi/linux/ptrace.h>

BPF_HASH(last);

struct trace_result_t {
    u64 ts;
    u64 delta;
    u64 count;
};

BPF_PERF_OUTPUT(result);

int do_trace(struct pt_regs *ctx) {
    u64 ts, *tsp, delta, key = 0, index=1, count = 0;
    struct trace_result_t data;

    // attempt to read stored timestamp
    tsp = last.lookup(&key);
    if (tsp != 0) {
        delta = bpf_ktime_get_ns() - *tsp;
        if (delta < 1000000000) {
            tsp = last.lookup(&index);
            if (tsp != NULL) {
                count = *tsp;
                count++;
            }
            data.ts = bpf_ktime_get_ns();
            data.delta = delta / 1000000;
            data.count = count;
            result.perf_submit(ctx, &data, sizeof(data));
        }
        last.delete(&key);
        last.delete(&index);
    }

    // update stored timestamp
    ts = bpf_ktime_get_ns();
    last.update(&key, &ts);
    last.update(&index, &count);
    return 0;
}
""")

b.attach_kprobe(event=b.get_syscall_fnname("sync"), fn_name="do_trace")
print("Tracing for quick sync's... Ctrl-C to end")

start = 0
def print_data(cpu, data, size):
    global start
    event = b["result"].event(data)
    if start == 0:
        start = event.ts
    ts = event.ts - start
    printb(b"At time %.2f s: multiple syncs detected, last %s ms ago, count %d" % (ts, event.delta, event.count))

b["result"].open_perf_buffer(print_data)

while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
