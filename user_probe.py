#!/usr/bin/python
#
# disksnoop.py	Trace block device I/O: basic version of iosnoop.
#		For Linux, uses BCC, eBPF. Embedded C.
#
# Written as a basic example of tracing latency.
#
# Copyright (c) 2015 Brendan Gregg.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 11-Aug-2015	Brendan Gregg	Created this.

from __future__ import print_function
from bcc import BPF, USDT
from bcc.utils import printb
from time import sleep
import sys

REQ_WRITE = 1		# from include/linux/blk_types.h

pid = int(sys.argv[1])
print("Probes for PID: %d" % pid)

u = USDT(pid = pid)
u.enable_probe(probe="sleep_trace", fn_name="trace_on_market_data")

# load BPF program
code="""
#include <uapi/linux/ptrace.h>
#include <linux/blkdev.h>

struct result_t {
	u32 seq_num;
};

BPF_PERF_OUTPUT(events);

void trace_on_market_data(struct pt_regs *ctx) {
	struct result_t data = {};
        bpf_usdt_readarg(1, ctx, &data.seq_num);
	events.perf_submit(ctx, &data, sizeof(data));
}
"""
b = BPF(text=code, usdt_contexts=[u])
#b.trace_print()

def print_data(cpu, data, size):
	e = b["events"].event(data)
	print("SleepTrace: Seq: %d %-5d" % (e.seq_num, cpu))

b["events"].open_perf_buffer(print_data)
while True:
	try:
		b.perf_buffer_poll()
	except KeyboardInterrupt:
		b["events"].clear()
