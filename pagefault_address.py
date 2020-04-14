#!/usr/bin/python
#

from __future__ import print_function
import argparse
from bcc import BPF, PerfType, PerfSWConfig
import signal
from time import sleep
import json

parser = argparse.ArgumentParser(
    description="Summarize cache references and misses by PID",
    formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument(
    "-c", "--sample_period", type=int, default=100,
    help="Sample one in this many number of cache reference / miss events")
parser.add_argument(
    "duration", nargs="?", default=10, help="Duration, in seconds, to run")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
args = parser.parse_args()

# load BPF program
bpf_text="""
#include <linux/ptrace.h>
#include <uapi/linux/bpf_perf_event.h>
#include <linux/perf_event.h>

struct cache_data_t {
    u64 address;
    u64 type;
    u32 tid;
};

BPF_PERF_OUTPUT(events);

int on_cache_miss(struct bpf_perf_event_data *ctx) {
    struct bpf_perf_event_data_kern* kctx = (struct bpf_perf_event_data_kern*)ctx;
    struct perf_sample_data *data;

    struct cache_data_t result = {};
    result.type = 1;

    bpf_probe_read(&data, sizeof(data), &kctx->data);
    bpf_probe_read(&result.address, sizeof(u64), &data->addr);
    result.tid = bpf_get_current_pid_tgid();

    events.perf_submit(ctx, &result, sizeof(result));
    return 0;
}

int on_cache_ref(struct bpf_perf_event_data *ctx) {
    struct bpf_perf_event_data_kern* kctx = (struct bpf_perf_event_data_kern*)ctx;
    struct perf_sample_data *data;

    struct cache_data_t result = {};
    result.type = 0;

    bpf_probe_read(&data, sizeof(data), &kctx->data);
    bpf_probe_read(&result.address, sizeof(u64), &data->addr);
    result.tid = bpf_get_current_pid_tgid();

    events.perf_submit(ctx, &result, sizeof(result));
    return 0;
}
"""

if args.ebpf:
    print(bpf_text)
    exit()

b = BPF(text=bpf_text)
try:
    b.attach_perf_event(
        ev_type=PerfType.SOFTWARE, ev_config=PerfSWConfig.PAGE_FAULTS,
        fn_name="on_cache_miss", sample_period=args.sample_period, cpu=3)
    # b.attach_perf_event(
    #    ev_type=PerfType.HARDWARE, ev_config=PerfHWConfig.CACHE_REFERENCES,
    #    fn_name="on_cache_ref", sample_period=args.sample_period)
except Exception as e:
    print("Failed to attach to a hardware event. Is this a virtual machine?")
    print(e)
    exit()

print("Running for {} seconds or hit Ctrl-C to end.".format(args.duration))

print("%-4s %-8s %-14s %-4s" % ("CPU", "TID", "ADDRESS", "H/M"))

def print_data(cpu, data, size):
    e = b["events"].event(data)
    t = 'H'
    if e.type == 1:
        t = 'M'
    print('%-4d %-8d 0x%-14x %-4s' % (cpu, e.tid, e.address, t))

b["events"].open_perf_buffer(print_data)

while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
