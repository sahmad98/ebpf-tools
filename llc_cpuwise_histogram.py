#!/usr/bin/python
#

from __future__ import print_function
import argparse
from bcc import BPF, PerfType, PerfHWConfig
import signal
from time import sleep

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

BPF_HISTOGRAM(ref_count, u32);
BPF_HISTOGRAM(miss_count, u32);

int on_cache_miss(struct bpf_perf_event_data *ctx) {
    u32 cpu = bpf_get_smp_processor_id();
    miss_count.increment(cpu, ctx->sample_period);
    return 0;
}

int on_cache_ref(struct bpf_perf_event_data *ctx) {
    u32 cpu = bpf_get_smp_processor_id();
    ref_count.increment(cpu, ctx->sample_period);
    return 0;
}
"""

if args.ebpf:
    print(bpf_text)
    exit()

b = BPF(text=bpf_text)
try:
    b.attach_perf_event(
        ev_type=PerfType.HARDWARE, ev_config=PerfHWConfig.CACHE_MISSES,
        fn_name="on_cache_miss", sample_period=args.sample_period)
    b.attach_perf_event(
        ev_type=PerfType.HARDWARE, ev_config=PerfHWConfig.CACHE_REFERENCES,
        fn_name="on_cache_ref", sample_period=args.sample_period)
except Exception:
    print("Failed to attach to a hardware event. Is this a virtual machine?")
    exit()

print("Running for {} seconds or hit Ctrl-C to end.".format(args.duration))

try:
    sleep(float(args.duration))
except KeyboardInterrupt:
    signal.signal(signal.SIGINT, lambda signal, frame: print())

print("-" * 32)
print("Miss Count Histogram")
b["miss_count"].print_linear_hist(val_type="CPU")

print("-" * 32)
print("Ref Count Histogram")
b["ref_count"].print_linear_hist(val_type="CPU")

miss = b.get_table("miss_count")
refs = b.get_table("ref_count")

hit_rate = {}
miss_rate = {}
for (k, v) in refs.items():
    total = v.value + miss[k].value
    hit_rate[k.value] = 1.0 * v.value / total
    miss_rate[k.value] = 1.0 * miss[k].value / total

print("-" * 32)
print("Hit/Miss Rate")
print("%-8s %-8s %s" % ("CPU", "HitRate", "MissRate"))
for cpu in hit_rate:
    print("%-8s %-8.2f %.2f" % (cpu, hit_rate[cpu], miss_rate[cpu]))
