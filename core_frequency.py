#!/usr/bin/env python

'''
core_frequency.py - Low overhead BPF Tool to monitor core frequencies.
Author: Saleem Ahmad (saleem.iitg[@]gmail.com)

Usage: ./core_frequency.py [-s 1] [-t 2.5]

NOTE: For Reference TSC Frequency, put the value of frequency in Model Name of
lscpu output, or read 0x16 leaf of CPUID. For more information read about
cpuid instruction in x86
'''

from bcc import BPF, PerfType, PerfHWConfig, utils, PerfSWConfig
from optparse import OptionParser

parser = OptionParser()
parser.add_option('-s', '--sample-freq', dest='sample_freq', help='Frequency Sample Rate in Hz', type=int, default=1)
parser.add_option('-t', '--tsc-freq', dest='tsc_freq', help='Reference Clock Frequency in GHz (see lscpu or cpuid)', type=float, default=2.5)
(option, args) = parser.parse_args()

code = '''
# include <linux/bpf.h>
# include <uapi/linux/bpf_perf_event.h>
# include <uapi/linux/ptrace.h>

/*
- Structure to hold the last sample data as well as to output
differential data via perf event buffer.
*/
struct PerfData {
    u64 cycles;
    u64 ref_cycles;
};

// Perf Events array
BPF_PERF_ARRAY(cycles, MAX_CPUS);
BPF_PERF_ARRAY(ref_cycles, MAX_CPUS);

// Per CPU array to store the last samples.
BPF_PERCPU_ARRAY(last_sample, struct PerfData, MAX_CPUS);

// Perf Ouptut Buffer
BPF_PERF_OUTPUT(output);

void get_perf_counters(struct bpf_perf_event_data* ctx) {
    u32 cpu = bpf_get_smp_processor_id();
    /*
    NOTE: Use bpf_perf_event_value is recommended over
    bpf_perf_event_read or map.perf_read() due to
    issues in ABI. map.perf_read_value() need to be
    implemented in future.
    */
    u64 cyc = cycles.perf_read(cpu);
    u64 ref = ref_cycles.perf_read(cpu);

    struct PerfData result;
    struct PerfData* ptr = last_sample.lookup(&cpu);

    if (ptr) {
        result.cycles = cyc - ptr->cycles;
        result.ref_cycles = ref - ptr->ref_cycles;
        ptr->cycles = cyc;
        ptr->ref_cycles = ref;
        output.perf_submit(ctx, &result, sizeof(struct PerfData));
    } else {
        result.cycles = cyc;
        result.ref_cycles = ref;
        last_sample.insert(&cpu, &result);
    }
}
'''

max_cpus = len(utils.get_online_cpus())
b = BPF(text=code, cflags=['-DMAX_CPUS=%s' % str(max_cpus)])

# Cycles and Ref Cycles counters are required to measure frequency.
b['cycles'].open_perf_event(PerfType.HARDWARE, PerfHWConfig.CPU_CYCLES)
b['ref_cycles'].open_perf_event(PerfType.HARDWARE, PerfHWConfig.REF_CPU_CYCLES)

# A dummy perf event which will get triggered at every Sample Frequency.
b.attach_perf_event(ev_type=PerfType.SOFTWARE,
    ev_config=PerfSWConfig.CPU_CLOCK,
    fn_name='get_perf_counters',
    sample_freq=option.sample_freq)


def print_data(cpu, data, size):
    e = b["output"].event(data)
    print "%-4d %-16d %-16d %-16.2f" % (cpu, e.cycles, 
        e.ref_cycles, 
        e.cycles * option.tsc_freq / e.ref_cycles)


print "Counters Data"
print "%-4s %-16s %-16s %-16s" % ('CPU', 'CLOCK', 'REF-CYCLES', 'FREQ')

b['output'].open_perf_buffer(print_data)

while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
