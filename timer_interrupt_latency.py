#!/usr/bin/env python

from bcc import BPF
from optparse import OptionParser

code='''
struct data_t {
    u64 delta;
};

BPF_HASH(time);
BPF_PERF_OUTPUT(events);

TRACEPOINT_PROBE(irq_vectors, local_timer_entry) {
    u64 key = 0;
    u64 t = bpf_ktime_get_ns();
    time.update(&key, &t);
    return 0;
}

TRACEPOINT_PROBE(irq_vectors, local_timer_exit) {
    u64 key = 0;
    u64* kp;
    kp = time.lookup(&key);
    if (kp != NULL) {
        struct data_t result;
        result.delta = bpf_ktime_get_ns() - *kp;
        events.perf_submit(args, &result, sizeof(result));
    }
}
'''

parser = OptionParser()
parser.add_option("-c", "--core", dest="core", help="Core to Trace", default=3, type=int)
(option, args) = parser.parse_args()

b = BPF(text = code)
def print_data(cpu, data, size):
    e = b["events"].event(data)
    if cpu == option.core:
        print "%-8d %-16s" % (cpu, e.delta)
b["events"].open_perf_buffer(print_data)
print 'Running CPU %d Timer Latency... Press Ctrl C-to Quit' % option.core
print '%-8s %-16s' % ("CPU", "LATENCY")
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        print 'Exiting'
        exit()
