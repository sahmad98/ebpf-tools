#!/usr/bin/python

'''
Author: Saleem Ahmad
usage: sudo python iospeed -p <pid>
'''
from __future__ import print_function
from bcc import BPF
from bcc.utils import printb
from time import sleep
from optparse import OptionParser

parser = OptionParser()
parser.add_option('-p', '--pid', dest='pid', help='pid to trace', type='int')

(option, args) = parser.parse_args()

# load BPF program
text='''
#include <uapi/linux/ptrace.h>

struct IOData {
	u64 bytes;
	u64 type;
	u64 time;
};

BPF_HASH(data, u32, struct IOData);
BPF_PERF_OUTPUT(output);

void write_probe(struct pt_regs* ctx, int fd, const void* buf, size_t len) {
	u32 pid = (bpf_get_current_pid_tgid() >> 32);
	if (pid != TRACE_PID) return;

	u64 ts = bpf_ktime_get_ns();
	u32 key = 1;
	struct IOData* val = data.lookup(&key);
    int count = PT_REGS_RC(ctx);
    if (count < 0) {
        count = 0;
    }

	if (val) {
		val->bytes += count;
		if (ts - val->time > 1000000000L) {
			output.perf_submit(ctx, val, sizeof(struct IOData));
			val->bytes = 0;
			val->time = ts;
		}
	} else {
		struct IOData zero;
		zero.time = ts;
		zero.type = key;
		zero.bytes = 0;
		data.insert(&key, &zero);
	}
}

void read_probe(struct pt_regs* ctx, int fd, const void* buf, size_t len) {
	u32 pid = (bpf_get_current_pid_tgid() >> 32);
	if (pid != TRACE_PID) return;

	u64 ts = bpf_ktime_get_ns();
	u32 key = 0;
	struct IOData* val = data.lookup(&key);
    int count = PT_REGS_RC(ctx);
    if (count < 0) {
        count = 0;
    }

	if (val) {
		val->bytes += count;
		if (ts - val->time > 1000000000L) {
			output.perf_submit(ctx, val, sizeof(struct IOData));
			val->bytes = 0;
			val->time = ts;
		}
	} else {
		struct IOData zero;
		zero.time = ts;
		zero.type = key;
		zero.bytes = 0;
		data.insert(&key, &zero);
	}
}
'''.replace('TRACE_PID', str(option.pid))

#print(text)

b = BPF(text=text)

print('IOSpeed Running, PID: %d' % option.pid)
w_name = b.get_syscall_fnname('write')
r_name = b.get_syscall_fnname('read')
print('Tracing: %s' % ','.join([w_name, r_name]))

b.attach_kretprobe(event=w_name, fn_name="write_probe")
b.attach_kretprobe(event=r_name, fn_name="read_probe")

MB_DIVIDER = 1024.0 * 1024.0

def print_data(cpu, data, size):
	e = b['output'].event(data)
	t = 'RD'
	if e.type == 1:
		t = 'WR'
	print("%ld,%s,%0.4f MB/sec" % (e.time, t, e.bytes / MB_DIVIDER))

b['output'].open_perf_buffer(print_data)
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
