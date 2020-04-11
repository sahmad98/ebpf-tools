#!/usr/bin/env python

from bcc import BPF

code='''
int kprobe__sys_sync(void* ctx) {
    bpf_trace_printk("sync called\\n");
    return 0;
}
'''

try:
    print 'Running trace sys... Press Ctrl C-to Quit'
    BPF(text = code).trace_print()
except KeyboardInterrupt:
    print 'Exiting'
