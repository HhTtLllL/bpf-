#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from __future__ import print_function
from bcc import BPF


#
#mm/vmstat.c refresh_cpu_stats --828
#
bpf_text ="""
#include <uapi/linux/ptrace.h>
#include <uapi/linux/sysinfo.h>
#include <uapi/linux/kernel.h>
int do_return(struct pt_regs *ctx) {
    bpf_trace_printk("aaaaaaaaaaaaaaaaaaaa"); 
    return 0;    
}

"""

b = BPF(text=bpf_text)
b.attach_kprobe(event="refresh_cpu_vm_stats", fn_name="do_return")
print("Tracing for quick sync's... Ctrl-C to end")

b.trace_print()
# format output
while 1:
    (task, pid, cpu, flags, ts, msg) = b.trace_fields()
    print("%-18.9f %-16s %-6d %s" % (ts, task, pid,msg ))    

