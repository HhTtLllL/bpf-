from __future__ import print_function
from time import sleep, strftime
from bcc import BPF


bpf_text = """

#include <uapi/linux/ptrace.h>
#include <uapi/linux/bpf.h>
#include <linux/mm.h>
#include <linux/seq_file.h>
#include <linux/page_ext.h>
#include <linux/page_owner.h>


BPF_HASH(table_mem, u64, int);

struct contig_page_info {
        unsigned long free_pages;
        unsigned long free_blocks_total;
        unsigned long free_blocks_suitable;
};


int cul_mem(struct pt_regs *ctx, unsigned int order, struct contig_page_info *info) {
    
    //struct contig_page_info info1 = *info;
    int return_value;
    
    return_value = PT_REGS_RC(ctx);
    u64 time = bpf_ktime_get_ns();
    table_mem.update(&time, &return_value);

    
    unsigned long free_page = info->free_pages;
    unsigned long requested = 1UL << order;
    
    time = bpf_ktime_get_ns();
    table_mem.update(&time, &res);

    return 0;
}

"""

b = BPF(text = bpf_text)
b.attach_kretprobe(event = "__fragmentation_index", fn_name = "cul_mem")
table_mem = b.get_table("table_mem")

b.trace_print()
t = 0
while(1):
    sleep(1)
    for k, v in table_mem.items():
        print("%d.%03d "%(v.value / 1000, v.value%1000))
        t += 1
        
    print(t)
    print("done")


