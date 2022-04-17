from __future__ import print_function
from time import sleep, strftime
from bcc import BPF


bpf_text = """
    
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/mm_types.h>
#include <linux/sched/mm.h>

#define PAGE_SHIFT 12
#define K(x) ((x) << (PAGE_SHIFT - 10))

BPF_HASH(table_meminfo, char, u32);

int cul_meminfo(struct pt_regs *ctx, struct seq_file *m, const char *s, unsigned long num) {

    u32 temp = 1;
    char c = s[0];

    //u32 totalram_size = val->totalram;
    u32 totalram = num;
    //u32 freeram = val->freeram;

    table_meminfo.update(&c, &totalram);

    return 0;
}


"""

b = BPF(text = bpf_text)

b.attach_kretprobe(event="show_val_kb" , fn_name="cul_meminfo")
table_meminfo = b.get_table("table_meminfo")

while(1):
    sleep(1)
    for k, v in table_meminfo.items():
        print("%c%d"%(k.value, v.value))

