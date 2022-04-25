#统计进程的可用内存

from __future__ import print_function
from time import sleep, strftime
from bcc import BPF

bpf_text = """

#include <uapi/linux/ptrace.h>

#define K(x) (x) << (PAGE_SHIFT - 10)
BPF_HASH(table_available, u32, u32);

int cul_available(struct pt_regs *ctx) {
    
    u32 return_value;

    return_value = PT_REGS_RC(ctx);
    return_value = K(return_value);
    table_available.update(&return_value, &return_value);
    
    return 0;
}


"""

b = BPF(text = bpf_text)
b.attach_kretprobe(event = "si_mem_available", fn_name = "cul_available")
table_available = b.get_table("table_available")

while(1):
    sleep(1)
    for k, v in table_available.items():
        print("MEMavailable(可用): %lu"%(v.value))


