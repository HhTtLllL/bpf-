#统计 每个进程的 virt  res shr 信息
#
#
#
#
from __future__ import print_function 
from bcc import BPF
from time import sleep, strftime
bpf_text = """

#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/mm_types.h>
#include <linux/sched/mm.h>

BPF_PROG_ARRAY(table_prog, 1024);
BPF_HASH(table_shared, u32, u32);
BPF_HASH(table_resident, u32, u32);
BPF_HASH(table_total, u32, u32);

int tail_call(void *ctx) {
    
    bpf_trace_printk("Tail-call++++++++++++++++++++++++++++++");

    return 0;
}


int cul_rss(struct pt_regs *ctx, struct mm_struct *mm, int *shared, int *text, int *data, int *resident) {

    
    bpf_trace_printk("cul_rss---------------------------987987987");

    u32 cur_pid = bpf_get_current_pid_tgid();
    u32 cur_shared = *shared;
    u32 cur_resident = *resident;
    u32 cur_total = mm->total_vm;

    table_shared.update(&cur_pid, &cur_shared);
    table_resident.update(&cur_pid, &cur_resident);

    table_total.update(&cur_pid, &cur_total);


    table_prog.call(ctx, 2);

    return 0;
}


"""


b = BPF(text=bpf_text)

tail_fn = b.load_func("tail_call", BPF.KPROBE)
table_prog = b.get_table("table_prog")
table_prog[int(2)] = int(tail_fn.fd)

b.attach_kretprobe(event="task_statm", fn_name="cul_rss")

table_shared = b.get_table("table_shared")
table_resident = b.get_table("table_resident")
table_total = b.get_table("table_total")

#b.trace_print()

#(task, pid, cpu, flags) = b.trace_fields()

print("PID            VIRT          RES          SHR          ")
while(1):
        sleep(1)
#        for k, v in table.items():
#            print("%-10d%-10d"%(k.value, v.value*4))
#        table.clear()
        
        for k, v in table_shared.items():
          #  print("ID: " + str(k) + "    " + "VIRT: " + str(table_total[k] * 4) + "   " +  "RES: " + str(table_resident[k] * 4) + "     " + "SHR: " + str(table_shared[k] * 4) )

          print("%-10d   %-10d   %-10d   %-10d"%(k.value, table_total[k].value * 4, table_resident[k].value * 4, table_shared[k].value * 4))
        



        table_shared.clear()
        table_resident.clear()
        table_total.clear()
        



