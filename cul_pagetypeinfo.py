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

BPF_HASH(pagetype, int, unsigned long);

int pagetypeinfo(struct pt_regs *ctx, struct seq_file *m, pg_data_t *pgdat, struct zone *zone) {

    int order, mtype, key;
    unsigned long value;
    for (mtype = 0; mtype < MIGRATE_TYPES; mtype++ ) {

        for (order = 0; order < MAX_ORDER; ++ order) {
            
            unsigned long freecount = 0;
            struct free_area *area;
            struct list_head *curr;
            bool overflow = false;
    
            //area = &(zone->free_area[order]);
            area = &(zone->free_area[0]) + order;

            list_for_each(curr, &area->free_list[mtype]) {
                
                if (++ freecount >= 100000) {

                    
                    overflow = true;
                    break;
                }
            }
            
            key = order;
            value = freecount;
            bpf_trace_printk("freecount = %lu", value);
            //pagetype.update(&key, &value);
        }
    }



    return 0;
}


"""


b = BPF(text = bpf_text)
b.attach_kprobe(event = "pagetypeinfo_showfree_print", fn_name = "pagetypeinfo")
b.trace_print()


