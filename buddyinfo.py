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


BPF_HASH(dma, int, unsigned long);
BPF_HASH(dma32, int, unsigned long);
BPF_HASH(normal, int, unsigned long);
BPF_HASH(zone, int, char);

int cul_mem(struct pt_regs *ctx, struct seq_file *m, pg_data_t *pgdat, struct zone *zone) {
    
    bpf_trace_printk("node %d, zone %s", pgdat->node_id, zone->name);

    const char* p = zone->name;

    int order, key;
    if (p[3] == \'3\') {

        //DMA32
        for (order = 0; order < MAX_ORDER; ++order) {
    
            //bpf_trace_printk("free_area = %6lu", (&(zone->free_area[0]) + order)->nr_free);
            unsigned long free = (&(zone->free_area[0])+order)->nr_free;
            key = order;
            dma32.update(&key, &free);
        }
    } else if (p[0] == \'N\'){
        
        //NORMAL
        for (order = 0; order < MAX_ORDER; ++order) {
    
            //bpf_trace_printk("free_area = %6lu", (&(zone->free_area[0]) + order)->nr_free);
            unsigned long free = (&(zone->free_area[0])+order)->nr_free;
            key = order;
            normal.update(&key, &free);
        }
    } else {

        //DMA
        for (order = 0; order < MAX_ORDER; ++order) {
    
            //bpf_trace_printk("free_area = %6lu", (&(zone->free_area[0]) + order)->nr_free);
            unsigned long free = (&(zone->free_area[0])+order)->nr_free;
            key = order;
            dma.update(&key, &free);
        }
    }

        return 0;
}

"""

b = BPF(text = bpf_text)
b.attach_kprobe(event = "frag_show_print", fn_name = "cul_mem")
dma = b.get_table("dma")
dma32 = b.get_table("dma32")
normal = b.get_table("normal")




#b.trace_print()
while(1):
    sleep(1)

    print("---------------------------------------------------------")
    print("dma ", end = '\t')
    for i in range (0, 12):
        for k, v in dma.items():
            if (i == k.value) :
                print("%6lu"%(v.value), end = '\t')
    print()

    print("dma32 ", end = '\t')   
    for i in range (0, 12):
        for k, v in dma32.items():
            if (i == k.value) :
                print("%6lu"%(v.value), end = '\t')
    print()

    print("normal ", end = '\t')   
    for i in range (0, 12):
        for k, v in normal.items():
            if (i == k.value) :
                print("%6lu"%(v.value), end = '\t')

    print()
    print()
    print()
    print()
