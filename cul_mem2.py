from __future__ import print_function
from time import sleep, strftime
from bcc import BPF

# -1 表示分配可以成功
# 0 表示分配失败和内存不足的关联更大
# 越接近表示分配和碎片化有关，表示当前内存碎片更多
#
#

bpf_text = """

#include <uapi/linux/ptrace.h>
#include <uapi/linux/bpf.h>
#include <linux/mm.h>
#include <linux/seq_file.h>
#include <linux/page_ext.h>
#include <linux/page_owner.h>

BPF_HASH(dma, int, int);
BPF_HASH(dma32, int, int);
BPF_HASH(normal, int, int);


struct contig_page_info {

        unsigned long free_pages;
        unsigned long free_blocks_total;
        unsigned long free_blocks_suitable;
};

int cul_mem(struct pt_regs *ctx, struct seq_file *m, pg_data_t *pgdat,  struct zone *zone) {

    int result = -1000;
    int zero = 0;
    const char *p = zone->name;
    int order, key;

    for (order = 0; order < MAX_ORDER; ++order) {
        
        //初始化 info
        unsigned long free_pages = 0;
        unsigned long free_blocks_total = 0;
        unsigned long free_blocks_suitable = 0;

        unsigned int fill_order;

        for (fill_order = 0; fill_order < MAX_ORDER; fill_order++) {
 
            unsigned long blocks = 0;
            /* Count number of free blocks */
            blocks = (&(zone->free_area[0]) + fill_order)->nr_free;
            free_blocks_total += blocks;
            /* Count free base pages */
            free_pages += blocks << fill_order;
            /* Count the suitable free blocks */
            if (fill_order >= order)    free_blocks_suitable += blocks << (fill_order - order);
        }


        //__fragmentation_index
        unsigned long requested = 1UL << order;
        key = order;

        if (p[3] == \'3\') {
            
            if (order >= MAX_ORDER) {
                dma32.update(&key, &zero);
                continue;
            }

            if (!free_blocks_total) {
                dma32.update(&key, &zero);
                continue;
            }

            /* Fragmentation index only makes sense when a request would fail */
            if (free_blocks_suitable) {
                dma32.update(&key, &result);
                continue;
            }

            int res =  1000 - div_u64( (1000+(div_u64(free_pages * 1000ULL, requested))), free_blocks_total);
            dma32.update(&key, &res);

        } else if (p[0] == \'N\') {
            
            if (order >= MAX_ORDER) {
                normal.update(&key, &zero);
                continue;
            }

            if (!free_blocks_total) {
                normal.update(&key, &zero);
                continue;
            }

            /* Fragmentation index only makes sense when a request would fail */
            if (free_blocks_suitable) {
                normal.update(&key, &result);
                continue;
            }

            int res =  1000 - div_u64( (1000+(div_u64(free_pages * 1000ULL, requested))), free_blocks_total);
            normal.update(&key, &res);
        } else {

            if (order >= MAX_ORDER) {
                dma.update(&key, &zero);
                continue;
            }

            if (!free_blocks_total) {
                dma.update(&key, &zero);
                continue;
            }

            /* Fragmentation index only makes sense when a request would fail */
            if (free_blocks_suitable) {
                dma.update(&key, &result);
                continue;
            }

            int res =  1000 - div_u64( (1000+(div_u64(free_pages * 1000ULL, requested))), free_blocks_total);
            dma.update(&key, &res);
        }
    }

    return 0;
}

"""

b = BPF(text = bpf_text)
b.attach_kprobe(event = "extfrag_show_print", fn_name = "cul_mem")
dma = b.get_table("dma")
dma32 = b.get_table("dma32")
normal = b.get_table("normal")

#b.trace_print()
t = 0
while(1):
    sleep(1)

    print("---------------------------------------------------------")
    print("dma ", end = '\t')
    for i in range (0, 12):
        for k, v in dma.items():
            if (i == k.value) :
                print("%d.%03d "%(v.value / 1000, v.value%1000), end = '\t')
    print()

    print("dma32 ", end = '\t')
    for i in range (0, 12):
        for k, v in dma32.items():
            if (i == k.value) :
                print("%d.%03d "%(v.value / 1000, v.value%1000), end = '\t')
    print()

    print("normal ", end = '\t')
    for i in range (0, 12):
        for k, v in normal.items():
            if (i == k.value) :
                print("%d.%03d "%(v.value / 1000, v.value%1000), end = '\t')

    print()
    print()
    print()
    print()
