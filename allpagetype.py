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

int allpage(struct pt_regs *ctx, struct seq_file *m, pg_data_t *pgdat, struct zone *zone) {
    
    bpf_trace_printk("pages = %d", pageblock_nr_pages);
    int mtype;
    unsigned long pfn;
    unsigned long start_pfn = zone->zone_start_pfn;
    unsigned long end_pfn = zone->zone_start_pfn + zone->spanned_pages;
    unsigned long count[MIGRATE_TYPES] = {0,};
    

    int time = (end_pfn - start_pfn) / pageblock_nr_pages;

    while(time --) {

        struct page *page;

        //问题在这里，但是不知道为什么
        page = (void*)(start_pfn * PAGE_SIZE);

        if (!page) continue;
        if (page_zone(page) != zone) continue;

        mtype = get_pageblock_migratetype(page);
        if (mtype < MIGRATE_TYPES) count[mtype]++;

        pfn += pageblock_nr_pages;
    }
    
    return 0;
}
"""


b = BPF(text = bpf_text)
b.attach_kprobe(event = "pagetypeinfo_showblockcount_print", fn_name = "allpage")

b.trace_print()
