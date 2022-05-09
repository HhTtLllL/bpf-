from __future__ import print_function
from time import sleep, strftime
from bcc import BPF

import pymysql

# -1 表示分配可以成功
# 0 表示分配失败和内存不足的关联更大
# 越接近表示分配和碎片化有关，表示当前内存碎片更多

#mm/vmstat
#/sys/kernel/debug/exfrag/extfrag_index
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


/*
struct contig_page_info {

        unsigned long free_pages;
        unsigned long free_blocks_total;
        unsigned long free_blocks_suitable;
};

*/

int cul_mem(struct pt_regs *ctx, struct seq_file *m, pg_data_t *pgdat,  struct zone *zone) {


    bpf_trace_printk("asdasdasd");

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
            blocks = (&(zone->free_area[0]) + fill_order)->nr_free; //nr_free 说明有多少个可用的页
            free_blocks_total += blocks;
            /* Count free base pages */
            free_pages += blocks << fill_order;
            /* Count the suitable free blocks */
            if (fill_order >= order)    free_blocks_suitable += blocks << (fill_order - order);
        }
        
        bpf_trace_printk("order = %d, free_blocks_total = %lu, free_pages = %lu",order, free_blocks_total, free_pages);

        //__fragmentation_index
        //数值从0-1,保留两位小数，总共是3位有效数字。转换成0-1000；
        unsigned long requested = 1UL << order;
        key = order;

        if (p[3] == \'3\') {
            
            if (order >= MAX_ORDER) {
                dma32.update(&key, &zero);
                continue;
            }

            if (!free_blocks_total) {       //如果没有内存，返回0。都没有内存，更没有碎片
                dma32.update(&key, &zero);
                continue;
            }

            /* Fragmentation index only makes sense when a request would fail */
            if (free_blocks_suitable) {         //内存充足,返回-1
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
            bpf_trace_printk("res_real = %d", res);
            bpf_trace_printk("request = %lu", requested);

            bpf_trace_printk("div_64_1 = %lu", (div_u64(free_pages * 1000ULL, requested)));
            bpf_trace_printk("res = %lu", div_u64( (1000+(div_u64(free_pages * 1000ULL, requested))), free_blocks_total));
            bpf_trace_printk("zone_free_page = %lu, free_blocks_total = %lu", free_pages, free_blocks_total);
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
                            //1000 - ( 1000 + (1000 * zone_free_page (申请连续page block的page数)) / freeblock 个数)

            int res =  1000 - div_u64( (1000+(div_u64(free_pages * 1000ULL, requested))), free_blocks_total);
                            //统计0-order中空闲页的总数量和各个链表上空闲块的总数，当空闲页数一定时，如果低阶的空闲页数量越多，则block值越高，则最后的最后的碎片化也越严重。如果高阶的空闲页数量多，则block相对较小。则碎片化比较轻微。
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



dma_list = [0.0,0.0,0,0,0,0,0,0,0,0,0,0,0,0,0]
dma32_list = [0.0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
normal_list = [0.0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]



b.trace_print()
t = 0
while(1):

    sleep(3)

    conn = pymysql.connect(host='127.0.0.1', user = 'root', password = 'll', database = 'memory')
    cursor = conn.cursor(cursor=pymysql.cursors.DictCursor)

    print("---------------------------------------------------------")
    print("dma ", end = '\t')
    for i in range (0, 12):
        for k, v in dma.items():
            if (i == k.value) :
                dma_list[i] = v.value / 1000 + (v.value%1000)/1000
                if (dma_list[i] > 1): 
                    dma_list[i] = dma_list[i] - 1;
                print("%d.%03d "%(v.value / 1000, v.value%1000), end = '\t')
    print()

    sql = 'insert into frag_dma(dma_zero, dma_one, dma_two, dma_three, dma_four, dma_five, dma_six, dma_seven, dma_eight, dma_nine, dma_ten, time) values(%(dma_zero)s, %(dma_one)s, %(dma_two)s, %(dma_three)s, %(dma_four)s, %(dma_five)s, %(dma_six)s, %(dma_seven)s, %(dma_eight)s, %(dma_nine)s, %(dma_ten)s,  now())'

    cursor.execute(sql, {'dma_zero' : dma_list[0], 'dma_one' : dma_list[1],'dma_two' : dma_list[2],'dma_three' : dma_list[3],'dma_four' : dma_list[4],'dma_five' : dma_list[5],'dma_six' : dma_list[6],'dma_seven' : dma_list[7],'dma_eight' : dma_list[8],'dma_nine' : dma_list[9],'dma_ten' : dma_list[10]})


    print("dma32 ", end = '\t')
    for i in range (0, 12):
        for k, v in dma32.items():
            if (i == k.value) :
                dma32_list[i] = v.value / 1000 + (v.value%1000)/1000
                if (dma32_list[i] > 1) :
                    dma32_list[i] = dma32_list[i] - 1;
                print("%d.%03d "%(v.value / 1000, v.value%1000), end = '\t')
    print()

    sql = 'insert into frag_dma32(dma32_zero, dma32_one, dma32_two, dma32_three, dma32_four, dma32_five, dma32_six, dma32_seven, dma32_eight, dma32_nine, dma32_ten, time) values(%(dma32_zero)s, %(dma32_one)s, %(dma32_two)s, %(dma32_three)s, %(dma32_four)s, %(dma32_five)s, %(dma32_six)s, %(dma32_seven)s, %(dma32_eight)s, %(dma32_nine)s, %(dma32_ten)s,  now())'

    cursor.execute(sql, {'dma32_zero' : dma32_list[0], 'dma32_one' : dma32_list[1],'dma32_two' : dma32_list[2],'dma32_three' : dma32_list[3],'dma32_four' : dma32_list[4],'dma32_five' : dma32_list[5],'dma32_six' : dma32_list[6],'dma32_seven' : dma32_list[7],'dma32_eight' : dma32_list[8],'dma32_nine' : dma32_list[9],'dma32_ten' : dma32_list[10]})


    print("normal ", end = '\t')
    for i in range (0, 12):
        for k, v in normal.items():
            if (i == k.value) :
                normal_list[i] = ((v.value + (v.value%1000)*1.0)) / 1000.0
                if (normal_list[i] > 1):
                    normal_list[i] = normal_list[i] - 1;
                print("%d.%03d "%(v.value / 1000, v.value%1000), end = '\t')

    sql = 'insert into frag_normal(normal_zero, normal_one, normal_two, normal_three, normal_four, normal_five, normal_six, normal_seven, normal_eight, normal_nine, normal_ten, time) values(%(normal_zero)s, %(normal_one)s, %(normal_two)s, %(normal_three)s, %(normal_four)s, %(normal_five)s, %(normal_six)s, %(normal_seven)s, %(normal_eight)s, %(normal_nine)s, %(normal_ten)s,  now())'

    cursor.execute(sql, {'normal_zero' : normal_list[0], 'normal_one' : normal_list[1],'normal_two' : normal_list[2],'normal_three' : normal_list[3],'normal_four' : normal_list[4],'normal_five' : normal_list[5],'normal_six' : normal_list[6],'normal_seven' : normal_list[7],'normal_eight' : normal_list[8],'normal_nine' : normal_list[9],'normal_ten' : normal_list[10]})

    


    cursor.close()
    conn.commit()
    conn.close()

    print()
    print()
    print()
    print()
