from __future__ import print_function
from time import sleep, strftime
from bcc import BPF

import pymysql

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
BPF_HASH(zone, int, char*);

int cul_mem(struct pt_regs *ctx, struct seq_file *m, pg_data_t *pgdat, struct zone *zone) {
    
    bpf_trace_printk("node %d, zone %s", pgdat->node_id, zone->name);
    bpf_trace_printk("node %d",  pageblock_order);

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


dma_list = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
dma32_list = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
normal_list = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]

#b.trace_print()
#num*2^x*PAGE_SIZE   /mm/vmstat.c 
sleep(3)
while(1):
    sleep(3)

    conn = pymysql.connect(host='127.0.0.1', user = 'root', password = 'll', database = 'memory')
    cursor = conn.cursor(cursor=pymysql.cursors.DictCursor)


    print("---------------------------------------------------------")
    print("dma ", end = '\t')
    for i in range (0, 12):
        for k, v in dma.items():
            if (i == k.value) :
                dma_list[i] = v.value
                print("%6lu"%(v.value), end = '\t')

    sql = 'insert into buddy_dma(dma_zero, dma_one, dma_two, dma_three, dma_four, dma_five, dma_six, dma_seven, dma_eight, dma_nine, dma_ten, time) values(%(dma_zero)s, %(dma_one)s, %(dma_two)s, %(dma_three)s, %(dma_four)s, %(dma_five)s, %(dma_six)s, %(dma_seven)s, %(dma_eight)s, %(dma_nine)s, %(dma_ten)s,  now())'

    cursor.execute(sql, {'dma_zero' : dma_list[0], 'dma_one' : dma_list[1],'dma_two' : dma_list[2],'dma_three' : dma_list[3],'dma_four' : dma_list[4],'dma_five' : dma_list[5],'dma_six' : dma_list[6],'dma_seven' : dma_list[7],'dma_eight' : dma_list[8],'dma_nine' : dma_list[9],'dma_ten' : dma_list[10]})

    print()

    print("dma32 ", end = '\t')   
    for i in range (0, 12):
        for k, v in dma32.items():
            if (i == k.value) :
                dma32_list[i] = v.value
                print("%6lu"%(v.value), end = '\t')
    

    sql = 'insert into buddy_dma32(dma32_zero, dma32_one, dma32_two, dma32_three, dma32_four, dma32_five, dma32_six, dma32_seven, dma32_eight, dma32_nine, dma32_ten, time) values(%(dma32_zero)s, %(dma32_one)s, %(dma32_two)s, %(dma32_three)s, %(dma32_four)s, %(dma32_five)s, %(dma32_six)s, %(dma32_seven)s, %(dma32_eight)s, %(dma32_nine)s, %(dma32_ten)s,  now())'

    cursor.execute(sql, {'dma32_zero' : dma32_list[0], 'dma32_one' : dma32_list[1],'dma32_two' : dma32_list[2],'dma32_three' : dma32_list[3],'dma32_four' : dma32_list[4],'dma32_five' : dma32_list[5],'dma32_six' : dma32_list[6],'dma32_seven' : dma32_list[7],'dma32_eight' : dma32_list[8],'dma32_nine' : dma32_list[9],'dma32_ten' : dma32_list[10]})

    print()

    print("normal ", end = '\t')   
    for i in range (0, 12):
        for k, v in normal.items():
            if (i == k.value) :
                normal_list[i] = v.value
                print("%6lu"%(v.value), end = '\t')


    sql = 'insert into buddy_normal(normal_zero, normal_one, normal_two, normal_three, normal_four, normal_five, normal_six, normal_seven, normal_eight, normal_nine, normal_ten, time) values(%(normal_zero)s, %(normal_one)s, %(normal_two)s, %(normal_three)s, %(normal_four)s, %(normal_five)s, %(normal_six)s, %(normal_seven)s, %(normal_eight)s, %(normal_nine)s, %(normal_ten)s,  now())'

    cursor.execute(sql, {'normal_zero' : normal_list[0], 'normal_one' : normal_list[1],'normal_two' : normal_list[2],'normal_three' : normal_list[3],'normal_four' : normal_list[4],'normal_five' : normal_list[5],'normal_six' : normal_list[6],'normal_seven' : normal_list[7],'normal_eight' : normal_list[8],'normal_nine' : normal_list[9],'normal_ten' : normal_list[10]})


    


    cursor.close()
    conn.commit()
    conn.close()

    print()
    print()
    print()
    print()
