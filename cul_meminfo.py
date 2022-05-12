#统计系统的 totalram, freeram, shareram
#
from __future__ import print_function
from time import sleep, strftime
from bcc import BPF

import pymysql

bpf_text = """
    
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/mm_types.h>
#include <linux/sched/mm.h>

#define PAGE_SHIFT 12
#define K(x) (x) << (PAGE_SHIFT - 10)
BPF_HASH(table_meminfo, unsigned long, unsigned long);

int cul_meminfo(struct pt_regs *ctx, struct sysinfo *val) {
    
    //totalram
    unsigned long temp1 = 1;
    unsigned long totalram_size = val->totalram;
    unsigned long totalram = K(totalram_size);
    table_meminfo.update(&temp1, &totalram);

    //freeram
    unsigned long temp2 = 2;
    unsigned long freeram_size = val->freeram;
    unsigned long freeram = K(freeram_size);
    table_meminfo.update(&temp2, &freeram);

    
    //sharedram
    unsigned long temp3 = 3;
    unsigned long shared_size = val->sharedram;
    unsigned long sharedram = K(shared_size);
    table_meminfo.update(&temp3, &sharedram);


    //buffer
    //unsigned long temp4 = 4;
    //unsigned long buffer_size = val->bufferram;
    //unsigned long bufferram = K(buffer_size);
    //table_meminfo.update(&temp4, &bufferram);




    return 0;
}


"""

#mm/page_alloc.c
b = BPF(text = bpf_text)
table_meminfo = b.get_table("table_meminfo")

b.attach_kprobe(event="si_swapinfo", fn_name="cul_meminfo")



totalram = 0
freeram = 0
shareram = 0

sleep(3)
while(1):
    
    conn = pymysql.connect(host='127.0.0.1', user = 'root', password = 'll', database = 'memory')
    cursor = conn.cursor(cursor=pymysql.cursors.DictCursor)
    for k, v in table_meminfo.items():
        if(k.value == 1):
            totalram = v.value
            print("totalram :%lu"%(v.value))
        if(k.value == 2):
            freeram = v.value
            print("freeram: %lu"%(v.value))
        if(k.value == 3):
            shareram = v.value
            print("sharedram: %lu"%(v.value))
    
       
    sql = 'insert into meminfo (totalram, freeram, shareram, time) values(%(totalram)s, %(freeram)s, %(shareram)s, now())'

    cursor.execute(sql, {'totalram' : totalram, 'freeram' : freeram, 'shareram' : shareram})

    cursor.close()
    conn.commit()
    conn.close()

    sleep(3)
