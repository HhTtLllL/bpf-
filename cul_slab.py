from __future__ import print_function
from time import sleep, strftime
from bcc import BPF

import pymysql

#get_slabinfo
bpf_text = """
    
#include <uapi/linux/ptrace.h>
#include <linux/sched/mm.h>
#include <linux/slub_def.h>

BPF_HASH(name, int, char*);
BPF_HASH(size, int, unsigned int);
BPF_HASH(objects_per_slab, int, unsigned int);
BPF_HASH(cache_order, int,  int);

#define OO_SHIFT 16
#define OO_MASK ((1 << OO_SHIFT) - 1)

struct slabinfo {
	unsigned long active_objs;
	unsigned long num_objs;
	unsigned long active_slabs;
	unsigned long num_slabs;
	unsigned long shared_avail;
	unsigned int limit;
	unsigned int batchcount;
	unsigned int shared;
	unsigned int objects_per_slab;
	unsigned int cache_order;
};

struct kmem_cache_node {

	spinlock_t list_lock;
	atomic_long_t nr_slabs;
	atomic_long_t total_objects;
	struct list_head full;
};


struct Myslab {
    
    char name[20];
    unsigned int size;
    unsigned int ob_slab;
    int cache_order;
};


BPF_HASH(myslab_table, unsigned long, struct Myslab);

#define for_each_kmem_cache_node(__s, __node, __n) \
	for (__node = 0; __node < 1; __node++) \
                 if ((__n = __s->node[__node]))

struct kmem_cache *kmem_cache_node;

int cul_meminfo(struct pt_regs *ctx, struct kmem_cache *s, struct slabinfo *sinfo) { 
    
    unsigned long nr_slabs = 0;
    unsigned long nr_objs = 0;
    unsigned long nr_free = 0;
    int node;
    char name[20];
/*
    struct kmem_cache_node *n;
    for (node = 0; node < 1; node ++) {
        n = s->node[node];
        unsigned long tmp =  &n->nr_slabs;
    }
*/

/*     for_each_kmem_cache_node(s, node, n) {
        nr_slabs += node_nr_slabs(n);
        nr_slabs += atomic_long_read(&n->nr_slabs);
    }
*/
    
    struct Myslab myslab;

    unsigned int x = (s->oo).x;
    int k = 1;

    //name.update(&k, s->name);
    unsigned int size_ = s->size;
    size.update(&k, &size_);
    
    unsigned int slab = x & OO_MASK;
    objects_per_slab.update(&k, &slab);

    int order = (1 << (x >> OO_SHIFT));
    cache_order.update(&k, &order);
        
    for (int i = 0; i < 20; i ++) {

        myslab.name[i] = *(s->name + i);   
    }
    
    myslab.size = s->size;

    myslab.ob_slab =  x & OO_MASK;
    myslab.cache_order = (1 << (x >> OO_SHIFT));
    
    unsigned long time = bpf_ktime_get_ns();

    myslab_table.update(&time, &myslab);
    


    bpf_trace_printk("name.size = %d ", sizeof(*(s->name)));
    bpf_trace_printk("name = %s ", s->name);
    bpf_trace_printk("size = %u ", s->size);

    bpf_trace_printk("objects_per_slab = %u ", x & OO_MASK);
    bpf_trace_printk("cache_order = %d", (1 << (x >> OO_SHIFT)));
    
    
    return 0;
}


"""

b = BPF(text = bpf_text)

b.attach_kprobe(event="get_slabinfo", fn_name="cul_meminfo")
myslab = b.get_table("myslab_table")

name = ''
size = 0
ob_slab = 0
cache_order = 0

#b.trace_print()
while(1):
    
    conn = pymysql.connect(host='127.0.0.1', user = 'root', password = 'll', database = 'memory')
    cursor = conn.cursor(cursor=pymysql.cursors.DictCursor)

    for k, v in myslab.items():
        # size 对象的大小, 每一个对象占用了多少slab, slab占用的页数 
        print("%-17s\t %u\t %u\t %d"%(v.name, v.size, v.ob_slab, v.cache_order))
        
        name = v.name
        size = v.size
        ob_slab = v.ob_slab
        cache_order = v.cache_order

        sql = 'insert into slab (name, size, ob_slab, cache_order, time) values(%(name)s, %(size)s, %(ob_slab)s, %(cache_order)s, now())'

        cursor.execute(sql, {'name' : name, 'size' : size, 'ob_slab' : ob_slab, 'cache_order' : cache_order})



    cursor.close()
    conn.commit()
    conn.close()
    
    sleep(3)
