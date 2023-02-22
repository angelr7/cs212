#ifndef VM_PAGE_H
#define VM_PAGE_H
#include <hash.h>
#include "threads/thread.h"

/* These are the different states a file in our page table can be in */
#define IN_DISK 0
#define IN_SWAP 1
#define ALL_ZEROES 2

// struct hash supplemental_table;

struct page {
    void *virtual_addr;
    void *physical_addr;
    struct hash_elem hash_elem;
    struct thread *process_refrence;
    bool loaded;
    short memory_flag;    
}

#endif  /* vm/page.h */