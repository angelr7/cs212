#ifndef VM_PAGE_H
#define VM_PAGE_H
#include <hash.h>
#include "filesys/off_t.h"
#include "threads/thread.h"

/* These are the different states a file in our page table can be in */
#define IN_DISK 0
#define IN_SWAP 1
#define ALL_ZEROES 2
#define IN_MEM 3

// struct hash supplemental_table;

struct page {
    void *virtual_addr;
    void *physical_addr;
    struct hash_elem hash_elem;
    struct thread *process_reference;
    bool loaded;
    short memory_flag;    
    struct file *file;
    off_t file_ofs;
    size_t page_read_bytes;
    size_t page_zero_bytes;
    bool writable;
};

void init_supplemental_table(struct hash*);
unsigned page_hash(const struct hash_elem *p_, void *aux UNUSED);
bool page_less(const struct hash_elem *a_, const struct hash_elem *b_,
               void *aux UNUSED);

bool load_page(void *fault_addr);

#endif  /* vm/page.h */