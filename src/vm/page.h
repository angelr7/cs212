#ifndef VM_PAGE_H
#define VM_PAGE_H
#include <hash.h>
#include "filesys/off_t.h"
#include "threads/thread.h"

/* These are the different states/locations a file in our page table can be in */
#define IN_DISK 0
#define IN_SWAP 1
#define ALL_ZEROES 2
#define IN_MEM 3

/* This represents that the entry was not created by a call to mmap */
#define NO_MAPID -1

typedef int mapid_t;

/* This is our supplemental page struct, it keeps
track of all information needed to retrieve a page
of information in swap or file and write it to memory. */
struct page {
    /* In Memory */
    struct frame_entry *frame;      /* the frame which goes to this page*/
    void *physical_addr;            /* physical address of this page*/

    /* In Disk */
    struct file *file;              /* file struct if page is in a file */
    off_t file_ofs;                 /* file offset if page is in a file */
    size_t page_read_bytes;         /* page read bytes if page is in a file */
    size_t page_zero_bytes;         /* page zero bytes if page is in a file */

    /* Mapped */
    mapid_t mapid;                  /* mapid if mapped  */

    /* In Swap*/
    int swap_slot;                  /* Slot in swap table if in swap*/

    /* Everything */
    void *virtual_addr;             /* pages virtual address*/
    struct hash_elem hash_elem;     /* pages hash elem*/
    struct thread *process_reference;   /* pointer to process which created the page*/
    short memory_flag;              /* memory flag to know where this page is*/
    bool writable;                  /* boolean for if page is writeable */
};

void init_supplemental_table(struct hash*);
unsigned page_hash(const struct hash_elem *p_, void *aux UNUSED);
bool page_less(const struct hash_elem *a_, const struct hash_elem *b_,
               void *aux UNUSED);

bool load_page(void *fault_addr);
void page_create_zero_entry(void *uaddr, struct frame_entry *frame, bool writable, bool loaded);
void page_create_file_entry(void *uaddr, struct frame_entry *frame, struct file *file, off_t file_ofs,
                             size_t read_bytes, size_t zero_bytes, 
                             bool writable, mapid_t mapid);
struct page *page_fetch(struct thread *t, void *uaddr);
void page_free(struct page *page_entry, bool delete_entry);
void unpin_page(struct frame_entry *frame);

void free_thread_pages(void);

#endif  /* vm/page.h */