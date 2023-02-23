#include "frame.h"
#include <hash.h>
#include <string.h>
#include "filesys/file.h"
#include "threads/palloc.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "vm/page.h"

/* Returns a hash value for page p. */
unsigned
page_hash(const struct hash_elem *p_, void *aux UNUSED)
{
    const struct page *p = hash_entry(p_, struct page, hash_elem);
    return hash_bytes(&p->virtual_addr, sizeof p->virtual_addr);
}

/* Returns true if page a precedes page b. */
bool page_less(const struct hash_elem *a_, const struct hash_elem *b_,
               void *aux UNUSED)
{
    const struct page *a = hash_entry(a_, struct page, hash_elem);
    const struct page *b = hash_entry(b_, struct page, hash_elem);
    return a->virtual_addr < b->virtual_addr;
}

void init_supplemental_table(struct hash *supplemental_table)
{
    hash_init(supplemental_table, page_hash, page_less, NULL);
}

bool load_page(void *fault_addr)
{
    void *upage = pg_round_down(fault_addr);
    struct page find_page;
    find_page.virtual_addr = upage;

    struct hash_elem *found_elem = hash_find(&thread_current()->spt, &find_page.hash_elem);
    if (found_elem == NULL)
    {
        if (fault_addr >= thread_current()->esp - 32)
        {
            uint8_t *kpage = get_frame(PAL_USER);
            if (kpage == NULL)
                return false;
            memset(kpage, 0, PGSIZE);
            if (!install_page(upage, kpage, true))
            {
                free_frame(kpage);
                return false;
            }
            return true;
            // struct page *page = malloc(sizeof (struct page));
            // page->virtual_addr = (void *)upage;
            // page->process_reference = thread_current();
            // page->loaded = !read_first_page;
            // page->memory_flag = IN_DISK;
            // page->file = file;
            // page->file_ofs = ofs;
            // page->page_read_bytes = page_read_bytes;
            // page->page_zero_bytes = page_zero_bytes;
            // page->writable = writable;
        }
        return false;
    }
    
    struct page *p = hash_entry(found_elem, struct page, hash_elem);
    if (p->memory_flag == IN_DISK)
    {
        uint8_t *kpage = get_frame(PAL_USER);
        if (kpage == NULL)
            return false;
        
        if (file_read_at(p->file, kpage, p->page_read_bytes, p->file_ofs) != (int)p->page_read_bytes)
        {
            free_frame(kpage);
            return false;
        }
        memset(kpage + p->page_read_bytes, 0, p->page_zero_bytes);

        if (!install_page(upage, kpage, p->writable))
        {
            free_frame(kpage);
            return false;
        }
    }
    return true;
}

// supplemental page table elems -- done
// key physical address/kernel virtual address -- done
// pointer to swap or file on disk -- done
// on swap -- done
// zero page? -- done
// on disk -- done
// process_id or whatever thread it is -- done