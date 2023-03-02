#include <hash.h>
#include <string.h>
#include <stdlib.h>
#include "frame.h"
#include "vm/page.h"
#include "swap.h"
#include "filesys/file.h"
#include "threads/vaddr.h"
#include "threads/palloc.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"

void page_create_zero_entry(void *uaddr, void *kpage, bool writable, bool loaded);
void page_create_file_entry(void *uaddr, void *kpage, struct file *file, off_t file_ofs,
                            size_t read_bytes, size_t zero_bytes, bool writable, mapid_t mapid);
struct page *page_fetch(struct thread *t, void *uaddr);

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
    struct page *p = page_fetch(thread_current(), fault_addr);
    void *upage = pg_round_down(fault_addr);
    
    if (p == NULL)
    {
        if (fault_addr <= thread_current()->esp && fault_addr >= thread_current()->esp - 32)
        {
            uint8_t *kpage = get_frame(upage, PAL_USER);
            if (kpage == NULL)
                return false;
            memset(kpage, 0, PGSIZE);

            if (!install_page(upage, kpage, true))
            {
                free_frame(kpage);
                return false;
            }

            page_create_zero_entry(upage, kpage, true, true);
            return true;
        }
        return false;
    }

    void *kpage = get_frame(upage, PAL_USER);
    if (kpage == NULL)
        return false;
    if (p->memory_flag == IN_DISK)
    {
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
    // else if (p->memory_flag == ALL_ZEROES)
    // {
    //     uint8_t *kpage = get_frame(upage, PAL_USER);
    //     if (kpage == NULL)
    //         return false;
    //     memset(kpage, 0, p->page_zero_bytes);
    //     if (!install_page(upage, kpage, p->writable))
    //     {
    //         free_frame(kpage);
    //         return false;
    //     }
    //     p->physical_addr = kpage;
    //     p->loaded = true;
    // }
    else if (p->memory_flag == IN_SWAP)
    {
        swap_remove(kpage, p->swap_slot);
        p->swap_slot = -1;
    }
    p->physical_addr = kpage;
    return true;
}

void page_create_zero_entry(void *uaddr, void *kpage, bool writable, bool loaded)
{
    struct page *page = malloc(sizeof(struct page));
    page->virtual_addr = uaddr;
    page->physical_addr = kpage;
    page->process_reference = thread_current();
    page->loaded = loaded;
    page->memory_flag = ALL_ZEROES;
    page->file = NULL;
    page->page_read_bytes = 0;
    page->page_zero_bytes = PGSIZE;
    page->writable = writable;
    page->mapid = NO_MAPID;
    hash_insert(&thread_current()->spt, &page->hash_elem);
}

void page_create_file_entry(void *uaddr, void *kpage, struct file *file, off_t file_ofs,
                            size_t read_bytes, size_t zero_bytes,
                            bool writable, mapid_t mapid)
{
    struct page *page = malloc(sizeof(struct page));
    page->virtual_addr = uaddr;
    page->physical_addr = kpage;
    page->process_reference = thread_current();
    page->memory_flag = IN_DISK;
    page->file = file;
    page->file_ofs = file_ofs;
    page->page_read_bytes = read_bytes;
    page->page_zero_bytes = zero_bytes;
    page->writable = writable;
    page->mapid = mapid;
    hash_insert(&thread_current()->spt, &page->hash_elem);
}

struct page *page_fetch(struct thread *t, void *uaddr)
{
    void *upage = pg_round_down(uaddr);
    struct page find_page;
    find_page.virtual_addr = upage;

    struct hash_elem *found_elem = hash_find(&t->spt, &find_page.hash_elem);
    if (found_elem == NULL)
        return NULL;
    return hash_entry(found_elem, struct page, hash_elem);
}

void page_free(struct page *page_entry, bool delete_entry)
{
    if (page_entry->physical_addr != NULL)
    {
        if (page_entry->mapid != NO_MAPID && pagedir_is_dirty(thread_current()->pagedir, page_entry->virtual_addr))
            file_write_at(page_entry->file, page_entry->virtual_addr, page_entry->page_read_bytes, page_entry->file_ofs);
        pagedir_clear_page(thread_current()->pagedir, page_entry->virtual_addr);
        free_frame(page_entry->physical_addr);
    }
    if (delete_entry)
        hash_delete(&thread_current()->spt, &page_entry->hash_elem);
    free(page_entry);
}

static void free_page_destructor(struct hash_elem *e, void *AUX UNUSED)
{
    page_free(hash_entry(e, struct page, hash_elem), false);
}

void free_thread_pages()
{
    struct thread *t = thread_current();
    hash_destroy(&t->spt, free_page_destructor);
}

// supplemental page table elems -- done
// key physical address/kernel virtual address -- done
// pointer to swap or file on disk -- done
// on swap -- done
// zero page? -- done
// on disk -- done
// process_id or whatever thread it is -- done