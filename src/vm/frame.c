#include "vm/frame.h"
#include "vm/page.h"
#include "vm/swap.h"
#include "filesys/file.h"
#include "lib/kernel/bitmap.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "userprog/pagedir.h"
#include <stdlib.h>
#include <stdio.h>

static struct frame_entry **frame_table;
static size_t frame_table_size;
static struct bitmap *used_map;
static struct lock bitmap_lock;
static int cur_evict;

struct frame_entry
{
    void* physical_address;
    void *virtual_address;
    struct thread* process_thread;
    // struct lock *lock;
};

void frame_table_init(void)
{
    frame_table = malloc(sizeof(struct frame_entry *) * frame_table_size);
    used_map = bitmap_create(frame_table_size);
    lock_init(&bitmap_lock);
    cur_evict = 0;
    void *kernel_addr;
    int i = 0;
    while ((kernel_addr = palloc_get_page(PAL_USER)) != NULL)
    {
        struct frame_entry *entry = malloc(sizeof(struct frame_entry));
        entry->physical_address = kernel_addr;
        entry->process_thread = NULL;
        // lock_init(entry->lock);
        frame_table[i++] = entry;
    }
}

void frame_table_set_size(size_t size)
{
    frame_table_size = size;
}

static size_t evict_algo(void)
{
    // TODO: run clock algo to get evicting frame index
    struct frame_entry *f = frame_table[cur_evict];
    struct page *p = page_fetch(f->process_thread, f->virtual_address);
    /* Evicting read-only page from executable */
    if (p->mapid == NO_MAPID && !p->writable)
    {
        p->memory_flag = IN_DISK;
    }
    /* Evicting writable pages from executable and stack to swap */
    if (p->mapid == NO_MAPID && p->writable)
    {
        p->swap_slot = swap_add(p->physical_addr);
        p->memory_flag = IN_SWAP;
    }
    /* Evicting mmapped file pages to file on disk */
    if (p->mapid != NO_MAPID)
    {
        file_write_at(p->file, p->physical_addr, p->page_read_bytes, p->file_ofs);
        p->memory_flag = IN_DISK;
    }
    p->physical_addr = NULL;
    pagedir_clear_page(f->process_thread->pagedir, p->virtual_addr);
    return cur_evict++;
}

// TODO: take in virtual adress to keep track in frame entry
void* get_frame(void *uaddr, enum palloc_flags flags)
{
    ASSERT(flags & PAL_USER);
    lock_acquire(&bitmap_lock);
    size_t idx = bitmap_scan_and_flip(used_map, 0, 1, false);
    lock_release(&bitmap_lock);
    if (idx == BITMAP_ERROR)
        idx = evict_algo();
    struct frame_entry *frame = frame_table[idx];
    frame->process_thread = thread_current();
    frame->virtual_address = uaddr;
    return frame->physical_address;


    // Swapping
    // Choose a frame to evict, using your page replacement algorithm. The "accessed" and "dirty" bits in the page table, described below, will come in handy.
    // Remove references to the frame from any page table that refers to it.
    // Unless you have implemented sharing, only a single page should refer to a frame at any given time.
    // If necessary, write the page to the file system or to swap.

}

void free_frame(void* kpage)
{
    for (size_t i = 0; i < frame_table_size; i++)
    {
        // printf("i: %d, frametablesize: %d\n", i, frame_table_size);
        if (frame_table[i]->physical_address == kpage)
        {
            ASSERT(bitmap_all (used_map, i, 1));
            bitmap_set(used_map, i, false);
            frame_table[i]->process_thread = NULL;
            break;
        }
    }
}
