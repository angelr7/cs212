#include "vm/frame.h"
#include "vm/page.h"
#include "vm/swap.h"
#include "filesys/file.h"
#include "lib/kernel/bitmap.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "userprog/pagedir.h"
#include "userprog/syscall.h"
#include <stdlib.h>
#include <stdio.h>

static struct frame_entry **frame_table;
static size_t frame_table_size;
static struct bitmap *used_map;
static struct lock bitmap_lock;
static struct lock evict_algo_lock;
static int cur_evict;

void frame_table_init(void)
{
    frame_table = malloc(sizeof(struct frame_entry *) * frame_table_size);
    used_map = bitmap_create(frame_table_size - 1);
    lock_init(&bitmap_lock);
    lock_init(&evict_algo_lock);
    cur_evict = 0;
    void *kernel_addr;
    int i = 0;
    while ((kernel_addr = palloc_get_page(PAL_USER)) != NULL)
    {
        struct frame_entry *entry = malloc(sizeof(struct frame_entry));
        entry->physical_address = kernel_addr;
        entry->process_thread = NULL;
        lock_init(&entry->lock);
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
    // if we find a free frame, return that frame
    int evict_idx = cur_evict % (frame_table_size - 1);
    cur_evict++;
    struct frame_entry *f = frame_table[evict_idx];
    if (f->pinned) {
        evict_idx = cur_evict % (frame_table_size - 1);
        cur_evict++;
        f = frame_table[evict_idx];
    }
    struct page *p = page_fetch(f->process_thread, f->virtual_address);
    pagedir_clear_page(f->process_thread->pagedir, p->virtual_addr);
    
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
        lock_acquire(&filesys_lock);
        file_write_at(p->file, p->physical_addr, p->page_read_bytes, p->file_ofs);
        lock_release(&filesys_lock);
        p->memory_flag = IN_DISK;
    }
    p->physical_addr = NULL;
    return evict_idx;
}

struct frame_entry *get_frame(void *uaddr, enum palloc_flags flags)
{
    ASSERT(flags & PAL_USER);
    lock_acquire(&bitmap_lock);
    size_t idx = bitmap_scan_and_flip(used_map, 0, 1, false);
    lock_release(&bitmap_lock);
    if (idx == BITMAP_ERROR)
    {
        lock_acquire(&evict_algo_lock);
        idx = evict_algo();
        lock_release(&evict_algo_lock);
    }
        
    struct frame_entry *frame = frame_table[idx];
    lock_acquire(&frame->lock);
    frame->process_thread = thread_current();
    frame->virtual_address = uaddr;
    lock_release(&frame->lock);
    return frame;
}

void free_frame(void* kpage)
{
    for (size_t i = 0; i < frame_table_size; i++)
    {
        lock_acquire(&frame_table[i]->lock);
        if (frame_table[i]->physical_address == kpage)
        {
            ASSERT(bitmap_all (used_map, i, 1));
            lock_acquire(&bitmap_lock);
            bitmap_set(used_map, i, false);
            lock_release(&bitmap_lock);
            frame_table[i]->process_thread = NULL;
            frame_table[i]->virtual_address = NULL;
            frame_table[i]->pinned = false;
            lock_release(&frame_table[i]->lock);
            break;
        }
        lock_release(&frame_table[i]->lock);
    }
}
