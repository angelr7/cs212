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

static struct frame_entry **frame_table;    /* Array of frame_entry which makes up our frame table */
static size_t frame_table_size;             /* Frame Table Size */
static struct bitmap *used_map;             /* Bitmap which keeps track of which spaces in the frame_table are available */
static struct lock bitmap_lock;             /* Bitmap Lock */
static int cur_evict;                       /* Index to keep track of last eviction location in frame table */

/*Initialize everything in our frame table. We malloc all frame_entries 
on initialization and reasign their values as get_frame() is called */
void frame_table_init(void)
{
    frame_table = malloc(sizeof(struct frame_entry *) * frame_table_size);
    used_map = bitmap_create(frame_table_size - 1);
    lock_init(&bitmap_lock);
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

/* Set size of the frame table*/
void frame_table_set_size(size_t size)
{
    frame_table_size = size;
}

/* Internal function to be used by get_frame. 
We utilize clock eviction, where we evict the first frame 
which has not been accessed, and update accessed bits along
the way. We then return the index in our frame table to 
the location we evicted  */
static size_t evict_algo(void)
{
    /* Clock Algo*/
    int evict_idx = cur_evict % (frame_table_size - 1);
    cur_evict++;
    struct frame_entry *f = frame_table[evict_idx];
    lock_acquire(&f->lock);
    bool accessed_page = pagedir_is_accessed(f->process_thread->pagedir, 
        f->virtual_address);
    /* if it is pinned  or accessed and it has virtual address or if frame has not been given data*/
    while(((accessed_page || f->pinned) && f->virtual_address != NULL) || f->physical_address == NULL)
    {
        if (f->physical_address != NULL && accessed_page)
            pagedir_set_accessed(f->process_thread->pagedir, 
                f->virtual_address, false);
        lock_release(&f->lock);
        evict_idx = cur_evict % (frame_table_size - 1);
        cur_evict++;
        f = frame_table[evict_idx];
        lock_acquire(&f->lock);
        accessed_page = pagedir_is_accessed(f->process_thread->pagedir, 
            f->virtual_address);
    }
    lock_release(&f->lock);
    if (f->virtual_address == NULL)
    {
        bitmap_set(used_map,evict_idx,true);
        return evict_idx;
    }

    struct page *p = page_fetch(f->process_thread, f->virtual_address);
    lock_acquire(&p->page_lock);
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
    lock_release(&p->page_lock);
    return evict_idx;
}

/* Retrieves a frame_entry for the calling process using the specified
virtual address and flags. If a frame is available returns the first
available, otherwise evicts a frame and returns that one.*/
struct frame_entry *get_frame(void *uaddr, enum palloc_flags flags)
{
    ASSERT(flags & PAL_USER);
    lock_acquire(&bitmap_lock);
    size_t idx = bitmap_scan_and_flip(used_map, 0, 1, false);
    if (idx == BITMAP_ERROR)
        idx = evict_algo();
    lock_release(&bitmap_lock);
    struct frame_entry *frame = frame_table[idx];
    lock_acquire(&frame->lock);
    frame->process_thread = thread_current();
    frame->virtual_address = uaddr;
    /* So that it is not immediatly evicted*/
    pagedir_set_accessed(frame->process_thread->pagedir, 
                frame->virtual_address, true);    
    lock_release(&frame->lock);
    return frame;
}

/* Removes all data/memory in the frame at a given physical address */
void free_frame(void* kpage)
{
    for (size_t i = 0; i < frame_table_size; i++)
    {
        struct frame_entry *cur_frame = frame_table[i];
        lock_acquire(&cur_frame->lock);
        if (cur_frame->physical_address == kpage && 
            cur_frame->process_thread == thread_current())
        {
            ASSERT(bitmap_all (used_map, i, 1));
            lock_acquire(&bitmap_lock);
            bitmap_set(used_map, i, false);
            lock_release(&bitmap_lock);
            cur_frame->process_thread = NULL;
            cur_frame->virtual_address = NULL;
            cur_frame->pinned = false;
            lock_release(&cur_frame->lock);
            break;
        }
        lock_release(&cur_frame->lock);
    }
}
