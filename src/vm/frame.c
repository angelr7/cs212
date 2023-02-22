#include "vm/frame.h"
#include "lib/kernel/bitmap.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "userprog/pagedir.h"
#include <stdlib.h>
#include <stdio.h>

static struct frame_entry **frame_table;
static size_t frame_table_size;
static struct bitmap *used_map;

struct frame_entry
{
    void* physical_address;
    struct thread* process_thread;
};

void frame_table_init(void)
{
    frame_table = malloc(sizeof(struct frame_entry *) * frame_table_size);
    used_map = bitmap_create(frame_table_size);
    void *kernel_addr;
    int i = 0;
    while ((kernel_addr = palloc_get_page(PAL_USER)) != NULL)
    {
        printf("%d\n", i);
        struct frame_entry *entry = malloc(sizeof(struct frame_entry));
        entry->physical_address = kernel_addr;
        entry->process_thread = NULL;
        frame_table[i++] = entry;
    }
    printf("frames allocated\n");
}

void frame_table_set_size(size_t size)
{
    frame_table_size = size;
}

void* get_frame(enum palloc_flags flags)
{
    ASSERT(flags & PAL_USER);
    size_t idx = bitmap_scan_and_flip(used_map, 0, 1, false);
    if (idx == BITMAP_ERROR)
        PANIC ("get_frame: out of pages");
    struct frame_entry *free_entry = frame_table[idx];
    free_entry->process_thread = thread_current();
    return free_entry->physical_address;


    // Swapping
    // Choose a frame to evict, using your page replacement algorithm. The "accessed" and "dirty" bits in the page table, described below, will come in handy.
    // Remove references to the frame from any page table that refers to it.
    // Unless you have implemented sharing, only a single page should refer to a frame at any given time.

    // If necessary, write the page to the file system or to swap.

}

void free_frame(void* page)
{
    for (size_t i = 0; i < frame_table_size; i++)
    {
        printf("i: %d, frametablesize: %d\n", i, frame_table_size);
        if (frame_table[i]->physical_address == page)
        {
            ASSERT(bitmap_all (used_map, i, 1));
            bitmap_set(used_map, i, false);
            frame_table[i]->process_thread = NULL;
            break;
        }
    }
}
