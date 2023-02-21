#include "vm/frame.h"

// struct list frame_table;

// struct frame_table_entry
// {
//     struct elem list_elem;
//     void* physical_address;
//     struct thread* process_thread;
// }

// void init_frame_table()
// {
// }


void* get_frame(enum palloc_flags flags)
{

    void* kern_address = palloc_get_page(flags);
    // if (kern_address == NULL)
        // panic kernel or fail allocator
    return kern_address;



    // Swapping
    // Choose a frame to evict, using your page replacement algorithm. The "accessed" and "dirty" bits in the page table, described below, will come in handy.
    // Remove references to the frame from any page table that refers to it.
    // Unless you have implemented sharing, only a single page should refer to a frame at any given time.

    // If necessary, write the page to the file system or to swap.

}

void free_frame(void* page)
{
    palloc_free_page(page);
}
