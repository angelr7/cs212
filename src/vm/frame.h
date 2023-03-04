#ifndef VM_FRAME_H
#define VM_FRAME_H
#include "threads/palloc.h"
#include "threads/synch.h"

/* Frame entry structed used to fill the frame table 
contains frames physical address, virtual address,
process_thread, lock, and pinned boolean. */
struct frame_entry
{
    void *physical_address;         /* Physical address associated with this frame */
    void *virtual_address;          /* Virtual address associated with this frame */
    struct thread *process_thread;  /* Pointer to a process thread which owns this frame at this time */
    struct lock lock;               /* Lock */
    bool pinned;                    /* Bool to see if this frame is pinned */
};

void frame_table_init(void); 
void frame_table_set_size(size_t size);
struct frame_entry *get_frame(void *uaddr, enum palloc_flags flags);
void free_frame(void* kpage);

#endif  /* vm/frame.h */