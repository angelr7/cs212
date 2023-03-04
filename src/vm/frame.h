#ifndef VM_FRAME_H
#define VM_FRAME_H
#include "threads/palloc.h"
#include "threads/synch.h"

struct frame_entry
{
    void *physical_address;
    void *virtual_address;
    struct thread *process_thread;
    struct lock lock;
    bool pinned;
};

void frame_table_init(void);
void frame_table_set_size(size_t size);
struct frame_entry *get_frame(void *uaddr, enum palloc_flags flags);
void free_frame(void* kpage);

#endif  /* vm/frame.h */