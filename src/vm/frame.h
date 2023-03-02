#ifndef VM_FRAME_H
#define VM_FRAME_H
#include "threads/palloc.h"

void frame_table_init(void);
void frame_table_set_size(size_t size);
void *get_frame(void *uaddr, enum palloc_flags flags);
void free_frame(void* kpage);

#endif  /* vm/frame.h */