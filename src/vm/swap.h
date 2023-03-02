#ifndef VM_SWAP_H
#define VM_SWAP_H

void swap_init(void);
int swap_add(void *phys_addr);
void swap_remove(void *phys_addr, int swap_slot);

#endif /* vm/swap.h*/