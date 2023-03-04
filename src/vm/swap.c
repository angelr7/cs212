#include "vm/swap.h"
#include "threads/vaddr.h"
#include "lib/kernel/bitmap.h"
#include "devices/block.h"
#include "threads/synch.h"
#include <stdlib.h>

static struct bitmap *used_map;
static struct block *swap_block;
static int num_slots;
static size_t sectors_per_page;
static struct lock swap_lock;

/* Initialize our swap block */
void swap_init(void)
{
    swap_block = malloc(sizeof(struct block *));
    swap_block = block_get_role(BLOCK_SWAP);
    sectors_per_page = PGSIZE / BLOCK_SECTOR_SIZE;
    num_slots = block_size(swap_block) / sectors_per_page;
    used_map = bitmap_create(num_slots - 1);
    lock_init(&swap_lock);
}

/* Add data in memory at phys_addr to swap. If swap is full panic*/
int swap_add(void *phys_addr)
{
    lock_acquire(&swap_lock);
    size_t idx = bitmap_scan_and_flip(used_map, 0, 1, false);
    if (idx == BITMAP_ERROR)
    {
        lock_release(&swap_lock);
        PANIC ("swap_add: swap block full");
    }
    size_t sector_idx = idx * sectors_per_page;
    for (size_t i = 0; i < sectors_per_page; i++)
        block_write(swap_block, sector_idx + i, phys_addr + (i * BLOCK_SECTOR_SIZE));
    lock_release(&swap_lock);
    return idx;
}

/* Remove data from swap and put into memory at location phys_addr*/
void swap_remove(void *phys_addr, int swap_slot)
{;
    ASSERT(swap_slot >= 0 && swap_slot < num_slots);
    ASSERT(bitmap_test(used_map, swap_slot));
    lock_acquire(&swap_lock);
    size_t sector_idx = swap_slot * sectors_per_page;
    for (size_t i = 0; i < sectors_per_page; i++)
        block_read(swap_block, sector_idx + i, phys_addr + (i * BLOCK_SECTOR_SIZE));
    bitmap_flip(used_map, swap_slot);
    lock_release(&swap_lock);
}
