#ifndef FILESYS_CACHE_H
#define FILESYS_CACHE_H

#include <stdbool.h>
#include <stddef.h>
#include <list.h>
#include "devices/block.h"
#include "threads/synch.h"

struct cache_entry
{
  block_sector_t sector_idx;
  bool accessed;
  bool dirty;
  int num_active;
  unsigned char data[BLOCK_SECTOR_SIZE];
  struct lock lock;
};

struct read_ahead_struct 
{
  block_sector_t sector_id; 
  struct list_elem elem;
};


struct list read_ahead_ids;
struct condition read_ahead;
struct lock read_ahead_lock;

void buffer_cache_init(void);
void *buffer_cache_read(struct block *, block_sector_t, void *, int sector_ofs, int size);
void buffer_cache_write(struct block *, block_sector_t, void *, int sector_ofs, int size);
void buffer_cache_flush(void);

#endif /* filesys/cache.h */