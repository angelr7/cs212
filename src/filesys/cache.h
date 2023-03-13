#ifndef FILESYS_CACHE_H
#define FILESYS_CACHE_H

#include <stdbool.h>
#include <stddef.h>
#include "devices/block.h"

void buffer_cache_init(void);
void buffer_cache_read(struct block *, block_sector_t, void *, int sector_ofs, int size);
void buffer_cache_write(struct block *, block_sector_t, void *, int sector_ofs, int size);
void buffer_cache_flush(void);

#endif /* filesys/cache.h */