#include "filesys/cache.h"
#include "filesys/filesys.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "devices/timer.h"
#include "lib/kernel/bitmap.h"
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define BUFFER_CACHE_SIZE 64

// struct cache_entry
//   {
//     block_sector_t sector_idx;
//     bool accessed;
//     bool dirty;
//     int num_active;
//     unsigned char data[BLOCK_SECTOR_SIZE];
//     struct lock lock;
//   };

static struct cache_entry **buffer_cache;
static struct bitmap *used_map;
static struct lock searching_lock;
static int evict_idx;

static struct cache_entry *find_cache_entry(block_sector_t);
static int read_in_sector(struct block *, block_sector_t);
static bool write_out_sector(struct block *, block_sector_t, struct cache_entry *);
static void flush_thread_func(void *);

void
buffer_cache_init(void)
{
  buffer_cache = malloc(sizeof(struct cache_entry *) * BUFFER_CACHE_SIZE);
  used_map = bitmap_create(BUFFER_CACHE_SIZE);
  evict_idx = 0;
  lock_init(&searching_lock);
  for (int i = 0; i < BUFFER_CACHE_SIZE; i++)
  {
    buffer_cache[i] = malloc(sizeof(struct cache_entry));
    lock_init(&buffer_cache[i]->lock);
  }
  thread_create("flush thread", 32, flush_thread_func, NULL);
}

// static void
// read_ahead_thread_func(void *AUX)
// {
//   // TODO: figure out if next sector of file exists
//   int sector_idx = (int)AUX;
//   lock_acquire(&searching_lock);
//   struct cache_entry *entry = find_cache_entry(sector_idx);
//   if (entry == NULL)
//     read_in_sector(block, sector_idx);
//   else
//     lock_release(&searching_lock);
// }

void *
buffer_cache_read(struct block *block, block_sector_t sector_idx, void *buffer, int sector_ofs, int size)
{
  lock_acquire(&searching_lock);
  struct cache_entry *entry = find_cache_entry(sector_idx);
  if (entry == NULL)
  {
    int cache_idx = read_in_sector(block, sector_idx);
    entry = buffer_cache[cache_idx];
  }
  else
  {
    entry->num_active++;
    lock_release(&searching_lock);
  }

  lock_acquire(&entry->lock);
  lock_release(&entry->lock);

  if (buffer == NULL) {
    return entry;
  }

  // acquire lock to ensure that sector has been read in if wasn't in cache
  memcpy(buffer, entry->data + sector_ofs, size);
  lock_acquire(&entry->lock);
  entry->num_active--;
  lock_release(&entry->lock);
  return NULL;
  // thread_create read ahead
}

void
buffer_cache_write(struct block *block, block_sector_t sector_idx, void *buffer, int sector_ofs, int size)
{
  lock_acquire(&searching_lock);
  struct cache_entry *entry = find_cache_entry(sector_idx);
  if (entry == NULL)
  {
    int cache_idx = read_in_sector(block, sector_idx);
    entry = buffer_cache[cache_idx];
  } 
  else
  {
    entry->num_active++;
    lock_release(&searching_lock);
  }
  // acquire lock to ensure that sector has been read in if wasn't in cache
  lock_acquire(&entry->lock);
  entry->dirty = true;
  lock_release(&entry->lock);
  memcpy(entry->data + sector_ofs, buffer, size);
  lock_acquire(&entry->lock);
  entry->num_active--;
  lock_release(&entry->lock);
}

static struct cache_entry *
find_cache_entry(block_sector_t sector_idx)
{
  for (int i = 0; i < BUFFER_CACHE_SIZE; i++)
  {
    if (bitmap_test(used_map, i))
    {
      if (buffer_cache[i]->sector_idx == sector_idx)
        return buffer_cache[i];
    }
  }
  return NULL;
}

static int
cache_evict(struct block *block, block_sector_t sector_idx)
{
  struct cache_entry *entry = buffer_cache[evict_idx % BUFFER_CACHE_SIZE];
  lock_acquire(&entry->lock);
  while (entry->num_active > 0) // TODO: evict algo bool checks
  {
    lock_release(&entry->lock);
    entry = buffer_cache[++evict_idx % BUFFER_CACHE_SIZE];
    lock_acquire(&entry->lock);
  }
  block_sector_t old_sector_idx = entry->sector_idx;
  entry->sector_idx = sector_idx;
  entry->num_active++;
  lock_release(&searching_lock);
  write_out_sector(block, old_sector_idx, entry);
  return evict_idx++ % BUFFER_CACHE_SIZE;
}

static int
read_in_sector(struct block *block, block_sector_t sector_idx)
{
  unsigned int cache_idx = bitmap_scan_and_flip(used_map, 0, 1, false);
  bool evicted = false;
  if (cache_idx == BITMAP_ERROR)
  {
    cache_idx = cache_evict(block, sector_idx);
    evicted = true;
  }
  struct cache_entry *entry = buffer_cache[cache_idx];
  if (!evicted)
  {
    lock_acquire(&entry->lock);
    entry->sector_idx = sector_idx;
    entry->num_active++;
    lock_release(&searching_lock);
  }
  block_read(block, sector_idx, entry->data);
  lock_release(&entry->lock);
  return cache_idx;
}

static bool
write_out_sector(struct block *block, block_sector_t sector_idx, struct cache_entry *entry)
{
  if (!entry->dirty)
    return false;
  block_write(block, sector_idx, entry->data);
  entry->dirty = 0;
  return true;
}

void
buffer_cache_flush(void)
{
  for (int i = 0; i < BUFFER_CACHE_SIZE; i++)
    {
      lock_acquire(&searching_lock);
      if (bitmap_test(used_map, i))
      {
        struct cache_entry *entry = buffer_cache[i];
        lock_acquire(&entry->lock);
        // bitmap_flip(used_map, i);
        lock_release(&searching_lock);
        write_out_sector(fs_device, entry->sector_idx, entry);
        lock_release(&entry->lock);
      }
      else
        lock_release(&searching_lock);
    }
  
}

static void
flush_thread_func(void *AUX UNUSED) 
{
  while (true)
  {
    timer_sleep(TIMER_FREQ);
    buffer_cache_flush();
  }
}
