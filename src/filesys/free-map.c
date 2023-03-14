#include "filesys/free-map.h"
#include <bitmap.h>
#include <debug.h>
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "filesys/inode.h"
#include "filesys/cache.h"

static struct file *free_map_file;   /* Free map file. */
static struct bitmap *free_map;      /* Free map, one bit per sector. */

/* Initializes the free map. */
void
free_map_init (void) 
{
  free_map = bitmap_create (block_size (fs_device));
  if (free_map == NULL)
    PANIC ("bitmap creation failed--file system device is too large");
  bitmap_mark (free_map, FREE_MAP_SECTOR);
  bitmap_mark (free_map, ROOT_DIR_SECTOR);
}

/* Allocates CNT  sectors from the free map and stores
   the first into *SECTORP.
   Returns true if successful, false if not enough 
   sectors were available or if the free_map file could not be
   written. */
bool
free_map_allocate (size_t cnt, block_sector_t *sectors)
{
  bool indirect_initialized = false;
  bool doubly_indirect_initialized = false;

  bool initialized[128];
  block_sector_t indirect_sectors[128];

  block_sector_t sector = BITMAP_ERROR;

  for (size_t i = 0; i < cnt; i++)
  {
    sector = bitmap_scan_and_flip (free_map, 0, 1, false);
    if (sector != BITMAP_ERROR
        && free_map_file != NULL
        && !bitmap_write (free_map, free_map_file))
      {
        bitmap_set_multiple (free_map, sector, 1, false); 
        sector = BITMAP_ERROR;
      }
    if (sector != BITMAP_ERROR)
    {
      if (i < 12)
        sectors[i] = sector;
      else if (i < 128 + 12)
      {
        if (!indirect_initialized)
        {
        block_sector_t indirect_sector = bitmap_scan_and_flip(free_map, 0, 1, false);
        // TODO: handle bitmap error
        static char zeros[BLOCK_SECTOR_SIZE];
        buffer_cache_write(fs_device, indirect_sector, zeros, 0, BLOCK_SECTOR_SIZE);
        sectors[12] = indirect_sector;
        indirect_initialized = true;
        }
        // block_sector_t sector_num_buf[1] = {sector};
        buffer_cache_write(fs_device, sectors[12], &sector, 
                          sizeof(block_sector_t) * (sector - 12), 
                          sizeof(block_sector_t));
      }
      else
      {
        if (!doubly_indirect_initialized)
        {
          block_sector_t doubly_indirect_sector = bitmap_scan_and_flip(free_map, 0, 1, false);
          // TODO: handle bitmap error
          static char zeros[BLOCK_SECTOR_SIZE];
          buffer_cache_write(fs_device, doubly_indirect_sector, zeros, 0, BLOCK_SECTOR_SIZE);
          sectors[13] = doubly_indirect_sector;
          doubly_indirect_initialized = true;
          
        }

        block_sector_t indirect_sector_idx = (sector - 140) / 512;
        if (!initialized[indirect_sector_idx])
        {
          block_sector_t indirect_sector = bitmap_scan_and_flip(free_map, 0, 1, false);
          // TODO: handle bitmap error
          static char zeros[BLOCK_SECTOR_SIZE];
          buffer_cache_write(fs_device, indirect_sector, zeros, 0, BLOCK_SECTOR_SIZE);
          buffer_cache_write(fs_device, sectors[13], &indirect_sector, 
                            sizeof(block_sector_t) * indirect_sector_idx, 
                            sizeof(block_sector_t));
          initialized[indirect_sector_idx] = true;
          indirect_sectors[indirect_sector_idx] = indirect_sector;
        }

        block_sector_t indirect_sector = indirect_sectors[indirect_sector_idx];
        // buffer_cache_read(fs_device, sectors[13], &actual_indirect, sizeof(block_sector_t) * indirect_sector, sizeof(block_sector_t));
        block_sector_t direct_sector_idx = sector - (140 + 128 * indirect_sector_idx);
        buffer_cache_write(fs_device, indirect_sector, &sector, 
                          sizeof(block_sector_t) * direct_sector_idx, 
                          sizeof(block_sector_t));
      }
    }
  }


  // block_sector_t sector = bitmap_scan_and_flip (free_map, 0, cnt, false);
  // if (sector != BITMAP_ERROR
  //     && free_map_file != NULL
  //     && !bitmap_write (free_map, free_map_file))
  //   {
  //     bitmap_set_multiple (free_map, sector, cnt, false); 
  //     sector = BITMAP_ERROR;
  //   }
  // if (sector != BITMAP_ERROR)
  //   *sectorp = sector;
  return sector != BITMAP_ERROR;
}

/* Makes CNT sectors starting at SECTOR available for use. */
void
free_map_release (block_sector_t sector, size_t cnt)
{
  ASSERT (bitmap_all (free_map, sector, cnt));
  bitmap_set_multiple (free_map, sector, cnt, false);
  bitmap_write (free_map, free_map_file);
}

/* Opens the free map file and reads it from disk. */
void
free_map_open (void) 
{
  free_map_file = file_open (inode_open (FREE_MAP_SECTOR));
  if (free_map_file == NULL)
    PANIC ("can't open free map");
  if (!bitmap_read (free_map, free_map_file))
    PANIC ("can't read free map");
}

/* Writes the free map to disk and closes the free map file. */
void
free_map_close (void) 
{
  file_close (free_map_file);
}

/* Creates a new free map file on disk and writes the free map to
   it. */
void
free_map_create (void) 
{
  /* Create inode. */
  if (!inode_create (FREE_MAP_SECTOR, bitmap_file_size (free_map)))
    PANIC ("free map creation failed");

  /* Write bitmap to file. */
  free_map_file = file_open (inode_open (FREE_MAP_SECTOR));
  if (free_map_file == NULL)
    PANIC ("can't open free map");
  if (!bitmap_write (free_map, free_map_file))
    PANIC ("can't write free map");
}
