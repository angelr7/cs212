#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "filesys/cache.h"
#include "threads/malloc.h"

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44
#define POINTERS_IN_SECTOR 128

/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk
{
  block_sector_t start; /* First data sector. */
  off_t length;         /* File size in bytes. */
  block_sector_t pointers[14];
  unsigned magic;       /* Magic number. */
  uint32_t unused[111]; /* Not used. */
};

/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t
bytes_to_sectors(off_t size)
{
  return DIV_ROUND_UP(size, BLOCK_SECTOR_SIZE);
}

/* In-memory inode. */
struct inode
{
  struct list_elem elem;  /* Element in inode list. */
  block_sector_t sector;  /* Sector number of disk location. */
  int open_cnt;           /* Number of openers. */
  bool removed;           /* True if deleted, false otherwise. */
  int deny_write_cnt;     /* 0: writes ok, >0: deny writes. */
  // struct inode_disk data; /* Inode content. */
};

static block_sector_t pos_to_sector_idx(off_t pos)
{
  return (block_sector_t)pos / BLOCK_SECTOR_SIZE;
}

static block_sector_t
sector_idx_to_num(block_sector_t *pointers, block_sector_t sector_idx)
{
  // mapid list of current thread corrupts after next line executes for file lg-create test
  block_sector_t sector_num = 0;
  if (sector_idx < 12)
    return pointers[sector_idx];
  else if (sector_idx < 12 + 128)
  {
    block_sector_t indirect_idx = sector_idx - 12;
    buffer_cache_read(fs_device, pointers[12], &sector_num, sizeof(block_sector_t) * indirect_idx, sizeof(block_sector_t));
  }
  else
  {
    block_sector_t doubly_indirect[128];
    buffer_cache_read(fs_device, pointers[13], doubly_indirect, 0, BLOCK_SECTOR_SIZE);
    block_sector_t indirect_idx = (sector_idx - 140) / BLOCK_SECTOR_SIZE;
    block_sector_t indirect_sector_num = doubly_indirect[indirect_idx];
    block_sector_t direct_idx = sector_idx - (140 + 128 * indirect_idx);
    buffer_cache_read(fs_device, indirect_sector_num, &sector_num, sizeof(block_sector_t) * direct_idx, sizeof(block_sector_t));
  }
  return sector_num;
}

/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static block_sector_t
byte_to_sector(const struct inode *inode, off_t pos)
{
  ASSERT(inode != NULL);
  // if (pos < inode->data.length)
  //   return inode->data.start + pos / BLOCK_SECTOR_SIZE;
  // else
  //   return -1;
  struct inode_disk inode_disk;
  buffer_cache_read(fs_device, inode->sector, &inode_disk, 0, BLOCK_SECTOR_SIZE);
  if (pos >= inode_disk.length)
    return -1;
  return (sector_idx_to_num(&inode_disk.pointers, pos_to_sector_idx(pos)));
}

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;

/* Initializes the inode module. */
void inode_init(void)
{
  list_init(&open_inodes);
}

static void cleanup_errors(int failure_idx, block_sector_t *pointers, block_sector_t *indirect_ptrs)
{
  if (failure_idx < 0)
    return;

  int num_data_blocks = failure_idx < 12 ? failure_idx : 12;
  for (int i = 0; i < num_data_blocks; i++)
    free_map_release(pointers[i], 1);

  if (failure_idx <= 12) return;

  failure_idx -= 12;
  int num_indirect_pointers = failure_idx < POINTERS_IN_SECTOR? failure_idx : POINTERS_IN_SECTOR;
  block_sector_t direct_pointers[POINTERS_IN_SECTOR];
  buffer_cache_read(fs_device, pointers[12], direct_pointers, 0, BLOCK_SECTOR_SIZE);

  for (int i = 0; i < num_indirect_pointers; i++) 
    free_map_release(direct_pointers[i], 1);

  if (failure_idx <= 128) return;

  failure_idx -= 128;
  int num_indirect_blocks = (failure_idx / 128) + 1;
  for (int i  = 0; i < num_indirect_blocks; i++) {
    block_sector_t indirect_block = indirect_ptrs[i];
    block_sector_t double_indirect_ptrs[POINTERS_IN_SECTOR];
    buffer_cache_read(fs_device, indirect_block, double_indirect_ptrs, 0, BLOCK_SECTOR_SIZE);
    
    for (int j  = 0; j < ((failure_idx < 128) ? failure_idx : 128); j++) 
      free_map_release(double_indirect_ptrs[j], 1);
    
    free_map_release(indirect_ptrs[i], 1);
    failure_idx -= 128;
  }

  free_map_release(pointers[13], 1);
}

// TODO: instead of writing each sector to the cache one-by-one, we can simply
// place all of our allocated sectors into one array and write them all to the
// cache when we're done using one call. this saves IO time that gets used when
// constantly writing.
static bool allocate_sectors(size_t starting_block, size_t cnt, block_sector_t *pointers)
{
  int failure_idx = -1;
  bool indirect_allocated = false;
  bool doubly_indirect_allocated = false;
  block_sector_t indirect_ptrs[128];
  static char zeros[BLOCK_SECTOR_SIZE];

  if (starting_block > 12)
  {
    indirect_allocated = true;
  }
  if (starting_block > 140)
  {
    doubly_indirect_allocated = true;
    buffer_cache_read(fs_device, pointers[13], indirect_ptrs, 0, BLOCK_SECTOR_SIZE);
  }


  for (size_t i = starting_block; i < starting_block + cnt; i++)
  {
    block_sector_t sector;
    if (!free_map_allocate(1, &sector))
    {
      free_map_release(sector, 1);
      failure_idx = i;
      break;
    }

    if (i < 12)
    {
      pointers[i] = sector;
    }

    else if (i < 12 + POINTERS_IN_SECTOR)
    {
      if (!indirect_allocated)
      {
        if (!free_map_allocate(1, &pointers[12]))
        {
          failure_idx = i;
          free_map_release(sector, 1);
          break;
        }
        buffer_cache_write(fs_device, pointers[12], zeros, 0, BLOCK_SECTOR_SIZE);
        indirect_allocated = true;
      }

      buffer_cache_write(fs_device, pointers[12], &sector,
                         sizeof(block_sector_t) * (i - 12),
                         sizeof(block_sector_t));
    }
    else
    {
      if (!doubly_indirect_allocated)
      {
        if (!free_map_allocate(1, &pointers[13]))
        {
          failure_idx = i;
          free_map_release(sector, 1);
          break;
        }
        buffer_cache_write(fs_device, pointers[13], zeros, 0, BLOCK_SECTOR_SIZE);
        doubly_indirect_allocated = true;
      }

      block_sector_t indirect_sector_idx = (i - 140) / POINTERS_IN_SECTOR;
      block_sector_t direct_sector_idx = i - (140 + 128 * indirect_sector_idx);
      if (direct_sector_idx == 0)
      {
        block_sector_t indirect_sector;
        if (!free_map_allocate(1, &indirect_sector))
        {
          failure_idx = i;
          free_map_release(sector, 1);
          if (indirect_sector_idx == 0)
          {
            free_map_release(pointers[13], 1);
          }
          break;
        }

        buffer_cache_write(fs_device, indirect_sector, zeros, 0, BLOCK_SECTOR_SIZE);
        buffer_cache_write(fs_device, pointers[13], &indirect_sector, sizeof(block_sector_t) * indirect_sector_idx, sizeof(block_sector_t));
        indirect_ptrs[indirect_sector_idx] = indirect_sector;
      }

      buffer_cache_write(fs_device,
                         indirect_ptrs[indirect_sector_idx],
                         &sector, sizeof(block_sector_t) * direct_sector_idx,
                         sizeof(block_sector_t));
    }
  }

  cleanup_errors(failure_idx, pointers, indirect_ptrs);
  return failure_idx == -1;
}

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool inode_create(block_sector_t sector, off_t length)
{
  struct inode_disk *disk_inode = NULL;
  bool success = false;

  ASSERT(length >= 0);

  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  ASSERT(sizeof *disk_inode == BLOCK_SECTOR_SIZE);

  disk_inode = calloc(1, sizeof *disk_inode);
  if (disk_inode != NULL)
  {
    size_t sectors = bytes_to_sectors(length);
    disk_inode->length = length;
    disk_inode->magic = INODE_MAGIC;
    if (allocate_sectors(0, sectors, disk_inode->pointers))
    {
      buffer_cache_write(fs_device, sector, disk_inode, 0, BLOCK_SECTOR_SIZE);
      if (sectors > 0)
      {
        static char zeros[BLOCK_SECTOR_SIZE];
        size_t i;

        for (i = 0; i < sectors; i++)
        {
          block_sector_t sector_num = sector_idx_to_num(disk_inode->pointers, i);
          buffer_cache_write(fs_device, sector_num, zeros, 0, BLOCK_SECTOR_SIZE);
        }
      }
      success = true;
    }
    free(disk_inode);
  }
  return success;
}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode *
inode_open(block_sector_t sector)
{
  struct list_elem *e;
  struct inode *inode;

  /* Check whether this inode is already open. */
  for (e = list_begin(&open_inodes); e != list_end(&open_inodes);
       e = list_next(e))
  {
    inode = list_entry(e, struct inode, elem);
    if (inode->sector == sector)
    {
      inode_reopen(inode);
      return inode;
    }
  }

  /* Allocate memory. */
  inode = malloc(sizeof *inode);
  if (inode == NULL)
    return NULL;

  /* Initialize. */
  list_push_front(&open_inodes, &inode->elem);
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;
  // buffer_cache_read(fs_device, inode->sector, &inode->data,
  //                   0, BLOCK_SECTOR_SIZE);
  // block_read(fs_device, inode->sector, &inode->data);
  return inode;
}

/* Reopens and returns INODE. */
struct inode *
inode_reopen(struct inode *inode)
{
  if (inode != NULL)
    inode->open_cnt++;
  return inode;
}

/* Returns INODE's inode number. */
block_sector_t
inode_get_inumber(const struct inode *inode)
{
  return inode->sector;
}

/* Closes INODE and writes it to disk.
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void inode_close(struct inode *inode)
{
  // TODO: write inode back to disk when we close and deallocate all sectors if removing inode
  /* Ignore null pointer. */
  if (inode == NULL)
    return;

  /* Release resources if this was the last opener. */
  if (--inode->open_cnt == 0)
  {
    /* Remove from inode list and release lock. */
    list_remove(&inode->elem);

    /* Deallocate blocks if removed. */
    if (inode->removed)
    { 
      // free_map_release(inode->sector, 1);
      // free_map_release(inode->data.start,
      //                  bytes_to_sectors(inode->data.length));
    }

    free(inode);
  }
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void inode_remove(struct inode *inode)
{
  ASSERT(inode != NULL);
  inode->removed = true;
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t inode_read_at(struct inode *inode, void *buffer_, off_t size, off_t offset)
{
  uint8_t *buffer = buffer_;
  off_t bytes_read = 0;
  // uint8_t *bounce = NULL;

  while (size > 0)
  {
    /* Disk sector to read, starting byte offset within sector. */
    block_sector_t sector_idx = byte_to_sector(inode, offset);
    int sector_ofs = offset % BLOCK_SECTOR_SIZE;

    /* Bytes left in inode, bytes left in sector, lesser of the two. */
    off_t inode_left = inode_length(inode) - offset;
    int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
    int min_left = inode_left < sector_left ? inode_left : sector_left;

    /* Number of bytes to actually copy out of this sector. */
    int chunk_size = size < min_left ? size : min_left;
    if (chunk_size <= 0)
      break;

    buffer_cache_read(fs_device, sector_idx, buffer + bytes_read,
                      sector_ofs, chunk_size);

    // if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE)
    //   {
    //     /* Read full sector directly into caller's buffer. */
    //     block_read (fs_device, sector_idx, buffer + bytes_read);
    //   }
    // else
    //   {
    //     /* Read sector into bounce buffer, then partially copy
    //        into caller's buffer. */
    //     if (bounce == NULL)
    //       {
    //         bounce = malloc (BLOCK_SECTOR_SIZE);
    //         if (bounce == NULL)
    //           break;
    //       }
    //     block_read (fs_device, sector_idx, bounce);
    //     memcpy (buffer + bytes_read, bounce + sector_ofs, chunk_size);
    //   }

    /* Advance. */
    size -= chunk_size;
    offset += chunk_size;
    bytes_read += chunk_size;
  }
  // free (bounce);

  return bytes_read;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if end of file is reached or an error occurs.
   (Normally a write at end of file would extend the inode, but
   growth is not yet implemented.) */
off_t inode_write_at(struct inode *inode, const void *buffer_, off_t size,
                     off_t offset)
{
  const uint8_t *buffer = buffer_;
  off_t bytes_written = 0;
  // uint8_t *bounce = NULL;

  if (inode->deny_write_cnt)
    return 0;

  block_sector_t starting_sector = pos_to_sector_idx(inode_length(inode));
  // printf("starting sector for byte %d: %d\n", inode_length(inode), starting_sector);
  off_t final_byte = offset + size;
  block_sector_t final_write_sector = pos_to_sector_idx(final_byte);
  // printf("final write sector for byte %d: %d\n", final_byte, final_write_sector);
  if (final_write_sector > starting_sector)
  {
    printf("NEED TO EXTEND\n");
    struct inode_disk inode_disk;
    for (int i = 0; i < 10; i++)
      printf("%d\n", i);
    buffer_cache_read(fs_device, inode->sector, &inode_disk, 0, BLOCK_SECTOR_SIZE);
    if (!allocate_sectors(starting_sector + 1, final_write_sector - starting_sector, inode_disk.pointers))
    {
      printf("allocated\n");
    }
      return 0; // TODO: figure out of we need to write as much as we can if not enough space to extend file all the way
    buffer_cache_write(fs_device, inode->sector, &inode_disk, 0, BLOCK_SECTOR_SIZE);
  }
  

  while (size > 0)
  {
    /* Sector to write, starting byte offset within sector. */
    block_sector_t sector_idx = byte_to_sector(inode, offset);
    int sector_ofs = offset % BLOCK_SECTOR_SIZE;

    /* Bytes left in inode, bytes left in sector, lesser of the two. */
    off_t inode_left = inode_length(inode) - offset;
    int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
    int min_left = inode_left < sector_left ? inode_left : sector_left;

    /* Number of bytes to actually write into this sector. */
    int chunk_size = size < min_left ? size : min_left;
    if (chunk_size <= 0)
      break;

    buffer_cache_write(fs_device, sector_idx, buffer + bytes_written,
                       sector_ofs, chunk_size);

    // if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE)
    // {
    //   /* Write full sector directly to disk. */
    //   block_write(fs_device, sector_idx, buffer + bytes_written);
    // }
    // else
    // {
    //   /* We need a bounce buffer. */
    //   if (bounce == NULL)
    //   {
    //     bounce = malloc(BLOCK_SECTOR_SIZE);
    //     if (bounce == NULL)
    //       break;
    //   }

    //   /* If the sector contains data before or after the chunk
    //      we're writing, then we need to read in the sector
    //      first.  Otherwise we start with a sector of all zeros. */
    //   if (sector_ofs > 0 || chunk_size < sector_left)
    //     block_read(fs_device, sector_idx, bounce);
    //   else
    //     memset(bounce, 0, BLOCK_SECTOR_SIZE);
    //   memcpy(bounce + sector_ofs, buffer + bytes_written, chunk_size);
    //   block_write(fs_device, sector_idx, bounce);
    // }

    /* Advance. */
    size -= chunk_size;
    offset += chunk_size;
    bytes_written += chunk_size;
  }
  // free(bounce);

  return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void inode_deny_write(struct inode *inode)
{
  inode->deny_write_cnt++;
  ASSERT(inode->deny_write_cnt <= inode->open_cnt);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void inode_allow_write(struct inode *inode)
{
  ASSERT(inode->deny_write_cnt > 0);
  ASSERT(inode->deny_write_cnt <= inode->open_cnt);
  inode->deny_write_cnt--;
}

/* Returns the length, in bytes, of INODE's data. */
off_t inode_length(const struct inode *inode)
{
  struct inode_disk inode_disk;
  buffer_cache_read(fs_device, inode->sector, &inode_disk, 0, BLOCK_SECTOR_SIZE);
  return inode_disk.length;
}
