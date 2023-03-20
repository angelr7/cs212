#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include <stdio.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "filesys/cache.h"
#include "threads/malloc.h"
#include "threads/synch.h"

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44
#define POINTERS_IN_SECTOR 128

/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk
{
  off_t length;                /* File size in bytes. */
  int is_dir;                  /* 1 if inode is for a directory file. */
  block_sector_t pointers[14]; /* Array of sector pointers. 12 direct, 
                                  1 singly-indirect, 1 doubly-indirect */
  int num_entries;             /* Number of entries if directory, 
                                  excluding . and .. entries. */
  unsigned magic;              /* Magic number. */
  uint32_t unused[110];        /* Not used. */
};

/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t
bytes_to_sectors(off_t size)
{
  return DIV_ROUND_UP(size, BLOCK_SECTOR_SIZE);
}

static block_sector_t pos_to_sector_idx(off_t pos)
{
  return (block_sector_t)pos / BLOCK_SECTOR_SIZE;
}

static block_sector_t
sector_idx_to_num(block_sector_t *pointers, block_sector_t sector_idx)
{
  /* mapid list of current thread corrupts after next line executes for file lg-create test */
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
byte_to_sector(const struct inode *inode, off_t pos, off_t length UNUSED)
{
  ASSERT(inode != NULL);
  struct cache_entry *entry = buffer_cache_read(fs_device, inode->sector, NULL, 0, 0);
  struct inode_disk *inode_disk = (struct inode_disk *)entry->data; 
  block_sector_t sector_num = sector_idx_to_num(inode_disk->pointers, pos_to_sector_idx(pos));
  lock_acquire(&entry->lock);
  entry->num_active--;
  lock_release(&entry->lock);
  return sector_num;
}

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;

/* Initializes the inode module. */
void inode_init(void)
{
  list_init(&open_inodes);
}

static void cleanup_errors(int failure_idx, block_sector_t *pointers, 
                           block_sector_t *indirect_ptrs)
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

  struct cache_entry *entry = NULL;
  if (indirect_ptrs == NULL) {
    entry = buffer_cache_read(fs_device, pointers[13], NULL, 0, 0);
    indirect_ptrs = (block_sector_t *)entry->data;
  }

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

  if (entry != NULL) {
    lock_acquire(&entry->lock);
    entry->num_active--;
    lock_release(&entry->lock);
  }
}

static bool allocate_sectors(size_t starting_block, size_t cnt, block_sector_t *pointers)
{
  int failure_idx = -1;
  bool indirect_allocated = false;
  bool doubly_indirect_allocated = false;
  static char zeros[BLOCK_SECTOR_SIZE];

  if (starting_block > 12)
    indirect_allocated = true;
  if (starting_block > 140)
    doubly_indirect_allocated = true;

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
        buffer_cache_write(fs_device, pointers[13], &indirect_sector, 
                           sizeof(block_sector_t) * indirect_sector_idx, sizeof(block_sector_t));
      }

      block_sector_t direct_pointers = 0;
      buffer_cache_read(fs_device, 
                        pointers[13], 
                        &direct_pointers, 
                        sizeof(block_sector_t) * indirect_sector_idx, 
                        sizeof(block_sector_t));
      buffer_cache_write(fs_device,
                         direct_pointers,
                         &sector, sizeof(block_sector_t) * direct_sector_idx,
                         sizeof(block_sector_t));
    }
  }
  cleanup_errors(failure_idx, pointers, NULL);
  return failure_idx == -1;
}

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool inode_create(block_sector_t sector, off_t length, bool is_dir)
{
  struct cache_entry *entry = buffer_cache_read(fs_device, sector, NULL, 0, 0);
  struct inode_disk *disk_inode = (struct inode_disk *)entry->data;
  bool success = false;

  ASSERT(length >= 0);

  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  ASSERT(sizeof *disk_inode == BLOCK_SECTOR_SIZE);

  if (disk_inode != NULL)
  {
    size_t sectors = bytes_to_sectors(length);
    disk_inode->length = length;
    disk_inode->is_dir = is_dir;
    disk_inode->num_entries = 0;
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
  }
  lock_acquire(&entry->lock);
  entry->num_active--;
  lock_release(&entry->lock);
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
  lock_init(&inode->eof_lock);
  lock_init(&inode->length_lock);
  buffer_cache_read(fs_device, inode->sector, &inode->is_dir,
                    sizeof(block_sector_t), sizeof(int));
  buffer_cache_read(fs_device, inode->sector, &inode->num_entries, 
                    sizeof(uint32_t) * 16, sizeof(int));
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
      struct cache_entry *entry = buffer_cache_read(fs_device, inode->sector, NULL, 0, 0);
      struct inode_disk *inode_disk = (struct inode_disk *)entry->data;
      block_sector_t last_sector = pos_to_sector_idx(inode_disk->length);
      if (inode_disk->length > 0)
        cleanup_errors(last_sector + 1, inode_disk->pointers, NULL);
      free_map_release(inode->sector, 1);
      
      lock_acquire(&entry->lock);
      entry->num_active--;
      lock_release(&entry->lock);
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

  while (size > 0)
  {
    /* Disk sector to read, starting byte offset within sector. */
    lock_acquire(&inode->length_lock);
    off_t inode_len = inode_length(inode);
    lock_release(&inode->length_lock);

    block_sector_t sector_idx = byte_to_sector(inode, offset, inode_len);
    int sector_ofs = offset % BLOCK_SECTOR_SIZE;

    /* Bytes left in inode, bytes left in sector, lesser of the two. */
    off_t inode_left = inode_len - offset;
    int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
    int min_left = inode_left < sector_left ? inode_left : sector_left;

    /* Number of bytes to actually copy out of this sector. */
    int chunk_size = size < min_left ? size : min_left;
    if (chunk_size <= 0)
      break;

    if (size - chunk_size > 0) 
    {
      lock_acquire(&inode->length_lock);
      off_t inode_len = inode_length(inode);
      lock_release(&inode->length_lock);
      
      block_sector_t sector_id = byte_to_sector(inode, offset + chunk_size, inode_len);
      struct read_ahead_struct *read_ahead_struct = malloc(sizeof(struct read_ahead_struct));
      read_ahead_struct->sector_id = sector_id;
      lock_acquire(&read_ahead_lock);
      list_push_back(&read_ahead_ids, &read_ahead_struct->elem);
      cond_signal(&read_ahead, &read_ahead_lock);      
      lock_release(&read_ahead_lock);
    }
    
    buffer_cache_read(fs_device, sector_idx, buffer + bytes_read,
                      sector_ofs, chunk_size);

    /* Advance. */
    size -= chunk_size;
    offset += chunk_size;
    bytes_read += chunk_size;
  }

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

  if (inode->deny_write_cnt)
    return 0;

  lock_acquire(&inode->eof_lock);
  lock_acquire(&inode->length_lock);
  off_t length = inode_length(inode);
  lock_release(&inode->length_lock);

  block_sector_t starting_sector = pos_to_sector_idx(length);
  off_t final_byte = offset + size;
  block_sector_t final_write_sector = pos_to_sector_idx(final_byte);
  struct cache_entry *entry = NULL;
  struct inode_disk *inode_disk = NULL;
  bool extended_file = false;

  if (final_write_sector > starting_sector || (length == 0 && size != 0))
  {
    entry =  buffer_cache_read(fs_device, inode->sector, NULL, 0, 0);
    inode_disk = (struct inode_disk *)entry->data;
    if (length != 0)

    {
      if (!allocate_sectors(starting_sector + 1, 
                            final_write_sector - starting_sector, 
                            inode_disk->pointers))
      {
        lock_release(&inode->eof_lock);
        return 0;
      }    
    }
    else
    {
      if (!allocate_sectors(starting_sector, 
                            (final_write_sector - starting_sector) + 1, 
                            inode_disk->pointers))
      {
        lock_release(&inode->eof_lock);
        return 0;
      }
    }
    extended_file = true;
  }
  if(!extended_file)
    lock_release(&inode->eof_lock);
  
  length = (length > offset + size) ? length : offset + size;

  while (size > 0)
  {
    /* Sector to write, starting byte offset within sector. */
    block_sector_t sector_idx = byte_to_sector(inode, offset, length);
    int sector_ofs = offset % BLOCK_SECTOR_SIZE;

    /* Bytes left in inode, bytes left in sector, lesser of the two. */
    off_t inode_left = length - offset;
    int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
    int min_left = inode_left < sector_left ? inode_left : sector_left;

    /* Number of bytes to actually write into this sector. */
    int chunk_size = size < min_left ? size : min_left;
    if (chunk_size <= 0)
      break;

    buffer_cache_write(fs_device, sector_idx, buffer + bytes_written,
                       sector_ofs, chunk_size);

    /* Advance. */
    size -= chunk_size;
    offset += chunk_size;
    bytes_written += chunk_size;
  }

  if (entry != NULL) {
    lock_acquire(&inode->length_lock);
    inode_disk->length = length;
    lock_release(&inode->length_lock);

    lock_acquire(&entry->lock);
    entry->num_active--;
    lock_release(&entry->lock);
  } 
  
  else { 
    lock_acquire(&inode->length_lock);
    buffer_cache_write(fs_device, inode->sector, &length, 0, sizeof(off_t));
    lock_release(&inode->length_lock);
  }  


  if (extended_file)
    lock_release(&inode->eof_lock);

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
  struct cache_entry *entry = buffer_cache_read(fs_device, inode->sector, NULL, 0, 0);
  struct inode_disk *inode_disk = (struct inode_disk *)entry->data;
  off_t length = 0;
  length = inode_disk->length;
  lock_acquire(&entry->lock);
  entry->num_active--;
  lock_release(&entry->lock);
  return length;
}
