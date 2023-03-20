#include "filesys/directory.h"
#include <stdio.h>
#include <string.h>
#include <list.h>
#include "filesys/cache.h"
#include "filesys/filesys.h"
#include "filesys/inode.h"
#include "threads/malloc.h"

// /* A directory. */
// struct dir 
//   {
//     struct inode *inode;                /* Backing store. */
//     off_t pos;                          /* Current position. */
//   };

/* A single directory entry. */
struct dir_entry 
  {
    block_sector_t inode_sector;        /* Sector number of header. */
    char name[NAME_MAX + 1];            /* Null terminated file name. */
    bool in_use;                        /* In use or free? */
  };

void
print_entries(struct inode *inode) {
  struct dir *dir = dir_open(inode);
  char name[15];
  while (dir_readdir(dir, name))
    printf("name: %s\n", name);
}

static int
get_num_entries(struct inode *inode) 
{
  int num_entries = 0;
  buffer_cache_read(fs_device, inode->sector, &num_entries, 
                    sizeof(int) * 16, sizeof(int));
  return num_entries;
}

static void
increment_num_entries(struct inode *inode) 
{
  int num_entries = 0;
  buffer_cache_read(fs_device, inode->sector, &num_entries, 
                    sizeof(int) * 16, sizeof(int));
  num_entries++;
  buffer_cache_write(fs_device, inode->sector, &num_entries, 
                    sizeof(int) * 16, sizeof(int));
  return;
}

static void
decrement_num_entries(struct inode *inode) 
{
  int num_entries = 0;
  buffer_cache_read(fs_device, inode->sector, &num_entries, 
                    sizeof(int) * 16, sizeof(int));
  num_entries--;
  buffer_cache_write(fs_device, inode->sector, &num_entries, 
                    sizeof(int) * 16, sizeof(int));
  return;
}


/* Creates a directory with space for ENTRY_CNT entries in the
   given SECTOR.  Returns true if successful, false on failure. */
bool
dir_create (block_sector_t sector, size_t entry_cnt, struct dir *parent_dir)
{
  
  bool success = inode_create (sector, entry_cnt * sizeof (struct dir_entry), true);
  if (!success)
  {
    
    return success;
  }
  
  if (sector == ROOT_DIR_SECTOR)
  {
    struct dir *root_dir = dir_open_root();
    success = dir_add(root_dir, ".", ROOT_DIR_SECTOR);
    if (!success) 
    {
      dir_close(root_dir);
      
      return success;
    }
    success = dir_add(root_dir, "..", ROOT_DIR_SECTOR);
    dir_close(root_dir);
    
    return success;
  }
  struct inode *cur_inode = inode_open(sector);
  struct dir *cur_dir = dir_open(cur_inode);
  success = dir_add(cur_dir, ".", sector);
  if (!success)
  {
    dir_close(cur_dir);
    
    return success;
  }
  success = dir_add(cur_dir, "..", parent_dir->inode->sector);
  // inode_close(cur_inode);
  dir_close(cur_dir);
  
  return success;
}

/* Opens and returns the directory for the given INODE, of which
   it takes ownership.  Returns a null pointer on failure. */
struct dir *
dir_open (struct inode *inode) 
{
  
  struct dir *dir = calloc (1, sizeof *dir);
  if (inode != NULL && inode->is_dir && dir != NULL)
    {
      dir->inode = inode;
      dir->pos = 0;
      
      return dir;
    }
  else
    {
      inode_close (inode);
      free (dir);
      
      return NULL; 
    }
}

/* Opens the root directory and returns a directory for it.
   Return true if successful, false on failure. */
struct dir *
dir_open_root (void)
{
  return dir_open (inode_open (ROOT_DIR_SECTOR));
}

/* Opens and returns a new directory for the same inode as DIR.
   Returns a null pointer on failure. */
struct dir *
dir_reopen (struct dir *dir) 
{
  return dir_open (inode_reopen (dir->inode));
}

/* Destroys DIR and frees associated resources. */
void
dir_close (struct dir *dir) 
{
  
  if (dir != NULL)
    {
      inode_close (dir->inode);
      free (dir);
    }
  
}

/* Returns the inode encapsulated by DIR. */
struct inode *
dir_get_inode (struct dir *dir) 
{
  return dir->inode;
}

/* Searches DIR for a file with the given NAME.
   If successful, returns true, sets *EP to the directory entry
   if EP is non-null, and sets *OFSP to the byte offset of the
   directory entry if OFSP is non-null.
   otherwise, returns false and ignores EP and OFSP. */
static bool
lookup (const struct dir *dir, const char *name,
        struct dir_entry *ep, off_t *ofsp) 
{
  
  struct dir_entry e;
  size_t ofs;
  
  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  for (ofs = 0; inode_read_at (dir->inode, &e, sizeof e, ofs) == sizeof e;
       ofs += sizeof e) 
    if (e.in_use && !strcmp (name, e.name)) 
      {
        if (ep != NULL)
          *ep = e;
        if (ofsp != NULL)
          *ofsp = ofs;
        
        return true;
      }
  
  return false;
}

/* Searches DIR for a file with the given NAME
   and returns true if one exists, false otherwise.
   On success, sets *INODE to an inode for the file, otherwise to
   a null pointer.  The caller must close *INODE. */
bool
dir_lookup (const struct dir *dir, const char *name,
            struct inode **inode) 
{
  
  struct dir_entry e;

  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  if (lookup (dir, name, &e, NULL))
    *inode = inode_open (e.inode_sector);
  else
    *inode = NULL;
  
  return *inode != NULL;
}

/* Adds a file named NAME to DIR, which must not already contain a
   file by that name.  The file's inode is in sector
   INODE_SECTOR.
   Returns true if successful, false on failure.
   Fails if NAME is invalid (i.e. too long) or a disk or memory
   error occurs. */
bool
dir_add (struct dir *dir, const char *name, block_sector_t inode_sector)
{
  
  struct dir_entry e;
  off_t ofs;
  bool success = false;

  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  /* Check NAME for validity. */
  if (*name == '\0' || strlen (name) > NAME_MAX)
  {
    
    return false;
  }

  /* Check that NAME is not in use. */
  if (lookup (dir, name, NULL, NULL))
    goto done;

  /* Set OFS to offset of free slot.
     If there are no free slots, then it will be set to the
     current end-of-file.
     
     inode_read_at() will only return a short read at end of file.
     Otherwise, we'd need to verify that we didn't get a short
     read due to something intermittent such as low memory. */
  for (ofs = 0; inode_read_at (dir->inode, &e, sizeof e, ofs) == sizeof e;
       ofs += sizeof e) 
    if (!e.in_use)
      break;

  /* Write slot. */
  e.in_use = true;
  strlcpy (e.name, name, sizeof e.name);
  e.inode_sector = inode_sector;
  success = inode_write_at (dir->inode, &e, sizeof e, ofs) == sizeof e;

 done:
  if (success && (strcmp(name, ".") != 0 && strcmp(name, "..") != 0))
    increment_num_entries(dir->inode);
  
  return success;
}

/* Removes any entry for NAME in DIR.
   Returns true if successful, false on failure,
   which occurs only if there is no file with the given NAME. */
bool
dir_remove (struct dir *dir, const char *name) 
{
  
  struct dir_entry e;
  struct inode *inode = NULL;
  bool success = false;
  off_t ofs;

  ASSERT (dir != NULL);
  ASSERT (name != NULL);

  /* Find directory entry. */
  if (!lookup (dir, name, &e, &ofs))
    goto done;

  /* Open inode. */
  inode = inode_open (e.inode_sector);
  if (inode == NULL || inode->sector == ROOT_DIR_SECTOR)
    goto done;

  if (inode->is_dir)
  {
    int num_entries = get_num_entries(inode);
    if (num_entries > 0 || inode->open_cnt - 2 > 0)
      goto done;
  }

  /* Erase directory entry. */
  e.in_use = false;
  if (inode_write_at (dir->inode, &e, sizeof e, ofs) != sizeof e) 
    goto done;

  /* Remove inode. */
  inode_remove (inode);
  success = true;

 done:
  if (success)
    decrement_num_entries(dir->inode);
  inode_close (inode);
  
  return success;
}

/* Reads the next directory entry in DIR and stores the name in
   NAME.  Returns true if successful, false if the directory
   contains no more entries. */
bool
dir_readdir (struct dir *dir, char name[NAME_MAX + 1])
{
  
  struct dir_entry e;

  while (inode_read_at (dir->inode, &e, sizeof e, dir->pos) == sizeof e) 
    {
      dir->pos += sizeof e;
      if (e.in_use)
        {
          strlcpy (name, e.name, strlen(e.name) + 1);
          
          return true;
        } 
    }
  
  return false;
}