#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "filesys/cache.h"
#include "threads/thread.h"
#include "userprog/syscall.h"

/* Partition that contains the file system. */
struct block *fs_device;

static void do_format (void);

/* Initializes the file system module.
   If FORMAT is true, reformats the file system. */
void
filesys_init (bool format) 
{
  fs_device = block_get_role (BLOCK_FILESYS);
  if (fs_device == NULL)
    PANIC ("No file system device found, can't initialize file system.");

  buffer_cache_init();
  inode_init ();
  free_map_init ();
  lock_init(&dir_lock);

  if (format) 
    do_format ();

  free_map_open ();
  thread_current()->working_dir = dir_open_root();
}

/* Shuts down the file system module, writing any unwritten data
   to disk. */
void
filesys_done (void) 
{
  free_map_flush();
  buffer_cache_flush();
  free_map_close ();
}

/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */
bool
filesys_create (const char *path, off_t initial_size, bool is_dir) 
{
  struct dir *dir;
  char last_name[NAME_MAX + 1];
  if(!parse_path(path, &dir, last_name))
    return false;
  struct inode *inode = NULL;
  if (dir_lookup (dir, last_name, &inode))
  {
    dir_close(dir);
    inode_close(inode);
    return false;
  }

  block_sector_t inode_sector = 0;
  // struct dir *dir = dir_open_root ();
  bool success = (dir != NULL
                  && free_map_allocate (1, &inode_sector)
                  && inode_create (inode_sector, initial_size, is_dir)
                  && dir_add (dir, last_name, inode_sector));
  dir_close(dir);
  if (!success && inode_sector != 0) 
    free_map_release (inode_sector, 1);
  return success;
}

/* Opens the file with the given NAME.
   Returns the new file if successful or a null pointer
   otherwise.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
struct file *
filesys_open (const char *path)
{
  // if(dir == NULL)
  struct dir *dir = NULL;
  char last_name[NAME_MAX + 1];
  if(!parse_path(path, &dir, last_name))
    return NULL;
  struct inode *inode = NULL;
  dir_lookup(dir, last_name, &inode);
  dir_close(dir);
  return file_open(inode);



  // if (strlen(last_name) == 0)
  // {
  //   struct file *opened = file_open(dir->inode);
  //   dir_close(dir);
  //   return opened;
  // }
  // else
  //   dir_lookup (dir, last_name, &inode);
  // dir_close (dir);
  // return file_open (inode);
}

/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool
filesys_remove (const char *path) 
{
  struct dir *dir;
  char last_name[NAME_MAX + 1];
  if(!parse_path(path, &dir, last_name))
    return false;

  struct inode *inode = NULL;
  if (!dir_lookup(dir, last_name, &inode) || 
      inode->sector == ROOT_DIR_SECTOR ||
      strcmp(last_name, "..") == 0 || 
      strcmp(last_name, ".") == 0)
  {
    dir_close(dir);
    return false;
  }
  inode_close(inode);
  bool success = dir_remove(dir, last_name);
  dir_close(dir);
  return success;
}

/* Formats the file system. */
static void
do_format (void)
{
  printf ("Formatting file system...");
  free_map_create ();
  if (!dir_create (ROOT_DIR_SECTOR, 16, NULL))
    PANIC ("root directory creation failed");
  free_map_close ();
  printf ("done.\n");
}
