#include "devices/input.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "userprog/syscall.h"
#include "userprog/pagedir.h"
#include <stdio.h>
#include <string.h>
#include <syscall-nr.h>
#include "devices/shutdown.h"
#include "userprog/process.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "vm/page.h"

typedef int pid_t;
typedef int mapid_t;

static void syscall_handler(struct intr_frame *);
static void verify_pointer(const void *pointer, int size);
static void halt(void) NO_RETURN;
void exit_handler(int status);
static void exec(const char *file, struct intr_frame *f);
static void wait(pid_t pid_t, struct intr_frame *f);
static void create(const char *file, unsigned initial_size, struct intr_frame *f);
static void remove(const char *file, struct intr_frame *f);
static void open(const char *file, struct intr_frame *f);
static void filesize(int fd, struct intr_frame *f);
static void read(int fd, void *buffer, unsigned length, struct intr_frame *f);
static void write(int fd, const void *buffer, unsigned int length, struct intr_frame *f);
static void seek(int fd, unsigned position);
static void tell(int fd, struct intr_frame *f);
static void close(int fd);
static void mmap(int fd, void *addr, struct intr_frame *f);

struct fd_elem
{
  int fd;
  struct file *file;
  struct list_elem elem;
};

void syscall_init(void)
{
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler(struct intr_frame *f)
{
  verify_pointer(f->esp, sizeof(uint32_t));
  uint32_t syscall_num = *(uint32_t *)f->esp;
  uint32_t arg1 = 0;
  uint32_t arg2 = 0;
  uint32_t arg3 = 0;

  // initialize arguments
  if (syscall_num != SYS_HALT)
  {
    verify_pointer(f->esp + 4, sizeof(uint32_t));
    arg1 = *(uint32_t *)(f->esp + 4);
  }
  if (syscall_num == SYS_CREATE || syscall_num == SYS_READ || syscall_num == SYS_WRITE || syscall_num == SYS_SEEK || syscall_num == SYS_MMAP)
  {
    verify_pointer(f->esp + 8, sizeof(uint32_t));
    arg2 = *(uint32_t *)(f->esp + 8);
  }
  if (syscall_num == SYS_READ || syscall_num == SYS_WRITE)
  {
    verify_pointer(f->esp + 8, sizeof(uint32_t));
    arg3 = *(uint32_t *)(f->esp + 12);
  }

  // call syscall function
  switch (syscall_num)
  {
  case SYS_HALT:
    halt();
    break;
  case SYS_EXIT:
    exit_handler((int)arg1);
    break;
  case SYS_EXEC:
    exec((const char *)arg1, f);
    break;
  case SYS_WAIT:
    wait((pid_t)arg1, f);
    break;
  case SYS_CREATE:
    create((const char *)arg1, (unsigned int)arg2, f);
    break;
  case SYS_REMOVE:
    remove((const char *)arg1, f);
    break;
  case SYS_OPEN:
    open((const char *)arg1, f);
    break;
  case SYS_FILESIZE:
    filesize((int)arg1, f);
    break;
  case SYS_READ:
    read((int)arg1, (void *)arg2, (unsigned int)arg3, f);
    break;
  case SYS_WRITE:
    write((int)arg1, (const void *)arg2, (unsigned int)arg3, f);
    break;
  case SYS_SEEK:
    seek((int)arg1, (unsigned int)arg2);
    break;
  case SYS_TELL:
    tell((int)arg1, f);
    break;
  case SYS_CLOSE:
    close((int)arg1);
    break;
  case SYS_MMAP:
    mmap((int)arg1, (void *)arg2, f);
    break;
  case SYS_MUNMAP:
    break;
  }
}

/*Search through fd list and return fd_elem with corresponding fd */
static struct list_elem *
list_find_fd_elem(struct thread *t, int fd)
{
  struct list_elem *e;

  for (e = list_begin(&t->fd_list);
       e != list_end(&t->fd_list);
       e = list_next(e))
  {
    struct fd_elem *f = list_entry(e, struct fd_elem, elem);
    if (f->fd == fd)
      return e;
  }

  return NULL;
}

/* Verify that every byte of data that a pointer points to is valid */
static void
verify_pointer(const void *pointer, int size)
{
  void *last_byte = (void *)((char *)pointer + (size - 1));
  if (pointer == NULL || is_kernel_vaddr(pointer) || is_kernel_vaddr(last_byte))
  {
    exit_handler(-1);
  }
  if (is_user_vaddr(pointer))
  {
    uint32_t *pd = thread_current()->pagedir;
    struct page p1;
    p1.virtual_addr = pg_round_down(pointer);
    struct page p2;
    p2.virtual_addr = pg_round_down(last_byte);
    bool pd1 = pagedir_get_page(pd, pointer) == NULL;
    bool spt1 = hash_find(&thread_current()->spt, &p1.hash_elem) == NULL;
    bool pd2 = pagedir_get_page(pd, last_byte) == NULL;
    bool spt2 = hash_find(&thread_current()->spt, &p2.hash_elem) == NULL;
    // if ((pagedir_get_page(pd, pointer) == NULL && hash_find(&thread_current()->spt, &p1.hash_elem) == NULL) ||
    //  (pagedir_get_page(pd, last_byte) == NULL && hash_find(&thread_current()->spt, &p2.hash_elem) == NULL))
    // {
    if ((pd1 && spt1) || (pd2 && spt2))
    {
      exit_handler(-1);
    }
  }
  else
    exit_handler(-1);
}

/*Verify that every byte of a string is in valid memory */
static void
verify_string(const char *string)
{
  char *cur = string;
  verify_pointer(cur, sizeof(char));
  while (*cur != '\0')
    verify_pointer(++cur, sizeof(char));
}

/*Halt program*/
static void
halt(void)
{
  shutdown_power_off();
}

/*Exit process and free fds and child_processes. If
this process is the last one using child_process free it*/
void exit_handler(int status)
{
  struct thread *cur = thread_current();

  lock_acquire(&process_lock);
  struct child_process *process_info = cur->process;
  process_info->status = status;

  /*loop through children if child exited free
  its corresponding child_process*/
  for (struct list_elem *e = list_begin(&cur->children);
       e != list_end(&cur->children);
       e = list_next(e))
  {
    struct child_process *child = list_entry(e, struct child_process, wait_elem);
    if (child->tried_to_free)
      free(child);
    else
      child->tried_to_free = true;
  }
  /*loop through fd_list and free fds*/
  lock_acquire(&filesys_lock);
  struct fd_elem *prev = NULL;
  for (struct list_elem *e = list_begin(&cur->fd_list);
       e != list_end(&cur->fd_list);
       e = list_next(e))
  {
    if (prev)
      free(prev);
    struct fd_elem *fd_elem = list_entry(e, struct fd_elem, elem);
    file_close(fd_elem->file);
    prev = fd_elem;
  }
  if (prev)
    free(prev);
  lock_release(&filesys_lock);

  /*if parent has exited then free yourself*/
  if (process_info->tried_to_free)
    free(process_info);

  /*if parent has not exited then wake up parent in process_wait*/
  else
  {
    lock_acquire(&process_info->wait_lock);
    cond_signal(&process_info->wait_cond, &process_info->wait_lock);
    lock_release(&process_info->wait_lock);
  }

  lock_release(&process_lock);
  printf("%s: exit(%d)\n", cur->exec_name, status);
  thread_exit();
}

/*Execute file*/
static void
exec(const char *file, struct intr_frame *f)
{
  verify_string(file);
  f->eax = process_execute(file);
}

/*Make parent wait for child with pid pid*/
static void
wait(pid_t pid, struct intr_frame *f)
{
  f->eax = process_wait(pid);
}

/*Create file*/
static void
create(const char *file, unsigned initial_size, struct intr_frame *f)
{
  verify_string(file);
  lock_acquire(&filesys_lock);
  bool success = filesys_create(file, initial_size);
  lock_release(&filesys_lock);
  f->eax = success;
}

/*Remove file*/
static void
remove(const char *file, struct intr_frame *f)
{
  verify_string(file);
  lock_acquire(&filesys_lock);
  bool success = filesys_remove(file);
  lock_release(&filesys_lock);
  f->eax = success;
}

/*Open file*/
static void
open(const char *file, struct intr_frame *f)
{
  verify_string(file);
  lock_acquire(&filesys_lock);
  struct file *opened_file = filesys_open(file);
  lock_release(&filesys_lock);
  if (opened_file == NULL)
  {
    f->eax = -1;
    return;
  }
  struct thread *t = thread_current();
  int fd = t->cur_fd;
  struct fd_elem *opened_fd = malloc(sizeof(struct fd_elem));
  ;
  opened_fd->fd = fd;
  opened_fd->file = opened_file;
  list_push_back(&t->fd_list, &opened_fd->elem);
  t->cur_fd++;
  f->eax = fd;
}

/*Get filesize of file descriptor fd*/
static void
filesize(int fd, struct intr_frame *f)
{
  struct list_elem *fd_list_elem = list_find_fd_elem(thread_current(), fd);
  if (fd_list_elem == NULL)
  {
    f->eax = -1;
    return;
  }
  struct fd_elem *found_fd_elem = list_entry(fd_list_elem, struct fd_elem, elem);
  lock_acquire(&filesys_lock);
  int size = file_length(found_fd_elem->file);
  lock_release(&filesys_lock);
  f->eax = size;
}

/*Read from file*/
static void
read(int fd, void *buffer, unsigned length, struct intr_frame *f)
{
  verify_pointer(buffer, length);
  if (fd == 0)
  {
    for (unsigned i = 0; i < length; i++)
      ((char *)buffer)[i] = input_getc();
    f->eax = length;
    return;
  }

  struct list_elem *fd_list_elem = list_find_fd_elem(thread_current(), fd);
  if (fd_list_elem == NULL)
  {
    f->eax = -1;
    return;
  }
  struct fd_elem *found_fd_elem = list_entry(fd_list_elem, struct fd_elem, elem);
  lock_acquire(&filesys_lock);
  int bytes_read = file_read(found_fd_elem->file, buffer, length);
  lock_release(&filesys_lock);
  f->eax = bytes_read;
  return;
}

/*Write to file*/
static void
write(int fd, const void *buffer, unsigned int length, struct intr_frame *f)
{
  verify_pointer(buffer, length);
  if (fd == 1)
  {
    putbuf(buffer, length);
    f->eax = length;
    return;
  }

  struct list_elem *fd_list_elem = list_find_fd_elem(thread_current(), fd);
  if (fd_list_elem == NULL)
  {
    f->eax = -1;
    return;
  }
  struct fd_elem *found_fd_elem = list_entry(fd_list_elem, struct fd_elem, elem);
  lock_acquire(&filesys_lock);
  int bytes_written = file_write(found_fd_elem->file, buffer, length);
  lock_release(&filesys_lock);
  f->eax = bytes_written;
}

/*Seek */
static void
seek(int fd, unsigned position)
{
  struct list_elem *fd_list_elem = list_find_fd_elem(thread_current(), fd);
  if (fd_list_elem == NULL)
  {
    return;
  }
  struct fd_elem *found_fd_elem = list_entry(fd_list_elem, struct fd_elem, elem);
  lock_acquire(&filesys_lock);
  file_seek(found_fd_elem->file, position);
  lock_release(&filesys_lock);
}

/*Tell */
static void
tell(int fd, struct intr_frame *f)
{
  struct list_elem *fd_list_elem = list_find_fd_elem(thread_current(), fd);
  if (fd_list_elem == NULL)
  {
    f->eax = -1;
    return;
  }
  struct fd_elem *found_fd_elem = list_entry(fd_list_elem, struct fd_elem, elem);
  lock_acquire(&filesys_lock);
  int position = file_tell(found_fd_elem->file);
  lock_release(&filesys_lock);
  f->eax = position;
}
/*Close file*/
static void
close(int fd)
{
  struct list_elem *fd_list_elem = list_find_fd_elem(thread_current(), fd);
  if (fd_list_elem == NULL)
  {
    return;
  }
  struct fd_elem *found_fd_elem = list_entry(fd_list_elem, struct fd_elem, elem);
  lock_acquire(&filesys_lock);
  file_close(found_fd_elem->file);
  lock_release(&filesys_lock);
  list_remove(fd_list_elem);
  free(found_fd_elem);
}

static void
mmap(int fd, void *addr, struct intr_frame *f)
{
  // we need to make sure that addr begins on the start of a page, and that it
  // also doesn't equal 0x0. we also need to make sure that they dont use 0 or 1
  // as a file descriptor.
  if (pg_round_down(addr) != addr || addr == 0x0)
  {
    f->eax = -1;
    return;
  };
  if (fd == 0 || fd == 1 || fd < 0)
  {
    f->eax = -1;
    return;
  }

  // find the list_elem that corresponds to fd
  struct list_elem *fd_list_elem = list_find_fd_elem(thread_current(), fd);
  if (fd_list_elem == NULL)
  {
    f->eax = -1;
    return;
  }

  // get the fd_elem that corresponds to the list_elem, which has the file struct
  // that we need to get the length of the file
  struct fd_elem *found_fd_elem = list_entry(fd_list_elem, struct fd_elem, elem);
  lock_acquire(&filesys_lock);
  int size = file_length(found_fd_elem->file);
  lock_release(&filesys_lock);

  // we know that we start on a valid page boundary, so we need to make sure that
  // the following pages don't overlap with virtual pages that are already used
  uint32_t currPtr = (char *)addr + size;
  while (currPtr % PGSIZE != 0)
    currPtr++;

  // determine if we've allocated any of the necessary pages for addr in the spt.
  // if that's the case, we have overlap, and this pointer isn't valid
  int totPages = (currPtr - (uint32_t)addr) / PGSIZE;
  for (int pageNum = 0; pageNum < totPages; pageNum++)
  {
    uint32_t currPage = (uint32_t)addr + pageNum * PGSIZE;
    struct page p;
    p.virtual_addr = (void *)currPage;

    struct hash_elem *found_item = hash_find(&thread_current()->spt, &p.hash_elem);
    if (found_item != NULL)
    {
      f->eax = -1;
      return;
    }
  }

  // create entries in the spt for each page of the file we're mapping
  off_t file_ofs = 0;
  while (size > 0)
  {
    size_t page_read_bytes = size < PGSIZE ? size : PGSIZE;
    size_t page_zero_bytes = PGSIZE - page_read_bytes;

    struct page *page = malloc(sizeof (struct page));
    page->virtual_addr = addr;
    page->process_reference = thread_current();
    page->loaded = false;
    page->memory_flag = IN_DISK;
    page->file = found_fd_elem->file;
    page->file_ofs = file_ofs;
    page->page_read_bytes = page_read_bytes;
    page->page_zero_bytes = page_zero_bytes;
    page->writable = true; // not sure how to get this???

    hash_insert(&thread_current()->spt, &page->hash_elem);
    size -= PGSIZE;
    file_ofs += PGSIZE;
    addr += PGSIZE;
  }
}
