#include "devices/input.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "userprog/syscall.h"
#include "userprog/pagedir.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

typedef int pid_t;

static struct lock filesys_lock;
static bool filesys_lock_initialized = false;

static void syscall_handler (struct intr_frame *);
static void halt (void) NO_RETURN;
static void exit_handler (int status, struct intr_frame *f) NO_RETURN;
// static pid_t exec (const char *file);
// static int wait (pid_t pid_t);
// static bool create (const char *file, unsigned initial_size);
// static bool remove (const char *file);
// static int open (const char *file);
// static int filesize (int fd);
// static int read (int fd, void *buffer, unsigned length);
// static int write (int fd, const void *buffer, unsigned length);
// static void seek (int fd, unsigned position);
// static unsigned tell (int fd);
// static void close (int fd);

static void exec (const char *file, struct intr_frame *f);
static void wait (pid_t pid_t, struct intr_frame *f);
static void create (const char *file, unsigned initial_size, struct intr_frame *f);
static void remove (const char *file, struct intr_frame *f);
static void open (const char *file, struct intr_frame *f);
static void filesize (int fd, struct intr_frame *f);
static void read (int fd, void *buffer, unsigned length, struct intr_frame *f);
static void write (int fd, const void *buffer, unsigned int length, struct intr_frame *f);
static void seek (int fd, unsigned position);
static void tell (int fd, struct intr_frame *f);
static void close (int fd);

struct fd_elem
{
  int fd;
  struct file *file;
  struct list_elem elem;
};

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  if (!filesys_lock_initialized)
  {
    lock_init(&filesys_lock);
    filesys_lock_initialized = true;
  }

  uint32_t syscall_num = *(uint32_t*)f->esp;
  // printf ("system call: %d!\n", syscall_num);
  uint32_t arg1 = 0;
  uint32_t arg2 = 0;
  uint32_t arg3 = 0;

  // initialize arguments
  if (syscall_num != SYS_HALT)
    arg1 = *(uint32_t*)(f->esp + 4);
  if (syscall_num == SYS_CREATE || syscall_num == SYS_READ 
      || syscall_num == SYS_WRITE || syscall_num == SYS_SEEK)
    arg2 = *(uint32_t*)(f->esp + 8);
  if (syscall_num == SYS_READ || syscall_num == SYS_WRITE)
    arg3 = *(uint32_t*)(f->esp + 12);

  // call syscall function
  switch (syscall_num)
    {
    case SYS_HALT:
      halt();
      break;
    case SYS_EXIT:
      exit_handler((int) arg1, f);
      break;
    case SYS_EXEC:
      exec((const char*) arg1, f);
      break;
    case SYS_WAIT:
      wait((pid_t) arg1, f);
      break;
    case SYS_CREATE:
      create((const char*) arg1, (unsigned int) arg2, f);
      break;
    case SYS_REMOVE:
      remove((const char*) arg1, f);
      break;
    case SYS_OPEN:
      open((const char*) arg1, f);
      break;
    case SYS_FILESIZE:
      filesize((int) arg1, f);
      break;
    case SYS_READ:
      read((int) arg1, (void *) arg2, (unsigned int) arg3, f);
      break;
    case SYS_WRITE:
      write((int) arg1, (const void *) arg2, (unsigned int) arg3, f);
      break;
    case SYS_SEEK:
      seek((int) arg1, (unsigned int) arg2);
      break;
    case SYS_TELL:
      tell((int) arg1, f);
      break;
    case SYS_CLOSE:
      close((int) arg1);
      break;
    }

}

static void
free_resources(void)
{
  // free locks and close file descriptors
  return;
}

static struct list_elem *
list_find_fd_elem(struct thread *t, int fd)
{
  struct list_elem *e;

  for (e = list_begin (&t->fd_list); e != list_end (&t->fd_list);
        e = list_next (e))
    {
      struct fd_elem *f = list_entry (e, struct fd_elem, elem);
      if (f->fd == fd)
        return e;
    }
  
  return NULL;
}

static void
verify_pointer(const void *pointer)
{
  if (pointer == NULL || is_kernel_vaddr(pointer))
  {
    // print exit message
    free_resources();
    thread_exit();
  }
  if (is_user_vaddr(pointer))
  {
    uint32_t *pd = thread_current()->pagedir;
    if (pagedir_get_page(pd, pointer) == NULL)
    {
      // print exit message
      free_resources();
      thread_exit();
    }
  }
}

static void
halt(void)
{

}

static void
exit_handler(int status, struct intr_frame *f)
{
  printf("exiting\n");
  f->eax = status;
  thread_exit();
}

static void
exec(const char *file, struct intr_frame *f)
{
  verify_pointer((void *) file);
  pid_t pid = process_execute(file);
}

static void
wait(pid_t pid, struct intr_frame *f)
{
  int i = 0;
  while (1)
  {
    i++;
  }
}

static void
create(const char *file, unsigned initial_size, struct intr_frame *f)
{
  verify_pointer((void *) file);
  lock_acquire(&filesys_lock);
  bool success = filesys_create(file, initial_size);
  lock_release(&filesys_lock);
  f->eax = success;
}

static void
remove(const char *file, struct intr_frame *f)
{
  verify_pointer((void *) file);
  lock_acquire(&filesys_lock);
  bool success = filesys_remove(file);
  lock_release(&filesys_lock);
  f->eax = success;
}

static void
open (const char *file, struct intr_frame *f)
{
  verify_pointer((void *) file);
  lock_acquire(&filesys_lock);
  struct file *opened_file = filesys_open(file);
  lock_release(&filesys_lock);
  if (opened_file == NULL)
  {
    f->eax = -1;
    return;
  }
  struct thread *t = thread_current();
  int fd = t->fd;
  struct fd_elem opened_fd;
  opened_fd.fd = fd;
  opened_fd.file = opened_file;
  list_push_back(&t->fd_list, &opened_fd.elem);
  t->fd++;
  f->eax = fd;
}

static void
filesize (int fd, struct intr_frame *f)
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

static void
read (int fd, void *buffer, unsigned length, struct intr_frame *f)
{
  verify_pointer(buffer);
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

static void
write (int fd, const void *buffer, unsigned int length, struct intr_frame *f)
{
  verify_pointer(buffer);
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

static void
seek (int fd, unsigned position)
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

static void
tell (int fd, struct intr_frame *f)
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

static void
close (int fd)
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
}
