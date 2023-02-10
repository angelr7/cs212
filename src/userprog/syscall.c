#include "devices/input.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "userprog/syscall.h"
#include "userprog/pagedir.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syscall-nr.h>
#include "devices/shutdown.h"
#include "userprog/process.h"
#include "threads/interrupt.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

typedef int pid_t;



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

static struct lock filesys_lock;
static bool filesys_lock_initialized = false;
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
  // verify_pointer(f, sizeof(struct intr_frame));
  if (!filesys_lock_initialized)
  {
    lock_init(&filesys_lock);
    filesys_lock_initialized = true;
  }

  verify_pointer(f->esp, sizeof(uint32_t));
  uint32_t syscall_num = *(uint32_t *)f->esp;
  // printf ("system call: %d!\n", syscall_num);
  uint32_t arg1 = 0;
  uint32_t arg2 = 0;
  uint32_t arg3 = 0;

  // initialize arguments
  if (syscall_num != SYS_HALT)
  {
    verify_pointer(f->esp + 4, sizeof(uint32_t));
    arg1 = *(uint32_t *)(f->esp + 4);
  }
  if (syscall_num == SYS_CREATE || syscall_num == SYS_READ || syscall_num == SYS_WRITE || syscall_num == SYS_SEEK)
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

/*Verify pointer address sent to us, if buffer validate that end byte is also valid */
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
    if (pagedir_get_page(pd, pointer) == NULL || pagedir_get_page(pd, last_byte) == NULL)
    {
      exit_handler(-1);
    }
  }
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
  uint32_t *pd;

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
    else child->tried_to_free = true;
  }
  /*loop through fd_list and free fds*/
  lock_acquire(&filesys_lock);
  struct fd_elem *prev = NULL;
  for (struct list_elem *e = list_begin(&cur->fd_list); 
    e != list_end(&cur->fd_list); 
    e = list_next(e)) 
  {
    if (prev) free(prev);
    struct fd_elem *fd_elem = list_entry(e, struct fd_elem, elem);
    file_close(fd_elem->file);
    prev = fd_elem;
  }
  if (prev) free(prev);
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
  verify_pointer((void *)file, sizeof(char *));
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
  verify_pointer((void *)file, sizeof(char *));
  lock_acquire(&filesys_lock);
  bool success = filesys_create(file, initial_size);
  lock_release(&filesys_lock);
  f->eax = success;
}

/*Remove file*/
static void
remove(const char *file, struct intr_frame *f)
{
  verify_pointer((void *)file, sizeof(char *));
  lock_acquire(&filesys_lock);
  bool success = filesys_remove(file);
  lock_release(&filesys_lock);
  f->eax = success;
}

/*Open file*/
static void
open(const char *file, struct intr_frame *f)
{
  verify_pointer((void *)file, sizeof(char *));
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
  struct fd_elem *opened_fd = malloc (sizeof (struct fd_elem));;
  opened_fd->fd = fd;
  opened_fd->file = opened_file;
  list_push_back(&t->fd_list, &opened_fd->elem);
  t->fd++;
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
  verify_pointer(buffer, sizeof(void *));
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
  verify_pointer(buffer, sizeof(void *));
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
