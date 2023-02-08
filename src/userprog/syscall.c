#include "userprog/syscall.h"
#include "userprog/pagedir.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

typedef int pid_t;

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

static void exec (const char *file);
static void wait (pid_t pid_t);
static void create (const char *file, unsigned initial_size);
static void remove (const char *file);
static void open (const char *file);
static void filesize (int fd);
static void read (int fd, void *buffer, unsigned length);
static void write (int fd, const void *buffer, unsigned int length, struct intr_frame *f);
static void seek (int fd, unsigned position);
static void tell (int fd);
static void close (int fd);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
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
      exec((const char*) arg1);
      break;
    case SYS_WAIT:
      wait((pid_t) arg1);
      break;
    case SYS_CREATE:
      create((const char*) arg1, (unsigned int) arg2);
      break;
    case SYS_REMOVE:
      remove((const char*) arg1);
      break;
    case SYS_OPEN:
      open((const char*) arg1);
      break;
    case SYS_FILESIZE:
      filesize((int) arg1);
      break;
    case SYS_READ:
      read((int) arg1, (void *) arg2, (unsigned int) arg3);
      break;
    case SYS_WRITE:
      write((int) arg1, (const void *) arg2, (unsigned int) arg3, f);
      break;
    case SYS_SEEK:
      seek((int) arg1, (unsigned int) arg2);
      break;
    case SYS_TELL:
      tell((int) arg1);
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
  // set the parent thread's status here
  // -----------------------------------

  printf("%s: exit(%d)\n", thread_current()->name, status);
  thread_exit();
}

static void
exec(const char *file)
{
  verify_pointer((void *) file);
}

static void
wait(pid_t pid)
{
  int i = 0;
  while (1)
  {
    i++;
  }
}

static void
create(const char *file, unsigned initial_size)
{
  verify_pointer((void *) file);
}

static void
remove(const char *file)
{
  verify_pointer((void *) file);
}

static void
open (const char *file)
{
  verify_pointer((void *) file);
}

static void
filesize (int fd)
{
}

static void
read (int fd, void *buffer, unsigned length)
{
  verify_pointer(buffer);
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
  int written = 0;
  // TODO: write to file as much as we can
  f->eax = written;
}

static void
seek (int fd, unsigned position)
{

}

static void
tell (int fd)
{
  
}

static void
close (int fd)
{

}
