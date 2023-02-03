#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

typedef int pid_t;

static void syscall_handler (struct intr_frame *);
static void halt (void) NO_RETURN;
static void exit (int status, struct intr_frame *f) NO_RETURN;
static pid_t exec (const char *file);
static int wait (pid_t pid_t);
static bool create (const char *file, unsigned initial_size);
static bool remove (const char *file);
static int open (const char *file);
static int filesize (int fd);
static int read (int fd, void *buffer, unsigned length);
static int write (int fd, const void *buffer, unsigned length);
static void seek (int fd, unsigned position);
static unsigned tell (int fd);
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
  uint32_t arg1;
  uint32_t arg2;
  uint32_t arg3;

  // initialize arguments
  if (syscall_num != SYS_HALT)
    arg1 = *(uint32_t*)(f->esp + 1);
  if (syscall_num == SYS_CREATE || syscall_num == SYS_READ 
      || syscall_num == SYS_WRITE || syscall_num == SYS_SEEK)
    arg2 = *(uint32_t*)(f->esp + 2);
  if (syscall_num == SYS_READ || syscall_num == SYS_WRITE)
    arg3 = *(uint32_t*)(f->esp + 3);

  // call syscall function
  switch (syscall_num)
    {
    case SYS_HALT:
      halt();
      break;
    case SYS_EXIT:
      exit((int) arg1, f);
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
      write((int) arg1, (const void *) arg2, (unsigned int) arg3);
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

  printf ("system call: %d!\n", syscall_num);
  thread_exit ();
}

static void
halt(void)
{

}

static void
exit(int status, struct intr_frame *f)
{
  f->eax = status;
  thread_exit();
}

static pid_t
exec(const char *file)
{
  return -1;
}

static int
wait(pid_t pid)
{
  return -1;
}

static bool
create(const char *file, unsigned initial_size)
{
  return false;
}

static bool
remove(const char *file)
{
  return false;
}

static int
open (const char *file)
{
  return -1;
}

static int
filesize (int fd)
{
  return -1;
}

static int
read (int fd, void *buffer, unsigned length)
{
  return -1;
}

static int
write (int fd, const void *buffer, unsigned length)
{
  return -1;
}

static void
seek (int fd, unsigned position)
{

}

static unsigned
tell (int fd)
{
  return 0;
}

static void
close (int fd)
{

}
