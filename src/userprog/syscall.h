#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init (void);
struct lock filesys_lock;
void exit_handler(int status);

#endif /* userprog/syscall.h */
