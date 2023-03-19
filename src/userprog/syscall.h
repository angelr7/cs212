#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <stdbool.h>
#include "filesys/directory.h"


void syscall_init (void);
struct lock filesys_lock;
void exit_handler(int status);

bool parse_path (const char *path, struct dir **last_dir, char *last_name);



#endif /* userprog/syscall.h */
