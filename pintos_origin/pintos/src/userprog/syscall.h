#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "lib/stdint.h"
#include "lib/kernel/list.h"
#include "filesys/file.h"

typedef int pid_t;

struct file_descriptor {
  int handle;
  struct file* file;
  struct list_elem elem;
};

void syscall_init (void);

static void copy_in (void *dst_ , void *usrc_ , size_t size );

struct lock fs_lock;

#endif /* userprog/syscall.h */
