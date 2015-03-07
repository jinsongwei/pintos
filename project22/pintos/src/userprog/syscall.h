#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "lib/stdint.h"
#include "lib/kernel/list.h"

typedef int pid_t;
struct file_descriptor {
  int handle;
  struct file* file;
  struct list_elem elem;
};


void syscall_init (void);

void sys_halt(void);
void sys_exit(int status);
pid_t sys_exec(const char *cmd_line);
int sys_wait(pid_t pid);
int sys_filesize(int fd);

bool sys_create(const char* file, unsigned initial_size);
bool sys_remove(const char* file);
int sys_open(const char *file);

int sys_read(int fd, void *buffer, unsigned size);
int sys_write(int fd, void *buffer, unsigned size);
void sys_seek(int fd, unsigned position);
unsigned sys_tell(int fd);
void sys_close(int fd);


struct file_descriptor* get_file(int fd);

int copy_in (uint8_t* dest, uint8_t* src, uint8_t size);

struct lock fs_lock;

#endif /* userprog/syscall.h */
