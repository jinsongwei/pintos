
#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

struct exec {
  bool success;
  struct semaphore loaded;
  char* file_name;
  struct wait_status* wait_status;
};

tid_t process_execute (struct exec*);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

int get_count(const char* s);

#endif /* userprog/process.h */
