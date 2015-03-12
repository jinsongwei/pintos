#include "userprog/syscall.h"
#include "userprog/process.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/syscall.h"
#include <string.h>
#include "devices/input.h"
#include "devices/shutdown.h"
#include "filesys/directory.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "threads/init.h"
#include "threads/malloc.h"
#include "threads/palloc.h"

void sys_halt(void);
void sys_exit(int );
//void sys_exit(void );
pid_t sys_exec(const char *);
int sys_wait(pid_t );
int sys_filesize(int );

bool sys_create(const char* , unsigned );
bool sys_remove(const char* );
int sys_open(const char *);

int sys_read(int , void *, unsigned );
int sys_write(int , void *, unsigned );
void sys_seek(int , unsigned );
unsigned sys_tell(int );
void sys_close(int );
bool verify_user(const void *);

static void syscall_handler (struct intr_frame *);
typedef int syscall_function (int, int, int);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&fs_lock);
}

static struct file_descriptor *lookup_fd (int handle)
{
  struct thread *cur = thread_current();
  struct list_elem *descs;
  for (descs = list_begin(&cur->fds); descs != list_end(&cur->fds); descs = list_next(descs)){
      struct file_descriptor *fd = list_entry(descs, struct file_descriptor, elem);
      if (fd->handle == handle){
          return fd;
      }
  }
  sys_exit(-1);
  return NULL; 
}


static inline int
get_user (uint8_t *dst, const uint8_t *usrc)
{
  if(is_user_vaddr(usrc) &&  is_kernel_vaddr(dst))
  {
    int eax;
    asm ("movl $1f, %%eax; movb %2, %%al; movb %%al, %0; 1:" : "=m" (*dst), "=&a" (eax) : "m" (*usrc));
    return eax != 0;
  }
  else
  {
    if(is_user_vaddr(usrc))
      printf("Kernel address is outside of its space: is %u\n", (unsigned)dst);
    if(is_kernel_vaddr(dst))
      sys_exit(-1);
    return 0;
  }
}


static void
copy_in (void *dst_, void *usrc_, size_t size) 
{
  uint8_t *dst = dst_;
  uint8_t *usrc = usrc_;
  uint8_t i = 0;
    while(i < size)
    {
        if(!get_user(dst + i, usrc+i))
            return;
        i++;
    }

}
bool verify_user(const void *uad)
{
    if(uad == NULL)
    {
        return false;
    }
    return (uad< PHYS_BASE
          && pagedir_get_page (thread_current ()->pagedir, uad) != NULL);
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{  
    struct syscall
  {
    size_t arg_cnt;
    syscall_function* func;
  };

  static const struct syscall syscall_table[] = 
  {
    {0,(syscall_function*) sys_halt},   
    {1,(syscall_function*) sys_exit},  
    {1,(syscall_function*) sys_exec},   
    {1,(syscall_function*) sys_wait},   
    {2,(syscall_function*) sys_create}, 
    {1,(syscall_function*) sys_remove}, 
    {1,(syscall_function*) sys_open},   
    {1,(syscall_function*) sys_filesize},
    {3,(syscall_function*) sys_read},  
    {3,(syscall_function*) sys_write},  
    {2,(syscall_function*) sys_seek},   
    {1,(syscall_function*) sys_tell},   
    {1,(syscall_function*) sys_close}   
  };

  const struct syscall* sc;
  unsigned call_nr;
  int args[3];

    if(!verify_user(f->esp))
    {
        sys_exit(-1);
    }
  //get system call
  copy_in (&call_nr, f->esp, sizeof call_nr);

  if (call_nr >= (sizeof syscall_table)/(sizeof *syscall_table))
    thread_exit();
  sc = syscall_table + call_nr;

  //get system call arguments
  ASSERT (sc->arg_cnt <= (sizeof args)/(sizeof *args));
  memset (args, 0, sizeof args);
  copy_in (args, (uint32_t *) f->esp + 1, sizeof *args * sc->arg_cnt);

  //execute system call
  f->eax = sc->func (args[0], args[1], args[2]);
}


void sys_halt(void)
{
  shutdown();
}

void sys_exit(int status) 
{
    struct thread* t = thread_current ();
    t->wait_status->exit_status = status;
  
 // t->wait_status->exit_status = status;

  printf("%s: exit(%d)\n", t->name, t->wait_status->exit_status);

  file_close(t->this_file);

  sema_up(&t->wait_status->done);
  thread_exit();
}

pid_t sys_exec(const char *ufile)
{

  struct exec exec;
  exec.success = false;
  sema_init(&exec.loaded,0);
  exec.file_name = ufile;
  int pid = process_execute(&exec);
  //palloc_free_page(ufile);
  if (!exec.success)
    pid = -1;
  return pid;
}


struct wait_status* find_child (tid_t child_tid)
{
  struct list_elem* e;
  struct wait_status* child_wait_status = NULL;
  struct thread* t = thread_current ();
  
  for (e = list_begin (&t->children); e != list_end (&t->children); e = list_next(e))
  {
    child_wait_status = list_entry (e, struct wait_status, elem);
    if (child_wait_status->tid == child_tid) break;
    else child_wait_status = NULL;
  }
  return child_wait_status;
}


void empty_children (struct thread* t)
{
  struct list_elem* e;
  struct wait_status* child_wait_status = NULL;

  if (t == NULL) t = thread_current ();

  for (e = list_begin (&t->children); e != list_end (&t->children); e = list_begin(&t->children))
  {
    child_wait_status = list_entry (e, struct wait_status, elem);
    list_remove(&child_wait_status->elem);
    free(child_wait_status);
    child_wait_status = NULL;
  }
}


int sys_wait(pid_t pid)
{
  int exit_status = -1;
  struct wait_status* child_wait_status = find_child (pid);
  if (child_wait_status != NULL)
  {
    list_remove (&child_wait_status->elem);
    sema_down (&child_wait_status->done);
    exit_status = child_wait_status->exit_status;
    free(child_wait_status);
  }
  return exit_status;
}


bool sys_create(const char* file, unsigned initial_size)
{
  if(!verify_user(file))
     sys_exit(-1);
  return filesys_create(file, initial_size);
}

bool sys_remove(const char* file)
{
 if(!verify_user(file))
     sys_exit(-1);
  return filesys_remove(file);
}

int sys_open (const char *ufile)
{
  struct file_descriptor *fd;
  int handle = -1;
    if(!verify_user(ufile))
     sys_exit(-1);
  
  fd = malloc (sizeof *fd);
  if (fd != NULL)
  {
    lock_acquire (&fs_lock);
    fd->file = filesys_open (ufile);
    if (fd->file != NULL)
    {
      struct thread *cur = thread_current ();
      handle = fd->handle = cur->next_handle++;
      list_push_front (&cur->fds, &fd->elem);
    }

  }
  else free (fd);
  lock_release (&fs_lock);
  return handle;
}

int sys_filesize(int fd)
{
  struct file_descriptor* file_d = lookup_fd(fd);
  if(file_d == NULL)
     sys_exit(-1);
  lock_acquire(&fs_lock);
  
  int len = file_length(file_d->file);
  lock_release(&fs_lock);
  return len;
}

int sys_read (int handle, void *udst_, unsigned size) 
{
  uint8_t *udst = udst_;
  struct file_descriptor *fd = NULL;
  int bytes_read = 0;

  if(handle != STDIN_FILENO)
      fd = lookup_fd(handle);
  if(fd == NULL)
      return -1;

  lock_acquire(&fs_lock);
  while(size > 0){
      size_t pages_left = PGSIZE - pg_ofs(udst);
      size_t read_amt = size < pages_left ? size : pages_left;
      off_t retval;

      if(!verify_user(udst))
      {
          lock_release(&fs_lock);
          thread_exit();
      }
      if(handle == STDIN_FILENO)
      {
          strlcat(udst, input_getc(), 1);
          retval = 1;
      }else{
          retval = file_read(fd->file, udst, read_amt);
      }
      if(retval < 0)
      {
          if (bytes_read == 0)
              bytes_read = -1;
          break;
      }
      bytes_read += retval;
      if(retval != (off_t) read_amt)
          break;
      udst += retval;
      size -= retval;
  }
  lock_release(&fs_lock);
  return bytes_read;
}
int sys_write (int handle, void *usrc_, unsigned size) 
{
  uint8_t *usrc = usrc_;
  struct file_descriptor *fd = NULL;
  int bytes_written = 0;

  if(!verify_user(usrc_) || !verify_user(usrc_+size)){
      sys_exit(-1);
  }
  if (handle != STDOUT_FILENO)
    fd = lookup_fd (handle);

  lock_acquire (&fs_lock);
  while (size > 0) 
    {
      size_t page_left = PGSIZE - pg_ofs (usrc);
      size_t write_amt = size < page_left ? size : page_left;
      off_t retval;

      if (!verify_user (usrc)) 
        {
          lock_release (&fs_lock);
          sys_exit(-1);
        }

      if (handle == STDOUT_FILENO)
        {
          putbuf (usrc, write_amt);
          retval = write_amt;
        }
      else
        retval = file_write (fd->file, usrc, write_amt);
      if (retval < 0) 
        {
          if (bytes_written == 0)
            bytes_written = -1;
          break;
        }
      bytes_written += retval;

      if (retval != (off_t) write_amt)
        break;

      usrc += retval;
      size -= retval;
    }
  lock_release (&fs_lock);
 
  return bytes_written;
}

void sys_seek(int fd, unsigned position)
{
  struct file_descriptor* file_d = lookup_fd(fd);
  if (file_d == NULL) sys_exit(-1);
  file_seek(file_d->file,position);
}

unsigned sys_tell(int fd)
{
  struct file_descriptor* file_d = lookup_fd(fd);
  if (file_d == NULL) sys_exit(-1);

  return file_tell(file_d);
}

void sys_close(int fd)
{
  struct file_descriptor* file_d = lookup_fd(fd);
  if (file_d == NULL) 
    sys_exit(-1);

  lock_acquire(&fs_lock);
  file_close(file_d->file);
  list_remove(&file_d->elem);
  free(file_d);
  lock_release(&fs_lock);
}

