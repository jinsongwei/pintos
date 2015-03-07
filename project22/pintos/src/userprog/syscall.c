#include "userprog/syscall.h"
#include "userprog/process.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"


static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&fs_lock);
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  if(is_kernel_vaddr(f->esp))
    sys_exit(-1);

  typedef int syscall_function (int, int, int);

  struct syscall
  {
    size_t arg_cnt;
    syscall_function* func;
  };

  static const struct syscall syscall_table[] = 
  {
    {0,(syscall_function*) sys_halt},   //0
    {1,(syscall_function*) sys_exit},   //1
    {1,(syscall_function*) sys_exec},   //2
    {1,(syscall_function*) sys_wait},   //3
    {2,(syscall_function*) sys_create}, //4
    {1,(syscall_function*) sys_remove}, //5
    {1,(syscall_function*) sys_open},   //6
    {1,(syscall_function*) sys_filesize},//7
    {3,(syscall_function*) sys_read},   //8
    {3,(syscall_function*) sys_write},  //9
    {2,(syscall_function*) sys_seek},   //10
    {1,(syscall_function*) sys_tell},   //11
    {1,(syscall_function*) sys_close}   //12
  };

  struct syscall* sc;
  unsigned call_nr;
  int args[3];

  copy_in (&call_nr, f->esp, sizeof call_nr);

  if (call_nr >= (sizeof syscall_table)/(sizeof *syscall_table))
    thread_exit();
  sc = syscall_table + call_nr;

  ASSERT (sc->arg_cnt <= (sizeof args)/(sizeof *args));
  memset (args, 0, sizeof args);
  copy_in (args, (uint32_t *) f->esp + 1, sizeof *args * sc->arg_cnt);

  f->eax = sc->func (args[0], args[1], args[2]);
}

/* Copies a byte from user address USRC to kernel address DST. */
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

/* Writes BYTE to user address UDST. */
static inline int
put_user (uint8_t *udst, uint8_t byte)
{
  if(is_user_vaddr(udst))
  {
    int eax;
    asm ("movl $1f, %%eax; movb %b2, %0; 1:" : "=m" (*udst), "=&a" (eax) : "q" (byte));
    return eax != 0;
  }
  else
  {
    return 0;
  }
}

int copy_in (uint8_t* dest, uint8_t* src, uint8_t size)
{
  uint8_t i = 0;
  for(; i < size; i++)
  {
    if(!get_user(dest+i, src+i))
        return 0;
  }
  return 1;
}

void sys_halt(void)
{
  shutdown_power_off();
}

void sys_exit(int status) 
{
  struct thread* t = thread_current ();
  t->wait_status->exit_status = status;
  printf("%s: exit(%d)\n", thread_current()->name, status);

  file_close(t->this_file);

  sema_up(&t->wait_status->done);
  thread_exit();
}

pid_t sys_exec(const char *cmd_line)
{
  struct exec exec;
  exec.success = false;
  sema_init(&exec.loaded,0);
  exec.file_name = cmd_line;
  int pid = process_execute(&exec);
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
  if(file == NULL) sys_exit(-1);
  return filesys_create(file, initial_size);
}

bool sys_remove(const char* file)
{
  if (file == NULL) sys_exit(-1);
  return filesys_remove(file);
}

int sys_open (const char *ufile)
{
  struct file_descriptor *fd;
  int handle = -1;

  if (ufile == NULL) sys_exit(-1);

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
  struct file_descriptor* file_d = get_file(fd);
  int len = -1;
  if (file_d == NULL) sys_exit(-1);
  len = file_length(file_d->file);
  return len;
}

int sys_read(int fd, void *buffer, unsigned size)
{
  if (!is_user_vaddr(buffer)) sys_exit(-1);//exit if the buffer to read to is not in user space
  int bytes_read = -1;

  if (fd == STDIN_FILENO)
  {
    for (bytes_read = 0; bytes_read < size; bytes_read++)
      *((char*)buffer+bytes_read) = input_getc();
  }
  else if (fd == STDOUT_FILENO) sys_exit(-1);//read from stdout == BAD
  else
  {
    lock_acquire(&fs_lock);
    struct file_descriptor* file_d = get_file(fd);
    if (file_d != NULL)
      bytes_read = file_read (file_d->file,buffer,size);
    lock_release(&fs_lock);
  }
  return bytes_read;
}

int sys_write(int fd, void *buffer, unsigned size)
{
  int bytes_written = -1;

  if (!is_user_vaddr(buffer)) sys_exit(-1);
  if(fd == STDOUT_FILENO) {
    putbuf(buffer, size);
    bytes_written = size;
  }
  else if (fd == STDIN_FILENO)
    sys_exit(-1);
  else
  {
    lock_acquire(&fs_lock);
    struct file_descriptor* file_d = get_file(fd);
    if (file_d != NULL)
      bytes_written = file_write(file_d->file,buffer,size);
    lock_release(&fs_lock);
  }

  return bytes_written;
}

void sys_seek(int fd, unsigned position)
{
  struct file_descriptor* file_d = get_file(fd);
  if (file_d == NULL) sys_exit(-1);
  file_seek(file_d->file,position);
}

unsigned sys_tell(int fd)
{
  struct file_descriptor* file_d = get_file(fd);
  if (file_d == NULL) sys_exit(-1);

  return file_tell(file_d);
}

void sys_close(int fd)
{
  struct file_descriptor* file_d = get_file(fd);
  if (file_d == NULL) sys_exit(-1);

  lock_acquire(&fs_lock);
  file_close(file_d->file);
  list_remove(&(file_d->elem));
  free(file_d);
  lock_release(&fs_lock);
}

struct file_descriptor* get_file(int fd)
{
  struct list_elem* e;
  struct file_descriptor* file_d = NULL;
  struct thread* t = thread_current();
  for (e = list_begin (&(t->fds)); e != list_end (&(t->fds)); e = list_next(e))
  {
    file_d = list_entry (e, struct file_descriptor, elem);
    if (file_d->handle == fd) break;
    else file_d = NULL;
  }
  return file_d;
}
