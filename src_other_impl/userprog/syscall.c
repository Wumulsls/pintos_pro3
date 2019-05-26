#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "userprog/process.h"
#include "pagedir.h"
#include "devices/shutdown.h"
#include "devices/input.h"
#include "threads/palloc.h"
#include "vm/page.h"


static struct mmap_node* get_m_node (mmapid_t fd);
static void syscall_handler (struct intr_frame *);
/* Some help function */
struct file_node *get_node (int fd);
static bool put_user (uint8_t *udst, uint8_t byte);
static int32_t get_user (const uint8_t *uaddr);
void is_valid_addr (void *addr);





/* sys_call function */
void halt (void);
pid_t exec (const char *cmd_line);
int wait (pid_t pid);
bool create (const char *file, unsigned initial_size);
bool remove (const char *file);
int open (const char *file);
int filesize (int fd);
int read (int fd, void *buffer, unsigned size);
int write (int fd, const void *buffer, unsigned size);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);
mmapid_t map(int fd, void *);

struct lock sys_lock;

void
syscall_init (void)
{
  lock_init (&sys_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED)
{
  int *sys_call = (int *)f->esp;
  is_valid_addr (sys_call);
  if ((int)(*sys_call) < 1 || (int)(*sys_call) > 19)
    exit (-1);
  int *sys_buffer = (int *)f->esp + 1;
  int *sys_size = (int *)f->esp + 2;
  int *sys_size1 = (int *)f->esp + 3;

  thread_current()->esp = f->esp;
  switch(*sys_call){
    case SYS_HALT:
      {
        halt ();
        break;
      }
    case SYS_EXIT:
      {
        is_valid_addr (sys_buffer);
        exit(*sys_buffer);
        break;
      }
    case SYS_EXEC:
      {
        is_valid_addr (sys_buffer);
        f->eax = exec ((const char*)(*sys_buffer));
        break;
      }
    case SYS_WAIT:
      {
        is_valid_addr (sys_buffer);
        f->eax = wait ((pid_t)(*sys_buffer));
        break;
      }
    case SYS_CREATE:
      {
        is_valid_addr (sys_buffer);
        is_valid_addr (sys_size);

        f->eax = create ((const char*)(*sys_buffer),(unsigned)(*sys_size));
        break;
      }
    case SYS_REMOVE:
      {
        is_valid_addr (sys_buffer);
        f->eax = remove ((const char*)(*sys_buffer));
        break;
      }
    case SYS_OPEN:
      {
        is_valid_addr (sys_buffer);
        f->eax = open ((const char *)(*sys_buffer));

        break;
      }
    case SYS_FILESIZE:
      {
        is_valid_addr (sys_buffer);
        f->eax = filesize (*sys_buffer);
        break;
      }
    case SYS_READ:
      {
        is_valid_addr (sys_buffer);
        is_valid_addr (sys_size);
        is_valid_addr (sys_size1);
        f->eax = read (*sys_buffer, (void *)(*sys_size), (unsigned)(*sys_size1));
        break;
      }

    case SYS_WRITE:
      {
        is_valid_addr (sys_buffer);
        is_valid_addr (sys_size);
        is_valid_addr (sys_size1);
        f->eax = write (*sys_buffer, (const void *)(*sys_size), (unsigned)(*sys_size1));

        break;
      }

    case SYS_SEEK:
      {
        is_valid_addr (sys_buffer);
        is_valid_addr (sys_size);
        seek(*sys_buffer, (unsigned)(*sys_size));
        break;
      }
    case SYS_TELL:
      {
        is_valid_addr (sys_buffer);
        f->eax = tell(*sys_buffer);
        break;
      }
    case SYS_CLOSE:
      {
        is_valid_addr (sys_buffer);
        close(*sys_buffer);
        break;
      }
    case SYS_MMAP:
      {
        is_valid_addr (sys_buffer);
        is_valid_addr (sys_size);
        f->eax = map (*sys_buffer, (void *)(*sys_size));
        break;
      }
    case SYS_MUNMAP:
      {
        is_valid_addr (sys_buffer);
        munmap (*sys_buffer);
        break;
      }
  }
}


struct file_node *
get_node (int fd)
{
  struct thread *cur = thread_current ();
  struct file_node *node = NULL;
  struct list_elem *e;
  /* Search node in file_list */
  if (list_empty(&cur->fn_list))
    return NULL;
  for(e = list_begin (&cur->fn_list); e != list_end (&cur->fn_list); e = list_next (e))
    {
      node = list_entry(e, struct file_node, elem);
      if(node->fd == fd)
        return node;
    }
  return NULL;
}

static bool
put_user (uint8_t *udst, uint8_t byte)
{
  /* Check addr*/
  if ((void*)udst >= PHYS_BASE)
    return false;
  int error_code;
  asm ("movl $1f, %0; movb %b2, %1; 1:"
      : "=&a" (error_code), "=m" (*udst) : "q" (byte));
  return error_code != -1;
}

static int32_t
get_user (const uint8_t *uaddr)
{
  /* Check addr*/
  if ((void*)uaddr >= PHYS_BASE)
    return -1;
  int result;
  asm ("movl $1f, %0; movzbl %1, %0; 1:"
      : "=&a" (result) : "m" (*uaddr));
  return result;
}

/* Check addr and memory */
void
is_valid_addr (void *addr)
{
  if (get_user (addr) == -1)
    {
      if (lock_held_by_current_thread (&sys_lock))
        lock_release (&sys_lock);
      exit (-1);
    }
}


void
halt (void)
{
  shutdown_power_off ();
}

void
exit (int status)
{
  struct child_process *child = thread_current ()->child;
  if (child != NULL)
    child->exit = status;
  printf ("%s: exit(%d)\n", thread_current ()->name, status);
  thread_exit ();
}

pid_t
exec (const char *cmd_line)
{
  is_valid_addr ((void *)cmd_line);
  lock_acquire (&sys_lock);
  pid_t pid = (pid_t)process_execute (cmd_line);
  lock_release (&sys_lock);
  return pid;
}

int
wait (pid_t pid)
{
  return process_wait (pid);
}

bool
create (const char *file, unsigned initial_size)
{
  is_valid_addr ((void *)file);
  bool temp;
  lock_acquire (&sys_lock);
  temp =  filesys_create (file, initial_size);
  lock_release (&sys_lock);
  return temp;
}

bool
remove (const char *file)
{
  is_valid_addr ((void *)file);
  bool temp;
  lock_acquire (&sys_lock);
  temp =  filesys_remove (file);
  lock_release (&sys_lock);
  return temp;
}

int
open (const char *file)
{
  is_valid_addr ((void *)file);
  struct file_node* node = palloc_get_page(0);
  if (!node)
    return -1;
  struct file *file_open;
  lock_acquire (&sys_lock);
  file_open = filesys_open(file);
  if (!file_open) {
    palloc_free_page (node);
    lock_release (&sys_lock);
    return -1;
  }
  node->file = file_open;

  struct list* fn_list = &thread_current()->fn_list;
  if (list_empty (fn_list))
  {
    node->fd = 3;
  }
  else
    node->fd = (list_entry (list_back (fn_list), struct file_node, elem)->fd) + 1;
  list_push_back(fn_list, &node->elem);
  lock_release (&sys_lock);
  return node->fd;
}

int
filesize (int fd)
{
  struct file_node *node = NULL;
  int temp;
  lock_acquire (&sys_lock);
  node = get_node (fd);
  if (node == NULL) {
    lock_release (&sys_lock);
    return -1;
  }
  temp = file_length(node->file);
  lock_release (&sys_lock);
  return temp;
}

int
read (int fd, void *buffer, unsigned size)
{
  /* Check head and tail */
  is_valid_addr (buffer);
  is_valid_addr (buffer + size - 1);
  lock_acquire (&sys_lock);

  if (fd == STDIN_FILENO)
    {
      for (unsigned i = 0; i < size; i++)
        {
          if (!put_user (buffer + i, input_getc ()) )
            {
              lock_release (&sys_lock);
              exit (-1);
            }
        }
      lock_release (&sys_lock);
      return (int)size;
    }

  struct file_node* node = get_node (fd);
  if (node == NULL || node->file == NULL)
    {
      lock_release (&sys_lock);
      return -1;
    }
  /* Load and pin all pages */
  struct thread *cur = thread_current();
  uint32_t *pagedir = cur->pagedir;
  for(void *upage = pg_round_down (buffer); upage < buffer + size; upage += PGSIZE)
    {
      load_page (cur->spt, pagedir, upage);
      pin_page (cur->spt, upage);
    }
  int temp = file_read (node->file, buffer, size);
  /* Unpin pages */
  for (void *upage = pg_round_down (buffer); upage < buffer + size; upage += PGSIZE)
    unpin_page (cur->spt, upage);

  lock_release (&sys_lock);
  return temp;
}



int
write (int fd, const void *buffer, unsigned size)
{
  is_valid_addr ((void *)buffer);
  is_valid_addr ((void *)buffer + size - 1);
  lock_acquire (&sys_lock);
  if(fd == STDOUT_FILENO)
    {
      putbuf (buffer, size);
      lock_release (&sys_lock);
      return (int)size;
    }
  struct file_node *node = get_node (fd);
  if (node == NULL || node->file == NULL)
    {
      lock_release (&sys_lock);
      return -1;
    }
  /* Load and pin all pages */
  struct thread *cur = thread_current();
  struct spt *spt = cur->spt;
  uint32_t *pagedir = cur->pagedir;
  for (void *upage = pg_round_down (buffer); upage < buffer + size; upage += PGSIZE)
    {
      load_page (spt, pagedir, upage);
      pin_page (spt, upage);
    }

  int temp = file_write (node->file, buffer, size);
  /* Unpin pages */
  for (void *upage = pg_round_down (buffer); upage < buffer + size; upage += PGSIZE)
    unpin_page (spt, upage);

  lock_release (&sys_lock);
  return temp;
}

void
seek (int fd, unsigned position)
{
  lock_acquire (&sys_lock);
  struct file_node *node = get_node (fd);
  if (node == NULL || node->file == NULL)
    {
      lock_release (&sys_lock);
      return;
    }
  file_seek(node->file, position);
  lock_release (&sys_lock);
}

unsigned
tell (int fd)
{
  lock_acquire (&sys_lock);
  struct file_node *node = get_node (fd);
  if (node == NULL || node->file == NULL)
    {
      lock_release (&sys_lock);
      return -1;
    }
  unsigned temp = file_tell (node->file);
  lock_release (&sys_lock);
  return temp;
}

void
close (int fd)
{
  lock_acquire (&sys_lock);
  struct file_node *node = get_node (fd);
  if (node == NULL || node->file == NULL)
    {
      lock_release (&sys_lock);
      return;
    }
  file_close(node->file);
  list_remove(&node->elem);
  palloc_free_page(node);
  lock_release (&sys_lock);
}

mmapid_t map (int fd, void *upage) {
  if (upage == NULL || pg_ofs(upage) != 0 || fd < 2)
    return -1;

  struct thread *cur = thread_current();

  lock_acquire (&sys_lock);

  /* Open file */
  struct file *file = NULL;
  struct file_node* node = get_node (fd);
  if(node && node->file)
    file = file_reopen (node->file);

  /* Check open state */
  if(file == NULL)
    {
      lock_release (&sys_lock);
      return -1;
    }
  size_t file_size = file_length(file);
  if(file_size == 0)
    {
      lock_release (&sys_lock);
      return -1;
    }

  /* Check page addr */
  for (size_t ofs = 0; ofs < file_size; ofs += PGSIZE)
    {
      void *addr = upage + ofs;
      if (get_spte (cur->spt, addr) != NULL)
        {
          lock_release (&sys_lock);
          return -1;
        }
    }
  /* Map pages */
  for (size_t ofs = 0; ofs < file_size; ofs += PGSIZE)
    {
      void *addr = upage + ofs;
      size_t zero_bytes = 0;
      size_t read_bytes = PGSIZE;
      if (ofs + PGSIZE >= file_size)
      {
        read_bytes =  file_size - ofs;
        zero_bytes = PGSIZE - read_bytes;

      }
      spt_add_file (cur->spt, addr, file, ofs, read_bytes, zero_bytes, /*writable*/true);
    }
  /* Assign an id */
  mmapid_t mmapid;
  if (list_empty (&cur->mmap_list))
    mmapid = 1;
  else
    mmapid = list_entry (list_back (&cur->mmap_list), struct mmap_node, elem)->id + 1;

  struct mmap_node *m_node = (struct mmap_node *)malloc (sizeof (struct mmap_node));
  m_node->id = mmapid;
  m_node->file = file;
  m_node->size = file_size;
  m_node->vaddr = upage;
  list_push_back (&cur->mmap_list, &m_node->elem);

  lock_release (&sys_lock);
  return mmapid;
}

bool munmap (mmapid_t mmapid)
{
  struct thread *cur = thread_current();
  struct mmap_node *node = get_m_node (mmapid);

  if (node == NULL)
    return false;

  lock_acquire (&sys_lock);
  size_t file_size = node->size;
  for(size_t ofs = 0; ofs < file_size; ofs += PGSIZE)
    {
      void *addr = node->vaddr + ofs;
      size_t bytes = PGSIZE;
      if (ofs + PGSIZE >= file_size)
        bytes = file_size - ofs;
      spt_unmap (cur->spt, cur->pagedir, addr, node->file, ofs, bytes);
    }
  /* Close file and delete node */
  list_remove (&node->elem);
  file_close (node->file);
  free (node);
  lock_release (&sys_lock);
  return true;
}

static struct mmap_node*
get_m_node (mmapid_t mmapid)
{
  struct thread *cur = thread_current();
  struct list_elem *e;
  if (list_empty(&cur->mmap_list))
    return NULL;

  for (e = list_begin (&cur->mmap_list); e != list_end (&cur->mmap_list); e = list_next (e))
    {
      struct mmap_node *node = list_entry(e, struct mmap_node, elem);
      if (node->id == mmapid)
        return node;
    }
  return NULL;
}
