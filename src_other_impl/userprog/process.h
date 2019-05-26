#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
typedef int mmapid_t;

struct file_node {
  int fd;
  struct list_elem elem;
  struct file *file;
};

struct child_process {

  char *file_name;          /* Transfer file_name to start process */

  tid_t tid;                /* Id of child process */
  struct thread *parent;    /* Parent process. */
  struct list_elem elem;    /* For list */

  bool waiting;             /* If child process is being waited. */
  bool finish;              /* If child process finished. */
  bool parent_finish;       /* If parent has terminated. */
  int exit;                 /* Exit code. */

  struct semaphore child_wait; /* the semaphore used for wait() : parent blocks until child exits */

};

struct mmap_node {
  mmapid_t id;
  struct list_elem elem;    /* List pointer */

  struct file *file;
  size_t size;              /* File size */
  void *vaddr;              /* Vaddr of node */
};


tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

#endif /* userprog/process.h */
