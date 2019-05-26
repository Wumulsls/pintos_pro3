#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "threads/synch.h"

typedef int pid_t;
typedef int mmapid_t;

void exit (int status);
void syscall_init (void);
/* Called in process.c */
bool munmap(mmapid_t mmapid);

#endif /* userprog/syscall.h */
