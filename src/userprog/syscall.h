#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "threads/interrupt.h"
#include "list.h"

typedef void (*syscall_function) (struct intr_frame *);
#define SYSCALL_NUMBER 14

void syscall_init (void);

void check(void *);
void check_func_args(void *, int);
void check_page(void *);
void check_addr(void *p);

// declarations of syscalls
void sys_exit(struct intr_frame *);
void sys_halt(struct intr_frame *);
void sys_exec(struct intr_frame *);
void sys_wait(struct intr_frame *);
void sys_create(struct intr_frame *);
void sys_remove(struct intr_frame *);
void sys_open(struct intr_frame *);
void sys_filesize(struct intr_frame *);
void sys_read(struct intr_frame *);
void sys_write(struct intr_frame *);
void sys_seek(struct intr_frame *);
void sys_tell(struct intr_frame *);
void sys_close(struct intr_frame *);


struct file_node * find_file(struct list *, int);
void exit(int);

// the struct of opened file
struct file_node {
    int fd;
    struct file *file;
    struct list_elem file_elem;
};
#endif /* userprog/syscall.h */
