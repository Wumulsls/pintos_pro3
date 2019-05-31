#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "threads/interrupt.h"
#include "list.h"

typedef void (*syscall_function) (struct intr_frame *);
#define SYSCALL_NUMBER 20

// the struct of opened file
struct file_node {
    int fd;
    struct file *file;
    struct list_elem file_elem;
    struct dir* dir;
};
#endif /* userprog/syscall.h */

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

void sys_chdir(struct intr_frame * f);
void sys_mkdir(struct intr_frame * f);
void sys_readdir(struct intr_frame * f);
void sys_isdir(struct intr_frame * f);
void sys_inumber(struct intr_frame * f);

// struct file_node *find_file(struct list *files, int fd, enum fd_search_filter flag);
void exit(int);
