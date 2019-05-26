#ifndef VM_FRAME_H
#define VM_FRAME_H

#include "threads/synch.h"
#include "threads/palloc.h"

/* Frame node */
struct frame_node
  {
    void *kpage;
    void *upage;

    struct list_elem l_elem;
    struct hash_elem h_elem;

    struct thread *t;
    bool pinned;
  };


void frame_init (void);
void *frame_allocate (enum palloc_flags flags, void *upage);
void frame_set_pinned (void *kpage, bool pinned);
void frame_free (void *kpage, bool free_page);


#endif /* vm/frame.h */
