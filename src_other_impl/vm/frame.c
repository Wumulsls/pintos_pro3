#include <stdio.h>
#include "threads/thread.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "vm/frame.h"


/* A mapping from physical address to frame table entry. */
static struct hash frame_map;

/* For clock eviction algorithm */
static struct lock frame_lock;
static struct list frame_list;
static struct list_elem *frame_ptr; /* the pointer in clock algorithm */

unsigned frame_hash (const struct hash_elem *elem, void *aux);
bool frame_cmp (const struct hash_elem *, const struct hash_elem *, void *aux);


struct frame_node * pick_frame (uint32_t *pagedir);
struct frame_node *frame_next(void);


void
frame_init ()
{
  lock_init (&frame_lock);
  list_init (&frame_list);
  hash_init (&frame_map, frame_hash, frame_cmp, NULL);
  frame_ptr = NULL;
}

/* Allocate frame */
void*
frame_allocate (enum palloc_flags flag, void *upage)
{
  lock_acquire (&frame_lock);

  void *frame_page = palloc_get_page (PAL_USER | flag);
  if (frame_page == NULL) {
    struct frame_node *node = pick_frame ( thread_current ()->pagedir );
    pagedir_clear_page(node->t->pagedir, node->upage);

    bool is_dirty = pagedir_is_dirty (node->t->pagedir, node->upage) ||
                    pagedir_is_dirty (node->t->pagedir, node->kpage);

    uint32_t swap_id = swap_write ( node->kpage );
    struct spt_elem *spte = get_spte (node->t->spt, node->upage);
    spte->dirty = spte->dirty || is_dirty;
    spte->status = SWAP;
    spte->swap_id = swap_id;
    spte->kpage = NULL;

    lock_release (&frame_lock);
    frame_free (node->kpage, true);
    lock_acquire (&frame_lock);

    frame_page = palloc_get_page (PAL_USER | flag);
  }
  /* Alloc page and add to hash list */
  struct frame_node *node = (struct frame_node *)malloc (sizeof (struct frame_node));
  if (node == NULL)
    {
      lock_release (&frame_lock);
      return NULL;
    }
  node->t = thread_current ();
  node->upage = upage;
  node->kpage = frame_page;
  node->pinned = true;
  hash_insert (&frame_map, &node->h_elem);
  list_push_back (&frame_list, &node->l_elem);

  lock_release (&frame_lock);
  return frame_page;
}

void
frame_set_pinned (void *kpage, bool pinned)
{
  lock_acquire (&frame_lock);

  struct frame_node node_temp;
  node_temp.kpage = kpage;
  struct hash_elem *h = hash_find (&frame_map, &(node_temp.h_elem));
  hash_entry(h, struct frame_node, h_elem)->pinned = pinned;

  lock_release (&frame_lock);
}

/* Free frame(free_page false) or free page(free_page true) */
void
frame_free (void *kpage, bool free_page)
{
  lock_acquire (&frame_lock);

  struct frame_node node_temp;
  node_temp.kpage = kpage;

  struct frame_node *node;
  node = hash_entry (hash_find (&frame_map, &(node_temp.h_elem)), struct frame_node, h_elem);

  hash_delete (&frame_map, &node->h_elem);
  list_remove (&node->l_elem);

  if (free_page)
    palloc_free_page (kpage);
  free(node);
  lock_release (&frame_lock);
}

struct frame_node *
pick_frame (uint32_t *pagedir)
{
  size_t n = hash_size (&frame_map);
  for (size_t i = 0; i <= 3*n; i++)
    {
      struct frame_node *node = frame_next ();
      if (node->pinned)
        continue;
      else if (pagedir_is_accessed (pagedir, node->upage))
        {
          pagedir_set_accessed (pagedir, node->upage, false);
          continue;
        }
      return node;
    }
  return NULL;
}

struct frame_node *
frame_next ()
{
  if (!frame_ptr || frame_ptr == list_end (&frame_list))
    frame_ptr = list_begin (&frame_list);
  else
    frame_ptr = list_next (frame_ptr);

  return list_entry (frame_ptr, struct frame_node, l_elem);
}

/* Frame hash */
unsigned frame_hash (const struct hash_elem *elem, void *aux UNUSED)
{
  struct frame_node *node = hash_entry (elem, struct frame_node, h_elem);
  return hash_bytes ( &node->kpage, sizeof(node->kpage));
}

bool frame_cmp (const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED)
{
  return hash_entry(a, struct frame_node, h_elem)->kpage < hash_entry(b, struct frame_node, h_elem)->kpage;
}
