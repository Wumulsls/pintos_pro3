#include <string.h>
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "vm/page.h"
#include "vm/frame.h"
#include "filesys/file.h"

/* Add a page on frame to spt */
bool
spt_add_frame (struct spt *spt, void *upage, void *kpage)
{
  struct spt_elem *spte;
  spte = (struct spt_elem *)malloc (sizeof (struct spt_elem));
  spte->status = ON_FRAME;
  spte->dirty = false;
  spte->swap_id = -1;
  spte->upage = upage;
  spte->kpage = kpage;

  if (!hash_insert (&spt->page_map, &spte->elem))
    return true;
  free (spte);
  return false;
}

/* Add zero_page to spt. */
bool
spt_add_page (struct spt *spt, void *upage)
{
  struct spt_elem *spte;
  spte = (struct spt_elem *)malloc (sizeof (struct spt_elem));
  spte->status = ALL_ZERO;
  spte->dirty = false;
  spte->upage = upage;
  spte->kpage = NULL;

  if (!hash_insert (&spt->page_map, &spte->elem))
    return true;
  return false;
}

/* Add file to be exec */
bool
spt_add_file (struct spt *spt, void *upage, struct file *file, off_t ofs,
                      uint32_t read_bytes, uint32_t zero_bytes, bool writable)
{
  struct spt_elem *spte = (struct spt_elem *)malloc (sizeof (struct spt_elem));
  spte->status = FILE;
  spte->dirty = false;
  spte->upage = upage;
  spte->kpage = NULL;
  spte->file = file;
  spte->file_ofs = ofs;
  spte->read_bytes = read_bytes;
  spte->zero_bytes = zero_bytes;
  spte->writable = writable;

  if (!hash_insert (&spt->page_map, &spte->elem))
    return true;
  return false;
}

bool
spt_unmap (struct spt *spt, uint32_t *pagedir, void *page, struct file *f, off_t ofs, size_t bytes)
{
  struct spt_elem *spte = get_spte (spt, page);

  if (spte->status == ON_FRAME)
    frame_set_pinned (spte->kpage, false);

  switch (spte->status)
  {
    case ALL_ZERO:
      {
        break;
      }
    case ON_FRAME:
      {
        /* If dirty, write to file */
        bool is_dirty = spte->dirty || pagedir_is_dirty (pagedir, spte->upage) ||
                        pagedir_is_dirty (pagedir, spte->kpage);
        if (is_dirty)
          file_write_at (f, spte->upage, bytes, ofs);

        frame_free (spte->kpage, true);
        pagedir_clear_page (pagedir, spte->upage);
        break;
      }

    case SWAP:
      {
        bool is_dirty = spte->dirty || pagedir_is_dirty (pagedir, spte->upage);
        if (is_dirty)
          {
            void *temp_page = palloc_get_page (0);
            swap_read (spte->swap_id, temp_page);
            file_write_at (f, temp_page, PGSIZE, ofs);
            palloc_free_page (temp_page);
          }
        else
          swap_free (spte->swap_id);
      }
      break;

    case FILE:
    {
      break;
    }
  }
  hash_delete (&spt->page_map, &spte->elem);
  return true;
}

/* Load page*/
bool
load_page (struct spt *spt, uint32_t *pagedir, void *upage)
{
  struct spt_elem *spte = get_spte (spt, upage);
  if(spte == NULL)
    return false;

  if (spte->status == ON_FRAME)
    return true;

  void *frame = frame_allocate (PAL_USER, upage);
  if(frame == NULL)
    return false;

  bool writable = true;
  switch (spte->status)
  {
  case ALL_ZERO:
    {
      memset (frame, 0, PGSIZE);
      break;
    }

  case ON_FRAME:
    {
      break;
    }
  case SWAP:
    {
      swap_read (spte->swap_id, frame);
      break;
    }

  case FILE:
    {
      if(!load_from_file (spte, frame))
        {
          frame_free (frame, true);
          return false;
        }
      writable = spte->writable;
      break;
    }
  }

  if(!pagedir_set_page (pagedir, upage, frame, writable))
    {
      frame_free (frame, true);
      return false;
    }

  spte->status = ON_FRAME;
  spte->kpage = frame;
  pagedir_set_dirty (pagedir, frame, false);
  frame_set_pinned (frame, false);
  return true;
}

bool load_from_file (struct spt_elem *spte, void *kpage)
{
  file_seek (spte->file, spte->file_ofs);
  int bytes = file_read (spte->file, kpage, spte->read_bytes);
  if ((int)spte->read_bytes != bytes)
    return false;

  memset (kpage + bytes, 0, spte->zero_bytes);
  return true;
}


/* Pin page */
void
pin_page (struct spt *spt, void *page)
{
  struct spt_elem *spte;
  spte = get_spte(spt, page);
  if(spte == NULL)
    return;
  frame_set_pinned (spte->kpage, true);
}

/* Unpin page */
void
unpin_page (struct spt *spt, void *page)
{
  struct spt_elem *spte = get_spte (spt, page);
  if (spte->status == ON_FRAME)
    frame_set_pinned (spte->kpage, false);
}

/* Find spt_e and return */
struct spt_elem*
get_spte (struct spt *spt, void *page)
{
  struct spt_elem spte;
  spte.upage = page;
  struct hash_elem *elem = hash_find (&spt->page_map, &spte.elem);
  if (elem == NULL)
    return NULL;
  return hash_entry (elem, struct spt_elem, elem);
}

/* Used by hash function */
unsigned
spte_hash (const struct hash_elem *elem, void *aux UNUSED)
{
  return hash_int ((int)hash_entry (elem, struct spt_elem, elem)->upage);
}

bool
spte_cmp (const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED)
{
  return hash_entry (a, struct spt_elem, elem)->upage < hash_entry (b, struct spt_elem, elem)->upage;
}

void
spte_destroy (struct hash_elem *elem, void *aux UNUSED)
{
  struct spt_elem *e = hash_entry (elem, struct spt_elem, elem);

  if (e->kpage != NULL)
    frame_free (e->kpage, false);
  else if (e->status == SWAP)
    swap_free (e->swap_id);
  free (e);
}
