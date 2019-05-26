#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <hash.h>
#include "vm/swap.h"
#include "filesys/off_t.h"

/* 4 page state */
enum page_status {
  ALL_ZERO,                       /* 0 */
  ON_FRAME,                       /* 1 */
  SWAP,                           /* 2 */
  FILE                            /* 3 */
};

/* Supplemental page table */
struct spt
  {
    struct hash page_map;
  };

struct spt_elem
  {
    void *upage;                  /* User page */
    void *kpage;                  /* Kernel page */
    struct hash_elem elem;        /* Hash elem */
    bool dirty;                   /* Dirty page record */
    enum page_status status;

    uint32_t swap_id;

    /* Store file info*/
    struct file *file;
    off_t file_ofs;
    uint32_t read_bytes;
    uint32_t zero_bytes;
    bool writable;
  };

bool spt_add_frame (struct spt *spt, void *upage, void *kpage);
bool spt_add_page (struct spt *spt, void *upage);
bool spt_add_file (struct spt *spt, void *page, struct file * file, off_t offset,
                    uint32_t read_bytes, uint32_t zero_bytes, bool writable);
bool spt_unmap (struct spt *spt, uint32_t *pagedir, void *page, struct file *f, off_t offset, size_t bytes);
bool load_page (struct spt *spt, uint32_t *pagedir, void *upage);

bool load_from_file(struct spt_elem *, void *);
void pin_page (struct spt *spt, void *page);
void unpin_page (struct spt *spt, void *page);

struct spt_elem *get_spte (struct spt *spt, void *);
unsigned spte_hash (const struct hash_elem *elem, void *aux);
bool spte_cmp (const struct hash_elem *, const struct hash_elem *, void *aux);
void spte_destroy (struct hash_elem *elem, void *aux);

#endif
