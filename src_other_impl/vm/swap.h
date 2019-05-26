#ifndef VM_SWAP_H
#define VM_SWAP_H



void swap_init (void);
/* Read from specified region */
void swap_read (uint32_t swap_id, void *page);
/* Write page to swap, return swap region */
uint32_t swap_write (void *page);
/* Free swap region */
void swap_free (uint32_t swap_id);

#endif /* vm/swap.h */
