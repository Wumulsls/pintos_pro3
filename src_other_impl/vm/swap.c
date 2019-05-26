#include <bitmap.h>
#include "threads/vaddr.h"
#include "devices/block.h"
#include "vm/swap.h"

static struct block *swap_block;
static struct bitmap *swap_map;

static const size_t NUM_SECTORS = PGSIZE / BLOCK_SECTOR_SIZE;


void
swap_init ()
{
  swap_block = block_get_role (BLOCK_SWAP);
  swap_map = bitmap_create (block_size (swap_block) / NUM_SECTORS);
  bitmap_set_all(swap_map, true);
}

uint32_t
swap_write (void *page)
{
  size_t swap_id = bitmap_scan (swap_map, 0, 1, true);
  for (size_t i = 0; i < NUM_SECTORS; i++)
    block_write (swap_block, swap_id * NUM_SECTORS + i, page + (BLOCK_SECTOR_SIZE * i));

  bitmap_set (swap_map, swap_id, false);
  return swap_id;
}

void
swap_read (uint32_t swap_id, void *page)
{
  if (bitmap_test (swap_map, swap_id))
    return;

  for (size_t i = 0; i < NUM_SECTORS; i++)
    block_read (swap_block, swap_id * NUM_SECTORS + i, page + (BLOCK_SECTOR_SIZE * i));

  bitmap_set (swap_map, swap_id, true);
}

void
swap_free (uint32_t swap_id)
{
  if (bitmap_test(swap_map, swap_id))
    return
  bitmap_set(swap_map, swap_id, true);
}
