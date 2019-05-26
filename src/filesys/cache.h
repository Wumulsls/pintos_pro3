#ifndef FILESYS_CACHE_H
#define FILESYS_CACHE_H

#include "devices/block.h"

void cache_init (void);
void cache_read (block_sector_t sector, void *target);
void cache_write (block_sector_t sector, void *source);
void cache_close (void);
struct cache_entry *cache_evict (void);
struct cache_entry *cache_find (block_sector_t sector);

#endif