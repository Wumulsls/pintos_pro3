#include "filesys/cache.h"
#include "filesys/filesys.h"
#include "threads/synch.h"
#include <string.h>

#define CACHE_SIZE 64


struct cache_entry {
  char data[BLOCK_SECTOR_SIZE];
  block_sector_t sector;

  bool dirty;                         /* dirty bit */
  bool access;                        /* reference bit */
  bool valid;                         /* valid or invalid entry */
};


/* Cache entries. */
static struct cache_entry cache[CACHE_SIZE];

/* A lock for synchronizing cache operations. */
static struct lock cache_lock;

/**
 * Init the cache.
 */
void
cache_init (void)
{
  lock_init (&cache_lock);

  int i;
  for (i = 0; i < CACHE_SIZE; i++)
  {
    cache[i].valid = false;
  }
}

/**
 * Close the cache. Must write back
 * the dirty entry.
 */
void
cache_close (void)
{
  lock_acquire (&cache_lock);
  int i;
  for (i = 0; i < CACHE_SIZE; i++)
  {
    if (cache[i].valid)
    {
      if (cache[i].dirty)
      {
        block_write (fs_device, cache[i].sector, cache[i].data);
        cache[i].dirty = false;
      }
    }
  }  

  lock_release (&cache_lock);
}

/**
 * Read cache entry.
 */
void
cache_read (block_sector_t sector, void *target)
{
  lock_acquire (&cache_lock);
  struct cache_entry *temp = cache_find (sector);
  if (temp == NULL)
  {
    /* cache miss */
    temp = cache_evict ();
    temp->valid = true;
    temp->sector = sector;
    block_read (fs_device, sector, temp->data);
  }

  temp->access = true;
  memcpy (target, temp->data, BLOCK_SECTOR_SIZE);
  lock_release (&cache_lock);
}

/**
 * Write to cache.
 */
void
cache_write (block_sector_t sector, void *source)
{
  lock_acquire (&cache_lock);
  struct cache_entry *temp = cache_find (sector);
  if (temp == NULL)
  {
    /* cache miss */
    temp = cache_evict ();
    temp->valid = true;
    temp->sector = sector;
    block_read (fs_device, sector, temp->data);
  }

  temp->access = true;
  temp->dirty = true;
  memcpy (temp->data, source, BLOCK_SECTOR_SIZE);
  lock_release (&cache_lock);
}

/**
 * Find the cache entry, return the pointer of 
 * the entry if hit, else NULL.
 */
struct cache_entry *
cache_find (block_sector_t sector)
{
  int i;
  for (i = 0; i < CACHE_SIZE; i++)
  {
    if (cache[i].valid && cache[i].sector == sector)
    {
      return &(cache[i]);
    }
  }  
  return NULL;
}

/**
 * Find if there is a free cache entry, if not
 * evict an entry by clock algorithm.
 */
struct cache_entry *
cache_evict (void)
{
  int clock = 0;
  while (true) {
    if (cache[clock].valid == false) {
      return &(cache[clock]);
    }
    if (cache[clock].access) {
      cache[clock].access = false;
    }
    else break;

    clock ++;
    clock %= CACHE_SIZE;
  }

  struct cache_entry *temp = &cache[clock];
  if (temp->dirty)
  {
    block_write (fs_device, temp->sector, temp->data);
    temp->dirty = false;
  }
  temp->valid = false;
  return temp;
}