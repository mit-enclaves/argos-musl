#pragma once

#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include "tyche.h"

/*
 * Every allocation needs an 8-byte header to store the allocation size while
 * staying 8-byte aligned. The address returned by "malloc" is the address
 * right after this header (i.e. the size occupies the 8 bytes before the
 * returned address).
 */
#define HEADER_SIZE 8

/*
 * The minimum allocation size is 16 bytes because we have an 8-byte header and
 * we need to stay 8-byte aligned.
 */
#define MIN_ALLOC_LOG2 4
#define MIN_ALLOC ((size_t)1 << MIN_ALLOC_LOG2)

/*
 * The maximum allocation size is currently set to 2gb. This is the total size
 * of the heap. It's technically also the maximum allocation size because the
 * heap could consist of a single allocation of this size. But of course real
 * heaps will have multiple allocations, so the real maximum allocation limit
 * is at most 1gb.
 */
#define MAX_ALLOC_LOG2 31
#define MAX_ALLOC ((size_t)1 << MAX_ALLOC_LOG2)

#ifndef PAGE_SIZE
#define PAGE_SIZE (0x1000)
#endif

#define NB_PAGES  (800 * 4)

#define MEMPOOL_ADDR 0x700000

void *alloc_segment(size_t request);
void free_segment(void *ptr);