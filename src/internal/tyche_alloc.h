#pragma once

#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include "tyche.h"

#define ALLOC_DEBUG 0

#ifndef PAGE_SHIFT
#define PAGE_SHIFT 12
#endif
#ifndef PAGE_SIZE
#define PAGE_SIZE ((size_t)1 << PAGE_SHIFT) // 0x1000
#endif

#define NB_PAGES  (800 * 32)

#define MEMPOOL_ADDR 0x700000

#define MAP_FAILED ((void *) -1)

/*
 * Every allocation needs an 8-byte header to store the allocation size while
 * staying 8-byte aligned. The address returned by "malloc" is the address
 * right after this header (i.e. the size occupies the 8 bytes before the
 * returned address).
 */
#define HEADER_SIZE 8

/*
 * The minimum allocation size is 0x1000 because we only allocate pages
 */
#define MIN_ALLOC_LOG2 PAGE_SHIFT
#define MIN_ALLOC ((size_t)1 << MIN_ALLOC_LOG2)

/*
 * The maximum allocation size is currently set to 2gb. This is the total size
 * of the mempool. It's technically also the maximum allocation size because the
 * mempool could consist of a single allocation of this size. But of course real
 * mempool will have multiple allocations, so the real maximum allocation limit
 * is at most 1gb.
 */
#define MAX_ALLOC_LOG2 31
#define MAX_ALLOC ((size_t)1 << MAX_ALLOC_LOG2)

void *alloc_segment(size_t request);
int free_segment(void *ptr, size_t len);

#if ALLOC_DEBUG == 1
void print_mempool_state();
void print_allocation_info();
#endif