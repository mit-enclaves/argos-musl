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

#define NB_PAGES (0x80000)

#define MEMPOOL_SIZE (PAGE_SIZE * NB_PAGES)
#define MEMPOOL_ADDR 0x900000

#define MAP_FAILED ((void *) -1)

/*
 * Every allocation needs an 8-byte header to store the allocation size while
 * staying 8-byte aligned. The address returned by "malloc" is the address
 * right after this header (i.e. the size occupies the 8 bytes before the
 * returned address).
 */
#define HEADER_SIZE 8

/*
 * The minimum allocation size a page
 */
#define MIN_ALLOC_LOG2 PAGE_SHIFT
#define MIN_ALLOC ((size_t)1 << MIN_ALLOC_LOG2)

/*
 * The maximum allocation size is currently set to 2GB
 */
#define MAX_ALLOC_LOG2 31
#define MAX_ALLOC ((size_t)1 << MAX_ALLOC_LOG2)

void *alloc_segment(size_t request);
int free_segment(void *ptr, size_t len);

#if ALLOC_DEBUG == 1
void print_allocation_info();
#endif