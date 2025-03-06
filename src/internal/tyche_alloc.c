/*
 * Code from https://github.com/evanw/buddy-malloc
 *
 * This file implements a buddy memory allocator, which is an allocator that
 * allocates memory within a fixed linear address range. It spans the address
 * range with a binary tree that tracks free space. Both "malloc" and "free"
 * are O(log N) time where N is the maximum possible number of allocations.
 *
 * The "buddy" term comes from how the tree is used. When memory is allocated,
 * nodes in the tree are split recursively until a node of the appropriate size
 * is reached. Every split results in two child nodes, each of which is the
 * buddy of the other. When a node is freed, the node and its buddy can be
 * merged again if the buddy is also free. This makes the memory available
 * for larger allocations again.
 */

#include "tyche_alloc.h"
#include "syscall.h"
#include <sys/mman.h>
#include <stdbool.h>

/*
 * Allocations are done in powers of two starting from MIN_ALLOC and ending at
 * MAX_ALLOC inclusive. Each allocation size has a bucket that stores the free
 * list for that allocation size.
 *
 * Given a bucket index, the size of the allocations in that bucket can be
 * found with "(size_t)1 << (MAX_ALLOC_LOG2 - bucket)".
 */
#define BUCKET_COUNT (MAX_ALLOC_LOG2 - MIN_ALLOC_LOG2 + 1)

#if ALLOC_DEBUG == 1

#define MAX_ALLOCATIONS 1000 // Adjust as needed

typedef struct {
    void *ptr;
    size_t size;
    bool is_used;
} allocation_info_t;

int max_allocations = 0;
int current_allocation = 0;

int max_allocations_blocks = 0;
int current_allocation_blocks = 0;

static allocation_info_t allocations[MAX_ALLOCATIONS] = {0};
static int allocation_count = 0;

static allocation_info_t* add_allocation(void *ptr, size_t size, bool is_used);
static allocation_info_t* find_allocation(void *ptr);
static size_t get_and_print_free_blocks_size();
#endif

/*
 * Free lists are stored as circular doubly-linked lists. Every possible
 * allocation size has an associated free list that is threaded through all
 * currently free blocks of that size. That means MIN_ALLOC must be at least
 * "sizeof(list_t)". MIN_ALLOC is currently 16 bytes, so this will be true for
 * both 32-bit and 64-bit.
 */
typedef struct list_t {
  struct list_t *prev, *next;
} list_t;

/*
 * Each bucket corresponds to a certain allocation size and stores a free list
 * for that size. The bucket at index 0 corresponds to an allocation size of
 * MAX_ALLOC (i.e. the whole address space).
 */
static list_t buckets[BUCKET_COUNT];

/*
 * We could initialize the allocator by giving it one free block the size of
 * the entire address space. However, this would cause us to instantly reserve
 * half of the entire address space on the first allocation, since the first
 * split would store a free list entry at the start of the right child of the
 * root. Instead, we have the tree start out small and grow the size of the
 * tree as we use more memory. The size of the tree is tracked by this value.
 */
static size_t bucket_limit;

/*
 * This array represents a linearized binary tree of bits. Every possible
 * allocation larger than MIN_ALLOC has a node in this tree (and therefore a
 * bit in this array).
 *
 * Given the index for a node, lineraized binary trees allow you to traverse to
 * the parent node or the child nodes just by doing simple arithmetic on the
 * index:
 *
 * - Move to parent:         index = (index - 1) / 2;
 * - Move to left child:     index = index * 2 + 1;
 * - Move to right child:    index = index * 2 + 2;
 * - Move to sibling:        index = ((index - 1) ^ 1) + 1;
 *
 * Each node in this tree can be in one of several states:
 *
 * - UNUSED (both children are UNUSED)
 * - SPLIT (one child is UNUSED and the other child isn't)
 * - USED (neither children are UNUSED)
 *
 * These states take two bits to store. However, it turns out we have enough
 * information to distinguish between UNUSED and USED from context, so we only
 * need to store SPLIT or not, which only takes a single bit.
 *
 * Note that we don't need to store any nodes for allocations of size MIN_ALLOC
 * since we only ever care about parent nodes.
 */
static uint8_t node_is_split[(1 << (BUCKET_COUNT - 1)) / 8];

/*
 * This is the starting address of the address range for this allocator. Every
 * returned allocation will be an offset of this pointer from 0 to MAX_ALLOC.
 */
static uint8_t *base_ptr;

/*
 * This is the maximum address that has ever been used by the allocator.
 */
static uint8_t *max_ptr;

/*
 * Make sure all addresses before "new_value" are valid and can be used. Memory
 * is allocated in a 2gb address range but that memory is not reserved up
 * front. It's only reserved when it's needed by calling this function. This
 * will return false if the memory could not be reserved.
 */
static int update_max_ptr(uint8_t *new_value) {
  if (new_value > max_ptr) {
    // Memory is allocated statically and cannot be extended
    return 0;
  }
  return 1;
}

/*
 * Initialize a list to empty. Because these are circular lists, an "empty"
 * list is an entry where both links point to itself. This makes insertion
 * and removal simpler because they don't need any branches.
 */
static void list_init(list_t *list) {
  list->prev = list;
  list->next = list;
}

/*
 * Append the provided entry to the end of the list. This assumes the entry
 * isn't in a list already because it overwrites the linked list pointers.
 */
static void list_push(list_t *list, list_t *entry) {
  list_t *prev = list->prev;
  entry->prev = prev;
  entry->next = list;
  prev->next = entry;
  list->prev = entry;
}

/*
 * Remove the provided entry from whichever list it's currently in. This
 * assumes that the entry is in a list. You don't need to provide the list
 * because the lists are circular, so the list's pointers will automatically
 * be updated if the first or last entries are removed.
 */
static void list_remove(list_t *entry) {
  list_t *prev = entry->prev;
  list_t *next = entry->next;
  prev->next = next;
  next->prev = prev;
}

/*
 * Remove and return the first entry in the list or NULL if the list is empty.
 */
static list_t *list_pop(list_t *list) {
  list_t *back = list->prev;
  if (back == list) return NULL;
  list_remove(back);
  return back;
}

/*
 * This maps from the index of a node to the address of memory that node
 * represents. The bucket can be derived from the index using a loop but is
 * required to be provided here since having them means we can avoid the loop
 * and have this function return in constant time.
 */
static uint8_t *ptr_for_node(size_t index, size_t bucket) {
  return base_ptr + ((index - (1 << bucket) + 1) << (MAX_ALLOC_LOG2 - bucket));
}

/*
 * This maps from an address of memory to the node that represents that
 * address. There are often many nodes that all map to the same address, so
 * the bucket is needed to uniquely identify a node.
 */
static size_t node_for_ptr(uint8_t *ptr, size_t bucket) {
  return ((ptr - base_ptr) >> (MAX_ALLOC_LOG2 - bucket)) + (1 << bucket) - 1;
}
/*
 * Given the index of a node, this returns the "is split" flag of the parent.
 */
static int parent_is_split(size_t index) {
  index = (index - 1) / 2;
  return (node_is_split[index / 8] >> (index % 8)) & 1;
}

/*
 * Given the index of a node, this flips the "is split" flag of the parent.
 */
static void flip_parent_is_split(size_t index) {
  index = (index - 1) / 2;
  node_is_split[index / 8] ^= 1 << (index % 8);
}

/*
 * Given the requested size passed to "malloc", this function returns the index
 * of the smallest bucket that can fit that size.
 */
static size_t bucket_for_request(size_t request) {
  size_t bucket = BUCKET_COUNT - 1;
  size_t size = MIN_ALLOC;

  while (size < request) {
    bucket--;
    size *= 2;
  }

  return bucket;
}

/*
 * The tree is always rooted at the current bucket limit. This call grows the
 * tree by repeatedly doubling it in size until the root lies at the provided
 * bucket index. Each doubling lowers the bucket limit by 1.
 */
static int lower_bucket_limit(size_t bucket) {
  while (bucket < bucket_limit) {
    size_t root = node_for_ptr(base_ptr, bucket_limit);
    uint8_t *right_child;

    /*
     * If the parent isn't SPLIT, that means the node at the current bucket
     * limit is UNUSED and our address space is entirely free. In that case,
     * clear the root free list, increase the bucket limit, and add a single
     * block with the newly-expanded address space to the new root free list.
     */
    if (!parent_is_split(root)) {
      list_remove((list_t *)base_ptr);
      list_init(&buckets[--bucket_limit]);
      list_push(&buckets[bucket_limit], (list_t *)base_ptr);
      continue;
    }

    /*
     * Otherwise, the tree is currently in use. Create a parent node for the
     * current root node in the SPLIT state with a right child on the free
     * list. Make sure to reserve the memory for the free list entry before
     * writing to it. Note that we do not need to flip the "is split" flag for
     * our current parent because it's already on (we know because we just
     * checked it above).
     */
    right_child = ptr_for_node(root + 1, bucket_limit);
    if (!update_max_ptr(right_child + sizeof(list_t))) {
      return 0;
    }
    list_push(&buckets[bucket_limit], (list_t *)right_child);
    list_init(&buckets[--bucket_limit]);

    /*
     * Set the grandparent's SPLIT flag so if we need to lower the bucket limit
     * again, we'll know that the new root node we just added is in use.
     */
    root = (root - 1) / 2;
    if (root != 0) {
      flip_parent_is_split(root);
    }
  }
  return 1;
}

#if ALLOC_DEBUG == 1

static allocation_info_t* add_allocation(void *ptr, size_t size, bool is_used) {
    for (int i = 0; i < allocation_count; i++) {
        if (allocations[i].ptr == ptr) {
            if(allocations[i].is_used == is_used) {
                LOG("Warning: Attempting to add already allocated memory at %p, size %zu\n", ptr, size);
            }
            allocations[i].size = size;
            allocations[i].is_used = is_used;
            current_allocation += size;
            if(current_allocation > max_allocations) {
                max_allocations = current_allocation;
            }
            size_t size_block = (size_t)1 << (MAX_ALLOC_LOG2 - bucket_for_request(size));
            current_allocation_blocks += size_block;
            //LOG("Current allocation vs current_allocation_blocks: 0x%llx vs 0x%llx\n", size, size_block);
            if(current_allocation_blocks > max_allocations_blocks) {
                max_allocations_blocks = current_allocation_blocks;
            }
          //LOG("Max allocation vs max_allocations_blocks: 0x%llx vs 0x%llx\n", current_allocation, current_allocation_blocks);
            return &allocations[i];
        }
    }
    if (allocation_count < MAX_ALLOCATIONS) {
        allocations[allocation_count].ptr = ptr;
        allocations[allocation_count].size = size;
        allocations[allocation_count].is_used = is_used;
        current_allocation += size;
        if(current_allocation > max_allocations) {
            max_allocations = current_allocation;
        }
        size_t size_block = (size_t)1 << (MAX_ALLOC_LOG2 - bucket_for_request(size));
        current_allocation_blocks += size_block;
        //LOG("Current allocation vs current_allocation_blocks: 0x%llx vs 0x%llx\n", size, size_block);
        if(current_allocation_blocks > max_allocations_blocks) {
            max_allocations_blocks = current_allocation_blocks;
        }
        //LOG("Max allocation vs max_allocations_blocks: 0x%llx vs 0x%llx\n", current_allocation, current_allocation_blocks);
        return &allocations[allocation_count++];
    }
    return NULL; // No space left to track allocations
}

static allocation_info_t* find_allocation(void *ptr) {
    for (int i = 0; i < allocation_count; i++) {
        if (allocations[i].ptr == ptr) {
            current_allocation -= allocations[i].size;
            current_allocation_blocks -= (size_t)1 << (MAX_ALLOC_LOG2 - bucket_for_request(allocations[i].size));
            return &allocations[i];
        }
    }
    return NULL; // No space left to track allocations
}

static size_t get_and_print_full_blocks_size() {
    size_t total_occupied = 0;

    for (int i = 0; i < MAX_ALLOCATIONS; i++) {
        allocation_info_t *info = &allocations[i];
        if(info->is_used) {
            size_t block_size = info->size;
            total_occupied += block_size;
            LOG("%zu full blocks in bucket %d: 0x%llx bytes\n", 1, bucket_for_request(block_size), block_size);
        }
    }
    return total_occupied;
}

static size_t get_and_print_free_blocks_size() {
    size_t total_free = 0;

    for (int i = bucket_limit; i < BUCKET_COUNT; i++) {
        size_t block_size = (size_t)1 << (MAX_ALLOC_LOG2 - i);
        size_t free_blocks = 0;
        list_t *current = buckets[i].next;
        
        while (current != &buckets[i]) {
            free_blocks++;
            current = current->next;
        }
        
        size_t free_size = free_blocks * block_size;
        total_free += free_size;
        
        LOG("%zu free blocks in bucket %d: 0x%llx bytes\n", free_blocks, i, free_size);
    }

    return total_free;
}

#endif

#ifdef RUN_WITHOUT_TYCHE
long mmap_no_tyche(void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
  unsigned long ret;
  register long r10 __asm__("r10") = flags;
  register long r8 __asm__("r8") = fd;
  register long r9 __asm__("r9") = offset;
  __asm__ __volatile__ ("syscall" : "=a"(ret) : "a"(SYS_mmap), "D"(addr), "S"(length),
              "d"(prot), "r"(r10), "r"(r8), "r"(r9) : "rcx", "r11", "memory");
  return ret;
}
#endif

void *alloc_segment(size_t request) {
  size_t original_bucket, bucket;

  /*
   * Make sure it's possible for an allocation of this size to succeed. There's
   * a hard-coded limit on the maximum allocation size because of the way this
   * allocator works.
   */
  if (request > MAX_ALLOC) {
    return MAP_FAILED;
  }

  /*
   * Initialize our global state if this is the first call to "malloc". At the
   * beginning, the tree has a single node that represents the smallestu
   * possible allocation size. More memory will be reserved later as needed.
   */
  if (base_ptr == NULL) {
    #ifdef RUN_WITHOUT_TYCHE // If not running inside Tyche, we allocate memory at the same location to ease debugging
    uint8_t *mempool = (uint8_t *)mmap_no_tyche(
        (void *)MEMPOOL_ADDR,           // addr
        MEMPOOL_SIZE,           // length
        PROT_READ | PROT_WRITE,         // prot
        MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,  // flags
        -1,                             // fd
        0                               // offset
    );

    if (mempool != (uint8_t*) MEMPOOL_ADDR) {
        // Handle error
        return MAP_FAILED;
    }
    #endif
    base_ptr = (uint8_t*) MEMPOOL_ADDR;
    max_ptr = base_ptr + (MEMPOOL_SIZE);

    bucket_limit = BUCKET_COUNT - 1;
    if(!update_max_ptr(base_ptr + sizeof(list_t))) {
        return MAP_FAILED;
    }
    list_init(&buckets[BUCKET_COUNT - 1]);
    list_push(&buckets[BUCKET_COUNT - 1], (list_t *)base_ptr);
    #if ALLOC_DEBUG == 1
    LOG("Mempool size vs max alloc: 0x%llx vs 0x%llx\n", MEMPOOL_SIZE, MAX_ALLOC);
    LOG("Mempool metadata is 0x%llx bytes\n", sizeof(buckets) + sizeof(node_is_split));
    if(MEMPOOL_SIZE < MAX_ALLOC) {
        LOG("Mempool size is less than max alloc, some mempool metadata state will not be allocated\n");
    }
    if(MEMPOOL_SIZE > MAX_ALLOC) {
        LOG("Mempool size is greater than max alloc, some allocated memory won't be used\n");
    }
    #endif
  }

  /*
   * Find the smallest bucket that will fit this request. This doesn't check
   * that there's space for the request yet.
   */
  bucket = bucket_for_request(request);
  original_bucket = bucket;

  /*
   * Search for a bucket with a non-empty free list that's as large or larger
   * than what we need. If there isn't an exact match, we'll need to split a
   * larger one to get a match.
   */
  while (bucket + 1 != 0) {
    size_t size, bytes_needed, i;
    uint8_t *ptr;

    /*
     * We may need to grow the tree to be able to fit an allocation of this
     * size. Try to grow the tree and stop here if we can't.
     */
    if (!lower_bucket_limit(bucket)) {
      return MAP_FAILED;
    }

    /*
     * Try to pop a block off the free list for this bucket. If the free list
     * is empty, we're going to have to split a larger block instead.
     */
    ptr = (uint8_t *)list_pop(&buckets[bucket]);
    if (!ptr) {
      /*
       * If we're not at the root of the tree or it's impossible to grow the
       * tree any more, continue on to the next bucket.
       */
      if (bucket != bucket_limit || bucket == 0) {
        bucket--;
        continue;
      }

      /*
       * Otherwise, grow the tree one more level and then pop a block off the
       * free list again. Since we know the root of the tree is used (because
       * the free list was empty), this will add a parent above this node in
       * the SPLIT state and then add the new right child node to the free list
       * for this bucket. Popping the free list will give us this right child.
       */
      if (!lower_bucket_limit(bucket - 1)) {
        return MAP_FAILED;
      }
      ptr = (uint8_t *)list_pop(&buckets[bucket]);
    }

    /*
     * Try to expand the address space first before going any further. If we
     * have run out of space, put this block back on the free list and fail.
     */
    size = (size_t)1 << (MAX_ALLOC_LOG2 - bucket);
    bytes_needed = bucket < original_bucket ? size / 2 + sizeof(list_t) : size;
    if (!update_max_ptr(ptr + bytes_needed)) {
      list_push(&buckets[bucket], (list_t *)ptr);
#if ALLOC_DEBUG == 1
      print_allocation_info();
#endif
      return MAP_FAILED;
    }

    /*
     * If we got a node off the free list, change the node from UNUSED to USED.
     * This involves flipping our parent's "is split" bit because that bit is
     * the exclusive-or of the UNUSED flags of both children, and our UNUSED
     * flag (which isn't ever stored explicitly) has just changed.
     *
     * Note that we shouldn't ever need to flip the "is split" bit of our
     * grandparent because we know our buddy is USED so it's impossible for our
     * grandparent to be UNUSED (if our buddy chunk was UNUSED, our parent
     * wouldn't ever have been split in the first place).
     */
    i = node_for_ptr(ptr, bucket);
    if (i != 0) {
      flip_parent_is_split(i);
    }

    /*
     * If the node we got is larger than we need, split it down to the correct
     * size and put the new unused child nodes on the free list in the
     * corresponding bucket. This is done by repeatedly moving to the left
     * child, splitting the parent, and then adding the right child to the free
     * list.
     */
    while (bucket < original_bucket) {
      i = i * 2 + 1;
      bucket++;
      flip_parent_is_split(i);
      list_push(&buckets[bucket], (list_t *)ptr_for_node(i + 1, bucket));
    }

    /*
     * Return the pointer.
     */
#if ALLOC_DEBUG == 1  
    if (ptr != MAP_FAILED) {
        allocation_info_t *info = add_allocation(ptr, request, 1);
        if (!info) {
            LOG("Warning: Unable to track allocation at %p, size %zu\n", ptr, request);
        }
    }
#endif

    return ptr;
  }

  return MAP_FAILED;
}

int free_segment(void *ptr, size_t len) {
  size_t bucket, i;

  /*
   * Ignore any attempts to free a NULL pointer.
   */
  if (!ptr) {
    return -1;
  }

  /*
   * Look up the index of the node corresponding to this address.
   */
  bucket = bucket_for_request(len);
  i = node_for_ptr((uint8_t *)ptr, bucket);

  /*
   * Traverse up to the root node, flipping USED blocks to UNUSED and merging
   * UNUSED buddies together into a single UNUSED parent.
   */
  while (i != 0) {
    /*
     * Change this node from UNUSED to USED. This involves flipping our
     * parent's "is split" bit because that bit is the exclusive-or of the
     * UNUSED flags of both children, and our UNUSED flag (which isn't ever
     * stored explicitly) has just changed.
     */
    flip_parent_is_split(i);

    /*
     * If the parent is now SPLIT, that means our buddy is USED, so don't merge
     * with it. Instead, stop the iteration here and add ourselves to the free
     * list for our bucket.
     *
     * Also stop here if we're at the current root node, even if that root node
     * is now UNUSED. Root nodes don't have a buddy so we can't merge with one.
     */
    if (parent_is_split(i) || bucket == bucket_limit) {
      break;
    }

    /*
     * If we get here, we know our buddy is UNUSED. In this case we should
     * merge with that buddy and continue traversing up to the root node. We
     * need to remove the buddy from its free list here but we don't need to
     * add the merged parent to its free list yet. That will be done once after
     * this loop is finished.
     */
    list_remove((list_t *)ptr_for_node(((i - 1) ^ 1) + 1, bucket));
    i = (i - 1) / 2;
    bucket--;
  }

  /*
   * Add ourselves to the free list for our bucket. We add to the back of the
   * list because "malloc" takes from the back of the list and we want a "free"
   * followed by a "malloc" of the same size to ideally use the same address
   * for better memory locality.
   */
  list_push(&buckets[bucket], (list_t *)ptr_for_node(i, bucket));

#if ALLOC_DEBUG == 1
  allocation_info_t *info = find_allocation(ptr);
  if (!info || !info->is_used) {
      LOG("Error: Attempting to free unallocated or already freed memory at %p\n", ptr);
      return -1;
  }
  if (bucket_for_request(len) != bucket_for_request(info->size)) {
      LOG("Warning: Freeing memory at %p with size %lx, but it was allocated with size %lx (bucket sizes %lx and %lx)\n", 
          ptr, len, info->size, bucket_for_request(len), bucket_for_request(info->size));
  }
  info->is_used = 0; // Mark as freed
#endif

  return 0;
}

#if ALLOC_DEBUG == 1
// Add a function to print allocation info
void print_allocation_info() {
    
    get_and_print_full_blocks_size();
    size_t free_blocks_size = get_and_print_free_blocks_size();
    size_t size_tree = (size_t)1 << (MAX_ALLOC_LOG2 - bucket_limit);

    LOG("Current allocation vs max allocation: 0x%llx / 0x%llx = %f\n", current_allocation, max_allocations, ((float)current_allocation / (float)max_allocations) * 100);
    LOG("Mempool utilisation: 0x%llx / 0x%llx = %f\n", current_allocation, size_tree, ((float)current_allocation / (float)size_tree) * 100);
    LOG("Lost to rounding up: 0x%llx = %f\n", current_allocation_blocks - current_allocation, ((float)(current_allocation_blocks - current_allocation) / (float)size_tree) * 100);
    LOG("Free and available memory: 0x%llx = %f\n", free_blocks_size, ((float)free_blocks_size / (float)(size_tree)) * 100);

    LOG("All time statistics:\n");
    LOG("Max Size Tree: 0x%lx\n", size_tree);
    LOG("Max Mempool utilisation: 0x%llx / 0x%llx = %f\n", max_allocations, size_tree, ((float)max_allocations / (float)size_tree) * 100);
    LOG("Max Mempool utilisation with rounding up: 0x%llx / 0x%llx = %f\n", max_allocations_blocks, size_tree, ((float)max_allocations_blocks / (float)size_tree) * 100);
    LOG("Lost to rounding up: 0x%llx = %f\n", max_allocations_blocks - max_allocations, ((float)(max_allocations_blocks - max_allocations) / (float)size_tree) * 100);
}
#endif