#ifndef __ALLOCATOR_DEFRAG_H
#define __ALLOCATOR_DEFRAG_H
#include "sds.h"

int defrag_jemalloc_init(void);
void defrag_jemalloc_free(void *ptr, size_t size);
__attribute__((malloc)) void *defrag_jemalloc_alloc(size_t size);
size_t defrag_jemalloc_get_frag_smallbins(void);
sds defrag_jemalloc_get_fragmentation_info(sds info);
void defrag_jemalloc_should_defrag_multi(void **ptrs, size_t num);

#endif /* __ALLOCATOR_DEFRAG_H */
