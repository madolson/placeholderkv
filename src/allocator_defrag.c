#include "fmacros.h"
#include "config.h"
#include "solarisfixes.h"
#include "serverassert.h"
#include "allocator_defrag.h"
#include "zmalloc.h"
#include "util.h"
#include <jemalloc/jemalloc.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>

#define UNUSED(x) (void)(x)

#ifdef HAVE_DEFRAG

#define STRINGIFY_(x) #x
#define STRINGIFY(x) STRINGIFY_(x)


#define SLAB_NFREE(out, i) out[(i) * 3]
#define SLAB_LEN(out, i) out[(i) * 3 + 2]
#define SLAB_NUM_REGS(out, i) out[(i) * 3 + 1]

#define LG_QUANTOM_8_FIRST_POW2 3
#define LG_QUANTOM_8_LAST_BININD ((64 >> LG_QUANTOM_8_FIRST_POW2) - 1)
#define SIZE_CLASS_GROUP_SZ 4
unsigned jemalloc_sz2binind(size_t sz) {
    if (sz <= (1<<(LG_QUANTOM_8_FIRST_POW2 + 3))) {
        // for sizes: 8, 16, 24, 32, 40, 48, 56, 64
        return (sz >> LG_QUANTOM_8_FIRST_POW2) - 1;
    }
    // following groups have SIZE_CLASS_GROUP_SZ size-class that are
    uint64_t last_sz_in_group_pow2 = 64 - __builtin_clzll(sz - 1);
    return (SIZE_CLASS_GROUP_SZ - (((1<<last_sz_in_group_pow2) - sz) >> (last_sz_in_group_pow2 - LG_QUANTOM_8_FIRST_POW2))) +
           ((last_sz_in_group_pow2 - (LG_QUANTOM_8_FIRST_POW2 + 3))-1)*SIZE_CLASS_GROUP_SZ + //offset index to account for prev
           LG_QUANTOM_8_LAST_BININD; //offset of first group spaced by 8
}
/**helper values to improve query performance, by avoiding cmd lookup perf impact.
 *
 * From https://jemalloc.net/jemalloc.3.html:
 *
 * The mallctlnametomib() function provides a way to avoid repeated name lookups for applications
 * that repeatedly query the same portion of the namespace, by translating a name to a
 * “Management Information Base” (MIB) that can be passed repeatedly to mallctlbymib().
 * Upon successful return from mallctlnametomib(), mibp contains an array of *miblenp integers,
 * where *miblenp is the lesser of the number of components in name and the input value of *miblenp.
 * Thus it is possible to pass a *miblenp that is smaller than the number of period-separated name components,
 * which results in a partial MIB that can be used as the basis for constructing a complete MIB.
 * or name components that are integers (e.g. the 2 in arenas.bin.2.size), t
 * he corresponding MIB component will always be that integer.
 * */
typedef struct je_bin_q_helper {
    size_t mib_curr_slabs[6];
    size_t miblen_curr_slabs;
    size_t mib_nonfull_slabs[6];
    size_t miblen_nonfull_slabs;
    size_t mib_curr_regs[6];
    size_t miblen_curr_regs;
    size_t mib_nmalloc[6];
    size_t miblen_nmalloc;
    size_t mib_ndealloc[6];
    size_t miblen_ndealloc;
} je_bin_q_helper;

// struct representing bin information
typedef struct je_binfo {
    size_t reg_size;
    size_t nregs;
    size_t len;
    // bin runtime query command - get mib to avoid cmd lookup perf impact
    je_bin_q_helper mib_helper;
} je_binfo;

typedef struct je_bins_conf {
    size_t nbins;
    je_binfo* bin_info;
    // ptrs runtime query command - get mib to avoid cmd lookup perf impact
    size_t mib_util_batch_query[3];
    size_t miblen_util_batch_query;
    size_t mib_util_query[3];
    size_t miblen_util_query;
} je_bins_conf;

typedef struct je_defrag_bstats {
    size_t bhits;
    size_t bmisses;
    size_t nmalloc;
    size_t ndealloc;
} je_defrag_bstats;

typedef struct je_defrag_stats {
    size_t hits;
    size_t misses;
    size_t hit_bytes;
    size_t miss_bytes;
    size_t ncalls;
    size_t nptrs;
} je_defrag_stats;

/// structure representing latenst info collected from jemalloc at the bin level
typedef struct je_busage {
    int can_defrag;
    size_t curr_slabs;
    size_t curr_nonfull_slabs;
    size_t curr_full_slabs;
    size_t curr_regs;
    size_t util; // in 0.01% units
    size_t nonfull_util; // in 0.01% units
    je_defrag_bstats stat;
} je_busage;

typedef struct je_usage_latest {
    je_busage* bins_usage;
    je_defrag_stats stats;
} je_usage_latest;

static int defrag_supported = 0;
static je_bins_conf arena_bin_conf = {0, NULL, {0}, 0, {0}, 0};
static je_usage_latest usage_latest = {NULL,{0}};



/* Allocation and free functions that bypass the thread cache
 * and go straight to the allocator arena bins.
 * Currently implemented only for jemalloc. Used for online defragmentation. */
void *defrag_jemalloc_alloc(size_t size) {
    void *ptr = je_mallocx(size, MALLOCX_TCACHE_NONE);
    return ptr;
}
void defrag_jemalloc_free(void *ptr, size_t size) {
    if (ptr == NULL) return;
    je_sdallocx(ptr, size, MALLOCX_TCACHE_NONE);
}

sds defrag_jemalloc_get_fragmentation_info(sds info) {
    if (!defrag_supported) return info;
    je_binfo* binfo;
    je_busage* busage;
    unsigned nbins = arena_bin_conf.nbins;
    if (nbins > 0) {
        info = sdscatprintf(info,
            "hit_ratio:%ld%%,hits:%ld,misses:%ld\r\n"
            "hit_bytes:%ld,miss_bytes:%ld\r\n"
            "ncalls_util_batches:%ld,ncalls_util_ptrs:%ld\r\n",
            (usage_latest.stats.hits + usage_latest.stats.misses)?
            usage_latest.stats.hits/(usage_latest.stats.hits + usage_latest.stats.misses) : 0,
            usage_latest.stats.hits, usage_latest.stats.misses,
            usage_latest.stats.hit_bytes, usage_latest.stats.miss_bytes,
            usage_latest.stats.ncalls,
            usage_latest.stats.nptrs);
        for (unsigned j = 0; j < nbins; j++) {
            binfo = &arena_bin_conf.bin_info[j];
            busage = &usage_latest.bins_usage[j];
            info = sdscatprintf(info,
                "[%d][%ld]::"
                "nregs:%ld,nslabs:%ld,nnonfull:%ld,"
                "util:%ld,nonfull_util:%ld,"
                "hit_rate:%ld%%,hit:%ld,miss:%ld,nmalloc:%ld,ndealloc:%ld\r\n",
                j, binfo->reg_size,
                busage->curr_regs, busage->curr_slabs, busage->curr_nonfull_slabs,
                busage->util, busage->nonfull_util,
                (busage->stat.bhits + busage->stat.bmisses)?
                            busage->stat.bhits/(busage->stat.bhits + busage->stat.bmisses) : 0,
                busage->stat.bhits, busage->stat.bmisses,
                busage->stat.nmalloc, busage->stat.ndealloc);
        }
    }
    return info;
}

#define ARENA_TO_QUERY  0 //MALLCTL_ARENAS_ALL
int defrag_jemalloc_init(void) {
    if (defrag_supported) return 1;
    uint64_t epoch = 1;
    size_t sz = sizeof(epoch);
    je_mallctl("epoch", &epoch, &sz, &epoch, sz);
    char buf[100];
    je_binfo* binfo;
    unsigned nbins;
    sz = sizeof(nbins);
    assert(!je_mallctl("arenas.nbins", &nbins, &sz, NULL, 0));
    arena_bin_conf.bin_info = zcalloc(sizeof(je_binfo) * nbins);
    for (unsigned j = 0; j < nbins; j++) {
        binfo = &arena_bin_conf.bin_info[j];
        /* The size of the current bin */
        snprintf(buf, sizeof(buf), "arenas.bin.%d.size", j);
        sz = sizeof(size_t);
        assert(!je_mallctl(buf, &binfo->reg_size, &sz, NULL, 0));

        /* Number of regions per slab */
        snprintf(buf, sizeof(buf), "arenas.bin.%d.nregs", j);
        sz = sizeof(uint32_t);
        assert(!je_mallctl(buf, &binfo->nregs, &sz, NULL, 0));
        binfo->len = binfo->reg_size * binfo->nregs;
        /* Mib of fetch number of used regions in the bin */
        snprintf(buf, sizeof(buf), "stats.arenas." STRINGIFY(ARENA_TO_QUERY) ".bins.%d.curregs", j);
        sz = sizeof(size_t);
        binfo->mib_helper.miblen_curr_regs = sizeof(binfo->mib_helper.mib_curr_regs)/sizeof(size_t);
        assert(!je_mallctlnametomib(buf,
                                    binfo->mib_helper.mib_curr_regs,
                                    &binfo->mib_helper.miblen_curr_regs));
        /* Mib of fetch number of current slabs in the bin */
        snprintf(buf, sizeof(buf), "stats.arenas." STRINGIFY(ARENA_TO_QUERY) ".bins.%d.curslabs", j);
        binfo->mib_helper.miblen_curr_slabs = sizeof(binfo->mib_helper.mib_curr_slabs)/sizeof(size_t);
        assert(!je_mallctlnametomib(buf,
                                    binfo->mib_helper.mib_curr_slabs,
                                    &binfo->mib_helper.miblen_curr_slabs));
        /* Mib of fetch nonfull slabs */
        snprintf(buf, sizeof(buf), "stats.arenas." STRINGIFY(ARENA_TO_QUERY) ".bins.%d.nonfull_slabs", j);
        binfo->mib_helper.miblen_nonfull_slabs = sizeof(binfo->mib_helper.mib_nonfull_slabs)/sizeof(size_t);
        assert(!je_mallctlnametomib(buf,
                                    binfo->mib_helper.mib_nonfull_slabs,
                                    &binfo->mib_helper.miblen_nonfull_slabs));
        
        /* Mib of fetch num of alloc op */
        snprintf(buf, sizeof(buf), "stats.arenas." STRINGIFY(ARENA_TO_QUERY) ".bins.%d.nmalloc", j);
        binfo->mib_helper.miblen_nmalloc = sizeof(binfo->mib_helper.mib_nmalloc)/sizeof(size_t);
        assert(!je_mallctlnametomib(buf,
                                    binfo->mib_helper.mib_nmalloc,
                                    &binfo->mib_helper.miblen_nmalloc));
        /* Mib of fetch num of dealloc op */
        snprintf(buf, sizeof(buf), "stats.arenas." STRINGIFY(ARENA_TO_QUERY) ".bins.%d.ndalloc", j);
        binfo->mib_helper.miblen_ndealloc = sizeof(binfo->mib_helper.mib_ndealloc)/sizeof(size_t);
        assert(!je_mallctlnametomib(buf,
                                    binfo->mib_helper.mib_ndealloc,
                                    &binfo->mib_helper.miblen_ndealloc));

        // set the reverse map of reg_size to bin index
        assert(jemalloc_sz2binind(binfo->reg_size) == j);
    }
    arena_bin_conf.nbins = nbins;
    usage_latest.bins_usage = zcalloc(sizeof(je_busage) * nbins);
    
    // get the mib of the per memory pointers query command that is used during defrag scan over memory
    arena_bin_conf.miblen_util_batch_query = sizeof(arena_bin_conf.mib_util_batch_query)/sizeof(size_t);
    if(je_mallctlnametomib("experimental.utilization.batch_query",
                                arena_bin_conf.mib_util_batch_query,
                                &arena_bin_conf.miblen_util_batch_query)) {
        defrag_supported = 0;
        return 0;
    }
    arena_bin_conf.miblen_util_query = sizeof(arena_bin_conf.mib_util_query)/sizeof(size_t);
    assert(!je_mallctlnametomib("experimental.utilization.query",
                                arena_bin_conf.mib_util_query, &arena_bin_conf.miblen_util_query));
    
    //
    defrag_supported = 1;
    return 1;
}
/* Total size of consumed meomry in unused regs in small bins (AKA external fragmentation). */

/* Compute the total memory wasted in fragmentation of inside small arena bins.
 * Done by summing the memory in unused regs in all slabs of all small bins. */
size_t defrag_jemalloc_get_frag_smallbins(void) {
    size_t frag = 0;
    // todo for frag calculation, should we consider sizes above page size?
    // especially in case of single reg in slab
    for (unsigned j = 0; j < arena_bin_conf.nbins; j++) {
        size_t sz;
        je_binfo* binfo = &arena_bin_conf.bin_info[j];
        je_busage* busage = &usage_latest.bins_usage[j];
        size_t curregs, curslabs, curr_nonfull_slabs;
        size_t nmalloc, ndealloc;
        /* Number of used regions in the bin */
        sz = sizeof(size_t);
        assert(!je_mallctlbymib(binfo->mib_helper.mib_curr_regs,
                                binfo->mib_helper.miblen_curr_regs,
                                &curregs, &sz, NULL, 0));
        /* Number of current slabs in the bin */
        sz = sizeof(size_t);
        assert(!je_mallctlbymib(binfo->mib_helper.mib_curr_slabs,
                                binfo->mib_helper.miblen_curr_slabs,
                                &curslabs, &sz, NULL, 0));
        /* Number of non full slabs in the bin */
        sz = sizeof(size_t);
        assert(!je_mallctlbymib(binfo->mib_helper.mib_nonfull_slabs,
                                binfo->mib_helper.miblen_nonfull_slabs,
                                &curr_nonfull_slabs, &sz, NULL, 0));
        /* Num alloc op */
        sz = sizeof(size_t);
        assert(!je_mallctlbymib(binfo->mib_helper.mib_nmalloc,
                                binfo->mib_helper.miblen_nmalloc,
                                &nmalloc, &sz, NULL, 0));
        /* Num dealloc op */
        sz = sizeof(size_t);
        assert(!je_mallctlbymib(binfo->mib_helper.mib_ndealloc,
                                binfo->mib_helper.miblen_ndealloc,
                                &ndealloc, &sz, NULL, 0));
        
        
        /* Calculate the fragmentation bytes for the current bin and add it to the total. */
        frag += ((binfo->nregs * curslabs) - curregs) * binfo->reg_size;
        busage->curr_slabs = curslabs;
        busage->curr_nonfull_slabs = curr_nonfull_slabs;
        busage->curr_full_slabs = curslabs - curr_nonfull_slabs;
        busage->curr_regs = curregs;
        if (curslabs*binfo->len != 0)
            busage->util = (100 * curregs * binfo->reg_size) /
                           (curslabs*binfo->len);
        size_t crr_regs_nonfull_slabs = curregs - busage->curr_full_slabs * binfo->nregs;
        if (curr_nonfull_slabs*binfo->len != 0) {
            busage->nonfull_util = (100 * crr_regs_nonfull_slabs * binfo->reg_size) / (curr_nonfull_slabs * binfo->len);
        } else {
            busage->nonfull_util = 100;
        }
        busage->can_defrag = (busage->nonfull_util*11 < 1000);
        busage->stat.nmalloc = nmalloc;
        busage->stat.ndealloc = ndealloc;
    }
    return frag;
}

int should_defrag(je_binfo* binfo, je_busage* busage,
                  size_t nalloced,
                  void *ptr) {
    UNUSED(ptr);
    /** we do not want to defrag if:
     * 1. nregs == 1. In this case moving is guaranteed to not change the frag ratio
     * 2. number of nonfull slabs is < 2. If we ignore the currslab we don't have anything to move
     * 3. keep the original algorithm as in je_hint.
     * */
    size_t allocated_nonfull =  busage->curr_regs - busage->curr_full_slabs*binfo->nregs;
    if ((!busage->can_defrag || binfo->nregs == 1 || busage->curr_nonfull_slabs <= 1 ||
         8*nalloced*busage->curr_nonfull_slabs > 8*allocated_nonfull + allocated_nonfull)) {
        return 0;
    } else {
        return 1;
    }
}

/** NOTE: compering to prior jemalloc hint, this implementation does not have the currslab information
 *  and could be defragging entry from that slab.
 *  My current thinking is that it's not such an issue, because it's either way likely get filled and
 *  stops being currslab (and at some point stops being candidate for defrag due to utilization).
 *  */
void defrag_jemalloc_should_defrag_multi(void **ptrs, size_t num) {
    assert(defrag_supported);
    assert(num < 100);
    static __thread size_t out[3*100] = {0};
    size_t out_sz = sizeof(size_t) * num * 3;
    size_t in_sz = sizeof(const void *) * num;

    for (unsigned j = 0; j < num * 3; j++) {
        out[j] = -1;
    }
    je_mallctlbymib(arena_bin_conf.mib_util_batch_query,
                    arena_bin_conf.miblen_util_batch_query,
                    out, &out_sz, ptrs, in_sz);

    usage_latest.stats.ncalls++;
    usage_latest.stats.nptrs += num;
    for (unsigned i = 0; i < num; i++) {
        size_t num_regs = SLAB_NUM_REGS(out, i);
        size_t slablen = SLAB_LEN(out, i);
        size_t nfree = SLAB_NFREE(out, i);
        assert(num_regs > 0);
        assert(slablen > 0);
        assert(nfree != (size_t)-1);
        unsigned bsz = slablen/num_regs;
        // check that the allocation is not too large
        if (bsz > arena_bin_conf.bin_info[arena_bin_conf.nbins-1].reg_size) {
            ptrs[i] = NULL;
            continue;
        }
        unsigned binind = jemalloc_sz2binind(bsz);
        // make sure binind is in range and reverse map is correct
        assert(binind < arena_bin_conf.nbins &&
               bsz == arena_bin_conf.bin_info[binind].reg_size);
        
        je_binfo* binfo = &arena_bin_conf.bin_info[binind];
        je_busage* busage = &usage_latest.bins_usage[binind];
        size_t nalloced = binfo->nregs - nfree;
        if (!should_defrag(binfo, busage, nalloced, ptrs[i])) {
            // MISS: utilization level is higher than threshold then set the ptr to NULL and caller will not defrag it
            ptrs[i] = NULL;
            //update miss statistics
            busage->stat.bmisses++;
            usage_latest.stats.misses++;
            usage_latest.stats.miss_bytes += bsz;
        } else { // HIT
            // update hit statistics
            busage->stat.bhits++;
            usage_latest.stats.hits++;
            usage_latest.stats.hit_bytes += bsz;
        }
    }
}
#else
int defrag_jemalloc_init(void) {
    return 0;
}
void defrag_jemalloc_free(void *ptr, size_t size) {
    UNUSED(ptr);
    UNUSED(size);
}
__attribute__((malloc)) void *defrag_jemalloc_alloc(size_t size) {
    UNUSED(size);
    return NULL;
}
size_t defrag_jemalloc_get_frag_smallbins(void) {
    return 0;
}
sds defrag_jemalloc_get_fragmentation_info(sds info) {
    return info;
}
void defrag_jemalloc_should_defrag_multi(void **ptrs, size_t num) {
    UNUSED(ptrs);
    UNUSED(num);
}
#endif