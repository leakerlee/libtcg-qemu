#ifndef LIBTCG_H
#define LIBTCG_H

#include <stdint.h>
#include <sys/mman.h>

#define PREFIX(x) LibTCG ## x
#define PREFIX2(x) LIBTCG_ ## x
#define PREFIX3(x) LIBTCG_ ## x

typedef uint8_t PREFIX(Reg);

#include "tcg-common.h"

#undef PREFIX
#undef PREFIX2
#undef PREFIX3

/**
 * This is a reduced version of TCGOp
 */
typedef struct LibTCGOp {
    LibTCGOpcode opc:8;

    /* The number of out and in parameter for a call. */
    unsigned calli:4;
    unsigned callo:2;

    LibTCGArg *args;
} LibTCGOp;

/**
 * Data structure holding a list of instructions, along with their arguments,
 * global and local variables
 */
typedef struct {
    LibTCGOp *instructions;
    unsigned instruction_count;

    /* Additional data, do not access this directly */
    LibTCGArg *arguments;
    LibTCGTemp *temps;
    unsigned global_temps;
    unsigned total_temps;
} LibTCGInstructions;

/**
 * Pair of an address in the emulated address space, and the corresponding
 * address in the host address space
 */
typedef struct {
    uint64_t virtual_address;
    void *pointer;
} address_pair;

/**
 * Maps a page in the emulated address space, if possible at @start. See mmap(2)
 * for further documentation.
 *
 * @return an address pair, i.e., the start of the mmap'd region in terms of the
 *         host and emulated address space.
 */
typedef address_pair (*libtcg_mmap_func)(uint64_t start, uint64_t len, int prot,
                                         int flags, int fd, off_t offset);

/**
 * Translates the basic block starting at @virtual_address into tiny code
 * instructions.
 *
 * @param virtual_address: the starting address of the basic block, in terms of
 *        the emulated address space.
 *
 * @return an instance of LibTCGInstructions containing the list generated of
 *         tiny code instructions. The caller is responsible to call
 *         free_instructions on this object when it's no longer needed.
 */
typedef LibTCGInstructions (*libtcg_translate_func)(uint64_t virtual_address);

/**
 * Releases the memory hold by @instructions.
 */
typedef void (*libtcg_free_instructions_func)(LibTCGInstructions *instructions);

typedef LibTCGHelperInfo *(*libtcg_find_helper_func)(uintptr_t val);
typedef int (*libtcg_munmap_func)(uint64_t start, uint64_t len);

typedef struct {
    libtcg_mmap_func mmap;
    libtcg_translate_func translate;
    libtcg_free_instructions_func free_instructions;
    libtcg_find_helper_func find_helper;
    libtcg_munmap_func munmap;
} LibTCGInterface;

/**
 * Initializes libtcg to generate code for @cpu_name.
 *
 * This is the only function exported by libtcg. Users are supposed to obtain
 * its address through dlsym(3), in this way multiple versions of libtcg can be
 * used at the same time by initializing them and using the appropriate
 * LibTCGInterface object.
 *
 * @param cpu_name: the name of the CPU to emulate. For a complete list invoke
 *        the qemu-user binary (e.g., qemu-arm) with the -cpu help option.
 * @param start_address: starting point for the guest address space, if in
 *        doubt, 0xb0000000 is usually a good value.
 *
 * @return an pointer to LibTCGInterface, which the caller can use to call the
 *         other functions exposed by libtcg.
 */
typedef const LibTCGInterface *(*libtcg_init_func)(const char *cpu_name,
                                                   intptr_t start_address);

#endif /* LIBTCG_H */
