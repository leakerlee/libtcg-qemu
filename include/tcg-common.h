/* This is file has no include guards because it's OK to include it multiple
 * times */

/* Includers should define the following macros:
 *
 * PREFIX: prefix for data types and structures.
 * PREFIX2: prefix for enum data types.
 * PREFIX3: prefix for other enum data types which, internally, do not need a
 *          prefix, since they already have one.
 */
#if !defined(PREFIX) || !defined(PREFIX2) || !defined(PREFIX3)
# error You need to define PREFIX, PREFIX2 and PREFIX3 to include this file
#endif

#include <stdint.h>

/* Includers outside the QEMU environment might need this. */
#ifndef TCG_TARGET_REG_BITS
# if __SIZEOF_POINTER__ == 8
#  define TCG_TARGET_REG_BITS 64
#  define TCG_TARGET_REG_BITS 64
# else
#  define TCG_TARGET_REG_BITS 32
# endif
#endif

#if TCG_TARGET_NB_REGS <= 32
typedef uint32_t PREFIX(RegSet);
#elif TCG_TARGET_NB_REGS <= 64
typedef uint64_t PREFIX(RegSet);
#else
#error unsupported
#endif

typedef uint64_t tcg_temp;
typedef uint64_t PREFIX(Arg);

typedef struct PREFIX(ArgConstraint) {
    uint16_t ct;
    uint8_t alias_index;
    union {
        PREFIX(RegSet) regs;
    } u;
} PREFIX(ArgConstraint);

typedef enum PREFIX(Opcode) {
#define DEF(name, oargs, iargs, cargs, flags) PREFIX3(INDEX_op_ ## name),
#include "tcg-opc.h"
#undef DEF
    PREFIX3(NB_OPS),
} PREFIX(Opcode);

typedef enum PREFIX(TempVal) {
    PREFIX3(TEMP_VAL_DEAD),
    PREFIX3(TEMP_VAL_REG),
    PREFIX3(TEMP_VAL_MEM),
    PREFIX3(TEMP_VAL_CONST),
} PREFIX(TempVal);

typedef enum PREFIX(Type) {
    PREFIX2(TYPE_I32),
    PREFIX2(TYPE_I64),

    PREFIX2(TYPE_V64),
    PREFIX2(TYPE_V128),
    PREFIX2(TYPE_V256),

    PREFIX2(TYPE_COUNT), /* number of different types */

#ifndef LIBTCG_INTERFACE
    /* An alias for the size of the host register.  */
#if TCG_TARGET_REG_BITS == 32
    PREFIX2(TYPE_REG) = PREFIX2(TYPE_I32),
#else
    PREFIX2(TYPE_REG) = PREFIX2(TYPE_I64),
#endif

    /* An alias for the size of the native pointer.  */
#if UINTPTR_MAX == UINT32_MAX
    PREFIX2(TYPE_PTR) = PREFIX2(TYPE_I32),
#else
    PREFIX2(TYPE_PTR) = PREFIX2(TYPE_I64),
#endif

    /* An alias for the size of the target "long", aka register.  */
#ifdef TARGET_LONG_BITS
#if TARGET_LONG_BITS == 64
    PREFIX2(TYPE_TL) = PREFIX2(TYPE_I64),
#else
    PREFIX2(TYPE_TL) = PREFIX2(TYPE_I32),
#endif
#endif

#endif
} PREFIX(Type);

typedef struct PREFIX(Temp) {
    PREFIX(Reg) reg:8;
    PREFIX(TempVal) val_type:8;
    PREFIX(Type) base_type:8;
    PREFIX(Type) type:8;
    unsigned int fixed_reg:1;
    unsigned int indirect_reg:1;
    unsigned int indirect_base:1;
    unsigned int mem_coherent:1;
    unsigned int mem_allocated:1;
    /* If true, the temp is saved across both basic blocks and
       translation blocks.  */
    unsigned int temp_global:1;
    /* If true, the temp is saved across basic blocks but dead
       at the end of translation blocks.  If false, the temp is
       dead at the end of basic blocks.  */
    unsigned int temp_local:1;
    unsigned int temp_allocated:1;

    //tcg_temp val;
    tcg_target_long val;
    struct PREFIX(Temp) *mem_base;
    intptr_t mem_offset;
    const char *name;

    /* Pass-specific information that can be stored for a temporary.
       One word worth of integer data, and one pointer to data
       allocated separately.  */
    uintptr_t state;
    void *state_ptr;
} PREFIX(Temp);

typedef struct PREFIX(OpDef) {
    const char *name;
    uint8_t nb_oargs, nb_iargs, nb_cargs, nb_args;
    uint8_t flags;
    PREFIX(ArgConstraint) *args_ct;
    int *sorted_args;
#if defined(CONFIG_DEBUG_TCG)
    int used;
#endif
} PREFIX(OpDef);

/* Conditions.  Note that these are laid out for easy manipulation by
   the functions below:
     bit 0 is used for inverting;
     bit 1 is signed,
     bit 2 is unsigned,
     bit 3 is used with bit 0 for swapping signed/unsigned.  */
typedef enum {
    /* non-signed */
    PREFIX2(COND_NEVER)  = 0 | 0 | 0 | 0,
    PREFIX2(COND_ALWAYS) = 0 | 0 | 0 | 1,
    PREFIX2(COND_EQ)     = 8 | 0 | 0 | 0,
    PREFIX2(COND_NE)     = 8 | 0 | 0 | 1,
    /* signed */
    PREFIX2(COND_LT)     = 0 | 0 | 2 | 0,
    PREFIX2(COND_GE)     = 0 | 0 | 2 | 1,
    PREFIX2(COND_LE)     = 8 | 0 | 2 | 0,
    PREFIX2(COND_GT)     = 8 | 0 | 2 | 1,
    /* unsigned */
    PREFIX2(COND_LTU)    = 0 | 4 | 0 | 0,
    PREFIX2(COND_GEU)    = 0 | 4 | 0 | 1,
    PREFIX2(COND_LEU)    = 8 | 4 | 0 | 0,
    PREFIX2(COND_GTU)    = 8 | 4 | 0 | 1,
} PREFIX(Cond);

/* Constants for qemu_ld and qemu_st for the Memory Operation field.  */
typedef enum PREFIX(MemOp) {
    PREFIX3(MO_8)     = 0,
    PREFIX3(MO_16)    = 1,
    PREFIX3(MO_32)    = 2,
    PREFIX3(MO_64)    = 3,
    PREFIX3(MO_SIZE)  = 3,   /* Mask for the above.  */

    PREFIX3(MO_SIGN)  = 4,   /* Sign-extended, otherwise zero-extended.  */

    PREFIX3(MO_BSWAP) = 8,   /* Host reverse endian.  */
#ifndef LIBTCG_INTERFACE
#ifdef HOST_WORDS_BIGENDIAN
    PREFIX3(MO_LE)    = PREFIX3(MO_BSWAP),
    PREFIX3(MO_BE)    = 0,
#else
    PREFIX3(MO_LE)    = 0,
    PREFIX3(MO_BE)    = PREFIX3(MO_BSWAP),
#endif
#ifdef TARGET_WORDS_BIGENDIAN
    PREFIX3(MO_TE)    = PREFIX3(MO_BE),
#else
    PREFIX3(MO_TE)    = PREFIX3(MO_LE),
#endif

    /* MO_UNALN accesses are never checked for alignment.
     * MO_ALIGN accesses will result in a call to the CPU's
     * do_unaligned_access hook if the guest address is not aligned.
     * The default depends on whether the target CPU defines ALIGNED_ONLY.
     *
     * Some architectures (e.g. ARMv8) need the address which is aligned
     * to a size more than the size of the memory access.
     * Some architectures (e.g. SPARCv9) need an address which is aligned,
     * but less strictly than the natural alignment.
     *
     * MO_ALIGN supposes the alignment size is the size of a memory access.
     *
     * There are three options:
     * - unaligned access permitted (MO_UNALN).
     * - an alignment to the size of an access (MO_ALIGN);
     * - an alignment to a specified size, which may be more or less than
     *   the access size (MO_ALIGN_x where 'x' is a size in bytes);
     */
    PREFIX3(MO_ASHIFT) = 4,
    PREFIX3(MO_AMASK) = 7 << PREFIX3(MO_ASHIFT),
#ifdef ALIGNED_ONLY
    PREFIX3(MO_ALIGN) = 0,
    PREFIX3(MO_UNALN) = PREFIX3(MO_AMASK),
#else
    PREFIX3(MO_ALIGN) = PREFIX3(MO_AMASK),
    PREFIX3(MO_UNALN) = 0,
#endif
    PREFIX3(MO_ALIGN_2)  = 1 << PREFIX3(MO_ASHIFT),
    PREFIX3(MO_ALIGN_4)  = 2 << PREFIX3(MO_ASHIFT),
    PREFIX3(MO_ALIGN_8)  = 3 << PREFIX3(MO_ASHIFT),
    PREFIX3(MO_ALIGN_16) = 4 << PREFIX3(MO_ASHIFT),
    PREFIX3(MO_ALIGN_32) = 5 << PREFIX3(MO_ASHIFT),
    PREFIX3(MO_ALIGN_64) = 6 << PREFIX3(MO_ASHIFT),

    /* Combinations of the above, for ease of use.  */
    PREFIX3(MO_UB)    = PREFIX3(MO_8),
    PREFIX3(MO_UW)    = PREFIX3(MO_16),
    PREFIX3(MO_UL)    = PREFIX3(MO_32),
    PREFIX3(MO_SB)    = PREFIX3(MO_SIGN) | PREFIX3(MO_8),
    PREFIX3(MO_SW)    = PREFIX3(MO_SIGN) | PREFIX3(MO_16),
    PREFIX3(MO_SL)    = PREFIX3(MO_SIGN) | PREFIX3(MO_32),
    PREFIX3(MO_Q)     = PREFIX3(MO_64),

    PREFIX3(MO_LEUW)  = PREFIX3(MO_LE) | PREFIX3(MO_UW),
    PREFIX3(MO_LEUL)  = PREFIX3(MO_LE) | PREFIX3(MO_UL),
    PREFIX3(MO_LESW)  = PREFIX3(MO_LE) | PREFIX3(MO_SW),
    PREFIX3(MO_LESL)  = PREFIX3(MO_LE) | PREFIX3(MO_SL),
    PREFIX3(MO_LEQ)   = PREFIX3(MO_LE) | PREFIX3(MO_Q),

    PREFIX3(MO_BEUW)  = PREFIX3(MO_BE) | PREFIX3(MO_UW),
    PREFIX3(MO_BEUL)  = PREFIX3(MO_BE) | PREFIX3(MO_UL),
    PREFIX3(MO_BESW)  = PREFIX3(MO_BE) | PREFIX3(MO_SW),
    PREFIX3(MO_BESL)  = PREFIX3(MO_BE) | PREFIX3(MO_SL),
    PREFIX3(MO_BEQ)   = PREFIX3(MO_BE) | PREFIX3(MO_Q),

    PREFIX3(MO_TEUW)  = PREFIX3(MO_TE) | PREFIX3(MO_UW),
    PREFIX3(MO_TEUL)  = PREFIX3(MO_TE) | PREFIX3(MO_UL),
    PREFIX3(MO_TESW)  = PREFIX3(MO_TE) | PREFIX3(MO_SW),
    PREFIX3(MO_TESL)  = PREFIX3(MO_TE) | PREFIX3(MO_SL),
    PREFIX3(MO_TEQ)   = PREFIX3(MO_TE) | PREFIX3(MO_Q),

    PREFIX3(MO_SSIZE) = PREFIX3(MO_SIZE) | PREFIX3(MO_SIGN),
#endif
} PREFIX(MemOp);

typedef struct PREFIX(HelperInfo) {
    void *func;
    const char *name;
    unsigned flags;
    unsigned sizemask;
} PREFIX(HelperInfo);
