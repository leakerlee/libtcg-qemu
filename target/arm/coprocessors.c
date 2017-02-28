#include "qemu/osdep.h"
#include "trace.h"
#include "cpu.h"
#include "internals.h"
#include "exec/gdbstub.h"
#include "sysemu/arch_init.h"
#include "sysemu/sysemu.h"
#include "exec/exec-all.h"

#define ARM_CPU_FREQ 1000000000 /* FIXME: 1 GHz, should be configurable */

#ifndef CONFIG_USER_ONLY
/* Definitions for the PMCCNTR and PMCR registers */
#define PMCRD   0x8
#define PMCRC   0x4
#define PMCRE   0x1
#endif

#ifndef CONFIG_LIBTCG
static int vfp_gdb_get_reg(CPUARMState *env, uint8_t *buf, int reg)
{
    int nregs;

    /* VFP data registers are always little-endian.  */
    nregs = arm_feature(env, ARM_FEATURE_VFP3) ? 32 : 16;
    if (reg < nregs) {
        stfq_le_p(buf, env->vfp.regs[reg]);
        return 8;
    }
    if (arm_feature(env, ARM_FEATURE_NEON)) {
        /* Aliases for Q regs.  */
        nregs += 16;
        if (reg < nregs) {
            stfq_le_p(buf, env->vfp.regs[(reg - 32) * 2]);
            stfq_le_p(buf + 8, env->vfp.regs[(reg - 32) * 2 + 1]);
            return 16;
        }
    }
    switch (reg - nregs) {
    case 0: stl_p(buf, env->vfp.xregs[ARM_VFP_FPSID]); return 4;
    case 1: stl_p(buf, env->vfp.xregs[ARM_VFP_FPSCR]); return 4;
    case 2: stl_p(buf, env->vfp.xregs[ARM_VFP_FPEXC]); return 4;
    }
    return 0;
}

static int vfp_gdb_set_reg(CPUARMState *env, uint8_t *buf, int reg)
{
    int nregs;

    nregs = arm_feature(env, ARM_FEATURE_VFP3) ? 32 : 16;
    if (reg < nregs) {
        env->vfp.regs[reg] = ldfq_le_p(buf);
        return 8;
    }
    if (arm_feature(env, ARM_FEATURE_NEON)) {
        nregs += 16;
        if (reg < nregs) {
            env->vfp.regs[(reg - 32) * 2] = ldfq_le_p(buf);
            env->vfp.regs[(reg - 32) * 2 + 1] = ldfq_le_p(buf + 8);
            return 16;
        }
    }
    switch (reg - nregs) {
    case 0: env->vfp.xregs[ARM_VFP_FPSID] = ldl_p(buf); return 4;
    case 1: env->vfp.xregs[ARM_VFP_FPSCR] = ldl_p(buf); return 4;
    case 2: env->vfp.xregs[ARM_VFP_FPEXC] = ldl_p(buf) & (1 << 30); return 4;
    }
    return 0;
}

static int aarch64_fpu_gdb_get_reg(CPUARMState *env, uint8_t *buf, int reg)
{
    switch (reg) {
    case 0 ... 31:
        /* 128 bit FP register */
        stfq_le_p(buf, env->vfp.regs[reg * 2]);
        stfq_le_p(buf + 8, env->vfp.regs[reg * 2 + 1]);
        return 16;
    case 32:
        /* FPSR */
        stl_p(buf, vfp_get_fpsr(env));
        return 4;
    case 33:
        /* FPCR */
        stl_p(buf, vfp_get_fpcr(env));
        return 4;
    default:
        return 0;
    }
}

static int aarch64_fpu_gdb_set_reg(CPUARMState *env, uint8_t *buf, int reg)
{
    switch (reg) {
    case 0 ... 31:
        /* 128 bit FP register */
        env->vfp.regs[reg * 2] = ldfq_le_p(buf);
        env->vfp.regs[reg * 2 + 1] = ldfq_le_p(buf + 8);
        return 16;
    case 32:
        /* FPSR */
        vfp_set_fpsr(env, ldl_p(buf));
        return 4;
    case 33:
        /* FPCR */
        vfp_set_fpcr(env, ldl_p(buf));
        return 4;
    default:
        return 0;
    }
}
#endif

static uint64_t raw_read(CPUARMState *env, const ARMCPRegInfo *ri)
{
    assert(ri->fieldoffset);
    if (cpreg_field_is_64bit(ri)) {
        return CPREG_FIELD64(env, ri);
    } else {
        return CPREG_FIELD32(env, ri);
    }
}

static void raw_write(CPUARMState *env, const ARMCPRegInfo *ri,
                      uint64_t value)
{
    assert(ri->fieldoffset);
    if (cpreg_field_is_64bit(ri)) {
        CPREG_FIELD64(env, ri) = value;
    } else {
        CPREG_FIELD32(env, ri) = value;
    }
}

static void *raw_ptr(CPUARMState *env, const ARMCPRegInfo *ri)
{
    return (char *)env + ri->fieldoffset;
}

uint64_t read_raw_cp_reg(CPUARMState *env, const ARMCPRegInfo *ri)
{
    /* Raw read of a coprocessor register (as needed for migration, etc). */
    if (ri->type & ARM_CP_CONST) {
        return ri->resetvalue;
    } else if (ri->raw_readfn) {
        return ri->raw_readfn(env, ri);
    } else if (ri->readfn) {
        return ri->readfn(env, ri);
    } else {
        return raw_read(env, ri);
    }
}

static void write_raw_cp_reg(CPUARMState *env, const ARMCPRegInfo *ri,
                             uint64_t v)
{
    /* Raw write of a coprocessor register (as needed for migration, etc).
     * Note that constant registers are treated as write-ignored; the
     * caller should check for success by whether a readback gives the
     * value written.
     */
    if (ri->type & ARM_CP_CONST) {
        return;
    } else if (ri->raw_writefn) {
        ri->raw_writefn(env, ri, v);
    } else if (ri->writefn) {
        ri->writefn(env, ri, v);
    } else {
        raw_write(env, ri, v);
    }
}

#ifndef CONFIG_LIBTCG
static bool raw_accessors_invalid(const ARMCPRegInfo *ri)
{
   /* Return true if the regdef would cause an assertion if you called
    * read_raw_cp_reg() or write_raw_cp_reg() on it (ie if it is a
    * program bug for it not to have the NO_RAW flag).
    * NB that returning false here doesn't necessarily mean that calling
    * read/write_raw_cp_reg() is safe, because we can't distinguish "has
    * read/write access functions which are safe for raw use" from "has
    * read/write access functions which have side effects but has forgotten
    * to provide raw access functions".
    * The tests here line up with the conditions in read/write_raw_cp_reg()
    * and assertions in raw_read()/raw_write().
    */
    if ((ri->type & ARM_CP_CONST) ||
        ri->fieldoffset ||
        ((ri->raw_writefn || ri->writefn) && (ri->raw_readfn || ri->readfn))) {
        return false;
    }
    return true;
}
#endif

bool write_cpustate_to_list(ARMCPU *cpu)
{
    /* Write the coprocessor state from cpu->env to the (index,value) list. */
    int i;
    bool ok = true;

    for (i = 0; i < cpu->cpreg_array_len; i++) {
        uint32_t regidx = kvm_to_cpreg_id(cpu->cpreg_indexes[i]);
        const ARMCPRegInfo *ri;

        ri = get_arm_cp_reginfo(cpu->cp_regs, regidx);
        if (!ri) {
            ok = false;
            continue;
        }
        if (ri->type & ARM_CP_NO_RAW) {
            continue;
        }
        cpu->cpreg_values[i] = read_raw_cp_reg(&cpu->env, ri);
    }
    return ok;
}

bool write_list_to_cpustate(ARMCPU *cpu)
{
    int i;
    bool ok = true;

    for (i = 0; i < cpu->cpreg_array_len; i++) {
        uint32_t regidx = kvm_to_cpreg_id(cpu->cpreg_indexes[i]);
        uint64_t v = cpu->cpreg_values[i];
        const ARMCPRegInfo *ri;

        ri = get_arm_cp_reginfo(cpu->cp_regs, regidx);
        if (!ri) {
            ok = false;
            continue;
        }
        if (ri->type & ARM_CP_NO_RAW) {
            continue;
        }
        /* Write value and confirm it reads back as written
         * (to catch read-only registers and partially read-only
         * registers where the incoming migration value doesn't match)
         */
        write_raw_cp_reg(&cpu->env, ri, v);
        if (read_raw_cp_reg(&cpu->env, ri) != v) {
            ok = false;
        }
    }
    return ok;
}

static void add_cpreg_to_list(gpointer key, gpointer opaque)
{
    ARMCPU *cpu = opaque;
    uint64_t regidx;
    const ARMCPRegInfo *ri;

    regidx = *(uint32_t *)key;
    ri = get_arm_cp_reginfo(cpu->cp_regs, regidx);

    if (!(ri->type & (ARM_CP_NO_RAW|ARM_CP_ALIAS))) {
        cpu->cpreg_indexes[cpu->cpreg_array_len] = cpreg_to_kvm_id(regidx);
        /* The value array need not be initialized at this point */
        cpu->cpreg_array_len++;
    }
}

static void count_cpreg(gpointer key, gpointer opaque)
{
    ARMCPU *cpu = opaque;
    uint64_t regidx;
    const ARMCPRegInfo *ri;

    regidx = *(uint32_t *)key;
    ri = get_arm_cp_reginfo(cpu->cp_regs, regidx);

    if (!(ri->type & (ARM_CP_NO_RAW|ARM_CP_ALIAS))) {
        cpu->cpreg_array_len++;
    }
}

static gint cpreg_key_compare(gconstpointer a, gconstpointer b)
{
    uint64_t aidx = cpreg_to_kvm_id(*(uint32_t *)a);
    uint64_t bidx = cpreg_to_kvm_id(*(uint32_t *)b);

    if (aidx > bidx) {
        return 1;
    }
    if (aidx < bidx) {
        return -1;
    }
    return 0;
}

void init_cpreg_list(ARMCPU *cpu)
{
    /* Initialise the cpreg_tuples[] array based on the cp_regs hash.
     * Note that we require cpreg_tuples[] to be sorted by key ID.
     */
    GList *keys;
    int arraylen;

    keys = g_hash_table_get_keys(cpu->cp_regs);
    keys = g_list_sort(keys, cpreg_key_compare);

    cpu->cpreg_array_len = 0;

    g_list_foreach(keys, count_cpreg, cpu);

    arraylen = cpu->cpreg_array_len;
    cpu->cpreg_indexes = g_new(uint64_t, arraylen);
    cpu->cpreg_values = g_new(uint64_t, arraylen);
    cpu->cpreg_vmstate_indexes = g_new(uint64_t, arraylen);
    cpu->cpreg_vmstate_values = g_new(uint64_t, arraylen);
    cpu->cpreg_vmstate_array_len = cpu->cpreg_array_len;
    cpu->cpreg_array_len = 0;

    g_list_foreach(keys, add_cpreg_to_list, cpu);

    assert(cpu->cpreg_array_len == arraylen);

    g_list_free(keys);
}

/*
 * Some registers are not accessible if EL3.NS=0 and EL3 is using AArch32 but
 * they are accessible when EL3 is using AArch64 regardless of EL3.NS.
 *
 * access_el3_aa32ns: Used to check AArch32 register views.
 * access_el3_aa32ns_aa64any: Used to check both AArch32/64 register views.
 */
static CPAccessResult access_el3_aa32ns(CPUARMState *env,
                                        const ARMCPRegInfo *ri,
                                        bool isread)
{
    bool secure = arm_is_secure_below_el3(env);

    assert(!arm_el_is_aa64(env, 3));
    if (secure) {
        return CP_ACCESS_TRAP_UNCATEGORIZED;
    }
    return CP_ACCESS_OK;
}

static CPAccessResult access_el3_aa32ns_aa64any(CPUARMState *env,
                                                const ARMCPRegInfo *ri,
                                                bool isread)
{
    if (!arm_el_is_aa64(env, 3)) {
        return access_el3_aa32ns(env, ri, isread);
    }
    return CP_ACCESS_OK;
}

/* Some secure-only AArch32 registers trap to EL3 if used from
 * Secure EL1 (but are just ordinary UNDEF in other non-EL3 contexts).
 * Note that an access from Secure EL1 can only happen if EL3 is AArch64.
 * We assume that the .access field is set to PL1_RW.
 */
static CPAccessResult access_trap_aa32s_el1(CPUARMState *env,
                                            const ARMCPRegInfo *ri,
                                            bool isread)
{
    if (arm_current_el(env) == 3) {
        return CP_ACCESS_OK;
    }
    if (arm_is_secure_below_el3(env)) {
        return CP_ACCESS_TRAP_EL3;
    }
    /* This will be EL1 NS and EL2 NS, which just UNDEF */
    return CP_ACCESS_TRAP_UNCATEGORIZED;
}

/* Check for traps to "powerdown debug" registers, which are controlled
 * by MDCR.TDOSA
 */
static CPAccessResult access_tdosa(CPUARMState *env, const ARMCPRegInfo *ri,
                                   bool isread)
{
    int el = arm_current_el(env);

    if (el < 2 && (env->cp15.mdcr_el2 & MDCR_TDOSA)
        && !arm_is_secure_below_el3(env)) {
        return CP_ACCESS_TRAP_EL2;
    }
    if (el < 3 && (env->cp15.mdcr_el3 & MDCR_TDOSA)) {
        return CP_ACCESS_TRAP_EL3;
    }
    return CP_ACCESS_OK;
}

/* Check for traps to "debug ROM" registers, which are controlled
 * by MDCR_EL2.TDRA for EL2 but by the more general MDCR_EL3.TDA for EL3.
 */
static CPAccessResult access_tdra(CPUARMState *env, const ARMCPRegInfo *ri,
                                  bool isread)
{
    int el = arm_current_el(env);

    if (el < 2 && (env->cp15.mdcr_el2 & MDCR_TDRA)
        && !arm_is_secure_below_el3(env)) {
        return CP_ACCESS_TRAP_EL2;
    }
    if (el < 3 && (env->cp15.mdcr_el3 & MDCR_TDA)) {
        return CP_ACCESS_TRAP_EL3;
    }
    return CP_ACCESS_OK;
}

/* Check for traps to general debug registers, which are controlled
 * by MDCR_EL2.TDA for EL2 and MDCR_EL3.TDA for EL3.
 */
static CPAccessResult access_tda(CPUARMState *env, const ARMCPRegInfo *ri,
                                  bool isread)
{
    int el = arm_current_el(env);

    if (el < 2 && (env->cp15.mdcr_el2 & MDCR_TDA)
        && !arm_is_secure_below_el3(env)) {
        return CP_ACCESS_TRAP_EL2;
    }
    if (el < 3 && (env->cp15.mdcr_el3 & MDCR_TDA)) {
        return CP_ACCESS_TRAP_EL3;
    }
    return CP_ACCESS_OK;
}

/* Check for traps to performance monitor registers, which are controlled
 * by MDCR_EL2.TPM for EL2 and MDCR_EL3.TPM for EL3.
 */
static CPAccessResult access_tpm(CPUARMState *env, const ARMCPRegInfo *ri,
                                 bool isread)
{
    int el = arm_current_el(env);

    if (el < 2 && (env->cp15.mdcr_el2 & MDCR_TPM)
        && !arm_is_secure_below_el3(env)) {
        return CP_ACCESS_TRAP_EL2;
    }
    if (el < 3 && (env->cp15.mdcr_el3 & MDCR_TPM)) {
        return CP_ACCESS_TRAP_EL3;
    }
    return CP_ACCESS_OK;
}

static void dacr_write(CPUARMState *env, const ARMCPRegInfo *ri, uint64_t value)
{
    ARMCPU *cpu = arm_env_get_cpu(env);

    raw_write(env, ri, value);
    tlb_flush(CPU(cpu)); /* Flush TLB as domain not tracked in TLB */
}

static void fcse_write(CPUARMState *env, const ARMCPRegInfo *ri, uint64_t value)
{
    ARMCPU *cpu = arm_env_get_cpu(env);

    if (raw_read(env, ri) != value) {
        /* Unlike real hardware the qemu TLB uses virtual addresses,
         * not modified virtual addresses, so this causes a TLB flush.
         */
        tlb_flush(CPU(cpu));
        raw_write(env, ri, value);
    }
}

static void contextidr_write(CPUARMState *env, const ARMCPRegInfo *ri,
                             uint64_t value)
{
    ARMCPU *cpu = arm_env_get_cpu(env);

    if (raw_read(env, ri) != value && !arm_feature(env, ARM_FEATURE_MPU)
        && !extended_addresses_enabled(env)) {
        /* For VMSA (when not using the LPAE long descriptor page table
         * format) this register includes the ASID, so do a TLB flush.
         * For PMSA it is purely a process ID and no action is needed.
         */
        tlb_flush(CPU(cpu));
    }
    raw_write(env, ri, value);
}

static void tlbiall_write(CPUARMState *env, const ARMCPRegInfo *ri,
                          uint64_t value)
{
    /* Invalidate all (TLBIALL) */
    ARMCPU *cpu = arm_env_get_cpu(env);

    tlb_flush(CPU(cpu));
}

static void tlbimva_write(CPUARMState *env, const ARMCPRegInfo *ri,
                          uint64_t value)
{
    /* Invalidate single TLB entry by MVA and ASID (TLBIMVA) */
    ARMCPU *cpu = arm_env_get_cpu(env);

    tlb_flush_page(CPU(cpu), value & TARGET_PAGE_MASK);
}

static void tlbiasid_write(CPUARMState *env, const ARMCPRegInfo *ri,
                           uint64_t value)
{
    /* Invalidate by ASID (TLBIASID) */
    ARMCPU *cpu = arm_env_get_cpu(env);

    tlb_flush(CPU(cpu));
}

static void tlbimvaa_write(CPUARMState *env, const ARMCPRegInfo *ri,
                           uint64_t value)
{
    /* Invalidate single entry by MVA, all ASIDs (TLBIMVAA) */
    ARMCPU *cpu = arm_env_get_cpu(env);

    tlb_flush_page(CPU(cpu), value & TARGET_PAGE_MASK);
}

/* IS variants of TLB operations must affect all cores */
static void tlbiall_is_write(CPUARMState *env, const ARMCPRegInfo *ri,
                             uint64_t value)
{
    CPUState *other_cs;

    CPU_FOREACH(other_cs) {
        tlb_flush(other_cs);
    }
}

static void tlbiasid_is_write(CPUARMState *env, const ARMCPRegInfo *ri,
                             uint64_t value)
{
    CPUState *other_cs;

    CPU_FOREACH(other_cs) {
        tlb_flush(other_cs);
    }
}

static void tlbimva_is_write(CPUARMState *env, const ARMCPRegInfo *ri,
                             uint64_t value)
{
    CPUState *other_cs;

    CPU_FOREACH(other_cs) {
        tlb_flush_page(other_cs, value & TARGET_PAGE_MASK);
    }
}

static void tlbimvaa_is_write(CPUARMState *env, const ARMCPRegInfo *ri,
                             uint64_t value)
{
    CPUState *other_cs;

    CPU_FOREACH(other_cs) {
        tlb_flush_page(other_cs, value & TARGET_PAGE_MASK);
    }
}

static void tlbiall_nsnh_write(CPUARMState *env, const ARMCPRegInfo *ri,
                               uint64_t value)
{
    CPUState *cs = ENV_GET_CPU(env);

    tlb_flush_by_mmuidx(cs, ARMMMUIdx_S12NSE1, ARMMMUIdx_S12NSE0,
                        ARMMMUIdx_S2NS, -1);
}

static void tlbiall_nsnh_is_write(CPUARMState *env, const ARMCPRegInfo *ri,
                                  uint64_t value)
{
    CPUState *other_cs;

    CPU_FOREACH(other_cs) {
        tlb_flush_by_mmuidx(other_cs, ARMMMUIdx_S12NSE1,
                            ARMMMUIdx_S12NSE0, ARMMMUIdx_S2NS, -1);
    }
}

static void tlbiipas2_write(CPUARMState *env, const ARMCPRegInfo *ri,
                            uint64_t value)
{
    /* Invalidate by IPA. This has to invalidate any structures that
     * contain only stage 2 translation information, but does not need
     * to apply to structures that contain combined stage 1 and stage 2
     * translation information.
     * This must NOP if EL2 isn't implemented or SCR_EL3.NS is zero.
     */
    CPUState *cs = ENV_GET_CPU(env);
    uint64_t pageaddr;

    if (!arm_feature(env, ARM_FEATURE_EL2) || !(env->cp15.scr_el3 & SCR_NS)) {
        return;
    }

    pageaddr = sextract64(value << 12, 0, 40);

    tlb_flush_page_by_mmuidx(cs, pageaddr, ARMMMUIdx_S2NS, -1);
}

static void tlbiipas2_is_write(CPUARMState *env, const ARMCPRegInfo *ri,
                               uint64_t value)
{
    CPUState *other_cs;
    uint64_t pageaddr;

    if (!arm_feature(env, ARM_FEATURE_EL2) || !(env->cp15.scr_el3 & SCR_NS)) {
        return;
    }

    pageaddr = sextract64(value << 12, 0, 40);

    CPU_FOREACH(other_cs) {
        tlb_flush_page_by_mmuidx(other_cs, pageaddr, ARMMMUIdx_S2NS, -1);
    }
}

static void tlbiall_hyp_write(CPUARMState *env, const ARMCPRegInfo *ri,
                              uint64_t value)
{
    CPUState *cs = ENV_GET_CPU(env);

    tlb_flush_by_mmuidx(cs, ARMMMUIdx_S1E2, -1);
}

static void tlbiall_hyp_is_write(CPUARMState *env, const ARMCPRegInfo *ri,
                                 uint64_t value)
{
    CPUState *other_cs;

    CPU_FOREACH(other_cs) {
        tlb_flush_by_mmuidx(other_cs, ARMMMUIdx_S1E2, -1);
    }
}

static void tlbimva_hyp_write(CPUARMState *env, const ARMCPRegInfo *ri,
                              uint64_t value)
{
    CPUState *cs = ENV_GET_CPU(env);
    uint64_t pageaddr = value & ~MAKE_64BIT_MASK(0, 12);

    tlb_flush_page_by_mmuidx(cs, pageaddr, ARMMMUIdx_S1E2, -1);
}

static void tlbimva_hyp_is_write(CPUARMState *env, const ARMCPRegInfo *ri,
                                 uint64_t value)
{
    CPUState *other_cs;
    uint64_t pageaddr = value & ~MAKE_64BIT_MASK(0, 12);

    CPU_FOREACH(other_cs) {
        tlb_flush_page_by_mmuidx(other_cs, pageaddr, ARMMMUIdx_S1E2, -1);
    }
}

static const ARMCPRegInfo cp_reginfo[] = {
    /* Define the secure and non-secure FCSE identifier CP registers
     * separately because there is no secure bank in V8 (no _EL3).  This allows
     * the secure register to be properly reset and migrated. There is also no
     * v8 EL1 version of the register so the non-secure instance stands alone.
     */
    { .name = "FCSEIDR(NS)",
      .cp = 15, .opc1 = 0, .crn = 13, .crm = 0, .opc2 = 0,
      .access = PL1_RW, .secure = ARM_CP_SECSTATE_NS,
      .fieldoffset = offsetof(CPUARMState, cp15.fcseidr_ns),
      .resetvalue = 0, .writefn = fcse_write, .raw_writefn = raw_write, },
    { .name = "FCSEIDR(S)",
      .cp = 15, .opc1 = 0, .crn = 13, .crm = 0, .opc2 = 0,
      .access = PL1_RW, .secure = ARM_CP_SECSTATE_S,
      .fieldoffset = offsetof(CPUARMState, cp15.fcseidr_s),
      .resetvalue = 0, .writefn = fcse_write, .raw_writefn = raw_write, },
    /* Define the secure and non-secure context identifier CP registers
     * separately because there is no secure bank in V8 (no _EL3).  This allows
     * the secure register to be properly reset and migrated.  In the
     * non-secure case, the 32-bit register will have reset and migration
     * disabled during registration as it is handled by the 64-bit instance.
     */
    { .name = "CONTEXTIDR_EL1", .state = ARM_CP_STATE_BOTH,
      .opc0 = 3, .opc1 = 0, .crn = 13, .crm = 0, .opc2 = 1,
      .access = PL1_RW, .secure = ARM_CP_SECSTATE_NS,
      .fieldoffset = offsetof(CPUARMState, cp15.contextidr_el[1]),
      .resetvalue = 0, .writefn = contextidr_write, .raw_writefn = raw_write, },
    { .name = "CONTEXTIDR(S)", .state = ARM_CP_STATE_AA32,
      .cp = 15, .opc1 = 0, .crn = 13, .crm = 0, .opc2 = 1,
      .access = PL1_RW, .secure = ARM_CP_SECSTATE_S,
      .fieldoffset = offsetof(CPUARMState, cp15.contextidr_s),
      .resetvalue = 0, .writefn = contextidr_write, .raw_writefn = raw_write, },
    REGINFO_SENTINEL
};

static const ARMCPRegInfo not_v8_cp_reginfo[] = {
    /* NB: Some of these registers exist in v8 but with more precise
     * definitions that don't use CP_ANY wildcards (mostly in v8_cp_reginfo[]).
     */
    /* MMU Domain access control / MPU write buffer control */
    { .name = "DACR",
      .cp = 15, .opc1 = CP_ANY, .crn = 3, .crm = CP_ANY, .opc2 = CP_ANY,
      .access = PL1_RW, .resetvalue = 0,
      .writefn = dacr_write, .raw_writefn = raw_write,
      .bank_fieldoffsets = { offsetoflow32(CPUARMState, cp15.dacr_s),
                             offsetoflow32(CPUARMState, cp15.dacr_ns) } },
    /* ARMv7 allocates a range of implementation defined TLB LOCKDOWN regs.
     * For v6 and v5, these mappings are overly broad.
     */
    { .name = "TLB_LOCKDOWN", .cp = 15, .crn = 10, .crm = 0,
      .opc1 = CP_ANY, .opc2 = CP_ANY, .access = PL1_RW, .type = ARM_CP_NOP },
    { .name = "TLB_LOCKDOWN", .cp = 15, .crn = 10, .crm = 1,
      .opc1 = CP_ANY, .opc2 = CP_ANY, .access = PL1_RW, .type = ARM_CP_NOP },
    { .name = "TLB_LOCKDOWN", .cp = 15, .crn = 10, .crm = 4,
      .opc1 = CP_ANY, .opc2 = CP_ANY, .access = PL1_RW, .type = ARM_CP_NOP },
    { .name = "TLB_LOCKDOWN", .cp = 15, .crn = 10, .crm = 8,
      .opc1 = CP_ANY, .opc2 = CP_ANY, .access = PL1_RW, .type = ARM_CP_NOP },
    /* Cache maintenance ops; some of this space may be overridden later. */
    { .name = "CACHEMAINT", .cp = 15, .crn = 7, .crm = CP_ANY,
      .opc1 = 0, .opc2 = CP_ANY, .access = PL1_W,
      .type = ARM_CP_NOP | ARM_CP_OVERRIDE },
    REGINFO_SENTINEL
};

static const ARMCPRegInfo not_v6_cp_reginfo[] = {
    /* Not all pre-v6 cores implemented this WFI, so this is slightly
     * over-broad.
     */
    { .name = "WFI_v5", .cp = 15, .crn = 7, .crm = 8, .opc1 = 0, .opc2 = 2,
      .access = PL1_W, .type = ARM_CP_WFI },
    REGINFO_SENTINEL
};

static const ARMCPRegInfo not_v7_cp_reginfo[] = {
    /* Standard v6 WFI (also used in some pre-v6 cores); not in v7 (which
     * is UNPREDICTABLE; we choose to NOP as most implementations do).
     */
    { .name = "WFI_v6", .cp = 15, .crn = 7, .crm = 0, .opc1 = 0, .opc2 = 4,
      .access = PL1_W, .type = ARM_CP_WFI },
    /* L1 cache lockdown. Not architectural in v6 and earlier but in practice
     * implemented in 926, 946, 1026, 1136, 1176 and 11MPCore. StrongARM and
     * OMAPCP will override this space.
     */
    { .name = "DLOCKDOWN", .cp = 15, .crn = 9, .crm = 0, .opc1 = 0, .opc2 = 0,
      .access = PL1_RW, .fieldoffset = offsetof(CPUARMState, cp15.c9_data),
      .resetvalue = 0 },
    { .name = "ILOCKDOWN", .cp = 15, .crn = 9, .crm = 0, .opc1 = 0, .opc2 = 1,
      .access = PL1_RW, .fieldoffset = offsetof(CPUARMState, cp15.c9_insn),
      .resetvalue = 0 },
    /* v6 doesn't have the cache ID registers but Linux reads them anyway */
    { .name = "DUMMY", .cp = 15, .crn = 0, .crm = 0, .opc1 = 1, .opc2 = CP_ANY,
      .access = PL1_R, .type = ARM_CP_CONST | ARM_CP_NO_RAW,
      .resetvalue = 0 },
    /* We don't implement pre-v7 debug but most CPUs had at least a DBGDIDR;
     * implementing it as RAZ means the "debug architecture version" bits
     * will read as a reserved value, which should cause Linux to not try
     * to use the debug hardware.
     */
    { .name = "DBGDIDR", .cp = 14, .crn = 0, .crm = 0, .opc1 = 0, .opc2 = 0,
      .access = PL0_R, .type = ARM_CP_CONST, .resetvalue = 0 },
    /* MMU TLB control. Note that the wildcarding means we cover not just
     * the unified TLB ops but also the dside/iside/inner-shareable variants.
     */
    { .name = "TLBIALL", .cp = 15, .crn = 8, .crm = CP_ANY,
      .opc1 = CP_ANY, .opc2 = 0, .access = PL1_W, .writefn = tlbiall_write,
      .type = ARM_CP_NO_RAW },
    { .name = "TLBIMVA", .cp = 15, .crn = 8, .crm = CP_ANY,
      .opc1 = CP_ANY, .opc2 = 1, .access = PL1_W, .writefn = tlbimva_write,
      .type = ARM_CP_NO_RAW },
    { .name = "TLBIASID", .cp = 15, .crn = 8, .crm = CP_ANY,
      .opc1 = CP_ANY, .opc2 = 2, .access = PL1_W, .writefn = tlbiasid_write,
      .type = ARM_CP_NO_RAW },
    { .name = "TLBIMVAA", .cp = 15, .crn = 8, .crm = CP_ANY,
      .opc1 = CP_ANY, .opc2 = 3, .access = PL1_W, .writefn = tlbimvaa_write,
      .type = ARM_CP_NO_RAW },
    { .name = "PRRR", .cp = 15, .crn = 10, .crm = 2,
      .opc1 = 0, .opc2 = 0, .access = PL1_RW, .type = ARM_CP_NOP },
    { .name = "NMRR", .cp = 15, .crn = 10, .crm = 2,
      .opc1 = 0, .opc2 = 1, .access = PL1_RW, .type = ARM_CP_NOP },
    REGINFO_SENTINEL
};

static void cpacr_write(CPUARMState *env, const ARMCPRegInfo *ri,
                        uint64_t value)
{
    uint32_t mask = 0;

    /* In ARMv8 most bits of CPACR_EL1 are RES0. */
    if (!arm_feature(env, ARM_FEATURE_V8)) {
        /* ARMv7 defines bits for unimplemented coprocessors as RAZ/WI.
         * ASEDIS [31] and D32DIS [30] are both UNK/SBZP without VFP.
         * TRCDIS [28] is RAZ/WI since we do not implement a trace macrocell.
         */
        if (arm_feature(env, ARM_FEATURE_VFP)) {
            /* VFP coprocessor: cp10 & cp11 [23:20] */
            mask |= (1 << 31) | (1 << 30) | (0xf << 20);

            if (!arm_feature(env, ARM_FEATURE_NEON)) {
                /* ASEDIS [31] bit is RAO/WI */
                value |= (1 << 31);
            }

            /* VFPv3 and upwards with NEON implement 32 double precision
             * registers (D0-D31).
             */
            if (!arm_feature(env, ARM_FEATURE_NEON) ||
                    !arm_feature(env, ARM_FEATURE_VFP3)) {
                /* D32DIS [30] is RAO/WI if D16-31 are not implemented. */
                value |= (1 << 30);
            }
        }
        value &= mask;
    }
    env->cp15.cpacr_el1 = value;
}

static CPAccessResult cpacr_access(CPUARMState *env, const ARMCPRegInfo *ri,
                                   bool isread)
{
    if (arm_feature(env, ARM_FEATURE_V8)) {
        /* Check if CPACR accesses are to be trapped to EL2 */
        if (arm_current_el(env) == 1 &&
            (env->cp15.cptr_el[2] & CPTR_TCPAC) && !arm_is_secure(env)) {
            return CP_ACCESS_TRAP_EL2;
        /* Check if CPACR accesses are to be trapped to EL3 */
        } else if (arm_current_el(env) < 3 &&
                   (env->cp15.cptr_el[3] & CPTR_TCPAC)) {
            return CP_ACCESS_TRAP_EL3;
        }
    }

    return CP_ACCESS_OK;
}

static CPAccessResult cptr_access(CPUARMState *env, const ARMCPRegInfo *ri,
                                  bool isread)
{
    /* Check if CPTR accesses are set to trap to EL3 */
    if (arm_current_el(env) == 2 && (env->cp15.cptr_el[3] & CPTR_TCPAC)) {
        return CP_ACCESS_TRAP_EL3;
    }

    return CP_ACCESS_OK;
}

static const ARMCPRegInfo v6_cp_reginfo[] = {
    /* prefetch by MVA in v6, NOP in v7 */
    { .name = "MVA_prefetch",
      .cp = 15, .crn = 7, .crm = 13, .opc1 = 0, .opc2 = 1,
      .access = PL1_W, .type = ARM_CP_NOP },
    /* We need to break the TB after ISB to execute self-modifying code
     * correctly and also to take any pending interrupts immediately.
     * So use arm_cp_write_ignore() function instead of ARM_CP_NOP flag.
     */
    { .name = "ISB", .cp = 15, .crn = 7, .crm = 5, .opc1 = 0, .opc2 = 4,
      .access = PL0_W, .type = ARM_CP_NO_RAW, .writefn = arm_cp_write_ignore },
    { .name = "DSB", .cp = 15, .crn = 7, .crm = 10, .opc1 = 0, .opc2 = 4,
      .access = PL0_W, .type = ARM_CP_NOP },
    { .name = "DMB", .cp = 15, .crn = 7, .crm = 10, .opc1 = 0, .opc2 = 5,
      .access = PL0_W, .type = ARM_CP_NOP },
    { .name = "IFAR", .cp = 15, .crn = 6, .crm = 0, .opc1 = 0, .opc2 = 2,
      .access = PL1_RW,
      .bank_fieldoffsets = { offsetof(CPUARMState, cp15.ifar_s),
                             offsetof(CPUARMState, cp15.ifar_ns) },
      .resetvalue = 0, },
    /* Watchpoint Fault Address Register : should actually only be present
     * for 1136, 1176, 11MPCore.
     */
    { .name = "WFAR", .cp = 15, .crn = 6, .crm = 0, .opc1 = 0, .opc2 = 1,
      .access = PL1_RW, .type = ARM_CP_CONST, .resetvalue = 0, },
    { .name = "CPACR", .state = ARM_CP_STATE_BOTH, .opc0 = 3,
      .crn = 1, .crm = 0, .opc1 = 0, .opc2 = 2, .accessfn = cpacr_access,
      .access = PL1_RW, .fieldoffset = offsetof(CPUARMState, cp15.cpacr_el1),
      .resetvalue = 0, .writefn = cpacr_write },
    REGINFO_SENTINEL
};

static CPAccessResult pmreg_access(CPUARMState *env, const ARMCPRegInfo *ri,
                                   bool isread)
{
    /* Performance monitor registers user accessibility is controlled
     * by PMUSERENR. MDCR_EL2.TPM and MDCR_EL3.TPM allow configurable
     * trapping to EL2 or EL3 for other accesses.
     */
    int el = arm_current_el(env);

    if (el == 0 && !env->cp15.c9_pmuserenr) {
        return CP_ACCESS_TRAP;
    }
    if (el < 2 && (env->cp15.mdcr_el2 & MDCR_TPM)
        && !arm_is_secure_below_el3(env)) {
        return CP_ACCESS_TRAP_EL2;
    }
    if (el < 3 && (env->cp15.mdcr_el3 & MDCR_TPM)) {
        return CP_ACCESS_TRAP_EL3;
    }

    return CP_ACCESS_OK;
}

#ifndef CONFIG_USER_ONLY

static inline bool arm_ccnt_enabled(CPUARMState *env)
{
    /* This does not support checking PMCCFILTR_EL0 register */

    if (!(env->cp15.c9_pmcr & PMCRE)) {
        return false;
    }

    return true;
}

void pmccntr_sync(CPUARMState *env)
{
    uint64_t temp_ticks;

    temp_ticks = muldiv64(qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL),
                          ARM_CPU_FREQ, NANOSECONDS_PER_SECOND);

    if (env->cp15.c9_pmcr & PMCRD) {
        /* Increment once every 64 processor clock cycles */
        temp_ticks /= 64;
    }

    if (arm_ccnt_enabled(env)) {
        env->cp15.c15_ccnt = temp_ticks - env->cp15.c15_ccnt;
    }
}

static void pmcr_write(CPUARMState *env, const ARMCPRegInfo *ri,
                       uint64_t value)
{
    pmccntr_sync(env);

    if (value & PMCRC) {
        /* The counter has been reset */
        env->cp15.c15_ccnt = 0;
    }

    /* only the DP, X, D and E bits are writable */
    env->cp15.c9_pmcr &= ~0x39;
    env->cp15.c9_pmcr |= (value & 0x39);

    pmccntr_sync(env);
}

static uint64_t pmccntr_read(CPUARMState *env, const ARMCPRegInfo *ri)
{
    uint64_t total_ticks;

    if (!arm_ccnt_enabled(env)) {
        /* Counter is disabled, do not change value */
        return env->cp15.c15_ccnt;
    }

    total_ticks = muldiv64(qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL),
                           ARM_CPU_FREQ, NANOSECONDS_PER_SECOND);

    if (env->cp15.c9_pmcr & PMCRD) {
        /* Increment once every 64 processor clock cycles */
        total_ticks /= 64;
    }
    return total_ticks - env->cp15.c15_ccnt;
}

static void pmselr_write(CPUARMState *env, const ARMCPRegInfo *ri,
                         uint64_t value)
{
    /* The value of PMSELR.SEL affects the behavior of PMXEVTYPER and
     * PMXEVCNTR. We allow [0..31] to be written to PMSELR here; in the
     * meanwhile, we check PMSELR.SEL when PMXEVTYPER and PMXEVCNTR are
     * accessed.
     */
    env->cp15.c9_pmselr = value & 0x1f;
}

static void pmccntr_write(CPUARMState *env, const ARMCPRegInfo *ri,
                        uint64_t value)
{
    uint64_t total_ticks;

    if (!arm_ccnt_enabled(env)) {
        /* Counter is disabled, set the absolute value */
        env->cp15.c15_ccnt = value;
        return;
    }

    total_ticks = muldiv64(qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL),
                           ARM_CPU_FREQ, NANOSECONDS_PER_SECOND);

    if (env->cp15.c9_pmcr & PMCRD) {
        /* Increment once every 64 processor clock cycles */
        total_ticks /= 64;
    }
    env->cp15.c15_ccnt = total_ticks - value;
}

static void pmccntr_write32(CPUARMState *env, const ARMCPRegInfo *ri,
                            uint64_t value)
{
    uint64_t cur_val = pmccntr_read(env, NULL);

    pmccntr_write(env, ri, deposit64(cur_val, 0, 32, value));
}

#else /* CONFIG_USER_ONLY */

void pmccntr_sync(CPUARMState *env)
{
}

#endif

static void pmccfiltr_write(CPUARMState *env, const ARMCPRegInfo *ri,
                            uint64_t value)
{
    pmccntr_sync(env);
    env->cp15.pmccfiltr_el0 = value & 0x7E000000;
    pmccntr_sync(env);
}

static void pmcntenset_write(CPUARMState *env, const ARMCPRegInfo *ri,
                            uint64_t value)
{
    value &= (1 << 31);
    env->cp15.c9_pmcnten |= value;
}

static void pmcntenclr_write(CPUARMState *env, const ARMCPRegInfo *ri,
                             uint64_t value)
{
    value &= (1 << 31);
    env->cp15.c9_pmcnten &= ~value;
}

static void pmovsr_write(CPUARMState *env, const ARMCPRegInfo *ri,
                         uint64_t value)
{
    env->cp15.c9_pmovsr &= ~value;
}

static void pmxevtyper_write(CPUARMState *env, const ARMCPRegInfo *ri,
                             uint64_t value)
{
    /* Attempts to access PMXEVTYPER are CONSTRAINED UNPREDICTABLE when
     * PMSELR value is equal to or greater than the number of implemented
     * counters, but not equal to 0x1f. We opt to behave as a RAZ/WI.
     */
    if (env->cp15.c9_pmselr == 0x1f) {
        pmccfiltr_write(env, ri, value);
    }
}

static uint64_t pmxevtyper_read(CPUARMState *env, const ARMCPRegInfo *ri)
{
    /* We opt to behave as a RAZ/WI when attempts to access PMXEVTYPER
     * are CONSTRAINED UNPREDICTABLE. See comments in pmxevtyper_write().
     */
    if (env->cp15.c9_pmselr == 0x1f) {
        return env->cp15.pmccfiltr_el0;
    } else {
        return 0;
    }
}

static void pmuserenr_write(CPUARMState *env, const ARMCPRegInfo *ri,
                            uint64_t value)
{
    env->cp15.c9_pmuserenr = value & 1;
}

static void pmintenset_write(CPUARMState *env, const ARMCPRegInfo *ri,
                             uint64_t value)
{
    /* We have no event counters so only the C bit can be changed */
    value &= (1 << 31);
    env->cp15.c9_pminten |= value;
}

static void pmintenclr_write(CPUARMState *env, const ARMCPRegInfo *ri,
                             uint64_t value)
{
    value &= (1 << 31);
    env->cp15.c9_pminten &= ~value;
}

static void vbar_write(CPUARMState *env, const ARMCPRegInfo *ri,
                       uint64_t value)
{
    /* Note that even though the AArch64 view of this register has bits
     * [10:0] all RES0 we can only mask the bottom 5, to comply with the
     * architectural requirements for bits which are RES0 only in some
     * contexts. (ARMv8 would permit us to do no masking at all, but ARMv7
     * requires the bottom five bits to be RAZ/WI because they're UNK/SBZP.)
     */
    raw_write(env, ri, value & ~0x1FULL);
}

static void scr_write(CPUARMState *env, const ARMCPRegInfo *ri, uint64_t value)
{
    /* We only mask off bits that are RES0 both for AArch64 and AArch32.
     * For bits that vary between AArch32/64, code needs to check the
     * current execution mode before directly using the feature bit.
     */
    uint32_t valid_mask = SCR_AARCH64_MASK | SCR_AARCH32_MASK;

    if (!arm_feature(env, ARM_FEATURE_EL2)) {
        valid_mask &= ~SCR_HCE;

        /* On ARMv7, SMD (or SCD as it is called in v7) is only
         * supported if EL2 exists. The bit is UNK/SBZP when
         * EL2 is unavailable. In QEMU ARMv7, we force it to always zero
         * when EL2 is unavailable.
         * On ARMv8, this bit is always available.
         */
        if (arm_feature(env, ARM_FEATURE_V7) &&
            !arm_feature(env, ARM_FEATURE_V8)) {
            valid_mask &= ~SCR_SMD;
        }
    }

    /* Clear all-context RES0 bits.  */
    value &= valid_mask;
    raw_write(env, ri, value);
}

static uint64_t ccsidr_read(CPUARMState *env, const ARMCPRegInfo *ri)
{
    ARMCPU *cpu = arm_env_get_cpu(env);

    /* Acquire the CSSELR index from the bank corresponding to the CCSIDR
     * bank
     */
    uint32_t index = A32_BANKED_REG_GET(env, csselr,
                                        ri->secure & ARM_CP_SECSTATE_S);

    return cpu->ccsidr[index];
}

static void csselr_write(CPUARMState *env, const ARMCPRegInfo *ri,
                         uint64_t value)
{
    raw_write(env, ri, value & 0xf);
}

static uint64_t isr_read(CPUARMState *env, const ARMCPRegInfo *ri)
{
    CPUState *cs = ENV_GET_CPU(env);
    uint64_t ret = 0;

    if (cs->interrupt_request & CPU_INTERRUPT_HARD) {
        ret |= CPSR_I;
    }
    if (cs->interrupt_request & CPU_INTERRUPT_FIQ) {
        ret |= CPSR_F;
    }
    /* External aborts are not possible in QEMU so A bit is always clear */
    return ret;
}

static const ARMCPRegInfo v7_cp_reginfo[] = {
    /* the old v6 WFI, UNPREDICTABLE in v7 but we choose to NOP */
    { .name = "NOP", .cp = 15, .crn = 7, .crm = 0, .opc1 = 0, .opc2 = 4,
      .access = PL1_W, .type = ARM_CP_NOP },
    /* Performance monitors are implementation defined in v7,
     * but with an ARM recommended set of registers, which we
     * follow (although we don't actually implement any counters)
     *
     * Performance registers fall into three categories:
     *  (a) always UNDEF in PL0, RW in PL1 (PMINTENSET, PMINTENCLR)
     *  (b) RO in PL0 (ie UNDEF on write), RW in PL1 (PMUSERENR)
     *  (c) UNDEF in PL0 if PMUSERENR.EN==0, otherwise accessible (all others)
     * For the cases controlled by PMUSERENR we must set .access to PL0_RW
     * or PL0_RO as appropriate and then check PMUSERENR in the helper fn.
     */
    { .name = "PMCNTENSET", .cp = 15, .crn = 9, .crm = 12, .opc1 = 0, .opc2 = 1,
      .access = PL0_RW, .type = ARM_CP_ALIAS,
      .fieldoffset = offsetoflow32(CPUARMState, cp15.c9_pmcnten),
      .writefn = pmcntenset_write,
      .accessfn = pmreg_access,
      .raw_writefn = raw_write },
    { .name = "PMCNTENSET_EL0", .state = ARM_CP_STATE_AA64,
      .opc0 = 3, .opc1 = 3, .crn = 9, .crm = 12, .opc2 = 1,
      .access = PL0_RW, .accessfn = pmreg_access,
      .fieldoffset = offsetof(CPUARMState, cp15.c9_pmcnten), .resetvalue = 0,
      .writefn = pmcntenset_write, .raw_writefn = raw_write },
    { .name = "PMCNTENCLR", .cp = 15, .crn = 9, .crm = 12, .opc1 = 0, .opc2 = 2,
      .access = PL0_RW,
      .fieldoffset = offsetoflow32(CPUARMState, cp15.c9_pmcnten),
      .accessfn = pmreg_access,
      .writefn = pmcntenclr_write,
      .type = ARM_CP_ALIAS },
    { .name = "PMCNTENCLR_EL0", .state = ARM_CP_STATE_AA64,
      .opc0 = 3, .opc1 = 3, .crn = 9, .crm = 12, .opc2 = 2,
      .access = PL0_RW, .accessfn = pmreg_access,
      .type = ARM_CP_ALIAS,
      .fieldoffset = offsetof(CPUARMState, cp15.c9_pmcnten),
      .writefn = pmcntenclr_write },
    { .name = "PMOVSR", .cp = 15, .crn = 9, .crm = 12, .opc1 = 0, .opc2 = 3,
      .access = PL0_RW, .fieldoffset = offsetof(CPUARMState, cp15.c9_pmovsr),
      .accessfn = pmreg_access,
      .writefn = pmovsr_write,
      .raw_writefn = raw_write },
    { .name = "PMOVSCLR_EL0", .state = ARM_CP_STATE_AA64,
      .opc0 = 3, .opc1 = 3, .crn = 9, .crm = 12, .opc2 = 3,
      .access = PL0_RW, .accessfn = pmreg_access,
      .type = ARM_CP_ALIAS,
      .fieldoffset = offsetof(CPUARMState, cp15.c9_pmovsr),
      .writefn = pmovsr_write,
      .raw_writefn = raw_write },
    /* Unimplemented so WI. */
    { .name = "PMSWINC", .cp = 15, .crn = 9, .crm = 12, .opc1 = 0, .opc2 = 4,
      .access = PL0_W, .accessfn = pmreg_access, .type = ARM_CP_NOP },
#ifndef CONFIG_USER_ONLY
    { .name = "PMSELR", .cp = 15, .crn = 9, .crm = 12, .opc1 = 0, .opc2 = 5,
      .access = PL0_RW, .type = ARM_CP_ALIAS,
      .fieldoffset = offsetoflow32(CPUARMState, cp15.c9_pmselr),
      .accessfn = pmreg_access, .writefn = pmselr_write,
      .raw_writefn = raw_write},
    { .name = "PMSELR_EL0", .state = ARM_CP_STATE_AA64,
      .opc0 = 3, .opc1 = 3, .crn = 9, .crm = 12, .opc2 = 5,
      .access = PL0_RW, .accessfn = pmreg_access,
      .fieldoffset = offsetof(CPUARMState, cp15.c9_pmselr),
      .writefn = pmselr_write, .raw_writefn = raw_write, },
    { .name = "PMCCNTR", .cp = 15, .crn = 9, .crm = 13, .opc1 = 0, .opc2 = 0,
      .access = PL0_RW, .resetvalue = 0, .type = ARM_CP_IO,
      .readfn = pmccntr_read, .writefn = pmccntr_write32,
      .accessfn = pmreg_access },
    { .name = "PMCCNTR_EL0", .state = ARM_CP_STATE_AA64,
      .opc0 = 3, .opc1 = 3, .crn = 9, .crm = 13, .opc2 = 0,
      .access = PL0_RW, .accessfn = pmreg_access,
      .type = ARM_CP_IO,
      .readfn = pmccntr_read, .writefn = pmccntr_write, },
#endif
    { .name = "PMCCFILTR_EL0", .state = ARM_CP_STATE_AA64,
      .opc0 = 3, .opc1 = 3, .crn = 14, .crm = 15, .opc2 = 7,
      .writefn = pmccfiltr_write,
      .access = PL0_RW, .accessfn = pmreg_access,
      .type = ARM_CP_IO,
      .fieldoffset = offsetof(CPUARMState, cp15.pmccfiltr_el0),
      .resetvalue = 0, },
    { .name = "PMXEVTYPER", .cp = 15, .crn = 9, .crm = 13, .opc1 = 0, .opc2 = 1,
      .access = PL0_RW, .type = ARM_CP_NO_RAW, .accessfn = pmreg_access,
      .writefn = pmxevtyper_write, .readfn = pmxevtyper_read },
    { .name = "PMXEVTYPER_EL0", .state = ARM_CP_STATE_AA64,
      .opc0 = 3, .opc1 = 3, .crn = 9, .crm = 13, .opc2 = 1,
      .access = PL0_RW, .type = ARM_CP_NO_RAW, .accessfn = pmreg_access,
      .writefn = pmxevtyper_write, .readfn = pmxevtyper_read },
    /* Unimplemented, RAZ/WI. */
    { .name = "PMXEVCNTR", .cp = 15, .crn = 9, .crm = 13, .opc1 = 0, .opc2 = 2,
      .access = PL0_RW, .type = ARM_CP_CONST, .resetvalue = 0,
      .accessfn = pmreg_access },
    { .name = "PMUSERENR", .cp = 15, .crn = 9, .crm = 14, .opc1 = 0, .opc2 = 0,
      .access = PL0_R | PL1_RW, .accessfn = access_tpm,
      .fieldoffset = offsetof(CPUARMState, cp15.c9_pmuserenr),
      .resetvalue = 0,
      .writefn = pmuserenr_write, .raw_writefn = raw_write },
    { .name = "PMUSERENR_EL0", .state = ARM_CP_STATE_AA64,
      .opc0 = 3, .opc1 = 3, .crn = 9, .crm = 14, .opc2 = 0,
      .access = PL0_R | PL1_RW, .accessfn = access_tpm, .type = ARM_CP_ALIAS,
      .fieldoffset = offsetof(CPUARMState, cp15.c9_pmuserenr),
      .resetvalue = 0,
      .writefn = pmuserenr_write, .raw_writefn = raw_write },
    { .name = "PMINTENSET", .cp = 15, .crn = 9, .crm = 14, .opc1 = 0, .opc2 = 1,
      .access = PL1_RW, .accessfn = access_tpm,
      .type = ARM_CP_ALIAS,
      .fieldoffset = offsetoflow32(CPUARMState, cp15.c9_pminten),
      .resetvalue = 0,
      .writefn = pmintenset_write, .raw_writefn = raw_write },
    { .name = "PMINTENSET_EL1", .state = ARM_CP_STATE_AA64,
      .opc0 = 3, .opc1 = 0, .crn = 9, .crm = 14, .opc2 = 1,
      .access = PL1_RW, .accessfn = access_tpm,
      .type = ARM_CP_IO,
      .fieldoffset = offsetof(CPUARMState, cp15.c9_pminten),
      .writefn = pmintenset_write, .raw_writefn = raw_write,
      .resetvalue = 0x0 },
    { .name = "PMINTENCLR", .cp = 15, .crn = 9, .crm = 14, .opc1 = 0, .opc2 = 2,
      .access = PL1_RW, .accessfn = access_tpm, .type = ARM_CP_ALIAS,
      .fieldoffset = offsetof(CPUARMState, cp15.c9_pminten),
      .writefn = pmintenclr_write, },
    { .name = "PMINTENCLR_EL1", .state = ARM_CP_STATE_AA64,
      .opc0 = 3, .opc1 = 0, .crn = 9, .crm = 14, .opc2 = 2,
      .access = PL1_RW, .accessfn = access_tpm, .type = ARM_CP_ALIAS,
      .fieldoffset = offsetof(CPUARMState, cp15.c9_pminten),
      .writefn = pmintenclr_write },
    { .name = "CCSIDR", .state = ARM_CP_STATE_BOTH,
      .opc0 = 3, .crn = 0, .crm = 0, .opc1 = 1, .opc2 = 0,
      .access = PL1_R, .readfn = ccsidr_read, .type = ARM_CP_NO_RAW },
    { .name = "CSSELR", .state = ARM_CP_STATE_BOTH,
      .opc0 = 3, .crn = 0, .crm = 0, .opc1 = 2, .opc2 = 0,
      .access = PL1_RW, .writefn = csselr_write, .resetvalue = 0,
      .bank_fieldoffsets = { offsetof(CPUARMState, cp15.csselr_s),
                             offsetof(CPUARMState, cp15.csselr_ns) } },
    /* Auxiliary ID register: this actually has an IMPDEF value but for now
     * just RAZ for all cores:
     */
    { .name = "AIDR", .state = ARM_CP_STATE_BOTH,
      .opc0 = 3, .opc1 = 1, .crn = 0, .crm = 0, .opc2 = 7,
      .access = PL1_R, .type = ARM_CP_CONST, .resetvalue = 0 },
    /* Auxiliary fault status registers: these also are IMPDEF, and we
     * choose to RAZ/WI for all cores.
     */
    { .name = "AFSR0_EL1", .state = ARM_CP_STATE_BOTH,
      .opc0 = 3, .opc1 = 0, .crn = 5, .crm = 1, .opc2 = 0,
      .access = PL1_RW, .type = ARM_CP_CONST, .resetvalue = 0 },
    { .name = "AFSR1_EL1", .state = ARM_CP_STATE_BOTH,
      .opc0 = 3, .opc1 = 0, .crn = 5, .crm = 1, .opc2 = 1,
      .access = PL1_RW, .type = ARM_CP_CONST, .resetvalue = 0 },
    /* MAIR can just read-as-written because we don't implement caches
     * and so don't need to care about memory attributes.
     */
    { .name = "MAIR_EL1", .state = ARM_CP_STATE_AA64,
      .opc0 = 3, .opc1 = 0, .crn = 10, .crm = 2, .opc2 = 0,
      .access = PL1_RW, .fieldoffset = offsetof(CPUARMState, cp15.mair_el[1]),
      .resetvalue = 0 },
    { .name = "MAIR_EL3", .state = ARM_CP_STATE_AA64,
      .opc0 = 3, .opc1 = 6, .crn = 10, .crm = 2, .opc2 = 0,
      .access = PL3_RW, .fieldoffset = offsetof(CPUARMState, cp15.mair_el[3]),
      .resetvalue = 0 },
    /* For non-long-descriptor page tables these are PRRR and NMRR;
     * regardless they still act as reads-as-written for QEMU.
     */
     /* MAIR0/1 are defined separately from their 64-bit counterpart which
      * allows them to assign the correct fieldoffset based on the endianness
      * handled in the field definitions.
      */
    { .name = "MAIR0", .state = ARM_CP_STATE_AA32,
      .cp = 15, .opc1 = 0, .crn = 10, .crm = 2, .opc2 = 0, .access = PL1_RW,
      .bank_fieldoffsets = { offsetof(CPUARMState, cp15.mair0_s),
                             offsetof(CPUARMState, cp15.mair0_ns) },
      .resetfn = arm_cp_reset_ignore },
    { .name = "MAIR1", .state = ARM_CP_STATE_AA32,
      .cp = 15, .opc1 = 0, .crn = 10, .crm = 2, .opc2 = 1, .access = PL1_RW,
      .bank_fieldoffsets = { offsetof(CPUARMState, cp15.mair1_s),
                             offsetof(CPUARMState, cp15.mair1_ns) },
      .resetfn = arm_cp_reset_ignore },
    { .name = "ISR_EL1", .state = ARM_CP_STATE_BOTH,
      .opc0 = 3, .opc1 = 0, .crn = 12, .crm = 1, .opc2 = 0,
      .type = ARM_CP_NO_RAW, .access = PL1_R, .readfn = isr_read },
    /* 32 bit ITLB invalidates */
    { .name = "ITLBIALL", .cp = 15, .opc1 = 0, .crn = 8, .crm = 5, .opc2 = 0,
      .type = ARM_CP_NO_RAW, .access = PL1_W, .writefn = tlbiall_write },
    { .name = "ITLBIMVA", .cp = 15, .opc1 = 0, .crn = 8, .crm = 5, .opc2 = 1,
      .type = ARM_CP_NO_RAW, .access = PL1_W, .writefn = tlbimva_write },
    { .name = "ITLBIASID", .cp = 15, .opc1 = 0, .crn = 8, .crm = 5, .opc2 = 2,
      .type = ARM_CP_NO_RAW, .access = PL1_W, .writefn = tlbiasid_write },
    /* 32 bit DTLB invalidates */
    { .name = "DTLBIALL", .cp = 15, .opc1 = 0, .crn = 8, .crm = 6, .opc2 = 0,
      .type = ARM_CP_NO_RAW, .access = PL1_W, .writefn = tlbiall_write },
    { .name = "DTLBIMVA", .cp = 15, .opc1 = 0, .crn = 8, .crm = 6, .opc2 = 1,
      .type = ARM_CP_NO_RAW, .access = PL1_W, .writefn = tlbimva_write },
    { .name = "DTLBIASID", .cp = 15, .opc1 = 0, .crn = 8, .crm = 6, .opc2 = 2,
      .type = ARM_CP_NO_RAW, .access = PL1_W, .writefn = tlbiasid_write },
    /* 32 bit TLB invalidates */
    { .name = "TLBIALL", .cp = 15, .opc1 = 0, .crn = 8, .crm = 7, .opc2 = 0,
      .type = ARM_CP_NO_RAW, .access = PL1_W, .writefn = tlbiall_write },
    { .name = "TLBIMVA", .cp = 15, .opc1 = 0, .crn = 8, .crm = 7, .opc2 = 1,
      .type = ARM_CP_NO_RAW, .access = PL1_W, .writefn = tlbimva_write },
    { .name = "TLBIASID", .cp = 15, .opc1 = 0, .crn = 8, .crm = 7, .opc2 = 2,
      .type = ARM_CP_NO_RAW, .access = PL1_W, .writefn = tlbiasid_write },
    { .name = "TLBIMVAA", .cp = 15, .opc1 = 0, .crn = 8, .crm = 7, .opc2 = 3,
      .type = ARM_CP_NO_RAW, .access = PL1_W, .writefn = tlbimvaa_write },
    REGINFO_SENTINEL
};

static const ARMCPRegInfo v7mp_cp_reginfo[] = {
    /* 32 bit TLB invalidates, Inner Shareable */
    { .name = "TLBIALLIS", .cp = 15, .opc1 = 0, .crn = 8, .crm = 3, .opc2 = 0,
      .type = ARM_CP_NO_RAW, .access = PL1_W, .writefn = tlbiall_is_write },
    { .name = "TLBIMVAIS", .cp = 15, .opc1 = 0, .crn = 8, .crm = 3, .opc2 = 1,
      .type = ARM_CP_NO_RAW, .access = PL1_W, .writefn = tlbimva_is_write },
    { .name = "TLBIASIDIS", .cp = 15, .opc1 = 0, .crn = 8, .crm = 3, .opc2 = 2,
      .type = ARM_CP_NO_RAW, .access = PL1_W,
      .writefn = tlbiasid_is_write },
    { .name = "TLBIMVAAIS", .cp = 15, .opc1 = 0, .crn = 8, .crm = 3, .opc2 = 3,
      .type = ARM_CP_NO_RAW, .access = PL1_W,
      .writefn = tlbimvaa_is_write },
    REGINFO_SENTINEL
};

static void teecr_write(CPUARMState *env, const ARMCPRegInfo *ri,
                        uint64_t value)
{
    value &= 1;
    env->teecr = value;
}

static CPAccessResult teehbr_access(CPUARMState *env, const ARMCPRegInfo *ri,
                                    bool isread)
{
    if (arm_current_el(env) == 0 && (env->teecr & 1)) {
        return CP_ACCESS_TRAP;
    }
    return CP_ACCESS_OK;
}

static const ARMCPRegInfo t2ee_cp_reginfo[] = {
    { .name = "TEECR", .cp = 14, .crn = 0, .crm = 0, .opc1 = 6, .opc2 = 0,
      .access = PL1_RW, .fieldoffset = offsetof(CPUARMState, teecr),
      .resetvalue = 0,
      .writefn = teecr_write },
    { .name = "TEEHBR", .cp = 14, .crn = 1, .crm = 0, .opc1 = 6, .opc2 = 0,
      .access = PL0_RW, .fieldoffset = offsetof(CPUARMState, teehbr),
      .accessfn = teehbr_access, .resetvalue = 0 },
    REGINFO_SENTINEL
};

static const ARMCPRegInfo v6k_cp_reginfo[] = {
    { .name = "TPIDR_EL0", .state = ARM_CP_STATE_AA64,
      .opc0 = 3, .opc1 = 3, .opc2 = 2, .crn = 13, .crm = 0,
      .access = PL0_RW,
      .fieldoffset = offsetof(CPUARMState, cp15.tpidr_el[0]), .resetvalue = 0 },
    { .name = "TPIDRURW", .cp = 15, .crn = 13, .crm = 0, .opc1 = 0, .opc2 = 2,
      .access = PL0_RW,
      .bank_fieldoffsets = { offsetoflow32(CPUARMState, cp15.tpidrurw_s),
                             offsetoflow32(CPUARMState, cp15.tpidrurw_ns) },
      .resetfn = arm_cp_reset_ignore },
    { .name = "TPIDRRO_EL0", .state = ARM_CP_STATE_AA64,
      .opc0 = 3, .opc1 = 3, .opc2 = 3, .crn = 13, .crm = 0,
      .access = PL0_R|PL1_W,
      .fieldoffset = offsetof(CPUARMState, cp15.tpidrro_el[0]),
      .resetvalue = 0},
    { .name = "TPIDRURO", .cp = 15, .crn = 13, .crm = 0, .opc1 = 0, .opc2 = 3,
      .access = PL0_R|PL1_W,
      .bank_fieldoffsets = { offsetoflow32(CPUARMState, cp15.tpidruro_s),
                             offsetoflow32(CPUARMState, cp15.tpidruro_ns) },
      .resetfn = arm_cp_reset_ignore },
    { .name = "TPIDR_EL1", .state = ARM_CP_STATE_AA64,
      .opc0 = 3, .opc1 = 0, .opc2 = 4, .crn = 13, .crm = 0,
      .access = PL1_RW,
      .fieldoffset = offsetof(CPUARMState, cp15.tpidr_el[1]), .resetvalue = 0 },
    { .name = "TPIDRPRW", .opc1 = 0, .cp = 15, .crn = 13, .crm = 0, .opc2 = 4,
      .access = PL1_RW,
      .bank_fieldoffsets = { offsetoflow32(CPUARMState, cp15.tpidrprw_s),
                             offsetoflow32(CPUARMState, cp15.tpidrprw_ns) },
      .resetvalue = 0 },
    REGINFO_SENTINEL
};

#ifndef CONFIG_USER_ONLY

static CPAccessResult gt_cntfrq_access(CPUARMState *env, const ARMCPRegInfo *ri,
                                       bool isread)
{
    /* CNTFRQ: not visible from PL0 if both PL0PCTEN and PL0VCTEN are zero.
     * Writable only at the highest implemented exception level.
     */
    int el = arm_current_el(env);

    switch (el) {
    case 0:
        if (!extract32(env->cp15.c14_cntkctl, 0, 2)) {
            return CP_ACCESS_TRAP;
        }
        break;
    case 1:
        if (!isread && ri->state == ARM_CP_STATE_AA32 &&
            arm_is_secure_below_el3(env)) {
            /* Accesses from 32-bit Secure EL1 UNDEF (*not* trap to EL3!) */
            return CP_ACCESS_TRAP_UNCATEGORIZED;
        }
        break;
    case 2:
    case 3:
        break;
    }

    if (!isread && el < arm_highest_el(env)) {
        return CP_ACCESS_TRAP_UNCATEGORIZED;
    }

    return CP_ACCESS_OK;
}

static CPAccessResult gt_counter_access(CPUARMState *env, int timeridx,
                                        bool isread)
{
    unsigned int cur_el = arm_current_el(env);
    bool secure = arm_is_secure(env);

    /* CNT[PV]CT: not visible from PL0 if ELO[PV]CTEN is zero */
    if (cur_el == 0 &&
        !extract32(env->cp15.c14_cntkctl, timeridx, 1)) {
        return CP_ACCESS_TRAP;
    }

    if (arm_feature(env, ARM_FEATURE_EL2) &&
        timeridx == GTIMER_PHYS && !secure && cur_el < 2 &&
        !extract32(env->cp15.cnthctl_el2, 0, 1)) {
        return CP_ACCESS_TRAP_EL2;
    }
    return CP_ACCESS_OK;
}

static CPAccessResult gt_timer_access(CPUARMState *env, int timeridx,
                                      bool isread)
{
    unsigned int cur_el = arm_current_el(env);
    bool secure = arm_is_secure(env);

    /* CNT[PV]_CVAL, CNT[PV]_CTL, CNT[PV]_TVAL: not visible from PL0 if
     * EL0[PV]TEN is zero.
     */
    if (cur_el == 0 &&
        !extract32(env->cp15.c14_cntkctl, 9 - timeridx, 1)) {
        return CP_ACCESS_TRAP;
    }

    if (arm_feature(env, ARM_FEATURE_EL2) &&
        timeridx == GTIMER_PHYS && !secure && cur_el < 2 &&
        !extract32(env->cp15.cnthctl_el2, 1, 1)) {
        return CP_ACCESS_TRAP_EL2;
    }
    return CP_ACCESS_OK;
}

static CPAccessResult gt_pct_access(CPUARMState *env,
                                    const ARMCPRegInfo *ri,
                                    bool isread)
{
    return gt_counter_access(env, GTIMER_PHYS, isread);
}

static CPAccessResult gt_vct_access(CPUARMState *env,
                                    const ARMCPRegInfo *ri,
                                    bool isread)
{
    return gt_counter_access(env, GTIMER_VIRT, isread);
}

static CPAccessResult gt_ptimer_access(CPUARMState *env, const ARMCPRegInfo *ri,
                                       bool isread)
{
    return gt_timer_access(env, GTIMER_PHYS, isread);
}

static CPAccessResult gt_vtimer_access(CPUARMState *env, const ARMCPRegInfo *ri,
                                       bool isread)
{
    return gt_timer_access(env, GTIMER_VIRT, isread);
}

static CPAccessResult gt_stimer_access(CPUARMState *env,
                                       const ARMCPRegInfo *ri,
                                       bool isread)
{
    /* The AArch64 register view of the secure physical timer is
     * always accessible from EL3, and configurably accessible from
     * Secure EL1.
     */
    switch (arm_current_el(env)) {
    case 1:
        if (!arm_is_secure(env)) {
            return CP_ACCESS_TRAP;
        }
        if (!(env->cp15.scr_el3 & SCR_ST)) {
            return CP_ACCESS_TRAP_EL3;
        }
        return CP_ACCESS_OK;
    case 0:
    case 2:
        return CP_ACCESS_TRAP;
    case 3:
        return CP_ACCESS_OK;
    default:
        g_assert_not_reached();
    }
}

static uint64_t gt_get_countervalue(CPUARMState *env)
{
    return qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) / GTIMER_SCALE;
}

static void gt_recalc_timer(ARMCPU *cpu, int timeridx)
{
    ARMGenericTimer *gt = &cpu->env.cp15.c14_timer[timeridx];

    if (gt->ctl & 1) {
        /* Timer enabled: calculate and set current ISTATUS, irq, and
         * reset timer to when ISTATUS next has to change
         */
        uint64_t offset = timeridx == GTIMER_VIRT ?
                                      cpu->env.cp15.cntvoff_el2 : 0;
        uint64_t count = gt_get_countervalue(&cpu->env);
        /* Note that this must be unsigned 64 bit arithmetic: */
        int istatus = count - offset >= gt->cval;
        uint64_t nexttick;
        int irqstate;

        gt->ctl = deposit32(gt->ctl, 2, 1, istatus);

        irqstate = (istatus && !(gt->ctl & 2));
        qemu_set_irq(cpu->gt_timer_outputs[timeridx], irqstate);

        if (istatus) {
            /* Next transition is when count rolls back over to zero */
            nexttick = UINT64_MAX;
        } else {
            /* Next transition is when we hit cval */
            nexttick = gt->cval + offset;
        }
        /* Note that the desired next expiry time might be beyond the
         * signed-64-bit range of a QEMUTimer -- in this case we just
         * set the timer for as far in the future as possible. When the
         * timer expires we will reset the timer for any remaining period.
         */
        if (nexttick > INT64_MAX / GTIMER_SCALE) {
            nexttick = INT64_MAX / GTIMER_SCALE;
        }
        timer_mod(cpu->gt_timer[timeridx], nexttick);
        trace_arm_gt_recalc(timeridx, irqstate, nexttick);
    } else {
        /* Timer disabled: ISTATUS and timer output always clear */
        gt->ctl &= ~4;
        qemu_set_irq(cpu->gt_timer_outputs[timeridx], 0);
        timer_del(cpu->gt_timer[timeridx]);
        trace_arm_gt_recalc_disabled(timeridx);
    }
}

static void gt_timer_reset(CPUARMState *env, const ARMCPRegInfo *ri,
                           int timeridx)
{
    ARMCPU *cpu = arm_env_get_cpu(env);

    timer_del(cpu->gt_timer[timeridx]);
}

static uint64_t gt_cnt_read(CPUARMState *env, const ARMCPRegInfo *ri)
{
    return gt_get_countervalue(env);
}

static uint64_t gt_virt_cnt_read(CPUARMState *env, const ARMCPRegInfo *ri)
{
    return gt_get_countervalue(env) - env->cp15.cntvoff_el2;
}

static void gt_cval_write(CPUARMState *env, const ARMCPRegInfo *ri,
                          int timeridx,
                          uint64_t value)
{
    trace_arm_gt_cval_write(timeridx, value);
    env->cp15.c14_timer[timeridx].cval = value;
    gt_recalc_timer(arm_env_get_cpu(env), timeridx);
}

static uint64_t gt_tval_read(CPUARMState *env, const ARMCPRegInfo *ri,
                             int timeridx)
{
    uint64_t offset = timeridx == GTIMER_VIRT ? env->cp15.cntvoff_el2 : 0;

    return (uint32_t)(env->cp15.c14_timer[timeridx].cval -
                      (gt_get_countervalue(env) - offset));
}

static void gt_tval_write(CPUARMState *env, const ARMCPRegInfo *ri,
                          int timeridx,
                          uint64_t value)
{
    uint64_t offset = timeridx == GTIMER_VIRT ? env->cp15.cntvoff_el2 : 0;

    trace_arm_gt_tval_write(timeridx, value);
    env->cp15.c14_timer[timeridx].cval = gt_get_countervalue(env) - offset +
                                         sextract64(value, 0, 32);
    gt_recalc_timer(arm_env_get_cpu(env), timeridx);
}

static void gt_ctl_write(CPUARMState *env, const ARMCPRegInfo *ri,
                         int timeridx,
                         uint64_t value)
{
    ARMCPU *cpu = arm_env_get_cpu(env);
    uint32_t oldval = env->cp15.c14_timer[timeridx].ctl;

    trace_arm_gt_ctl_write(timeridx, value);
    env->cp15.c14_timer[timeridx].ctl = deposit64(oldval, 0, 2, value);
    if ((oldval ^ value) & 1) {
        /* Enable toggled */
        gt_recalc_timer(cpu, timeridx);
    } else if ((oldval ^ value) & 2) {
        /* IMASK toggled: don't need to recalculate,
         * just set the interrupt line based on ISTATUS
         */
        int irqstate = (oldval & 4) && !(value & 2);

        trace_arm_gt_imask_toggle(timeridx, irqstate);
        qemu_set_irq(cpu->gt_timer_outputs[timeridx], irqstate);
    }
}

static void gt_phys_timer_reset(CPUARMState *env, const ARMCPRegInfo *ri)
{
    gt_timer_reset(env, ri, GTIMER_PHYS);
}

static void gt_phys_cval_write(CPUARMState *env, const ARMCPRegInfo *ri,
                               uint64_t value)
{
    gt_cval_write(env, ri, GTIMER_PHYS, value);
}

static uint64_t gt_phys_tval_read(CPUARMState *env, const ARMCPRegInfo *ri)
{
    return gt_tval_read(env, ri, GTIMER_PHYS);
}

static void gt_phys_tval_write(CPUARMState *env, const ARMCPRegInfo *ri,
                               uint64_t value)
{
    gt_tval_write(env, ri, GTIMER_PHYS, value);
}

static void gt_phys_ctl_write(CPUARMState *env, const ARMCPRegInfo *ri,
                              uint64_t value)
{
    gt_ctl_write(env, ri, GTIMER_PHYS, value);
}

static void gt_virt_timer_reset(CPUARMState *env, const ARMCPRegInfo *ri)
{
    gt_timer_reset(env, ri, GTIMER_VIRT);
}

static void gt_virt_cval_write(CPUARMState *env, const ARMCPRegInfo *ri,
                               uint64_t value)
{
    gt_cval_write(env, ri, GTIMER_VIRT, value);
}

static uint64_t gt_virt_tval_read(CPUARMState *env, const ARMCPRegInfo *ri)
{
    return gt_tval_read(env, ri, GTIMER_VIRT);
}

static void gt_virt_tval_write(CPUARMState *env, const ARMCPRegInfo *ri,
                               uint64_t value)
{
    gt_tval_write(env, ri, GTIMER_VIRT, value);
}

static void gt_virt_ctl_write(CPUARMState *env, const ARMCPRegInfo *ri,
                              uint64_t value)
{
    gt_ctl_write(env, ri, GTIMER_VIRT, value);
}

static void gt_cntvoff_write(CPUARMState *env, const ARMCPRegInfo *ri,
                              uint64_t value)
{
    ARMCPU *cpu = arm_env_get_cpu(env);

    trace_arm_gt_cntvoff_write(value);
    raw_write(env, ri, value);
    gt_recalc_timer(cpu, GTIMER_VIRT);
}

static void gt_hyp_timer_reset(CPUARMState *env, const ARMCPRegInfo *ri)
{
    gt_timer_reset(env, ri, GTIMER_HYP);
}

static void gt_hyp_cval_write(CPUARMState *env, const ARMCPRegInfo *ri,
                              uint64_t value)
{
    gt_cval_write(env, ri, GTIMER_HYP, value);
}

static uint64_t gt_hyp_tval_read(CPUARMState *env, const ARMCPRegInfo *ri)
{
    return gt_tval_read(env, ri, GTIMER_HYP);
}

static void gt_hyp_tval_write(CPUARMState *env, const ARMCPRegInfo *ri,
                              uint64_t value)
{
    gt_tval_write(env, ri, GTIMER_HYP, value);
}

static void gt_hyp_ctl_write(CPUARMState *env, const ARMCPRegInfo *ri,
                              uint64_t value)
{
    gt_ctl_write(env, ri, GTIMER_HYP, value);
}

static void gt_sec_timer_reset(CPUARMState *env, const ARMCPRegInfo *ri)
{
    gt_timer_reset(env, ri, GTIMER_SEC);
}

static void gt_sec_cval_write(CPUARMState *env, const ARMCPRegInfo *ri,
                              uint64_t value)
{
    gt_cval_write(env, ri, GTIMER_SEC, value);
}

static uint64_t gt_sec_tval_read(CPUARMState *env, const ARMCPRegInfo *ri)
{
    return gt_tval_read(env, ri, GTIMER_SEC);
}

static void gt_sec_tval_write(CPUARMState *env, const ARMCPRegInfo *ri,
                              uint64_t value)
{
    gt_tval_write(env, ri, GTIMER_SEC, value);
}

static void gt_sec_ctl_write(CPUARMState *env, const ARMCPRegInfo *ri,
                              uint64_t value)
{
    gt_ctl_write(env, ri, GTIMER_SEC, value);
}

void arm_gt_ptimer_cb(void *opaque)
{
    ARMCPU *cpu = opaque;

    gt_recalc_timer(cpu, GTIMER_PHYS);
}

void arm_gt_vtimer_cb(void *opaque)
{
    ARMCPU *cpu = opaque;

    gt_recalc_timer(cpu, GTIMER_VIRT);
}

void arm_gt_htimer_cb(void *opaque)
{
    ARMCPU *cpu = opaque;

    gt_recalc_timer(cpu, GTIMER_HYP);
}

void arm_gt_stimer_cb(void *opaque)
{
    ARMCPU *cpu = opaque;

    gt_recalc_timer(cpu, GTIMER_SEC);
}

static const ARMCPRegInfo generic_timer_cp_reginfo[] = {
    /* Note that CNTFRQ is purely reads-as-written for the benefit
     * of software; writing it doesn't actually change the timer frequency.
     * Our reset value matches the fixed frequency we implement the timer at.
     */
    { .name = "CNTFRQ", .cp = 15, .crn = 14, .crm = 0, .opc1 = 0, .opc2 = 0,
      .type = ARM_CP_ALIAS,
      .access = PL1_RW | PL0_R, .accessfn = gt_cntfrq_access,
      .fieldoffset = offsetoflow32(CPUARMState, cp15.c14_cntfrq),
    },
    { .name = "CNTFRQ_EL0", .state = ARM_CP_STATE_AA64,
      .opc0 = 3, .opc1 = 3, .crn = 14, .crm = 0, .opc2 = 0,
      .access = PL1_RW | PL0_R, .accessfn = gt_cntfrq_access,
      .fieldoffset = offsetof(CPUARMState, cp15.c14_cntfrq),
      .resetvalue = (1000 * 1000 * 1000) / GTIMER_SCALE,
    },
    /* overall control: mostly access permissions */
    { .name = "CNTKCTL", .state = ARM_CP_STATE_BOTH,
      .opc0 = 3, .opc1 = 0, .crn = 14, .crm = 1, .opc2 = 0,
      .access = PL1_RW,
      .fieldoffset = offsetof(CPUARMState, cp15.c14_cntkctl),
      .resetvalue = 0,
    },
    /* per-timer control */
    { .name = "CNTP_CTL", .cp = 15, .crn = 14, .crm = 2, .opc1 = 0, .opc2 = 1,
      .secure = ARM_CP_SECSTATE_NS,
      .type = ARM_CP_IO | ARM_CP_ALIAS, .access = PL1_RW | PL0_R,
      .accessfn = gt_ptimer_access,
      .fieldoffset = offsetoflow32(CPUARMState,
                                   cp15.c14_timer[GTIMER_PHYS].ctl),
      .writefn = gt_phys_ctl_write, .raw_writefn = raw_write,
    },
    { .name = "CNTP_CTL(S)",
      .cp = 15, .crn = 14, .crm = 2, .opc1 = 0, .opc2 = 1,
      .secure = ARM_CP_SECSTATE_S,
      .type = ARM_CP_IO | ARM_CP_ALIAS, .access = PL1_RW | PL0_R,
      .accessfn = gt_ptimer_access,
      .fieldoffset = offsetoflow32(CPUARMState,
                                   cp15.c14_timer[GTIMER_SEC].ctl),
      .writefn = gt_sec_ctl_write, .raw_writefn = raw_write,
    },
    { .name = "CNTP_CTL_EL0", .state = ARM_CP_STATE_AA64,
      .opc0 = 3, .opc1 = 3, .crn = 14, .crm = 2, .opc2 = 1,
      .type = ARM_CP_IO, .access = PL1_RW | PL0_R,
      .accessfn = gt_ptimer_access,
      .fieldoffset = offsetof(CPUARMState, cp15.c14_timer[GTIMER_PHYS].ctl),
      .resetvalue = 0,
      .writefn = gt_phys_ctl_write, .raw_writefn = raw_write,
    },
    { .name = "CNTV_CTL", .cp = 15, .crn = 14, .crm = 3, .opc1 = 0, .opc2 = 1,
      .type = ARM_CP_IO | ARM_CP_ALIAS, .access = PL1_RW | PL0_R,
      .accessfn = gt_vtimer_access,
      .fieldoffset = offsetoflow32(CPUARMState,
                                   cp15.c14_timer[GTIMER_VIRT].ctl),
      .writefn = gt_virt_ctl_write, .raw_writefn = raw_write,
    },
    { .name = "CNTV_CTL_EL0", .state = ARM_CP_STATE_AA64,
      .opc0 = 3, .opc1 = 3, .crn = 14, .crm = 3, .opc2 = 1,
      .type = ARM_CP_IO, .access = PL1_RW | PL0_R,
      .accessfn = gt_vtimer_access,
      .fieldoffset = offsetof(CPUARMState, cp15.c14_timer[GTIMER_VIRT].ctl),
      .resetvalue = 0,
      .writefn = gt_virt_ctl_write, .raw_writefn = raw_write,
    },
    /* TimerValue views: a 32 bit downcounting view of the underlying state */
    { .name = "CNTP_TVAL", .cp = 15, .crn = 14, .crm = 2, .opc1 = 0, .opc2 = 0,
      .secure = ARM_CP_SECSTATE_NS,
      .type = ARM_CP_NO_RAW | ARM_CP_IO, .access = PL1_RW | PL0_R,
      .accessfn = gt_ptimer_access,
      .readfn = gt_phys_tval_read, .writefn = gt_phys_tval_write,
    },
    { .name = "CNTP_TVAL(S)",
      .cp = 15, .crn = 14, .crm = 2, .opc1 = 0, .opc2 = 0,
      .secure = ARM_CP_SECSTATE_S,
      .type = ARM_CP_NO_RAW | ARM_CP_IO, .access = PL1_RW | PL0_R,
      .accessfn = gt_ptimer_access,
      .readfn = gt_sec_tval_read, .writefn = gt_sec_tval_write,
    },
    { .name = "CNTP_TVAL_EL0", .state = ARM_CP_STATE_AA64,
      .opc0 = 3, .opc1 = 3, .crn = 14, .crm = 2, .opc2 = 0,
      .type = ARM_CP_NO_RAW | ARM_CP_IO, .access = PL1_RW | PL0_R,
      .accessfn = gt_ptimer_access, .resetfn = gt_phys_timer_reset,
      .readfn = gt_phys_tval_read, .writefn = gt_phys_tval_write,
    },
    { .name = "CNTV_TVAL", .cp = 15, .crn = 14, .crm = 3, .opc1 = 0, .opc2 = 0,
      .type = ARM_CP_NO_RAW | ARM_CP_IO, .access = PL1_RW | PL0_R,
      .accessfn = gt_vtimer_access,
      .readfn = gt_virt_tval_read, .writefn = gt_virt_tval_write,
    },
    { .name = "CNTV_TVAL_EL0", .state = ARM_CP_STATE_AA64,
      .opc0 = 3, .opc1 = 3, .crn = 14, .crm = 3, .opc2 = 0,
      .type = ARM_CP_NO_RAW | ARM_CP_IO, .access = PL1_RW | PL0_R,
      .accessfn = gt_vtimer_access, .resetfn = gt_virt_timer_reset,
      .readfn = gt_virt_tval_read, .writefn = gt_virt_tval_write,
    },
    /* The counter itself */
    { .name = "CNTPCT", .cp = 15, .crm = 14, .opc1 = 0,
      .access = PL0_R, .type = ARM_CP_64BIT | ARM_CP_NO_RAW | ARM_CP_IO,
      .accessfn = gt_pct_access,
      .readfn = gt_cnt_read, .resetfn = arm_cp_reset_ignore,
    },
    { .name = "CNTPCT_EL0", .state = ARM_CP_STATE_AA64,
      .opc0 = 3, .opc1 = 3, .crn = 14, .crm = 0, .opc2 = 1,
      .access = PL0_R, .type = ARM_CP_NO_RAW | ARM_CP_IO,
      .accessfn = gt_pct_access, .readfn = gt_cnt_read,
    },
    { .name = "CNTVCT", .cp = 15, .crm = 14, .opc1 = 1,
      .access = PL0_R, .type = ARM_CP_64BIT | ARM_CP_NO_RAW | ARM_CP_IO,
      .accessfn = gt_vct_access,
      .readfn = gt_virt_cnt_read, .resetfn = arm_cp_reset_ignore,
    },
    { .name = "CNTVCT_EL0", .state = ARM_CP_STATE_AA64,
      .opc0 = 3, .opc1 = 3, .crn = 14, .crm = 0, .opc2 = 2,
      .access = PL0_R, .type = ARM_CP_NO_RAW | ARM_CP_IO,
      .accessfn = gt_vct_access, .readfn = gt_virt_cnt_read,
    },
    /* Comparison value, indicating when the timer goes off */
    { .name = "CNTP_CVAL", .cp = 15, .crm = 14, .opc1 = 2,
      .secure = ARM_CP_SECSTATE_NS,
      .access = PL1_RW | PL0_R,
      .type = ARM_CP_64BIT | ARM_CP_IO | ARM_CP_ALIAS,
      .fieldoffset = offsetof(CPUARMState, cp15.c14_timer[GTIMER_PHYS].cval),
      .accessfn = gt_ptimer_access,
      .writefn = gt_phys_cval_write, .raw_writefn = raw_write,
    },
    { .name = "CNTP_CVAL(S)", .cp = 15, .crm = 14, .opc1 = 2,
      .secure = ARM_CP_SECSTATE_S,
      .access = PL1_RW | PL0_R,
      .type = ARM_CP_64BIT | ARM_CP_IO | ARM_CP_ALIAS,
      .fieldoffset = offsetof(CPUARMState, cp15.c14_timer[GTIMER_SEC].cval),
      .accessfn = gt_ptimer_access,
      .writefn = gt_sec_cval_write, .raw_writefn = raw_write,
    },
    { .name = "CNTP_CVAL_EL0", .state = ARM_CP_STATE_AA64,
      .opc0 = 3, .opc1 = 3, .crn = 14, .crm = 2, .opc2 = 2,
      .access = PL1_RW | PL0_R,
      .type = ARM_CP_IO,
      .fieldoffset = offsetof(CPUARMState, cp15.c14_timer[GTIMER_PHYS].cval),
      .resetvalue = 0, .accessfn = gt_ptimer_access,
      .writefn = gt_phys_cval_write, .raw_writefn = raw_write,
    },
    { .name = "CNTV_CVAL", .cp = 15, .crm = 14, .opc1 = 3,
      .access = PL1_RW | PL0_R,
      .type = ARM_CP_64BIT | ARM_CP_IO | ARM_CP_ALIAS,
      .fieldoffset = offsetof(CPUARMState, cp15.c14_timer[GTIMER_VIRT].cval),
      .accessfn = gt_vtimer_access,
      .writefn = gt_virt_cval_write, .raw_writefn = raw_write,
    },
    { .name = "CNTV_CVAL_EL0", .state = ARM_CP_STATE_AA64,
      .opc0 = 3, .opc1 = 3, .crn = 14, .crm = 3, .opc2 = 2,
      .access = PL1_RW | PL0_R,
      .type = ARM_CP_IO,
      .fieldoffset = offsetof(CPUARMState, cp15.c14_timer[GTIMER_VIRT].cval),
      .resetvalue = 0, .accessfn = gt_vtimer_access,
      .writefn = gt_virt_cval_write, .raw_writefn = raw_write,
    },
    /* Secure timer -- this is actually restricted to only EL3
     * and configurably Secure-EL1 via the accessfn.
     */
    { .name = "CNTPS_TVAL_EL1", .state = ARM_CP_STATE_AA64,
      .opc0 = 3, .opc1 = 7, .crn = 14, .crm = 2, .opc2 = 0,
      .type = ARM_CP_NO_RAW | ARM_CP_IO, .access = PL1_RW,
      .accessfn = gt_stimer_access,
      .readfn = gt_sec_tval_read,
      .writefn = gt_sec_tval_write,
      .resetfn = gt_sec_timer_reset,
    },
    { .name = "CNTPS_CTL_EL1", .state = ARM_CP_STATE_AA64,
      .opc0 = 3, .opc1 = 7, .crn = 14, .crm = 2, .opc2 = 1,
      .type = ARM_CP_IO, .access = PL1_RW,
      .accessfn = gt_stimer_access,
      .fieldoffset = offsetof(CPUARMState, cp15.c14_timer[GTIMER_SEC].ctl),
      .resetvalue = 0,
      .writefn = gt_sec_ctl_write, .raw_writefn = raw_write,
    },
    { .name = "CNTPS_CVAL_EL1", .state = ARM_CP_STATE_AA64,
      .opc0 = 3, .opc1 = 7, .crn = 14, .crm = 2, .opc2 = 2,
      .type = ARM_CP_IO, .access = PL1_RW,
      .accessfn = gt_stimer_access,
      .fieldoffset = offsetof(CPUARMState, cp15.c14_timer[GTIMER_SEC].cval),
      .writefn = gt_sec_cval_write, .raw_writefn = raw_write,
    },
    REGINFO_SENTINEL
};

#else
/* In user-mode none of the generic timer registers are accessible,
 * and their implementation depends on QEMU_CLOCK_VIRTUAL and qdev gpio outputs,
 * so instead just don't register any of them.
 */
static const ARMCPRegInfo generic_timer_cp_reginfo[] = {
    REGINFO_SENTINEL
};

#endif

static void par_write(CPUARMState *env, const ARMCPRegInfo *ri, uint64_t value)
{
    if (arm_feature(env, ARM_FEATURE_LPAE)) {
        raw_write(env, ri, value);
    } else if (arm_feature(env, ARM_FEATURE_V7)) {
        raw_write(env, ri, value & 0xfffff6ff);
    } else {
        raw_write(env, ri, value & 0xfffff1ff);
    }
}

#ifndef CONFIG_USER_ONLY
/* get_phys_addr() isn't present for user-mode-only targets */

static CPAccessResult ats_access(CPUARMState *env, const ARMCPRegInfo *ri,
                                 bool isread)
{
    if (ri->opc2 & 4) {
        /* The ATS12NSO* operations must trap to EL3 if executed in
         * Secure EL1 (which can only happen if EL3 is AArch64).
         * They are simply UNDEF if executed from NS EL1.
         * They function normally from EL2 or EL3.
         */
        if (arm_current_el(env) == 1) {
            if (arm_is_secure_below_el3(env)) {
                return CP_ACCESS_TRAP_UNCATEGORIZED_EL3;
            }
            return CP_ACCESS_TRAP_UNCATEGORIZED;
        }
    }
    return CP_ACCESS_OK;
}

static uint64_t do_ats_write(CPUARMState *env, uint64_t value,
                             int access_type, ARMMMUIdx mmu_idx)
{
    hwaddr phys_addr;
    target_ulong page_size;
    int prot;
    uint32_t fsr;
    bool ret;
    uint64_t par64;
    MemTxAttrs attrs = {};
    ARMMMUFaultInfo fi = {};

    ret = get_phys_addr(env, value, access_type, mmu_idx,
                        &phys_addr, &attrs, &prot, &page_size, &fsr, &fi);
    if (extended_addresses_enabled(env)) {
        /* fsr is a DFSR/IFSR value for the long descriptor
         * translation table format, but with WnR always clear.
         * Convert it to a 64-bit PAR.
         */
        par64 = (1 << 11); /* LPAE bit always set */
        if (!ret) {
            par64 |= phys_addr & ~0xfffULL;
            if (!attrs.secure) {
                par64 |= (1 << 9); /* NS */
            }
            /* We don't set the ATTR or SH fields in the PAR. */
        } else {
            par64 |= 1; /* F */
            par64 |= (fsr & 0x3f) << 1; /* FS */
            /* Note that S2WLK and FSTAGE are always zero, because we don't
             * implement virtualization and therefore there can't be a stage 2
             * fault.
             */
        }
    } else {
        /* fsr is a DFSR/IFSR value for the short descriptor
         * translation table format (with WnR always clear).
         * Convert it to a 32-bit PAR.
         */
        if (!ret) {
            /* We do not set any attribute bits in the PAR */
            if (page_size == (1 << 24)
                && arm_feature(env, ARM_FEATURE_V7)) {
                par64 = (phys_addr & 0xff000000) | (1 << 1);
            } else {
                par64 = phys_addr & 0xfffff000;
            }
            if (!attrs.secure) {
                par64 |= (1 << 9); /* NS */
            }
        } else {
            par64 = ((fsr & (1 << 10)) >> 5) | ((fsr & (1 << 12)) >> 6) |
                    ((fsr & 0xf) << 1) | 1;
        }
    }
    return par64;
}

static void ats_write(CPUARMState *env, const ARMCPRegInfo *ri, uint64_t value)
{
    int access_type = ri->opc2 & 1;
    uint64_t par64;
    ARMMMUIdx mmu_idx;
    int el = arm_current_el(env);
    bool secure = arm_is_secure_below_el3(env);

    switch (ri->opc2 & 6) {
    case 0:
        /* stage 1 current state PL1: ATS1CPR, ATS1CPW */
        switch (el) {
        case 3:
            mmu_idx = ARMMMUIdx_S1E3;
            break;
        case 2:
            mmu_idx = ARMMMUIdx_S1NSE1;
            break;
        case 1:
            mmu_idx = secure ? ARMMMUIdx_S1SE1 : ARMMMUIdx_S1NSE1;
            break;
        default:
            g_assert_not_reached();
        }
        break;
    case 2:
        /* stage 1 current state PL0: ATS1CUR, ATS1CUW */
        switch (el) {
        case 3:
            mmu_idx = ARMMMUIdx_S1SE0;
            break;
        case 2:
            mmu_idx = ARMMMUIdx_S1NSE0;
            break;
        case 1:
            mmu_idx = secure ? ARMMMUIdx_S1SE0 : ARMMMUIdx_S1NSE0;
            break;
        default:
            g_assert_not_reached();
        }
        break;
    case 4:
        /* stage 1+2 NonSecure PL1: ATS12NSOPR, ATS12NSOPW */
        mmu_idx = ARMMMUIdx_S12NSE1;
        break;
    case 6:
        /* stage 1+2 NonSecure PL0: ATS12NSOUR, ATS12NSOUW */
        mmu_idx = ARMMMUIdx_S12NSE0;
        break;
    default:
        g_assert_not_reached();
    }

    par64 = do_ats_write(env, value, access_type, mmu_idx);

    A32_BANKED_CURRENT_REG_SET(env, par, par64);
}

static void ats1h_write(CPUARMState *env, const ARMCPRegInfo *ri,
                        uint64_t value)
{
    int access_type = ri->opc2 & 1;
    uint64_t par64;

    par64 = do_ats_write(env, value, access_type, ARMMMUIdx_S2NS);

    A32_BANKED_CURRENT_REG_SET(env, par, par64);
}

static CPAccessResult at_s1e2_access(CPUARMState *env, const ARMCPRegInfo *ri,
                                     bool isread)
{
    if (arm_current_el(env) == 3 && !(env->cp15.scr_el3 & SCR_NS)) {
        return CP_ACCESS_TRAP;
    }
    return CP_ACCESS_OK;
}

static void ats_write64(CPUARMState *env, const ARMCPRegInfo *ri,
                        uint64_t value)
{
    int access_type = ri->opc2 & 1;
    ARMMMUIdx mmu_idx;
    int secure = arm_is_secure_below_el3(env);

    switch (ri->opc2 & 6) {
    case 0:
        switch (ri->opc1) {
        case 0: /* AT S1E1R, AT S1E1W */
            mmu_idx = secure ? ARMMMUIdx_S1SE1 : ARMMMUIdx_S1NSE1;
            break;
        case 4: /* AT S1E2R, AT S1E2W */
            mmu_idx = ARMMMUIdx_S1E2;
            break;
        case 6: /* AT S1E3R, AT S1E3W */
            mmu_idx = ARMMMUIdx_S1E3;
            break;
        default:
            g_assert_not_reached();
        }
        break;
    case 2: /* AT S1E0R, AT S1E0W */
        mmu_idx = secure ? ARMMMUIdx_S1SE0 : ARMMMUIdx_S1NSE0;
        break;
    case 4: /* AT S12E1R, AT S12E1W */
        mmu_idx = secure ? ARMMMUIdx_S1SE1 : ARMMMUIdx_S12NSE1;
        break;
    case 6: /* AT S12E0R, AT S12E0W */
        mmu_idx = secure ? ARMMMUIdx_S1SE0 : ARMMMUIdx_S12NSE0;
        break;
    default:
        g_assert_not_reached();
    }

    env->cp15.par_el[1] = do_ats_write(env, value, access_type, mmu_idx);
}
#endif

static const ARMCPRegInfo vapa_cp_reginfo[] = {
    { .name = "PAR", .cp = 15, .crn = 7, .crm = 4, .opc1 = 0, .opc2 = 0,
      .access = PL1_RW, .resetvalue = 0,
      .bank_fieldoffsets = { offsetoflow32(CPUARMState, cp15.par_s),
                             offsetoflow32(CPUARMState, cp15.par_ns) },
      .writefn = par_write },
#ifndef CONFIG_USER_ONLY
    /* This underdecoding is safe because the reginfo is NO_RAW. */
    { .name = "ATS", .cp = 15, .crn = 7, .crm = 8, .opc1 = 0, .opc2 = CP_ANY,
      .access = PL1_W, .accessfn = ats_access,
      .writefn = ats_write, .type = ARM_CP_NO_RAW },
#endif
    REGINFO_SENTINEL
};

/* Return basic MPU access permission bits.  */
static uint32_t simple_mpu_ap_bits(uint32_t val)
{
    uint32_t ret;
    uint32_t mask;
    int i;
    ret = 0;
    mask = 3;
    for (i = 0; i < 16; i += 2) {
        ret |= (val >> i) & mask;
        mask <<= 2;
    }
    return ret;
}

/* Pad basic MPU access permission bits to extended format.  */
static uint32_t extended_mpu_ap_bits(uint32_t val)
{
    uint32_t ret;
    uint32_t mask;
    int i;
    ret = 0;
    mask = 3;
    for (i = 0; i < 16; i += 2) {
        ret |= (val & mask) << i;
        mask <<= 2;
    }
    return ret;
}

static void pmsav5_data_ap_write(CPUARMState *env, const ARMCPRegInfo *ri,
                                 uint64_t value)
{
    env->cp15.pmsav5_data_ap = extended_mpu_ap_bits(value);
}

static uint64_t pmsav5_data_ap_read(CPUARMState *env, const ARMCPRegInfo *ri)
{
    return simple_mpu_ap_bits(env->cp15.pmsav5_data_ap);
}

static void pmsav5_insn_ap_write(CPUARMState *env, const ARMCPRegInfo *ri,
                                 uint64_t value)
{
    env->cp15.pmsav5_insn_ap = extended_mpu_ap_bits(value);
}

static uint64_t pmsav5_insn_ap_read(CPUARMState *env, const ARMCPRegInfo *ri)
{
    return simple_mpu_ap_bits(env->cp15.pmsav5_insn_ap);
}

static uint64_t pmsav7_read(CPUARMState *env, const ARMCPRegInfo *ri)
{
    uint32_t *u32p = *(uint32_t **)raw_ptr(env, ri);

    if (!u32p) {
        return 0;
    }

    u32p += env->cp15.c6_rgnr;
    return *u32p;
}

static void pmsav7_write(CPUARMState *env, const ARMCPRegInfo *ri,
                         uint64_t value)
{
    ARMCPU *cpu = arm_env_get_cpu(env);
    uint32_t *u32p = *(uint32_t **)raw_ptr(env, ri);

    if (!u32p) {
        return;
    }

    u32p += env->cp15.c6_rgnr;
    tlb_flush(CPU(cpu)); /* Mappings may have changed - purge! */
    *u32p = value;
}

static void pmsav7_reset(CPUARMState *env, const ARMCPRegInfo *ri)
{
    ARMCPU *cpu = arm_env_get_cpu(env);
    uint32_t *u32p = *(uint32_t **)raw_ptr(env, ri);

    if (!u32p) {
        return;
    }

    memset(u32p, 0, sizeof(*u32p) * cpu->pmsav7_dregion);
}

static void pmsav7_rgnr_write(CPUARMState *env, const ARMCPRegInfo *ri,
                              uint64_t value)
{
    ARMCPU *cpu = arm_env_get_cpu(env);
    uint32_t nrgs = cpu->pmsav7_dregion;

    if (value >= nrgs) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "PMSAv7 RGNR write >= # supported regions, %" PRIu32
                      " > %" PRIu32 "\n", (uint32_t)value, nrgs);
        return;
    }

    raw_write(env, ri, value);
}

static const ARMCPRegInfo pmsav7_cp_reginfo[] = {
    { .name = "DRBAR", .cp = 15, .crn = 6, .opc1 = 0, .crm = 1, .opc2 = 0,
      .access = PL1_RW, .type = ARM_CP_NO_RAW,
      .fieldoffset = offsetof(CPUARMState, pmsav7.drbar),
      .readfn = pmsav7_read, .writefn = pmsav7_write, .resetfn = pmsav7_reset },
    { .name = "DRSR", .cp = 15, .crn = 6, .opc1 = 0, .crm = 1, .opc2 = 2,
      .access = PL1_RW, .type = ARM_CP_NO_RAW,
      .fieldoffset = offsetof(CPUARMState, pmsav7.drsr),
      .readfn = pmsav7_read, .writefn = pmsav7_write, .resetfn = pmsav7_reset },
    { .name = "DRACR", .cp = 15, .crn = 6, .opc1 = 0, .crm = 1, .opc2 = 4,
      .access = PL1_RW, .type = ARM_CP_NO_RAW,
      .fieldoffset = offsetof(CPUARMState, pmsav7.dracr),
      .readfn = pmsav7_read, .writefn = pmsav7_write, .resetfn = pmsav7_reset },
    { .name = "RGNR", .cp = 15, .crn = 6, .opc1 = 0, .crm = 2, .opc2 = 0,
      .access = PL1_RW,
      .fieldoffset = offsetof(CPUARMState, cp15.c6_rgnr),
      .writefn = pmsav7_rgnr_write },
    REGINFO_SENTINEL
};

static const ARMCPRegInfo pmsav5_cp_reginfo[] = {
    { .name = "DATA_AP", .cp = 15, .crn = 5, .crm = 0, .opc1 = 0, .opc2 = 0,
      .access = PL1_RW, .type = ARM_CP_ALIAS,
      .fieldoffset = offsetof(CPUARMState, cp15.pmsav5_data_ap),
      .readfn = pmsav5_data_ap_read, .writefn = pmsav5_data_ap_write, },
    { .name = "INSN_AP", .cp = 15, .crn = 5, .crm = 0, .opc1 = 0, .opc2 = 1,
      .access = PL1_RW, .type = ARM_CP_ALIAS,
      .fieldoffset = offsetof(CPUARMState, cp15.pmsav5_insn_ap),
      .readfn = pmsav5_insn_ap_read, .writefn = pmsav5_insn_ap_write, },
    { .name = "DATA_EXT_AP", .cp = 15, .crn = 5, .crm = 0, .opc1 = 0, .opc2 = 2,
      .access = PL1_RW,
      .fieldoffset = offsetof(CPUARMState, cp15.pmsav5_data_ap),
      .resetvalue = 0, },
    { .name = "INSN_EXT_AP", .cp = 15, .crn = 5, .crm = 0, .opc1 = 0, .opc2 = 3,
      .access = PL1_RW,
      .fieldoffset = offsetof(CPUARMState, cp15.pmsav5_insn_ap),
      .resetvalue = 0, },
    { .name = "DCACHE_CFG", .cp = 15, .crn = 2, .crm = 0, .opc1 = 0, .opc2 = 0,
      .access = PL1_RW,
      .fieldoffset = offsetof(CPUARMState, cp15.c2_data), .resetvalue = 0, },
    { .name = "ICACHE_CFG", .cp = 15, .crn = 2, .crm = 0, .opc1 = 0, .opc2 = 1,
      .access = PL1_RW,
      .fieldoffset = offsetof(CPUARMState, cp15.c2_insn), .resetvalue = 0, },
    /* Protection region base and size registers */
    { .name = "946_PRBS0", .cp = 15, .crn = 6, .crm = 0, .opc1 = 0,
      .opc2 = CP_ANY, .access = PL1_RW, .resetvalue = 0,
      .fieldoffset = offsetof(CPUARMState, cp15.c6_region[0]) },
    { .name = "946_PRBS1", .cp = 15, .crn = 6, .crm = 1, .opc1 = 0,
      .opc2 = CP_ANY, .access = PL1_RW, .resetvalue = 0,
      .fieldoffset = offsetof(CPUARMState, cp15.c6_region[1]) },
    { .name = "946_PRBS2", .cp = 15, .crn = 6, .crm = 2, .opc1 = 0,
      .opc2 = CP_ANY, .access = PL1_RW, .resetvalue = 0,
      .fieldoffset = offsetof(CPUARMState, cp15.c6_region[2]) },
    { .name = "946_PRBS3", .cp = 15, .crn = 6, .crm = 3, .opc1 = 0,
      .opc2 = CP_ANY, .access = PL1_RW, .resetvalue = 0,
      .fieldoffset = offsetof(CPUARMState, cp15.c6_region[3]) },
    { .name = "946_PRBS4", .cp = 15, .crn = 6, .crm = 4, .opc1 = 0,
      .opc2 = CP_ANY, .access = PL1_RW, .resetvalue = 0,
      .fieldoffset = offsetof(CPUARMState, cp15.c6_region[4]) },
    { .name = "946_PRBS5", .cp = 15, .crn = 6, .crm = 5, .opc1 = 0,
      .opc2 = CP_ANY, .access = PL1_RW, .resetvalue = 0,
      .fieldoffset = offsetof(CPUARMState, cp15.c6_region[5]) },
    { .name = "946_PRBS6", .cp = 15, .crn = 6, .crm = 6, .opc1 = 0,
      .opc2 = CP_ANY, .access = PL1_RW, .resetvalue = 0,
      .fieldoffset = offsetof(CPUARMState, cp15.c6_region[6]) },
    { .name = "946_PRBS7", .cp = 15, .crn = 6, .crm = 7, .opc1 = 0,
      .opc2 = CP_ANY, .access = PL1_RW, .resetvalue = 0,
      .fieldoffset = offsetof(CPUARMState, cp15.c6_region[7]) },
    REGINFO_SENTINEL
};

static void vmsa_ttbcr_raw_write(CPUARMState *env, const ARMCPRegInfo *ri,
                                 uint64_t value)
{
    TCR *tcr = raw_ptr(env, ri);
    int maskshift = extract32(value, 0, 3);

    if (!arm_feature(env, ARM_FEATURE_V8)) {
        if (arm_feature(env, ARM_FEATURE_LPAE) && (value & TTBCR_EAE)) {
            /* Pre ARMv8 bits [21:19], [15:14] and [6:3] are UNK/SBZP when
             * using Long-desciptor translation table format */
            value &= ~((7 << 19) | (3 << 14) | (0xf << 3));
        } else if (arm_feature(env, ARM_FEATURE_EL3)) {
            /* In an implementation that includes the Security Extensions
             * TTBCR has additional fields PD0 [4] and PD1 [5] for
             * Short-descriptor translation table format.
             */
            value &= TTBCR_PD1 | TTBCR_PD0 | TTBCR_N;
        } else {
            value &= TTBCR_N;
        }
    }

    /* Update the masks corresponding to the TCR bank being written
     * Note that we always calculate mask and base_mask, but
     * they are only used for short-descriptor tables (ie if EAE is 0);
     * for long-descriptor tables the TCR fields are used differently
     * and the mask and base_mask values are meaningless.
     */
    tcr->raw_tcr = value;
    tcr->mask = ~(((uint32_t)0xffffffffu) >> maskshift);
    tcr->base_mask = ~((uint32_t)0x3fffu >> maskshift);
}

static void vmsa_ttbcr_write(CPUARMState *env, const ARMCPRegInfo *ri,
                             uint64_t value)
{
    ARMCPU *cpu = arm_env_get_cpu(env);

    if (arm_feature(env, ARM_FEATURE_LPAE)) {
        /* With LPAE the TTBCR could result in a change of ASID
         * via the TTBCR.A1 bit, so do a TLB flush.
         */
        tlb_flush(CPU(cpu));
    }
    vmsa_ttbcr_raw_write(env, ri, value);
}

static void vmsa_ttbcr_reset(CPUARMState *env, const ARMCPRegInfo *ri)
{
    TCR *tcr = raw_ptr(env, ri);

    /* Reset both the TCR as well as the masks corresponding to the bank of
     * the TCR being reset.
     */
    tcr->raw_tcr = 0;
    tcr->mask = 0;
    tcr->base_mask = 0xffffc000u;
}

static void vmsa_tcr_el1_write(CPUARMState *env, const ARMCPRegInfo *ri,
                               uint64_t value)
{
    ARMCPU *cpu = arm_env_get_cpu(env);
    TCR *tcr = raw_ptr(env, ri);

    /* For AArch64 the A1 bit could result in a change of ASID, so TLB flush. */
    tlb_flush(CPU(cpu));
    tcr->raw_tcr = value;
}

static void vmsa_ttbr_write(CPUARMState *env, const ARMCPRegInfo *ri,
                            uint64_t value)
{
    /* 64 bit accesses to the TTBRs can change the ASID and so we
     * must flush the TLB.
     */
    if (cpreg_field_is_64bit(ri)) {
        ARMCPU *cpu = arm_env_get_cpu(env);

        tlb_flush(CPU(cpu));
    }
    raw_write(env, ri, value);
}

static void vttbr_write(CPUARMState *env, const ARMCPRegInfo *ri,
                        uint64_t value)
{
    ARMCPU *cpu = arm_env_get_cpu(env);
    CPUState *cs = CPU(cpu);

    /* Accesses to VTTBR may change the VMID so we must flush the TLB.  */
    if (raw_read(env, ri) != value) {
        tlb_flush_by_mmuidx(cs, ARMMMUIdx_S12NSE1, ARMMMUIdx_S12NSE0,
                            ARMMMUIdx_S2NS, -1);
        raw_write(env, ri, value);
    }
}

static const ARMCPRegInfo vmsa_pmsa_cp_reginfo[] = {
    { .name = "DFSR", .cp = 15, .crn = 5, .crm = 0, .opc1 = 0, .opc2 = 0,
      .access = PL1_RW, .type = ARM_CP_ALIAS,
      .bank_fieldoffsets = { offsetoflow32(CPUARMState, cp15.dfsr_s),
                             offsetoflow32(CPUARMState, cp15.dfsr_ns) }, },
    { .name = "IFSR", .cp = 15, .crn = 5, .crm = 0, .opc1 = 0, .opc2 = 1,
      .access = PL1_RW, .resetvalue = 0,
      .bank_fieldoffsets = { offsetoflow32(CPUARMState, cp15.ifsr_s),
                             offsetoflow32(CPUARMState, cp15.ifsr_ns) } },
    { .name = "DFAR", .cp = 15, .opc1 = 0, .crn = 6, .crm = 0, .opc2 = 0,
      .access = PL1_RW, .resetvalue = 0,
      .bank_fieldoffsets = { offsetof(CPUARMState, cp15.dfar_s),
                             offsetof(CPUARMState, cp15.dfar_ns) } },
    { .name = "FAR_EL1", .state = ARM_CP_STATE_AA64,
      .opc0 = 3, .crn = 6, .crm = 0, .opc1 = 0, .opc2 = 0,
      .access = PL1_RW, .fieldoffset = offsetof(CPUARMState, cp15.far_el[1]),
      .resetvalue = 0, },
    REGINFO_SENTINEL
};

static const ARMCPRegInfo vmsa_cp_reginfo[] = {
    { .name = "ESR_EL1", .state = ARM_CP_STATE_AA64,
      .opc0 = 3, .crn = 5, .crm = 2, .opc1 = 0, .opc2 = 0,
      .access = PL1_RW,
      .fieldoffset = offsetof(CPUARMState, cp15.esr_el[1]), .resetvalue = 0, },
    { .name = "TTBR0_EL1", .state = ARM_CP_STATE_BOTH,
      .opc0 = 3, .opc1 = 0, .crn = 2, .crm = 0, .opc2 = 0,
      .access = PL1_RW, .writefn = vmsa_ttbr_write, .resetvalue = 0,
      .bank_fieldoffsets = { offsetof(CPUARMState, cp15.ttbr0_s),
                             offsetof(CPUARMState, cp15.ttbr0_ns) } },
    { .name = "TTBR1_EL1", .state = ARM_CP_STATE_BOTH,
      .opc0 = 3, .opc1 = 0, .crn = 2, .crm = 0, .opc2 = 1,
      .access = PL1_RW, .writefn = vmsa_ttbr_write, .resetvalue = 0,
      .bank_fieldoffsets = { offsetof(CPUARMState, cp15.ttbr1_s),
                             offsetof(CPUARMState, cp15.ttbr1_ns) } },
    { .name = "TCR_EL1", .state = ARM_CP_STATE_AA64,
      .opc0 = 3, .crn = 2, .crm = 0, .opc1 = 0, .opc2 = 2,
      .access = PL1_RW, .writefn = vmsa_tcr_el1_write,
      .resetfn = vmsa_ttbcr_reset, .raw_writefn = raw_write,
      .fieldoffset = offsetof(CPUARMState, cp15.tcr_el[1]) },
    { .name = "TTBCR", .cp = 15, .crn = 2, .crm = 0, .opc1 = 0, .opc2 = 2,
      .access = PL1_RW, .type = ARM_CP_ALIAS, .writefn = vmsa_ttbcr_write,
      .raw_writefn = vmsa_ttbcr_raw_write,
      .bank_fieldoffsets = { offsetoflow32(CPUARMState, cp15.tcr_el[3]),
                             offsetoflow32(CPUARMState, cp15.tcr_el[1])} },
    REGINFO_SENTINEL
};

static void omap_ticonfig_write(CPUARMState *env, const ARMCPRegInfo *ri,
                                uint64_t value)
{
    env->cp15.c15_ticonfig = value & 0xe7;
    /* The OS_TYPE bit in this register changes the reported CPUID! */
    env->cp15.c0_cpuid = (value & (1 << 5)) ?
        ARM_CPUID_TI915T : ARM_CPUID_TI925T;
}

static void omap_threadid_write(CPUARMState *env, const ARMCPRegInfo *ri,
                                uint64_t value)
{
    env->cp15.c15_threadid = value & 0xffff;
}

static void omap_wfi_write(CPUARMState *env, const ARMCPRegInfo *ri,
                           uint64_t value)
{
    /* Wait-for-interrupt (deprecated) */
    cpu_interrupt(CPU(arm_env_get_cpu(env)), CPU_INTERRUPT_HALT);
}

static void omap_cachemaint_write(CPUARMState *env, const ARMCPRegInfo *ri,
                                  uint64_t value)
{
    /* On OMAP there are registers indicating the max/min index of dcache lines
     * containing a dirty line; cache flush operations have to reset these.
     */
    env->cp15.c15_i_max = 0x000;
    env->cp15.c15_i_min = 0xff0;
}

static const ARMCPRegInfo omap_cp_reginfo[] = {
    { .name = "DFSR", .cp = 15, .crn = 5, .crm = CP_ANY,
      .opc1 = CP_ANY, .opc2 = CP_ANY, .access = PL1_RW, .type = ARM_CP_OVERRIDE,
      .fieldoffset = offsetoflow32(CPUARMState, cp15.esr_el[1]),
      .resetvalue = 0, },
    { .name = "", .cp = 15, .crn = 15, .crm = 0, .opc1 = 0, .opc2 = 0,
      .access = PL1_RW, .type = ARM_CP_NOP },
    { .name = "TICONFIG", .cp = 15, .crn = 15, .crm = 1, .opc1 = 0, .opc2 = 0,
      .access = PL1_RW,
      .fieldoffset = offsetof(CPUARMState, cp15.c15_ticonfig), .resetvalue = 0,
      .writefn = omap_ticonfig_write },
    { .name = "IMAX", .cp = 15, .crn = 15, .crm = 2, .opc1 = 0, .opc2 = 0,
      .access = PL1_RW,
      .fieldoffset = offsetof(CPUARMState, cp15.c15_i_max), .resetvalue = 0, },
    { .name = "IMIN", .cp = 15, .crn = 15, .crm = 3, .opc1 = 0, .opc2 = 0,
      .access = PL1_RW, .resetvalue = 0xff0,
      .fieldoffset = offsetof(CPUARMState, cp15.c15_i_min) },
    { .name = "THREADID", .cp = 15, .crn = 15, .crm = 4, .opc1 = 0, .opc2 = 0,
      .access = PL1_RW,
      .fieldoffset = offsetof(CPUARMState, cp15.c15_threadid), .resetvalue = 0,
      .writefn = omap_threadid_write },
    { .name = "TI925T_STATUS", .cp = 15, .crn = 15,
      .crm = 8, .opc1 = 0, .opc2 = 0, .access = PL1_RW,
      .type = ARM_CP_NO_RAW,
      .readfn = arm_cp_read_zero, .writefn = omap_wfi_write, },
    /* TODO: Peripheral port remap register:
     * On OMAP2 mcr p15, 0, rn, c15, c2, 4 sets up the interrupt controller
     * base address at $rn & ~0xfff and map size of 0x200 << ($rn & 0xfff),
     * when MMU is off.
     */
    { .name = "OMAP_CACHEMAINT", .cp = 15, .crn = 7, .crm = CP_ANY,
      .opc1 = 0, .opc2 = CP_ANY, .access = PL1_W,
      .type = ARM_CP_OVERRIDE | ARM_CP_NO_RAW,
      .writefn = omap_cachemaint_write },
    { .name = "C9", .cp = 15, .crn = 9,
      .crm = CP_ANY, .opc1 = CP_ANY, .opc2 = CP_ANY, .access = PL1_RW,
      .type = ARM_CP_CONST | ARM_CP_OVERRIDE, .resetvalue = 0 },
    REGINFO_SENTINEL
};

static void xscale_cpar_write(CPUARMState *env, const ARMCPRegInfo *ri,
                              uint64_t value)
{
    env->cp15.c15_cpar = value & 0x3fff;
}

static const ARMCPRegInfo xscale_cp_reginfo[] = {
    { .name = "XSCALE_CPAR",
      .cp = 15, .crn = 15, .crm = 1, .opc1 = 0, .opc2 = 0, .access = PL1_RW,
      .fieldoffset = offsetof(CPUARMState, cp15.c15_cpar), .resetvalue = 0,
      .writefn = xscale_cpar_write, },
    { .name = "XSCALE_AUXCR",
      .cp = 15, .crn = 1, .crm = 0, .opc1 = 0, .opc2 = 1, .access = PL1_RW,
      .fieldoffset = offsetof(CPUARMState, cp15.c1_xscaleauxcr),
      .resetvalue = 0, },
    /* XScale specific cache-lockdown: since we have no cache we NOP these
     * and hope the guest does not really rely on cache behaviour.
     */
    { .name = "XSCALE_LOCK_ICACHE_LINE",
      .cp = 15, .opc1 = 0, .crn = 9, .crm = 1, .opc2 = 0,
      .access = PL1_W, .type = ARM_CP_NOP },
    { .name = "XSCALE_UNLOCK_ICACHE",
      .cp = 15, .opc1 = 0, .crn = 9, .crm = 1, .opc2 = 1,
      .access = PL1_W, .type = ARM_CP_NOP },
    { .name = "XSCALE_DCACHE_LOCK",
      .cp = 15, .opc1 = 0, .crn = 9, .crm = 2, .opc2 = 0,
      .access = PL1_RW, .type = ARM_CP_NOP },
    { .name = "XSCALE_UNLOCK_DCACHE",
      .cp = 15, .opc1 = 0, .crn = 9, .crm = 2, .opc2 = 1,
      .access = PL1_W, .type = ARM_CP_NOP },
    REGINFO_SENTINEL
};

static const ARMCPRegInfo dummy_c15_cp_reginfo[] = {
    /* RAZ/WI the whole crn=15 space, when we don't have a more specific
     * implementation of this implementation-defined space.
     * Ideally this should eventually disappear in favour of actually
     * implementing the correct behaviour for all cores.
     */
    { .name = "C15_IMPDEF", .cp = 15, .crn = 15,
      .crm = CP_ANY, .opc1 = CP_ANY, .opc2 = CP_ANY,
      .access = PL1_RW,
      .type = ARM_CP_CONST | ARM_CP_NO_RAW | ARM_CP_OVERRIDE,
      .resetvalue = 0 },
    REGINFO_SENTINEL
};

static const ARMCPRegInfo cache_dirty_status_cp_reginfo[] = {
    /* Cache status: RAZ because we have no cache so it's always clean */
    { .name = "CDSR", .cp = 15, .crn = 7, .crm = 10, .opc1 = 0, .opc2 = 6,
      .access = PL1_R, .type = ARM_CP_CONST | ARM_CP_NO_RAW,
      .resetvalue = 0 },
    REGINFO_SENTINEL
};

static const ARMCPRegInfo cache_block_ops_cp_reginfo[] = {
    /* We never have a a block transfer operation in progress */
    { .name = "BXSR", .cp = 15, .crn = 7, .crm = 12, .opc1 = 0, .opc2 = 4,
      .access = PL0_R, .type = ARM_CP_CONST | ARM_CP_NO_RAW,
      .resetvalue = 0 },
    /* The cache ops themselves: these all NOP for QEMU */
    { .name = "IICR", .cp = 15, .crm = 5, .opc1 = 0,
      .access = PL1_W, .type = ARM_CP_NOP|ARM_CP_64BIT },
    { .name = "IDCR", .cp = 15, .crm = 6, .opc1 = 0,
      .access = PL1_W, .type = ARM_CP_NOP|ARM_CP_64BIT },
    { .name = "CDCR", .cp = 15, .crm = 12, .opc1 = 0,
      .access = PL0_W, .type = ARM_CP_NOP|ARM_CP_64BIT },
    { .name = "PIR", .cp = 15, .crm = 12, .opc1 = 1,
      .access = PL0_W, .type = ARM_CP_NOP|ARM_CP_64BIT },
    { .name = "PDR", .cp = 15, .crm = 12, .opc1 = 2,
      .access = PL0_W, .type = ARM_CP_NOP|ARM_CP_64BIT },
    { .name = "CIDCR", .cp = 15, .crm = 14, .opc1 = 0,
      .access = PL1_W, .type = ARM_CP_NOP|ARM_CP_64BIT },
    REGINFO_SENTINEL
};

static const ARMCPRegInfo cache_test_clean_cp_reginfo[] = {
    /* The cache test-and-clean instructions always return (1 << 30)
     * to indicate that there are no dirty cache lines.
     */
    { .name = "TC_DCACHE", .cp = 15, .crn = 7, .crm = 10, .opc1 = 0, .opc2 = 3,
      .access = PL0_R, .type = ARM_CP_CONST | ARM_CP_NO_RAW,
      .resetvalue = (1 << 30) },
    { .name = "TCI_DCACHE", .cp = 15, .crn = 7, .crm = 14, .opc1 = 0, .opc2 = 3,
      .access = PL0_R, .type = ARM_CP_CONST | ARM_CP_NO_RAW,
      .resetvalue = (1 << 30) },
    REGINFO_SENTINEL
};

static const ARMCPRegInfo strongarm_cp_reginfo[] = {
    /* Ignore ReadBuffer accesses */
    { .name = "C9_READBUFFER", .cp = 15, .crn = 9,
      .crm = CP_ANY, .opc1 = CP_ANY, .opc2 = CP_ANY,
      .access = PL1_RW, .resetvalue = 0,
      .type = ARM_CP_CONST | ARM_CP_OVERRIDE | ARM_CP_NO_RAW },
    REGINFO_SENTINEL
};

static uint64_t midr_read(CPUARMState *env, const ARMCPRegInfo *ri)
{
    ARMCPU *cpu = arm_env_get_cpu(env);
    unsigned int cur_el = arm_current_el(env);
    bool secure = arm_is_secure(env);

    if (arm_feature(&cpu->env, ARM_FEATURE_EL2) && !secure && cur_el == 1) {
        return env->cp15.vpidr_el2;
    }
    return raw_read(env, ri);
}

static uint64_t mpidr_read_val(CPUARMState *env)
{
    ARMCPU *cpu = ARM_CPU(arm_env_get_cpu(env));
    uint64_t mpidr = cpu->mp_affinity;

    if (arm_feature(env, ARM_FEATURE_V7MP)) {
        mpidr |= (1U << 31);
        /* Cores which are uniprocessor (non-coherent)
         * but still implement the MP extensions set
         * bit 30. (For instance, Cortex-R5).
         */
        if (cpu->mp_is_up) {
            mpidr |= (1u << 30);
        }
    }
    return mpidr;
}

static uint64_t mpidr_read(CPUARMState *env, const ARMCPRegInfo *ri)
{
    unsigned int cur_el = arm_current_el(env);
    bool secure = arm_is_secure(env);

    if (arm_feature(env, ARM_FEATURE_EL2) && !secure && cur_el == 1) {
        return env->cp15.vmpidr_el2;
    }
    return mpidr_read_val(env);
}

static const ARMCPRegInfo mpidr_cp_reginfo[] = {
    { .name = "MPIDR", .state = ARM_CP_STATE_BOTH,
      .opc0 = 3, .crn = 0, .crm = 0, .opc1 = 0, .opc2 = 5,
      .access = PL1_R, .readfn = mpidr_read, .type = ARM_CP_NO_RAW },
    REGINFO_SENTINEL
};

static const ARMCPRegInfo lpae_cp_reginfo[] = {
    /* NOP AMAIR0/1 */
    { .name = "AMAIR0", .state = ARM_CP_STATE_BOTH,
      .opc0 = 3, .crn = 10, .crm = 3, .opc1 = 0, .opc2 = 0,
      .access = PL1_RW, .type = ARM_CP_CONST,
      .resetvalue = 0 },
    /* AMAIR1 is mapped to AMAIR_EL1[63:32] */
    { .name = "AMAIR1", .cp = 15, .crn = 10, .crm = 3, .opc1 = 0, .opc2 = 1,
      .access = PL1_RW, .type = ARM_CP_CONST,
      .resetvalue = 0 },
    { .name = "PAR", .cp = 15, .crm = 7, .opc1 = 0,
      .access = PL1_RW, .type = ARM_CP_64BIT, .resetvalue = 0,
      .bank_fieldoffsets = { offsetof(CPUARMState, cp15.par_s),
                             offsetof(CPUARMState, cp15.par_ns)} },
    { .name = "TTBR0", .cp = 15, .crm = 2, .opc1 = 0,
      .access = PL1_RW, .type = ARM_CP_64BIT | ARM_CP_ALIAS,
      .bank_fieldoffsets = { offsetof(CPUARMState, cp15.ttbr0_s),
                             offsetof(CPUARMState, cp15.ttbr0_ns) },
      .writefn = vmsa_ttbr_write, },
    { .name = "TTBR1", .cp = 15, .crm = 2, .opc1 = 1,
      .access = PL1_RW, .type = ARM_CP_64BIT | ARM_CP_ALIAS,
      .bank_fieldoffsets = { offsetof(CPUARMState, cp15.ttbr1_s),
                             offsetof(CPUARMState, cp15.ttbr1_ns) },
      .writefn = vmsa_ttbr_write, },
    REGINFO_SENTINEL
};

/* Convert vfp exception flags to target form.  */
static inline int vfp_exceptbits_to_host(int target_bits)
{
    int host_bits = 0;

    if (target_bits & 1)
        host_bits |= float_flag_invalid;
    if (target_bits & 2)
        host_bits |= float_flag_divbyzero;
    if (target_bits & 4)
        host_bits |= float_flag_overflow;
    if (target_bits & 8)
        host_bits |= float_flag_underflow;
    if (target_bits & 0x10)
        host_bits |= float_flag_inexact;
    if (target_bits & 0x80)
        host_bits |= float_flag_input_denormal;
    return host_bits;
}

void vfp_set_fpsr(CPUARMState *env, uint32_t val)
{
    uint32_t new_fpscr = (vfp_get_fpscr(env) & ~FPSR_MASK) | (val & FPSR_MASK);
    vfp_set_fpscr(env, new_fpscr);
}

void vfp_set_fpcr(CPUARMState *env, uint32_t val)
{
    uint32_t new_fpscr = (vfp_get_fpscr(env) & ~FPCR_MASK) | (val & FPCR_MASK);
    vfp_set_fpscr(env, new_fpscr);
}

void vfp_set_fpscr(CPUARMState *env, uint32_t val)
{
    int i;
    uint32_t changed;

    changed = env->vfp.xregs[ARM_VFP_FPSCR];
    env->vfp.xregs[ARM_VFP_FPSCR] = (val & 0xffc8ffff);
    env->vfp.vec_len = (val >> 16) & 7;
    env->vfp.vec_stride = (val >> 20) & 3;

    changed ^= val;
    if (changed & (3 << 22)) {
        i = (val >> 22) & 3;
        switch (i) {
        case FPROUNDING_TIEEVEN:
            i = float_round_nearest_even;
            break;
        case FPROUNDING_POSINF:
            i = float_round_up;
            break;
        case FPROUNDING_NEGINF:
            i = float_round_down;
            break;
        case FPROUNDING_ZERO:
            i = float_round_to_zero;
            break;
        }
        set_float_rounding_mode(i, &env->vfp.fp_status);
    }
    if (changed & (1 << 24)) {
        set_flush_to_zero((val & (1 << 24)) != 0, &env->vfp.fp_status);
        set_flush_inputs_to_zero((val & (1 << 24)) != 0, &env->vfp.fp_status);
    }
    if (changed & (1 << 25))
        set_default_nan_mode((val & (1 << 25)) != 0, &env->vfp.fp_status);

    i = vfp_exceptbits_to_host(val);
    set_float_exception_flags(i, &env->vfp.fp_status);
    set_float_exception_flags(0, &env->vfp.standard_fp_status);
}

static uint64_t aa64_fpcr_read(CPUARMState *env, const ARMCPRegInfo *ri)
{
    return vfp_get_fpcr(env);
}

static void aa64_fpcr_write(CPUARMState *env, const ARMCPRegInfo *ri,
                            uint64_t value)
{
    vfp_set_fpcr(env, value);
}

static uint64_t aa64_fpsr_read(CPUARMState *env, const ARMCPRegInfo *ri)
{
    return vfp_get_fpsr(env);
}

static void aa64_fpsr_write(CPUARMState *env, const ARMCPRegInfo *ri,
                            uint64_t value)
{
    vfp_set_fpsr(env, value);
}

static CPAccessResult aa64_daif_access(CPUARMState *env, const ARMCPRegInfo *ri,
                                       bool isread)
{
    if (arm_current_el(env) == 0 && !(env->cp15.sctlr_el[1] & SCTLR_UMA)) {
        return CP_ACCESS_TRAP;
    }
    return CP_ACCESS_OK;
}

static void aa64_daif_write(CPUARMState *env, const ARMCPRegInfo *ri,
                            uint64_t value)
{
    env->daif = value & PSTATE_DAIF;
}

static CPAccessResult aa64_cacheop_access(CPUARMState *env,
                                          const ARMCPRegInfo *ri,
                                          bool isread)
{
    /* Cache invalidate/clean: NOP, but EL0 must UNDEF unless
     * SCTLR_EL1.UCI is set.
     */
    if (arm_current_el(env) == 0 && !(env->cp15.sctlr_el[1] & SCTLR_UCI)) {
        return CP_ACCESS_TRAP;
    }
    return CP_ACCESS_OK;
}

/* See: D4.7.2 TLB maintenance requirements and the TLB maintenance instructions
 * Page D4-1736 (DDI0487A.b)
 */

static void tlbi_aa64_vmalle1_write(CPUARMState *env, const ARMCPRegInfo *ri,
                                    uint64_t value)
{
    ARMCPU *cpu = arm_env_get_cpu(env);
    CPUState *cs = CPU(cpu);

    if (arm_is_secure_below_el3(env)) {
        tlb_flush_by_mmuidx(cs, ARMMMUIdx_S1SE1, ARMMMUIdx_S1SE0, -1);
    } else {
        tlb_flush_by_mmuidx(cs, ARMMMUIdx_S12NSE1, ARMMMUIdx_S12NSE0, -1);
    }
}

static void tlbi_aa64_vmalle1is_write(CPUARMState *env, const ARMCPRegInfo *ri,
                                      uint64_t value)
{
    bool sec = arm_is_secure_below_el3(env);
    CPUState *other_cs;

    CPU_FOREACH(other_cs) {
        if (sec) {
            tlb_flush_by_mmuidx(other_cs, ARMMMUIdx_S1SE1, ARMMMUIdx_S1SE0, -1);
        } else {
            tlb_flush_by_mmuidx(other_cs, ARMMMUIdx_S12NSE1,
                                ARMMMUIdx_S12NSE0, -1);
        }
    }
}

static void tlbi_aa64_alle1_write(CPUARMState *env, const ARMCPRegInfo *ri,
                                  uint64_t value)
{
    /* Note that the 'ALL' scope must invalidate both stage 1 and
     * stage 2 translations, whereas most other scopes only invalidate
     * stage 1 translations.
     */
    ARMCPU *cpu = arm_env_get_cpu(env);
    CPUState *cs = CPU(cpu);

    if (arm_is_secure_below_el3(env)) {
        tlb_flush_by_mmuidx(cs, ARMMMUIdx_S1SE1, ARMMMUIdx_S1SE0, -1);
    } else {
        if (arm_feature(env, ARM_FEATURE_EL2)) {
            tlb_flush_by_mmuidx(cs, ARMMMUIdx_S12NSE1, ARMMMUIdx_S12NSE0,
                                ARMMMUIdx_S2NS, -1);
        } else {
            tlb_flush_by_mmuidx(cs, ARMMMUIdx_S12NSE1, ARMMMUIdx_S12NSE0, -1);
        }
    }
}

static void tlbi_aa64_alle2_write(CPUARMState *env, const ARMCPRegInfo *ri,
                                  uint64_t value)
{
    ARMCPU *cpu = arm_env_get_cpu(env);
    CPUState *cs = CPU(cpu);

    tlb_flush_by_mmuidx(cs, ARMMMUIdx_S1E2, -1);
}

static void tlbi_aa64_alle3_write(CPUARMState *env, const ARMCPRegInfo *ri,
                                  uint64_t value)
{
    ARMCPU *cpu = arm_env_get_cpu(env);
    CPUState *cs = CPU(cpu);

    tlb_flush_by_mmuidx(cs, ARMMMUIdx_S1E3, -1);
}

static void tlbi_aa64_alle1is_write(CPUARMState *env, const ARMCPRegInfo *ri,
                                    uint64_t value)
{
    /* Note that the 'ALL' scope must invalidate both stage 1 and
     * stage 2 translations, whereas most other scopes only invalidate
     * stage 1 translations.
     */
    bool sec = arm_is_secure_below_el3(env);
    bool has_el2 = arm_feature(env, ARM_FEATURE_EL2);
    CPUState *other_cs;

    CPU_FOREACH(other_cs) {
        if (sec) {
            tlb_flush_by_mmuidx(other_cs, ARMMMUIdx_S1SE1, ARMMMUIdx_S1SE0, -1);
        } else if (has_el2) {
            tlb_flush_by_mmuidx(other_cs, ARMMMUIdx_S12NSE1,
                                ARMMMUIdx_S12NSE0, ARMMMUIdx_S2NS, -1);
        } else {
            tlb_flush_by_mmuidx(other_cs, ARMMMUIdx_S12NSE1,
                                ARMMMUIdx_S12NSE0, -1);
        }
    }
}

static void tlbi_aa64_alle2is_write(CPUARMState *env, const ARMCPRegInfo *ri,
                                    uint64_t value)
{
    CPUState *other_cs;

    CPU_FOREACH(other_cs) {
        tlb_flush_by_mmuidx(other_cs, ARMMMUIdx_S1E2, -1);
    }
}

static void tlbi_aa64_alle3is_write(CPUARMState *env, const ARMCPRegInfo *ri,
                                    uint64_t value)
{
    CPUState *other_cs;

    CPU_FOREACH(other_cs) {
        tlb_flush_by_mmuidx(other_cs, ARMMMUIdx_S1E3, -1);
    }
}

static void tlbi_aa64_vae1_write(CPUARMState *env, const ARMCPRegInfo *ri,
                                 uint64_t value)
{
    /* Invalidate by VA, EL1&0 (AArch64 version).
     * Currently handles all of VAE1, VAAE1, VAALE1 and VALE1,
     * since we don't support flush-for-specific-ASID-only or
     * flush-last-level-only.
     */
    ARMCPU *cpu = arm_env_get_cpu(env);
    CPUState *cs = CPU(cpu);
    uint64_t pageaddr = sextract64(value << 12, 0, 56);

    if (arm_is_secure_below_el3(env)) {
        tlb_flush_page_by_mmuidx(cs, pageaddr, ARMMMUIdx_S1SE1,
                                 ARMMMUIdx_S1SE0, -1);
    } else {
        tlb_flush_page_by_mmuidx(cs, pageaddr, ARMMMUIdx_S12NSE1,
                                 ARMMMUIdx_S12NSE0, -1);
    }
}

static void tlbi_aa64_vae2_write(CPUARMState *env, const ARMCPRegInfo *ri,
                                 uint64_t value)
{
    /* Invalidate by VA, EL2
     * Currently handles both VAE2 and VALE2, since we don't support
     * flush-last-level-only.
     */
    ARMCPU *cpu = arm_env_get_cpu(env);
    CPUState *cs = CPU(cpu);
    uint64_t pageaddr = sextract64(value << 12, 0, 56);

    tlb_flush_page_by_mmuidx(cs, pageaddr, ARMMMUIdx_S1E2, -1);
}

static void tlbi_aa64_vae3_write(CPUARMState *env, const ARMCPRegInfo *ri,
                                 uint64_t value)
{
    /* Invalidate by VA, EL3
     * Currently handles both VAE3 and VALE3, since we don't support
     * flush-last-level-only.
     */
    ARMCPU *cpu = arm_env_get_cpu(env);
    CPUState *cs = CPU(cpu);
    uint64_t pageaddr = sextract64(value << 12, 0, 56);

    tlb_flush_page_by_mmuidx(cs, pageaddr, ARMMMUIdx_S1E3, -1);
}

static void tlbi_aa64_vae1is_write(CPUARMState *env, const ARMCPRegInfo *ri,
                                   uint64_t value)
{
    bool sec = arm_is_secure_below_el3(env);
    CPUState *other_cs;
    uint64_t pageaddr = sextract64(value << 12, 0, 56);

    CPU_FOREACH(other_cs) {
        if (sec) {
            tlb_flush_page_by_mmuidx(other_cs, pageaddr, ARMMMUIdx_S1SE1,
                                     ARMMMUIdx_S1SE0, -1);
        } else {
            tlb_flush_page_by_mmuidx(other_cs, pageaddr, ARMMMUIdx_S12NSE1,
                                     ARMMMUIdx_S12NSE0, -1);
        }
    }
}

static void tlbi_aa64_vae2is_write(CPUARMState *env, const ARMCPRegInfo *ri,
                                   uint64_t value)
{
    CPUState *other_cs;
    uint64_t pageaddr = sextract64(value << 12, 0, 56);

    CPU_FOREACH(other_cs) {
        tlb_flush_page_by_mmuidx(other_cs, pageaddr, ARMMMUIdx_S1E2, -1);
    }
}

static void tlbi_aa64_vae3is_write(CPUARMState *env, const ARMCPRegInfo *ri,
                                   uint64_t value)
{
    CPUState *other_cs;
    uint64_t pageaddr = sextract64(value << 12, 0, 56);

    CPU_FOREACH(other_cs) {
        tlb_flush_page_by_mmuidx(other_cs, pageaddr, ARMMMUIdx_S1E3, -1);
    }
}

static void tlbi_aa64_ipas2e1_write(CPUARMState *env, const ARMCPRegInfo *ri,
                                    uint64_t value)
{
    /* Invalidate by IPA. This has to invalidate any structures that
     * contain only stage 2 translation information, but does not need
     * to apply to structures that contain combined stage 1 and stage 2
     * translation information.
     * This must NOP if EL2 isn't implemented or SCR_EL3.NS is zero.
     */
    ARMCPU *cpu = arm_env_get_cpu(env);
    CPUState *cs = CPU(cpu);
    uint64_t pageaddr;

    if (!arm_feature(env, ARM_FEATURE_EL2) || !(env->cp15.scr_el3 & SCR_NS)) {
        return;
    }

    pageaddr = sextract64(value << 12, 0, 48);

    tlb_flush_page_by_mmuidx(cs, pageaddr, ARMMMUIdx_S2NS, -1);
}

static void tlbi_aa64_ipas2e1is_write(CPUARMState *env, const ARMCPRegInfo *ri,
                                      uint64_t value)
{
    CPUState *other_cs;
    uint64_t pageaddr;

    if (!arm_feature(env, ARM_FEATURE_EL2) || !(env->cp15.scr_el3 & SCR_NS)) {
        return;
    }

    pageaddr = sextract64(value << 12, 0, 48);

    CPU_FOREACH(other_cs) {
        tlb_flush_page_by_mmuidx(other_cs, pageaddr, ARMMMUIdx_S2NS, -1);
    }
}

static CPAccessResult aa64_zva_access(CPUARMState *env, const ARMCPRegInfo *ri,
                                      bool isread)
{
    /* We don't implement EL2, so the only control on DC ZVA is the
     * bit in the SCTLR which can prohibit access for EL0.
     */
    if (arm_current_el(env) == 0 && !(env->cp15.sctlr_el[1] & SCTLR_DZE)) {
        return CP_ACCESS_TRAP;
    }
    return CP_ACCESS_OK;
}

static uint64_t aa64_dczid_read(CPUARMState *env, const ARMCPRegInfo *ri)
{
    ARMCPU *cpu = arm_env_get_cpu(env);
    int dzp_bit = 1 << 4;

    /* DZP indicates whether DC ZVA access is allowed */
    if (aa64_zva_access(env, NULL, false) == CP_ACCESS_OK) {
        dzp_bit = 0;
    }
    return cpu->dcz_blocksize | dzp_bit;
}

static CPAccessResult sp_el0_access(CPUARMState *env, const ARMCPRegInfo *ri,
                                    bool isread)
{
    if (!(env->pstate & PSTATE_SP)) {
        /* Access to SP_EL0 is undefined if it's being used as
         * the stack pointer.
         */
        return CP_ACCESS_TRAP_UNCATEGORIZED;
    }
    return CP_ACCESS_OK;
}

static uint64_t spsel_read(CPUARMState *env, const ARMCPRegInfo *ri)
{
    return env->pstate & PSTATE_SP;
}

static void spsel_write(CPUARMState *env, const ARMCPRegInfo *ri, uint64_t val)
{
    update_spsel(env, val);
}

static void sctlr_write(CPUARMState *env, const ARMCPRegInfo *ri,
                        uint64_t value)
{
    ARMCPU *cpu = arm_env_get_cpu(env);

    if (raw_read(env, ri) == value) {
        /* Skip the TLB flush if nothing actually changed; Linux likes
         * to do a lot of pointless SCTLR writes.
         */
        return;
    }

    raw_write(env, ri, value);
    /* ??? Lots of these bits are not implemented.  */
    /* This may enable/disable the MMU, so do a TLB flush.  */
    tlb_flush(CPU(cpu));
}

static CPAccessResult fpexc32_access(CPUARMState *env, const ARMCPRegInfo *ri,
                                     bool isread)
{
    if ((env->cp15.cptr_el[2] & CPTR_TFP) && arm_current_el(env) == 2) {
        return CP_ACCESS_TRAP_FP_EL2;
    }
    if (env->cp15.cptr_el[3] & CPTR_TFP) {
        return CP_ACCESS_TRAP_FP_EL3;
    }
    return CP_ACCESS_OK;
}

static void sdcr_write(CPUARMState *env, const ARMCPRegInfo *ri,
                       uint64_t value)
{
    env->cp15.mdcr_el3 = value & SDCR_VALID_MASK;
}

static const ARMCPRegInfo v8_cp_reginfo[] = {
    /* Minimal set of EL0-visible registers. This will need to be expanded
     * significantly for system emulation of AArch64 CPUs.
     */
    { .name = "NZCV", .state = ARM_CP_STATE_AA64,
      .opc0 = 3, .opc1 = 3, .opc2 = 0, .crn = 4, .crm = 2,
      .access = PL0_RW, .type = ARM_CP_NZCV },
    { .name = "DAIF", .state = ARM_CP_STATE_AA64,
      .opc0 = 3, .opc1 = 3, .opc2 = 1, .crn = 4, .crm = 2,
      .type = ARM_CP_NO_RAW,
      .access = PL0_RW, .accessfn = aa64_daif_access,
      .fieldoffset = offsetof(CPUARMState, daif),
      .writefn = aa64_daif_write, .resetfn = arm_cp_reset_ignore },
    { .name = "FPCR", .state = ARM_CP_STATE_AA64,
      .opc0 = 3, .opc1 = 3, .opc2 = 0, .crn = 4, .crm = 4,
      .access = PL0_RW, .readfn = aa64_fpcr_read, .writefn = aa64_fpcr_write },
    { .name = "FPSR", .state = ARM_CP_STATE_AA64,
      .opc0 = 3, .opc1 = 3, .opc2 = 1, .crn = 4, .crm = 4,
      .access = PL0_RW, .readfn = aa64_fpsr_read, .writefn = aa64_fpsr_write },
    { .name = "DCZID_EL0", .state = ARM_CP_STATE_AA64,
      .opc0 = 3, .opc1 = 3, .opc2 = 7, .crn = 0, .crm = 0,
      .access = PL0_R, .type = ARM_CP_NO_RAW,
      .readfn = aa64_dczid_read },
    { .name = "DC_ZVA", .state = ARM_CP_STATE_AA64,
      .opc0 = 1, .opc1 = 3, .crn = 7, .crm = 4, .opc2 = 1,
      .access = PL0_W, .type = ARM_CP_DC_ZVA,
#ifndef CONFIG_USER_ONLY
      /* Avoid overhead of an access check that always passes in user-mode */
      .accessfn = aa64_zva_access,
#endif
    },
    { .name = "CURRENTEL", .state = ARM_CP_STATE_AA64,
      .opc0 = 3, .opc1 = 0, .opc2 = 2, .crn = 4, .crm = 2,
      .access = PL1_R, .type = ARM_CP_CURRENTEL },
    /* Cache ops: all NOPs since we don't emulate caches */
    { .name = "IC_IALLUIS", .state = ARM_CP_STATE_AA64,
      .opc0 = 1, .opc1 = 0, .crn = 7, .crm = 1, .opc2 = 0,
      .access = PL1_W, .type = ARM_CP_NOP },
    { .name = "IC_IALLU", .state = ARM_CP_STATE_AA64,
      .opc0 = 1, .opc1 = 0, .crn = 7, .crm = 5, .opc2 = 0,
      .access = PL1_W, .type = ARM_CP_NOP },
    { .name = "IC_IVAU", .state = ARM_CP_STATE_AA64,
      .opc0 = 1, .opc1 = 3, .crn = 7, .crm = 5, .opc2 = 1,
      .access = PL0_W, .type = ARM_CP_NOP,
      .accessfn = aa64_cacheop_access },
    { .name = "DC_IVAC", .state = ARM_CP_STATE_AA64,
      .opc0 = 1, .opc1 = 0, .crn = 7, .crm = 6, .opc2 = 1,
      .access = PL1_W, .type = ARM_CP_NOP },
    { .name = "DC_ISW", .state = ARM_CP_STATE_AA64,
      .opc0 = 1, .opc1 = 0, .crn = 7, .crm = 6, .opc2 = 2,
      .access = PL1_W, .type = ARM_CP_NOP },
    { .name = "DC_CVAC", .state = ARM_CP_STATE_AA64,
      .opc0 = 1, .opc1 = 3, .crn = 7, .crm = 10, .opc2 = 1,
      .access = PL0_W, .type = ARM_CP_NOP,
      .accessfn = aa64_cacheop_access },
    { .name = "DC_CSW", .state = ARM_CP_STATE_AA64,
      .opc0 = 1, .opc1 = 0, .crn = 7, .crm = 10, .opc2 = 2,
      .access = PL1_W, .type = ARM_CP_NOP },
    { .name = "DC_CVAU", .state = ARM_CP_STATE_AA64,
      .opc0 = 1, .opc1 = 3, .crn = 7, .crm = 11, .opc2 = 1,
      .access = PL0_W, .type = ARM_CP_NOP,
      .accessfn = aa64_cacheop_access },
    { .name = "DC_CIVAC", .state = ARM_CP_STATE_AA64,
      .opc0 = 1, .opc1 = 3, .crn = 7, .crm = 14, .opc2 = 1,
      .access = PL0_W, .type = ARM_CP_NOP,
      .accessfn = aa64_cacheop_access },
    { .name = "DC_CISW", .state = ARM_CP_STATE_AA64,
      .opc0 = 1, .opc1 = 0, .crn = 7, .crm = 14, .opc2 = 2,
      .access = PL1_W, .type = ARM_CP_NOP },
    /* TLBI operations */
    { .name = "TLBI_VMALLE1IS", .state = ARM_CP_STATE_AA64,
      .opc0 = 1, .opc1 = 0, .crn = 8, .crm = 3, .opc2 = 0,
      .access = PL1_W, .type = ARM_CP_NO_RAW,
      .writefn = tlbi_aa64_vmalle1is_write },
    { .name = "TLBI_VAE1IS", .state = ARM_CP_STATE_AA64,
      .opc0 = 1, .opc1 = 0, .crn = 8, .crm = 3, .opc2 = 1,
      .access = PL1_W, .type = ARM_CP_NO_RAW,
      .writefn = tlbi_aa64_vae1is_write },
    { .name = "TLBI_ASIDE1IS", .state = ARM_CP_STATE_AA64,
      .opc0 = 1, .opc1 = 0, .crn = 8, .crm = 3, .opc2 = 2,
      .access = PL1_W, .type = ARM_CP_NO_RAW,
      .writefn = tlbi_aa64_vmalle1is_write },
    { .name = "TLBI_VAAE1IS", .state = ARM_CP_STATE_AA64,
      .opc0 = 1, .opc1 = 0, .crn = 8, .crm = 3, .opc2 = 3,
      .access = PL1_W, .type = ARM_CP_NO_RAW,
      .writefn = tlbi_aa64_vae1is_write },
    { .name = "TLBI_VALE1IS", .state = ARM_CP_STATE_AA64,
      .opc0 = 1, .opc1 = 0, .crn = 8, .crm = 3, .opc2 = 5,
      .access = PL1_W, .type = ARM_CP_NO_RAW,
      .writefn = tlbi_aa64_vae1is_write },
    { .name = "TLBI_VAALE1IS", .state = ARM_CP_STATE_AA64,
      .opc0 = 1, .opc1 = 0, .crn = 8, .crm = 3, .opc2 = 7,
      .access = PL1_W, .type = ARM_CP_NO_RAW,
      .writefn = tlbi_aa64_vae1is_write },
    { .name = "TLBI_VMALLE1", .state = ARM_CP_STATE_AA64,
      .opc0 = 1, .opc1 = 0, .crn = 8, .crm = 7, .opc2 = 0,
      .access = PL1_W, .type = ARM_CP_NO_RAW,
      .writefn = tlbi_aa64_vmalle1_write },
    { .name = "TLBI_VAE1", .state = ARM_CP_STATE_AA64,
      .opc0 = 1, .opc1 = 0, .crn = 8, .crm = 7, .opc2 = 1,
      .access = PL1_W, .type = ARM_CP_NO_RAW,
      .writefn = tlbi_aa64_vae1_write },
    { .name = "TLBI_ASIDE1", .state = ARM_CP_STATE_AA64,
      .opc0 = 1, .opc1 = 0, .crn = 8, .crm = 7, .opc2 = 2,
      .access = PL1_W, .type = ARM_CP_NO_RAW,
      .writefn = tlbi_aa64_vmalle1_write },
    { .name = "TLBI_VAAE1", .state = ARM_CP_STATE_AA64,
      .opc0 = 1, .opc1 = 0, .crn = 8, .crm = 7, .opc2 = 3,
      .access = PL1_W, .type = ARM_CP_NO_RAW,
      .writefn = tlbi_aa64_vae1_write },
    { .name = "TLBI_VALE1", .state = ARM_CP_STATE_AA64,
      .opc0 = 1, .opc1 = 0, .crn = 8, .crm = 7, .opc2 = 5,
      .access = PL1_W, .type = ARM_CP_NO_RAW,
      .writefn = tlbi_aa64_vae1_write },
    { .name = "TLBI_VAALE1", .state = ARM_CP_STATE_AA64,
      .opc0 = 1, .opc1 = 0, .crn = 8, .crm = 7, .opc2 = 7,
      .access = PL1_W, .type = ARM_CP_NO_RAW,
      .writefn = tlbi_aa64_vae1_write },
    { .name = "TLBI_IPAS2E1IS", .state = ARM_CP_STATE_AA64,
      .opc0 = 1, .opc1 = 4, .crn = 8, .crm = 0, .opc2 = 1,
      .access = PL2_W, .type = ARM_CP_NO_RAW,
      .writefn = tlbi_aa64_ipas2e1is_write },
    { .name = "TLBI_IPAS2LE1IS", .state = ARM_CP_STATE_AA64,
      .opc0 = 1, .opc1 = 4, .crn = 8, .crm = 0, .opc2 = 5,
      .access = PL2_W, .type = ARM_CP_NO_RAW,
      .writefn = tlbi_aa64_ipas2e1is_write },
    { .name = "TLBI_ALLE1IS", .state = ARM_CP_STATE_AA64,
      .opc0 = 1, .opc1 = 4, .crn = 8, .crm = 3, .opc2 = 4,
      .access = PL2_W, .type = ARM_CP_NO_RAW,
      .writefn = tlbi_aa64_alle1is_write },
    { .name = "TLBI_VMALLS12E1IS", .state = ARM_CP_STATE_AA64,
      .opc0 = 1, .opc1 = 4, .crn = 8, .crm = 3, .opc2 = 6,
      .access = PL2_W, .type = ARM_CP_NO_RAW,
      .writefn = tlbi_aa64_alle1is_write },
    { .name = "TLBI_IPAS2E1", .state = ARM_CP_STATE_AA64,
      .opc0 = 1, .opc1 = 4, .crn = 8, .crm = 4, .opc2 = 1,
      .access = PL2_W, .type = ARM_CP_NO_RAW,
      .writefn = tlbi_aa64_ipas2e1_write },
    { .name = "TLBI_IPAS2LE1", .state = ARM_CP_STATE_AA64,
      .opc0 = 1, .opc1 = 4, .crn = 8, .crm = 4, .opc2 = 5,
      .access = PL2_W, .type = ARM_CP_NO_RAW,
      .writefn = tlbi_aa64_ipas2e1_write },
    { .name = "TLBI_ALLE1", .state = ARM_CP_STATE_AA64,
      .opc0 = 1, .opc1 = 4, .crn = 8, .crm = 7, .opc2 = 4,
      .access = PL2_W, .type = ARM_CP_NO_RAW,
      .writefn = tlbi_aa64_alle1_write },
    { .name = "TLBI_VMALLS12E1", .state = ARM_CP_STATE_AA64,
      .opc0 = 1, .opc1 = 4, .crn = 8, .crm = 7, .opc2 = 6,
      .access = PL2_W, .type = ARM_CP_NO_RAW,
      .writefn = tlbi_aa64_alle1is_write },
#ifndef CONFIG_USER_ONLY
    /* 64 bit address translation operations */
    { .name = "AT_S1E1R", .state = ARM_CP_STATE_AA64,
      .opc0 = 1, .opc1 = 0, .crn = 7, .crm = 8, .opc2 = 0,
      .access = PL1_W, .type = ARM_CP_NO_RAW, .writefn = ats_write64 },
    { .name = "AT_S1E1W", .state = ARM_CP_STATE_AA64,
      .opc0 = 1, .opc1 = 0, .crn = 7, .crm = 8, .opc2 = 1,
      .access = PL1_W, .type = ARM_CP_NO_RAW, .writefn = ats_write64 },
    { .name = "AT_S1E0R", .state = ARM_CP_STATE_AA64,
      .opc0 = 1, .opc1 = 0, .crn = 7, .crm = 8, .opc2 = 2,
      .access = PL1_W, .type = ARM_CP_NO_RAW, .writefn = ats_write64 },
    { .name = "AT_S1E0W", .state = ARM_CP_STATE_AA64,
      .opc0 = 1, .opc1 = 0, .crn = 7, .crm = 8, .opc2 = 3,
      .access = PL1_W, .type = ARM_CP_NO_RAW, .writefn = ats_write64 },
    { .name = "AT_S12E1R", .state = ARM_CP_STATE_AA64,
      .opc0 = 1, .opc1 = 4, .crn = 7, .crm = 8, .opc2 = 4,
      .access = PL2_W, .type = ARM_CP_NO_RAW, .writefn = ats_write64 },
    { .name = "AT_S12E1W", .state = ARM_CP_STATE_AA64,
      .opc0 = 1, .opc1 = 4, .crn = 7, .crm = 8, .opc2 = 5,
      .access = PL2_W, .type = ARM_CP_NO_RAW, .writefn = ats_write64 },
    { .name = "AT_S12E0R", .state = ARM_CP_STATE_AA64,
      .opc0 = 1, .opc1 = 4, .crn = 7, .crm = 8, .opc2 = 6,
      .access = PL2_W, .type = ARM_CP_NO_RAW, .writefn = ats_write64 },
    { .name = "AT_S12E0W", .state = ARM_CP_STATE_AA64,
      .opc0 = 1, .opc1 = 4, .crn = 7, .crm = 8, .opc2 = 7,
      .access = PL2_W, .type = ARM_CP_NO_RAW, .writefn = ats_write64 },
    /* AT S1E2* are elsewhere as they UNDEF from EL3 if EL2 is not present */
    { .name = "AT_S1E3R", .state = ARM_CP_STATE_AA64,
      .opc0 = 1, .opc1 = 6, .crn = 7, .crm = 8, .opc2 = 0,
      .access = PL3_W, .type = ARM_CP_NO_RAW, .writefn = ats_write64 },
    { .name = "AT_S1E3W", .state = ARM_CP_STATE_AA64,
      .opc0 = 1, .opc1 = 6, .crn = 7, .crm = 8, .opc2 = 1,
      .access = PL3_W, .type = ARM_CP_NO_RAW, .writefn = ats_write64 },
    { .name = "PAR_EL1", .state = ARM_CP_STATE_AA64,
      .type = ARM_CP_ALIAS,
      .opc0 = 3, .opc1 = 0, .crn = 7, .crm = 4, .opc2 = 0,
      .access = PL1_RW, .resetvalue = 0,
      .fieldoffset = offsetof(CPUARMState, cp15.par_el[1]),
      .writefn = par_write },
#endif
    /* TLB invalidate last level of translation table walk */
    { .name = "TLBIMVALIS", .cp = 15, .opc1 = 0, .crn = 8, .crm = 3, .opc2 = 5,
      .type = ARM_CP_NO_RAW, .access = PL1_W, .writefn = tlbimva_is_write },
    { .name = "TLBIMVAALIS", .cp = 15, .opc1 = 0, .crn = 8, .crm = 3, .opc2 = 7,
      .type = ARM_CP_NO_RAW, .access = PL1_W,
      .writefn = tlbimvaa_is_write },
    { .name = "TLBIMVAL", .cp = 15, .opc1 = 0, .crn = 8, .crm = 7, .opc2 = 5,
      .type = ARM_CP_NO_RAW, .access = PL1_W, .writefn = tlbimva_write },
    { .name = "TLBIMVAAL", .cp = 15, .opc1 = 0, .crn = 8, .crm = 7, .opc2 = 7,
      .type = ARM_CP_NO_RAW, .access = PL1_W, .writefn = tlbimvaa_write },
    { .name = "TLBIMVALH", .cp = 15, .opc1 = 4, .crn = 8, .crm = 7, .opc2 = 5,
      .type = ARM_CP_NO_RAW, .access = PL2_W,
      .writefn = tlbimva_hyp_write },
    { .name = "TLBIMVALHIS",
      .cp = 15, .opc1 = 4, .crn = 8, .crm = 3, .opc2 = 5,
      .type = ARM_CP_NO_RAW, .access = PL2_W,
      .writefn = tlbimva_hyp_is_write },
    { .name = "TLBIIPAS2",
      .cp = 15, .opc1 = 4, .crn = 8, .crm = 4, .opc2 = 1,
      .type = ARM_CP_NO_RAW, .access = PL2_W,
      .writefn = tlbiipas2_write },
    { .name = "TLBIIPAS2IS",
      .cp = 15, .opc1 = 4, .crn = 8, .crm = 0, .opc2 = 1,
      .type = ARM_CP_NO_RAW, .access = PL2_W,
      .writefn = tlbiipas2_is_write },
    { .name = "TLBIIPAS2L",
      .cp = 15, .opc1 = 4, .crn = 8, .crm = 4, .opc2 = 5,
      .type = ARM_CP_NO_RAW, .access = PL2_W,
      .writefn = tlbiipas2_write },
    { .name = "TLBIIPAS2LIS",
      .cp = 15, .opc1 = 4, .crn = 8, .crm = 0, .opc2 = 5,
      .type = ARM_CP_NO_RAW, .access = PL2_W,
      .writefn = tlbiipas2_is_write },
    /* 32 bit cache operations */
    { .name = "ICIALLUIS", .cp = 15, .opc1 = 0, .crn = 7, .crm = 1, .opc2 = 0,
      .type = ARM_CP_NOP, .access = PL1_W },
    { .name = "BPIALLUIS", .cp = 15, .opc1 = 0, .crn = 7, .crm = 1, .opc2 = 6,
      .type = ARM_CP_NOP, .access = PL1_W },
    { .name = "ICIALLU", .cp = 15, .opc1 = 0, .crn = 7, .crm = 5, .opc2 = 0,
      .type = ARM_CP_NOP, .access = PL1_W },
    { .name = "ICIMVAU", .cp = 15, .opc1 = 0, .crn = 7, .crm = 5, .opc2 = 1,
      .type = ARM_CP_NOP, .access = PL1_W },
    { .name = "BPIALL", .cp = 15, .opc1 = 0, .crn = 7, .crm = 5, .opc2 = 6,
      .type = ARM_CP_NOP, .access = PL1_W },
    { .name = "BPIMVA", .cp = 15, .opc1 = 0, .crn = 7, .crm = 5, .opc2 = 7,
      .type = ARM_CP_NOP, .access = PL1_W },
    { .name = "DCIMVAC", .cp = 15, .opc1 = 0, .crn = 7, .crm = 6, .opc2 = 1,
      .type = ARM_CP_NOP, .access = PL1_W },
    { .name = "DCISW", .cp = 15, .opc1 = 0, .crn = 7, .crm = 6, .opc2 = 2,
      .type = ARM_CP_NOP, .access = PL1_W },
    { .name = "DCCMVAC", .cp = 15, .opc1 = 0, .crn = 7, .crm = 10, .opc2 = 1,
      .type = ARM_CP_NOP, .access = PL1_W },
    { .name = "DCCSW", .cp = 15, .opc1 = 0, .crn = 7, .crm = 10, .opc2 = 2,
      .type = ARM_CP_NOP, .access = PL1_W },
    { .name = "DCCMVAU", .cp = 15, .opc1 = 0, .crn = 7, .crm = 11, .opc2 = 1,
      .type = ARM_CP_NOP, .access = PL1_W },
    { .name = "DCCIMVAC", .cp = 15, .opc1 = 0, .crn = 7, .crm = 14, .opc2 = 1,
      .type = ARM_CP_NOP, .access = PL1_W },
    { .name = "DCCISW", .cp = 15, .opc1 = 0, .crn = 7, .crm = 14, .opc2 = 2,
      .type = ARM_CP_NOP, .access = PL1_W },
    /* MMU Domain access control / MPU write buffer control */
    { .name = "DACR", .cp = 15, .opc1 = 0, .crn = 3, .crm = 0, .opc2 = 0,
      .access = PL1_RW, .resetvalue = 0,
      .writefn = dacr_write, .raw_writefn = raw_write,
      .bank_fieldoffsets = { offsetoflow32(CPUARMState, cp15.dacr_s),
                             offsetoflow32(CPUARMState, cp15.dacr_ns) } },
    { .name = "ELR_EL1", .state = ARM_CP_STATE_AA64,
      .type = ARM_CP_ALIAS,
      .opc0 = 3, .opc1 = 0, .crn = 4, .crm = 0, .opc2 = 1,
      .access = PL1_RW,
      .fieldoffset = offsetof(CPUARMState, elr_el[1]) },
    { .name = "SPSR_EL1", .state = ARM_CP_STATE_AA64,
      .type = ARM_CP_ALIAS,
      .opc0 = 3, .opc1 = 0, .crn = 4, .crm = 0, .opc2 = 0,
      .access = PL1_RW,
      .fieldoffset = offsetof(CPUARMState, banked_spsr[BANK_SVC]) },
    /* We rely on the access checks not allowing the guest to write to the
     * state field when SPSel indicates that it's being used as the stack
     * pointer.
     */
    { .name = "SP_EL0", .state = ARM_CP_STATE_AA64,
      .opc0 = 3, .opc1 = 0, .crn = 4, .crm = 1, .opc2 = 0,
      .access = PL1_RW, .accessfn = sp_el0_access,
      .type = ARM_CP_ALIAS,
      .fieldoffset = offsetof(CPUARMState, sp_el[0]) },
    { .name = "SP_EL1", .state = ARM_CP_STATE_AA64,
      .opc0 = 3, .opc1 = 4, .crn = 4, .crm = 1, .opc2 = 0,
      .access = PL2_RW, .type = ARM_CP_ALIAS,
      .fieldoffset = offsetof(CPUARMState, sp_el[1]) },
    { .name = "SPSel", .state = ARM_CP_STATE_AA64,
      .opc0 = 3, .opc1 = 0, .crn = 4, .crm = 2, .opc2 = 0,
      .type = ARM_CP_NO_RAW,
      .access = PL1_RW, .readfn = spsel_read, .writefn = spsel_write },
    { .name = "FPEXC32_EL2", .state = ARM_CP_STATE_AA64,
      .opc0 = 3, .opc1 = 4, .crn = 5, .crm = 3, .opc2 = 0,
      .type = ARM_CP_ALIAS,
      .fieldoffset = offsetof(CPUARMState, vfp.xregs[ARM_VFP_FPEXC]),
      .access = PL2_RW, .accessfn = fpexc32_access },
    { .name = "DACR32_EL2", .state = ARM_CP_STATE_AA64,
      .opc0 = 3, .opc1 = 4, .crn = 3, .crm = 0, .opc2 = 0,
      .access = PL2_RW, .resetvalue = 0,
      .writefn = dacr_write, .raw_writefn = raw_write,
      .fieldoffset = offsetof(CPUARMState, cp15.dacr32_el2) },
    { .name = "IFSR32_EL2", .state = ARM_CP_STATE_AA64,
      .opc0 = 3, .opc1 = 4, .crn = 5, .crm = 0, .opc2 = 1,
      .access = PL2_RW, .resetvalue = 0,
      .fieldoffset = offsetof(CPUARMState, cp15.ifsr32_el2) },
    { .name = "SPSR_IRQ", .state = ARM_CP_STATE_AA64,
      .type = ARM_CP_ALIAS,
      .opc0 = 3, .opc1 = 4, .crn = 4, .crm = 3, .opc2 = 0,
      .access = PL2_RW,
      .fieldoffset = offsetof(CPUARMState, banked_spsr[BANK_IRQ]) },
    { .name = "SPSR_ABT", .state = ARM_CP_STATE_AA64,
      .type = ARM_CP_ALIAS,
      .opc0 = 3, .opc1 = 4, .crn = 4, .crm = 3, .opc2 = 1,
      .access = PL2_RW,
      .fieldoffset = offsetof(CPUARMState, banked_spsr[BANK_ABT]) },
    { .name = "SPSR_UND", .state = ARM_CP_STATE_AA64,
      .type = ARM_CP_ALIAS,
      .opc0 = 3, .opc1 = 4, .crn = 4, .crm = 3, .opc2 = 2,
      .access = PL2_RW,
      .fieldoffset = offsetof(CPUARMState, banked_spsr[BANK_UND]) },
    { .name = "SPSR_FIQ", .state = ARM_CP_STATE_AA64,
      .type = ARM_CP_ALIAS,
      .opc0 = 3, .opc1 = 4, .crn = 4, .crm = 3, .opc2 = 3,
      .access = PL2_RW,
      .fieldoffset = offsetof(CPUARMState, banked_spsr[BANK_FIQ]) },
    { .name = "MDCR_EL3", .state = ARM_CP_STATE_AA64,
      .opc0 = 3, .opc1 = 6, .crn = 1, .crm = 3, .opc2 = 1,
      .resetvalue = 0,
      .access = PL3_RW, .fieldoffset = offsetof(CPUARMState, cp15.mdcr_el3) },
    { .name = "SDCR", .type = ARM_CP_ALIAS,
      .cp = 15, .opc1 = 0, .crn = 1, .crm = 3, .opc2 = 1,
      .access = PL1_RW, .accessfn = access_trap_aa32s_el1,
      .writefn = sdcr_write,
      .fieldoffset = offsetoflow32(CPUARMState, cp15.mdcr_el3) },
    REGINFO_SENTINEL
};

/* Used to describe the behaviour of EL2 regs when EL2 does not exist.  */
static const ARMCPRegInfo el3_no_el2_cp_reginfo[] = {
    { .name = "VBAR_EL2", .state = ARM_CP_STATE_AA64,
      .opc0 = 3, .opc1 = 4, .crn = 12, .crm = 0, .opc2 = 0,
      .access = PL2_RW,
      .readfn = arm_cp_read_zero, .writefn = arm_cp_write_ignore },
    { .name = "HCR_EL2", .state = ARM_CP_STATE_AA64,
      .type = ARM_CP_NO_RAW,
      .opc0 = 3, .opc1 = 4, .crn = 1, .crm = 1, .opc2 = 0,
      .access = PL2_RW,
      .readfn = arm_cp_read_zero, .writefn = arm_cp_write_ignore },
    { .name = "CPTR_EL2", .state = ARM_CP_STATE_BOTH,
      .opc0 = 3, .opc1 = 4, .crn = 1, .crm = 1, .opc2 = 2,
      .access = PL2_RW, .type = ARM_CP_CONST, .resetvalue = 0 },
    { .name = "MAIR_EL2", .state = ARM_CP_STATE_BOTH,
      .opc0 = 3, .opc1 = 4, .crn = 10, .crm = 2, .opc2 = 0,
      .access = PL2_RW, .type = ARM_CP_CONST,
      .resetvalue = 0 },
    { .name = "HMAIR1", .state = ARM_CP_STATE_AA32,
      .opc1 = 4, .crn = 10, .crm = 2, .opc2 = 1,
      .access = PL2_RW, .type = ARM_CP_CONST, .resetvalue = 0 },
    { .name = "AMAIR_EL2", .state = ARM_CP_STATE_BOTH,
      .opc0 = 3, .opc1 = 4, .crn = 10, .crm = 3, .opc2 = 0,
      .access = PL2_RW, .type = ARM_CP_CONST,
      .resetvalue = 0 },
    { .name = "HMAIR1", .state = ARM_CP_STATE_AA32,
      .opc1 = 4, .crn = 10, .crm = 3, .opc2 = 1,
      .access = PL2_RW, .type = ARM_CP_CONST,
      .resetvalue = 0 },
    { .name = "AFSR0_EL2", .state = ARM_CP_STATE_BOTH,
      .opc0 = 3, .opc1 = 4, .crn = 5, .crm = 1, .opc2 = 0,
      .access = PL2_RW, .type = ARM_CP_CONST,
      .resetvalue = 0 },
    { .name = "AFSR1_EL2", .state = ARM_CP_STATE_BOTH,
      .opc0 = 3, .opc1 = 4, .crn = 5, .crm = 1, .opc2 = 1,
      .access = PL2_RW, .type = ARM_CP_CONST,
      .resetvalue = 0 },
    { .name = "TCR_EL2", .state = ARM_CP_STATE_BOTH,
      .opc0 = 3, .opc1 = 4, .crn = 2, .crm = 0, .opc2 = 2,
      .access = PL2_RW, .type = ARM_CP_CONST, .resetvalue = 0 },
    { .name = "VTCR_EL2", .state = ARM_CP_STATE_BOTH,
      .opc0 = 3, .opc1 = 4, .crn = 2, .crm = 1, .opc2 = 2,
      .access = PL2_RW, .accessfn = access_el3_aa32ns_aa64any,
      .type = ARM_CP_CONST, .resetvalue = 0 },
    { .name = "VTTBR", .state = ARM_CP_STATE_AA32,
      .cp = 15, .opc1 = 6, .crm = 2,
      .access = PL2_RW, .accessfn = access_el3_aa32ns,
      .type = ARM_CP_CONST | ARM_CP_64BIT, .resetvalue = 0 },
    { .name = "VTTBR_EL2", .state = ARM_CP_STATE_AA64,
      .opc0 = 3, .opc1 = 4, .crn = 2, .crm = 1, .opc2 = 0,
      .access = PL2_RW, .type = ARM_CP_CONST, .resetvalue = 0 },
    { .name = "SCTLR_EL2", .state = ARM_CP_STATE_BOTH,
      .opc0 = 3, .opc1 = 4, .crn = 1, .crm = 0, .opc2 = 0,
      .access = PL2_RW, .type = ARM_CP_CONST, .resetvalue = 0 },
    { .name = "TPIDR_EL2", .state = ARM_CP_STATE_BOTH,
      .opc0 = 3, .opc1 = 4, .crn = 13, .crm = 0, .opc2 = 2,
      .access = PL2_RW, .type = ARM_CP_CONST, .resetvalue = 0 },
    { .name = "TTBR0_EL2", .state = ARM_CP_STATE_AA64,
      .opc0 = 3, .opc1 = 4, .crn = 2, .crm = 0, .opc2 = 0,
      .access = PL2_RW, .type = ARM_CP_CONST, .resetvalue = 0 },
    { .name = "HTTBR", .cp = 15, .opc1 = 4, .crm = 2,
      .access = PL2_RW, .type = ARM_CP_64BIT | ARM_CP_CONST,
      .resetvalue = 0 },
    { .name = "CNTHCTL_EL2", .state = ARM_CP_STATE_BOTH,
      .opc0 = 3, .opc1 = 4, .crn = 14, .crm = 1, .opc2 = 0,
      .access = PL2_RW, .type = ARM_CP_CONST, .resetvalue = 0 },
    { .name = "CNTVOFF_EL2", .state = ARM_CP_STATE_AA64,
      .opc0 = 3, .opc1 = 4, .crn = 14, .crm = 0, .opc2 = 3,
      .access = PL2_RW, .type = ARM_CP_CONST, .resetvalue = 0 },
    { .name = "CNTVOFF", .cp = 15, .opc1 = 4, .crm = 14,
      .access = PL2_RW, .type = ARM_CP_64BIT | ARM_CP_CONST,
      .resetvalue = 0 },
    { .name = "CNTHP_CVAL_EL2", .state = ARM_CP_STATE_AA64,
      .opc0 = 3, .opc1 = 4, .crn = 14, .crm = 2, .opc2 = 2,
      .access = PL2_RW, .type = ARM_CP_CONST, .resetvalue = 0 },
    { .name = "CNTHP_CVAL", .cp = 15, .opc1 = 6, .crm = 14,
      .access = PL2_RW, .type = ARM_CP_64BIT | ARM_CP_CONST,
      .resetvalue = 0 },
    { .name = "CNTHP_TVAL_EL2", .state = ARM_CP_STATE_BOTH,
      .opc0 = 3, .opc1 = 4, .crn = 14, .crm = 2, .opc2 = 0,
      .access = PL2_RW, .type = ARM_CP_CONST, .resetvalue = 0 },
    { .name = "CNTHP_CTL_EL2", .state = ARM_CP_STATE_BOTH,
      .opc0 = 3, .opc1 = 4, .crn = 14, .crm = 2, .opc2 = 1,
      .access = PL2_RW, .type = ARM_CP_CONST, .resetvalue = 0 },
    { .name = "MDCR_EL2", .state = ARM_CP_STATE_BOTH,
      .opc0 = 3, .opc1 = 4, .crn = 1, .crm = 1, .opc2 = 1,
      .access = PL2_RW, .accessfn = access_tda,
      .type = ARM_CP_CONST, .resetvalue = 0 },
    { .name = "HPFAR_EL2", .state = ARM_CP_STATE_BOTH,
      .opc0 = 3, .opc1 = 4, .crn = 6, .crm = 0, .opc2 = 4,
      .access = PL2_RW, .accessfn = access_el3_aa32ns_aa64any,
      .type = ARM_CP_CONST, .resetvalue = 0 },
    { .name = "HSTR_EL2", .state = ARM_CP_STATE_BOTH,
      .opc0 = 3, .opc1 = 4, .crn = 1, .crm = 1, .opc2 = 3,
      .access = PL2_RW, .type = ARM_CP_CONST, .resetvalue = 0 },
    REGINFO_SENTINEL
};

static void hcr_write(CPUARMState *env, const ARMCPRegInfo *ri, uint64_t value)
{
    ARMCPU *cpu = arm_env_get_cpu(env);
    uint64_t valid_mask = HCR_MASK;

    if (arm_feature(env, ARM_FEATURE_EL3)) {
        valid_mask &= ~HCR_HCD;
    } else {
        valid_mask &= ~HCR_TSC;
    }

    /* Clear RES0 bits.  */
    value &= valid_mask;

    /* These bits change the MMU setup:
     * HCR_VM enables stage 2 translation
     * HCR_PTW forbids certain page-table setups
     * HCR_DC Disables stage1 and enables stage2 translation
     */
    if ((raw_read(env, ri) ^ value) & (HCR_VM | HCR_PTW | HCR_DC)) {
        tlb_flush(CPU(cpu));
    }
    raw_write(env, ri, value);
}

static const ARMCPRegInfo el2_cp_reginfo[] = {
    { .name = "HCR_EL2", .state = ARM_CP_STATE_AA64,
      .opc0 = 3, .opc1 = 4, .crn = 1, .crm = 1, .opc2 = 0,
      .access = PL2_RW, .fieldoffset = offsetof(CPUARMState, cp15.hcr_el2),
      .writefn = hcr_write },
    { .name = "ELR_EL2", .state = ARM_CP_STATE_AA64,
      .type = ARM_CP_ALIAS,
      .opc0 = 3, .opc1 = 4, .crn = 4, .crm = 0, .opc2 = 1,
      .access = PL2_RW,
      .fieldoffset = offsetof(CPUARMState, elr_el[2]) },
    { .name = "ESR_EL2", .state = ARM_CP_STATE_AA64,
      .opc0 = 3, .opc1 = 4, .crn = 5, .crm = 2, .opc2 = 0,
      .access = PL2_RW, .fieldoffset = offsetof(CPUARMState, cp15.esr_el[2]) },
    { .name = "FAR_EL2", .state = ARM_CP_STATE_AA64,
      .opc0 = 3, .opc1 = 4, .crn = 6, .crm = 0, .opc2 = 0,
      .access = PL2_RW, .fieldoffset = offsetof(CPUARMState, cp15.far_el[2]) },
    { .name = "SPSR_EL2", .state = ARM_CP_STATE_AA64,
      .type = ARM_CP_ALIAS,
      .opc0 = 3, .opc1 = 4, .crn = 4, .crm = 0, .opc2 = 0,
      .access = PL2_RW,
      .fieldoffset = offsetof(CPUARMState, banked_spsr[BANK_HYP]) },
    { .name = "VBAR_EL2", .state = ARM_CP_STATE_AA64,
      .opc0 = 3, .opc1 = 4, .crn = 12, .crm = 0, .opc2 = 0,
      .access = PL2_RW, .writefn = vbar_write,
      .fieldoffset = offsetof(CPUARMState, cp15.vbar_el[2]),
      .resetvalue = 0 },
    { .name = "SP_EL2", .state = ARM_CP_STATE_AA64,
      .opc0 = 3, .opc1 = 6, .crn = 4, .crm = 1, .opc2 = 0,
      .access = PL3_RW, .type = ARM_CP_ALIAS,
      .fieldoffset = offsetof(CPUARMState, sp_el[2]) },
    { .name = "CPTR_EL2", .state = ARM_CP_STATE_BOTH,
      .opc0 = 3, .opc1 = 4, .crn = 1, .crm = 1, .opc2 = 2,
      .access = PL2_RW, .accessfn = cptr_access, .resetvalue = 0,
      .fieldoffset = offsetof(CPUARMState, cp15.cptr_el[2]) },
    { .name = "MAIR_EL2", .state = ARM_CP_STATE_BOTH,
      .opc0 = 3, .opc1 = 4, .crn = 10, .crm = 2, .opc2 = 0,
      .access = PL2_RW, .fieldoffset = offsetof(CPUARMState, cp15.mair_el[2]),
      .resetvalue = 0 },
    { .name = "HMAIR1", .state = ARM_CP_STATE_AA32,
      .opc1 = 4, .crn = 10, .crm = 2, .opc2 = 1,
      .access = PL2_RW, .type = ARM_CP_ALIAS,
      .fieldoffset = offsetofhigh32(CPUARMState, cp15.mair_el[2]) },
    { .name = "AMAIR_EL2", .state = ARM_CP_STATE_BOTH,
      .opc0 = 3, .opc1 = 4, .crn = 10, .crm = 3, .opc2 = 0,
      .access = PL2_RW, .type = ARM_CP_CONST,
      .resetvalue = 0 },
    /* HAMAIR1 is mapped to AMAIR_EL2[63:32] */
    { .name = "HMAIR1", .state = ARM_CP_STATE_AA32,
      .opc1 = 4, .crn = 10, .crm = 3, .opc2 = 1,
      .access = PL2_RW, .type = ARM_CP_CONST,
      .resetvalue = 0 },
    { .name = "AFSR0_EL2", .state = ARM_CP_STATE_BOTH,
      .opc0 = 3, .opc1 = 4, .crn = 5, .crm = 1, .opc2 = 0,
      .access = PL2_RW, .type = ARM_CP_CONST,
      .resetvalue = 0 },
    { .name = "AFSR1_EL2", .state = ARM_CP_STATE_BOTH,
      .opc0 = 3, .opc1 = 4, .crn = 5, .crm = 1, .opc2 = 1,
      .access = PL2_RW, .type = ARM_CP_CONST,
      .resetvalue = 0 },
    { .name = "TCR_EL2", .state = ARM_CP_STATE_BOTH,
      .opc0 = 3, .opc1 = 4, .crn = 2, .crm = 0, .opc2 = 2,
      .access = PL2_RW,
      /* no .writefn needed as this can't cause an ASID change;
       * no .raw_writefn or .resetfn needed as we never use mask/base_mask
       */
      .fieldoffset = offsetof(CPUARMState, cp15.tcr_el[2]) },
    { .name = "VTCR", .state = ARM_CP_STATE_AA32,
      .cp = 15, .opc1 = 4, .crn = 2, .crm = 1, .opc2 = 2,
      .type = ARM_CP_ALIAS,
      .access = PL2_RW, .accessfn = access_el3_aa32ns,
      .fieldoffset = offsetof(CPUARMState, cp15.vtcr_el2) },
    { .name = "VTCR_EL2", .state = ARM_CP_STATE_AA64,
      .opc0 = 3, .opc1 = 4, .crn = 2, .crm = 1, .opc2 = 2,
      .access = PL2_RW,
      /* no .writefn needed as this can't cause an ASID change;
       * no .raw_writefn or .resetfn needed as we never use mask/base_mask
       */
      .fieldoffset = offsetof(CPUARMState, cp15.vtcr_el2) },
    { .name = "VTTBR", .state = ARM_CP_STATE_AA32,
      .cp = 15, .opc1 = 6, .crm = 2,
      .type = ARM_CP_64BIT | ARM_CP_ALIAS,
      .access = PL2_RW, .accessfn = access_el3_aa32ns,
      .fieldoffset = offsetof(CPUARMState, cp15.vttbr_el2),
      .writefn = vttbr_write },
    { .name = "VTTBR_EL2", .state = ARM_CP_STATE_AA64,
      .opc0 = 3, .opc1 = 4, .crn = 2, .crm = 1, .opc2 = 0,
      .access = PL2_RW, .writefn = vttbr_write,
      .fieldoffset = offsetof(CPUARMState, cp15.vttbr_el2) },
    { .name = "SCTLR_EL2", .state = ARM_CP_STATE_BOTH,
      .opc0 = 3, .opc1 = 4, .crn = 1, .crm = 0, .opc2 = 0,
      .access = PL2_RW, .raw_writefn = raw_write, .writefn = sctlr_write,
      .fieldoffset = offsetof(CPUARMState, cp15.sctlr_el[2]) },
    { .name = "TPIDR_EL2", .state = ARM_CP_STATE_BOTH,
      .opc0 = 3, .opc1 = 4, .crn = 13, .crm = 0, .opc2 = 2,
      .access = PL2_RW, .resetvalue = 0,
      .fieldoffset = offsetof(CPUARMState, cp15.tpidr_el[2]) },
    { .name = "TTBR0_EL2", .state = ARM_CP_STATE_AA64,
      .opc0 = 3, .opc1 = 4, .crn = 2, .crm = 0, .opc2 = 0,
      .access = PL2_RW, .resetvalue = 0,
      .fieldoffset = offsetof(CPUARMState, cp15.ttbr0_el[2]) },
    { .name = "HTTBR", .cp = 15, .opc1 = 4, .crm = 2,
      .access = PL2_RW, .type = ARM_CP_64BIT | ARM_CP_ALIAS,
      .fieldoffset = offsetof(CPUARMState, cp15.ttbr0_el[2]) },
    { .name = "TLBIALLNSNH",
      .cp = 15, .opc1 = 4, .crn = 8, .crm = 7, .opc2 = 4,
      .type = ARM_CP_NO_RAW, .access = PL2_W,
      .writefn = tlbiall_nsnh_write },
    { .name = "TLBIALLNSNHIS",
      .cp = 15, .opc1 = 4, .crn = 8, .crm = 3, .opc2 = 4,
      .type = ARM_CP_NO_RAW, .access = PL2_W,
      .writefn = tlbiall_nsnh_is_write },
    { .name = "TLBIALLH", .cp = 15, .opc1 = 4, .crn = 8, .crm = 7, .opc2 = 0,
      .type = ARM_CP_NO_RAW, .access = PL2_W,
      .writefn = tlbiall_hyp_write },
    { .name = "TLBIALLHIS", .cp = 15, .opc1 = 4, .crn = 8, .crm = 3, .opc2 = 0,
      .type = ARM_CP_NO_RAW, .access = PL2_W,
      .writefn = tlbiall_hyp_is_write },
    { .name = "TLBIMVAH", .cp = 15, .opc1 = 4, .crn = 8, .crm = 7, .opc2 = 1,
      .type = ARM_CP_NO_RAW, .access = PL2_W,
      .writefn = tlbimva_hyp_write },
    { .name = "TLBIMVAHIS", .cp = 15, .opc1 = 4, .crn = 8, .crm = 3, .opc2 = 1,
      .type = ARM_CP_NO_RAW, .access = PL2_W,
      .writefn = tlbimva_hyp_is_write },
    { .name = "TLBI_ALLE2", .state = ARM_CP_STATE_AA64,
      .opc0 = 1, .opc1 = 4, .crn = 8, .crm = 7, .opc2 = 0,
      .type = ARM_CP_NO_RAW, .access = PL2_W,
      .writefn = tlbi_aa64_alle2_write },
    { .name = "TLBI_VAE2", .state = ARM_CP_STATE_AA64,
      .opc0 = 1, .opc1 = 4, .crn = 8, .crm = 7, .opc2 = 1,
      .type = ARM_CP_NO_RAW, .access = PL2_W,
      .writefn = tlbi_aa64_vae2_write },
    { .name = "TLBI_VALE2", .state = ARM_CP_STATE_AA64,
      .opc0 = 1, .opc1 = 4, .crn = 8, .crm = 7, .opc2 = 5,
      .access = PL2_W, .type = ARM_CP_NO_RAW,
      .writefn = tlbi_aa64_vae2_write },
    { .name = "TLBI_ALLE2IS", .state = ARM_CP_STATE_AA64,
      .opc0 = 1, .opc1 = 4, .crn = 8, .crm = 3, .opc2 = 0,
      .access = PL2_W, .type = ARM_CP_NO_RAW,
      .writefn = tlbi_aa64_alle2is_write },
    { .name = "TLBI_VAE2IS", .state = ARM_CP_STATE_AA64,
      .opc0 = 1, .opc1 = 4, .crn = 8, .crm = 3, .opc2 = 1,
      .type = ARM_CP_NO_RAW, .access = PL2_W,
      .writefn = tlbi_aa64_vae2is_write },
    { .name = "TLBI_VALE2IS", .state = ARM_CP_STATE_AA64,
      .opc0 = 1, .opc1 = 4, .crn = 8, .crm = 3, .opc2 = 5,
      .access = PL2_W, .type = ARM_CP_NO_RAW,
      .writefn = tlbi_aa64_vae2is_write },
#ifndef CONFIG_USER_ONLY
    /* Unlike the other EL2-related AT operations, these must
     * UNDEF from EL3 if EL2 is not implemented, which is why we
     * define them here rather than with the rest of the AT ops.
     */
    { .name = "AT_S1E2R", .state = ARM_CP_STATE_AA64,
      .opc0 = 1, .opc1 = 4, .crn = 7, .crm = 8, .opc2 = 0,
      .access = PL2_W, .accessfn = at_s1e2_access,
      .type = ARM_CP_NO_RAW, .writefn = ats_write64 },
    { .name = "AT_S1E2W", .state = ARM_CP_STATE_AA64,
      .opc0 = 1, .opc1 = 4, .crn = 7, .crm = 8, .opc2 = 1,
      .access = PL2_W, .accessfn = at_s1e2_access,
      .type = ARM_CP_NO_RAW, .writefn = ats_write64 },
    /* The AArch32 ATS1H* operations are CONSTRAINED UNPREDICTABLE
     * if EL2 is not implemented; we choose to UNDEF. Behaviour at EL3
     * with SCR.NS == 0 outside Monitor mode is UNPREDICTABLE; we choose
     * to behave as if SCR.NS was 1.
     */
    { .name = "ATS1HR", .cp = 15, .opc1 = 4, .crn = 7, .crm = 8, .opc2 = 0,
      .access = PL2_W,
      .writefn = ats1h_write, .type = ARM_CP_NO_RAW },
    { .name = "ATS1HW", .cp = 15, .opc1 = 4, .crn = 7, .crm = 8, .opc2 = 1,
      .access = PL2_W,
      .writefn = ats1h_write, .type = ARM_CP_NO_RAW },
    { .name = "CNTHCTL_EL2", .state = ARM_CP_STATE_BOTH,
      .opc0 = 3, .opc1 = 4, .crn = 14, .crm = 1, .opc2 = 0,
      /* ARMv7 requires bit 0 and 1 to reset to 1. ARMv8 defines the
       * reset values as IMPDEF. We choose to reset to 3 to comply with
       * both ARMv7 and ARMv8.
       */
      .access = PL2_RW, .resetvalue = 3,
      .fieldoffset = offsetof(CPUARMState, cp15.cnthctl_el2) },
    { .name = "CNTVOFF_EL2", .state = ARM_CP_STATE_AA64,
      .opc0 = 3, .opc1 = 4, .crn = 14, .crm = 0, .opc2 = 3,
      .access = PL2_RW, .type = ARM_CP_IO, .resetvalue = 0,
      .writefn = gt_cntvoff_write,
      .fieldoffset = offsetof(CPUARMState, cp15.cntvoff_el2) },
    { .name = "CNTVOFF", .cp = 15, .opc1 = 4, .crm = 14,
      .access = PL2_RW, .type = ARM_CP_64BIT | ARM_CP_ALIAS | ARM_CP_IO,
      .writefn = gt_cntvoff_write,
      .fieldoffset = offsetof(CPUARMState, cp15.cntvoff_el2) },
    { .name = "CNTHP_CVAL_EL2", .state = ARM_CP_STATE_AA64,
      .opc0 = 3, .opc1 = 4, .crn = 14, .crm = 2, .opc2 = 2,
      .fieldoffset = offsetof(CPUARMState, cp15.c14_timer[GTIMER_HYP].cval),
      .type = ARM_CP_IO, .access = PL2_RW,
      .writefn = gt_hyp_cval_write, .raw_writefn = raw_write },
    { .name = "CNTHP_CVAL", .cp = 15, .opc1 = 6, .crm = 14,
      .fieldoffset = offsetof(CPUARMState, cp15.c14_timer[GTIMER_HYP].cval),
      .access = PL2_RW, .type = ARM_CP_64BIT | ARM_CP_IO,
      .writefn = gt_hyp_cval_write, .raw_writefn = raw_write },
    { .name = "CNTHP_TVAL_EL2", .state = ARM_CP_STATE_BOTH,
      .opc0 = 3, .opc1 = 4, .crn = 14, .crm = 2, .opc2 = 0,
      .type = ARM_CP_NO_RAW | ARM_CP_IO, .access = PL2_RW,
      .resetfn = gt_hyp_timer_reset,
      .readfn = gt_hyp_tval_read, .writefn = gt_hyp_tval_write },
    { .name = "CNTHP_CTL_EL2", .state = ARM_CP_STATE_BOTH,
      .type = ARM_CP_IO,
      .opc0 = 3, .opc1 = 4, .crn = 14, .crm = 2, .opc2 = 1,
      .access = PL2_RW,
      .fieldoffset = offsetof(CPUARMState, cp15.c14_timer[GTIMER_HYP].ctl),
      .resetvalue = 0,
      .writefn = gt_hyp_ctl_write, .raw_writefn = raw_write },
#endif
    /* The only field of MDCR_EL2 that has a defined architectural reset value
     * is MDCR_EL2.HPMN which should reset to the value of PMCR_EL0.N; but we
     * don't impelment any PMU event counters, so using zero as a reset
     * value for MDCR_EL2 is okay
     */
    { .name = "MDCR_EL2", .state = ARM_CP_STATE_BOTH,
      .opc0 = 3, .opc1 = 4, .crn = 1, .crm = 1, .opc2 = 1,
      .access = PL2_RW, .resetvalue = 0,
      .fieldoffset = offsetof(CPUARMState, cp15.mdcr_el2), },
    { .name = "HPFAR", .state = ARM_CP_STATE_AA32,
      .cp = 15, .opc1 = 4, .crn = 6, .crm = 0, .opc2 = 4,
      .access = PL2_RW, .accessfn = access_el3_aa32ns,
      .fieldoffset = offsetof(CPUARMState, cp15.hpfar_el2) },
    { .name = "HPFAR_EL2", .state = ARM_CP_STATE_AA64,
      .opc0 = 3, .opc1 = 4, .crn = 6, .crm = 0, .opc2 = 4,
      .access = PL2_RW,
      .fieldoffset = offsetof(CPUARMState, cp15.hpfar_el2) },
    { .name = "HSTR_EL2", .state = ARM_CP_STATE_BOTH,
      .cp = 15, .opc0 = 3, .opc1 = 4, .crn = 1, .crm = 1, .opc2 = 3,
      .access = PL2_RW,
      .fieldoffset = offsetof(CPUARMState, cp15.hstr_el2) },
    REGINFO_SENTINEL
};

static CPAccessResult nsacr_access(CPUARMState *env, const ARMCPRegInfo *ri,
                                   bool isread)
{
    /* The NSACR is RW at EL3, and RO for NS EL1 and NS EL2.
     * At Secure EL1 it traps to EL3.
     */
    if (arm_current_el(env) == 3) {
        return CP_ACCESS_OK;
    }
    if (arm_is_secure_below_el3(env)) {
        return CP_ACCESS_TRAP_EL3;
    }
    /* Accesses from EL1 NS and EL2 NS are UNDEF for write but allow reads. */
    if (isread) {
        return CP_ACCESS_OK;
    }
    return CP_ACCESS_TRAP_UNCATEGORIZED;
}

static const ARMCPRegInfo el3_cp_reginfo[] = {
    { .name = "SCR_EL3", .state = ARM_CP_STATE_AA64,
      .opc0 = 3, .opc1 = 6, .crn = 1, .crm = 1, .opc2 = 0,
      .access = PL3_RW, .fieldoffset = offsetof(CPUARMState, cp15.scr_el3),
      .resetvalue = 0, .writefn = scr_write },
    { .name = "SCR",  .type = ARM_CP_ALIAS,
      .cp = 15, .opc1 = 0, .crn = 1, .crm = 1, .opc2 = 0,
      .access = PL1_RW, .accessfn = access_trap_aa32s_el1,
      .fieldoffset = offsetoflow32(CPUARMState, cp15.scr_el3),
      .writefn = scr_write },
    { .name = "SDER32_EL3", .state = ARM_CP_STATE_AA64,
      .opc0 = 3, .opc1 = 6, .crn = 1, .crm = 1, .opc2 = 1,
      .access = PL3_RW, .resetvalue = 0,
      .fieldoffset = offsetof(CPUARMState, cp15.sder) },
    { .name = "SDER",
      .cp = 15, .opc1 = 0, .crn = 1, .crm = 1, .opc2 = 1,
      .access = PL3_RW, .resetvalue = 0,
      .fieldoffset = offsetoflow32(CPUARMState, cp15.sder) },
    { .name = "MVBAR", .cp = 15, .opc1 = 0, .crn = 12, .crm = 0, .opc2 = 1,
      .access = PL1_RW, .accessfn = access_trap_aa32s_el1,
      .writefn = vbar_write, .resetvalue = 0,
      .fieldoffset = offsetof(CPUARMState, cp15.mvbar) },
    { .name = "TTBR0_EL3", .state = ARM_CP_STATE_AA64,
      .opc0 = 3, .opc1 = 6, .crn = 2, .crm = 0, .opc2 = 0,
      .access = PL3_RW, .writefn = vmsa_ttbr_write, .resetvalue = 0,
      .fieldoffset = offsetof(CPUARMState, cp15.ttbr0_el[3]) },
    { .name = "TCR_EL3", .state = ARM_CP_STATE_AA64,
      .opc0 = 3, .opc1 = 6, .crn = 2, .crm = 0, .opc2 = 2,
      .access = PL3_RW,
      /* no .writefn needed as this can't cause an ASID change;
       * we must provide a .raw_writefn and .resetfn because we handle
       * reset and migration for the AArch32 TTBCR(S), which might be
       * using mask and base_mask.
       */
      .resetfn = vmsa_ttbcr_reset, .raw_writefn = vmsa_ttbcr_raw_write,
      .fieldoffset = offsetof(CPUARMState, cp15.tcr_el[3]) },
    { .name = "ELR_EL3", .state = ARM_CP_STATE_AA64,
      .type = ARM_CP_ALIAS,
      .opc0 = 3, .opc1 = 6, .crn = 4, .crm = 0, .opc2 = 1,
      .access = PL3_RW,
      .fieldoffset = offsetof(CPUARMState, elr_el[3]) },
    { .name = "ESR_EL3", .state = ARM_CP_STATE_AA64,
      .opc0 = 3, .opc1 = 6, .crn = 5, .crm = 2, .opc2 = 0,
      .access = PL3_RW, .fieldoffset = offsetof(CPUARMState, cp15.esr_el[3]) },
    { .name = "FAR_EL3", .state = ARM_CP_STATE_AA64,
      .opc0 = 3, .opc1 = 6, .crn = 6, .crm = 0, .opc2 = 0,
      .access = PL3_RW, .fieldoffset = offsetof(CPUARMState, cp15.far_el[3]) },
    { .name = "SPSR_EL3", .state = ARM_CP_STATE_AA64,
      .type = ARM_CP_ALIAS,
      .opc0 = 3, .opc1 = 6, .crn = 4, .crm = 0, .opc2 = 0,
      .access = PL3_RW,
      .fieldoffset = offsetof(CPUARMState, banked_spsr[BANK_MON]) },
    { .name = "VBAR_EL3", .state = ARM_CP_STATE_AA64,
      .opc0 = 3, .opc1 = 6, .crn = 12, .crm = 0, .opc2 = 0,
      .access = PL3_RW, .writefn = vbar_write,
      .fieldoffset = offsetof(CPUARMState, cp15.vbar_el[3]),
      .resetvalue = 0 },
    { .name = "CPTR_EL3", .state = ARM_CP_STATE_AA64,
      .opc0 = 3, .opc1 = 6, .crn = 1, .crm = 1, .opc2 = 2,
      .access = PL3_RW, .accessfn = cptr_access, .resetvalue = 0,
      .fieldoffset = offsetof(CPUARMState, cp15.cptr_el[3]) },
    { .name = "TPIDR_EL3", .state = ARM_CP_STATE_AA64,
      .opc0 = 3, .opc1 = 6, .crn = 13, .crm = 0, .opc2 = 2,
      .access = PL3_RW, .resetvalue = 0,
      .fieldoffset = offsetof(CPUARMState, cp15.tpidr_el[3]) },
    { .name = "AMAIR_EL3", .state = ARM_CP_STATE_AA64,
      .opc0 = 3, .opc1 = 6, .crn = 10, .crm = 3, .opc2 = 0,
      .access = PL3_RW, .type = ARM_CP_CONST,
      .resetvalue = 0 },
    { .name = "AFSR0_EL3", .state = ARM_CP_STATE_BOTH,
      .opc0 = 3, .opc1 = 6, .crn = 5, .crm = 1, .opc2 = 0,
      .access = PL3_RW, .type = ARM_CP_CONST,
      .resetvalue = 0 },
    { .name = "AFSR1_EL3", .state = ARM_CP_STATE_BOTH,
      .opc0 = 3, .opc1 = 6, .crn = 5, .crm = 1, .opc2 = 1,
      .access = PL3_RW, .type = ARM_CP_CONST,
      .resetvalue = 0 },
    { .name = "TLBI_ALLE3IS", .state = ARM_CP_STATE_AA64,
      .opc0 = 1, .opc1 = 6, .crn = 8, .crm = 3, .opc2 = 0,
      .access = PL3_W, .type = ARM_CP_NO_RAW,
      .writefn = tlbi_aa64_alle3is_write },
    { .name = "TLBI_VAE3IS", .state = ARM_CP_STATE_AA64,
      .opc0 = 1, .opc1 = 6, .crn = 8, .crm = 3, .opc2 = 1,
      .access = PL3_W, .type = ARM_CP_NO_RAW,
      .writefn = tlbi_aa64_vae3is_write },
    { .name = "TLBI_VALE3IS", .state = ARM_CP_STATE_AA64,
      .opc0 = 1, .opc1 = 6, .crn = 8, .crm = 3, .opc2 = 5,
      .access = PL3_W, .type = ARM_CP_NO_RAW,
      .writefn = tlbi_aa64_vae3is_write },
    { .name = "TLBI_ALLE3", .state = ARM_CP_STATE_AA64,
      .opc0 = 1, .opc1 = 6, .crn = 8, .crm = 7, .opc2 = 0,
      .access = PL3_W, .type = ARM_CP_NO_RAW,
      .writefn = tlbi_aa64_alle3_write },
    { .name = "TLBI_VAE3", .state = ARM_CP_STATE_AA64,
      .opc0 = 1, .opc1 = 6, .crn = 8, .crm = 7, .opc2 = 1,
      .access = PL3_W, .type = ARM_CP_NO_RAW,
      .writefn = tlbi_aa64_vae3_write },
    { .name = "TLBI_VALE3", .state = ARM_CP_STATE_AA64,
      .opc0 = 1, .opc1 = 6, .crn = 8, .crm = 7, .opc2 = 5,
      .access = PL3_W, .type = ARM_CP_NO_RAW,
      .writefn = tlbi_aa64_vae3_write },
    REGINFO_SENTINEL
};

static CPAccessResult ctr_el0_access(CPUARMState *env, const ARMCPRegInfo *ri,
                                     bool isread)
{
    /* Only accessible in EL0 if SCTLR.UCT is set (and only in AArch64,
     * but the AArch32 CTR has its own reginfo struct)
     */
    if (arm_current_el(env) == 0 && !(env->cp15.sctlr_el[1] & SCTLR_UCT)) {
        return CP_ACCESS_TRAP;
    }
    return CP_ACCESS_OK;
}

static void oslar_write(CPUARMState *env, const ARMCPRegInfo *ri,
                        uint64_t value)
{
    /* Writes to OSLAR_EL1 may update the OS lock status, which can be
     * read via a bit in OSLSR_EL1.
     */
    int oslock;

    if (ri->state == ARM_CP_STATE_AA32) {
        oslock = (value == 0xC5ACCE55);
    } else {
        oslock = value & 1;
    }

    env->cp15.oslsr_el1 = deposit32(env->cp15.oslsr_el1, 1, 1, oslock);
}

static const ARMCPRegInfo debug_cp_reginfo[] = {
    /* DBGDRAR, DBGDSAR: always RAZ since we don't implement memory mapped
     * debug components. The AArch64 version of DBGDRAR is named MDRAR_EL1;
     * unlike DBGDRAR it is never accessible from EL0.
     * DBGDSAR is deprecated and must RAZ from v8 anyway, so it has no AArch64
     * accessor.
     */
    { .name = "DBGDRAR", .cp = 14, .crn = 1, .crm = 0, .opc1 = 0, .opc2 = 0,
      .access = PL0_R, .accessfn = access_tdra,
      .type = ARM_CP_CONST, .resetvalue = 0 },
    { .name = "MDRAR_EL1", .state = ARM_CP_STATE_AA64,
      .opc0 = 2, .opc1 = 0, .crn = 1, .crm = 0, .opc2 = 0,
      .access = PL1_R, .accessfn = access_tdra,
      .type = ARM_CP_CONST, .resetvalue = 0 },
    { .name = "DBGDSAR", .cp = 14, .crn = 2, .crm = 0, .opc1 = 0, .opc2 = 0,
      .access = PL0_R, .accessfn = access_tdra,
      .type = ARM_CP_CONST, .resetvalue = 0 },
    /* Monitor debug system control register; the 32-bit alias is DBGDSCRext. */
    { .name = "MDSCR_EL1", .state = ARM_CP_STATE_BOTH,
      .cp = 14, .opc0 = 2, .opc1 = 0, .crn = 0, .crm = 2, .opc2 = 2,
      .access = PL1_RW, .accessfn = access_tda,
      .fieldoffset = offsetof(CPUARMState, cp15.mdscr_el1),
      .resetvalue = 0 },
    /* MDCCSR_EL0, aka DBGDSCRint. This is a read-only mirror of MDSCR_EL1.
     * We don't implement the configurable EL0 access.
     */
    { .name = "MDCCSR_EL0", .state = ARM_CP_STATE_BOTH,
      .cp = 14, .opc0 = 2, .opc1 = 0, .crn = 0, .crm = 1, .opc2 = 0,
      .type = ARM_CP_ALIAS,
      .access = PL1_R, .accessfn = access_tda,
      .fieldoffset = offsetof(CPUARMState, cp15.mdscr_el1), },
    { .name = "OSLAR_EL1", .state = ARM_CP_STATE_BOTH,
      .cp = 14, .opc0 = 2, .opc1 = 0, .crn = 1, .crm = 0, .opc2 = 4,
      .access = PL1_W, .type = ARM_CP_NO_RAW,
      .accessfn = access_tdosa,
      .writefn = oslar_write },
    { .name = "OSLSR_EL1", .state = ARM_CP_STATE_BOTH,
      .cp = 14, .opc0 = 2, .opc1 = 0, .crn = 1, .crm = 1, .opc2 = 4,
      .access = PL1_R, .resetvalue = 10,
      .accessfn = access_tdosa,
      .fieldoffset = offsetof(CPUARMState, cp15.oslsr_el1) },
    /* Dummy OSDLR_EL1: 32-bit Linux will read this */
    { .name = "OSDLR_EL1", .state = ARM_CP_STATE_BOTH,
      .cp = 14, .opc0 = 2, .opc1 = 0, .crn = 1, .crm = 3, .opc2 = 4,
      .access = PL1_RW, .accessfn = access_tdosa,
      .type = ARM_CP_NOP },
    /* Dummy DBGVCR: Linux wants to clear this on startup, but we don't
     * implement vector catch debug events yet.
     */
    { .name = "DBGVCR",
      .cp = 14, .opc1 = 0, .crn = 0, .crm = 7, .opc2 = 0,
      .access = PL1_RW, .accessfn = access_tda,
      .type = ARM_CP_NOP },
    /* Dummy DBGVCR32_EL2 (which is only for a 64-bit hypervisor
     * to save and restore a 32-bit guest's DBGVCR)
     */
    { .name = "DBGVCR32_EL2", .state = ARM_CP_STATE_AA64,
      .opc0 = 2, .opc1 = 4, .crn = 0, .crm = 7, .opc2 = 0,
      .access = PL2_RW, .accessfn = access_tda,
      .type = ARM_CP_NOP },
    /* Dummy MDCCINT_EL1, since we don't implement the Debug Communications
     * Channel but Linux may try to access this register. The 32-bit
     * alias is DBGDCCINT.
     */
    { .name = "MDCCINT_EL1", .state = ARM_CP_STATE_BOTH,
      .cp = 14, .opc0 = 2, .opc1 = 0, .crn = 0, .crm = 2, .opc2 = 0,
      .access = PL1_RW, .accessfn = access_tda,
      .type = ARM_CP_NOP },
    REGINFO_SENTINEL
};

static const ARMCPRegInfo debug_lpae_cp_reginfo[] = {
    /* 64 bit access versions of the (dummy) debug registers */
    { .name = "DBGDRAR", .cp = 14, .crm = 1, .opc1 = 0,
      .access = PL0_R, .type = ARM_CP_CONST|ARM_CP_64BIT, .resetvalue = 0 },
    { .name = "DBGDSAR", .cp = 14, .crm = 2, .opc1 = 0,
      .access = PL0_R, .type = ARM_CP_CONST|ARM_CP_64BIT, .resetvalue = 0 },
    REGINFO_SENTINEL
};

void hw_watchpoint_update(ARMCPU *cpu, int n)
{
    CPUARMState *env = &cpu->env;
    vaddr len = 0;
    vaddr wvr = env->cp15.dbgwvr[n];
    uint64_t wcr = env->cp15.dbgwcr[n];
    int mask;
    int flags = BP_CPU | BP_STOP_BEFORE_ACCESS;

    if (env->cpu_watchpoint[n]) {
        cpu_watchpoint_remove_by_ref(CPU(cpu), env->cpu_watchpoint[n]);
        env->cpu_watchpoint[n] = NULL;
    }

    if (!extract64(wcr, 0, 1)) {
        /* E bit clear : watchpoint disabled */
        return;
    }

    switch (extract64(wcr, 3, 2)) {
    case 0:
        /* LSC 00 is reserved and must behave as if the wp is disabled */
        return;
    case 1:
        flags |= BP_MEM_READ;
        break;
    case 2:
        flags |= BP_MEM_WRITE;
        break;
    case 3:
        flags |= BP_MEM_ACCESS;
        break;
    }

    /* Attempts to use both MASK and BAS fields simultaneously are
     * CONSTRAINED UNPREDICTABLE; we opt to ignore BAS in this case,
     * thus generating a watchpoint for every byte in the masked region.
     */
    mask = extract64(wcr, 24, 4);
    if (mask == 1 || mask == 2) {
        /* Reserved values of MASK; we must act as if the mask value was
         * some non-reserved value, or as if the watchpoint were disabled.
         * We choose the latter.
         */
        return;
    } else if (mask) {
        /* Watchpoint covers an aligned area up to 2GB in size */
        len = 1ULL << mask;
        /* If masked bits in WVR are not zero it's CONSTRAINED UNPREDICTABLE
         * whether the watchpoint fires when the unmasked bits match; we opt
         * to generate the exceptions.
         */
        wvr &= ~(len - 1);
    } else {
        /* Watchpoint covers bytes defined by the byte address select bits */
        int bas = extract64(wcr, 5, 8);
        int basstart;

        if (bas == 0) {
            /* This must act as if the watchpoint is disabled */
            return;
        }

        if (extract64(wvr, 2, 1)) {
            /* Deprecated case of an only 4-aligned address. BAS[7:4] are
             * ignored, and BAS[3:0] define which bytes to watch.
             */
            bas &= 0xf;
        }
        /* The BAS bits are supposed to be programmed to indicate a contiguous
         * range of bytes. Otherwise it is CONSTRAINED UNPREDICTABLE whether
         * we fire for each byte in the word/doubleword addressed by the WVR.
         * We choose to ignore any non-zero bits after the first range of 1s.
         */
        basstart = ctz32(bas);
        len = cto32(bas >> basstart);
        wvr += basstart;
    }

    cpu_watchpoint_insert(CPU(cpu), wvr, len, flags,
                          &env->cpu_watchpoint[n]);
}

void hw_watchpoint_update_all(ARMCPU *cpu)
{
    int i;
    CPUARMState *env = &cpu->env;

    /* Completely clear out existing QEMU watchpoints and our array, to
     * avoid possible stale entries following migration load.
     */
    cpu_watchpoint_remove_all(CPU(cpu), BP_CPU);
    memset(env->cpu_watchpoint, 0, sizeof(env->cpu_watchpoint));

    for (i = 0; i < ARRAY_SIZE(cpu->env.cpu_watchpoint); i++) {
        hw_watchpoint_update(cpu, i);
    }
}

static void dbgwvr_write(CPUARMState *env, const ARMCPRegInfo *ri,
                         uint64_t value)
{
    ARMCPU *cpu = arm_env_get_cpu(env);
    int i = ri->crm;

    /* Bits [63:49] are hardwired to the value of bit [48]; that is, the
     * register reads and behaves as if values written are sign extended.
     * Bits [1:0] are RES0.
     */
    value = sextract64(value, 0, 49) & ~3ULL;

    raw_write(env, ri, value);
    hw_watchpoint_update(cpu, i);
}

static void dbgwcr_write(CPUARMState *env, const ARMCPRegInfo *ri,
                         uint64_t value)
{
    ARMCPU *cpu = arm_env_get_cpu(env);
    int i = ri->crm;

    raw_write(env, ri, value);
    hw_watchpoint_update(cpu, i);
}

void hw_breakpoint_update(ARMCPU *cpu, int n)
{
    CPUARMState *env = &cpu->env;
    uint64_t bvr = env->cp15.dbgbvr[n];
    uint64_t bcr = env->cp15.dbgbcr[n];
    vaddr addr;
    int bt;
    int flags = BP_CPU;

    if (env->cpu_breakpoint[n]) {
        cpu_breakpoint_remove_by_ref(CPU(cpu), env->cpu_breakpoint[n]);
        env->cpu_breakpoint[n] = NULL;
    }

    if (!extract64(bcr, 0, 1)) {
        /* E bit clear : watchpoint disabled */
        return;
    }

    bt = extract64(bcr, 20, 4);

    switch (bt) {
    case 4: /* unlinked address mismatch (reserved if AArch64) */
    case 5: /* linked address mismatch (reserved if AArch64) */
        qemu_log_mask(LOG_UNIMP,
                      "arm: address mismatch breakpoint types not implemented");
        return;
    case 0: /* unlinked address match */
    case 1: /* linked address match */
    {
        /* Bits [63:49] are hardwired to the value of bit [48]; that is,
         * we behave as if the register was sign extended. Bits [1:0] are
         * RES0. The BAS field is used to allow setting breakpoints on 16
         * bit wide instructions; it is CONSTRAINED UNPREDICTABLE whether
         * a bp will fire if the addresses covered by the bp and the addresses
         * covered by the insn overlap but the insn doesn't start at the
         * start of the bp address range. We choose to require the insn and
         * the bp to have the same address. The constraints on writing to
         * BAS enforced in dbgbcr_write mean we have only four cases:
         *  0b0000  => no breakpoint
         *  0b0011  => breakpoint on addr
         *  0b1100  => breakpoint on addr + 2
         *  0b1111  => breakpoint on addr
         * See also figure D2-3 in the v8 ARM ARM (DDI0487A.c).
         */
        int bas = extract64(bcr, 5, 4);
        addr = sextract64(bvr, 0, 49) & ~3ULL;
        if (bas == 0) {
            return;
        }
        if (bas == 0xc) {
            addr += 2;
        }
        break;
    }
    case 2: /* unlinked context ID match */
    case 8: /* unlinked VMID match (reserved if no EL2) */
    case 10: /* unlinked context ID and VMID match (reserved if no EL2) */
        qemu_log_mask(LOG_UNIMP,
                      "arm: unlinked context breakpoint types not implemented");
        return;
    case 9: /* linked VMID match (reserved if no EL2) */
    case 11: /* linked context ID and VMID match (reserved if no EL2) */
    case 3: /* linked context ID match */
    default:
        /* We must generate no events for Linked context matches (unless
         * they are linked to by some other bp/wp, which is handled in
         * updates for the linking bp/wp). We choose to also generate no events
         * for reserved values.
         */
        return;
    }

    cpu_breakpoint_insert(CPU(cpu), addr, flags, &env->cpu_breakpoint[n]);
}

void hw_breakpoint_update_all(ARMCPU *cpu)
{
    int i;
    CPUARMState *env = &cpu->env;

    /* Completely clear out existing QEMU breakpoints and our array, to
     * avoid possible stale entries following migration load.
     */
    cpu_breakpoint_remove_all(CPU(cpu), BP_CPU);
    memset(env->cpu_breakpoint, 0, sizeof(env->cpu_breakpoint));

    for (i = 0; i < ARRAY_SIZE(cpu->env.cpu_breakpoint); i++) {
        hw_breakpoint_update(cpu, i);
    }
}

static void dbgbvr_write(CPUARMState *env, const ARMCPRegInfo *ri,
                         uint64_t value)
{
    ARMCPU *cpu = arm_env_get_cpu(env);
    int i = ri->crm;

    raw_write(env, ri, value);
    hw_breakpoint_update(cpu, i);
}

static void dbgbcr_write(CPUARMState *env, const ARMCPRegInfo *ri,
                         uint64_t value)
{
    ARMCPU *cpu = arm_env_get_cpu(env);
    int i = ri->crm;

    /* BAS[3] is a read-only copy of BAS[2], and BAS[1] a read-only
     * copy of BAS[0].
     */
    value = deposit64(value, 6, 1, extract64(value, 5, 1));
    value = deposit64(value, 8, 1, extract64(value, 7, 1));

    raw_write(env, ri, value);
    hw_breakpoint_update(cpu, i);
}

static void define_debug_regs(ARMCPU *cpu)
{
    /* Define v7 and v8 architectural debug registers.
     * These are just dummy implementations for now.
     */
    int i;
    int wrps, brps, ctx_cmps;
    ARMCPRegInfo dbgdidr = {
        .name = "DBGDIDR", .cp = 14, .crn = 0, .crm = 0, .opc1 = 0, .opc2 = 0,
        .access = PL0_R, .accessfn = access_tda,
        .type = ARM_CP_CONST, .resetvalue = cpu->dbgdidr,
    };

    /* Note that all these register fields hold "number of Xs minus 1". */
    brps = extract32(cpu->dbgdidr, 24, 4);
    wrps = extract32(cpu->dbgdidr, 28, 4);
    ctx_cmps = extract32(cpu->dbgdidr, 20, 4);

    assert(ctx_cmps <= brps);

    /* The DBGDIDR and ID_AA64DFR0_EL1 define various properties
     * of the debug registers such as number of breakpoints;
     * check that if they both exist then they agree.
     */
    if (arm_feature(&cpu->env, ARM_FEATURE_AARCH64)) {
        assert(extract32(cpu->id_aa64dfr0, 12, 4) == brps);
        assert(extract32(cpu->id_aa64dfr0, 20, 4) == wrps);
        assert(extract32(cpu->id_aa64dfr0, 28, 4) == ctx_cmps);
    }

    define_one_arm_cp_reg(cpu, &dbgdidr);
    define_arm_cp_regs(cpu, debug_cp_reginfo);

    if (arm_feature(&cpu->env, ARM_FEATURE_LPAE)) {
        define_arm_cp_regs(cpu, debug_lpae_cp_reginfo);
    }

    for (i = 0; i < brps + 1; i++) {
        ARMCPRegInfo dbgregs[] = {
            { .name = "DBGBVR", .state = ARM_CP_STATE_BOTH,
              .cp = 14, .opc0 = 2, .opc1 = 0, .crn = 0, .crm = i, .opc2 = 4,
              .access = PL1_RW, .accessfn = access_tda,
              .fieldoffset = offsetof(CPUARMState, cp15.dbgbvr[i]),
              .writefn = dbgbvr_write, .raw_writefn = raw_write
            },
            { .name = "DBGBCR", .state = ARM_CP_STATE_BOTH,
              .cp = 14, .opc0 = 2, .opc1 = 0, .crn = 0, .crm = i, .opc2 = 5,
              .access = PL1_RW, .accessfn = access_tda,
              .fieldoffset = offsetof(CPUARMState, cp15.dbgbcr[i]),
              .writefn = dbgbcr_write, .raw_writefn = raw_write
            },
            REGINFO_SENTINEL
        };
        define_arm_cp_regs(cpu, dbgregs);
    }

    for (i = 0; i < wrps + 1; i++) {
        ARMCPRegInfo dbgregs[] = {
            { .name = "DBGWVR", .state = ARM_CP_STATE_BOTH,
              .cp = 14, .opc0 = 2, .opc1 = 0, .crn = 0, .crm = i, .opc2 = 6,
              .access = PL1_RW, .accessfn = access_tda,
              .fieldoffset = offsetof(CPUARMState, cp15.dbgwvr[i]),
              .writefn = dbgwvr_write, .raw_writefn = raw_write
            },
            { .name = "DBGWCR", .state = ARM_CP_STATE_BOTH,
              .cp = 14, .opc0 = 2, .opc1 = 0, .crn = 0, .crm = i, .opc2 = 7,
              .access = PL1_RW, .accessfn = access_tda,
              .fieldoffset = offsetof(CPUARMState, cp15.dbgwcr[i]),
              .writefn = dbgwcr_write, .raw_writefn = raw_write
            },
            REGINFO_SENTINEL
        };
        define_arm_cp_regs(cpu, dbgregs);
    }
}

void register_cp_regs_for_features(ARMCPU *cpu)
{
    /* Register all the coprocessor registers based on feature bits */
    CPUARMState *env = &cpu->env;
    if (arm_feature(env, ARM_FEATURE_M)) {
        /* M profile has no coprocessor registers */
        return;
    }

    define_arm_cp_regs(cpu, cp_reginfo);
    if (!arm_feature(env, ARM_FEATURE_V8)) {
        /* Must go early as it is full of wildcards that may be
         * overridden by later definitions.
         */
        define_arm_cp_regs(cpu, not_v8_cp_reginfo);
    }

    if (arm_feature(env, ARM_FEATURE_V6)) {
        /* The ID registers all have impdef reset values */
        ARMCPRegInfo v6_idregs[] = {
            { .name = "ID_PFR0", .state = ARM_CP_STATE_BOTH,
              .opc0 = 3, .opc1 = 0, .crn = 0, .crm = 1, .opc2 = 0,
              .access = PL1_R, .type = ARM_CP_CONST,
              .resetvalue = cpu->id_pfr0 },
            { .name = "ID_PFR1", .state = ARM_CP_STATE_BOTH,
              .opc0 = 3, .opc1 = 0, .crn = 0, .crm = 1, .opc2 = 1,
              .access = PL1_R, .type = ARM_CP_CONST,
              .resetvalue = cpu->id_pfr1 },
            { .name = "ID_DFR0", .state = ARM_CP_STATE_BOTH,
              .opc0 = 3, .opc1 = 0, .crn = 0, .crm = 1, .opc2 = 2,
              .access = PL1_R, .type = ARM_CP_CONST,
              .resetvalue = cpu->id_dfr0 },
            { .name = "ID_AFR0", .state = ARM_CP_STATE_BOTH,
              .opc0 = 3, .opc1 = 0, .crn = 0, .crm = 1, .opc2 = 3,
              .access = PL1_R, .type = ARM_CP_CONST,
              .resetvalue = cpu->id_afr0 },
            { .name = "ID_MMFR0", .state = ARM_CP_STATE_BOTH,
              .opc0 = 3, .opc1 = 0, .crn = 0, .crm = 1, .opc2 = 4,
              .access = PL1_R, .type = ARM_CP_CONST,
              .resetvalue = cpu->id_mmfr0 },
            { .name = "ID_MMFR1", .state = ARM_CP_STATE_BOTH,
              .opc0 = 3, .opc1 = 0, .crn = 0, .crm = 1, .opc2 = 5,
              .access = PL1_R, .type = ARM_CP_CONST,
              .resetvalue = cpu->id_mmfr1 },
            { .name = "ID_MMFR2", .state = ARM_CP_STATE_BOTH,
              .opc0 = 3, .opc1 = 0, .crn = 0, .crm = 1, .opc2 = 6,
              .access = PL1_R, .type = ARM_CP_CONST,
              .resetvalue = cpu->id_mmfr2 },
            { .name = "ID_MMFR3", .state = ARM_CP_STATE_BOTH,
              .opc0 = 3, .opc1 = 0, .crn = 0, .crm = 1, .opc2 = 7,
              .access = PL1_R, .type = ARM_CP_CONST,
              .resetvalue = cpu->id_mmfr3 },
            { .name = "ID_ISAR0", .state = ARM_CP_STATE_BOTH,
              .opc0 = 3, .opc1 = 0, .crn = 0, .crm = 2, .opc2 = 0,
              .access = PL1_R, .type = ARM_CP_CONST,
              .resetvalue = cpu->id_isar0 },
            { .name = "ID_ISAR1", .state = ARM_CP_STATE_BOTH,
              .opc0 = 3, .opc1 = 0, .crn = 0, .crm = 2, .opc2 = 1,
              .access = PL1_R, .type = ARM_CP_CONST,
              .resetvalue = cpu->id_isar1 },
            { .name = "ID_ISAR2", .state = ARM_CP_STATE_BOTH,
              .opc0 = 3, .opc1 = 0, .crn = 0, .crm = 2, .opc2 = 2,
              .access = PL1_R, .type = ARM_CP_CONST,
              .resetvalue = cpu->id_isar2 },
            { .name = "ID_ISAR3", .state = ARM_CP_STATE_BOTH,
              .opc0 = 3, .opc1 = 0, .crn = 0, .crm = 2, .opc2 = 3,
              .access = PL1_R, .type = ARM_CP_CONST,
              .resetvalue = cpu->id_isar3 },
            { .name = "ID_ISAR4", .state = ARM_CP_STATE_BOTH,
              .opc0 = 3, .opc1 = 0, .crn = 0, .crm = 2, .opc2 = 4,
              .access = PL1_R, .type = ARM_CP_CONST,
              .resetvalue = cpu->id_isar4 },
            { .name = "ID_ISAR5", .state = ARM_CP_STATE_BOTH,
              .opc0 = 3, .opc1 = 0, .crn = 0, .crm = 2, .opc2 = 5,
              .access = PL1_R, .type = ARM_CP_CONST,
              .resetvalue = cpu->id_isar5 },
            { .name = "ID_MMFR4", .state = ARM_CP_STATE_BOTH,
              .opc0 = 3, .opc1 = 0, .crn = 0, .crm = 2, .opc2 = 6,
              .access = PL1_R, .type = ARM_CP_CONST,
              .resetvalue = cpu->id_mmfr4 },
            /* 7 is as yet unallocated and must RAZ */
            { .name = "ID_ISAR7_RESERVED", .state = ARM_CP_STATE_BOTH,
              .opc0 = 3, .opc1 = 0, .crn = 0, .crm = 2, .opc2 = 7,
              .access = PL1_R, .type = ARM_CP_CONST,
              .resetvalue = 0 },
            REGINFO_SENTINEL
        };
        define_arm_cp_regs(cpu, v6_idregs);
        define_arm_cp_regs(cpu, v6_cp_reginfo);
    } else {
        define_arm_cp_regs(cpu, not_v6_cp_reginfo);
    }
    if (arm_feature(env, ARM_FEATURE_V6K)) {
        define_arm_cp_regs(cpu, v6k_cp_reginfo);
    }
    if (arm_feature(env, ARM_FEATURE_V7MP) &&
        !arm_feature(env, ARM_FEATURE_MPU)) {
        define_arm_cp_regs(cpu, v7mp_cp_reginfo);
    }
    if (arm_feature(env, ARM_FEATURE_V7)) {
        /* v7 performance monitor control register: same implementor
         * field as main ID register, and we implement only the cycle
         * count register.
         */
#ifndef CONFIG_USER_ONLY
        ARMCPRegInfo pmcr = {
            .name = "PMCR", .cp = 15, .crn = 9, .crm = 12, .opc1 = 0, .opc2 = 0,
            .access = PL0_RW,
            .type = ARM_CP_IO | ARM_CP_ALIAS,
            .fieldoffset = offsetoflow32(CPUARMState, cp15.c9_pmcr),
            .accessfn = pmreg_access, .writefn = pmcr_write,
            .raw_writefn = raw_write,
        };
        ARMCPRegInfo pmcr64 = {
            .name = "PMCR_EL0", .state = ARM_CP_STATE_AA64,
            .opc0 = 3, .opc1 = 3, .crn = 9, .crm = 12, .opc2 = 0,
            .access = PL0_RW, .accessfn = pmreg_access,
            .type = ARM_CP_IO,
            .fieldoffset = offsetof(CPUARMState, cp15.c9_pmcr),
            .resetvalue = cpu->midr & 0xff000000,
            .writefn = pmcr_write, .raw_writefn = raw_write,
        };
        define_one_arm_cp_reg(cpu, &pmcr);
        define_one_arm_cp_reg(cpu, &pmcr64);
#endif
        ARMCPRegInfo clidr = {
            .name = "CLIDR", .state = ARM_CP_STATE_BOTH,
            .opc0 = 3, .crn = 0, .crm = 0, .opc1 = 1, .opc2 = 1,
            .access = PL1_R, .type = ARM_CP_CONST, .resetvalue = cpu->clidr
        };
        define_one_arm_cp_reg(cpu, &clidr);
        define_arm_cp_regs(cpu, v7_cp_reginfo);
        define_debug_regs(cpu);
    } else {
        define_arm_cp_regs(cpu, not_v7_cp_reginfo);
    }
    if (arm_feature(env, ARM_FEATURE_V8)) {
        /* AArch64 ID registers, which all have impdef reset values.
         * Note that within the ID register ranges the unused slots
         * must all RAZ, not UNDEF; future architecture versions may
         * define new registers here.
         */
        ARMCPRegInfo v8_idregs[] = {
            { .name = "ID_AA64PFR0_EL1", .state = ARM_CP_STATE_AA64,
              .opc0 = 3, .opc1 = 0, .crn = 0, .crm = 4, .opc2 = 0,
              .access = PL1_R, .type = ARM_CP_CONST,
              .resetvalue = cpu->id_aa64pfr0 },
            { .name = "ID_AA64PFR1_EL1", .state = ARM_CP_STATE_AA64,
              .opc0 = 3, .opc1 = 0, .crn = 0, .crm = 4, .opc2 = 1,
              .access = PL1_R, .type = ARM_CP_CONST,
              .resetvalue = cpu->id_aa64pfr1},
            { .name = "ID_AA64PFR2_EL1_RESERVED", .state = ARM_CP_STATE_AA64,
              .opc0 = 3, .opc1 = 0, .crn = 0, .crm = 4, .opc2 = 2,
              .access = PL1_R, .type = ARM_CP_CONST,
              .resetvalue = 0 },
            { .name = "ID_AA64PFR3_EL1_RESERVED", .state = ARM_CP_STATE_AA64,
              .opc0 = 3, .opc1 = 0, .crn = 0, .crm = 4, .opc2 = 3,
              .access = PL1_R, .type = ARM_CP_CONST,
              .resetvalue = 0 },
            { .name = "ID_AA64PFR4_EL1_RESERVED", .state = ARM_CP_STATE_AA64,
              .opc0 = 3, .opc1 = 0, .crn = 0, .crm = 4, .opc2 = 4,
              .access = PL1_R, .type = ARM_CP_CONST,
              .resetvalue = 0 },
            { .name = "ID_AA64PFR5_EL1_RESERVED", .state = ARM_CP_STATE_AA64,
              .opc0 = 3, .opc1 = 0, .crn = 0, .crm = 4, .opc2 = 5,
              .access = PL1_R, .type = ARM_CP_CONST,
              .resetvalue = 0 },
            { .name = "ID_AA64PFR6_EL1_RESERVED", .state = ARM_CP_STATE_AA64,
              .opc0 = 3, .opc1 = 0, .crn = 0, .crm = 4, .opc2 = 6,
              .access = PL1_R, .type = ARM_CP_CONST,
              .resetvalue = 0 },
            { .name = "ID_AA64PFR7_EL1_RESERVED", .state = ARM_CP_STATE_AA64,
              .opc0 = 3, .opc1 = 0, .crn = 0, .crm = 4, .opc2 = 7,
              .access = PL1_R, .type = ARM_CP_CONST,
              .resetvalue = 0 },
            { .name = "ID_AA64DFR0_EL1", .state = ARM_CP_STATE_AA64,
              .opc0 = 3, .opc1 = 0, .crn = 0, .crm = 5, .opc2 = 0,
              .access = PL1_R, .type = ARM_CP_CONST,
              .resetvalue = cpu->id_aa64dfr0 },
            { .name = "ID_AA64DFR1_EL1", .state = ARM_CP_STATE_AA64,
              .opc0 = 3, .opc1 = 0, .crn = 0, .crm = 5, .opc2 = 1,
              .access = PL1_R, .type = ARM_CP_CONST,
              .resetvalue = cpu->id_aa64dfr1 },
            { .name = "ID_AA64DFR2_EL1_RESERVED", .state = ARM_CP_STATE_AA64,
              .opc0 = 3, .opc1 = 0, .crn = 0, .crm = 5, .opc2 = 2,
              .access = PL1_R, .type = ARM_CP_CONST,
              .resetvalue = 0 },
            { .name = "ID_AA64DFR3_EL1_RESERVED", .state = ARM_CP_STATE_AA64,
              .opc0 = 3, .opc1 = 0, .crn = 0, .crm = 5, .opc2 = 3,
              .access = PL1_R, .type = ARM_CP_CONST,
              .resetvalue = 0 },
            { .name = "ID_AA64AFR0_EL1", .state = ARM_CP_STATE_AA64,
              .opc0 = 3, .opc1 = 0, .crn = 0, .crm = 5, .opc2 = 4,
              .access = PL1_R, .type = ARM_CP_CONST,
              .resetvalue = cpu->id_aa64afr0 },
            { .name = "ID_AA64AFR1_EL1", .state = ARM_CP_STATE_AA64,
              .opc0 = 3, .opc1 = 0, .crn = 0, .crm = 5, .opc2 = 5,
              .access = PL1_R, .type = ARM_CP_CONST,
              .resetvalue = cpu->id_aa64afr1 },
            { .name = "ID_AA64AFR2_EL1_RESERVED", .state = ARM_CP_STATE_AA64,
              .opc0 = 3, .opc1 = 0, .crn = 0, .crm = 5, .opc2 = 6,
              .access = PL1_R, .type = ARM_CP_CONST,
              .resetvalue = 0 },
            { .name = "ID_AA64AFR3_EL1_RESERVED", .state = ARM_CP_STATE_AA64,
              .opc0 = 3, .opc1 = 0, .crn = 0, .crm = 5, .opc2 = 7,
              .access = PL1_R, .type = ARM_CP_CONST,
              .resetvalue = 0 },
            { .name = "ID_AA64ISAR0_EL1", .state = ARM_CP_STATE_AA64,
              .opc0 = 3, .opc1 = 0, .crn = 0, .crm = 6, .opc2 = 0,
              .access = PL1_R, .type = ARM_CP_CONST,
              .resetvalue = cpu->id_aa64isar0 },
            { .name = "ID_AA64ISAR1_EL1", .state = ARM_CP_STATE_AA64,
              .opc0 = 3, .opc1 = 0, .crn = 0, .crm = 6, .opc2 = 1,
              .access = PL1_R, .type = ARM_CP_CONST,
              .resetvalue = cpu->id_aa64isar1 },
            { .name = "ID_AA64ISAR2_EL1_RESERVED", .state = ARM_CP_STATE_AA64,
              .opc0 = 3, .opc1 = 0, .crn = 0, .crm = 6, .opc2 = 2,
              .access = PL1_R, .type = ARM_CP_CONST,
              .resetvalue = 0 },
            { .name = "ID_AA64ISAR3_EL1_RESERVED", .state = ARM_CP_STATE_AA64,
              .opc0 = 3, .opc1 = 0, .crn = 0, .crm = 6, .opc2 = 3,
              .access = PL1_R, .type = ARM_CP_CONST,
              .resetvalue = 0 },
            { .name = "ID_AA64ISAR4_EL1_RESERVED", .state = ARM_CP_STATE_AA64,
              .opc0 = 3, .opc1 = 0, .crn = 0, .crm = 6, .opc2 = 4,
              .access = PL1_R, .type = ARM_CP_CONST,
              .resetvalue = 0 },
            { .name = "ID_AA64ISAR5_EL1_RESERVED", .state = ARM_CP_STATE_AA64,
              .opc0 = 3, .opc1 = 0, .crn = 0, .crm = 6, .opc2 = 5,
              .access = PL1_R, .type = ARM_CP_CONST,
              .resetvalue = 0 },
            { .name = "ID_AA64ISAR6_EL1_RESERVED", .state = ARM_CP_STATE_AA64,
              .opc0 = 3, .opc1 = 0, .crn = 0, .crm = 6, .opc2 = 6,
              .access = PL1_R, .type = ARM_CP_CONST,
              .resetvalue = 0 },
            { .name = "ID_AA64ISAR7_EL1_RESERVED", .state = ARM_CP_STATE_AA64,
              .opc0 = 3, .opc1 = 0, .crn = 0, .crm = 6, .opc2 = 7,
              .access = PL1_R, .type = ARM_CP_CONST,
              .resetvalue = 0 },
            { .name = "ID_AA64MMFR0_EL1", .state = ARM_CP_STATE_AA64,
              .opc0 = 3, .opc1 = 0, .crn = 0, .crm = 7, .opc2 = 0,
              .access = PL1_R, .type = ARM_CP_CONST,
              .resetvalue = cpu->id_aa64mmfr0 },
            { .name = "ID_AA64MMFR1_EL1", .state = ARM_CP_STATE_AA64,
              .opc0 = 3, .opc1 = 0, .crn = 0, .crm = 7, .opc2 = 1,
              .access = PL1_R, .type = ARM_CP_CONST,
              .resetvalue = cpu->id_aa64mmfr1 },
            { .name = "ID_AA64MMFR2_EL1_RESERVED", .state = ARM_CP_STATE_AA64,
              .opc0 = 3, .opc1 = 0, .crn = 0, .crm = 7, .opc2 = 2,
              .access = PL1_R, .type = ARM_CP_CONST,
              .resetvalue = 0 },
            { .name = "ID_AA64MMFR3_EL1_RESERVED", .state = ARM_CP_STATE_AA64,
              .opc0 = 3, .opc1 = 0, .crn = 0, .crm = 7, .opc2 = 3,
              .access = PL1_R, .type = ARM_CP_CONST,
              .resetvalue = 0 },
            { .name = "ID_AA64MMFR4_EL1_RESERVED", .state = ARM_CP_STATE_AA64,
              .opc0 = 3, .opc1 = 0, .crn = 0, .crm = 7, .opc2 = 4,
              .access = PL1_R, .type = ARM_CP_CONST,
              .resetvalue = 0 },
            { .name = "ID_AA64MMFR5_EL1_RESERVED", .state = ARM_CP_STATE_AA64,
              .opc0 = 3, .opc1 = 0, .crn = 0, .crm = 7, .opc2 = 5,
              .access = PL1_R, .type = ARM_CP_CONST,
              .resetvalue = 0 },
            { .name = "ID_AA64MMFR6_EL1_RESERVED", .state = ARM_CP_STATE_AA64,
              .opc0 = 3, .opc1 = 0, .crn = 0, .crm = 7, .opc2 = 6,
              .access = PL1_R, .type = ARM_CP_CONST,
              .resetvalue = 0 },
            { .name = "ID_AA64MMFR7_EL1_RESERVED", .state = ARM_CP_STATE_AA64,
              .opc0 = 3, .opc1 = 0, .crn = 0, .crm = 7, .opc2 = 7,
              .access = PL1_R, .type = ARM_CP_CONST,
              .resetvalue = 0 },
            { .name = "MVFR0_EL1", .state = ARM_CP_STATE_AA64,
              .opc0 = 3, .opc1 = 0, .crn = 0, .crm = 3, .opc2 = 0,
              .access = PL1_R, .type = ARM_CP_CONST,
              .resetvalue = cpu->mvfr0 },
            { .name = "MVFR1_EL1", .state = ARM_CP_STATE_AA64,
              .opc0 = 3, .opc1 = 0, .crn = 0, .crm = 3, .opc2 = 1,
              .access = PL1_R, .type = ARM_CP_CONST,
              .resetvalue = cpu->mvfr1 },
            { .name = "MVFR2_EL1", .state = ARM_CP_STATE_AA64,
              .opc0 = 3, .opc1 = 0, .crn = 0, .crm = 3, .opc2 = 2,
              .access = PL1_R, .type = ARM_CP_CONST,
              .resetvalue = cpu->mvfr2 },
            { .name = "MVFR3_EL1_RESERVED", .state = ARM_CP_STATE_AA64,
              .opc0 = 3, .opc1 = 0, .crn = 0, .crm = 3, .opc2 = 3,
              .access = PL1_R, .type = ARM_CP_CONST,
              .resetvalue = 0 },
            { .name = "MVFR4_EL1_RESERVED", .state = ARM_CP_STATE_AA64,
              .opc0 = 3, .opc1 = 0, .crn = 0, .crm = 3, .opc2 = 4,
              .access = PL1_R, .type = ARM_CP_CONST,
              .resetvalue = 0 },
            { .name = "MVFR5_EL1_RESERVED", .state = ARM_CP_STATE_AA64,
              .opc0 = 3, .opc1 = 0, .crn = 0, .crm = 3, .opc2 = 5,
              .access = PL1_R, .type = ARM_CP_CONST,
              .resetvalue = 0 },
            { .name = "MVFR6_EL1_RESERVED", .state = ARM_CP_STATE_AA64,
              .opc0 = 3, .opc1 = 0, .crn = 0, .crm = 3, .opc2 = 6,
              .access = PL1_R, .type = ARM_CP_CONST,
              .resetvalue = 0 },
            { .name = "MVFR7_EL1_RESERVED", .state = ARM_CP_STATE_AA64,
              .opc0 = 3, .opc1 = 0, .crn = 0, .crm = 3, .opc2 = 7,
              .access = PL1_R, .type = ARM_CP_CONST,
              .resetvalue = 0 },
            { .name = "PMCEID0", .state = ARM_CP_STATE_AA32,
              .cp = 15, .opc1 = 0, .crn = 9, .crm = 12, .opc2 = 6,
              .access = PL0_R, .accessfn = pmreg_access, .type = ARM_CP_CONST,
              .resetvalue = cpu->pmceid0 },
            { .name = "PMCEID0_EL0", .state = ARM_CP_STATE_AA64,
              .opc0 = 3, .opc1 = 3, .crn = 9, .crm = 12, .opc2 = 6,
              .access = PL0_R, .accessfn = pmreg_access, .type = ARM_CP_CONST,
              .resetvalue = cpu->pmceid0 },
            { .name = "PMCEID1", .state = ARM_CP_STATE_AA32,
              .cp = 15, .opc1 = 0, .crn = 9, .crm = 12, .opc2 = 7,
              .access = PL0_R, .accessfn = pmreg_access, .type = ARM_CP_CONST,
              .resetvalue = cpu->pmceid1 },
            { .name = "PMCEID1_EL0", .state = ARM_CP_STATE_AA64,
              .opc0 = 3, .opc1 = 3, .crn = 9, .crm = 12, .opc2 = 7,
              .access = PL0_R, .accessfn = pmreg_access, .type = ARM_CP_CONST,
              .resetvalue = cpu->pmceid1 },
            REGINFO_SENTINEL
        };
        /* RVBAR_EL1 is only implemented if EL1 is the highest EL */
        if (!arm_feature(env, ARM_FEATURE_EL3) &&
            !arm_feature(env, ARM_FEATURE_EL2)) {
            ARMCPRegInfo rvbar = {
                .name = "RVBAR_EL1", .state = ARM_CP_STATE_AA64,
                .opc0 = 3, .opc1 = 0, .crn = 12, .crm = 0, .opc2 = 1,
                .type = ARM_CP_CONST, .access = PL1_R, .resetvalue = cpu->rvbar
            };
            define_one_arm_cp_reg(cpu, &rvbar);
        }
        define_arm_cp_regs(cpu, v8_idregs);
        define_arm_cp_regs(cpu, v8_cp_reginfo);
    }
    if (arm_feature(env, ARM_FEATURE_EL2)) {
        uint64_t vmpidr_def = mpidr_read_val(env);
        ARMCPRegInfo vpidr_regs[] = {
            { .name = "VPIDR", .state = ARM_CP_STATE_AA32,
              .cp = 15, .opc1 = 4, .crn = 0, .crm = 0, .opc2 = 0,
              .access = PL2_RW, .accessfn = access_el3_aa32ns,
              .resetvalue = cpu->midr,
              .fieldoffset = offsetof(CPUARMState, cp15.vpidr_el2) },
            { .name = "VPIDR_EL2", .state = ARM_CP_STATE_AA64,
              .opc0 = 3, .opc1 = 4, .crn = 0, .crm = 0, .opc2 = 0,
              .access = PL2_RW, .resetvalue = cpu->midr,
              .fieldoffset = offsetof(CPUARMState, cp15.vpidr_el2) },
            { .name = "VMPIDR", .state = ARM_CP_STATE_AA32,
              .cp = 15, .opc1 = 4, .crn = 0, .crm = 0, .opc2 = 5,
              .access = PL2_RW, .accessfn = access_el3_aa32ns,
              .resetvalue = vmpidr_def,
              .fieldoffset = offsetof(CPUARMState, cp15.vmpidr_el2) },
            { .name = "VMPIDR_EL2", .state = ARM_CP_STATE_AA64,
              .opc0 = 3, .opc1 = 4, .crn = 0, .crm = 0, .opc2 = 5,
              .access = PL2_RW,
              .resetvalue = vmpidr_def,
              .fieldoffset = offsetof(CPUARMState, cp15.vmpidr_el2) },
            REGINFO_SENTINEL
        };
        define_arm_cp_regs(cpu, vpidr_regs);
        define_arm_cp_regs(cpu, el2_cp_reginfo);
        /* RVBAR_EL2 is only implemented if EL2 is the highest EL */
        if (!arm_feature(env, ARM_FEATURE_EL3)) {
            ARMCPRegInfo rvbar = {
                .name = "RVBAR_EL2", .state = ARM_CP_STATE_AA64,
                .opc0 = 3, .opc1 = 4, .crn = 12, .crm = 0, .opc2 = 1,
                .type = ARM_CP_CONST, .access = PL2_R, .resetvalue = cpu->rvbar
            };
            define_one_arm_cp_reg(cpu, &rvbar);
        }
    } else {
        /* If EL2 is missing but higher ELs are enabled, we need to
         * register the no_el2 reginfos.
         */
        if (arm_feature(env, ARM_FEATURE_EL3)) {
            /* When EL3 exists but not EL2, VPIDR and VMPIDR take the value
             * of MIDR_EL1 and MPIDR_EL1.
             */
            ARMCPRegInfo vpidr_regs[] = {
                { .name = "VPIDR_EL2", .state = ARM_CP_STATE_BOTH,
                  .opc0 = 3, .opc1 = 4, .crn = 0, .crm = 0, .opc2 = 0,
                  .access = PL2_RW, .accessfn = access_el3_aa32ns_aa64any,
                  .type = ARM_CP_CONST, .resetvalue = cpu->midr,
                  .fieldoffset = offsetof(CPUARMState, cp15.vpidr_el2) },
                { .name = "VMPIDR_EL2", .state = ARM_CP_STATE_BOTH,
                  .opc0 = 3, .opc1 = 4, .crn = 0, .crm = 0, .opc2 = 5,
                  .access = PL2_RW, .accessfn = access_el3_aa32ns_aa64any,
                  .type = ARM_CP_NO_RAW,
                  .writefn = arm_cp_write_ignore, .readfn = mpidr_read },
                REGINFO_SENTINEL
            };
            define_arm_cp_regs(cpu, vpidr_regs);
            define_arm_cp_regs(cpu, el3_no_el2_cp_reginfo);
        }
    }
    if (arm_feature(env, ARM_FEATURE_EL3)) {
        define_arm_cp_regs(cpu, el3_cp_reginfo);
        ARMCPRegInfo el3_regs[] = {
            { .name = "RVBAR_EL3", .state = ARM_CP_STATE_AA64,
              .opc0 = 3, .opc1 = 6, .crn = 12, .crm = 0, .opc2 = 1,
              .type = ARM_CP_CONST, .access = PL3_R, .resetvalue = cpu->rvbar },
            { .name = "SCTLR_EL3", .state = ARM_CP_STATE_AA64,
              .opc0 = 3, .opc1 = 6, .crn = 1, .crm = 0, .opc2 = 0,
              .access = PL3_RW,
              .raw_writefn = raw_write, .writefn = sctlr_write,
              .fieldoffset = offsetof(CPUARMState, cp15.sctlr_el[3]),
              .resetvalue = cpu->reset_sctlr },
            REGINFO_SENTINEL
        };

        define_arm_cp_regs(cpu, el3_regs);
    }
    /* The behaviour of NSACR is sufficiently various that we don't
     * try to describe it in a single reginfo:
     *  if EL3 is 64 bit, then trap to EL3 from S EL1,
     *     reads as constant 0xc00 from NS EL1 and NS EL2
     *  if EL3 is 32 bit, then RW at EL3, RO at NS EL1 and NS EL2
     *  if v7 without EL3, register doesn't exist
     *  if v8 without EL3, reads as constant 0xc00 from NS EL1 and NS EL2
     */
    if (arm_feature(env, ARM_FEATURE_EL3)) {
        if (arm_feature(env, ARM_FEATURE_AARCH64)) {
            ARMCPRegInfo nsacr = {
                .name = "NSACR", .type = ARM_CP_CONST,
                .cp = 15, .opc1 = 0, .crn = 1, .crm = 1, .opc2 = 2,
                .access = PL1_RW, .accessfn = nsacr_access,
                .resetvalue = 0xc00
            };
            define_one_arm_cp_reg(cpu, &nsacr);
        } else {
            ARMCPRegInfo nsacr = {
                .name = "NSACR",
                .cp = 15, .opc1 = 0, .crn = 1, .crm = 1, .opc2 = 2,
                .access = PL3_RW | PL1_R,
                .resetvalue = 0,
                .fieldoffset = offsetof(CPUARMState, cp15.nsacr)
            };
            define_one_arm_cp_reg(cpu, &nsacr);
        }
    } else {
        if (arm_feature(env, ARM_FEATURE_V8)) {
            ARMCPRegInfo nsacr = {
                .name = "NSACR", .type = ARM_CP_CONST,
                .cp = 15, .opc1 = 0, .crn = 1, .crm = 1, .opc2 = 2,
                .access = PL1_R,
                .resetvalue = 0xc00
            };
            define_one_arm_cp_reg(cpu, &nsacr);
        }
    }

    if (arm_feature(env, ARM_FEATURE_MPU)) {
        if (arm_feature(env, ARM_FEATURE_V6)) {
            /* PMSAv6 not implemented */
            assert(arm_feature(env, ARM_FEATURE_V7));
            define_arm_cp_regs(cpu, vmsa_pmsa_cp_reginfo);
            define_arm_cp_regs(cpu, pmsav7_cp_reginfo);
        } else {
            define_arm_cp_regs(cpu, pmsav5_cp_reginfo);
        }
    } else {
        define_arm_cp_regs(cpu, vmsa_pmsa_cp_reginfo);
        define_arm_cp_regs(cpu, vmsa_cp_reginfo);
    }
    if (arm_feature(env, ARM_FEATURE_THUMB2EE)) {
        define_arm_cp_regs(cpu, t2ee_cp_reginfo);
    }
    if (arm_feature(env, ARM_FEATURE_GENERIC_TIMER)) {
        define_arm_cp_regs(cpu, generic_timer_cp_reginfo);
    }
    if (arm_feature(env, ARM_FEATURE_VAPA)) {
        define_arm_cp_regs(cpu, vapa_cp_reginfo);
    }
    if (arm_feature(env, ARM_FEATURE_CACHE_TEST_CLEAN)) {
        define_arm_cp_regs(cpu, cache_test_clean_cp_reginfo);
    }
    if (arm_feature(env, ARM_FEATURE_CACHE_DIRTY_REG)) {
        define_arm_cp_regs(cpu, cache_dirty_status_cp_reginfo);
    }
    if (arm_feature(env, ARM_FEATURE_CACHE_BLOCK_OPS)) {
        define_arm_cp_regs(cpu, cache_block_ops_cp_reginfo);
    }
    if (arm_feature(env, ARM_FEATURE_OMAPCP)) {
        define_arm_cp_regs(cpu, omap_cp_reginfo);
    }
    if (arm_feature(env, ARM_FEATURE_STRONGARM)) {
        define_arm_cp_regs(cpu, strongarm_cp_reginfo);
    }
    if (arm_feature(env, ARM_FEATURE_XSCALE)) {
        define_arm_cp_regs(cpu, xscale_cp_reginfo);
    }
    if (arm_feature(env, ARM_FEATURE_DUMMY_C15_REGS)) {
        define_arm_cp_regs(cpu, dummy_c15_cp_reginfo);
    }
    if (arm_feature(env, ARM_FEATURE_LPAE)) {
        define_arm_cp_regs(cpu, lpae_cp_reginfo);
    }
    /* Slightly awkwardly, the OMAP and StrongARM cores need all of
     * cp15 crn=0 to be writes-ignored, whereas for other cores they should
     * be read-only (ie write causes UNDEF exception).
     */
    {
        ARMCPRegInfo id_pre_v8_midr_cp_reginfo[] = {
            /* Pre-v8 MIDR space.
             * Note that the MIDR isn't a simple constant register because
             * of the TI925 behaviour where writes to another register can
             * cause the MIDR value to change.
             *
             * Unimplemented registers in the c15 0 0 0 space default to
             * MIDR. Define MIDR first as this entire space, then CTR, TCMTR
             * and friends override accordingly.
             */
            { .name = "MIDR",
              .cp = 15, .crn = 0, .crm = 0, .opc1 = 0, .opc2 = CP_ANY,
              .access = PL1_R, .resetvalue = cpu->midr,
              .writefn = arm_cp_write_ignore, .raw_writefn = raw_write,
              .readfn = midr_read,
              .fieldoffset = offsetof(CPUARMState, cp15.c0_cpuid),
              .type = ARM_CP_OVERRIDE },
            /* crn = 0 op1 = 0 crm = 3..7 : currently unassigned; we RAZ. */
            { .name = "DUMMY",
              .cp = 15, .crn = 0, .crm = 3, .opc1 = 0, .opc2 = CP_ANY,
              .access = PL1_R, .type = ARM_CP_CONST, .resetvalue = 0 },
            { .name = "DUMMY",
              .cp = 15, .crn = 0, .crm = 4, .opc1 = 0, .opc2 = CP_ANY,
              .access = PL1_R, .type = ARM_CP_CONST, .resetvalue = 0 },
            { .name = "DUMMY",
              .cp = 15, .crn = 0, .crm = 5, .opc1 = 0, .opc2 = CP_ANY,
              .access = PL1_R, .type = ARM_CP_CONST, .resetvalue = 0 },
            { .name = "DUMMY",
              .cp = 15, .crn = 0, .crm = 6, .opc1 = 0, .opc2 = CP_ANY,
              .access = PL1_R, .type = ARM_CP_CONST, .resetvalue = 0 },
            { .name = "DUMMY",
              .cp = 15, .crn = 0, .crm = 7, .opc1 = 0, .opc2 = CP_ANY,
              .access = PL1_R, .type = ARM_CP_CONST, .resetvalue = 0 },
            REGINFO_SENTINEL
        };
        ARMCPRegInfo id_v8_midr_cp_reginfo[] = {
            { .name = "MIDR_EL1", .state = ARM_CP_STATE_BOTH,
              .opc0 = 3, .opc1 = 0, .crn = 0, .crm = 0, .opc2 = 0,
              .access = PL1_R, .type = ARM_CP_NO_RAW, .resetvalue = cpu->midr,
              .fieldoffset = offsetof(CPUARMState, cp15.c0_cpuid),
              .readfn = midr_read },
            /* crn = 0 op1 = 0 crm = 0 op2 = 4,7 : AArch32 aliases of MIDR */
            { .name = "MIDR", .type = ARM_CP_ALIAS | ARM_CP_CONST,
              .cp = 15, .crn = 0, .crm = 0, .opc1 = 0, .opc2 = 4,
              .access = PL1_R, .resetvalue = cpu->midr },
            { .name = "MIDR", .type = ARM_CP_ALIAS | ARM_CP_CONST,
              .cp = 15, .crn = 0, .crm = 0, .opc1 = 0, .opc2 = 7,
              .access = PL1_R, .resetvalue = cpu->midr },
            { .name = "REVIDR_EL1", .state = ARM_CP_STATE_BOTH,
              .opc0 = 3, .opc1 = 0, .crn = 0, .crm = 0, .opc2 = 6,
              .access = PL1_R, .type = ARM_CP_CONST, .resetvalue = cpu->revidr },
            REGINFO_SENTINEL
        };
        ARMCPRegInfo id_cp_reginfo[] = {
            /* These are common to v8 and pre-v8 */
            { .name = "CTR",
              .cp = 15, .crn = 0, .crm = 0, .opc1 = 0, .opc2 = 1,
              .access = PL1_R, .type = ARM_CP_CONST, .resetvalue = cpu->ctr },
            { .name = "CTR_EL0", .state = ARM_CP_STATE_AA64,
              .opc0 = 3, .opc1 = 3, .opc2 = 1, .crn = 0, .crm = 0,
              .access = PL0_R, .accessfn = ctr_el0_access,
              .type = ARM_CP_CONST, .resetvalue = cpu->ctr },
            /* TCMTR and TLBTR exist in v8 but have no 64-bit versions */
            { .name = "TCMTR",
              .cp = 15, .crn = 0, .crm = 0, .opc1 = 0, .opc2 = 2,
              .access = PL1_R, .type = ARM_CP_CONST, .resetvalue = 0 },
            REGINFO_SENTINEL
        };
        /* TLBTR is specific to VMSA */
        ARMCPRegInfo id_tlbtr_reginfo = {
              .name = "TLBTR",
              .cp = 15, .crn = 0, .crm = 0, .opc1 = 0, .opc2 = 3,
              .access = PL1_R, .type = ARM_CP_CONST, .resetvalue = 0,
        };
        /* MPUIR is specific to PMSA V6+ */
        ARMCPRegInfo id_mpuir_reginfo = {
              .name = "MPUIR",
              .cp = 15, .crn = 0, .crm = 0, .opc1 = 0, .opc2 = 4,
              .access = PL1_R, .type = ARM_CP_CONST,
              .resetvalue = cpu->pmsav7_dregion << 8
        };
        ARMCPRegInfo crn0_wi_reginfo = {
            .name = "CRN0_WI", .cp = 15, .crn = 0, .crm = CP_ANY,
            .opc1 = CP_ANY, .opc2 = CP_ANY, .access = PL1_W,
            .type = ARM_CP_NOP | ARM_CP_OVERRIDE
        };
        if (arm_feature(env, ARM_FEATURE_OMAPCP) ||
            arm_feature(env, ARM_FEATURE_STRONGARM)) {
            ARMCPRegInfo *r;
            /* Register the blanket "writes ignored" value first to cover the
             * whole space. Then update the specific ID registers to allow write
             * access, so that they ignore writes rather than causing them to
             * UNDEF.
             */
            define_one_arm_cp_reg(cpu, &crn0_wi_reginfo);
            for (r = id_pre_v8_midr_cp_reginfo;
                 r->type != ARM_CP_SENTINEL; r++) {
                r->access = PL1_RW;
            }
            for (r = id_cp_reginfo; r->type != ARM_CP_SENTINEL; r++) {
                r->access = PL1_RW;
            }
            id_tlbtr_reginfo.access = PL1_RW;
            id_tlbtr_reginfo.access = PL1_RW;
        }
        if (arm_feature(env, ARM_FEATURE_V8)) {
            define_arm_cp_regs(cpu, id_v8_midr_cp_reginfo);
        } else {
            define_arm_cp_regs(cpu, id_pre_v8_midr_cp_reginfo);
        }
        define_arm_cp_regs(cpu, id_cp_reginfo);
        if (!arm_feature(env, ARM_FEATURE_MPU)) {
            define_one_arm_cp_reg(cpu, &id_tlbtr_reginfo);
        } else if (arm_feature(env, ARM_FEATURE_V7)) {
            define_one_arm_cp_reg(cpu, &id_mpuir_reginfo);
        }
    }

    if (arm_feature(env, ARM_FEATURE_MPIDR)) {
        define_arm_cp_regs(cpu, mpidr_cp_reginfo);
    }

    if (arm_feature(env, ARM_FEATURE_AUXCR)) {
        ARMCPRegInfo auxcr_reginfo[] = {
            { .name = "ACTLR_EL1", .state = ARM_CP_STATE_BOTH,
              .opc0 = 3, .opc1 = 0, .crn = 1, .crm = 0, .opc2 = 1,
              .access = PL1_RW, .type = ARM_CP_CONST,
              .resetvalue = cpu->reset_auxcr },
            { .name = "ACTLR_EL2", .state = ARM_CP_STATE_BOTH,
              .opc0 = 3, .opc1 = 4, .crn = 1, .crm = 0, .opc2 = 1,
              .access = PL2_RW, .type = ARM_CP_CONST,
              .resetvalue = 0 },
            { .name = "ACTLR_EL3", .state = ARM_CP_STATE_AA64,
              .opc0 = 3, .opc1 = 6, .crn = 1, .crm = 0, .opc2 = 1,
              .access = PL3_RW, .type = ARM_CP_CONST,
              .resetvalue = 0 },
            REGINFO_SENTINEL
        };
        define_arm_cp_regs(cpu, auxcr_reginfo);
    }

    if (arm_feature(env, ARM_FEATURE_CBAR)) {
        if (arm_feature(env, ARM_FEATURE_AARCH64)) {
            /* 32 bit view is [31:18] 0...0 [43:32]. */
            uint32_t cbar32 = (extract64(cpu->reset_cbar, 18, 14) << 18)
                | extract64(cpu->reset_cbar, 32, 12);
            ARMCPRegInfo cbar_reginfo[] = {
                { .name = "CBAR",
                  .type = ARM_CP_CONST,
                  .cp = 15, .crn = 15, .crm = 0, .opc1 = 4, .opc2 = 0,
                  .access = PL1_R, .resetvalue = cpu->reset_cbar },
                { .name = "CBAR_EL1", .state = ARM_CP_STATE_AA64,
                  .type = ARM_CP_CONST,
                  .opc0 = 3, .opc1 = 1, .crn = 15, .crm = 3, .opc2 = 0,
                  .access = PL1_R, .resetvalue = cbar32 },
                REGINFO_SENTINEL
            };
            /* We don't implement a r/w 64 bit CBAR currently */
            assert(arm_feature(env, ARM_FEATURE_CBAR_RO));
            define_arm_cp_regs(cpu, cbar_reginfo);
        } else {
            ARMCPRegInfo cbar = {
                .name = "CBAR",
                .cp = 15, .crn = 15, .crm = 0, .opc1 = 4, .opc2 = 0,
                .access = PL1_R|PL3_W, .resetvalue = cpu->reset_cbar,
                .fieldoffset = offsetof(CPUARMState,
                                        cp15.c15_config_base_address)
            };
            if (arm_feature(env, ARM_FEATURE_CBAR_RO)) {
                cbar.access = PL1_R;
                cbar.fieldoffset = 0;
                cbar.type = ARM_CP_CONST;
            }
            define_one_arm_cp_reg(cpu, &cbar);
        }
    }

    if (arm_feature(env, ARM_FEATURE_VBAR)) {
        ARMCPRegInfo vbar_cp_reginfo[] = {
            { .name = "VBAR", .state = ARM_CP_STATE_BOTH,
              .opc0 = 3, .crn = 12, .crm = 0, .opc1 = 0, .opc2 = 0,
              .access = PL1_RW, .writefn = vbar_write,
              .bank_fieldoffsets = { offsetof(CPUARMState, cp15.vbar_s),
                                     offsetof(CPUARMState, cp15.vbar_ns) },
              .resetvalue = 0 },
            REGINFO_SENTINEL
        };
        define_arm_cp_regs(cpu, vbar_cp_reginfo);
    }

    /* Generic registers whose values depend on the implementation */
    {
        ARMCPRegInfo sctlr = {
            .name = "SCTLR", .state = ARM_CP_STATE_BOTH,
            .opc0 = 3, .opc1 = 0, .crn = 1, .crm = 0, .opc2 = 0,
            .access = PL1_RW,
            .bank_fieldoffsets = { offsetof(CPUARMState, cp15.sctlr_s),
                                   offsetof(CPUARMState, cp15.sctlr_ns) },
            .writefn = sctlr_write, .resetvalue = cpu->reset_sctlr,
            .raw_writefn = raw_write,
        };
        if (arm_feature(env, ARM_FEATURE_XSCALE)) {
            /* Normally we would always end the TB on an SCTLR write, but Linux
             * arch/arm/mach-pxa/sleep.S expects two instructions following
             * an MMU enable to execute from cache.  Imitate this behaviour.
             */
            sctlr.type |= ARM_CP_SUPPRESS_TB_END;
        }
        define_one_arm_cp_reg(cpu, &sctlr);
    }
}

ARMCPU *cpu_arm_init(const char *cpu_model)
{
    return ARM_CPU(cpu_generic_init(TYPE_ARM_CPU, cpu_model));
}

#ifndef CONFIG_LIBTCG
void arm_cpu_register_gdb_regs_for_features(ARMCPU *cpu)
{
    CPUState *cs = CPU(cpu);
    CPUARMState *env = &cpu->env;

    if (arm_feature(env, ARM_FEATURE_AARCH64)) {
        gdb_register_coprocessor(cs, aarch64_fpu_gdb_get_reg,
                                 aarch64_fpu_gdb_set_reg,
                                 34, "aarch64-fpu.xml", 0);
    } else if (arm_feature(env, ARM_FEATURE_NEON)) {
        gdb_register_coprocessor(cs, vfp_gdb_get_reg, vfp_gdb_set_reg,
                                 51, "arm-neon.xml", 0);
    } else if (arm_feature(env, ARM_FEATURE_VFP3)) {
        gdb_register_coprocessor(cs, vfp_gdb_get_reg, vfp_gdb_set_reg,
                                 35, "arm-vfp3.xml", 0);
    } else if (arm_feature(env, ARM_FEATURE_VFP)) {
        gdb_register_coprocessor(cs, vfp_gdb_get_reg, vfp_gdb_set_reg,
                                 19, "arm-vfp.xml", 0);
    }
}
#endif

/* Sort alphabetically by type name, except for "any". */
static gint arm_cpu_list_compare(gconstpointer a, gconstpointer b)
{
    ObjectClass *class_a = (ObjectClass *)a;
    ObjectClass *class_b = (ObjectClass *)b;
    const char *name_a, *name_b;

    name_a = object_class_get_name(class_a);
    name_b = object_class_get_name(class_b);
    if (strcmp(name_a, "any-" TYPE_ARM_CPU) == 0) {
        return 1;
    } else if (strcmp(name_b, "any-" TYPE_ARM_CPU) == 0) {
        return -1;
    } else {
        return strcmp(name_a, name_b);
    }
}

static void arm_cpu_list_entry(gpointer data, gpointer user_data)
{
    ObjectClass *oc = data;
    CPUListState *s = user_data;
    const char *typename;
    char *name;

    typename = object_class_get_name(oc);
    name = g_strndup(typename, strlen(typename) - strlen("-" TYPE_ARM_CPU));
    (*s->cpu_fprintf)(s->file, "  %s\n",
                      name);
    g_free(name);
}

void arm_cpu_list(FILE *f, fprintf_function cpu_fprintf)
{
    CPUListState s = {
        .file = f,
        .cpu_fprintf = cpu_fprintf,
    };
    GSList *list;

    list = object_class_get_list(TYPE_ARM_CPU, false);
    list = g_slist_sort(list, arm_cpu_list_compare);
    (*cpu_fprintf)(f, "Available CPUs:\n");
    g_slist_foreach(list, arm_cpu_list_entry, &s);
    g_slist_free(list);
#ifdef CONFIG_KVM
    /* The 'host' CPU type is dynamically registered only if KVM is
     * enabled, so we have to special-case it here:
     */
    (*cpu_fprintf)(f, "  host (only available in KVM mode)\n");
#endif
}

static void arm_cpu_add_definition(gpointer data, gpointer user_data)
{
    ObjectClass *oc = data;
    CpuDefinitionInfoList **cpu_list = user_data;
    CpuDefinitionInfoList *entry;
    CpuDefinitionInfo *info;
    const char *typename;

    typename = object_class_get_name(oc);
    info = g_malloc0(sizeof(*info));
    info->name = g_strndup(typename,
                           strlen(typename) - strlen("-" TYPE_ARM_CPU));
    info->q_typename = g_strdup(typename);

    entry = g_malloc0(sizeof(*entry));
    entry->value = info;
    entry->next = *cpu_list;
    *cpu_list = entry;
}

CpuDefinitionInfoList *arch_query_cpu_definitions(Error **errp)
{
    CpuDefinitionInfoList *cpu_list = NULL;
    GSList *list;

    list = object_class_get_list(TYPE_ARM_CPU, false);
    g_slist_foreach(list, arm_cpu_add_definition, &cpu_list);
    g_slist_free(list);

    return cpu_list;
}

static void add_cpreg_to_hashtable(ARMCPU *cpu, const ARMCPRegInfo *r,
                                   void *opaque, int state, int secstate,
                                   int crm, int opc1, int opc2)
{
    /* Private utility function for define_one_arm_cp_reg_with_opaque():
     * add a single reginfo struct to the hash table.
     */
    uint32_t *key = g_new(uint32_t, 1);
    ARMCPRegInfo *r2 = g_memdup(r, sizeof(ARMCPRegInfo));
    int is64 = (r->type & ARM_CP_64BIT) ? 1 : 0;
    int ns = (secstate & ARM_CP_SECSTATE_NS) ? 1 : 0;

    /* Reset the secure state to the specific incoming state.  This is
     * necessary as the register may have been defined with both states.
     */
    r2->secure = secstate;

    if (r->bank_fieldoffsets[0] && r->bank_fieldoffsets[1]) {
        /* Register is banked (using both entries in array).
         * Overwriting fieldoffset as the array is only used to define
         * banked registers but later only fieldoffset is used.
         */
        r2->fieldoffset = r->bank_fieldoffsets[ns];
    }

    if (state == ARM_CP_STATE_AA32) {
        if (r->bank_fieldoffsets[0] && r->bank_fieldoffsets[1]) {
            /* If the register is banked then we don't need to migrate or
             * reset the 32-bit instance in certain cases:
             *
             * 1) If the register has both 32-bit and 64-bit instances then we
             *    can count on the 64-bit instance taking care of the
             *    non-secure bank.
             * 2) If ARMv8 is enabled then we can count on a 64-bit version
             *    taking care of the secure bank.  This requires that separate
             *    32 and 64-bit definitions are provided.
             */
            if ((r->state == ARM_CP_STATE_BOTH && ns) ||
                (arm_feature(&cpu->env, ARM_FEATURE_V8) && !ns)) {
                r2->type |= ARM_CP_ALIAS;
            }
        } else if ((secstate != r->secure) && !ns) {
            /* The register is not banked so we only want to allow migration of
             * the non-secure instance.
             */
            r2->type |= ARM_CP_ALIAS;
        }

        if (r->state == ARM_CP_STATE_BOTH) {
            /* We assume it is a cp15 register if the .cp field is left unset.
             */
            if (r2->cp == 0) {
                r2->cp = 15;
            }

#ifdef HOST_WORDS_BIGENDIAN
            if (r2->fieldoffset) {
                r2->fieldoffset += sizeof(uint32_t);
            }
#endif
        }
    }
    if (state == ARM_CP_STATE_AA64) {
        /* To allow abbreviation of ARMCPRegInfo
         * definitions, we treat cp == 0 as equivalent to
         * the value for "standard guest-visible sysreg".
         * STATE_BOTH definitions are also always "standard
         * sysreg" in their AArch64 view (the .cp value may
         * be non-zero for the benefit of the AArch32 view).
         */
        if (r->cp == 0 || r->state == ARM_CP_STATE_BOTH) {
            r2->cp = CP_REG_ARM64_SYSREG_CP;
        }
        *key = ENCODE_AA64_CP_REG(r2->cp, r2->crn, crm,
                                  r2->opc0, opc1, opc2);
    } else {
        *key = ENCODE_CP_REG(r2->cp, is64, ns, r2->crn, crm, opc1, opc2);
    }
    if (opaque) {
        r2->opaque = opaque;
    }
    /* reginfo passed to helpers is correct for the actual access,
     * and is never ARM_CP_STATE_BOTH:
     */
    r2->state = state;
    /* Make sure reginfo passed to helpers for wildcarded regs
     * has the correct crm/opc1/opc2 for this reg, not CP_ANY:
     */
    r2->crm = crm;
    r2->opc1 = opc1;
    r2->opc2 = opc2;
    /* By convention, for wildcarded registers only the first
     * entry is used for migration; the others are marked as
     * ALIAS so we don't try to transfer the register
     * multiple times. Special registers (ie NOP/WFI) are
     * never migratable and not even raw-accessible.
     */
    if ((r->type & ARM_CP_SPECIAL)) {
        r2->type |= ARM_CP_NO_RAW;
    }
    if (((r->crm == CP_ANY) && crm != 0) ||
        ((r->opc1 == CP_ANY) && opc1 != 0) ||
        ((r->opc2 == CP_ANY) && opc2 != 0)) {
        r2->type |= ARM_CP_ALIAS;
    }

#ifndef CONFIG_LIBTCG
    /* Check that raw accesses are either forbidden or handled. Note that
     * we can't assert this earlier because the setup of fieldoffset for
     * banked registers has to be done first.
     */
    if (!(r2->type & ARM_CP_NO_RAW)) {
        assert(!raw_accessors_invalid(r2));
    }
#endif

    /* Overriding of an existing definition must be explicitly
     * requested.
     */
    if (!(r->type & ARM_CP_OVERRIDE)) {
        ARMCPRegInfo *oldreg;
        oldreg = g_hash_table_lookup(cpu->cp_regs, key);
        if (oldreg && !(oldreg->type & ARM_CP_OVERRIDE)) {
            fprintf(stderr, "Register redefined: cp=%d %d bit "
                    "crn=%d crm=%d opc1=%d opc2=%d, "
                    "was %s, now %s\n", r2->cp, 32 + 32 * is64,
                    r2->crn, r2->crm, r2->opc1, r2->opc2,
                    oldreg->name, r2->name);
            g_assert_not_reached();
        }
    }
    g_hash_table_insert(cpu->cp_regs, key, r2);
}


void define_one_arm_cp_reg_with_opaque(ARMCPU *cpu,
                                       const ARMCPRegInfo *r, void *opaque)
{
    /* Define implementations of coprocessor registers.
     * We store these in a hashtable because typically
     * there are less than 150 registers in a space which
     * is 16*16*16*8*8 = 262144 in size.
     * Wildcarding is supported for the crm, opc1 and opc2 fields.
     * If a register is defined twice then the second definition is
     * used, so this can be used to define some generic registers and
     * then override them with implementation specific variations.
     * At least one of the original and the second definition should
     * include ARM_CP_OVERRIDE in its type bits -- this is just a guard
     * against accidental use.
     *
     * The state field defines whether the register is to be
     * visible in the AArch32 or AArch64 execution state. If the
     * state is set to ARM_CP_STATE_BOTH then we synthesise a
     * reginfo structure for the AArch32 view, which sees the lower
     * 32 bits of the 64 bit register.
     *
     * Only registers visible in AArch64 may set r->opc0; opc0 cannot
     * be wildcarded. AArch64 registers are always considered to be 64
     * bits; the ARM_CP_64BIT* flag applies only to the AArch32 view of
     * the register, if any.
     */
    int crm, opc1, opc2, state;
    int crmmin = (r->crm == CP_ANY) ? 0 : r->crm;
    int crmmax = (r->crm == CP_ANY) ? 15 : r->crm;
    int opc1min = (r->opc1 == CP_ANY) ? 0 : r->opc1;
    int opc1max = (r->opc1 == CP_ANY) ? 7 : r->opc1;
    int opc2min = (r->opc2 == CP_ANY) ? 0 : r->opc2;
    int opc2max = (r->opc2 == CP_ANY) ? 7 : r->opc2;
    /* 64 bit registers have only CRm and Opc1 fields */
    assert(!((r->type & ARM_CP_64BIT) && (r->opc2 || r->crn)));
    /* op0 only exists in the AArch64 encodings */
    assert((r->state != ARM_CP_STATE_AA32) || (r->opc0 == 0));
    /* AArch64 regs are all 64 bit so ARM_CP_64BIT is meaningless */
    assert((r->state != ARM_CP_STATE_AA64) || !(r->type & ARM_CP_64BIT));
    /* The AArch64 pseudocode CheckSystemAccess() specifies that op1
     * encodes a minimum access level for the register. We roll this
     * runtime check into our general permission check code, so check
     * here that the reginfo's specified permissions are strict enough
     * to encompass the generic architectural permission check.
     */
    if (r->state != ARM_CP_STATE_AA32) {
        int mask = 0;
        switch (r->opc1) {
        case 0: case 1: case 2:
            /* min_EL EL1 */
            mask = PL1_RW;
            break;
        case 3:
            /* min_EL EL0 */
            mask = PL0_RW;
            break;
        case 4:
            /* min_EL EL2 */
            mask = PL2_RW;
            break;
        case 5:
            /* unallocated encoding, so not possible */
            assert(false);
            break;
        case 6:
            /* min_EL EL3 */
            mask = PL3_RW;
            break;
        case 7:
            /* min_EL EL1, secure mode only (we don't check the latter) */
            mask = PL1_RW;
            break;
        default:
            /* broken reginfo with out-of-range opc1 */
            assert(false);
            break;
        }
        /* assert our permissions are not too lax (stricter is fine) */
        assert((r->access & ~mask) == 0);
    }

#ifndef CONFIG_LIBTCG
    /* Check that the register definition has enough info to handle
     * reads and writes if they are permitted.
     */
    if (!(r->type & (ARM_CP_SPECIAL|ARM_CP_CONST))) {
        if (r->access & PL3_R) {
            assert((r->fieldoffset ||
                   (r->bank_fieldoffsets[0] && r->bank_fieldoffsets[1])) ||
                   r->readfn);
        }
        if (r->access & PL3_W) {
            assert((r->fieldoffset ||
                   (r->bank_fieldoffsets[0] && r->bank_fieldoffsets[1])) ||
                   r->writefn);
        }
    }
#endif
    /* Bad type field probably means missing sentinel at end of reg list */
    assert(cptype_valid(r->type));
    for (crm = crmmin; crm <= crmmax; crm++) {
        for (opc1 = opc1min; opc1 <= opc1max; opc1++) {
            for (opc2 = opc2min; opc2 <= opc2max; opc2++) {
                for (state = ARM_CP_STATE_AA32;
                     state <= ARM_CP_STATE_AA64; state++) {
                    if (r->state != state && r->state != ARM_CP_STATE_BOTH) {
                        continue;
                    }
                    if (state == ARM_CP_STATE_AA32) {
                        /* Under AArch32 CP registers can be common
                         * (same for secure and non-secure world) or banked.
                         */
                        switch (r->secure) {
                        case ARM_CP_SECSTATE_S:
                        case ARM_CP_SECSTATE_NS:
                            add_cpreg_to_hashtable(cpu, r, opaque, state,
                                                   r->secure, crm, opc1, opc2);
                            break;
                        default:
                            add_cpreg_to_hashtable(cpu, r, opaque, state,
                                                   ARM_CP_SECSTATE_S,
                                                   crm, opc1, opc2);
                            add_cpreg_to_hashtable(cpu, r, opaque, state,
                                                   ARM_CP_SECSTATE_NS,
                                                   crm, opc1, opc2);
                            break;
                        }
                    } else {
                        /* AArch64 registers get mapped to non-secure instance
                         * of AArch32 */
                        add_cpreg_to_hashtable(cpu, r, opaque, state,
                                               ARM_CP_SECSTATE_NS,
                                               crm, opc1, opc2);
                    }
                }
            }
        }
    }
}

void define_arm_cp_regs_with_opaque(ARMCPU *cpu,
                                    const ARMCPRegInfo *regs, void *opaque)
{
    /* Define a whole list of registers */
    const ARMCPRegInfo *r;
    for (r = regs; r->type != ARM_CP_SENTINEL; r++) {
        define_one_arm_cp_reg_with_opaque(cpu, r, opaque);
    }
}

void arm_cp_write_ignore(CPUARMState *env, const ARMCPRegInfo *ri,
                         uint64_t value)
{
    /* Helper coprocessor write function for write-ignore registers */
}

uint64_t arm_cp_read_zero(CPUARMState *env, const ARMCPRegInfo *ri)
{
    /* Helper coprocessor write function for read-as-zero registers */
    return 0;
}

void arm_cp_reset_ignore(CPUARMState *env, const ARMCPRegInfo *opaque)
{
    /* Helper coprocessor reset function for do-nothing-on-reset registers */
}

#ifndef CONFIG_LIBTCG
static int bad_mode_switch(CPUARMState *env, int mode, CPSRWriteType write_type)
{
    /* Return true if it is not valid for us to switch to
     * this CPU mode (ie all the UNPREDICTABLE cases in
     * the ARM ARM CPSRWriteByInstr pseudocode).
     */

    /* Changes to or from Hyp via MSR and CPS are illegal. */
    if (write_type == CPSRWriteByInstr &&
        ((env->uncached_cpsr & CPSR_M) == ARM_CPU_MODE_HYP ||
         mode == ARM_CPU_MODE_HYP)) {
        return 1;
    }

    switch (mode) {
    case ARM_CPU_MODE_USR:
        return 0;
    case ARM_CPU_MODE_SYS:
    case ARM_CPU_MODE_SVC:
    case ARM_CPU_MODE_ABT:
    case ARM_CPU_MODE_UND:
    case ARM_CPU_MODE_IRQ:
    case ARM_CPU_MODE_FIQ:
        /* Note that we don't implement the IMPDEF NSACR.RFR which in v7
         * allows FIQ mode to be Secure-only. (In v8 this doesn't exist.)
         */
        /* If HCR.TGE is set then changes from Monitor to NS PL1 via MSR
         * and CPS are treated as illegal mode changes.
         */
        if (write_type == CPSRWriteByInstr &&
            (env->cp15.hcr_el2 & HCR_TGE) &&
            (env->uncached_cpsr & CPSR_M) == ARM_CPU_MODE_MON &&
            !arm_is_secure_below_el3(env)) {
            return 1;
        }
        return 0;
    case ARM_CPU_MODE_HYP:
        return !arm_feature(env, ARM_FEATURE_EL2)
            || arm_current_el(env) < 2 || arm_is_secure(env);
    case ARM_CPU_MODE_MON:
        return arm_current_el(env) < 3;
    default:
        return 1;
    }
}

uint32_t cpsr_read(CPUARMState *env)
{
    int ZF;
    ZF = (env->ZF == 0);
    return env->uncached_cpsr | (env->NF & 0x80000000) | (ZF << 30) |
        (env->CF << 29) | ((env->VF & 0x80000000) >> 3) | (env->QF << 27)
        | (env->thumb << 5) | ((env->condexec_bits & 3) << 25)
        | ((env->condexec_bits & 0xfc) << 8)
        | (env->GE << 16) | (env->daif & CPSR_AIF);
}

void cpsr_write(CPUARMState *env, uint32_t val, uint32_t mask,
                CPSRWriteType write_type)
{
    uint32_t changed_daif;

    if (mask & CPSR_NZCV) {
        env->ZF = (~val) & CPSR_Z;
        env->NF = val;
        env->CF = (val >> 29) & 1;
        env->VF = (val << 3) & 0x80000000;
    }
    if (mask & CPSR_Q)
        env->QF = ((val & CPSR_Q) != 0);
    if (mask & CPSR_T)
        env->thumb = ((val & CPSR_T) != 0);
    if (mask & CPSR_IT_0_1) {
        env->condexec_bits &= ~3;
        env->condexec_bits |= (val >> 25) & 3;
    }
    if (mask & CPSR_IT_2_7) {
        env->condexec_bits &= 3;
        env->condexec_bits |= (val >> 8) & 0xfc;
    }
    if (mask & CPSR_GE) {
        env->GE = (val >> 16) & 0xf;
    }

    /* In a V7 implementation that includes the security extensions but does
     * not include Virtualization Extensions the SCR.FW and SCR.AW bits control
     * whether non-secure software is allowed to change the CPSR_F and CPSR_A
     * bits respectively.
     *
     * In a V8 implementation, it is permitted for privileged software to
     * change the CPSR A/F bits regardless of the SCR.AW/FW bits.
     */
    if (write_type != CPSRWriteRaw && !arm_feature(env, ARM_FEATURE_V8) &&
        arm_feature(env, ARM_FEATURE_EL3) &&
        !arm_feature(env, ARM_FEATURE_EL2) &&
        !arm_is_secure(env)) {

        changed_daif = (env->daif ^ val) & mask;

        if (changed_daif & CPSR_A) {
            /* Check to see if we are allowed to change the masking of async
             * abort exceptions from a non-secure state.
             */
            if (!(env->cp15.scr_el3 & SCR_AW)) {
                qemu_log_mask(LOG_GUEST_ERROR,
                              "Ignoring attempt to switch CPSR_A flag from "
                              "non-secure world with SCR.AW bit clear\n");
                mask &= ~CPSR_A;
            }
        }

        if (changed_daif & CPSR_F) {
            /* Check to see if we are allowed to change the masking of FIQ
             * exceptions from a non-secure state.
             */
            if (!(env->cp15.scr_el3 & SCR_FW)) {
                qemu_log_mask(LOG_GUEST_ERROR,
                              "Ignoring attempt to switch CPSR_F flag from "
                              "non-secure world with SCR.FW bit clear\n");
                mask &= ~CPSR_F;
            }

            /* Check whether non-maskable FIQ (NMFI) support is enabled.
             * If this bit is set software is not allowed to mask
             * FIQs, but is allowed to set CPSR_F to 0.
             */
            if ((A32_BANKED_CURRENT_REG_GET(env, sctlr) & SCTLR_NMFI) &&
                (val & CPSR_F)) {
                qemu_log_mask(LOG_GUEST_ERROR,
                              "Ignoring attempt to enable CPSR_F flag "
                              "(non-maskable FIQ [NMFI] support enabled)\n");
                mask &= ~CPSR_F;
            }
        }
    }

    env->daif &= ~(CPSR_AIF & mask);
    env->daif |= val & CPSR_AIF & mask;

    if (write_type != CPSRWriteRaw &&
        ((env->uncached_cpsr ^ val) & mask & CPSR_M)) {
        if ((env->uncached_cpsr & CPSR_M) == ARM_CPU_MODE_USR) {
            /* Note that we can only get here in USR mode if this is a
             * gdb stub write; for this case we follow the architectural
             * behaviour for guest writes in USR mode of ignoring an attempt
             * to switch mode. (Those are caught by translate.c for writes
             * triggered by guest instructions.)
             */
            mask &= ~CPSR_M;
        } else if (bad_mode_switch(env, val & CPSR_M, write_type)) {
            /* Attempt to switch to an invalid mode: this is UNPREDICTABLE in
             * v7, and has defined behaviour in v8:
             *  + leave CPSR.M untouched
             *  + allow changes to the other CPSR fields
             *  + set PSTATE.IL
             * For user changes via the GDB stub, we don't set PSTATE.IL,
             * as this would be unnecessarily harsh for a user error.
             */
            mask &= ~CPSR_M;
            if (write_type != CPSRWriteByGDBStub &&
                arm_feature(env, ARM_FEATURE_V8)) {
                mask |= CPSR_IL;
                val |= CPSR_IL;
            }
        } else {
            switch_mode(env, val & CPSR_M);
        }
    }
    mask &= ~CACHED_CPSR_BITS;
    env->uncached_cpsr = (env->uncached_cpsr & ~mask) | (val & mask);
}
#endif
