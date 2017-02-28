#include "qemu/osdep.h"
#include "cpu.h"
#include "internals.h"
#include "exec/helper-proto.h"
#include "qemu/crc32c.h"
#include "arm_ldst.h"
#include <zlib.h> /* For crc32 */
#include "exec/semihost.h"
#include "sysemu/kvm.h"

#ifndef CONFIG_USER_ONLY
static bool get_phys_addr_lpae(CPUARMState *env, target_ulong address,
                               int access_type, ARMMMUIdx mmu_idx,
                               hwaddr *phys_ptr, MemTxAttrs *txattrs, int *prot,
                               target_ulong *page_size_ptr, uint32_t *fsr,
                               ARMMMUFaultInfo *fi);
#endif

/* Sign/zero extend */
uint32_t HELPER(sxtb16)(uint32_t x)
{
    uint32_t res;
    res = (uint16_t)(int8_t)x;
    res |= (uint32_t)(int8_t)(x >> 16) << 16;
    return res;
}

uint32_t HELPER(uxtb16)(uint32_t x)
{
    uint32_t res;
    res = (uint16_t)(uint8_t)x;
    res |= (uint32_t)(uint8_t)(x >> 16) << 16;
    return res;
}

int32_t HELPER(sdiv)(int32_t num, int32_t den)
{
    if (den == 0)
      return 0;
    if (num == INT_MIN && den == -1)
      return INT_MIN;
    return num / den;
}

uint32_t HELPER(udiv)(uint32_t num, uint32_t den)
{
    if (den == 0)
      return 0;
    return num / den;
}

uint32_t HELPER(rbit)(uint32_t x)
{
    return revbit32(x);
}

#if defined(CONFIG_USER_ONLY)

/* These should probably raise undefined insn exceptions.  */
void HELPER(v7m_msr)(CPUARMState *env, uint32_t reg, uint32_t val)
{
    ARMCPU *cpu = arm_env_get_cpu(env);

    cpu_abort(CPU(cpu), "v7m_msr %d\n", reg);
}

uint32_t HELPER(v7m_mrs)(CPUARMState *env, uint32_t reg)
{
    ARMCPU *cpu = arm_env_get_cpu(env);

    cpu_abort(CPU(cpu), "v7m_mrs %d\n", reg);
    return 0;
}

void switch_mode(CPUARMState *env, int mode)
{
    ARMCPU *cpu = arm_env_get_cpu(env);

    if (mode != ARM_CPU_MODE_USR) {
        cpu_abort(CPU(cpu), "Tried to switch out of user mode\n");
    }
}

uint32_t arm_phys_excp_target_el(CPUState *cs, uint32_t excp_idx,
                                 uint32_t cur_el, bool secure)
{
    return 1;
}

void aarch64_sync_64_to_32(CPUARMState *env)
{
    g_assert_not_reached();
}

#else

void switch_mode(CPUARMState *env, int mode)
{
    int old_mode;
    int i;

    old_mode = env->uncached_cpsr & CPSR_M;
    if (mode == old_mode)
        return;

    if (old_mode == ARM_CPU_MODE_FIQ) {
        memcpy (env->fiq_regs, env->regs + 8, 5 * sizeof(uint32_t));
        memcpy (env->regs + 8, env->usr_regs, 5 * sizeof(uint32_t));
    } else if (mode == ARM_CPU_MODE_FIQ) {
        memcpy (env->usr_regs, env->regs + 8, 5 * sizeof(uint32_t));
        memcpy (env->regs + 8, env->fiq_regs, 5 * sizeof(uint32_t));
    }

    i = bank_number(old_mode);
    env->banked_r13[i] = env->regs[13];
    env->banked_r14[i] = env->regs[14];
    env->banked_spsr[i] = env->spsr;

    i = bank_number(mode);
    env->regs[13] = env->banked_r13[i];
    env->regs[14] = env->banked_r14[i];
    env->spsr = env->banked_spsr[i];
}

/* Physical Interrupt Target EL Lookup Table
 *
 * [ From ARM ARM section G1.13.4 (Table G1-15) ]
 *
 * The below multi-dimensional table is used for looking up the target
 * exception level given numerous condition criteria.  Specifically, the
 * target EL is based on SCR and HCR routing controls as well as the
 * currently executing EL and secure state.
 *
 *    Dimensions:
 *    target_el_table[2][2][2][2][2][4]
 *                    |  |  |  |  |  +--- Current EL
 *                    |  |  |  |  +------ Non-secure(0)/Secure(1)
 *                    |  |  |  +--------- HCR mask override
 *                    |  |  +------------ SCR exec state control
 *                    |  +--------------- SCR mask override
 *                    +------------------ 32-bit(0)/64-bit(1) EL3
 *
 *    The table values are as such:
 *    0-3 = EL0-EL3
 *     -1 = Cannot occur
 *
 * The ARM ARM target EL table includes entries indicating that an "exception
 * is not taken".  The two cases where this is applicable are:
 *    1) An exception is taken from EL3 but the SCR does not have the exception
 *    routed to EL3.
 *    2) An exception is taken from EL2 but the HCR does not have the exception
 *    routed to EL2.
 * In these two cases, the below table contain a target of EL1.  This value is
 * returned as it is expected that the consumer of the table data will check
 * for "target EL >= current EL" to ensure the exception is not taken.
 *
 *            SCR     HCR
 *         64  EA     AMO                 From
 *        BIT IRQ     IMO      Non-secure         Secure
 *        EL3 FIQ  RW FMO   EL0 EL1 EL2 EL3   EL0 EL1 EL2 EL3
 */
static const int8_t target_el_table[2][2][2][2][2][4] = {
    {{{{/* 0   0   0   0 */{ 1,  1,  2, -1 },{ 3, -1, -1,  3 },},
       {/* 0   0   0   1 */{ 2,  2,  2, -1 },{ 3, -1, -1,  3 },},},
      {{/* 0   0   1   0 */{ 1,  1,  2, -1 },{ 3, -1, -1,  3 },},
       {/* 0   0   1   1 */{ 2,  2,  2, -1 },{ 3, -1, -1,  3 },},},},
     {{{/* 0   1   0   0 */{ 3,  3,  3, -1 },{ 3, -1, -1,  3 },},
       {/* 0   1   0   1 */{ 3,  3,  3, -1 },{ 3, -1, -1,  3 },},},
      {{/* 0   1   1   0 */{ 3,  3,  3, -1 },{ 3, -1, -1,  3 },},
       {/* 0   1   1   1 */{ 3,  3,  3, -1 },{ 3, -1, -1,  3 },},},},},
    {{{{/* 1   0   0   0 */{ 1,  1,  2, -1 },{ 1,  1, -1,  1 },},
       {/* 1   0   0   1 */{ 2,  2,  2, -1 },{ 1,  1, -1,  1 },},},
      {{/* 1   0   1   0 */{ 1,  1,  1, -1 },{ 1,  1, -1,  1 },},
       {/* 1   0   1   1 */{ 2,  2,  2, -1 },{ 1,  1, -1,  1 },},},},
     {{{/* 1   1   0   0 */{ 3,  3,  3, -1 },{ 3,  3, -1,  3 },},
       {/* 1   1   0   1 */{ 3,  3,  3, -1 },{ 3,  3, -1,  3 },},},
      {{/* 1   1   1   0 */{ 3,  3,  3, -1 },{ 3,  3, -1,  3 },},
       {/* 1   1   1   1 */{ 3,  3,  3, -1 },{ 3,  3, -1,  3 },},},},},
};

/*
 * Determine the target EL for physical exceptions
 */
uint32_t arm_phys_excp_target_el(CPUState *cs, uint32_t excp_idx,
                                 uint32_t cur_el, bool secure)
{
    CPUARMState *env = cs->env_ptr;
    int rw;
    int scr;
    int hcr;
    int target_el;
    /* Is the highest EL AArch64? */
    int is64 = arm_feature(env, ARM_FEATURE_AARCH64);

    if (arm_feature(env, ARM_FEATURE_EL3)) {
        rw = ((env->cp15.scr_el3 & SCR_RW) == SCR_RW);
    } else {
        /* Either EL2 is the highest EL (and so the EL2 register width
         * is given by is64); or there is no EL2 or EL3, in which case
         * the value of 'rw' does not affect the table lookup anyway.
         */
        rw = is64;
    }

    switch (excp_idx) {
    case EXCP_IRQ:
        scr = ((env->cp15.scr_el3 & SCR_IRQ) == SCR_IRQ);
        hcr = ((env->cp15.hcr_el2 & HCR_IMO) == HCR_IMO);
        break;
    case EXCP_FIQ:
        scr = ((env->cp15.scr_el3 & SCR_FIQ) == SCR_FIQ);
        hcr = ((env->cp15.hcr_el2 & HCR_FMO) == HCR_FMO);
        break;
    default:
        scr = ((env->cp15.scr_el3 & SCR_EA) == SCR_EA);
        hcr = ((env->cp15.hcr_el2 & HCR_AMO) == HCR_AMO);
        break;
    };

    /* If HCR.TGE is set then HCR is treated as being 1 */
    hcr |= ((env->cp15.hcr_el2 & HCR_TGE) == HCR_TGE);

    /* Perform a table-lookup for the target EL given the current state */
    target_el = target_el_table[is64][scr][rw][hcr][secure][cur_el];

    assert(target_el > 0);

    return target_el;
}

static void v7m_push(CPUARMState *env, uint32_t val)
{
    CPUState *cs = CPU(arm_env_get_cpu(env));

    env->regs[13] -= 4;
    stl_phys(cs->as, env->regs[13], val);
}

static uint32_t v7m_pop(CPUARMState *env)
{
    CPUState *cs = CPU(arm_env_get_cpu(env));
    uint32_t val;

    val = ldl_phys(cs->as, env->regs[13]);
    env->regs[13] += 4;
    return val;
}

/* Switch to V7M main or process stack pointer.  */
static void switch_v7m_sp(CPUARMState *env, bool new_spsel)
{
    uint32_t tmp;
    bool old_spsel = env->v7m.control & R_V7M_CONTROL_SPSEL_MASK;

    if (old_spsel != new_spsel) {
        tmp = env->v7m.other_sp;
        env->v7m.other_sp = env->regs[13];
        env->regs[13] = tmp;

        env->v7m.control = deposit32(env->v7m.control,
                                     R_V7M_CONTROL_SPSEL_SHIFT,
                                     R_V7M_CONTROL_SPSEL_LENGTH, new_spsel);
    }
}

static void do_v7m_exception_exit(CPUARMState *env)
{
    uint32_t type;
    uint32_t xpsr;

    type = env->regs[15];
    if (env->v7m.exception != ARMV7M_EXCP_NMI) {
        /* Auto-clear FAULTMASK on return from other than NMI */
        env->daif &= ~PSTATE_F;
    }
    if (env->v7m.exception != 0) {
        armv7m_nvic_complete_irq(env->nvic, env->v7m.exception);
    }

    /* Switch to the target stack.  */
    switch_v7m_sp(env, (type & 4) != 0);
    /* Pop registers.  */
    env->regs[0] = v7m_pop(env);
    env->regs[1] = v7m_pop(env);
    env->regs[2] = v7m_pop(env);
    env->regs[3] = v7m_pop(env);
    env->regs[12] = v7m_pop(env);
    env->regs[14] = v7m_pop(env);
    env->regs[15] = v7m_pop(env);
    if (env->regs[15] & 1) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "M profile return from interrupt with misaligned "
                      "PC is UNPREDICTABLE\n");
        /* Actual hardware seems to ignore the lsbit, and there are several
         * RTOSes out there which incorrectly assume the r15 in the stack
         * frame should be a Thumb-style "lsbit indicates ARM/Thumb" value.
         */
        env->regs[15] &= ~1U;
    }
    xpsr = v7m_pop(env);
    xpsr_write(env, xpsr, 0xfffffdff);
    /* Undo stack alignment.  */
    if (xpsr & 0x200)
        env->regs[13] |= 4;
    /* ??? The exception return type specifies Thread/Handler mode.  However
       this is also implied by the xPSR value. Not sure what to do
       if there is a mismatch.  */
    /* ??? Likewise for mismatches between the CONTROL register and the stack
       pointer.  */
}

static void arm_log_exception(int idx)
{
    if (qemu_loglevel_mask(CPU_LOG_INT)) {
        const char *exc = NULL;

        if (idx >= 0 && idx < ARRAY_SIZE(excnames)) {
            exc = excnames[idx];
        }
        if (!exc) {
            exc = "unknown";
        }
        qemu_log_mask(CPU_LOG_INT, "Taking exception %d [%s]\n", idx, exc);
    }
}

static uint32_t arm_v7m_load_vector(ARMCPU *cpu)

{
    CPUState *cs = CPU(cpu);
    CPUARMState *env = &cpu->env;
    MemTxResult result;
    hwaddr vec = env->v7m.vecbase + env->v7m.exception * 4;
    uint32_t addr;

    addr = address_space_ldl(cs->as, vec,
                             MEMTXATTRS_UNSPECIFIED, &result);
    if (result != MEMTX_OK) {
        /* Architecturally this should cause a HardFault setting HSFR.VECTTBL,
         * which would then be immediately followed by our failing to load
         * the entry vector for that HardFault, which is a Lockup case.
         * Since we don't model Lockup, we just report this guest error
         * via cpu_abort().
         */
        cpu_abort(cs, "Failed to read from exception vector table "
                  "entry %08x\n", (unsigned)vec);
    }
    return addr;
}

void arm_v7m_cpu_do_interrupt(CPUState *cs)
{
    ARMCPU *cpu = ARM_CPU(cs);
    CPUARMState *env = &cpu->env;
    uint32_t xpsr = xpsr_read(env);
    uint32_t lr;
    uint32_t addr;

    arm_log_exception(cs->exception_index);

    lr = 0xfffffff1;
    if (env->v7m.control & R_V7M_CONTROL_SPSEL_MASK) {
        lr |= 4;
    }
    if (env->v7m.exception == 0)
        lr |= 8;

    /* For exceptions we just mark as pending on the NVIC, and let that
       handle it.  */
    /* TODO: Need to escalate if the current priority is higher than the
       one we're raising.  */
    switch (cs->exception_index) {
    case EXCP_UDEF:
        armv7m_nvic_set_pending(env->nvic, ARMV7M_EXCP_USAGE);
        env->v7m.cfsr |= R_V7M_CFSR_UNDEFINSTR_MASK;
        return;
    case EXCP_NOCP:
        armv7m_nvic_set_pending(env->nvic, ARMV7M_EXCP_USAGE);
        env->v7m.cfsr |= R_V7M_CFSR_NOCP_MASK;
        return;
    case EXCP_SWI:
        /* The PC already points to the next instruction.  */
        armv7m_nvic_set_pending(env->nvic, ARMV7M_EXCP_SVC);
        return;
    case EXCP_PREFETCH_ABORT:
    case EXCP_DATA_ABORT:
        /* TODO: if we implemented the MPU registers, this is where we
         * should set the MMFAR, etc from exception.fsr and exception.vaddress.
         */
        armv7m_nvic_set_pending(env->nvic, ARMV7M_EXCP_MEM);
        return;
    case EXCP_BKPT:
        if (semihosting_enabled()) {
            int nr;
            nr = arm_lduw_code(env, env->regs[15], arm_sctlr_b(env)) & 0xff;
            if (nr == 0xab) {
                env->regs[15] += 2;
                qemu_log_mask(CPU_LOG_INT,
                              "...handling as semihosting call 0x%x\n",
                              env->regs[0]);
                env->regs[0] = do_arm_semihosting(env);
                return;
            }
        }
        armv7m_nvic_set_pending(env->nvic, ARMV7M_EXCP_DEBUG);
        return;
    case EXCP_IRQ:
        env->v7m.exception = armv7m_nvic_acknowledge_irq(env->nvic);
        break;
    case EXCP_EXCEPTION_EXIT:
        do_v7m_exception_exit(env);
        return;
    default:
        cpu_abort(cs, "Unhandled exception 0x%x\n", cs->exception_index);
        return; /* Never happens.  Keep compiler happy.  */
    }

    /* Align stack pointer if the guest wants that */
    if ((env->regs[13] & 4) && (env->v7m.ccr & R_V7M_CCR_STKALIGN_MASK)) {
        env->regs[13] -= 4;
        xpsr |= 0x200;
    }
    /* Switch to the handler mode.  */
    v7m_push(env, xpsr);
    v7m_push(env, env->regs[15]);
    v7m_push(env, env->regs[14]);
    v7m_push(env, env->regs[12]);
    v7m_push(env, env->regs[3]);
    v7m_push(env, env->regs[2]);
    v7m_push(env, env->regs[1]);
    v7m_push(env, env->regs[0]);
    switch_v7m_sp(env, 0);
    /* Clear IT bits */
    env->condexec_bits = 0;
    env->regs[14] = lr;
    addr = arm_v7m_load_vector(cpu);
    env->regs[15] = addr & 0xfffffffe;
    env->thumb = addr & 1;
}

/* Function used to synchronize QEMU's AArch64 register set with AArch32
 * register set.  This is necessary when switching between AArch32 and AArch64
 * execution state.
 */
void aarch64_sync_32_to_64(CPUARMState *env)
{
    int i;
    uint32_t mode = env->uncached_cpsr & CPSR_M;

    /* We can blanket copy R[0:7] to X[0:7] */
    for (i = 0; i < 8; i++) {
        env->xregs[i] = env->regs[i];
    }

    /* Unless we are in FIQ mode, x8-x12 come from the user registers r8-r12.
     * Otherwise, they come from the banked user regs.
     */
    if (mode == ARM_CPU_MODE_FIQ) {
        for (i = 8; i < 13; i++) {
            env->xregs[i] = env->usr_regs[i - 8];
        }
    } else {
        for (i = 8; i < 13; i++) {
            env->xregs[i] = env->regs[i];
        }
    }

    /* Registers x13-x23 are the various mode SP and FP registers. Registers
     * r13 and r14 are only copied if we are in that mode, otherwise we copy
     * from the mode banked register.
     */
    if (mode == ARM_CPU_MODE_USR || mode == ARM_CPU_MODE_SYS) {
        env->xregs[13] = env->regs[13];
        env->xregs[14] = env->regs[14];
    } else {
        env->xregs[13] = env->banked_r13[bank_number(ARM_CPU_MODE_USR)];
        /* HYP is an exception in that it is copied from r14 */
        if (mode == ARM_CPU_MODE_HYP) {
            env->xregs[14] = env->regs[14];
        } else {
            env->xregs[14] = env->banked_r14[bank_number(ARM_CPU_MODE_USR)];
        }
    }

    if (mode == ARM_CPU_MODE_HYP) {
        env->xregs[15] = env->regs[13];
    } else {
        env->xregs[15] = env->banked_r13[bank_number(ARM_CPU_MODE_HYP)];
    }

    if (mode == ARM_CPU_MODE_IRQ) {
        env->xregs[16] = env->regs[14];
        env->xregs[17] = env->regs[13];
    } else {
        env->xregs[16] = env->banked_r14[bank_number(ARM_CPU_MODE_IRQ)];
        env->xregs[17] = env->banked_r13[bank_number(ARM_CPU_MODE_IRQ)];
    }

    if (mode == ARM_CPU_MODE_SVC) {
        env->xregs[18] = env->regs[14];
        env->xregs[19] = env->regs[13];
    } else {
        env->xregs[18] = env->banked_r14[bank_number(ARM_CPU_MODE_SVC)];
        env->xregs[19] = env->banked_r13[bank_number(ARM_CPU_MODE_SVC)];
    }

    if (mode == ARM_CPU_MODE_ABT) {
        env->xregs[20] = env->regs[14];
        env->xregs[21] = env->regs[13];
    } else {
        env->xregs[20] = env->banked_r14[bank_number(ARM_CPU_MODE_ABT)];
        env->xregs[21] = env->banked_r13[bank_number(ARM_CPU_MODE_ABT)];
    }

    if (mode == ARM_CPU_MODE_UND) {
        env->xregs[22] = env->regs[14];
        env->xregs[23] = env->regs[13];
    } else {
        env->xregs[22] = env->banked_r14[bank_number(ARM_CPU_MODE_UND)];
        env->xregs[23] = env->banked_r13[bank_number(ARM_CPU_MODE_UND)];
    }

    /* Registers x24-x30 are mapped to r8-r14 in FIQ mode.  If we are in FIQ
     * mode, then we can copy from r8-r14.  Otherwise, we copy from the
     * FIQ bank for r8-r14.
     */
    if (mode == ARM_CPU_MODE_FIQ) {
        for (i = 24; i < 31; i++) {
            env->xregs[i] = env->regs[i - 16];   /* X[24:30] <- R[8:14] */
        }
    } else {
        for (i = 24; i < 29; i++) {
            env->xregs[i] = env->fiq_regs[i - 24];
        }
        env->xregs[29] = env->banked_r13[bank_number(ARM_CPU_MODE_FIQ)];
        env->xregs[30] = env->banked_r14[bank_number(ARM_CPU_MODE_FIQ)];
    }

    env->pc = env->regs[15];
}

/* Function used to synchronize QEMU's AArch32 register set with AArch64
 * register set.  This is necessary when switching between AArch32 and AArch64
 * execution state.
 */
void aarch64_sync_64_to_32(CPUARMState *env)
{
    int i;
    uint32_t mode = env->uncached_cpsr & CPSR_M;

    /* We can blanket copy X[0:7] to R[0:7] */
    for (i = 0; i < 8; i++) {
        env->regs[i] = env->xregs[i];
    }

    /* Unless we are in FIQ mode, r8-r12 come from the user registers x8-x12.
     * Otherwise, we copy x8-x12 into the banked user regs.
     */
    if (mode == ARM_CPU_MODE_FIQ) {
        for (i = 8; i < 13; i++) {
            env->usr_regs[i - 8] = env->xregs[i];
        }
    } else {
        for (i = 8; i < 13; i++) {
            env->regs[i] = env->xregs[i];
        }
    }

    /* Registers r13 & r14 depend on the current mode.
     * If we are in a given mode, we copy the corresponding x registers to r13
     * and r14.  Otherwise, we copy the x register to the banked r13 and r14
     * for the mode.
     */
    if (mode == ARM_CPU_MODE_USR || mode == ARM_CPU_MODE_SYS) {
        env->regs[13] = env->xregs[13];
        env->regs[14] = env->xregs[14];
    } else {
        env->banked_r13[bank_number(ARM_CPU_MODE_USR)] = env->xregs[13];

        /* HYP is an exception in that it does not have its own banked r14 but
         * shares the USR r14
         */
        if (mode == ARM_CPU_MODE_HYP) {
            env->regs[14] = env->xregs[14];
        } else {
            env->banked_r14[bank_number(ARM_CPU_MODE_USR)] = env->xregs[14];
        }
    }

    if (mode == ARM_CPU_MODE_HYP) {
        env->regs[13] = env->xregs[15];
    } else {
        env->banked_r13[bank_number(ARM_CPU_MODE_HYP)] = env->xregs[15];
    }

    if (mode == ARM_CPU_MODE_IRQ) {
        env->regs[14] = env->xregs[16];
        env->regs[13] = env->xregs[17];
    } else {
        env->banked_r14[bank_number(ARM_CPU_MODE_IRQ)] = env->xregs[16];
        env->banked_r13[bank_number(ARM_CPU_MODE_IRQ)] = env->xregs[17];
    }

    if (mode == ARM_CPU_MODE_SVC) {
        env->regs[14] = env->xregs[18];
        env->regs[13] = env->xregs[19];
    } else {
        env->banked_r14[bank_number(ARM_CPU_MODE_SVC)] = env->xregs[18];
        env->banked_r13[bank_number(ARM_CPU_MODE_SVC)] = env->xregs[19];
    }

    if (mode == ARM_CPU_MODE_ABT) {
        env->regs[14] = env->xregs[20];
        env->regs[13] = env->xregs[21];
    } else {
        env->banked_r14[bank_number(ARM_CPU_MODE_ABT)] = env->xregs[20];
        env->banked_r13[bank_number(ARM_CPU_MODE_ABT)] = env->xregs[21];
    }

    if (mode == ARM_CPU_MODE_UND) {
        env->regs[14] = env->xregs[22];
        env->regs[13] = env->xregs[23];
    } else {
        env->banked_r14[bank_number(ARM_CPU_MODE_UND)] = env->xregs[22];
        env->banked_r13[bank_number(ARM_CPU_MODE_UND)] = env->xregs[23];
    }

    /* Registers x24-x30 are mapped to r8-r14 in FIQ mode.  If we are in FIQ
     * mode, then we can copy to r8-r14.  Otherwise, we copy to the
     * FIQ bank for r8-r14.
     */
    if (mode == ARM_CPU_MODE_FIQ) {
        for (i = 24; i < 31; i++) {
            env->regs[i - 16] = env->xregs[i];   /* X[24:30] -> R[8:14] */
        }
    } else {
        for (i = 24; i < 29; i++) {
            env->fiq_regs[i - 24] = env->xregs[i];
        }
        env->banked_r13[bank_number(ARM_CPU_MODE_FIQ)] = env->xregs[29];
        env->banked_r14[bank_number(ARM_CPU_MODE_FIQ)] = env->xregs[30];
    }

    env->regs[15] = env->pc;
}

static void arm_cpu_do_interrupt_aarch32(CPUState *cs)
{
    ARMCPU *cpu = ARM_CPU(cs);
    CPUARMState *env = &cpu->env;
    uint32_t addr;
    uint32_t mask;
    int new_mode;
    uint32_t offset;
    uint32_t moe;

    /* If this is a debug exception we must update the DBGDSCR.MOE bits */
    switch (env->exception.syndrome >> ARM_EL_EC_SHIFT) {
    case EC_BREAKPOINT:
    case EC_BREAKPOINT_SAME_EL:
        moe = 1;
        break;
    case EC_WATCHPOINT:
    case EC_WATCHPOINT_SAME_EL:
        moe = 10;
        break;
    case EC_AA32_BKPT:
        moe = 3;
        break;
    case EC_VECTORCATCH:
        moe = 5;
        break;
    default:
        moe = 0;
        break;
    }

    if (moe) {
        env->cp15.mdscr_el1 = deposit64(env->cp15.mdscr_el1, 2, 4, moe);
    }

    /* TODO: Vectored interrupt controller.  */
    switch (cs->exception_index) {
    case EXCP_UDEF:
        new_mode = ARM_CPU_MODE_UND;
        addr = 0x04;
        mask = CPSR_I;
        if (env->thumb)
            offset = 2;
        else
            offset = 4;
        break;
    case EXCP_SWI:
        new_mode = ARM_CPU_MODE_SVC;
        addr = 0x08;
        mask = CPSR_I;
        /* The PC already points to the next instruction.  */
        offset = 0;
        break;
    case EXCP_BKPT:
        env->exception.fsr = 2;
        /* Fall through to prefetch abort.  */
    case EXCP_PREFETCH_ABORT:
        A32_BANKED_CURRENT_REG_SET(env, ifsr, env->exception.fsr);
        A32_BANKED_CURRENT_REG_SET(env, ifar, env->exception.vaddress);
        qemu_log_mask(CPU_LOG_INT, "...with IFSR 0x%x IFAR 0x%x\n",
                      env->exception.fsr, (uint32_t)env->exception.vaddress);
        new_mode = ARM_CPU_MODE_ABT;
        addr = 0x0c;
        mask = CPSR_A | CPSR_I;
        offset = 4;
        break;
    case EXCP_DATA_ABORT:
        A32_BANKED_CURRENT_REG_SET(env, dfsr, env->exception.fsr);
        A32_BANKED_CURRENT_REG_SET(env, dfar, env->exception.vaddress);
        qemu_log_mask(CPU_LOG_INT, "...with DFSR 0x%x DFAR 0x%x\n",
                      env->exception.fsr,
                      (uint32_t)env->exception.vaddress);
        new_mode = ARM_CPU_MODE_ABT;
        addr = 0x10;
        mask = CPSR_A | CPSR_I;
        offset = 8;
        break;
    case EXCP_IRQ:
        new_mode = ARM_CPU_MODE_IRQ;
        addr = 0x18;
        /* Disable IRQ and imprecise data aborts.  */
        mask = CPSR_A | CPSR_I;
        offset = 4;
        if (env->cp15.scr_el3 & SCR_IRQ) {
            /* IRQ routed to monitor mode */
            new_mode = ARM_CPU_MODE_MON;
            mask |= CPSR_F;
        }
        break;
    case EXCP_FIQ:
        new_mode = ARM_CPU_MODE_FIQ;
        addr = 0x1c;
        /* Disable FIQ, IRQ and imprecise data aborts.  */
        mask = CPSR_A | CPSR_I | CPSR_F;
        if (env->cp15.scr_el3 & SCR_FIQ) {
            /* FIQ routed to monitor mode */
            new_mode = ARM_CPU_MODE_MON;
        }
        offset = 4;
        break;
    case EXCP_VIRQ:
        new_mode = ARM_CPU_MODE_IRQ;
        addr = 0x18;
        /* Disable IRQ and imprecise data aborts.  */
        mask = CPSR_A | CPSR_I;
        offset = 4;
        break;
    case EXCP_VFIQ:
        new_mode = ARM_CPU_MODE_FIQ;
        addr = 0x1c;
        /* Disable FIQ, IRQ and imprecise data aborts.  */
        mask = CPSR_A | CPSR_I | CPSR_F;
        offset = 4;
        break;
    case EXCP_SMC:
        new_mode = ARM_CPU_MODE_MON;
        addr = 0x08;
        mask = CPSR_A | CPSR_I | CPSR_F;
        offset = 0;
        break;
    default:
        cpu_abort(cs, "Unhandled exception 0x%x\n", cs->exception_index);
        return; /* Never happens.  Keep compiler happy.  */
    }

    if (new_mode == ARM_CPU_MODE_MON) {
        addr += env->cp15.mvbar;
    } else if (A32_BANKED_CURRENT_REG_GET(env, sctlr) & SCTLR_V) {
        /* High vectors. When enabled, base address cannot be remapped. */
        addr += 0xffff0000;
    } else {
        /* ARM v7 architectures provide a vector base address register to remap
         * the interrupt vector table.
         * This register is only followed in non-monitor mode, and is banked.
         * Note: only bits 31:5 are valid.
         */
        addr += A32_BANKED_CURRENT_REG_GET(env, vbar);
    }

    if ((env->uncached_cpsr & CPSR_M) == ARM_CPU_MODE_MON) {
        env->cp15.scr_el3 &= ~SCR_NS;
    }

    switch_mode (env, new_mode);
    /* For exceptions taken to AArch32 we must clear the SS bit in both
     * PSTATE and in the old-state value we save to SPSR_<mode>, so zero it now.
     */
    env->uncached_cpsr &= ~PSTATE_SS;
    env->spsr = cpsr_read(env);
    /* Clear IT bits.  */
    env->condexec_bits = 0;
    /* Switch to the new mode, and to the correct instruction set.  */
    env->uncached_cpsr = (env->uncached_cpsr & ~CPSR_M) | new_mode;
    /* Set new mode endianness */
    env->uncached_cpsr &= ~CPSR_E;
    if (env->cp15.sctlr_el[arm_current_el(env)] & SCTLR_EE) {
        env->uncached_cpsr |= CPSR_E;
    }
    env->daif |= mask;
    /* this is a lie, as the was no c1_sys on V4T/V5, but who cares
     * and we should just guard the thumb mode on V4 */
    if (arm_feature(env, ARM_FEATURE_V4T)) {
        env->thumb = (A32_BANKED_CURRENT_REG_GET(env, sctlr) & SCTLR_TE) != 0;
    }
    env->regs[14] = env->regs[15] + offset;
    env->regs[15] = addr;
}

/* Handle exception entry to a target EL which is using AArch64 */
static void arm_cpu_do_interrupt_aarch64(CPUState *cs)
{
    ARMCPU *cpu = ARM_CPU(cs);
    CPUARMState *env = &cpu->env;
    unsigned int new_el = env->exception.target_el;
    target_ulong addr = env->cp15.vbar_el[new_el];
    unsigned int new_mode = aarch64_pstate_mode(new_el, true);

    if (arm_current_el(env) < new_el) {
        /* Entry vector offset depends on whether the implemented EL
         * immediately lower than the target level is using AArch32 or AArch64
         */
        bool is_aa64;

        switch (new_el) {
        case 3:
            is_aa64 = (env->cp15.scr_el3 & SCR_RW) != 0;
            break;
        case 2:
            is_aa64 = (env->cp15.hcr_el2 & HCR_RW) != 0;
            break;
        case 1:
            is_aa64 = is_a64(env);
            break;
        default:
            g_assert_not_reached();
        }

        if (is_aa64) {
            addr += 0x400;
        } else {
            addr += 0x600;
        }
    } else if (pstate_read(env) & PSTATE_SP) {
        addr += 0x200;
    }

    switch (cs->exception_index) {
    case EXCP_PREFETCH_ABORT:
    case EXCP_DATA_ABORT:
        env->cp15.far_el[new_el] = env->exception.vaddress;
        qemu_log_mask(CPU_LOG_INT, "...with FAR 0x%" PRIx64 "\n",
                      env->cp15.far_el[new_el]);
        /* fall through */
    case EXCP_BKPT:
    case EXCP_UDEF:
    case EXCP_SWI:
    case EXCP_HVC:
    case EXCP_HYP_TRAP:
    case EXCP_SMC:
        env->cp15.esr_el[new_el] = env->exception.syndrome;
        break;
    case EXCP_IRQ:
    case EXCP_VIRQ:
        addr += 0x80;
        break;
    case EXCP_FIQ:
    case EXCP_VFIQ:
        addr += 0x100;
        break;
    case EXCP_SEMIHOST:
        qemu_log_mask(CPU_LOG_INT,
                      "...handling as semihosting call 0x%" PRIx64 "\n",
                      env->xregs[0]);
        env->xregs[0] = do_arm_semihosting(env);
        return;
    default:
        cpu_abort(cs, "Unhandled exception 0x%x\n", cs->exception_index);
    }

    if (is_a64(env)) {
        env->banked_spsr[aarch64_banked_spsr_index(new_el)] = pstate_read(env);
        aarch64_save_sp(env, arm_current_el(env));
        env->elr_el[new_el] = env->pc;
    } else {
        env->banked_spsr[aarch64_banked_spsr_index(new_el)] = cpsr_read(env);
        env->elr_el[new_el] = env->regs[15];

        aarch64_sync_32_to_64(env);

        env->condexec_bits = 0;
    }
    qemu_log_mask(CPU_LOG_INT, "...with ELR 0x%" PRIx64 "\n",
                  env->elr_el[new_el]);

    pstate_write(env, PSTATE_DAIF | new_mode);
    env->aarch64 = 1;
    aarch64_restore_sp(env, new_el);

    env->pc = addr;

    qemu_log_mask(CPU_LOG_INT, "...to EL%d PC 0x%" PRIx64 " PSTATE 0x%x\n",
                  new_el, env->pc, pstate_read(env));
}

static inline bool check_for_semihosting(CPUState *cs)
{
    /* Check whether this exception is a semihosting call; if so
     * then handle it and return true; otherwise return false.
     */
    ARMCPU *cpu = ARM_CPU(cs);
    CPUARMState *env = &cpu->env;

    if (is_a64(env)) {
        if (cs->exception_index == EXCP_SEMIHOST) {
            /* This is always the 64-bit semihosting exception.
             * The "is this usermode" and "is semihosting enabled"
             * checks have been done at translate time.
             */
            qemu_log_mask(CPU_LOG_INT,
                          "...handling as semihosting call 0x%" PRIx64 "\n",
                          env->xregs[0]);
            env->xregs[0] = do_arm_semihosting(env);
            return true;
        }
        return false;
    } else {
        uint32_t imm;

        /* Only intercept calls from privileged modes, to provide some
         * semblance of security.
         */
        if (cs->exception_index != EXCP_SEMIHOST &&
            (!semihosting_enabled() ||
             ((env->uncached_cpsr & CPSR_M) == ARM_CPU_MODE_USR))) {
            return false;
        }

        switch (cs->exception_index) {
        case EXCP_SEMIHOST:
            /* This is always a semihosting call; the "is this usermode"
             * and "is semihosting enabled" checks have been done at
             * translate time.
             */
            break;
        case EXCP_SWI:
            /* Check for semihosting interrupt.  */
            if (env->thumb) {
                imm = arm_lduw_code(env, env->regs[15] - 2, arm_sctlr_b(env))
                    & 0xff;
                if (imm == 0xab) {
                    break;
                }
            } else {
                imm = arm_ldl_code(env, env->regs[15] - 4, arm_sctlr_b(env))
                    & 0xffffff;
                if (imm == 0x123456) {
                    break;
                }
            }
            return false;
        case EXCP_BKPT:
            /* See if this is a semihosting syscall.  */
            if (env->thumb) {
                imm = arm_lduw_code(env, env->regs[15], arm_sctlr_b(env))
                    & 0xff;
                if (imm == 0xab) {
                    env->regs[15] += 2;
                    break;
                }
            }
            return false;
        default:
            return false;
        }

        qemu_log_mask(CPU_LOG_INT,
                      "...handling as semihosting call 0x%x\n",
                      env->regs[0]);
        env->regs[0] = do_arm_semihosting(env);
        return true;
    }
}

/* Handle a CPU exception for A and R profile CPUs.
 * Do any appropriate logging, handle PSCI calls, and then hand off
 * to the AArch64-entry or AArch32-entry function depending on the
 * target exception level's register width.
 */
void arm_cpu_do_interrupt(CPUState *cs)
{
    ARMCPU *cpu = ARM_CPU(cs);
    CPUARMState *env = &cpu->env;
    unsigned int new_el = env->exception.target_el;

    assert(!arm_feature(env, ARM_FEATURE_M));

    arm_log_exception(cs->exception_index);
    qemu_log_mask(CPU_LOG_INT, "...from EL%d to EL%d\n", arm_current_el(env),
                  new_el);
    if (qemu_loglevel_mask(CPU_LOG_INT)
        && !excp_is_internal(cs->exception_index)) {
        qemu_log_mask(CPU_LOG_INT, "...with ESR %x/0x%" PRIx32 "\n",
                      env->exception.syndrome >> ARM_EL_EC_SHIFT,
                      env->exception.syndrome);
    }

    if (arm_is_psci_call(cpu, cs->exception_index)) {
        arm_handle_psci_call(cpu);
        qemu_log_mask(CPU_LOG_INT, "...handled as PSCI call\n");
        return;
    }

    /* Semihosting semantics depend on the register width of the
     * code that caused the exception, not the target exception level,
     * so must be handled here.
     */
    if (check_for_semihosting(cs)) {
        return;
    }

    assert(!excp_is_internal(cs->exception_index));
    if (arm_el_is_aa64(env, new_el)) {
        arm_cpu_do_interrupt_aarch64(cs);
    } else {
        arm_cpu_do_interrupt_aarch32(cs);
    }

    arm_call_el_change_hook(cpu);

    if (!kvm_enabled()) {
        cs->interrupt_request |= CPU_INTERRUPT_EXITTB;
    }
}

/* Return the exception level which controls this address translation regime */
static inline uint32_t regime_el(CPUARMState *env, ARMMMUIdx mmu_idx)
{
    switch (mmu_idx) {
    case ARMMMUIdx_S2NS:
    case ARMMMUIdx_S1E2:
        return 2;
    case ARMMMUIdx_S1E3:
        return 3;
    case ARMMMUIdx_S1SE0:
        return arm_el_is_aa64(env, 3) ? 1 : 3;
    case ARMMMUIdx_S1SE1:
    case ARMMMUIdx_S1NSE0:
    case ARMMMUIdx_S1NSE1:
        return 1;
    default:
        g_assert_not_reached();
    }
}

/* Return true if this address translation regime is secure */
static inline bool regime_is_secure(CPUARMState *env, ARMMMUIdx mmu_idx)
{
    switch (mmu_idx) {
    case ARMMMUIdx_S12NSE0:
    case ARMMMUIdx_S12NSE1:
    case ARMMMUIdx_S1NSE0:
    case ARMMMUIdx_S1NSE1:
    case ARMMMUIdx_S1E2:
    case ARMMMUIdx_S2NS:
        return false;
    case ARMMMUIdx_S1E3:
    case ARMMMUIdx_S1SE0:
    case ARMMMUIdx_S1SE1:
        return true;
    default:
        g_assert_not_reached();
    }
}

/* Return the SCTLR value which controls this address translation regime */
static inline uint32_t regime_sctlr(CPUARMState *env, ARMMMUIdx mmu_idx)
{
    return env->cp15.sctlr_el[regime_el(env, mmu_idx)];
}

/* Return true if the specified stage of address translation is disabled */
static inline bool regime_translation_disabled(CPUARMState *env,
                                               ARMMMUIdx mmu_idx)
{
    if (mmu_idx == ARMMMUIdx_S2NS) {
        return (env->cp15.hcr_el2 & HCR_VM) == 0;
    }
    return (regime_sctlr(env, mmu_idx) & SCTLR_M) == 0;
}

static inline bool regime_translation_big_endian(CPUARMState *env,
                                                 ARMMMUIdx mmu_idx)
{
    return (regime_sctlr(env, mmu_idx) & SCTLR_EE) != 0;
}

/* Return the TCR controlling this translation regime */
static inline TCR *regime_tcr(CPUARMState *env, ARMMMUIdx mmu_idx)
{
    if (mmu_idx == ARMMMUIdx_S2NS) {
        return &env->cp15.vtcr_el2;
    }
    return &env->cp15.tcr_el[regime_el(env, mmu_idx)];
}

/* Returns TBI0 value for current regime el */
uint32_t arm_regime_tbi0(CPUARMState *env, ARMMMUIdx mmu_idx)
{
    TCR *tcr;
    uint32_t el;

    /* For EL0 and EL1, TBI is controlled by stage 1's TCR, so convert
       * a stage 1+2 mmu index into the appropriate stage 1 mmu index.
       */
    if (mmu_idx == ARMMMUIdx_S12NSE0 || mmu_idx == ARMMMUIdx_S12NSE1) {
        mmu_idx += ARMMMUIdx_S1NSE0;
    }

    tcr = regime_tcr(env, mmu_idx);
    el = regime_el(env, mmu_idx);

    if (el > 1) {
        return extract64(tcr->raw_tcr, 20, 1);
    } else {
        return extract64(tcr->raw_tcr, 37, 1);
    }
}

/* Returns TBI1 value for current regime el */
uint32_t arm_regime_tbi1(CPUARMState *env, ARMMMUIdx mmu_idx)
{
    TCR *tcr;
    uint32_t el;

    /* For EL0 and EL1, TBI is controlled by stage 1's TCR, so convert
       * a stage 1+2 mmu index into the appropriate stage 1 mmu index.
       */
    if (mmu_idx == ARMMMUIdx_S12NSE0 || mmu_idx == ARMMMUIdx_S12NSE1) {
        mmu_idx += ARMMMUIdx_S1NSE0;
    }

    tcr = regime_tcr(env, mmu_idx);
    el = regime_el(env, mmu_idx);

    if (el > 1) {
        return 0;
    } else {
        return extract64(tcr->raw_tcr, 38, 1);
    }
}

/* Return the TTBR associated with this translation regime */
static inline uint64_t regime_ttbr(CPUARMState *env, ARMMMUIdx mmu_idx,
                                   int ttbrn)
{
    if (mmu_idx == ARMMMUIdx_S2NS) {
        return env->cp15.vttbr_el2;
    }
    if (ttbrn == 0) {
        return env->cp15.ttbr0_el[regime_el(env, mmu_idx)];
    } else {
        return env->cp15.ttbr1_el[regime_el(env, mmu_idx)];
    }
}

/* Return true if the translation regime is using LPAE format page tables */
static inline bool regime_using_lpae_format(CPUARMState *env,
                                            ARMMMUIdx mmu_idx)
{
    int el = regime_el(env, mmu_idx);
    if (el == 2 || arm_el_is_aa64(env, el)) {
        return true;
    }
    if (arm_feature(env, ARM_FEATURE_LPAE)
        && (regime_tcr(env, mmu_idx)->raw_tcr & TTBCR_EAE)) {
        return true;
    }
    return false;
}

/* Returns true if the stage 1 translation regime is using LPAE format page
 * tables. Used when raising alignment exceptions, whose FSR changes depending
 * on whether the long or short descriptor format is in use. */
bool arm_s1_regime_using_lpae_format(CPUARMState *env, ARMMMUIdx mmu_idx)
{
    if (mmu_idx == ARMMMUIdx_S12NSE0 || mmu_idx == ARMMMUIdx_S12NSE1) {
        mmu_idx += ARMMMUIdx_S1NSE0;
    }

    return regime_using_lpae_format(env, mmu_idx);
}

static inline bool regime_is_user(CPUARMState *env, ARMMMUIdx mmu_idx)
{
    switch (mmu_idx) {
    case ARMMMUIdx_S1SE0:
    case ARMMMUIdx_S1NSE0:
        return true;
    default:
        return false;
    case ARMMMUIdx_S12NSE0:
    case ARMMMUIdx_S12NSE1:
        g_assert_not_reached();
    }
}

/* Translate section/page access permissions to page
 * R/W protection flags
 *
 * @env:         CPUARMState
 * @mmu_idx:     MMU index indicating required translation regime
 * @ap:          The 3-bit access permissions (AP[2:0])
 * @domain_prot: The 2-bit domain access permissions
 */
static inline int ap_to_rw_prot(CPUARMState *env, ARMMMUIdx mmu_idx,
                                int ap, int domain_prot)
{
    bool is_user = regime_is_user(env, mmu_idx);

    if (domain_prot == 3) {
        return PAGE_READ | PAGE_WRITE;
    }

    switch (ap) {
    case 0:
        if (arm_feature(env, ARM_FEATURE_V7)) {
            return 0;
        }
        switch (regime_sctlr(env, mmu_idx) & (SCTLR_S | SCTLR_R)) {
        case SCTLR_S:
            return is_user ? 0 : PAGE_READ;
        case SCTLR_R:
            return PAGE_READ;
        default:
            return 0;
        }
    case 1:
        return is_user ? 0 : PAGE_READ | PAGE_WRITE;
    case 2:
        if (is_user) {
            return PAGE_READ;
        } else {
            return PAGE_READ | PAGE_WRITE;
        }
    case 3:
        return PAGE_READ | PAGE_WRITE;
    case 4: /* Reserved.  */
        return 0;
    case 5:
        return is_user ? 0 : PAGE_READ;
    case 6:
        return PAGE_READ;
    case 7:
        if (!arm_feature(env, ARM_FEATURE_V6K)) {
            return 0;
        }
        return PAGE_READ;
    default:
        g_assert_not_reached();
    }
}

/* Translate section/page access permissions to page
 * R/W protection flags.
 *
 * @ap:      The 2-bit simple AP (AP[2:1])
 * @is_user: TRUE if accessing from PL0
 */
static inline int simple_ap_to_rw_prot_is_user(int ap, bool is_user)
{
    switch (ap) {
    case 0:
        return is_user ? 0 : PAGE_READ | PAGE_WRITE;
    case 1:
        return PAGE_READ | PAGE_WRITE;
    case 2:
        return is_user ? 0 : PAGE_READ;
    case 3:
        return PAGE_READ;
    default:
        g_assert_not_reached();
    }
}

static inline int
simple_ap_to_rw_prot(CPUARMState *env, ARMMMUIdx mmu_idx, int ap)
{
    return simple_ap_to_rw_prot_is_user(ap, regime_is_user(env, mmu_idx));
}

/* Translate S2 section/page access permissions to protection flags
 *
 * @env:     CPUARMState
 * @s2ap:    The 2-bit stage2 access permissions (S2AP)
 * @xn:      XN (execute-never) bit
 */
static int get_S2prot(CPUARMState *env, int s2ap, int xn)
{
    int prot = 0;

    if (s2ap & 1) {
        prot |= PAGE_READ;
    }
    if (s2ap & 2) {
        prot |= PAGE_WRITE;
    }
    if (!xn) {
        if (arm_el_is_aa64(env, 2) || prot & PAGE_READ) {
            prot |= PAGE_EXEC;
        }
    }
    return prot;
}

/* Translate section/page access permissions to protection flags
 *
 * @env:     CPUARMState
 * @mmu_idx: MMU index indicating required translation regime
 * @is_aa64: TRUE if AArch64
 * @ap:      The 2-bit simple AP (AP[2:1])
 * @ns:      NS (non-secure) bit
 * @xn:      XN (execute-never) bit
 * @pxn:     PXN (privileged execute-never) bit
 */
static int get_S1prot(CPUARMState *env, ARMMMUIdx mmu_idx, bool is_aa64,
                      int ap, int ns, int xn, int pxn)
{
    bool is_user = regime_is_user(env, mmu_idx);
    int prot_rw, user_rw;
    bool have_wxn;
    int wxn = 0;

    assert(mmu_idx != ARMMMUIdx_S2NS);

    user_rw = simple_ap_to_rw_prot_is_user(ap, true);
    if (is_user) {
        prot_rw = user_rw;
    } else {
        prot_rw = simple_ap_to_rw_prot_is_user(ap, false);
    }

    if (ns && arm_is_secure(env) && (env->cp15.scr_el3 & SCR_SIF)) {
        return prot_rw;
    }

    /* TODO have_wxn should be replaced with
     *   ARM_FEATURE_V8 || (ARM_FEATURE_V7 && ARM_FEATURE_EL2)
     * when ARM_FEATURE_EL2 starts getting set. For now we assume all LPAE
     * compatible processors have EL2, which is required for [U]WXN.
     */
    have_wxn = arm_feature(env, ARM_FEATURE_LPAE);

    if (have_wxn) {
        wxn = regime_sctlr(env, mmu_idx) & SCTLR_WXN;
    }

    if (is_aa64) {
        switch (regime_el(env, mmu_idx)) {
        case 1:
            if (!is_user) {
                xn = pxn || (user_rw & PAGE_WRITE);
            }
            break;
        case 2:
        case 3:
            break;
        }
    } else if (arm_feature(env, ARM_FEATURE_V7)) {
        switch (regime_el(env, mmu_idx)) {
        case 1:
        case 3:
            if (is_user) {
                xn = xn || !(user_rw & PAGE_READ);
            } else {
                int uwxn = 0;
                if (have_wxn) {
                    uwxn = regime_sctlr(env, mmu_idx) & SCTLR_UWXN;
                }
                xn = xn || !(prot_rw & PAGE_READ) || pxn ||
                     (uwxn && (user_rw & PAGE_WRITE));
            }
            break;
        case 2:
            break;
        }
    } else {
        xn = wxn = 0;
    }

    if (xn || (wxn && (prot_rw & PAGE_WRITE))) {
        return prot_rw;
    }
    return prot_rw | PAGE_EXEC;
}

static bool get_level1_table_address(CPUARMState *env, ARMMMUIdx mmu_idx,
                                     uint32_t *table, uint32_t address)
{
    /* Note that we can only get here for an AArch32 PL0/PL1 lookup */
    TCR *tcr = regime_tcr(env, mmu_idx);

    if (address & tcr->mask) {
        if (tcr->raw_tcr & TTBCR_PD1) {
            /* Translation table walk disabled for TTBR1 */
            return false;
        }
        *table = regime_ttbr(env, mmu_idx, 1) & 0xffffc000;
    } else {
        if (tcr->raw_tcr & TTBCR_PD0) {
            /* Translation table walk disabled for TTBR0 */
            return false;
        }
        *table = regime_ttbr(env, mmu_idx, 0) & tcr->base_mask;
    }
    *table |= (address >> 18) & 0x3ffc;
    return true;
}

/* Translate a S1 pagetable walk through S2 if needed.  */
static hwaddr S1_ptw_translate(CPUARMState *env, ARMMMUIdx mmu_idx,
                               hwaddr addr, MemTxAttrs txattrs,
                               uint32_t *fsr,
                               ARMMMUFaultInfo *fi)
{
    if ((mmu_idx == ARMMMUIdx_S1NSE0 || mmu_idx == ARMMMUIdx_S1NSE1) &&
        !regime_translation_disabled(env, ARMMMUIdx_S2NS)) {
        target_ulong s2size;
        hwaddr s2pa;
        int s2prot;
        int ret;

        ret = get_phys_addr_lpae(env, addr, 0, ARMMMUIdx_S2NS, &s2pa,
                                 &txattrs, &s2prot, &s2size, fsr, fi);
        if (ret) {
            fi->s2addr = addr;
            fi->stage2 = true;
            fi->s1ptw = true;
            return ~0;
        }
        addr = s2pa;
    }
    return addr;
}

/* All loads done in the course of a page table walk go through here.
 * TODO: rather than ignoring errors from physical memory reads (which
 * are external aborts in ARM terminology) we should propagate this
 * error out so that we can turn it into a Data Abort if this walk
 * was being done for a CPU load/store or an address translation instruction
 * (but not if it was for a debug access).
 */
static uint32_t arm_ldl_ptw(CPUState *cs, hwaddr addr, bool is_secure,
                            ARMMMUIdx mmu_idx, uint32_t *fsr,
                            ARMMMUFaultInfo *fi)
{
    ARMCPU *cpu = ARM_CPU(cs);
    CPUARMState *env = &cpu->env;
    MemTxAttrs attrs = {};
    AddressSpace *as;

    attrs.secure = is_secure;
    as = arm_addressspace(cs, attrs);
    addr = S1_ptw_translate(env, mmu_idx, addr, attrs, fsr, fi);
    if (fi->s1ptw) {
        return 0;
    }
    if (regime_translation_big_endian(env, mmu_idx)) {
        return address_space_ldl_be(as, addr, attrs, NULL);
    } else {
        return address_space_ldl_le(as, addr, attrs, NULL);
    }
}

static uint64_t arm_ldq_ptw(CPUState *cs, hwaddr addr, bool is_secure,
                            ARMMMUIdx mmu_idx, uint32_t *fsr,
                            ARMMMUFaultInfo *fi)
{
    ARMCPU *cpu = ARM_CPU(cs);
    CPUARMState *env = &cpu->env;
    MemTxAttrs attrs = {};
    AddressSpace *as;

    attrs.secure = is_secure;
    as = arm_addressspace(cs, attrs);
    addr = S1_ptw_translate(env, mmu_idx, addr, attrs, fsr, fi);
    if (fi->s1ptw) {
        return 0;
    }
    if (regime_translation_big_endian(env, mmu_idx)) {
        return address_space_ldq_be(as, addr, attrs, NULL);
    } else {
        return address_space_ldq_le(as, addr, attrs, NULL);
    }
}

static bool get_phys_addr_v5(CPUARMState *env, uint32_t address,
                             int access_type, ARMMMUIdx mmu_idx,
                             hwaddr *phys_ptr, int *prot,
                             target_ulong *page_size, uint32_t *fsr,
                             ARMMMUFaultInfo *fi)
{
    CPUState *cs = CPU(arm_env_get_cpu(env));
    int code;
    uint32_t table;
    uint32_t desc;
    int type;
    int ap;
    int domain = 0;
    int domain_prot;
    hwaddr phys_addr;
    uint32_t dacr;

    /* Pagetable walk.  */
    /* Lookup l1 descriptor.  */
    if (!get_level1_table_address(env, mmu_idx, &table, address)) {
        /* Section translation fault if page walk is disabled by PD0 or PD1 */
        code = 5;
        goto do_fault;
    }
    desc = arm_ldl_ptw(cs, table, regime_is_secure(env, mmu_idx),
                       mmu_idx, fsr, fi);
    type = (desc & 3);
    domain = (desc >> 5) & 0x0f;
    if (regime_el(env, mmu_idx) == 1) {
        dacr = env->cp15.dacr_ns;
    } else {
        dacr = env->cp15.dacr_s;
    }
    domain_prot = (dacr >> (domain * 2)) & 3;
    if (type == 0) {
        /* Section translation fault.  */
        code = 5;
        goto do_fault;
    }
    if (domain_prot == 0 || domain_prot == 2) {
        if (type == 2)
            code = 9; /* Section domain fault.  */
        else
            code = 11; /* Page domain fault.  */
        goto do_fault;
    }
    if (type == 2) {
        /* 1Mb section.  */
        phys_addr = (desc & 0xfff00000) | (address & 0x000fffff);
        ap = (desc >> 10) & 3;
        code = 13;
        *page_size = 1024 * 1024;
    } else {
        /* Lookup l2 entry.  */
        if (type == 1) {
            /* Coarse pagetable.  */
            table = (desc & 0xfffffc00) | ((address >> 10) & 0x3fc);
        } else {
            /* Fine pagetable.  */
            table = (desc & 0xfffff000) | ((address >> 8) & 0xffc);
        }
        desc = arm_ldl_ptw(cs, table, regime_is_secure(env, mmu_idx),
                           mmu_idx, fsr, fi);
        switch (desc & 3) {
        case 0: /* Page translation fault.  */
            code = 7;
            goto do_fault;
        case 1: /* 64k page.  */
            phys_addr = (desc & 0xffff0000) | (address & 0xffff);
            ap = (desc >> (4 + ((address >> 13) & 6))) & 3;
            *page_size = 0x10000;
            break;
        case 2: /* 4k page.  */
            phys_addr = (desc & 0xfffff000) | (address & 0xfff);
            ap = (desc >> (4 + ((address >> 9) & 6))) & 3;
            *page_size = 0x1000;
            break;
        case 3: /* 1k page, or ARMv6/XScale "extended small (4k) page" */
            if (type == 1) {
                /* ARMv6/XScale extended small page format */
                if (arm_feature(env, ARM_FEATURE_XSCALE)
                    || arm_feature(env, ARM_FEATURE_V6)) {
                    phys_addr = (desc & 0xfffff000) | (address & 0xfff);
                    *page_size = 0x1000;
                } else {
                    /* UNPREDICTABLE in ARMv5; we choose to take a
                     * page translation fault.
                     */
                    code = 7;
                    goto do_fault;
                }
            } else {
                phys_addr = (desc & 0xfffffc00) | (address & 0x3ff);
                *page_size = 0x400;
            }
            ap = (desc >> 4) & 3;
            break;
        default:
            /* Never happens, but compiler isn't smart enough to tell.  */
            abort();
        }
        code = 15;
    }
    *prot = ap_to_rw_prot(env, mmu_idx, ap, domain_prot);
    *prot |= *prot ? PAGE_EXEC : 0;
    if (!(*prot & (1 << access_type))) {
        /* Access permission fault.  */
        goto do_fault;
    }
    *phys_ptr = phys_addr;
    return false;
do_fault:
    *fsr = code | (domain << 4);
    return true;
}

static bool get_phys_addr_v6(CPUARMState *env, uint32_t address,
                             int access_type, ARMMMUIdx mmu_idx,
                             hwaddr *phys_ptr, MemTxAttrs *attrs, int *prot,
                             target_ulong *page_size, uint32_t *fsr,
                             ARMMMUFaultInfo *fi)
{
    CPUState *cs = CPU(arm_env_get_cpu(env));
    int code;
    uint32_t table;
    uint32_t desc;
    uint32_t xn;
    uint32_t pxn = 0;
    int type;
    int ap;
    int domain = 0;
    int domain_prot;
    hwaddr phys_addr;
    uint32_t dacr;
    bool ns;

    /* Pagetable walk.  */
    /* Lookup l1 descriptor.  */
    if (!get_level1_table_address(env, mmu_idx, &table, address)) {
        /* Section translation fault if page walk is disabled by PD0 or PD1 */
        code = 5;
        goto do_fault;
    }
    desc = arm_ldl_ptw(cs, table, regime_is_secure(env, mmu_idx),
                       mmu_idx, fsr, fi);
    type = (desc & 3);
    if (type == 0 || (type == 3 && !arm_feature(env, ARM_FEATURE_PXN))) {
        /* Section translation fault, or attempt to use the encoding
         * which is Reserved on implementations without PXN.
         */
        code = 5;
        goto do_fault;
    }
    if ((type == 1) || !(desc & (1 << 18))) {
        /* Page or Section.  */
        domain = (desc >> 5) & 0x0f;
    }
    if (regime_el(env, mmu_idx) == 1) {
        dacr = env->cp15.dacr_ns;
    } else {
        dacr = env->cp15.dacr_s;
    }
    domain_prot = (dacr >> (domain * 2)) & 3;
    if (domain_prot == 0 || domain_prot == 2) {
        if (type != 1) {
            code = 9; /* Section domain fault.  */
        } else {
            code = 11; /* Page domain fault.  */
        }
        goto do_fault;
    }
    if (type != 1) {
        if (desc & (1 << 18)) {
            /* Supersection.  */
            phys_addr = (desc & 0xff000000) | (address & 0x00ffffff);
            phys_addr |= (uint64_t)extract32(desc, 20, 4) << 32;
            phys_addr |= (uint64_t)extract32(desc, 5, 4) << 36;
            *page_size = 0x1000000;
        } else {
            /* Section.  */
            phys_addr = (desc & 0xfff00000) | (address & 0x000fffff);
            *page_size = 0x100000;
        }
        ap = ((desc >> 10) & 3) | ((desc >> 13) & 4);
        xn = desc & (1 << 4);
        pxn = desc & 1;
        code = 13;
        ns = extract32(desc, 19, 1);
    } else {
        if (arm_feature(env, ARM_FEATURE_PXN)) {
            pxn = (desc >> 2) & 1;
        }
        ns = extract32(desc, 3, 1);
        /* Lookup l2 entry.  */
        table = (desc & 0xfffffc00) | ((address >> 10) & 0x3fc);
        desc = arm_ldl_ptw(cs, table, regime_is_secure(env, mmu_idx),
                           mmu_idx, fsr, fi);
        ap = ((desc >> 4) & 3) | ((desc >> 7) & 4);
        switch (desc & 3) {
        case 0: /* Page translation fault.  */
            code = 7;
            goto do_fault;
        case 1: /* 64k page.  */
            phys_addr = (desc & 0xffff0000) | (address & 0xffff);
            xn = desc & (1 << 15);
            *page_size = 0x10000;
            break;
        case 2: case 3: /* 4k page.  */
            phys_addr = (desc & 0xfffff000) | (address & 0xfff);
            xn = desc & 1;
            *page_size = 0x1000;
            break;
        default:
            /* Never happens, but compiler isn't smart enough to tell.  */
            abort();
        }
        code = 15;
    }
    if (domain_prot == 3) {
        *prot = PAGE_READ | PAGE_WRITE | PAGE_EXEC;
    } else {
        if (pxn && !regime_is_user(env, mmu_idx)) {
            xn = 1;
        }
        if (xn && access_type == 2)
            goto do_fault;

        if (arm_feature(env, ARM_FEATURE_V6K) &&
                (regime_sctlr(env, mmu_idx) & SCTLR_AFE)) {
            /* The simplified model uses AP[0] as an access control bit.  */
            if ((ap & 1) == 0) {
                /* Access flag fault.  */
                code = (code == 15) ? 6 : 3;
                goto do_fault;
            }
            *prot = simple_ap_to_rw_prot(env, mmu_idx, ap >> 1);
        } else {
            *prot = ap_to_rw_prot(env, mmu_idx, ap, domain_prot);
        }
        if (*prot && !xn) {
            *prot |= PAGE_EXEC;
        }
        if (!(*prot & (1 << access_type))) {
            /* Access permission fault.  */
            goto do_fault;
        }
    }
    if (ns) {
        /* The NS bit will (as required by the architecture) have no effect if
         * the CPU doesn't support TZ or this is a non-secure translation
         * regime, because the attribute will already be non-secure.
         */
        attrs->secure = false;
    }
    *phys_ptr = phys_addr;
    return false;
do_fault:
    *fsr = code | (domain << 4);
    return true;
}

/* Fault type for long-descriptor MMU fault reporting; this corresponds
 * to bits [5..2] in the STATUS field in long-format DFSR/IFSR.
 */
typedef enum {
    translation_fault = 1,
    access_fault = 2,
    permission_fault = 3,
} MMUFaultType;

/*
 * check_s2_mmu_setup
 * @cpu:        ARMCPU
 * @is_aa64:    True if the translation regime is in AArch64 state
 * @startlevel: Suggested starting level
 * @inputsize:  Bitsize of IPAs
 * @stride:     Page-table stride (See the ARM ARM)
 *
 * Returns true if the suggested S2 translation parameters are OK and
 * false otherwise.
 */
static bool check_s2_mmu_setup(ARMCPU *cpu, bool is_aa64, int level,
                               int inputsize, int stride)
{
    const int grainsize = stride + 3;
    int startsizecheck;

    /* Negative levels are never allowed.  */
    if (level < 0) {
        return false;
    }

    startsizecheck = inputsize - ((3 - level) * stride + grainsize);
    if (startsizecheck < 1 || startsizecheck > stride + 4) {
        return false;
    }

    if (is_aa64) {
        CPUARMState *env = &cpu->env;
        unsigned int pamax = arm_pamax(cpu);

        switch (stride) {
        case 13: /* 64KB Pages.  */
            if (level == 0 || (level == 1 && pamax <= 42)) {
                return false;
            }
            break;
        case 11: /* 16KB Pages.  */
            if (level == 0 || (level == 1 && pamax <= 40)) {
                return false;
            }
            break;
        case 9: /* 4KB Pages.  */
            if (level == 0 && pamax <= 42) {
                return false;
            }
            break;
        default:
            g_assert_not_reached();
        }

        /* Inputsize checks.  */
        if (inputsize > pamax &&
            (arm_el_is_aa64(env, 1) || inputsize > 40)) {
            /* This is CONSTRAINED UNPREDICTABLE and we choose to fault.  */
            return false;
        }
    } else {
        /* AArch32 only supports 4KB pages. Assert on that.  */
        assert(stride == 9);

        if (level == 0) {
            return false;
        }
    }
    return true;
}

static bool get_phys_addr_lpae(CPUARMState *env, target_ulong address,
                               int access_type, ARMMMUIdx mmu_idx,
                               hwaddr *phys_ptr, MemTxAttrs *txattrs, int *prot,
                               target_ulong *page_size_ptr, uint32_t *fsr,
                               ARMMMUFaultInfo *fi)
{
    ARMCPU *cpu = arm_env_get_cpu(env);
    CPUState *cs = CPU(cpu);
    /* Read an LPAE long-descriptor translation table. */
    MMUFaultType fault_type = translation_fault;
    uint32_t level;
    uint32_t epd = 0;
    int32_t t0sz, t1sz;
    uint32_t tg;
    uint64_t ttbr;
    int ttbr_select;
    hwaddr descaddr, indexmask, indexmask_grainsize;
    uint32_t tableattrs;
    target_ulong page_size;
    uint32_t attrs;
    int32_t stride = 9;
    int32_t addrsize;
    int inputsize;
    int32_t tbi = 0;
    TCR *tcr = regime_tcr(env, mmu_idx);
    int ap, ns, xn, pxn;
    uint32_t el = regime_el(env, mmu_idx);
    bool ttbr1_valid = true;
    uint64_t descaddrmask;
    bool aarch64 = arm_el_is_aa64(env, el);

    /* TODO:
     * This code does not handle the different format TCR for VTCR_EL2.
     * This code also does not support shareability levels.
     * Attribute and permission bit handling should also be checked when adding
     * support for those page table walks.
     */
    if (aarch64) {
        level = 0;
        addrsize = 64;
        if (el > 1) {
            if (mmu_idx != ARMMMUIdx_S2NS) {
                tbi = extract64(tcr->raw_tcr, 20, 1);
            }
        } else {
            if (extract64(address, 55, 1)) {
                tbi = extract64(tcr->raw_tcr, 38, 1);
            } else {
                tbi = extract64(tcr->raw_tcr, 37, 1);
            }
        }
        tbi *= 8;

        /* If we are in 64-bit EL2 or EL3 then there is no TTBR1, so mark it
         * invalid.
         */
        if (el > 1) {
            ttbr1_valid = false;
        }
    } else {
        level = 1;
        addrsize = 32;
        /* There is no TTBR1 for EL2 */
        if (el == 2) {
            ttbr1_valid = false;
        }
    }

    /* Determine whether this address is in the region controlled by
     * TTBR0 or TTBR1 (or if it is in neither region and should fault).
     * This is a Non-secure PL0/1 stage 1 translation, so controlled by
     * TTBCR/TTBR0/TTBR1 in accordance with ARM ARM DDI0406C table B-32:
     */
    if (aarch64) {
        /* AArch64 translation.  */
        t0sz = extract32(tcr->raw_tcr, 0, 6);
        t0sz = MIN(t0sz, 39);
        t0sz = MAX(t0sz, 16);
    } else if (mmu_idx != ARMMMUIdx_S2NS) {
        /* AArch32 stage 1 translation.  */
        t0sz = extract32(tcr->raw_tcr, 0, 3);
    } else {
        /* AArch32 stage 2 translation.  */
        bool sext = extract32(tcr->raw_tcr, 4, 1);
        bool sign = extract32(tcr->raw_tcr, 3, 1);
        /* Address size is 40-bit for a stage 2 translation,
         * and t0sz can be negative (from -8 to 7),
         * so we need to adjust it to use the TTBR selecting logic below.
         */
        addrsize = 40;
        t0sz = sextract32(tcr->raw_tcr, 0, 4) + 8;

        /* If the sign-extend bit is not the same as t0sz[3], the result
         * is unpredictable. Flag this as a guest error.  */
        if (sign != sext) {
            qemu_log_mask(LOG_GUEST_ERROR,
                          "AArch32: VTCR.S / VTCR.T0SZ[3] mismatch\n");
        }
    }
    t1sz = extract32(tcr->raw_tcr, 16, 6);
    if (aarch64) {
        t1sz = MIN(t1sz, 39);
        t1sz = MAX(t1sz, 16);
    }
    if (t0sz && !extract64(address, addrsize - t0sz, t0sz - tbi)) {
        /* there is a ttbr0 region and we are in it (high bits all zero) */
        ttbr_select = 0;
    } else if (ttbr1_valid && t1sz &&
               !extract64(~address, addrsize - t1sz, t1sz - tbi)) {
        /* there is a ttbr1 region and we are in it (high bits all one) */
        ttbr_select = 1;
    } else if (!t0sz) {
        /* ttbr0 region is "everything not in the ttbr1 region" */
        ttbr_select = 0;
    } else if (!t1sz && ttbr1_valid) {
        /* ttbr1 region is "everything not in the ttbr0 region" */
        ttbr_select = 1;
    } else {
        /* in the gap between the two regions, this is a Translation fault */
        fault_type = translation_fault;
        goto do_fault;
    }

    /* Note that QEMU ignores shareability and cacheability attributes,
     * so we don't need to do anything with the SH, ORGN, IRGN fields
     * in the TTBCR.  Similarly, TTBCR:A1 selects whether we get the
     * ASID from TTBR0 or TTBR1, but QEMU's TLB doesn't currently
     * implement any ASID-like capability so we can ignore it (instead
     * we will always flush the TLB any time the ASID is changed).
     */
    if (ttbr_select == 0) {
        ttbr = regime_ttbr(env, mmu_idx, 0);
        if (el < 2) {
            epd = extract32(tcr->raw_tcr, 7, 1);
        }
        inputsize = addrsize - t0sz;

        tg = extract32(tcr->raw_tcr, 14, 2);
        if (tg == 1) { /* 64KB pages */
            stride = 13;
        }
        if (tg == 2) { /* 16KB pages */
            stride = 11;
        }
    } else {
        /* We should only be here if TTBR1 is valid */
        assert(ttbr1_valid);

        ttbr = regime_ttbr(env, mmu_idx, 1);
        epd = extract32(tcr->raw_tcr, 23, 1);
        inputsize = addrsize - t1sz;

        tg = extract32(tcr->raw_tcr, 30, 2);
        if (tg == 3)  { /* 64KB pages */
            stride = 13;
        }
        if (tg == 1) { /* 16KB pages */
            stride = 11;
        }
    }

    /* Here we should have set up all the parameters for the translation:
     * inputsize, ttbr, epd, stride, tbi
     */

    if (epd) {
        /* Translation table walk disabled => Translation fault on TLB miss
         * Note: This is always 0 on 64-bit EL2 and EL3.
         */
        goto do_fault;
    }

    if (mmu_idx != ARMMMUIdx_S2NS) {
        /* The starting level depends on the virtual address size (which can
         * be up to 48 bits) and the translation granule size. It indicates
         * the number of strides (stride bits at a time) needed to
         * consume the bits of the input address. In the pseudocode this is:
         *  level = 4 - RoundUp((inputsize - grainsize) / stride)
         * where their 'inputsize' is our 'inputsize', 'grainsize' is
         * our 'stride + 3' and 'stride' is our 'stride'.
         * Applying the usual "rounded up m/n is (m+n-1)/n" and simplifying:
         * = 4 - (inputsize - stride - 3 + stride - 1) / stride
         * = 4 - (inputsize - 4) / stride;
         */
        level = 4 - (inputsize - 4) / stride;
    } else {
        /* For stage 2 translations the starting level is specified by the
         * VTCR_EL2.SL0 field (whose interpretation depends on the page size)
         */
        uint32_t sl0 = extract32(tcr->raw_tcr, 6, 2);
        uint32_t startlevel;
        bool ok;

        if (!aarch64 || stride == 9) {
            /* AArch32 or 4KB pages */
            startlevel = 2 - sl0;
        } else {
            /* 16KB or 64KB pages */
            startlevel = 3 - sl0;
        }

        /* Check that the starting level is valid. */
        ok = check_s2_mmu_setup(cpu, aarch64, startlevel,
                                inputsize, stride);
        if (!ok) {
            fault_type = translation_fault;
            goto do_fault;
        }
        level = startlevel;
    }

    indexmask_grainsize = (1ULL << (stride + 3)) - 1;
    indexmask = (1ULL << (inputsize - (stride * (4 - level)))) - 1;

    /* Now we can extract the actual base address from the TTBR */
    descaddr = extract64(ttbr, 0, 48);
    descaddr &= ~indexmask;

    /* The address field in the descriptor goes up to bit 39 for ARMv7
     * but up to bit 47 for ARMv8, but we use the descaddrmask
     * up to bit 39 for AArch32, because we don't need other bits in that case
     * to construct next descriptor address (anyway they should be all zeroes).
     */
    descaddrmask = ((1ull << (aarch64 ? 48 : 40)) - 1) &
                   ~indexmask_grainsize;

    /* Secure accesses start with the page table in secure memory and
     * can be downgraded to non-secure at any step. Non-secure accesses
     * remain non-secure. We implement this by just ORing in the NSTable/NS
     * bits at each step.
     */
    tableattrs = regime_is_secure(env, mmu_idx) ? 0 : (1 << 4);
    for (;;) {
        uint64_t descriptor;
        bool nstable;

        descaddr |= (address >> (stride * (4 - level))) & indexmask;
        descaddr &= ~7ULL;
        nstable = extract32(tableattrs, 4, 1);
        descriptor = arm_ldq_ptw(cs, descaddr, !nstable, mmu_idx, fsr, fi);
        if (fi->s1ptw) {
            goto do_fault;
        }

        if (!(descriptor & 1) ||
            (!(descriptor & 2) && (level == 3))) {
            /* Invalid, or the Reserved level 3 encoding */
            goto do_fault;
        }
        descaddr = descriptor & descaddrmask;

        if ((descriptor & 2) && (level < 3)) {
            /* Table entry. The top five bits are attributes which  may
             * propagate down through lower levels of the table (and
             * which are all arranged so that 0 means "no effect", so
             * we can gather them up by ORing in the bits at each level).
             */
            tableattrs |= extract64(descriptor, 59, 5);
            level++;
            indexmask = indexmask_grainsize;
            continue;
        }
        /* Block entry at level 1 or 2, or page entry at level 3.
         * These are basically the same thing, although the number
         * of bits we pull in from the vaddr varies.
         */
        page_size = (1ULL << ((stride * (4 - level)) + 3));
        descaddr |= (address & (page_size - 1));
        /* Extract attributes from the descriptor */
        attrs = extract64(descriptor, 2, 10)
            | (extract64(descriptor, 52, 12) << 10);

        if (mmu_idx == ARMMMUIdx_S2NS) {
            /* Stage 2 table descriptors do not include any attribute fields */
            break;
        }
        /* Merge in attributes from table descriptors */
        attrs |= extract32(tableattrs, 0, 2) << 11; /* XN, PXN */
        attrs |= extract32(tableattrs, 3, 1) << 5; /* APTable[1] => AP[2] */
        /* The sense of AP[1] vs APTable[0] is reversed, as APTable[0] == 1
         * means "force PL1 access only", which means forcing AP[1] to 0.
         */
        if (extract32(tableattrs, 2, 1)) {
            attrs &= ~(1 << 4);
        }
        attrs |= nstable << 3; /* NS */
        break;
    }
    /* Here descaddr is the final physical address, and attributes
     * are all in attrs.
     */
    fault_type = access_fault;
    if ((attrs & (1 << 8)) == 0) {
        /* Access flag */
        goto do_fault;
    }

    ap = extract32(attrs, 4, 2);
    xn = extract32(attrs, 12, 1);

    if (mmu_idx == ARMMMUIdx_S2NS) {
        ns = true;
        *prot = get_S2prot(env, ap, xn);
    } else {
        ns = extract32(attrs, 3, 1);
        pxn = extract32(attrs, 11, 1);
        *prot = get_S1prot(env, mmu_idx, aarch64, ap, ns, xn, pxn);
    }

    fault_type = permission_fault;
    if (!(*prot & (1 << access_type))) {
        goto do_fault;
    }

    if (ns) {
        /* The NS bit will (as required by the architecture) have no effect if
         * the CPU doesn't support TZ or this is a non-secure translation
         * regime, because the attribute will already be non-secure.
         */
        txattrs->secure = false;
    }
    *phys_ptr = descaddr;
    *page_size_ptr = page_size;
    return false;

do_fault:
    /* Long-descriptor format IFSR/DFSR value */
    *fsr = (1 << 9) | (fault_type << 2) | level;
    /* Tag the error as S2 for failed S1 PTW at S2 or ordinary S2.  */
    fi->stage2 = fi->s1ptw || (mmu_idx == ARMMMUIdx_S2NS);
    return true;
}

static inline void get_phys_addr_pmsav7_default(CPUARMState *env,
                                                ARMMMUIdx mmu_idx,
                                                int32_t address, int *prot)
{
    *prot = PAGE_READ | PAGE_WRITE;
    switch (address) {
    case 0xF0000000 ... 0xFFFFFFFF:
        if (regime_sctlr(env, mmu_idx) & SCTLR_V) { /* hivecs execing is ok */
            *prot |= PAGE_EXEC;
        }
        break;
    case 0x00000000 ... 0x7FFFFFFF:
        *prot |= PAGE_EXEC;
        break;
    }

}

static bool get_phys_addr_pmsav7(CPUARMState *env, uint32_t address,
                                 int access_type, ARMMMUIdx mmu_idx,
                                 hwaddr *phys_ptr, int *prot, uint32_t *fsr)
{
    ARMCPU *cpu = arm_env_get_cpu(env);
    int n;
    bool is_user = regime_is_user(env, mmu_idx);

    *phys_ptr = address;
    *prot = 0;

    if (regime_translation_disabled(env, mmu_idx)) { /* MPU disabled */
        get_phys_addr_pmsav7_default(env, mmu_idx, address, prot);
    } else { /* MPU enabled */
        for (n = (int)cpu->pmsav7_dregion - 1; n >= 0; n--) {
            /* region search */
            uint32_t base = env->pmsav7.drbar[n];
            uint32_t rsize = extract32(env->pmsav7.drsr[n], 1, 5);
            uint32_t rmask;
            bool srdis = false;

            if (!(env->pmsav7.drsr[n] & 0x1)) {
                continue;
            }

            if (!rsize) {
                qemu_log_mask(LOG_GUEST_ERROR, "DRSR.Rsize field can not be 0");
                continue;
            }
            rsize++;
            rmask = (1ull << rsize) - 1;

            if (base & rmask) {
                qemu_log_mask(LOG_GUEST_ERROR, "DRBAR %" PRIx32 " misaligned "
                              "to DRSR region size, mask = %" PRIx32,
                              base, rmask);
                continue;
            }

            if (address < base || address > base + rmask) {
                continue;
            }

            /* Region matched */

            if (rsize >= 8) { /* no subregions for regions < 256 bytes */
                int i, snd;
                uint32_t srdis_mask;

                rsize -= 3; /* sub region size (power of 2) */
                snd = ((address - base) >> rsize) & 0x7;
                srdis = extract32(env->pmsav7.drsr[n], snd + 8, 1);

                srdis_mask = srdis ? 0x3 : 0x0;
                for (i = 2; i <= 8 && rsize < TARGET_PAGE_BITS; i *= 2) {
                    /* This will check in groups of 2, 4 and then 8, whether
                     * the subregion bits are consistent. rsize is incremented
                     * back up to give the region size, considering consistent
                     * adjacent subregions as one region. Stop testing if rsize
                     * is already big enough for an entire QEMU page.
                     */
                    int snd_rounded = snd & ~(i - 1);
                    uint32_t srdis_multi = extract32(env->pmsav7.drsr[n],
                                                     snd_rounded + 8, i);
                    if (srdis_mask ^ srdis_multi) {
                        break;
                    }
                    srdis_mask = (srdis_mask << i) | srdis_mask;
                    rsize++;
                }
            }
            if (rsize < TARGET_PAGE_BITS) {
                qemu_log_mask(LOG_UNIMP, "No support for MPU (sub)region"
                              "alignment of %" PRIu32 " bits. Minimum is %d\n",
                              rsize, TARGET_PAGE_BITS);
                continue;
            }
            if (srdis) {
                continue;
            }
            break;
        }

        if (n == -1) { /* no hits */
            if (cpu->pmsav7_dregion &&
                (is_user || !(regime_sctlr(env, mmu_idx) & SCTLR_BR))) {
                /* background fault */
                *fsr = 0;
                return true;
            }
            get_phys_addr_pmsav7_default(env, mmu_idx, address, prot);
        } else { /* a MPU hit! */
            uint32_t ap = extract32(env->pmsav7.dracr[n], 8, 3);

            if (is_user) { /* User mode AP bit decoding */
                switch (ap) {
                case 0:
                case 1:
                case 5:
                    break; /* no access */
                case 3:
                    *prot |= PAGE_WRITE;
                    /* fall through */
                case 2:
                case 6:
                    *prot |= PAGE_READ | PAGE_EXEC;
                    break;
                default:
                    qemu_log_mask(LOG_GUEST_ERROR,
                                  "Bad value for AP bits in DRACR %"
                                  PRIx32 "\n", ap);
                }
            } else { /* Priv. mode AP bits decoding */
                switch (ap) {
                case 0:
                    break; /* no access */
                case 1:
                case 2:
                case 3:
                    *prot |= PAGE_WRITE;
                    /* fall through */
                case 5:
                case 6:
                    *prot |= PAGE_READ | PAGE_EXEC;
                    break;
                default:
                    qemu_log_mask(LOG_GUEST_ERROR,
                                  "Bad value for AP bits in DRACR %"
                                  PRIx32 "\n", ap);
                }
            }

            /* execute never */
            if (env->pmsav7.dracr[n] & (1 << 12)) {
                *prot &= ~PAGE_EXEC;
            }
        }
    }

    *fsr = 0x00d; /* Permission fault */
    return !(*prot & (1 << access_type));
}

static bool get_phys_addr_pmsav5(CPUARMState *env, uint32_t address,
                                 int access_type, ARMMMUIdx mmu_idx,
                                 hwaddr *phys_ptr, int *prot, uint32_t *fsr)
{
    int n;
    uint32_t mask;
    uint32_t base;
    bool is_user = regime_is_user(env, mmu_idx);

    *phys_ptr = address;
    for (n = 7; n >= 0; n--) {
        base = env->cp15.c6_region[n];
        if ((base & 1) == 0) {
            continue;
        }
        mask = 1 << ((base >> 1) & 0x1f);
        /* Keep this shift separate from the above to avoid an
           (undefined) << 32.  */
        mask = (mask << 1) - 1;
        if (((base ^ address) & ~mask) == 0) {
            break;
        }
    }
    if (n < 0) {
        *fsr = 2;
        return true;
    }

    if (access_type == 2) {
        mask = env->cp15.pmsav5_insn_ap;
    } else {
        mask = env->cp15.pmsav5_data_ap;
    }
    mask = (mask >> (n * 4)) & 0xf;
    switch (mask) {
    case 0:
        *fsr = 1;
        return true;
    case 1:
        if (is_user) {
            *fsr = 1;
            return true;
        }
        *prot = PAGE_READ | PAGE_WRITE;
        break;
    case 2:
        *prot = PAGE_READ;
        if (!is_user) {
            *prot |= PAGE_WRITE;
        }
        break;
    case 3:
        *prot = PAGE_READ | PAGE_WRITE;
        break;
    case 5:
        if (is_user) {
            *fsr = 1;
            return true;
        }
        *prot = PAGE_READ;
        break;
    case 6:
        *prot = PAGE_READ;
        break;
    default:
        /* Bad permission.  */
        *fsr = 1;
        return true;
    }
    *prot |= PAGE_EXEC;
    return false;
}

/* get_phys_addr - get the physical address for this virtual address
 *
 * Find the physical address corresponding to the given virtual address,
 * by doing a translation table walk on MMU based systems or using the
 * MPU state on MPU based systems.
 *
 * Returns false if the translation was successful. Otherwise, phys_ptr, attrs,
 * prot and page_size may not be filled in, and the populated fsr value provides
 * information on why the translation aborted, in the format of a
 * DFSR/IFSR fault register, with the following caveats:
 *  * we honour the short vs long DFSR format differences.
 *  * the WnR bit is never set (the caller must do this).
 *  * for PSMAv5 based systems we don't bother to return a full FSR format
 *    value.
 *
 * @env: CPUARMState
 * @address: virtual address to get physical address for
 * @access_type: 0 for read, 1 for write, 2 for execute
 * @mmu_idx: MMU index indicating required translation regime
 * @phys_ptr: set to the physical address corresponding to the virtual address
 * @attrs: set to the memory transaction attributes to use
 * @prot: set to the permissions for the page containing phys_ptr
 * @page_size: set to the size of the page containing phys_ptr
 * @fsr: set to the DFSR/IFSR value on failure
 */
bool get_phys_addr(CPUARMState *env, target_ulong address,
                   int access_type, ARMMMUIdx mmu_idx,
                   hwaddr *phys_ptr, MemTxAttrs *attrs, int *prot,
                   target_ulong *page_size, uint32_t *fsr,
                   ARMMMUFaultInfo *fi)
{
    if (mmu_idx == ARMMMUIdx_S12NSE0 || mmu_idx == ARMMMUIdx_S12NSE1) {
        /* Call ourselves recursively to do the stage 1 and then stage 2
         * translations.
         */
        if (arm_feature(env, ARM_FEATURE_EL2)) {
            hwaddr ipa;
            int s2_prot;
            int ret;

            ret = get_phys_addr(env, address, access_type,
                                mmu_idx + ARMMMUIdx_S1NSE0, &ipa, attrs,
                                prot, page_size, fsr, fi);

            /* If S1 fails or S2 is disabled, return early.  */
            if (ret || regime_translation_disabled(env, ARMMMUIdx_S2NS)) {
                *phys_ptr = ipa;
                return ret;
            }

            /* S1 is done. Now do S2 translation.  */
            ret = get_phys_addr_lpae(env, ipa, access_type, ARMMMUIdx_S2NS,
                                     phys_ptr, attrs, &s2_prot,
                                     page_size, fsr, fi);
            fi->s2addr = ipa;
            /* Combine the S1 and S2 perms.  */
            *prot &= s2_prot;
            return ret;
        } else {
            /*
             * For non-EL2 CPUs a stage1+stage2 translation is just stage 1.
             */
            mmu_idx += ARMMMUIdx_S1NSE0;
        }
    }

    /* The page table entries may downgrade secure to non-secure, but
     * cannot upgrade an non-secure translation regime's attributes
     * to secure.
     */
    attrs->secure = regime_is_secure(env, mmu_idx);
    attrs->user = regime_is_user(env, mmu_idx);

    /* Fast Context Switch Extension. This doesn't exist at all in v8.
     * In v7 and earlier it affects all stage 1 translations.
     */
    if (address < 0x02000000 && mmu_idx != ARMMMUIdx_S2NS
        && !arm_feature(env, ARM_FEATURE_V8)) {
        if (regime_el(env, mmu_idx) == 3) {
            address += env->cp15.fcseidr_s;
        } else {
            address += env->cp15.fcseidr_ns;
        }
    }

    /* pmsav7 has special handling for when MPU is disabled so call it before
     * the common MMU/MPU disabled check below.
     */
    if (arm_feature(env, ARM_FEATURE_MPU) &&
        arm_feature(env, ARM_FEATURE_V7)) {
        *page_size = TARGET_PAGE_SIZE;
        return get_phys_addr_pmsav7(env, address, access_type, mmu_idx,
                                    phys_ptr, prot, fsr);
    }

    if (regime_translation_disabled(env, mmu_idx)) {
        /* MMU/MPU disabled.  */
        *phys_ptr = address;
        *prot = PAGE_READ | PAGE_WRITE | PAGE_EXEC;
        *page_size = TARGET_PAGE_SIZE;
        return 0;
    }

    if (arm_feature(env, ARM_FEATURE_MPU)) {
        /* Pre-v7 MPU */
        *page_size = TARGET_PAGE_SIZE;
        return get_phys_addr_pmsav5(env, address, access_type, mmu_idx,
                                    phys_ptr, prot, fsr);
    }

    if (regime_using_lpae_format(env, mmu_idx)) {
        return get_phys_addr_lpae(env, address, access_type, mmu_idx, phys_ptr,
                                  attrs, prot, page_size, fsr, fi);
    } else if (regime_sctlr(env, mmu_idx) & SCTLR_XP) {
        return get_phys_addr_v6(env, address, access_type, mmu_idx, phys_ptr,
                                attrs, prot, page_size, fsr, fi);
    } else {
        return get_phys_addr_v5(env, address, access_type, mmu_idx, phys_ptr,
                                prot, page_size, fsr, fi);
    }
}

/* Walk the page table and (if the mapping exists) add the page
 * to the TLB. Return false on success, or true on failure. Populate
 * fsr with ARM DFSR/IFSR fault register format value on failure.
 */
bool arm_tlb_fill(CPUState *cs, vaddr address,
                  int access_type, int mmu_idx, uint32_t *fsr,
                  ARMMMUFaultInfo *fi)
{
    ARMCPU *cpu = ARM_CPU(cs);
    CPUARMState *env = &cpu->env;
    hwaddr phys_addr;
    target_ulong page_size;
    int prot;
    int ret;
    MemTxAttrs attrs = {};

    ret = get_phys_addr(env, address, access_type, mmu_idx, &phys_addr,
                        &attrs, &prot, &page_size, fsr, fi);
    if (!ret) {
        /* Map a single [sub]page.  */
        phys_addr &= TARGET_PAGE_MASK;
        address &= TARGET_PAGE_MASK;
        tlb_set_page_with_attrs(cs, address, phys_addr, attrs,
                                prot, mmu_idx, page_size);
        return 0;
    }

    return ret;
}

hwaddr arm_cpu_get_phys_page_attrs_debug(CPUState *cs, vaddr addr,
                                         MemTxAttrs *attrs)
{
    ARMCPU *cpu = ARM_CPU(cs);
    CPUARMState *env = &cpu->env;
    hwaddr phys_addr;
    target_ulong page_size;
    int prot;
    bool ret;
    uint32_t fsr;
    ARMMMUFaultInfo fi = {};

    *attrs = (MemTxAttrs) {};

    ret = get_phys_addr(env, addr, 0, cpu_mmu_index(env, false), &phys_addr,
                        attrs, &prot, &page_size, &fsr, &fi);

    if (ret) {
        return -1;
    }
    return phys_addr;
}

uint32_t HELPER(v7m_mrs)(CPUARMState *env, uint32_t reg)
{
    uint32_t mask;
    unsigned el = arm_current_el(env);

    /* First handle registers which unprivileged can read */

    switch (reg) {
    case 0 ... 7: /* xPSR sub-fields */
        mask = 0;
        if ((reg & 1) && el) {
            mask |= 0x000001ff; /* IPSR (unpriv. reads as zero) */
        }
        if (!(reg & 4)) {
            mask |= 0xf8000000; /* APSR */
        }
        /* EPSR reads as zero */
        return xpsr_read(env) & mask;
        break;
    case 20: /* CONTROL */
        return env->v7m.control;
    }

    if (el == 0) {
        return 0; /* unprivileged reads others as zero */
    }

    switch (reg) {
    case 8: /* MSP */
        return (env->v7m.control & R_V7M_CONTROL_SPSEL_MASK) ?
            env->v7m.other_sp : env->regs[13];
    case 9: /* PSP */
        return (env->v7m.control & R_V7M_CONTROL_SPSEL_MASK) ?
            env->regs[13] : env->v7m.other_sp;
    case 16: /* PRIMASK */
        return (env->daif & PSTATE_I) != 0;
    case 17: /* BASEPRI */
    case 18: /* BASEPRI_MAX */
        return env->v7m.basepri;
    case 19: /* FAULTMASK */
        return (env->daif & PSTATE_F) != 0;
    default:
        qemu_log_mask(LOG_GUEST_ERROR, "Attempt to read unknown special"
                                       " register %d\n", reg);
        return 0;
    }
}

void HELPER(v7m_msr)(CPUARMState *env, uint32_t reg, uint32_t val)
{
    if (arm_current_el(env) == 0 && reg > 7) {
        /* only xPSR sub-fields may be written by unprivileged */
        return;
    }

    switch (reg) {
    case 0 ... 7: /* xPSR sub-fields */
        /* only APSR is actually writable */
        if (reg & 4) {
            xpsr_write(env, val, 0xf8000000); /* APSR */
        }
        break;
    case 8: /* MSP */
        if (env->v7m.control & R_V7M_CONTROL_SPSEL_MASK) {
            env->v7m.other_sp = val;
        } else {
            env->regs[13] = val;
        }
        break;
    case 9: /* PSP */
        if (env->v7m.control & R_V7M_CONTROL_SPSEL_MASK) {
            env->regs[13] = val;
        } else {
            env->v7m.other_sp = val;
        }
        break;
    case 16: /* PRIMASK */
        if (val & 1) {
            env->daif |= PSTATE_I;
        } else {
            env->daif &= ~PSTATE_I;
        }
        break;
    case 17: /* BASEPRI */
        env->v7m.basepri = val & 0xff;
        break;
    case 18: /* BASEPRI_MAX */
        val &= 0xff;
        if (val != 0 && (val < env->v7m.basepri || env->v7m.basepri == 0))
            env->v7m.basepri = val;
        break;
    case 19: /* FAULTMASK */
        if (val & 1) {
            env->daif |= PSTATE_F;
        } else {
            env->daif &= ~PSTATE_F;
        }
        break;
    case 20: /* CONTROL */
        switch_v7m_sp(env, (val & R_V7M_CONTROL_SPSEL_MASK) != 0);
        env->v7m.control = val & (R_V7M_CONTROL_SPSEL_MASK |
                                  R_V7M_CONTROL_NPRIV_MASK);
        break;
    default:
        qemu_log_mask(LOG_GUEST_ERROR, "Attempt to write unknown special"
                                       " register %d\n", reg);
        return;
    }
}

#endif

void HELPER(dc_zva)(CPUARMState *env, uint64_t vaddr_in)
{
    /* Implement DC ZVA, which zeroes a fixed-length block of memory.
     * Note that we do not implement the (architecturally mandated)
     * alignment fault for attempts to use this on Device memory
     * (which matches the usual QEMU behaviour of not implementing either
     * alignment faults or any memory attribute handling).
     */

    ARMCPU *cpu = arm_env_get_cpu(env);
    uint64_t blocklen = 4 << cpu->dcz_blocksize;
    uint64_t vaddr = vaddr_in & ~(blocklen - 1);

#ifndef CONFIG_USER_ONLY
    {
        /* Slightly awkwardly, QEMU's TARGET_PAGE_SIZE may be less than
         * the block size so we might have to do more than one TLB lookup.
         * We know that in fact for any v8 CPU the page size is at least 4K
         * and the block size must be 2K or less, but TARGET_PAGE_SIZE is only
         * 1K as an artefact of legacy v5 subpage support being present in the
         * same QEMU executable.
         */
        int maxidx = DIV_ROUND_UP(blocklen, TARGET_PAGE_SIZE);
        void *hostaddr[maxidx];
        int try, i;
        unsigned mmu_idx = cpu_mmu_index(env, false);
        TCGMemOpIdx oi = make_memop_idx(MO_UB, mmu_idx);

        for (try = 0; try < 2; try++) {

            for (i = 0; i < maxidx; i++) {
                hostaddr[i] = tlb_vaddr_to_host(env,
                                                vaddr + TARGET_PAGE_SIZE * i,
                                                1, mmu_idx);
                if (!hostaddr[i]) {
                    break;
                }
            }
            if (i == maxidx) {
                /* If it's all in the TLB it's fair game for just writing to;
                 * we know we don't need to update dirty status, etc.
                 */
                for (i = 0; i < maxidx - 1; i++) {
                    memset(hostaddr[i], 0, TARGET_PAGE_SIZE);
                }
                memset(hostaddr[i], 0, blocklen - (i * TARGET_PAGE_SIZE));
                return;
            }
            /* OK, try a store and see if we can populate the tlb. This
             * might cause an exception if the memory isn't writable,
             * in which case we will longjmp out of here. We must for
             * this purpose use the actual register value passed to us
             * so that we get the fault address right.
             */
            helper_ret_stb_mmu(env, vaddr_in, 0, oi, GETPC());
            /* Now we can populate the other TLB entries, if any */
            for (i = 0; i < maxidx; i++) {
                uint64_t va = vaddr + TARGET_PAGE_SIZE * i;
                if (va != (vaddr_in & TARGET_PAGE_MASK)) {
                    helper_ret_stb_mmu(env, va, 0, oi, GETPC());
                }
            }
        }

        /* Slow path (probably attempt to do this to an I/O device or
         * similar, or clearing of a block of code we have translations
         * cached for). Just do a series of byte writes as the architecture
         * demands. It's not worth trying to use a cpu_physical_memory_map(),
         * memset(), unmap() sequence here because:
         *  + we'd need to account for the blocksize being larger than a page
         *  + the direct-RAM access case is almost always going to be dealt
         *    with in the fastpath code above, so there's no speed benefit
         *  + we would have to deal with the map returning NULL because the
         *    bounce buffer was in use
         */
        for (i = 0; i < blocklen; i++) {
            helper_ret_stb_mmu(env, vaddr + i, 0, oi, GETPC());
        }
    }
#else
    memset(g2h(vaddr), 0, blocklen);
#endif
}

/* Note that signed overflow is undefined in C.  The following routines are
   careful to use unsigned types where modulo arithmetic is required.
   Failure to do so _will_ break on newer gcc.  */

/* Signed saturating arithmetic.  */

/* Perform 16-bit signed saturating addition.  */
static inline uint16_t add16_sat(uint16_t a, uint16_t b)
{
    uint16_t res;

    res = a + b;
    if (((res ^ a) & 0x8000) && !((a ^ b) & 0x8000)) {
        if (a & 0x8000)
            res = 0x8000;
        else
            res = 0x7fff;
    }
    return res;
}

/* Perform 8-bit signed saturating addition.  */
static inline uint8_t add8_sat(uint8_t a, uint8_t b)
{
    uint8_t res;

    res = a + b;
    if (((res ^ a) & 0x80) && !((a ^ b) & 0x80)) {
        if (a & 0x80)
            res = 0x80;
        else
            res = 0x7f;
    }
    return res;
}

/* Perform 16-bit signed saturating subtraction.  */
static inline uint16_t sub16_sat(uint16_t a, uint16_t b)
{
    uint16_t res;

    res = a - b;
    if (((res ^ a) & 0x8000) && ((a ^ b) & 0x8000)) {
        if (a & 0x8000)
            res = 0x8000;
        else
            res = 0x7fff;
    }
    return res;
}

/* Perform 8-bit signed saturating subtraction.  */
static inline uint8_t sub8_sat(uint8_t a, uint8_t b)
{
    uint8_t res;

    res = a - b;
    if (((res ^ a) & 0x80) && ((a ^ b) & 0x80)) {
        if (a & 0x80)
            res = 0x80;
        else
            res = 0x7f;
    }
    return res;
}

#define ADD16(a, b, n) RESULT(add16_sat(a, b), n, 16);
#define SUB16(a, b, n) RESULT(sub16_sat(a, b), n, 16);
#define ADD8(a, b, n)  RESULT(add8_sat(a, b), n, 8);
#define SUB8(a, b, n)  RESULT(sub8_sat(a, b), n, 8);
#define PFX q

#include "op_addsub.h"

/* Unsigned saturating arithmetic.  */
static inline uint16_t add16_usat(uint16_t a, uint16_t b)
{
    uint16_t res;
    res = a + b;
    if (res < a)
        res = 0xffff;
    return res;
}

static inline uint16_t sub16_usat(uint16_t a, uint16_t b)
{
    if (a > b)
        return a - b;
    else
        return 0;
}

static inline uint8_t add8_usat(uint8_t a, uint8_t b)
{
    uint8_t res;
    res = a + b;
    if (res < a)
        res = 0xff;
    return res;
}

static inline uint8_t sub8_usat(uint8_t a, uint8_t b)
{
    if (a > b)
        return a - b;
    else
        return 0;
}

#define ADD16(a, b, n) RESULT(add16_usat(a, b), n, 16);
#define SUB16(a, b, n) RESULT(sub16_usat(a, b), n, 16);
#define ADD8(a, b, n)  RESULT(add8_usat(a, b), n, 8);
#define SUB8(a, b, n)  RESULT(sub8_usat(a, b), n, 8);
#define PFX uq

#include "op_addsub.h"

/* Signed modulo arithmetic.  */
#define SARITH16(a, b, n, op) do { \
    int32_t sum; \
    sum = (int32_t)(int16_t)(a) op (int32_t)(int16_t)(b); \
    RESULT(sum, n, 16); \
    if (sum >= 0) \
        ge |= 3 << (n * 2); \
    } while(0)

#define SARITH8(a, b, n, op) do { \
    int32_t sum; \
    sum = (int32_t)(int8_t)(a) op (int32_t)(int8_t)(b); \
    RESULT(sum, n, 8); \
    if (sum >= 0) \
        ge |= 1 << n; \
    } while(0)


#define ADD16(a, b, n) SARITH16(a, b, n, +)
#define SUB16(a, b, n) SARITH16(a, b, n, -)
#define ADD8(a, b, n)  SARITH8(a, b, n, +)
#define SUB8(a, b, n)  SARITH8(a, b, n, -)
#define PFX s
#define ARITH_GE

#include "op_addsub.h"

/* Unsigned modulo arithmetic.  */
#define ADD16(a, b, n) do { \
    uint32_t sum; \
    sum = (uint32_t)(uint16_t)(a) + (uint32_t)(uint16_t)(b); \
    RESULT(sum, n, 16); \
    if ((sum >> 16) == 1) \
        ge |= 3 << (n * 2); \
    } while(0)

#define ADD8(a, b, n) do { \
    uint32_t sum; \
    sum = (uint32_t)(uint8_t)(a) + (uint32_t)(uint8_t)(b); \
    RESULT(sum, n, 8); \
    if ((sum >> 8) == 1) \
        ge |= 1 << n; \
    } while(0)

#define SUB16(a, b, n) do { \
    uint32_t sum; \
    sum = (uint32_t)(uint16_t)(a) - (uint32_t)(uint16_t)(b); \
    RESULT(sum, n, 16); \
    if ((sum >> 16) == 0) \
        ge |= 3 << (n * 2); \
    } while(0)

#define SUB8(a, b, n) do { \
    uint32_t sum; \
    sum = (uint32_t)(uint8_t)(a) - (uint32_t)(uint8_t)(b); \
    RESULT(sum, n, 8); \
    if ((sum >> 8) == 0) \
        ge |= 1 << n; \
    } while(0)

#define PFX u
#define ARITH_GE

#include "op_addsub.h"

/* Halved signed arithmetic.  */
#define ADD16(a, b, n) \
  RESULT(((int32_t)(int16_t)(a) + (int32_t)(int16_t)(b)) >> 1, n, 16)
#define SUB16(a, b, n) \
  RESULT(((int32_t)(int16_t)(a) - (int32_t)(int16_t)(b)) >> 1, n, 16)
#define ADD8(a, b, n) \
  RESULT(((int32_t)(int8_t)(a) + (int32_t)(int8_t)(b)) >> 1, n, 8)
#define SUB8(a, b, n) \
  RESULT(((int32_t)(int8_t)(a) - (int32_t)(int8_t)(b)) >> 1, n, 8)
#define PFX sh

#include "op_addsub.h"

/* Halved unsigned arithmetic.  */
#define ADD16(a, b, n) \
  RESULT(((uint32_t)(uint16_t)(a) + (uint32_t)(uint16_t)(b)) >> 1, n, 16)
#define SUB16(a, b, n) \
  RESULT(((uint32_t)(uint16_t)(a) - (uint32_t)(uint16_t)(b)) >> 1, n, 16)
#define ADD8(a, b, n) \
  RESULT(((uint32_t)(uint8_t)(a) + (uint32_t)(uint8_t)(b)) >> 1, n, 8)
#define SUB8(a, b, n) \
  RESULT(((uint32_t)(uint8_t)(a) - (uint32_t)(uint8_t)(b)) >> 1, n, 8)
#define PFX uh

#include "op_addsub.h"

static inline uint8_t do_usad(uint8_t a, uint8_t b)
{
    if (a > b)
        return a - b;
    else
        return b - a;
}

/* Unsigned sum of absolute byte differences.  */
uint32_t HELPER(usad8)(uint32_t a, uint32_t b)
{
    uint32_t sum;
    sum = do_usad(a, b);
    sum += do_usad(a >> 8, b >> 8);
    sum += do_usad(a >> 16, b >>16);
    sum += do_usad(a >> 24, b >> 24);
    return sum;
}

/* For ARMv6 SEL instruction.  */
uint32_t HELPER(sel_flags)(uint32_t flags, uint32_t a, uint32_t b)
{
    uint32_t mask;

    mask = 0;
    if (flags & 1)
        mask |= 0xff;
    if (flags & 2)
        mask |= 0xff00;
    if (flags & 4)
        mask |= 0xff0000;
    if (flags & 8)
        mask |= 0xff000000;
    return (a & mask) | (b & ~mask);
}

uint32_t HELPER(vfp_get_fpscr)(CPUARMState *env)
{
    return vfp_get_fpscr(env);
}

void HELPER(vfp_set_fpscr)(CPUARMState *env, uint32_t val)
{
    vfp_set_fpscr(env, val);
}

#define VFP_HELPER(name, p) HELPER(glue(glue(vfp_,name),p))

#define VFP_BINOP(name) \
float32 VFP_HELPER(name, s)(float32 a, float32 b, void *fpstp) \
{ \
    float_status *fpst = fpstp; \
    return float32_ ## name(a, b, fpst); \
} \
float64 VFP_HELPER(name, d)(float64 a, float64 b, void *fpstp) \
{ \
    float_status *fpst = fpstp; \
    return float64_ ## name(a, b, fpst); \
}
VFP_BINOP(add)
VFP_BINOP(sub)
VFP_BINOP(mul)
VFP_BINOP(div)
VFP_BINOP(min)
VFP_BINOP(max)
VFP_BINOP(minnum)
VFP_BINOP(maxnum)
#undef VFP_BINOP

float32 VFP_HELPER(neg, s)(float32 a)
{
    return float32_chs(a);
}

float64 VFP_HELPER(neg, d)(float64 a)
{
    return float64_chs(a);
}

float32 VFP_HELPER(abs, s)(float32 a)
{
    return float32_abs(a);
}

float64 VFP_HELPER(abs, d)(float64 a)
{
    return float64_abs(a);
}

float32 VFP_HELPER(sqrt, s)(float32 a, CPUARMState *env)
{
    return float32_sqrt(a, &env->vfp.fp_status);
}

float64 VFP_HELPER(sqrt, d)(float64 a, CPUARMState *env)
{
    return float64_sqrt(a, &env->vfp.fp_status);
}

/* XXX: check quiet/signaling case */
#define DO_VFP_cmp(p, type) \
void VFP_HELPER(cmp, p)(type a, type b, CPUARMState *env)  \
{ \
    uint32_t flags; \
    switch(type ## _compare_quiet(a, b, &env->vfp.fp_status)) { \
    case 0: flags = 0x6; break; \
    case -1: flags = 0x8; break; \
    case 1: flags = 0x2; break; \
    default: case 2: flags = 0x3; break; \
    } \
    env->vfp.xregs[ARM_VFP_FPSCR] = (flags << 28) \
        | (env->vfp.xregs[ARM_VFP_FPSCR] & 0x0fffffff); \
} \
void VFP_HELPER(cmpe, p)(type a, type b, CPUARMState *env) \
{ \
    uint32_t flags; \
    switch(type ## _compare(a, b, &env->vfp.fp_status)) { \
    case 0: flags = 0x6; break; \
    case -1: flags = 0x8; break; \
    case 1: flags = 0x2; break; \
    default: case 2: flags = 0x3; break; \
    } \
    env->vfp.xregs[ARM_VFP_FPSCR] = (flags << 28) \
        | (env->vfp.xregs[ARM_VFP_FPSCR] & 0x0fffffff); \
}
DO_VFP_cmp(s, float32)
DO_VFP_cmp(d, float64)
#undef DO_VFP_cmp

/* Integer to float and float to integer conversions */

#define CONV_ITOF(name, fsz, sign) \
    float##fsz HELPER(name)(uint32_t x, void *fpstp) \
{ \
    float_status *fpst = fpstp; \
    return sign##int32_to_##float##fsz((sign##int32_t)x, fpst); \
}

#define CONV_FTOI(name, fsz, sign, round) \
uint32_t HELPER(name)(float##fsz x, void *fpstp) \
{ \
    float_status *fpst = fpstp; \
    if (float##fsz##_is_any_nan(x)) { \
        float_raise(float_flag_invalid, fpst); \
        return 0; \
    } \
    return float##fsz##_to_##sign##int32##round(x, fpst); \
}

#define FLOAT_CONVS(name, p, fsz, sign) \
CONV_ITOF(vfp_##name##to##p, fsz, sign) \
CONV_FTOI(vfp_to##name##p, fsz, sign, ) \
CONV_FTOI(vfp_to##name##z##p, fsz, sign, _round_to_zero)

FLOAT_CONVS(si, s, 32, )
FLOAT_CONVS(si, d, 64, )
FLOAT_CONVS(ui, s, 32, u)
FLOAT_CONVS(ui, d, 64, u)

#undef CONV_ITOF
#undef CONV_FTOI
#undef FLOAT_CONVS

/* floating point conversion */
float64 VFP_HELPER(fcvtd, s)(float32 x, CPUARMState *env)
{
    float64 r = float32_to_float64(x, &env->vfp.fp_status);
    /* ARM requires that S<->D conversion of any kind of NaN generates
     * a quiet NaN by forcing the most significant frac bit to 1.
     */
    return float64_maybe_silence_nan(r, &env->vfp.fp_status);
}

float32 VFP_HELPER(fcvts, d)(float64 x, CPUARMState *env)
{
    float32 r =  float64_to_float32(x, &env->vfp.fp_status);
    /* ARM requires that S<->D conversion of any kind of NaN generates
     * a quiet NaN by forcing the most significant frac bit to 1.
     */
    return float32_maybe_silence_nan(r, &env->vfp.fp_status);
}

/* VFP3 fixed point conversion.  */
#define VFP_CONV_FIX_FLOAT(name, p, fsz, isz, itype) \
float##fsz HELPER(vfp_##name##to##p)(uint##isz##_t  x, uint32_t shift, \
                                     void *fpstp) \
{ \
    float_status *fpst = fpstp; \
    float##fsz tmp; \
    tmp = itype##_to_##float##fsz(x, fpst); \
    return float##fsz##_scalbn(tmp, -(int)shift, fpst); \
}

/* Notice that we want only input-denormal exception flags from the
 * scalbn operation: the other possible flags (overflow+inexact if
 * we overflow to infinity, output-denormal) aren't correct for the
 * complete scale-and-convert operation.
 */
#define VFP_CONV_FLOAT_FIX_ROUND(name, p, fsz, isz, itype, round) \
uint##isz##_t HELPER(vfp_to##name##p##round)(float##fsz x, \
                                             uint32_t shift, \
                                             void *fpstp) \
{ \
    float_status *fpst = fpstp; \
    int old_exc_flags = get_float_exception_flags(fpst); \
    float##fsz tmp; \
    if (float##fsz##_is_any_nan(x)) { \
        float_raise(float_flag_invalid, fpst); \
        return 0; \
    } \
    tmp = float##fsz##_scalbn(x, shift, fpst); \
    old_exc_flags |= get_float_exception_flags(fpst) \
        & float_flag_input_denormal; \
    set_float_exception_flags(old_exc_flags, fpst); \
    return float##fsz##_to_##itype##round(tmp, fpst); \
}

#define VFP_CONV_FIX(name, p, fsz, isz, itype)                   \
VFP_CONV_FIX_FLOAT(name, p, fsz, isz, itype)                     \
VFP_CONV_FLOAT_FIX_ROUND(name, p, fsz, isz, itype, _round_to_zero) \
VFP_CONV_FLOAT_FIX_ROUND(name, p, fsz, isz, itype, )

#define VFP_CONV_FIX_A64(name, p, fsz, isz, itype)               \
VFP_CONV_FIX_FLOAT(name, p, fsz, isz, itype)                     \
VFP_CONV_FLOAT_FIX_ROUND(name, p, fsz, isz, itype, )

VFP_CONV_FIX(sh, d, 64, 64, int16)
VFP_CONV_FIX(sl, d, 64, 64, int32)
VFP_CONV_FIX_A64(sq, d, 64, 64, int64)
VFP_CONV_FIX(uh, d, 64, 64, uint16)
VFP_CONV_FIX(ul, d, 64, 64, uint32)
VFP_CONV_FIX_A64(uq, d, 64, 64, uint64)
VFP_CONV_FIX(sh, s, 32, 32, int16)
VFP_CONV_FIX(sl, s, 32, 32, int32)
VFP_CONV_FIX_A64(sq, s, 32, 64, int64)
VFP_CONV_FIX(uh, s, 32, 32, uint16)
VFP_CONV_FIX(ul, s, 32, 32, uint32)
VFP_CONV_FIX_A64(uq, s, 32, 64, uint64)
#undef VFP_CONV_FIX
#undef VFP_CONV_FIX_FLOAT
#undef VFP_CONV_FLOAT_FIX_ROUND

/* Set the current fp rounding mode and return the old one.
 * The argument is a softfloat float_round_ value.
 */
uint32_t HELPER(set_rmode)(uint32_t rmode, CPUARMState *env)
{
    float_status *fp_status = &env->vfp.fp_status;

    uint32_t prev_rmode = get_float_rounding_mode(fp_status);
    set_float_rounding_mode(rmode, fp_status);

    return prev_rmode;
}

/* Set the current fp rounding mode in the standard fp status and return
 * the old one. This is for NEON instructions that need to change the
 * rounding mode but wish to use the standard FPSCR values for everything
 * else. Always set the rounding mode back to the correct value after
 * modifying it.
 * The argument is a softfloat float_round_ value.
 */
uint32_t HELPER(set_neon_rmode)(uint32_t rmode, CPUARMState *env)
{
    float_status *fp_status = &env->vfp.standard_fp_status;

    uint32_t prev_rmode = get_float_rounding_mode(fp_status);
    set_float_rounding_mode(rmode, fp_status);

    return prev_rmode;
}

/* Half precision conversions.  */
static float32 do_fcvt_f16_to_f32(uint32_t a, CPUARMState *env, float_status *s)
{
    int ieee = (env->vfp.xregs[ARM_VFP_FPSCR] & (1 << 26)) == 0;
    float32 r = float16_to_float32(make_float16(a), ieee, s);
    if (ieee) {
        return float32_maybe_silence_nan(r, s);
    }
    return r;
}

static uint32_t do_fcvt_f32_to_f16(float32 a, CPUARMState *env, float_status *s)
{
    int ieee = (env->vfp.xregs[ARM_VFP_FPSCR] & (1 << 26)) == 0;
    float16 r = float32_to_float16(a, ieee, s);
    if (ieee) {
        r = float16_maybe_silence_nan(r, s);
    }
    return float16_val(r);
}

float32 HELPER(neon_fcvt_f16_to_f32)(uint32_t a, CPUARMState *env)
{
    return do_fcvt_f16_to_f32(a, env, &env->vfp.standard_fp_status);
}

uint32_t HELPER(neon_fcvt_f32_to_f16)(float32 a, CPUARMState *env)
{
    return do_fcvt_f32_to_f16(a, env, &env->vfp.standard_fp_status);
}

float32 HELPER(vfp_fcvt_f16_to_f32)(uint32_t a, CPUARMState *env)
{
    return do_fcvt_f16_to_f32(a, env, &env->vfp.fp_status);
}

uint32_t HELPER(vfp_fcvt_f32_to_f16)(float32 a, CPUARMState *env)
{
    return do_fcvt_f32_to_f16(a, env, &env->vfp.fp_status);
}

float64 HELPER(vfp_fcvt_f16_to_f64)(uint32_t a, CPUARMState *env)
{
    int ieee = (env->vfp.xregs[ARM_VFP_FPSCR] & (1 << 26)) == 0;
    float64 r = float16_to_float64(make_float16(a), ieee, &env->vfp.fp_status);
    if (ieee) {
        return float64_maybe_silence_nan(r, &env->vfp.fp_status);
    }
    return r;
}

uint32_t HELPER(vfp_fcvt_f64_to_f16)(float64 a, CPUARMState *env)
{
    int ieee = (env->vfp.xregs[ARM_VFP_FPSCR] & (1 << 26)) == 0;
    float16 r = float64_to_float16(a, ieee, &env->vfp.fp_status);
    if (ieee) {
        r = float16_maybe_silence_nan(r, &env->vfp.fp_status);
    }
    return float16_val(r);
}

#define float32_two make_float32(0x40000000)
#define float32_three make_float32(0x40400000)
#define float32_one_point_five make_float32(0x3fc00000)

float32 HELPER(recps_f32)(float32 a, float32 b, CPUARMState *env)
{
    float_status *s = &env->vfp.standard_fp_status;
    if ((float32_is_infinity(a) && float32_is_zero_or_denormal(b)) ||
        (float32_is_infinity(b) && float32_is_zero_or_denormal(a))) {
        if (!(float32_is_zero(a) || float32_is_zero(b))) {
            float_raise(float_flag_input_denormal, s);
        }
        return float32_two;
    }
    return float32_sub(float32_two, float32_mul(a, b, s), s);
}

float32 HELPER(rsqrts_f32)(float32 a, float32 b, CPUARMState *env)
{
    float_status *s = &env->vfp.standard_fp_status;
    float32 product;
    if ((float32_is_infinity(a) && float32_is_zero_or_denormal(b)) ||
        (float32_is_infinity(b) && float32_is_zero_or_denormal(a))) {
        if (!(float32_is_zero(a) || float32_is_zero(b))) {
            float_raise(float_flag_input_denormal, s);
        }
        return float32_one_point_five;
    }
    product = float32_mul(a, b, s);
    return float32_div(float32_sub(float32_three, product, s), float32_two, s);
}

/* NEON helpers.  */

/* Constants 256 and 512 are used in some helpers; we avoid relying on
 * int->float conversions at run-time.  */
#define float64_256 make_float64(0x4070000000000000LL)
#define float64_512 make_float64(0x4080000000000000LL)
#define float32_maxnorm make_float32(0x7f7fffff)
#define float64_maxnorm make_float64(0x7fefffffffffffffLL)

/* Reciprocal functions
 *
 * The algorithm that must be used to calculate the estimate
 * is specified by the ARM ARM, see FPRecipEstimate()
 */

static float64 recip_estimate(float64 a, float_status *real_fp_status)
{
    /* These calculations mustn't set any fp exception flags,
     * so we use a local copy of the fp_status.
     */
    float_status dummy_status = *real_fp_status;
    float_status *s = &dummy_status;
    /* q = (int)(a * 512.0) */
    float64 q = float64_mul(float64_512, a, s);
    int64_t q_int = float64_to_int64_round_to_zero(q, s);

    /* r = 1.0 / (((double)q + 0.5) / 512.0) */
    q = int64_to_float64(q_int, s);
    q = float64_add(q, float64_half, s);
    q = float64_div(q, float64_512, s);
    q = float64_div(float64_one, q, s);

    /* s = (int)(256.0 * r + 0.5) */
    q = float64_mul(q, float64_256, s);
    q = float64_add(q, float64_half, s);
    q_int = float64_to_int64_round_to_zero(q, s);

    /* return (double)s / 256.0 */
    return float64_div(int64_to_float64(q_int, s), float64_256, s);
}

/* Common wrapper to call recip_estimate */
static float64 call_recip_estimate(float64 num, int off, float_status *fpst)
{
    uint64_t val64 = float64_val(num);
    uint64_t frac = extract64(val64, 0, 52);
    int64_t exp = extract64(val64, 52, 11);
    uint64_t sbit;
    float64 scaled, estimate;

    /* Generate the scaled number for the estimate function */
    if (exp == 0) {
        if (extract64(frac, 51, 1) == 0) {
            exp = -1;
            frac = extract64(frac, 0, 50) << 2;
        } else {
            frac = extract64(frac, 0, 51) << 1;
        }
    }

    /* scaled = '0' : '01111111110' : fraction<51:44> : Zeros(44); */
    scaled = make_float64((0x3feULL << 52)
                          | extract64(frac, 44, 8) << 44);

    estimate = recip_estimate(scaled, fpst);

    /* Build new result */
    val64 = float64_val(estimate);
    sbit = 0x8000000000000000ULL & val64;
    exp = off - exp;
    frac = extract64(val64, 0, 52);

    if (exp == 0) {
        frac = 1ULL << 51 | extract64(frac, 1, 51);
    } else if (exp == -1) {
        frac = 1ULL << 50 | extract64(frac, 2, 50);
        exp = 0;
    }

    return make_float64(sbit | (exp << 52) | frac);
}

static bool round_to_inf(float_status *fpst, bool sign_bit)
{
    switch (fpst->float_rounding_mode) {
    case float_round_nearest_even: /* Round to Nearest */
        return true;
    case float_round_up: /* Round to +Inf */
        return !sign_bit;
    case float_round_down: /* Round to -Inf */
        return sign_bit;
    case float_round_to_zero: /* Round to Zero */
        return false;
    }

    g_assert_not_reached();
}

float32 HELPER(recpe_f32)(float32 input, void *fpstp)
{
    float_status *fpst = fpstp;
    float32 f32 = float32_squash_input_denormal(input, fpst);
    uint32_t f32_val = float32_val(f32);
    uint32_t f32_sbit = 0x80000000ULL & f32_val;
    int32_t f32_exp = extract32(f32_val, 23, 8);
    uint32_t f32_frac = extract32(f32_val, 0, 23);
    float64 f64, r64;
    uint64_t r64_val;
    int64_t r64_exp;
    uint64_t r64_frac;

    if (float32_is_any_nan(f32)) {
        float32 nan = f32;
        if (float32_is_signaling_nan(f32, fpst)) {
            float_raise(float_flag_invalid, fpst);
            nan = float32_maybe_silence_nan(f32, fpst);
        }
        if (fpst->default_nan_mode) {
            nan =  float32_default_nan(fpst);
        }
        return nan;
    } else if (float32_is_infinity(f32)) {
        return float32_set_sign(float32_zero, float32_is_neg(f32));
    } else if (float32_is_zero(f32)) {
        float_raise(float_flag_divbyzero, fpst);
        return float32_set_sign(float32_infinity, float32_is_neg(f32));
    } else if ((f32_val & ~(1ULL << 31)) < (1ULL << 21)) {
        /* Abs(value) < 2.0^-128 */
        float_raise(float_flag_overflow | float_flag_inexact, fpst);
        if (round_to_inf(fpst, f32_sbit)) {
            return float32_set_sign(float32_infinity, float32_is_neg(f32));
        } else {
            return float32_set_sign(float32_maxnorm, float32_is_neg(f32));
        }
    } else if (f32_exp >= 253 && fpst->flush_to_zero) {
        float_raise(float_flag_underflow, fpst);
        return float32_set_sign(float32_zero, float32_is_neg(f32));
    }


    f64 = make_float64(((int64_t)(f32_exp) << 52) | (int64_t)(f32_frac) << 29);
    r64 = call_recip_estimate(f64, 253, fpst);
    r64_val = float64_val(r64);
    r64_exp = extract64(r64_val, 52, 11);
    r64_frac = extract64(r64_val, 0, 52);

    /* result = sign : result_exp<7:0> : fraction<51:29>; */
    return make_float32(f32_sbit |
                        (r64_exp & 0xff) << 23 |
                        extract64(r64_frac, 29, 24));
}

float64 HELPER(recpe_f64)(float64 input, void *fpstp)
{
    float_status *fpst = fpstp;
    float64 f64 = float64_squash_input_denormal(input, fpst);
    uint64_t f64_val = float64_val(f64);
    uint64_t f64_sbit = 0x8000000000000000ULL & f64_val;
    int64_t f64_exp = extract64(f64_val, 52, 11);
    float64 r64;
    uint64_t r64_val;
    int64_t r64_exp;
    uint64_t r64_frac;

    /* Deal with any special cases */
    if (float64_is_any_nan(f64)) {
        float64 nan = f64;
        if (float64_is_signaling_nan(f64, fpst)) {
            float_raise(float_flag_invalid, fpst);
            nan = float64_maybe_silence_nan(f64, fpst);
        }
        if (fpst->default_nan_mode) {
            nan =  float64_default_nan(fpst);
        }
        return nan;
    } else if (float64_is_infinity(f64)) {
        return float64_set_sign(float64_zero, float64_is_neg(f64));
    } else if (float64_is_zero(f64)) {
        float_raise(float_flag_divbyzero, fpst);
        return float64_set_sign(float64_infinity, float64_is_neg(f64));
    } else if ((f64_val & ~(1ULL << 63)) < (1ULL << 50)) {
        /* Abs(value) < 2.0^-1024 */
        float_raise(float_flag_overflow | float_flag_inexact, fpst);
        if (round_to_inf(fpst, f64_sbit)) {
            return float64_set_sign(float64_infinity, float64_is_neg(f64));
        } else {
            return float64_set_sign(float64_maxnorm, float64_is_neg(f64));
        }
    } else if (f64_exp >= 2045 && fpst->flush_to_zero) {
        float_raise(float_flag_underflow, fpst);
        return float64_set_sign(float64_zero, float64_is_neg(f64));
    }

    r64 = call_recip_estimate(f64, 2045, fpst);
    r64_val = float64_val(r64);
    r64_exp = extract64(r64_val, 52, 11);
    r64_frac = extract64(r64_val, 0, 52);

    /* result = sign : result_exp<10:0> : fraction<51:0> */
    return make_float64(f64_sbit |
                        ((r64_exp & 0x7ff) << 52) |
                        r64_frac);
}

/* The algorithm that must be used to calculate the estimate
 * is specified by the ARM ARM.
 */
static float64 recip_sqrt_estimate(float64 a, float_status *real_fp_status)
{
    /* These calculations mustn't set any fp exception flags,
     * so we use a local copy of the fp_status.
     */
    float_status dummy_status = *real_fp_status;
    float_status *s = &dummy_status;
    float64 q;
    int64_t q_int;

    if (float64_lt(a, float64_half, s)) {
        /* range 0.25 <= a < 0.5 */

        /* a in units of 1/512 rounded down */
        /* q0 = (int)(a * 512.0);  */
        q = float64_mul(float64_512, a, s);
        q_int = float64_to_int64_round_to_zero(q, s);

        /* reciprocal root r */
        /* r = 1.0 / sqrt(((double)q0 + 0.5) / 512.0);  */
        q = int64_to_float64(q_int, s);
        q = float64_add(q, float64_half, s);
        q = float64_div(q, float64_512, s);
        q = float64_sqrt(q, s);
        q = float64_div(float64_one, q, s);
    } else {
        /* range 0.5 <= a < 1.0 */

        /* a in units of 1/256 rounded down */
        /* q1 = (int)(a * 256.0); */
        q = float64_mul(float64_256, a, s);
        int64_t q_int = float64_to_int64_round_to_zero(q, s);

        /* reciprocal root r */
        /* r = 1.0 /sqrt(((double)q1 + 0.5) / 256); */
        q = int64_to_float64(q_int, s);
        q = float64_add(q, float64_half, s);
        q = float64_div(q, float64_256, s);
        q = float64_sqrt(q, s);
        q = float64_div(float64_one, q, s);
    }
    /* r in units of 1/256 rounded to nearest */
    /* s = (int)(256.0 * r + 0.5); */

    q = float64_mul(q, float64_256,s );
    q = float64_add(q, float64_half, s);
    q_int = float64_to_int64_round_to_zero(q, s);

    /* return (double)s / 256.0;*/
    return float64_div(int64_to_float64(q_int, s), float64_256, s);
}

float32 HELPER(rsqrte_f32)(float32 input, void *fpstp)
{
    float_status *s = fpstp;
    float32 f32 = float32_squash_input_denormal(input, s);
    uint32_t val = float32_val(f32);
    uint32_t f32_sbit = 0x80000000 & val;
    int32_t f32_exp = extract32(val, 23, 8);
    uint32_t f32_frac = extract32(val, 0, 23);
    uint64_t f64_frac;
    uint64_t val64;
    int result_exp;
    float64 f64;

    if (float32_is_any_nan(f32)) {
        float32 nan = f32;
        if (float32_is_signaling_nan(f32, s)) {
            float_raise(float_flag_invalid, s);
            nan = float32_maybe_silence_nan(f32, s);
        }
        if (s->default_nan_mode) {
            nan =  float32_default_nan(s);
        }
        return nan;
    } else if (float32_is_zero(f32)) {
        float_raise(float_flag_divbyzero, s);
        return float32_set_sign(float32_infinity, float32_is_neg(f32));
    } else if (float32_is_neg(f32)) {
        float_raise(float_flag_invalid, s);
        return float32_default_nan(s);
    } else if (float32_is_infinity(f32)) {
        return float32_zero;
    }

    /* Scale and normalize to a double-precision value between 0.25 and 1.0,
     * preserving the parity of the exponent.  */

    f64_frac = ((uint64_t) f32_frac) << 29;
    if (f32_exp == 0) {
        while (extract64(f64_frac, 51, 1) == 0) {
            f64_frac = f64_frac << 1;
            f32_exp = f32_exp-1;
        }
        f64_frac = extract64(f64_frac, 0, 51) << 1;
    }

    if (extract64(f32_exp, 0, 1) == 0) {
        f64 = make_float64(((uint64_t) f32_sbit) << 32
                           | (0x3feULL << 52)
                           | f64_frac);
    } else {
        f64 = make_float64(((uint64_t) f32_sbit) << 32
                           | (0x3fdULL << 52)
                           | f64_frac);
    }

    result_exp = (380 - f32_exp) / 2;

    f64 = recip_sqrt_estimate(f64, s);

    val64 = float64_val(f64);

    val = ((result_exp & 0xff) << 23)
        | ((val64 >> 29)  & 0x7fffff);
    return make_float32(val);
}

float64 HELPER(rsqrte_f64)(float64 input, void *fpstp)
{
    float_status *s = fpstp;
    float64 f64 = float64_squash_input_denormal(input, s);
    uint64_t val = float64_val(f64);
    uint64_t f64_sbit = 0x8000000000000000ULL & val;
    int64_t f64_exp = extract64(val, 52, 11);
    uint64_t f64_frac = extract64(val, 0, 52);
    int64_t result_exp;
    uint64_t result_frac;

    if (float64_is_any_nan(f64)) {
        float64 nan = f64;
        if (float64_is_signaling_nan(f64, s)) {
            float_raise(float_flag_invalid, s);
            nan = float64_maybe_silence_nan(f64, s);
        }
        if (s->default_nan_mode) {
            nan =  float64_default_nan(s);
        }
        return nan;
    } else if (float64_is_zero(f64)) {
        float_raise(float_flag_divbyzero, s);
        return float64_set_sign(float64_infinity, float64_is_neg(f64));
    } else if (float64_is_neg(f64)) {
        float_raise(float_flag_invalid, s);
        return float64_default_nan(s);
    } else if (float64_is_infinity(f64)) {
        return float64_zero;
    }

    /* Scale and normalize to a double-precision value between 0.25 and 1.0,
     * preserving the parity of the exponent.  */

    if (f64_exp == 0) {
        while (extract64(f64_frac, 51, 1) == 0) {
            f64_frac = f64_frac << 1;
            f64_exp = f64_exp - 1;
        }
        f64_frac = extract64(f64_frac, 0, 51) << 1;
    }

    if (extract64(f64_exp, 0, 1) == 0) {
        f64 = make_float64(f64_sbit
                           | (0x3feULL << 52)
                           | f64_frac);
    } else {
        f64 = make_float64(f64_sbit
                           | (0x3fdULL << 52)
                           | f64_frac);
    }

    result_exp = (3068 - f64_exp) / 2;

    f64 = recip_sqrt_estimate(f64, s);

    result_frac = extract64(float64_val(f64), 0, 52);

    return make_float64(f64_sbit |
                        ((result_exp & 0x7ff) << 52) |
                        result_frac);
}

uint32_t HELPER(recpe_u32)(uint32_t a, void *fpstp)
{
    float_status *s = fpstp;
    float64 f64;

    if ((a & 0x80000000) == 0) {
        return 0xffffffff;
    }

    f64 = make_float64((0x3feULL << 52)
                       | ((int64_t)(a & 0x7fffffff) << 21));

    f64 = recip_estimate(f64, s);

    return 0x80000000 | ((float64_val(f64) >> 21) & 0x7fffffff);
}

uint32_t HELPER(rsqrte_u32)(uint32_t a, void *fpstp)
{
    float_status *fpst = fpstp;
    float64 f64;

    if ((a & 0xc0000000) == 0) {
        return 0xffffffff;
    }

    if (a & 0x80000000) {
        f64 = make_float64((0x3feULL << 52)
                           | ((uint64_t)(a & 0x7fffffff) << 21));
    } else { /* bits 31-30 == '01' */
        f64 = make_float64((0x3fdULL << 52)
                           | ((uint64_t)(a & 0x3fffffff) << 22));
    }

    f64 = recip_sqrt_estimate(f64, fpst);

    return 0x80000000 | ((float64_val(f64) >> 21) & 0x7fffffff);
}

/* VFPv4 fused multiply-accumulate */
float32 VFP_HELPER(muladd, s)(float32 a, float32 b, float32 c, void *fpstp)
{
    float_status *fpst = fpstp;
    return float32_muladd(a, b, c, 0, fpst);
}

float64 VFP_HELPER(muladd, d)(float64 a, float64 b, float64 c, void *fpstp)
{
    float_status *fpst = fpstp;
    return float64_muladd(a, b, c, 0, fpst);
}

/* ARMv8 round to integral */
float32 HELPER(rints_exact)(float32 x, void *fp_status)
{
    return float32_round_to_int(x, fp_status);
}

float64 HELPER(rintd_exact)(float64 x, void *fp_status)
{
    return float64_round_to_int(x, fp_status);
}

float32 HELPER(rints)(float32 x, void *fp_status)
{
    int old_flags = get_float_exception_flags(fp_status), new_flags;
    float32 ret;

    ret = float32_round_to_int(x, fp_status);

    /* Suppress any inexact exceptions the conversion produced */
    if (!(old_flags & float_flag_inexact)) {
        new_flags = get_float_exception_flags(fp_status);
        set_float_exception_flags(new_flags & ~float_flag_inexact, fp_status);
    }

    return ret;
}

float64 HELPER(rintd)(float64 x, void *fp_status)
{
    int old_flags = get_float_exception_flags(fp_status), new_flags;
    float64 ret;

    ret = float64_round_to_int(x, fp_status);

    new_flags = get_float_exception_flags(fp_status);

    /* Suppress any inexact exceptions the conversion produced */
    if (!(old_flags & float_flag_inexact)) {
        new_flags = get_float_exception_flags(fp_status);
        set_float_exception_flags(new_flags & ~float_flag_inexact, fp_status);
    }

    return ret;
}

/* CRC helpers.
 * The upper bytes of val (above the number specified by 'bytes') must have
 * been zeroed out by the caller.
 */
uint32_t HELPER(crc32)(uint32_t acc, uint32_t val, uint32_t bytes)
{
    uint8_t buf[4];

    stl_le_p(buf, val);

    /* zlib crc32 converts the accumulator and output to one's complement.  */
    return crc32(acc ^ 0xffffffff, buf, bytes) ^ 0xffffffff;
}

uint32_t HELPER(crc32c)(uint32_t acc, uint32_t val, uint32_t bytes)
{
    uint8_t buf[4];

    stl_le_p(buf, val);

    /* Linux crc32c converts the output to one's complement.  */
    return crc32c(acc, buf, bytes) ^ 0xffffffff;
}
