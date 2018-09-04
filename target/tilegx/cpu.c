/*
 * QEMU TILE-Gx CPU
 *
 *  Copyright (c) 2015 Chen Gang
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see
 * <http://www.gnu.org/licenses/lgpl-2.1.html>
 */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "cpu.h"
#include "qemu-common.h"
#include "hw/qdev-properties.h"
#ifdef CONFIG_LIBTCG
# define TARGET_SIGSEGV 0
#else
# include "linux-user/syscall_defs.h"
#endif
#include "exec/exec-all.h"


static ObjectClass *tilegx_cpu_class_by_name(const char *cpu_model)
{
    return object_class_by_name(TYPE_TILEGX_CPU);
}

static void tilegx_cpu_set_pc(CPUState *cs, vaddr value)
{
    TileGXCPU *cpu = TILEGX_CPU(cs);

    cpu->env.pc = value;
}

static bool tilegx_cpu_has_work(CPUState *cs)
{
    return true;
}

static void tilegx_cpu_reset(CPUState *s)
{
    TileGXCPU *cpu = TILEGX_CPU(s);
    TileGXCPUClass *tcc = TILEGX_CPU_GET_CLASS(cpu);
    CPUTLGState *env = &cpu->env;

    tcc->parent_reset(s);

    memset(env, 0, offsetof(CPUTLGState, end_reset_fields));
}

static void tilegx_cpu_realizefn(DeviceState *dev, Error **errp)
{
    CPUState *cs = CPU(dev);
    TileGXCPUClass *tcc = TILEGX_CPU_GET_CLASS(dev);
    Error *local_err = NULL;

    cpu_exec_realizefn(cs, &local_err);
    if (local_err != NULL) {
        error_propagate(errp, local_err);
        return;
    }

    cpu_reset(cs);
    qemu_init_vcpu(cs);

    tcc->parent_realize(dev, errp);
}

static void tilegx_cpu_initfn(Object *obj)
{
    CPUState *cs = CPU(obj);
    TileGXCPU *cpu = TILEGX_CPU(obj);
    CPUTLGState *env = &cpu->env;

    cs->env_ptr = env;
}

#ifndef CONFIG_LIBTCG
static void tilegx_cpu_do_interrupt(CPUState *cs)
{
    cs->exception_index = -1;
}

static int tilegx_cpu_handle_mmu_fault(CPUState *cs, vaddr address, int size,
                                       int rw, int mmu_idx)
{
    TileGXCPU *cpu = TILEGX_CPU(cs);

    /* The sigcode field will be filled in by do_signal in main.c.  */
    cs->exception_index = TILEGX_EXCP_SIGNAL;
    cpu->env.excaddr = address;
    cpu->env.signo = TARGET_SIGSEGV;
    cpu->env.sigcode = 0;

    return 1;
}

static bool tilegx_cpu_exec_interrupt(CPUState *cs, int interrupt_request)
{
    if (interrupt_request & CPU_INTERRUPT_HARD) {
        tilegx_cpu_do_interrupt(cs);
        return true;
    }
    return false;
}
#endif

static void tilegx_cpu_class_init(ObjectClass *oc, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(oc);
    CPUClass *cc = CPU_CLASS(oc);
    TileGXCPUClass *tcc = TILEGX_CPU_CLASS(oc);

    device_class_set_parent_realize(dc, tilegx_cpu_realizefn,
                                    &tcc->parent_realize);

    tcc->parent_reset = cc->reset;
    cc->reset = tilegx_cpu_reset;

    cc->class_by_name = tilegx_cpu_class_by_name;
    cc->has_work = tilegx_cpu_has_work;
#ifndef CONFIG_LIBTCG
    cc->do_interrupt = tilegx_cpu_do_interrupt;
    cc->cpu_exec_interrupt = tilegx_cpu_exec_interrupt;
    cc->dump_state = tilegx_cpu_dump_state;
    cc->handle_mmu_fault = tilegx_cpu_handle_mmu_fault;
#endif
    cc->set_pc = tilegx_cpu_set_pc;
    cc->gdb_num_core_regs = 0;
    cc->tcg_initialize = tilegx_tcg_init;
}

static const TypeInfo tilegx_cpu_type_info = {
    .name = TYPE_TILEGX_CPU,
    .parent = TYPE_CPU,
    .instance_size = sizeof(TileGXCPU),
    .instance_init = tilegx_cpu_initfn,
    .class_size = sizeof(TileGXCPUClass),
    .class_init = tilegx_cpu_class_init,
};

static void tilegx_cpu_register_types(void)
{
    type_register_static(&tilegx_cpu_type_info);
}

type_init(tilegx_cpu_register_types)
