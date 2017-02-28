#include "qemu/osdep.h"
#include <assert.h>
#include <glib.h>
#include "qemu.h"
#include "exec/exec-all.h"

#include "libtcg.h"

#define REINTERPRET(type, value) (*((type *) &(value)))

/* Functions and global variables we need to provide */
unsigned long guest_base;
int singlestep;
unsigned long mmap_min_addr;
unsigned long reserved_va;

void cpu_resume(CPUState *cpu)
{
    abort();
}

bool qemu_cpu_is_self(CPUState *cpu)
{
    abort();
}

void qemu_cpu_kick(CPUState *cpu)
{
}

void qemu_init_vcpu(CPUState *cpu)
{
}

static CPUState *cpu;

/* Interface functions */
const LibTCGInterface *libtcg_init(const char *cpu_name,
                                   intptr_t start_address);
static address_pair libtcg_mmap(uint64_t start, uint64_t len, int prot,
                                int flags, int fd, off_t offset);
static LibTCGInstructions libtcg_translate(uint64_t virtual_address);
static void libtcg_free_instructions(LibTCGInstructions *instructions);

/* The interface object return by libtcg_init */
static LibTCGInterface interface;

/* This is the only function exposed by the library */
__attribute__((visibility("default")))
const LibTCGInterface *libtcg_init(const char *cpu_name,
                                   intptr_t start_address)
{
    /* TODO: support changing CPU */
    assert(cpu == NULL);

    /* Initialize guest_base. Since libtcg only translates buffers of code, and
     * doesn't have the full view over the program being translated as
     * {linux,bsd}-user have, we let the user mmap the code. */
    assert(start_address <= UINT_MAX);
    guest_base = (unsigned long) start_address;

    /* Initialize the TCG subsystem using the default translation buffer size */
    tcg_exec_init(0);

    /* Initialize the QOM subsystem */
    module_call_init(MODULE_INIT_QOM);

    /* Initialize the CPU with the given name. This is a call to the
     * cpu_*_init function */
    cpu = cpu_init(cpu_name);
    assert(cpu != NULL);

    /* Initialize the interface object */
    interface.mmap = libtcg_mmap;
    interface.translate = libtcg_translate;
    interface.free_instructions = libtcg_free_instructions;

    /* Return a reference to the interface object */
    return &interface;
}

static address_pair libtcg_mmap(uint64_t start, uint64_t len, int prot,
                                int flags, int fd, off_t offset)
{
    address_pair result;
    result.virtual_address = target_mmap(start, len, prot, flags, fd, offset);
    result.pointer = g2h(result.virtual_address);
    return result;
}

static TranslationBlock *do_gen_code(TCGContext *context, CPUState *cpu,
                                     target_ulong pc, target_ulong cs_base,
                                     int flags, int cflags)
{
    CPUArchState *env = cpu->env_ptr;

    /* We don't care about caching translation blocks, flush out the cache */
    tb_flush(cpu);

    /* Allocate a new translation block and get a pointer to it */
    TranslationBlock *tb = tb_alloc(pc);

    /* Configure translation options */
    tb->cs_base = cs_base;
    tb->flags = flags;
    tb->cflags = cflags;

    /* Clean the translation context */
    tcg_func_start(context);

    /* Invoke the frontend-specific gen_intermediate_code function to perform
     * the actual translation to tiny code instructions */
    gen_intermediate_code(env, tb);

    /* Return the TranslationBlock */
    return tb;
}

static LibTCGInstructions libtcg_translate(uint64_t virtual_address)
{
    TCGContext *context = &tcg_ctx;

    /* Get the flags defining in which context the code was generated */
    target_ulong temp;
    uint32_t flags = 0;
    cpu_get_tb_cpu_state(cpu->env_ptr, &temp, &temp, &flags);

    /* Perform the translation forcing the pc and with cs_base and cflags set to
     * 0 */
    TranslationBlock *tb = do_gen_code(context, cpu,
                                       (target_ulong) virtual_address, 0, flags,
                                       0);

    LibTCGInstructions result;
    unsigned arguments_count = 0;

    /* First, count the instructions and the arguments, so we can allocate an
     * appropriate amount of space */
    TCGOp *op = NULL;
    for (unsigned i = context->gen_op_buf[0].next; i != 0; i = op->next) {
        result.instruction_count++;

        op = &context->gen_op_buf[i];
        TCGOpcode c = op->opc;
        const TCGOpDef *def = &tcg_op_defs[c];

        if (c == INDEX_op_insn_start) {
            arguments_count += 2;
        } else if (c == INDEX_op_call) {
            arguments_count += op->callo + op->calli + def->nb_cargs;
        } else {
            arguments_count += def->nb_oargs + def->nb_iargs + def->nb_cargs;
        }
    }

    /* Allocate space for the instructions and arguments data structures */
    result.instructions = (LibTCGOp *) g_new0(LibTCGOp,
                                              result.instruction_count);
    result.arguments = (LibTCGArg *) g_new0(LibTCGArg, arguments_count);

    /* Copy the temp values */
    result.total_temps = context->nb_temps;
    result.global_temps = context->nb_globals;
    result.temps = (LibTCGTemp *) g_new0(LibTCGTemp, result.total_temps);

    for (unsigned i = 0; i < result.total_temps; i++) {
        result.temps[i] = REINTERPRET(LibTCGTemp, context->temps[i]);
    }

    /* Go through all the instructions again and copy to the output buffers */
    result.instruction_count = 0;
    unsigned total_arguments_count = 0;
    op = NULL;
    for (unsigned i = context->gen_op_buf[0].next; i != 0; i = op->next) {
        /* Get the pointer to the output LibTCGOp object */
        LibTCGOp *current_instruction = NULL;
        current_instruction = &result.instructions[result.instruction_count];
        result.instruction_count++;

        op = &context->gen_op_buf[i];
        TCGArg *args = &context->gen_opparam_buf[op->args];

        current_instruction->opc = (LibTCGOpcode) op->opc;
        current_instruction->callo = op->callo;
        current_instruction->calli = op->calli;
        current_instruction->args = &result.arguments[total_arguments_count];

        /* Compute the number of arguments for this instruction */
        TCGOpcode opcode = current_instruction->opc;
        const TCGOpDef *def = &tcg_op_defs[opcode];
        unsigned arguments_count = 0;
        if (opcode == INDEX_op_insn_start) {
            arguments_count = 2;
        } else if (opcode == INDEX_op_call) {
            arguments_count += current_instruction->callo;
            arguments_count += current_instruction->calli;
            arguments_count += def->nb_cargs;
        } else {
            arguments_count = def->nb_oargs + def->nb_iargs + def->nb_cargs;
        }

        /* Copy all the new arguments to the output buffer */
        for (unsigned j = 0; j < arguments_count; j++) {
            LibTCGArg argument = REINTERPRET(LibTCGArg, args[j]);
            result.arguments[total_arguments_count + j] = argument;
        }

        /* Increment the counter of the total number of arguments */
        total_arguments_count += arguments_count;
    }

    /* Free the TranslationBlock */
    tb_free(tb);

    return result;
}

void libtcg_free_instructions(LibTCGInstructions *instructions)
{
    assert(instructions != NULL);
    g_free(instructions->instructions);
    g_free(instructions->arguments);
    g_free(instructions->temps);
}

#undef REINTERPRET
