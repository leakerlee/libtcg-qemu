/*
 * libtcg unit-tests.
 *
 * Copyright (C) 2017 Alessandro Di Federico
 *
 * Authors:
 *  Alessandro Di Federico <ale+qemu@clearmind.me>
 *
 * This work is licensed under the terms of the GNU LGPL, version 2.1 or later.
 * See the COPYING.LIB file in the top-level directory.
 */

#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <glib.h>
#include <glob.h>
#include <dlfcn.h>

#include "libtcg.h"

static const char *get_default_cpu(const char *architecture)
{
    if (strcmp(architecture, "arm") == 0) {
        return "any";
    } else if (strcmp(architecture, "armeb") == 0) {
        return "any";
    } else if (strcmp(architecture, "cris") == 0) {
        return "crisv17";
    } else if (strcmp(architecture, "aarch64") == 0) {
        return "any";
    } else if (strcmp(architecture, "or1k") == 0) {
        return "any";
    } else if (strcmp(architecture, "hppa") == 0) {
        return "any";
    } else if (strcmp(architecture, "microblaze") == 0) {
        return "any";
    } else if (strcmp(architecture, "microblazeel") == 0) {
        return "any";
    } else if (strcmp(architecture, "nios2") == 0) {
        return "any";
    } else if (strcmp(architecture, "m68k") == 0) {
        return "any";
    } else if (strcmp(architecture, "tilegx") == 0) {
        return "any";
    } else if (strcmp(architecture, "alpha") == 0) {
        return "ev4-alpha-cpu";
    } else if (strcmp(architecture, "mips") == 0) {
        return "mips32r6-generic";
    } else if (strcmp(architecture, "mips64el") == 0) {
        return "mips32r6-generic";
    } else if (strcmp(architecture, "mips64") == 0) {
        return "mips32r6-generic";
    } else if (strcmp(architecture, "mipsel") == 0) {
        return "mips32r6-generic";
    } else if (strcmp(architecture, "mipsn32el") == 0) {
        return "mips32r6-generic";
    } else if (strcmp(architecture, "mipsn32") == 0) {
        return "mips32r6-generic";
    } else if (strcmp(architecture, "x86_64") == 0) {
        return "qemu64";
    } else if (strcmp(architecture, "i386") == 0) {
        return "qemu64";
    } else if (strcmp(architecture, "ppc64abi32") == 0) {
        return "default";
    } else if (strcmp(architecture, "ppc64le") == 0) {
        return "default";
    } else if (strcmp(architecture, "ppc64") == 0) {
        return "default";
    } else if (strcmp(architecture, "ppc") == 0) {
        return "default";
    } else if (strcmp(architecture, "s390x") == 0) {
        return "qemu";
    } else if (strcmp(architecture, "sh4") == 0) {
        return "SH7785";
    } else if (strcmp(architecture, "sh4eb") == 0) {
        return "SH7785";
    } else if (strcmp(architecture, "sparc") == 0) {
        return "TI MicroSparc II";
    } else if (strcmp(architecture, "sparc64") == 0) {
        return "Fujitsu Sparc64 V";
    } else if (strcmp(architecture, "sparc32plus") == 0) {
        return "Sun UltraSparc IV";
    }

    g_assert(false);
}

static const char *get_architecture(char *path)
{
    size_t length = strlen(path);
    path += length;

    while (*path != '-') {
        path--;
    }

    char *start = path + 1;

    while (*path != '.') {
        path++;
    }

    *path = '\0';
    return start;
}

typedef struct {
    char *path;
    char *name;
    const char *cpu;
} Architecture;

static void test_libtcg(gconstpointer argument)
{
    const Architecture *architecture = (const Architecture *) argument;

    /* Load the library */
    void *handle = dlopen(architecture->path, RTLD_LAZY);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't load %s: %s\n",
                architecture->path, dlerror());
    }
    g_assert(handle != NULL);

    /* Obtain a reference to the libtcg_init entry point */
    libtcg_init_func libtcg_init = dlsym(handle, "libtcg_init");
    g_assert(libtcg_init != NULL);

    /* For some architectures, actually test the translation */
    bool translate = true;
    uint32_t buffer[8] = { 0 };
    unsigned expected_instruction_count = 0;
    if (strcmp(architecture->name, "arm") == 0) {
        buffer[0] = 0xe3a0b000;
        buffer[1] = 0xe3a0e000;
        buffer[2] = 0xe12fff1e;
        expected_instruction_count = 3;
    } else if (strcmp(architecture->name, "mips") == 0) {
        buffer[0] = 0x8fbf001c;
        buffer[1] = 0x03e00008;
        buffer[2] = 0x27bd0020;
        expected_instruction_count = 3;
    } else if (strcmp(architecture->name, "x86_64") == 0) {
        buffer[0] = 0x9090c3;
        expected_instruction_count = 1;
    } else if (strcmp(architecture->name, "s390x") == 0) {
        /* s390x is currently broken, disable it */
        return;
    } else {
        translate = false;
    }

    /* Initialize libtcg */
    const LibTCGInterface *libtcg = libtcg_init(architecture->cpu, 0xb0000000);
    g_assert(libtcg != NULL);


    if (translate) {
        /* mmap a page */
        address_pair mmapd_address = { 0 };
        mmapd_address = libtcg->mmap(0, 4096, PROT_READ | PROT_WRITE,
                                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        g_assert(mmapd_address.pointer != NULL
                 && mmapd_address.virtual_address != 0);

        /* Copy the code to the mmap'd page */
        memcpy(mmapd_address.pointer,
               buffer,
               8 * sizeof(uint32_t));

        /* Perform the translation */
        LibTCGInstructions instructions;
        instructions = libtcg->translate(mmapd_address.virtual_address);

        /* Count the instructions (in terms of the input architectures, not tiny
         * code instructions) */
        unsigned tci_count = instructions.instruction_count;
        unsigned instruction_count = 0;
        for (unsigned i = 0; i < tci_count; i++) {
            LibTCGOpcode opcode = instructions.instructions[i].opc;
            if (opcode == LIBTCG_INDEX_op_insn_start) {
                instruction_count++;
            }
        }

        /* Check the expected amount of instructions have been met */
        g_assert(instruction_count == expected_instruction_count);

        /* Cleanup */
        libtcg->free_instructions(&instructions);
    }
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);

    /* Enumerate all the versions of libtcg that have been compiled */
    glob_t results;
    int result = glob("*-libtcg/libtcg-*.so*", 0, NULL, &results);
    if (result == GLOB_NOMATCH) {
        return 0;
    }
    g_assert(result == 0);

    /* Collect path to the library, name of the architecture and default CPU
     * for the architecture in a data structure */
    unsigned architectures_count = results.gl_pathc;
    Architecture *architectures = g_malloc0_n(sizeof(Architecture),
                                              architectures_count);

    for (unsigned i = 0; i < architectures_count; i++) {
        char *path = results.gl_pathv[i];
        architectures[i].path = g_strdup(path);
        architectures[i].name = g_strdup(get_architecture(path));
        architectures[i].cpu = get_default_cpu(architectures[i].name);

        /* Create a test for each architecture */
        gchar *name = g_strdup_printf("/libtcg/%s", architectures[i].name);
        g_test_add_data_func(name, &architectures[i], test_libtcg);
        g_free(name);
    }

    globfree(&results);

    /* Run the tests */
    result = g_test_run();

    /* Perform cleanup operations */
    for (unsigned i = 0; i < architectures_count; i++) {
        g_free(architectures[i].path);
        g_free(architectures[i].name);
    }
    g_free(architectures);

    return result;
}
