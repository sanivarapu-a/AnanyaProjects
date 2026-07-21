#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <assert.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/personality.h>
#include <sys/ptrace.h>

#include "ldb.h"

#define COLOR_RESET   "\x1B[0m"
#define COLOR_RED     "\x1B[91m"
#define COLOR_GREEN   "\x1B[92m"
#define COLOR_BLUE    "\x1B[94m"
#define COLOR_MAGENTA "\x1B[95m"

static void print_prompt(struct user_regs_struct *rp, struct breakpoint *bp, long sig_to_forward) {
    // We're either at a breakpoint (we intercepted SIGTRAP sent by the kernel)
    // or we intercepted a non-SIGTRAP bound for the tracee.
    assert(!(bp != NULL && sig_to_forward != 0));

    char *condition;
    if (bp != NULL) {
        condition = "*";
    } else if (sig_to_forward != 0) {
        condition = "!";
    } else {
        condition = "";
    }

    printf(COLOR_BLUE "(" COLOR_GREEN "ldb" COLOR_RESET "@%llx"
           COLOR_MAGENTA "%s" COLOR_BLUE ") " COLOR_RESET,
           rp->rip, condition);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <target> [args...]\n", argv[0]);
        exit(1);
    }

    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        exit(1);
    }

    if (pid == 0) {
        /* Target */
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
            perror("ptrace_traceme");
            exit(1);
        }

        // Disable Address-space Layout Randomization
        // This ensures that addresses of all variables are consistent across
        // runs of the target program.
        personality(ADDR_NO_RANDOMIZE);

        execv(argv[1], argv + 1);
        perror("execv");
        exit(1);
    }

    siginfo_t sp;
    struct breakpoint *bp = NULL;
    int wstatus, ret = 0;
    char line[100];
    void *target_addr;
    long data, sig_to_forward = 0;

    // Wait for child to be stopped after execv().
    waitpid(pid, &wstatus, 0);
    assert(WIFSTOPPED(wstatus));

    struct user_regs_struct regs;
    if ((ret = ldb_read_regs(pid, &regs)) == -1) {
        perror("ldb_read_regs");
        goto out_kill;
    }

    struct symbol_info sym_info = {
        .elf_file = NULL,
        .elf_file_size = 0,
        .symtab = NULL,
        .num_syms = 0,
        .strtab = NULL
    };
    if (ldb_get_symbol_info(argv[1], &sym_info) == -1) {
        goto out_kill;
    }

    print_prompt(&regs, bp, sig_to_forward);
    while (fgets(line, sizeof(line), stdin) != NULL) {
        char *ldb_cmd = strtok(line, " ");
        char *ldb_arg1 = strtok(NULL, " ");
        char *ldb_arg2 = strtok(NULL, " ");
        if (strtok(NULL, " ") != NULL) {
            continue;
        }

        switch (*ldb_cmd) {
            case LDB_STEP:
                ret = ldb_step(pid, bp, sig_to_forward);
                break;
            case LDB_CONT:
                ret = ldb_cont(pid, bp, sig_to_forward);
                break;
            case LDB_INFO:
                printf("rdi:0x%.16llx\trax:0x%.16llx\n"
                       "rsi:0x%.16llx\trbp:0x%.16llx\n"
                       "rdx:0x%.16llx\trsp:0x%.16llx\n"
                       "rcx:0x%.16llx\trip:0x%.16llx\n",
                       regs.rdi, regs.rax, regs.rsi, regs.rbp,
                       regs.rdx, regs.rsp, regs.rcx, regs.rip);
                break;
            case LDB_EXAMINE:
                if (ldb_arg1 == NULL) {
                    fprintf(stderr, "Usage: x <addr>\n");
                    break;
                }
                target_addr = (void *)strtol(ldb_arg1, NULL, 16);
                ret = ldb_examine_memory(pid, target_addr, &data);
                if (ret == 0) {
                    // Print from the least significant byte to the most
                    // significant byte. This reflects the order in which the
                    // bytes are laid out in memory on little endian machines.
                    for (int i = 0; i < 8; i++) {
                        printf("%.2lx ", data & 0xff);
                        data >>= 8;
                    }
                    printf("\n");
                }
                break;
            case LDB_EDIT:
                if (ldb_arg1 == NULL || ldb_arg2 == NULL) {
                    fprintf(stderr, "Usage: e <addr> <byte>\n");
                    break;
                }
                target_addr = (void *)strtol(ldb_arg1, NULL, 16);
                data = strtol(ldb_arg2, NULL, 16);
                ret = ldb_edit_memory(pid, target_addr, data & 0xff);
                break;
            case LDB_BREAK:
                if (ldb_arg1 == NULL) {
                    ldb_list_breakpoints();
                    break;
                }

                target_addr = (void *)strtol(ldb_arg1, NULL, 16);
                ret = ldb_add_breakpoint(pid, target_addr);
                if (ret == LDB_BRK_DUP) {
                    fprintf(stderr, "bp already set at %p\n", target_addr);
                    ret = 0;
                }
                if (ret == LDB_BRK_FULL) {
                    fprintf(stderr, "too many breakpoints\n");
                    ret = 0;
                }
                break;
            case LDB_DELETE:
                ret = ldb_delete_breakpoints(pid, /*at_bp=*/bp != NULL);
                break;
            case LDB_BACKTRACE:
                ret = ldb_backtrace(pid, &sym_info, &regs);
                break;
            case LDB_QUIT:
                ret = 0;
                goto out_kill;
            default:
                break;
        }

        // Tracee terminated
        if (ret == 1) {
            ret = 0;
            goto out_nokill;
        }

        // System error
        if (ret == -1) {
            perror("ldb");
            break;
        }

        // Get current registers and signal info
        if ((ret = ldb_read_regs(pid, &regs)) == -1) {
            perror("ldb_read_regs");
            break;
        }
        if ((ret = ldb_read_signal(pid, &sp)) == -1) {
            perror("ldb_read_signal");
            break;
        }

        bp = ldb_current_breakpoint(&regs, &sp);

        // For simplicity, do not forward any SIGTRAPs to the tracee.
        sig_to_forward = (sp.si_signo == SIGTRAP) ? 0 : sp.si_signo;

        if (sig_to_forward != 0) {
            printf("Signal sent to tracee: %s\n", strsignal(sig_to_forward));
        }
        if (sig_to_forward == SIGSEGV || sig_to_forward == SIGFPE) {
            if ((ret = ldb_backtrace(pid, &sym_info, &regs)) == -1) {
                perror("ldb_backtrace");
                break;
            }
        }

        print_prompt(&regs, bp, sig_to_forward);
    }

out_kill:
    kill(pid, SIGKILL);
out_nokill:
    if (sym_info.elf_file != NULL) {
        munmap(sym_info.elf_file, sym_info.elf_file_size);
    }
    return ret;
}
