#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>

#include "ldb.h"

#define INT3 0xcc
#define NUM_BREAKPOINTS 4

struct breakpoint {
    void *addr;
    uint8_t in_use;
    uint8_t saved_byte;
};

struct breakpoint breakpoints[NUM_BREAKPOINTS] = {{NULL, 0, 0}};

/*
 * ldb_step: Performs single step on the tracee and waits until it's completed.
 * bp points to the breakpoint that the tracee just hit, NULL otherwise.
 * Returns -1 on error, 0 if the tracee is stopped, 1 otherwise.
 */
int ldb_step(pid_t pid, struct breakpoint *bp, long sig_to_forward) {
    // Part 2 and Part 3
    int status;

    if (ptrace(PTRACE_SINGLESTEP, pid, 0, sig_to_forward) < 0) {
        return -1;
    }

    if (waitpid(pid, &status, 0) < 0) {
        return -1;
    }

    if (WIFSTOPPED(status)) {
        return 0;
    }

    if (WIFEXITED(status) || WIFSIGNALED(status)) {
        return 1;
    }

    return -1;
}

/*
 * ldb_cont: Restarts tracee and waits until it's completed. bp points to the
 * breakpoint that the tracee just hit, NULL otherwise. Returns -1 on error, 0
 * if the tracee is stopped, 1 otherwise.
 */
int ldb_cont(pid_t pid, struct breakpoint *bp, long sig_to_forward) {
    // Part 2 and Part 3
    int status;
    
    if (ptrace(PTRACE_CONT, pid, 0, sig_to_forward) < 0) {
        return -1;
    }

    if (waitpid(pid, &status, 0) < 0) {
        return -1;
    }

    // check if status == -1

    if (WIFSTOPPED(status)) {
        return 0;
    }

    if (WIFEXITED(status) || WIFSIGNALED(status)) {
        return 1;
    }

    return 1;
}

/*
 * ldb_add_breakpoint: Add a breakpoint at addr. Returns 0 on success,
 * -1 on system error, LDB_BRK_DUP if a breakpoint already exists at
 *  addr, and LDB_BRK_FULL if ldb is already tracking the maximum number
 *  of breakpoints.
 */
int ldb_add_breakpoint(pid_t pid, void *addr) {
    // Part 3
    return -1;
}

/*
 * ldb_delete_breakpoints: Deletes all in_use breakpoints and restores the
 * saved bytes to the tracee's memory space. Updates the program's RIP if it
 * was at a breakpoint. Returns 0 on success and -1 otherwise.
 */
int ldb_delete_breakpoints(pid_t pid, int at_bp) {
    // Part 3
    return -1;
}

/*
 * ldb_current_breakpoint: If the tracee raised INT3 and the breakpoint is
 * still registered at rip - 1, return the breakpoint info. Otherwise, return
 * NULL.
 */
struct breakpoint *ldb_current_breakpoint(struct user_regs_struct *rp, siginfo_t *sp) {
    // When the tracee executes 0xcc (INT3), it raises a software interrupt
    // that the kernel handles by sending a SIGTRAP.
    int int3_raised = (sp->si_signo == SIGTRAP && sp->si_code == SI_KERNEL);
    if (!int3_raised) {
        return NULL;
    }

    // See if there is still a breakpoint registered at rip - 1. We may have
    // deleted the breakpoint after it was raised.
    for (int i = 0; i < NUM_BREAKPOINTS; ++i) {
        if (breakpoints[i].in_use && rp->rip - 1 == (uint64_t) breakpoints[i].addr) {
            return breakpoints + i;
        }
    }
    return NULL;
}

void ldb_list_breakpoints() {
    for (int i = 0; i < NUM_BREAKPOINTS; i++) {
        struct breakpoint *bp = breakpoints + i;
        if (!bp->in_use) {
            continue;
        }

        printf("bp #%d: %p (saved: 0x%.2x)\n", i, bp->addr, bp->saved_byte);
    }
}
