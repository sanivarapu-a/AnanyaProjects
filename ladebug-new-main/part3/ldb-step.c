// ldb-step.c
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

	if (bp) { 
		// if bp isn't null, rip points to the one past the bp
		if (ldb_edit_memory(pid, bp->addr, bp->saved_byte) < 0) {
			return -1;
		} // restore the original byte of memory at the breakpoint. 

		//Backtrack the RIP pointer. 
		struct user_regs_struct regs;
		if (ldb_read_regs(pid,&regs) < 0) {
            return -1;
        }
		regs.rip = regs.rip - 1; // backtrack the instruction pointer by 1. 	
					 //update regs
		if (ldb_write_regs(pid, &regs) < 0) {
            return -1;
        }

	}
	
    //Resume the progression of the ptrace function. 
    int status;

    if (ptrace(PTRACE_SINGLESTEP, pid, 0, sig_to_forward) < 0) {
        return -1;
    }

    //Now, to exit the function as usual. 
    if (waitpid(pid, &status, 0) < 0) {
        return -1;
    }

    // check if function terminated
    if (WIFEXITED(status) || WIFSIGNALED(status)) {
        return 1;
    }

    if (bp) { 
        if (ldb_edit_memory(pid, bp->addr, 0xCC) < 0) {
            return -1;
        } // restore the original byte of memory at the breakpoint. 
    }
    
    if (WIFSTOPPED(status)) {
        return 0;
    }
   
    return 1;
    
}

/*
 * ldb_cont: Restarts tracee and waits until it's completed. bp points to the
 * breakpoint that the tracee just hit, NULL otherwise. Returns -1 on error, 0
 * if the tracee is stopped, 1 otherwise.
 */
int ldb_cont(pid_t pid, struct breakpoint *bp, long sig_to_forward) {
	//Essentially the same code as ldb_step

	// If at breakpoint, restore original code at breakpoint temporarily, 
	// bactrack the rip pointer, run ptrace, restore breakpoint's 0xCC byte. 
    int status;

	if (bp) { 
		// if bp isn't null, is your rip pointing one past the bp? 
		if (ldb_edit_memory(pid, bp->addr, bp->saved_byte) < 0) {
			return -1;
		} // restore the original byte of memory at the breakpoint. 

		//Backtrack the RIP pointer. 
		struct user_regs_struct regs;
		if (ldb_read_regs(pid,&regs) < 0) {
            return -1;
        }
		regs.rip = regs.rip - 1; // backtrack the instruction pointer by 1. 	
		//update regs
		if (ldb_write_regs(pid, &regs) < 0) {
            return -1;
        }


        // single step first in case the breakpoint is at the last instruction line
        if (ptrace(PTRACE_SINGLESTEP, pid, 0, sig_to_forward) < 0) {
            return -1;
        }

        if (waitpid(pid, &status, 0) < 0) {
            return -1;
        }

        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            return 1;
        }
        
        // restore the breakpoint's edited byte at bp to 0xCC
        if (ldb_edit_memory(pid, bp->addr, 0xCC) < 0) {
            return -1;
        } 

        // if we stopped due to a non-SIGTRAP signal then return control to tracer
        if (WIFSTOPPED(status) && WSTOPSIG(status) != SIGTRAP) {
            return 0;
        }

    }
    
    if (ptrace(PTRACE_CONT, pid, 0, 0) < 0) {
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
    int open_ind = -1;
    for (int i = 0; i < NUM_BREAKPOINTS; i++) {
        struct breakpoint *bp = breakpoints + i;
        if (bp->in_use && bp->addr == addr) {
            return LDB_BRK_DUP;
        }
        
        if (open_ind == -1 && !bp->in_use) { // if we find an open slot, save index
            open_ind = i;
            continue;
        }
    }
    if (open_ind == -1) {
        return LDB_BRK_FULL;
    }

    // This whole section is about saving the existing byte: -------------------------------------
    // Use examine memory to read the saved byte. 
    long odata;
    if (ldb_examine_memory(pid, addr, &odata) < 0){
        //fprintf(stderr, "the value returned was -1c in the add breakpoint function");
        return -1;
    } // The conversion from long to uint8_t discards the most significant 56 bits. 
    uint8_t saved = (uint8_t)(odata & 0xff); // just take the first byte of odata ( so the least significant bit ) 
	// and discard most significant 56 bits. 

    // add to list of break points
    struct breakpoint *b = breakpoints + open_ind;
    b->addr = addr;
    b->in_use = 1;
    b->saved_byte = saved;
    //--------------------------------------------------------------------------------------------

    // change the last byte of the word to be 0xCC
   if (ldb_edit_memory(pid, addr, (uint8_t)0xCC) < 0 ) { 
        // undo partial breakpoint state
        b->in_use = 0;
        b->addr = NULL;
        b->saved_byte = 0;
        return -1;
   }
    return 0;
}



/*
 * ldb_delete_breakpoints: Deletes all in_use breakpoints and restores the
 * saved bytes to the tracee's memory space. Updates the program's RIP if it
 * was at a breakpoint. Returns 0 on success and -1 otherwise.
 */
int ldb_delete_breakpoints(pid_t pid, int at_bp) {
    // Part 3
    for (int i = 0; i < NUM_BREAKPOINTS; i++) {
        if (!breakpoints[i].in_use) {
            continue; // if not in use, then don't do anything. 
        }
        // restore the original byte back into memory, and set other fields to NULL. 
        if (ldb_edit_memory(pid, breakpoints[i].addr, breakpoints[i].saved_byte) < 0) {
            return -1;
        }
        breakpoints[i].in_use = 0;
	    breakpoints[i].addr = NULL;
        breakpoints[i].saved_byte = 0;
    }
    
    // unwind RIP if the program was at a breakpoint when breakpoints get deleted with the d command
    if (at_bp) {

        //define a new struct regs with updated rip value
        struct user_regs_struct regs;
        if (ldb_read_regs(pid,&regs) < 0) {
            return -1;
        }
        regs.rip = regs.rip - 1; // backtrack the instruction pointer by 1. 	
        //update regs
        if (ldb_write_regs(pid, &regs) < 0) {
            return -1;
        }
    }

    return 0;
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
