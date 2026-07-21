#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <elf.h>

#include "ldb.h"

/* SLIGHT ISSUE WITH PART 2:
after the pause, Jae's program needs 2 c's in order
to end the program due to an extra "Signal sent to tracee: Window changed"
whereas ours only needs 1 c command.
Is this due to backtrace implementation / fine for part 2?
*/


/*
 * ldb_read_regs: Retrieve the tracee's current register values. Returns -1
 * on error, 0 otherwise.
 */
int ldb_read_regs(pid_t pid, struct user_regs_struct *rp) {
    // Part 2: Replace this dummy implementation
    if (ptrace(PTRACE_GETREGS, pid, 0, rp) < 0) {
        perror("ptrace_getregs");
        return -1;
    }
    
    return 0;
}

/*
 * ldb_write_regs: Overwrite the tracee's registers. Returns -1 on error, 0
 * otherwise.
 */
int ldb_write_regs(pid_t pid, struct user_regs_struct *rp) {
    // Part 3
    return -1;
}

/*
 * ldb_examine_memory: Read an 8-byte word at addr in the tracee's memory space
 * into odata. Note that the 8-byte word is stored in *odata in little-endian
 * format. Returns 0 on success, -1 otherwise.
 */
 // ASK: Jae's crashes if we do x 0x____ instead of just x ____. 
 // is it okay if ours can take in commands x 0x___?
int ldb_examine_memory(pid_t pid, void *addr, long *odata) {
    // Part 2
    errno = 0;
    long word = ptrace(PTRACE_PEEKDATA, pid, addr, 0);
    if (word == -1 && errno!=0) {
        return -1;
    }
    *odata = word;
    return 0;
}

/*
 * ldb_edit_memory: Write a single byte to addr in the
 * tracee's memory space. Returns 0 on success, -1
 * otherwise.
 */
 // can we assume that the data stored at addr will be in little endian format?
int ldb_edit_memory(pid_t pid, void *addr, uint8_t byte) {
    // Part 2
    // 1st read 8 bytes at the target address
    errno = 0;
    long word = ptrace(PTRACE_PEEKDATA,pid,addr,0);
    if (word == -1 && errno!=0) {
        return -1;
    }

    // change the last byte of the word to be what we inputted
    word = word & 0xffffffffffffff00; 
    word = word | ((long)byte);

    // write back the 8 bytes
    if (ptrace(PTRACE_POKEDATA, pid, addr, word) < 0) {
        return -1;
    }

    return 0;
}

/*
 * ldb_read_signal: Retrieve info about the signal that caused the
 * tracee to stop. Return 0 on success, -1 otherwise.
 */
int ldb_read_signal(pid_t pid, siginfo_t *sp) {
    // Part 2: Replace this dummy implementation
    if (ptrace(PTRACE_GETSIGINFO, pid, 0, sp) < 0) {
        return -1;
    }
    return 0;
}

int ldb_get_symbol_info(char *exec_path, struct symbol_info *oinfo) {
    // Part 4
    return 0;
}

Elf64_Sym *ldb_find_function(struct symbol_info *sym_info, uint64_t addr) {
    // Part 4
    return NULL;
}

int ldb_backtrace(pid_t pid, struct symbol_info *sym_info, struct user_regs_struct *rp) {
    // Part 4
    return 0;
}
