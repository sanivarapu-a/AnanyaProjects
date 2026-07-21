// ldb-info.c
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
	if (ptrace(PTRACE_SETREGS, pid, NULL, rp) < 0) { 
		return -1;
	}

	return 0;

	// Part 3
}

/*
 * ldb_examine_memory: Read an 8-byte word at addr in the tracee's memory space
 * into odata. Note that the 8-byte word is stored in *odata in little-endian
 * format. Returns 0 on success, -1 otherwise.
 */
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


/*
Read the target program’s symbol information from 
its ELF file on disk
Use mmap() to map the ELF file into memory. The main() function will unmap it at exit.

*/
int ldb_get_symbol_info(char *exec_path, struct symbol_info *oinfo) {
    // Part 4
    int fd = open(exec_path, O_RDONLY);
    if (fd < 0) {
        return -1;
    }
    // is this how we setup the elf file?
    struct stat st;
    if (fstat(fd, &st) == -1) {
        perror("fstat() failed");
        close(fd);
        return -1;
    }

    char *elf = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (elf == MAP_FAILED) {
        perror("mmap");
        return -1;
    }

    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)elf;
    Elf64_Shdr *shdr_tab = ( Elf64_Shdr *) (elf + ehdr->e_shoff);
    char *shstrtab = elf + shdr_tab[ehdr->e_shstrndx].sh_offset;

    // iterate through shdr table to find symtab and strtab
    Elf64_Sym *symtab = NULL;
    int num_syms = 0;
    char *strtab = NULL;
    Elf64_Shdr curr;
    char *name;
    // should this be < or <=?
    for (int i = 1; i < ehdr->e_shnum; i++) {
        curr = shdr_tab[i];
        name = shstrtab + curr.sh_name;
        // if this section is symtab
        if (strcmp(name, ".symtab") == 0) {
            symtab = (Elf64_Sym *) (elf + curr.sh_offset);
            // check this. get number of symbols by
            // dividing section size by size of symbol entries
            num_syms = (int) (curr.sh_size / curr.sh_entsize);
        } // else if this section is strtab
        else if (strcmp(name, ".strtab") == 0) {
            strtab = elf + curr.sh_offset;
        }
    }

    if (symtab == NULL || strtab == NULL) {
        fprintf(stderr, "couldn't find symtab or strtab\n");
        munmap(elf, st.st_size);
        return -1;
    }

    // populate oinfo
    oinfo->elf_file = elf;
    oinfo->elf_file_size = st.st_size;
    oinfo->symtab = symtab;
    oinfo->num_syms = num_syms;
    oinfo->strtab = strtab;

    return 0;
}

/*
Given a return address to a function, find the function’s symbol object in the ELF symbol table.
For a symbol of type STT_FUNC, its st_value field is the address of the first instruction of the 
function and the st_size field is the total byte size of all of the instructions in the function. 
Use these fields to determine if the specified address is contained within a given function.
*/
Elf64_Sym *ldb_find_function(struct symbol_info *sym_info, uint64_t addr) {
    // Part 4
    Elf64_Sym *symtab = sym_info->symtab;
    int num_syms = sym_info->num_syms;
    for (int i = 1; i < num_syms; i++) {
        if (ELF64_ST_TYPE(symtab[i].st_info) == STT_FUNC && symtab[i].st_value <= addr && addr < symtab[i].st_value + symtab[i].st_size) {
            return symtab + i;
        }
    }
    return NULL;
}

/*
Trace through the tracee’s current function call stack by following the saved frame 
pointers and return addresses on the stack.
*/
int ldb_backtrace(pid_t pid, struct symbol_info *sym_info, struct user_regs_struct *rp) {
    // Part 4
    Elf64_Sym *s = NULL;
    long instr_p = rp->rip;
    uint64_t rbp_copy = rp->rbp;
    long next_rbp;

    while (1) {
        s = ldb_find_function(sym_info, instr_p);
        if (s == NULL) {
            fprintf(stderr, "no function @ 0x%lx\n", instr_p);
            return -1;
        }
        
        if (instr_p == rp->rip) {
            printf("0x%lx in %s:%lx\n", instr_p, sym_info->strtab + s->st_name, s->st_value);
        }
        else {
            printf("  called from 0x%lx in %s:%lx\n", instr_p, sym_info->strtab + s->st_name, s->st_value);
        }
            
        if (strcmp(sym_info->strtab + s->st_name, "main") == 0) {
            break;
        }

        if (ldb_examine_memory(pid, (void *) (rbp_copy + 8), &instr_p) < 0) {
            return -1;
        }
        
        if (ldb_examine_memory(pid, (void *)rbp_copy, &next_rbp) < 0) {
            return -1;
        }
        rbp_copy = (uint64_t)next_rbp;
    }

    return 0;
}
