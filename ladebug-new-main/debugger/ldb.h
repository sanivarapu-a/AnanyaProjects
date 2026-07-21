#ifndef __LDB_H__
#define __LDB_H__

#include <stdint.h>
#include <elf.h>
#include <sys/user.h>

/* ldb-step */

#define LDB_BRK_DUP -2
#define LDB_BRK_FULL -3
int ldb_add_breakpoint(pid_t pid, void *addr);

int ldb_delete_breakpoints(pid_t pid, int at_bp);
struct breakpoint *ldb_current_breakpoint(struct user_regs_struct *rp, siginfo_t *sp);
void ldb_list_breakpoints();
int ldb_step(pid_t pid, struct breakpoint *bp, long sig_to_forward);
int ldb_cont(pid_t pid, struct breakpoint *bp, long sig_to_forward);

/* ldb-info */

struct symbol_info {
    char *elf_file;
    size_t elf_file_size;
    Elf64_Sym *symtab;
    size_t num_syms;
    char *strtab;
};

int ldb_read_regs(pid_t pid, struct user_regs_struct *rp);
int ldb_write_regs(pid_t pid, struct user_regs_struct *rp);
int ldb_examine_memory(pid_t pid, void *addr, long *odata);
int ldb_edit_memory(pid_t pid, void *addr, uint8_t byte);
int ldb_read_signal(pid_t pid, siginfo_t *sp);
int ldb_get_symbol_info(char *exec_name, struct symbol_info *oinfo);
int ldb_backtrace(pid_t pid, struct symbol_info *sym_info, struct user_regs_struct *rp);

/* Commands */

#define LDB_STEP      's'
#define LDB_CONT      'c'
#define LDB_INFO      'i'
#define LDB_EXAMINE   'x'
#define LDB_EDIT      'e'
#define LDB_BREAK     'b'
#define LDB_DELETE    'd'
#define LDB_BACKTRACE 't'
#define LDB_QUIT      'q'

#endif
