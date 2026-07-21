#include "my_libc.h"

/*
 * C runtime entry point. Sets up the environment for a C program and calls
 * main().
 */
void _start_c(long *sp) {
    long argc;
    char **argv;
    char **envp;
    int ret;

    // Silence warnings about different types for main()
    int _mylib_main(int, char **, char **) __asm__ ("main");

    /*
     * sp  :  argc          <-- argument count, required by main()
     * argv:  argv[0]       <-- argument vector, required by main()
     *        argv[1]
     *        ...
     *        argv[argc-1]
     *        NULL
     * envp:  envp[0]       <-- environment variables, required by main()/getenv()
     *        envp[1]
     *        ...
     *        NULL
     *
     * NOT IMPLEMENTED:
     * _auxv: _auxv[0]      <-- auxiliary vector, required by getauxval()
     *        _auxv[1]
     *        ...
     *        NULL
     */

    argc = *sp;
    argv = (void *)(sp + 1);
    envp = argv + argc + 1;

    ret = _mylib_main(argc, argv, envp);

    exit(ret);
}

/*
 * Start up code inspired by the Linux kernel's nolibc header library.
 * x86-64 System V ABI requires:
 * - %rsp must be 16-byte aligned before calling a function
 * - Deepest stack frame should be zero (%rbp)
 *
 * Requires -fomit-frame-pointer to work.
 */
void __attribute__((noreturn, optimize("omit-frame-pointer"))) _start() {
    __asm__ volatile (
            "xor  %ebp, %ebp\n"  // zero the stack frame
            "mov  %rsp, %rdi\n"  // save stack pointer to %rdi, as arg1 of _start_c
            "and  $-16, %rsp\n"  // %rsp must be 16-byte aligned before call
            "call _start_c\n"    // transfer to c runtime
            "hlt\n"              // ensure it does not return
            );
    __builtin_unreachable();
}
