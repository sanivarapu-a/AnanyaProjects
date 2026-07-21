#ifndef __MY_LIBC_H__
#define __MY_LIBC_H__

/*
 * Header file for minimal C standard library.
 */

// Standard stream file descriptors
#define STDIN_FILENO  0
#define STDOUT_FILENO 1
#define STDERR_FILENO 2

// System call numbers for x86_64 Linux
#define __NR_write 1
#define __NR_exit 60

/*
 * The syscall() function is implemented as an inline assembly function.
 * The function uses the System V AMD64 ABI calling convention, which
 * specifies that the syscall number is passed in %rax, and the first six
 * arguments are passed in %rdi, %rsi, %rdx, %r10, %r8, and %r9.
 *
 * The syscall instruction clobbers %rcx and %r11, so we must list them as
 * clobbered registers. Additionally, we list memory and cc as clobbered
 * because the syscall instruction may write to memory and may modify the flags
 * register.
*/
static inline long syscall(long n, long a1, long a2, long a3, long a4, long a5, long a6) {
    long ret;

    register long _num  asm("rax") = n;
    register long _arg1 asm("rdi") = a1;
    register long _arg2 asm("rsi") = a2;
    register long _arg3 asm("rdx") = a3;
    register long _arg4 asm("r10") = a4;
    register long _arg5 asm("r8")  = a5;
    register long _arg6 asm("r9")  = a6;

    asm volatile (
        "syscall\n\t"
        : "=a" (ret)
        : "0" (_num), "r" (_arg1), "r" (_arg2), "r" (_arg3), "r" (_arg4),
          "r" (_arg5), "r" (_arg6)
        : "memory", "cc", "r11", "rcx"
    );

    return ret;
}

static inline __attribute__((noreturn)) void exit(int code) {
    syscall(__NR_exit, code, 0, 0, 0, 0, 0);
    __builtin_unreachable();
}

static inline void write(int fd, const char *buf, unsigned long len) {
    syscall(__NR_write, fd, (long)buf, len, 0, 0, 0);
}

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

#endif // __MY_LIBC_H__
