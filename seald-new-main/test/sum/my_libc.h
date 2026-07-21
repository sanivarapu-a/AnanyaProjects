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

#endif // __MY_LIBC_H__
