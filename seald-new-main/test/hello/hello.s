        .text

.globl _start

// Equivalent to write(1, "ASP\n", 4) or syscall(__NR_write, 1, "ASP\n", 4),
// followed by exit(0)
_start:
        // Initialize buffer on stack
        push    $0x0a505341   # "ASP\n"
        mov     %rsp, %rsi    # pointer to string
        mov     $1, %eax      # __NR_write
        mov     $1, %edi      # STDOUT_FILENO
        mov     $4, %edx      # length of string
        syscall

        mov     $0, %rdi      # exit code
        mov     $60, %rax     # __NR_exit
        syscall
