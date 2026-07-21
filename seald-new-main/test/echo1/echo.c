#include "my_libc.h"

int my_strlen(const char *s) {
    int len = 0;
    while (*s++)
        len++;

    return len;
}

// Print all arguments
int main(int argc, char **argv) {
    char space[] = " ";
    char newline[] = "\n";

    // Use write() since we don't have printf()
    for (int i = 1; i < argc; i++) {
        write(STDOUT_FILENO, argv[i], my_strlen(argv[i]));
        write(STDOUT_FILENO, space, 1);
    }

    write(STDOUT_FILENO, newline, 1);

    return 0;
}
