int my_strlen(const char *s) {
    int len = 0;
    while (*s++)
        len++;

    return len;
}
