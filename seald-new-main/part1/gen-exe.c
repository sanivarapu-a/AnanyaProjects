// gen-exe.c
#include <stdio.h>
#include <elf.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
/*
open() perms and settings:
gen-exe should write out a.out in the current directory. You should overwrite the file if it already exists and create it with 0755 permissions. Note that if you have a file mode creation mask set using the umask command, the resulting file permissions will be different.


Since a.out is a minimal ELF file, just write 0 for fields in the ELF Header that refer to offsets, addresses, and counts. You’ll revisit these fields once we start building out a real linker in the later parts of this assignment. However, there are many constant field values that you should fill out now. To point out a couple:

e_ident: Most of the bytes in here are straightforward. Note that for OSABI, the ELF specification says to specify ELFOSABI_NONE since we won’t be using any special Linux extensions.
e_type: Specify ET_EXEC since our linker will only support static linking.
*/

int add_header(int fd) {
    ssize_t n;
    Elf64_Ehdr ehdr;
    memset(&ehdr, 0, sizeof(Elf64_Ehdr));
    ehdr.e_type = ET_EXEC; 

    // initializing e_ident array
    ehdr.e_ident[EI_MAG0] = ELFMAG0;
    ehdr.e_ident[EI_MAG1] = ELFMAG1;
    ehdr.e_ident[EI_MAG2] = ELFMAG2;
    ehdr.e_ident[EI_MAG3] = ELFMAG3;
    ehdr.e_ident[EI_CLASS] = ELFCLASS64;
    ehdr.e_ident[EI_DATA] = ELFDATA2LSB;
    ehdr.e_ident[EI_VERSION] = EV_CURRENT;
    ehdr.e_ident[EI_OSABI] = ELFOSABI_NONE;
    ehdr.e_ident[EI_ABIVERSION] = 0;

    ehdr.e_machine = EM_X86_64;
    ehdr.e_version = 1;
    ehdr.e_entry = 0; 

    ehdr.e_phoff = 0;
    ehdr.e_shoff = 0;
    ehdr.e_flags = 0; 
    ehdr.e_ehsize = sizeof(Elf64_Ehdr);
    ehdr.e_phentsize = sizeof(Elf64_Phdr);
    ehdr.e_phnum = 0;
    ehdr.e_shentsize = sizeof(Elf64_Shdr);
    ehdr.e_shnum = 0;
    ehdr.e_shstrndx = 0; 

    if ((n = write(fd, &ehdr, sizeof(ehdr))) < 0) {
        perror("write");
        return -1;
    }
    
    if (n != sizeof(ehdr)) {
        fprintf(stderr, "short write\n");
        return -1;
    }
    return 0; // returns 0 if n == 64
}

int main (int argc, char **argv) {
    int fd = open("./a.out",O_WRONLY | O_CREAT | O_TRUNC, 0755);
    if (fd == -1) {
        perror("open");
        exit(1);
    }

    if (add_header(fd) == -1) {
        close(fd);
        return -1;
    }

    close(fd);
    return 0;
}