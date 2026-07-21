// gen-exe.c
#include <stdio.h>
#include <elf.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>

#define PAGE_SIZE 4096

struct elf_info {
    Elf64_Ehdr *ehdr;
    Elf64_Phdr **phdrtab;
    Elf64_Shdr **shdrtab;
    Elf64_Sym *symtab;
    char *strtab;
    char *shstrtab;
    struct section *text;
};

struct section {
    void *buf;
    Elf64_Addr addr;
    Elf64_Off off;
    uint64_t size;
};

static int check_valid(char *, size_t);
static int get_padding(int);


// processes an object file's .text section
// returning a populated struct section
int process_obj(char *path, struct elf_info *einfo) {
    // 1. load the object file
    int obj_fd = open(path, O_RDONLY);
    if (obj_fd < 0) {
	    perror("open");
	    return -1;
    }

    struct stat st;
    if (fstat(obj_fd, &st) == -1) {
        perror("fstat() failed");
        close(obj_fd);
        return -1;
    }

    char *obj_elf = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, obj_fd, 0);
    close(obj_fd);
    if (obj_elf == MAP_FAILED) {
        perror("mmap");
        return -1;
    }

    // verify that it's a valid elf file
    if (! check_valid(obj_elf, st.st_size)) {
        fprintf(stderr, "invalid elf file\n");
        munmap(obj_elf, st.st_size);
        return -1;
    }

    // parse object elf file for desired .text, .symtab, .strtab section
    Elf64_Ehdr *obj_ehdr = (Elf64_Ehdr *)obj_elf;
    Elf64_Shdr *obj_shdr_tab = (Elf64_Shdr *) (obj_elf + obj_ehdr->e_shoff);
    char *obj_shstrtab = obj_elf + obj_shdr_tab[obj_ehdr->e_shstrndx].sh_offset;
    
    Elf64_Shdr curr;
    char *name;
    struct section text;
    memset(&text, 0, sizeof(text));
    // verify that this is < and not <=
    for (int i = 1; i < obj_ehdr->e_shnum; i++) {
        curr = obj_shdr_tab[i];
        name = obj_shstrtab + curr.sh_name;
        // if this section is the one we're looking for
        if (strcmp(name, ".text") == 0) {
            text.off = curr.sh_offset;
            text.size = curr.sh_size;
            text.addr = curr.sh_addr;
            break;
        } 
    }

    // grab the .text section
    if (text.size == 0) { // in the future if we deal w/ size 0 sections this is problematic
        fprintf(stderr, "get_offset failed\n");
        munmap(obj_elf, st.st_size);
	    return -1;
    }

    text.buf = malloc(text.size);
    if (text.buf == NULL) {
        perror("malloc");
        munmap(obj_elf, st.st_size);
        return -1;
    }

    // copy the object's text section into our text buffer
    memset(text.buf, 0, text.size);
    memcpy(text.buf, obj_elf + text.off, text.size);
    munmap(obj_elf, st.st_size);

    einfo->text[0] = text;

    Elf64_Phdr **phdr_tab = einfo->phdrtab;
    Elf64_Shdr **shdr_tab = einfo->shdrtab;

    shdr_tab[1]->sh_size += text.size;
    phdr_tab[1]->p_filesz += text.size;
    phdr_tab[1]->p_memsz += text.size;


    return 0;
}



// compare magic numbers 
// check system compatibility
// check that program header, section header, and elf header ecan fit
// but C has no way to actually check if something is of a certain type of struct. 
int check_valid(char *elf, size_t file_size) {
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)elf;

    if (file_size < sizeof(Elf64_Ehdr)) {
        return 0;
    }

    // check magic numbers
    if (! (ehdr->e_ident[EI_MAG0] == 0x7f && ehdr->e_ident[EI_MAG1] == 'E' && ehdr->e_ident[EI_MAG2] == 'L' && ehdr->e_ident[EI_MAG3] == 'F')) {
        return 0;
    }

    // check system requirements
    if (! (ehdr->e_ident[EI_CLASS] == ELFCLASS64 && ehdr->e_ident[EI_DATA] == ELFDATA2LSB && ehdr->e_type == ET_REL && ehdr->e_machine == EM_X86_64)) {
        return 0;
    }

    // check is sizes and offsets fit in file_size
    if (! ((sizeof(Elf64_Ehdr) <= file_size) && (ehdr->e_phoff + ehdr->e_phentsize * ehdr->e_phnum <= file_size) && (ehdr->e_shoff + ehdr->e_shentsize * ehdr->e_shnum <= file_size) && (ehdr->e_shstrndx < ehdr->e_shnum))) {
        return 0;
    }
    
    if ((ehdr->e_ehsize != sizeof(Elf64_Ehdr)) || (ehdr->e_shentsize != sizeof(Elf64_Shdr)) || (ehdr->e_phnum > 0 && (ehdr->e_phentsize != sizeof(Elf64_Phdr)))) {
        return 0;
    }

   return 1;

}


// open() hello.o to retrieve info to write to a.out
// parse hello.o's .text and check that it's a valid elf header
// pwrite() ??

// make a checker function that can verify if you're at .strtab
// for strtab can get one of the strings
// check if the fields line up with what we expect them to be
// make a function to parse strtab and grab offset
int main (int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: ./cld <object-file>\n");
        exit(1);
    }
    
	int fd = open("./a.out",O_WRONLY | O_CREAT | O_TRUNC, 0755);
    if (fd == -1) {
        perror("open");
        exit(1);
    }

    struct elf_info einfo;

    // initialize the elf header
    ssize_t n;
    Elf64_Ehdr ehdr;
    einfo.ehdr = &ehdr;
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

    ehdr.e_phoff = sizeof(Elf64_Ehdr);
    ehdr.e_flags = 0; 
    ehdr.e_ehsize = sizeof(Elf64_Ehdr);
    ehdr.e_phentsize = sizeof(Elf64_Phdr);
    ehdr.e_phnum = 2;
    ehdr.e_shentsize = sizeof(Elf64_Shdr);
    ehdr.e_shnum = 2;
    ehdr.e_shstrndx = 0;  
    

    // create the section header table
    Elf64_Shdr *shdr_tab[ehdr.e_shnum]; // in later parts should have 5 items
    einfo.shdrtab = shdr_tab;

    Elf64_Shdr sec0;
    memset(&sec0, 0, sizeof(Elf64_Shdr));
    shdr_tab[0] = &sec0;

    Elf64_Shdr sec1;
    memset(&sec1, 0, sizeof(Elf64_Shdr)); //new_shdr.sh_name =  NOT IN PART 2
    shdr_tab[1] = &sec1;
    sec1.sh_type = SHT_PROGBITS;
    sec1.sh_flags = SHF_ALLOC | SHF_EXECINSTR;
    sec1.sh_addralign = 1;


    Elf64_Phdr *phdr_tab[ehdr.e_phnum];
    einfo.phdrtab = phdr_tab;
    Elf64_Phdr seg0;
    memset(&seg0, 0, sizeof(Elf64_Phdr));
    phdr_tab[0] = &seg0;

    seg0.p_type = PT_LOAD;
    seg0.p_flags = PF_R; 
    seg0.p_offset = 0;
    seg0.p_vaddr = 0x400000;
    seg0.p_paddr = 0x400000;
    seg0.p_align = PAGE_SIZE;
    seg0.p_filesz = sizeof(Elf64_Ehdr) + sizeof(Elf64_Phdr)*ehdr.e_phnum; // not including padding
    seg0.p_memsz = seg0.p_filesz; //this used to be: sizeof(Elf64_Ehdr) + 2*sizeof(Elf64_Phdr);

    Elf64_Phdr seg1;
    memset(&seg1, 0, sizeof(Elf64_Phdr));
    phdr_tab[1] = &seg1;
    seg1.p_type = PT_LOAD;
    seg1.p_flags = PF_R | PF_X;
    seg1.p_align = PAGE_SIZE;

    // initialize the einfo text pointer
    struct section text[argc];
    einfo.text = text;

    if (process_obj(argv[1], &einfo) < 0) {
        fprintf(stderr, "process_obj failed\n");
        close(fd);
        return -1;
    }

    //Ok now that we have text size, we can properly set fields for P-header and Section header tables. 
    seg1.p_offset = seg0.p_filesz + get_padding(seg0.p_filesz); 
    ehdr.e_shoff = seg1.p_offset + seg1.p_filesz + get_padding(seg1.p_offset + seg1.p_filesz);

    sec1.sh_offset = seg1.p_offset;

    seg1.p_vaddr = seg0.p_vaddr + seg1.p_offset;
    seg1.p_paddr = seg1.p_vaddr;
    ehdr.e_entry = seg1.p_vaddr; // virtual address of text section 
    sec1.sh_addr = seg1.p_vaddr; 

       
    // TIME TO WRITE EVERYTHING. 
    int written_bytes = 0;
    // write elf header
    if ((n = write(fd, &ehdr, sizeof(ehdr))) != sizeof(ehdr)) {
        perror("write");
        // ***prob make a function to free everything in the text table for part 4/5
        free(text[0].buf);
        close(fd);
        return -1;
    }
    written_bytes += n;
    
    // write program header table
    for (int i = 0; i < ehdr.e_phnum; i++) {
        if ((n = write(fd, phdr_tab[i], ehdr.e_phentsize)) != ehdr.e_phentsize) {
            perror("write");
            free(text[0].buf);
            close(fd);
            return -1;
        }
        written_bytes += n;
    }


    //Ok now write 000s to manage the padding (PAGESIZE - sizeof (EHDR) - 2*sizeof(PHDR))
	int padding_size = get_padding(written_bytes);
    if (padding_size != 0) {
        char buf1[padding_size];
        memset(buf1, 0, padding_size);
        if ((n = write(fd, buf1, padding_size)) != padding_size) {
            perror("write");
            free(text[0].buf);
            close(fd);
            return -1;
        }
        written_bytes += n;
    }


    //Ok now write the text
    if ((n = write(fd, text[0].buf, text[0].size)) != text[0].size) {
        perror("write");
        free(text[0].buf);
        close(fd);
        return -1;
    }
    // get rid of text buffer now that it's written
    free(text[0].buf);
    written_bytes += n;

    // write the padding
    padding_size = get_padding(written_bytes);
    if (padding_size != 0) {
        char buf2[padding_size];
        memset(buf2, 0, padding_size);
        if ((n = write(fd, buf2, padding_size)) != padding_size) {
            perror("write");
            close(fd);
            return -1;
        }
        written_bytes += n;
    }

    //Write the section header table
    for (int i = 0; i < ehdr.e_shnum; i++) {
        if ((n = write(fd, shdr_tab[i], ehdr.e_shentsize)) != (ehdr.e_shentsize)) { 
            perror("writing to file on disk.");
            close(fd);
            return -1;
        }
        written_bytes += n;
    }

    close(fd);
    return 0;
}

int get_padding(int curr_offset) {
    int multiplier = (curr_offset) / PAGE_SIZE + 1;
    int padding_size = 0;
    if (curr_offset % PAGE_SIZE != 0) {
        padding_size = multiplier*PAGE_SIZE - curr_offset;
    }
    return padding_size;
}