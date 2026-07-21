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

struct section {
    void *buf;
    Elf64_Addr addr;
    Elf64_Off off;
    uint64_t size;
    uint64_t entsize;
};

struct obj_info {
    char *elf;
    uint64_t size;
    Elf64_Ehdr *ehdr;
    Elf64_Phdr *phdrtab;
    Elf64_Shdr *shdrtab;
    char *shstrtab;
    struct section text;
    struct section symtab;
    struct section strtab;
};

struct out_info {
    Elf64_Ehdr *ehdr;
    Elf64_Phdr *phdrtab;
    Elf64_Shdr *shdrtab;
    char *shstrtab;
    struct section *text;
    struct section symtab;
    struct section strtab;
};

static int check_valid(char *, size_t);
static int get_padding(int, int);
static void clean_up(int, void *, void *, void *);


// process object file
// return populated elf_info struct
// returns NULL on error
int process_obj(char *path, struct obj_info *obj_einfo) {

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
    obj_einfo->elf = obj_elf;
    obj_einfo->size = st.st_size;
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
    Elf64_Shdr *obj_shdrtab = (Elf64_Shdr *) (obj_elf + obj_ehdr->e_shoff);
    char *obj_shstrtab = obj_elf + obj_shdrtab[obj_ehdr->e_shstrndx].sh_offset;
    
    obj_einfo->ehdr = obj_ehdr;
    obj_einfo->shdrtab = obj_shdrtab;
    obj_einfo->shstrtab = obj_shstrtab;

    Elf64_Shdr curr;
    char *name;
    struct section text;
    struct section symtab;
    struct section strtab;
    memset(&text, 0, sizeof(text));
    memset(&symtab, 0, sizeof(symtab));
    memset(&strtab, 0, sizeof(strtab));

    // traverse object file's section header table
    for (int i = 1; i < obj_ehdr->e_shnum; i++) {
        curr = obj_shdrtab[i];
        name = obj_shstrtab + curr.sh_name;
        // if this section is the one we're looking for
        if (strcmp(name, ".text") == 0) {
            text.off = curr.sh_offset;
            text.size = curr.sh_size;
            text.addr = curr.sh_addr;
        } 
        else if (strcmp(name, ".symtab") == 0) {
            symtab.off = curr.sh_offset;
            symtab.size = curr.sh_size;
            symtab.addr = curr.sh_addr;
            symtab.entsize = curr.sh_entsize;
        }
        else if (strcmp(name, ".strtab") == 0) {
            strtab.off = curr.sh_offset;
            strtab.size = curr.sh_size;
            strtab.addr = curr.sh_addr;
        }
    }

    // grab the .text section
    if (text.off == 0 || symtab.off == 0 || strtab.off == 0) { 
        fprintf(stderr, "process_obj failed\n");
        munmap(obj_elf, st.st_size);
	    return -1;
    }

    text.buf = malloc(text.size);
    if (text.buf == NULL) {
        perror("malloc");
        munmap(obj_elf, st.st_size);
        return -1;
    }

    symtab.buf = malloc(symtab.size);
    if (symtab.buf == NULL) {
        perror("malloc");
        free(text.buf);
        munmap(obj_elf, st.st_size);
        return -1;
    }

    strtab.buf = malloc(strtab.size);
    if (strtab.buf == NULL) {
        perror("malloc");
        free(text.buf);
        free(symtab.buf);
        munmap(obj_elf, st.st_size);
        return -1;
    }

    obj_einfo->text = text;
    obj_einfo->symtab = symtab;
    obj_einfo->strtab = strtab;

    // copy the object's text section into our text buffer
    memset(obj_einfo->text.buf, 0, obj_einfo->text.size);
    memcpy(obj_einfo->text.buf, obj_einfo->elf + obj_einfo->text.off, obj_einfo->text.size);

    memset(obj_einfo->symtab.buf, 0, obj_einfo->symtab.size);
    memcpy(obj_einfo->symtab.buf, obj_einfo->elf + obj_einfo->symtab.off, obj_einfo->symtab.size);

    memset(obj_einfo->strtab.buf, 0, obj_einfo->strtab.size);
    memcpy(obj_einfo->strtab.buf, obj_einfo->elf + obj_einfo->strtab.off, obj_einfo->strtab.size);
    
    munmap(obj_einfo->elf, obj_einfo->size);
    
    return 0;
}


// compare magic numbers 
// check system compatibility
// check that program header, section header, and elf header can fit
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

    struct out_info einfo;
    memset(&einfo, 0, sizeof(struct out_info));


    // SET UP TEMPLATE ELF HEADER INFO
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
    ehdr.e_shnum = 5;
    ehdr.e_shstrndx = 4;  
    

    // create the section header table
    Elf64_Shdr shdr_tab[ehdr.e_shnum]; // in later parts should have 5 items
    einfo.shdrtab = shdr_tab;

    Elf64_Shdr sec0;
    memset(&sec0, 0, sizeof(Elf64_Shdr));

    Elf64_Shdr sec1;
    memset(&sec1, 0, sizeof(Elf64_Shdr)); //new_shdr.sh_name =  NOT IN PART 2
    
    Elf64_Shdr sec2;
    memset(&sec2, 0, sizeof(Elf64_Shdr));

    Elf64_Shdr sec3;
    memset(&sec3, 0, sizeof(Elf64_Shdr));

    Elf64_Shdr sec4;
    memset(&sec4, 0, sizeof(Elf64_Shdr));

    sec1.sh_type = SHT_PROGBITS;
    sec1.sh_flags = SHF_ALLOC | SHF_EXECINSTR;
    sec1.sh_addralign = 1; 
    sec1.sh_name = 1;

    sec2.sh_type = SHT_SYMTAB;
    sec2.sh_addralign = 8;
    sec2.sh_link = 3;
    sec2.sh_name = 7;
    sec2.sh_info = 1;

    sec3.sh_type = SHT_STRTAB;
    sec3.sh_addralign = 1;
    sec3.sh_name = 15;

    sec4.sh_type = SHT_STRTAB;
    sec4.sh_addralign = 1;
    sec4.sh_name = 23;


    Elf64_Phdr phdr_tab[ehdr.e_phnum];
    einfo.phdrtab = phdr_tab;
    
    Elf64_Phdr seg0;
    memset(&seg0, 0, sizeof(Elf64_Phdr));
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
    seg1.p_type = PT_LOAD;
    seg1.p_flags = PF_R | PF_X;
    seg1.p_align = PAGE_SIZE;


    struct obj_info obj_einfo;
    memset(&obj_einfo, 0, sizeof(struct obj_info));

    if (process_obj(argv[1], &obj_einfo) < 0) {
        fprintf(stderr, "process obj failed\n");
        exit(1);
    }

    // create the shstrtab
    char shstrtab[] = "\0.text\0.symtab\0.strtab\0.shstrtab";
    einfo.shstrtab = shstrtab;

    // update the sizes
    sec1.sh_size += obj_einfo.text.size;
    sec2.sh_size += obj_einfo.symtab.size;
    sec3.sh_size += obj_einfo.strtab.size;
    sec4.sh_size += sizeof(shstrtab);

    sec2.sh_entsize = obj_einfo.symtab.entsize;

    seg1.p_filesz += obj_einfo.text.size;
    seg1.p_memsz += obj_einfo.text.size;

    //Ok now that we have text size, we can properly set fields for P-header and Section header tables. 
    seg1.p_offset = seg0.p_filesz + get_padding(seg0.p_filesz, PAGE_SIZE);     

    seg1.p_vaddr = seg0.p_vaddr + seg1.p_offset;
    seg1.p_paddr = seg1.p_vaddr;
    ehdr.e_entry = seg1.p_vaddr; // virtual address of text section 
    sec1.sh_addr = seg1.p_vaddr; 

    // update offsets
    sec1.sh_offset = seg1.p_offset;
    sec2.sh_offset = sec1.sh_offset + sec1.sh_size + get_padding(sec1.sh_offset + sec1.sh_size, PAGE_SIZE);
    sec3.sh_offset = sec2.sh_offset + sec2.sh_size;
    sec4.sh_offset = sec3.sh_offset + sec3.sh_size;

    ehdr.e_shoff = sec4.sh_offset + sec4.sh_size + get_padding(sec4.sh_offset + sec4.sh_size, 8);//seg1.p_offset + seg1.p_filesz + get_padding(seg1.p_offset + seg1.p_filesz);

    shdr_tab[0] = sec0;
    shdr_tab[1] = sec1;
    shdr_tab[2] = sec2;
    shdr_tab[3] = sec3;
    shdr_tab[4] = sec4;

    phdr_tab[0] = seg0;
    phdr_tab[1] = seg1;

    // alter the two fields in each symbol table entry
    Elf64_Sym *curr;
    for (int i = 1; i < obj_einfo.symtab.size / sizeof(Elf64_Sym); i++){
		curr = ((Elf64_Sym *)(obj_einfo.symtab.buf) + i); //  address of current symtable entry. 
		if (curr->st_shndx == SHN_ABS) {
            continue;
        }
        else if (curr->st_shndx == SHN_UNDEF || curr->st_shndx == SHN_COMMON || curr->st_shndx == SHN_XINDEX) {
            clean_up(fd, obj_einfo.text.buf, obj_einfo.symtab.buf, obj_einfo.strtab.buf);
            fprintf(stderr,"symbol not supported\n");
            return -1;
        }
        curr->st_shndx = 1; 
        curr->st_value = seg1.p_vaddr + curr->st_value;
	}

       
    // TIME TO WRITE EVERYTHING. 
    int written_bytes = 0;
    // write elf header
    if ((n = write(fd, &ehdr, sizeof(ehdr))) != sizeof(ehdr)) {
        perror("write");
        clean_up(fd, obj_einfo.text.buf, obj_einfo.symtab.buf, obj_einfo.strtab.buf);
        return -1;
    }
    written_bytes += n;
    
    // write program header table
    if ((n = write(fd, phdr_tab, ehdr.e_phentsize*ehdr.e_phnum)) != ehdr.e_phentsize*ehdr.e_phnum) {
        perror("write");
        clean_up(fd, obj_einfo.text.buf, obj_einfo.symtab.buf, obj_einfo.strtab.buf);
        return -1;
    }
    written_bytes += n;


    //Ok now write 000s to manage the padding (PAGESIZE - sizeof (EHDR) - 2*sizeof(PHDR))
	int padding_size = get_padding(written_bytes, PAGE_SIZE);
    if (padding_size != 0) {
        char buf1[padding_size];
        memset(buf1, 0, padding_size);
        if ((n = write(fd, buf1, padding_size)) != padding_size) {
            perror("write");
            clean_up(fd, obj_einfo.text.buf, obj_einfo.symtab.buf, obj_einfo.strtab.buf);
            return -1;
        }
        written_bytes += n;
    }


    //Ok now write the text
    if ((n = write(fd, obj_einfo.text.buf, obj_einfo.text.size)) != obj_einfo.text.size) {
        perror("write");
        clean_up(fd, obj_einfo.text.buf, obj_einfo.symtab.buf, obj_einfo.strtab.buf);
        return -1;
    }
    // get rid of text buffer now that it's written
    free(obj_einfo.text.buf);
    obj_einfo.text.buf = NULL;
    written_bytes += n;

    // write the padding
    padding_size = get_padding(written_bytes, PAGE_SIZE);
    if (padding_size != 0) {
        char buf2[padding_size];
        memset(buf2, 0, padding_size);
        if ((n = write(fd, buf2, padding_size)) != padding_size) {
            perror("write");
            clean_up(fd, obj_einfo.text.buf, obj_einfo.symtab.buf, obj_einfo.strtab.buf);
            return -1;
        }
        written_bytes += n;
    }

    
    // write the symbol table
    if ((n = write(fd, obj_einfo.symtab.buf, obj_einfo.symtab.size)) != (obj_einfo.symtab.size)) { 
        perror("writing to file on disk.");
        clean_up(fd, obj_einfo.text.buf, obj_einfo.symtab.buf, obj_einfo.strtab.buf);
        return -1;
    }
    written_bytes += n;
    free(obj_einfo.symtab.buf);
    obj_einfo.symtab.buf = NULL;

    // need to write strtab
    if ((n = write(fd, obj_einfo.strtab.buf, obj_einfo.strtab.size)) != (obj_einfo.strtab.size)) { 
        perror("writing to file on disk.");
        clean_up(fd, obj_einfo.text.buf, obj_einfo.symtab.buf, obj_einfo.strtab.buf);
        return -1;
    }
    written_bytes += n;
    free(obj_einfo.strtab.buf);
    obj_einfo.strtab.buf = NULL;

    // write shstrtab
    if ((n = write(fd, shstrtab, sizeof(shstrtab))) != sizeof(shstrtab)) { 
        perror("writing to file on disk.");
        clean_up(fd, obj_einfo.text.buf, obj_einfo.symtab.buf, obj_einfo.strtab.buf);
        return -1;
    }
    written_bytes += n;

    // write padding to align shdrtab to 8 bytes
    padding_size = get_padding(written_bytes, 8);
    if (padding_size != 0) {
        char buf1[padding_size];
        memset(buf1, 0, padding_size);
        if ((n = write(fd, buf1, padding_size)) != padding_size) {
            perror("write");
            clean_up(fd, obj_einfo.text.buf, obj_einfo.symtab.buf, obj_einfo.strtab.buf);
            return -1;
        }
        written_bytes += n;
    }

    //Write the section header table
    if ((n = write(fd, shdr_tab, ehdr.e_shentsize*ehdr.e_shnum)) != (ehdr.e_shentsize*ehdr.e_shnum)) { 
        perror("writing to file on disk.");
        clean_up(fd, obj_einfo.text.buf, obj_einfo.symtab.buf, obj_einfo.strtab.buf);
        return -1;
    }
    written_bytes += n;

    clean_up(fd, obj_einfo.text.buf, obj_einfo.symtab.buf, obj_einfo.strtab.buf);
    return 0;
}

int get_padding(int curr_offset, int num_align) {
    int multiplier = (curr_offset) / num_align + 1;
    int padding_size = 0;
    if (curr_offset % num_align != 0) {
        padding_size = multiplier*num_align - curr_offset;
    }
    return padding_size;
}

void clean_up(int fd, void *text, void *symtab, void *strtab) {
    if (fd >= 0) {
        close(fd);
    }
    if (text != NULL) {
        free(text);
    }
    if (symtab != NULL) {
        free(symtab);
    }
    if (strtab != NULL) {
        free(strtab);
    }
}