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
    uint16_t text_shndx;
    struct section rela;
    struct section symtab;
    struct section strtab;
};

struct out_info {
    int num_obj;
    Elf64_Ehdr *ehdr;
    Elf64_Phdr *phdrtab;
    Elf64_Shdr *shdrtab;
    char *shstrtab;
    struct section *text;
    struct section symtab;
    struct section strtab;
};

static int check_valid(char *, size_t);
static size_t get_padding(Elf64_Off, size_t);
static void clean_up(int, struct obj_info *, struct out_info *, int**);


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
        obj_einfo->elf = NULL;
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
    struct section rela;
    memset(&text, 0, sizeof(text));
    memset(&symtab, 0, sizeof(symtab));
    memset(&strtab, 0, sizeof(strtab));
    memset(&rela, 0, sizeof(rela));

    // traverse object file's section header table
    for (int i = 1; i < obj_ehdr->e_shnum; i++) {
        curr = obj_shdrtab[i];
        name = obj_shstrtab + curr.sh_name;
        // if this section is the one we're looking for
        if (strcmp(name, ".text") == 0) {
            text.off = curr.sh_offset;
            text.size = curr.sh_size;
            obj_einfo->text_shndx = i;
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
        else if (strcmp(name, ".rela.text") == 0) {
            rela.off = curr.sh_offset;
            rela.size = curr.sh_size;
            rela.addr = curr.sh_addr;
            rela.entsize = curr.sh_entsize; // check this
        }
    }

    // grab the .text section
    if (text.off == 0 || symtab.off == 0 || strtab.off == 0) { 
        fprintf(stderr, "process_obj failed\n");
        munmap(obj_elf, st.st_size);
        obj_einfo->elf = NULL;
	    return -1;
    }

    text.buf = malloc(text.size);
    if (text.buf == NULL) {
        perror("malloc");
        munmap(obj_elf, st.st_size);
        obj_einfo->elf = NULL;
        return -1;
    }

    symtab.buf = malloc(symtab.size);
    if (symtab.buf == NULL) {
        perror("malloc");
        free(text.buf);
        text.buf = NULL;
        munmap(obj_elf, st.st_size);
        obj_einfo->elf = NULL;
        return -1;
    }

    strtab.buf = malloc(strtab.size);
    if (strtab.buf == NULL) {
        perror("malloc");
        free(text.buf);
        free(symtab.buf);
        text.buf = NULL;
        symtab.buf = NULL;
        munmap(obj_elf, st.st_size);
        obj_einfo->elf = NULL;
        return -1;
    }

    if (rela.size > 0) {
        rela.buf = malloc(rela.size);
        if (rela.buf == NULL) {
            perror("malloc");
            free(text.buf);
            free(symtab.buf);
            free(strtab.buf);
            text.buf = NULL;
            symtab.buf = NULL;
            strtab.buf = NULL;
            munmap(obj_elf, st.st_size);
            obj_einfo->elf = NULL;
            return -1;
        }
    }

    obj_einfo->text = text;
    obj_einfo->symtab = symtab;
    obj_einfo->strtab = strtab;
    obj_einfo->rela = rela;

    // copy the object file's text section into our the respective obj_info buffer
    memset(obj_einfo->text.buf, 0, obj_einfo->text.size);
    memcpy(obj_einfo->text.buf, obj_einfo->elf + obj_einfo->text.off, obj_einfo->text.size);

    memset(obj_einfo->symtab.buf, 0, obj_einfo->symtab.size);
    memcpy(obj_einfo->symtab.buf, obj_einfo->elf + obj_einfo->symtab.off, obj_einfo->symtab.size);

    memset(obj_einfo->strtab.buf, 0, obj_einfo->strtab.size);
    memcpy(obj_einfo->strtab.buf, obj_einfo->elf + obj_einfo->strtab.off, obj_einfo->strtab.size);

    if (rela.size > 0) {
        memset(obj_einfo->rela.buf, 0, obj_einfo->rela.size);
        memcpy(obj_einfo->rela.buf, obj_einfo->elf + obj_einfo->rela.off, obj_einfo->rela.size);
    }
  
    munmap(obj_einfo->elf, obj_einfo->size);
    obj_einfo->elf = NULL;
    
    return 0;
}

int relocate(struct obj_info *obj_einfo, struct out_info *einfo, int *map) {
    if (obj_einfo->rela.size == 0 || obj_einfo->rela.entsize == 0) {
        return 0;
    }
    
    // iterate through object file's relocation table
    // changes are applied directly to the object file's own text buffer
    for (int i = 0; i < (obj_einfo->rela.size / obj_einfo->rela.entsize); i++) {
        Elf64_Rela *curr = (Elf64_Rela *) (obj_einfo->rela.buf) + i;
        // filter out unsupported types
        if ((ELF64_R_TYPE(curr->r_info) != R_X86_64_PC32) && (ELF64_R_TYPE(curr->r_info) != R_X86_64_PLT32 )) {
            fprintf(stderr,"rela type not supported\n");
            return -1;
        }
        // replace zero bytes with the distance from the next line to the symbol address
        int32_t val;
        Elf64_Sym *local_sym = ((Elf64_Sym *)(obj_einfo->symtab.buf)) + ELF64_R_SYM(curr->r_info);
        if (ELF64_ST_BIND(local_sym->st_info) == STB_GLOBAL) {
            // map to master symtab index
            int out_i = map[ELF64_R_SYM(curr->r_info)];
            if (out_i < 0) {
                fprintf(stderr, "invalid mapping for local sym index: %d\n", (int) ELF64_R_SYM(curr->r_info));
                return -1;
            }
            val = (((Elf64_Sym *) einfo->symtab.buf) + map[ELF64_R_SYM(curr->r_info)])->st_value - (obj_einfo->text.addr + curr->r_offset) + curr->r_addend;
        }
        else {
            val = obj_einfo->text.addr + local_sym->st_value - (obj_einfo->text.addr + curr->r_offset) + curr->r_addend; // all vals are virtual addrs now. 
        }
        memcpy((char *)obj_einfo->text.buf + curr->r_offset, &val, sizeof(val));
    }
    return 0;
}


// make a checker function that can verify if you're at .strtab
// for strtab can get one of the strings
// check if the fields line up with what we expect them to be
// make a function to parse strtab and grab offset
int main (int argc, char **argv) {
    if (argc < 2) {
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
    einfo.num_obj = argc - 1;

    // SET UP TEMPLATE ELF HEADER INFO
    // initialize the elf header
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
    Elf64_Shdr shdr_tab[ehdr.e_shnum];
    einfo.shdrtab = shdr_tab;

    Elf64_Shdr sec0;
    memset(&sec0, 0, sizeof(Elf64_Shdr));

    Elf64_Shdr sec1;
    memset(&sec1, 0, sizeof(Elf64_Shdr));
    
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

    sec3.sh_type = SHT_STRTAB;
    sec3.sh_addralign = 1;
    sec3.sh_name = 15;

    sec4.sh_type = SHT_STRTAB;
    sec4.sh_addralign = 1;
    sec4.sh_name = 23;


    // create the phdr table
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
    seg0.p_memsz = seg0.p_filesz; 

    Elf64_Phdr seg1;
    memset(&seg1, 0, sizeof(Elf64_Phdr));
    seg1.p_type = PT_LOAD;
    seg1.p_flags = PF_R | PF_X;
    seg1.p_align = PAGE_SIZE;

    // set offset and virtual address for start of text section (fixed)
    seg1.p_offset = seg0.p_filesz + get_padding(seg0.p_filesz, PAGE_SIZE);  
    sec1.sh_offset = seg1.p_offset;  
    seg1.p_vaddr = seg0.p_vaddr + seg1.p_offset;
    seg1.p_paddr = seg1.p_vaddr;
    sec1.sh_addr = seg1.p_vaddr; 

    // create the shstrtab
    char shstrtab[] = "\0.text\0.symtab\0.strtab\0.shstrtab";
    einfo.shstrtab = shstrtab;
    sec4.sh_size = sizeof(shstrtab);



    // Create an array of obj_info
    struct obj_info obj_arr[einfo.num_obj];
    struct obj_info curr_obj;
    size_t max_symtab_size = 0;
    size_t max_strtab_size = 0;
    size_t text_off = 0;

    // iterate through obj_arr to process each object and track total size
    for (int i = 1; i <= einfo.num_obj; i++) {
        memset(&curr_obj, 0, sizeof(struct obj_info));

        // setup the obj_info struct for each object file
        if (process_obj(argv[i], &curr_obj) < 0) {
            fprintf(stderr, "process obj failed\n");
            clean_up(fd, obj_arr, &einfo, NULL);
            exit(1);
        }
        // for each object file, text.addr contains the master virtual address of the start of its text section
        curr_obj.text.addr = seg1.p_vaddr + text_off;
        memcpy(obj_arr + i - 1, &curr_obj, sizeof(curr_obj));
        // grab the max master symtab size
        max_symtab_size += curr_obj.symtab.size;
        max_strtab_size += curr_obj.strtab.size;
        text_off += curr_obj.text.size;
    }

    // update the sizes w/ concatenated text size
    sec1.sh_size = text_off; 
    seg1.p_filesz = text_off;
    seg1.p_memsz = text_off; 




//----------------------------------------------------------------------------------------------------------------------------
    // CREATE MASTER SYMTAB AND STRTAB

    struct section o_symtab;
    struct section o_strtab;
    memset(&o_symtab, 0, sizeof(o_symtab));
    memset(&o_strtab, 0, sizeof(o_strtab));
    einfo.symtab = o_symtab;
    einfo.strtab = o_strtab;

    //malloc maximum possible size of master symtab and strtab
    einfo.symtab.buf = malloc(max_symtab_size); 
    if (einfo.symtab.buf == NULL ) { 
        fprintf(stderr, "malloc error during symtab"); 
        clean_up(fd, obj_arr, &einfo, NULL);
        return -1;
    }
    memset(einfo.symtab.buf, 0, max_symtab_size);

    einfo.strtab.buf = malloc(max_strtab_size); 
    if (einfo.strtab.buf == NULL ) { 
        fprintf(stderr, "malloc error during strtab"); 
        clean_up(fd, obj_arr, &einfo, NULL);
        return -1;
    }
    memset(einfo.strtab.buf, 0, max_strtab_size);


    // CREATE UNION SYMTAB AND STRTAB
    int master_sym_ind = 1; // next open index in master symtab buf where each entry is of size Elf64_Sym
    int master_str_ind = 1;
    int *sym_map[einfo.num_obj];
    memset(sym_map, 0, sizeof(sym_map));
    
    // iterate through each obj_info and appropriately populate master symtab
    for (int j = 0; j < einfo.num_obj; j++) {
        struct obj_info *obj_einfo = obj_arr + j; // current obj_info
        // malloc the object's mapping array which stores num_sym integers
        // maps object's symtab index -> corresponding master symtab index for a certain symbol
        sym_map[j] = malloc(obj_einfo->symtab.size / obj_einfo->symtab.entsize * sizeof(int));
        if (sym_map[j] == NULL) {
            perror("malloc");
            clean_up(fd, obj_arr, &einfo, sym_map);
            exit(1);
        }
        memset(sym_map[j], -1, obj_einfo->symtab.size / obj_einfo->symtab.entsize * sizeof(int));
        // iterate through each symbol in the object file's symtab
        for (int i = 1; i < (obj_einfo->symtab.size / obj_einfo->symtab.entsize); i++) {
            Elf64_Sym *curr = (Elf64_Sym *) (obj_einfo->symtab.buf) + i;
            
            // skip non-global symbols
            if (ELF64_ST_BIND(curr->st_info) != STB_GLOBAL) {
                continue;
            }

            char *name = ((char *) (obj_einfo->strtab.buf)) + curr->st_name;

            // traverse master symtab to look for existing entry
            int append = 1;
            for (int k = 0; k < master_sym_ind; k++) {
                Elf64_Sym *master_curr = (Elf64_Sym *) (einfo.symtab.buf) + k;
                char *master_name = ((char *) einfo.strtab.buf) + master_curr->st_name;
                    
                if (strcmp(name, master_name) == 0) {
                    // map obj index -> master index for each symbol
                    sym_map[j][i] = k;
                    append = 0;
                    // if the entry already exists and we aren't defining it, do not alter master symtab
                    if (curr->st_shndx != obj_einfo->text_shndx) {
                        break;
                    }

                    if (master_curr->st_shndx == 1 && curr->st_shndx == obj_einfo->text_shndx) {
                        // if we find a new definition for a symbol we already had defined
                        // throw error and exit
                        fprintf(stderr, "double definition error for symbol %s\n", master_name);
                        clean_up(fd, obj_arr, &einfo, sym_map);
                        exit(1);
                    }
                    else if (curr->st_shndx == obj_einfo->text_shndx) { // update previous master symtab entry to now have the definition
                        uint32_t master_name_copy = master_curr->st_name;
                        memcpy(master_curr, curr, sizeof(*curr));
                        master_curr->st_name = master_name_copy;
                        master_curr->st_shndx = 1;
                        master_curr->st_value = obj_einfo->text.addr + curr->st_value;
                        if (strcmp(name, "_start") == 0) {
                            einfo.ehdr->e_entry = master_curr->st_value;//obj_einfo->text.addr + curr->st_value;
                        }
                        break;
                    }
                }
            }
            if (append) { // if we didn't find an existing entry, append it to the end of master symtab and strtab
                Elf64_Sym *master_curr = (Elf64_Sym *)(einfo.symtab.buf) + master_sym_ind;
                memcpy(master_curr, curr, sizeof(Elf64_Sym)); 
                master_curr->st_name = master_str_ind;
                // text_off should be the total offset from all the current master symbol entries' text sections
                if (curr->st_shndx == obj_einfo->text_shndx) {
                    master_curr->st_value = obj_einfo->text.addr + curr->st_value;
                    master_curr->st_shndx = 1;
                }
                strcpy((char *)einfo.strtab.buf + master_str_ind, name);
                sym_map[j][i] = master_sym_ind;
                master_sym_ind++;
                master_str_ind += strlen(name) + 1;
                if (curr->st_shndx == obj_einfo->text_shndx && strcmp(name, "_start") == 0) {
                    einfo.ehdr->e_entry = master_curr->st_value;
                }
            }
            
        }
    }
    


    // make sure this is AFTER we've processed all object files
    if (einfo.ehdr->e_entry == 0) {
        fprintf(stderr, "no _start function found\n");
        clean_up(fd, obj_arr, &einfo, sym_map);
        exit(1);
    }
    sec2.sh_entsize = obj_arr[0].symtab.entsize; // ASSUMPTION: all symtabs have same entry size. i think this is find? should all be Elf64_Sym


    einfo.symtab.size = (master_sym_ind) * sizeof(Elf64_Sym); 
    einfo.strtab.size = master_str_ind; 

    sec2.sh_info = 1;
    
    //Update the sizes in the section headers: 
    sec2.sh_size = einfo.symtab.size;
    sec3.sh_size = einfo.strtab.size;
    //---------------------------------------------------------------------------------------------------------------------------------------------------------------------


    // update offsets after having adjusted strtab and symtab. 
    sec2.sh_offset = sec1.sh_offset + sec1.sh_size + get_padding(sec1.sh_offset + sec1.sh_size, PAGE_SIZE);
    sec3.sh_offset = sec2.sh_offset + sec2.sh_size;
    sec4.sh_offset = sec3.sh_offset + sec3.sh_size;

    ehdr.e_shoff = sec4.sh_offset + sec4.sh_size + get_padding(sec4.sh_offset + sec4.sh_size, 8);
    
    //Save these to shdr_tab and phdr_tab arrays: 

    shdr_tab[0] = sec0;
    shdr_tab[1] = sec1;
    shdr_tab[2] = sec2;
    shdr_tab[3] = sec3;
    shdr_tab[4] = sec4;

    phdr_tab[0] = seg0;
    phdr_tab[1] = seg1;

    for (int i = 0; i < einfo.num_obj; i++) {
        struct obj_info *obj_einfo = obj_arr + i; // current obj_info
        // handle relocations within an object's elf file
        if (relocate(obj_einfo, &einfo, sym_map[i]) < 0) {
            clean_up(fd, obj_arr, &einfo, sym_map);
            fprintf(stderr, "relocation error");
            exit(1);
        }
    }

    // alter the two fields in each symbol table entry
    Elf64_Sym *curr;
    for (int i = 1; i < einfo.symtab.size / sizeof(Elf64_Sym); i++) {
		curr = ((Elf64_Sym *)(einfo.symtab.buf) + i); //  address of current symtable entry. 
		if (curr->st_shndx == SHN_ABS) {
            continue;
        }
        else if (curr->st_shndx == SHN_UNDEF) {
            clean_up(fd, obj_arr, &einfo, sym_map);
            fprintf(stderr,"undefined reference\n");
            return -1;
        } 
        else if (curr->st_shndx == SHN_COMMON || curr->st_shndx == SHN_XINDEX) {
            clean_up(fd, obj_arr, &einfo, sym_map);
            fprintf(stderr,"symbol not supported\n");
            return -1;
        }
        curr->st_shndx = 1; 
	}
       

//----------------------------------------------------------------------------------------------------------------------------------
    // TIME TO WRITE EVERYTHING. 
    size_t n;

    size_t written_bytes = 0;
    // write elf header
    if ((n = write(fd, &ehdr, sizeof(ehdr))) != sizeof(ehdr)) {
        perror("write");
        clean_up(fd, obj_arr, &einfo, sym_map);
        return -1;
    }
    written_bytes += n;
    
    // write program header table
    if ((n = write(fd, phdr_tab, ehdr.e_phentsize*ehdr.e_phnum)) != ehdr.e_phentsize*ehdr.e_phnum) {
        perror("write");
        clean_up(fd, obj_arr, &einfo, sym_map);
        return -1;
    }
    written_bytes += n;


    //Ok now write 000s to manage the padding (PAGESIZE - sizeof (EHDR) - 2*sizeof(PHDR))
	size_t padding_size = get_padding(written_bytes, PAGE_SIZE);
    if (padding_size != 0) {
        char buf1[padding_size];
        memset(buf1, 0, padding_size);
        if ((n = write(fd, buf1, padding_size)) != padding_size) {
            perror("write");
            clean_up(fd, obj_arr, &einfo, sym_map);
            return -1;
        }
        written_bytes += n;
    }


    //Ok now write the text
    for (int i = 0; i < einfo.num_obj; i++) {
        struct obj_info *obj_einfo = obj_arr + i;
        if ((n = write(fd, obj_einfo->text.buf, obj_einfo->text.size)) != obj_einfo->text.size) {
            perror("write");
            clean_up(fd, obj_arr, &einfo, sym_map);
            return -1;
        }
        // get rid of text buffer now that it's written
        free(obj_einfo->text.buf);
        obj_einfo->text.buf = NULL;
        written_bytes += n;
    }


    // write the padding
    padding_size = get_padding(written_bytes, PAGE_SIZE);
    if (padding_size != 0) {
        char buf2[padding_size];
        memset(buf2, 0, padding_size);
        if ((n = write(fd, buf2, padding_size)) != padding_size) {
            perror("write");
            clean_up(fd, obj_arr, &einfo, sym_map);
            return -1;
        }
        written_bytes += n;
    }

    
    // write the symbol table
    if ((n = write(fd, einfo.symtab.buf, einfo.symtab.size)) != (einfo.symtab.size)) { 
        perror("writing to file on disk.");
        clean_up(fd, obj_arr, &einfo, sym_map);
        return -1;
    }
    written_bytes += n;
    free(einfo.symtab.buf);
    einfo.symtab.buf = NULL;

    // write strtab
    if ((n = write(fd, einfo.strtab.buf, einfo.strtab.size)) != (einfo.strtab.size)) { 
        perror("writing to file on disk.");
        clean_up(fd, obj_arr, &einfo, sym_map);
        return -1;
    }
    written_bytes += n;
    free(einfo.strtab.buf);
    einfo.strtab.buf = NULL;

    // write shstrtab
    if ((n = write(fd, shstrtab, sizeof(shstrtab))) != sizeof(shstrtab)) { 
        perror("writing to file on disk.");
        clean_up(fd, obj_arr, &einfo, sym_map);
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
            clean_up(fd, obj_arr, &einfo, sym_map);
            return -1;
        }
        written_bytes += n;
    }

    //Write the section header table
    if ((n = write(fd, shdr_tab, ehdr.e_shentsize*ehdr.e_shnum)) != (ehdr.e_shentsize*ehdr.e_shnum)) { 
        perror("writing to file on disk.");
        clean_up(fd, obj_arr, &einfo, sym_map);
        return -1;
    }
    written_bytes += n;

    clean_up(fd, obj_arr, &einfo, sym_map);
    return 0;
}


// compare magic numbers 
// check system compatibility
// check that program header, section header, and elf header ecan fit
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


size_t get_padding(Elf64_Off curr_offset, size_t num_align) {
    int multiplier = (curr_offset) / num_align + 1;
    int padding_size = 0;
    if (curr_offset % num_align != 0) {
        padding_size = multiplier*num_align - curr_offset;
    }
    return padding_size;
}


// need to adjust to also free symmap
void clean_up(int fd, struct obj_info *obj, struct out_info *out, int**sym_map) {
    if (fd >= 0) {
        close(fd);
    }
    
    if (out != NULL) {
        if (out->symtab.buf != NULL) {
            free(out->symtab.buf);
            out->symtab.buf = NULL;
        }
        if (out->strtab.buf != NULL) {
            free(out->strtab.buf);
            out->strtab.buf = NULL;
        }
    }

    if (out != NULL) {
        for (int i = 0; i < out->num_obj; i++) {
            //if (obj + i != NULL) {
            if ((obj + i)->text.buf != NULL) {
                free((obj + i)->text.buf);
                (obj+i)->text.buf = NULL;
            }
            if ((obj + i)->strtab.buf != NULL) {
                free((obj + i)->strtab.buf);
                (obj+i)->strtab.buf = NULL;
            }
            if ((obj+i)->symtab.buf != NULL) {
                free((obj+i)->symtab.buf);
                (obj+i)->symtab.buf = NULL;
            }
            if ((obj+i)->rela.buf != NULL) {
                free((obj+i)->rela.buf);
                (obj+i)->rela.buf = NULL;
            }
            //}
            if (sym_map != NULL) {
                if (sym_map[i] != NULL) {
                    free(sym_map[i]);
                    sym_map[i] = NULL;
                }
            }
        }
        out = NULL;
    }
}

