#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <elf.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>

#define INVALID_FD (-1)

typedef unsigned char *ElfFile;

typedef struct menuitem {
    char *fname;
    void (*call)();
} MenuItem;

int curfd = INVALID_FD;
int debug = 0;
ElfFile elf;
off_t fsize;

void toggledebug();
void examine();
void sections();
void symbols();
void reloct();
void quit();

char *shtype(Elf32_Shdr *);

int main() {
    MenuItem menu[] = {
        {"Toggle Debug Mode", toggledebug}, {"Examine ELF File", examine}, 
        {"Print Section Names", sections}, {"Print Symbols", symbols},
        {"Relocation Tables", reloct}, {"Quit", quit}, {NULL, NULL}
    };
    while (1) {
        printf("Choose action\n");
        for (int i = 0; menu[i].fname; i++) {
            printf("%d-%s\n", i, menu[i].fname);
        }
        char buf [3];
        fgets(buf, 3, stdin);
        int c =  buf[0] - '0';
        menu[c].call();
    }
    return 0;
}

void toggledebug() {
    debug = !debug;
}

void examine() {
    printf("enter a file name: ");
    char buf[512];
    fgets(buf, 512, stdin);
    int len = strlen(buf);
    if (buf[len - 1] == '\n')
        buf[len - 1] = 0;
    if (curfd > INVALID_FD)
        close(curfd);
    curfd = open(buf, O_RDONLY, 0777);
    fsize = lseek(curfd, 0, SEEK_END);
    elf = mmap(0, fsize, PROT_READ, MAP_PRIVATE, curfd, 0);
    if (elf[EI_MAG0] != 0x7f || elf[EI_MAG1] != 'E' || elf[EI_MAG2] != 'L' || elf[EI_MAG3] != 'F') {
        printf("examine failed: %s is not ELF\n", buf);
        munmap((void *) elf, fsize);
        close(curfd);
        curfd = INVALID_FD;
        return;
    }
    Elf32_Ehdr *eh = (Elf32_Ehdr *) elf;
    char *data;
    switch (eh->e_ident[EI_DATA]) {
        case ELFDATA2LSB: 
            data = "little endian";
            break;
        case ELFDATA2MSB:
            data = "big endian";
            break;
        case ELFDATANONE:
        default:
            data = "invalid";
    }
    printf("%c%c%c\nData: %s\nEntry point: 0x%x\nSection offset: %u\nSection entries: %hu\nSection entries size: %hu\nProgram offset: %u\nProgram entries: %hu\nProgram entries size: %hu\n",
     elf[EI_MAG1], elf[EI_MAG2], elf[EI_MAG3], data, eh->e_entry, eh->e_shoff, eh->e_shnum, eh->e_shentsize, eh->e_phoff, eh->e_phnum, eh->e_phentsize);
}

void sections() {
    if (curfd <= INVALID_FD)
        return;
    Elf32_Ehdr *eh = (Elf32_Ehdr *) elf;
    Elf32_Shdr *s = (Elf32_Shdr *) (elf + (eh->e_shoff + eh->e_shentsize * eh->e_shstrndx));
    char *names = elf + s->sh_offset;
    for (int i = 0; i < eh->e_shnum; i++) {
        s = (Elf32_Shdr *) (elf + eh->e_shoff + eh->e_shentsize * i);
        printf("%d %s %x %x %s\n", i, names + s->sh_name, s->sh_offset, s->sh_size, shtype(s));
    }
}

void symbols() {
    Elf32_Ehdr *eh = (Elf32_Ehdr *) elf;
    Elf32_Shdr *symh;
    for (int i = 0; i < eh->e_shnum; i++) {
        symh = (Elf32_Shdr *) (elf + eh->e_shoff + eh->e_shentsize * i);
        if (symh->sh_type == SHT_SYMTAB)
            break;
    }
    Elf32_Sym *symt = (Elf32_Sym *) (elf + symh->sh_offset);
    //Elf32_Shdr *strt = symh + 1;
    Elf32_Shdr *strt = (Elf32_Shdr *) (elf + eh->e_shoff + eh->e_shentsize * symh->sh_link);
    char *strtn = elf + strt->sh_offset;
    Elf32_Shdr *shnt =  (Elf32_Shdr *) (elf + eh->e_shoff + eh->e_shentsize * eh->e_shstrndx);
    char *snames = elf + shnt->sh_offset;
    for (int i = 0; (void *) symt < (void *) (elf + symh->sh_offset + symh->sh_size); i++) {
        if (symt->st_shndx == SHN_ABS || symt->st_shndx == SHN_COMMON || symt->st_shndx == SHN_UNDEF) {
            printf("%02d %08x %02hu %s\n",i, symt->st_value, symt->st_shndx, strtn + symt->st_name);
        }
        else {
            Elf32_Shdr *s = (Elf32_Shdr *) (elf + eh->e_shoff + eh->e_shentsize * symt->st_shndx);
            printf("%02d %08x %02hu %s %s\n",i, symt->st_value, symt->st_shndx, snames + s->sh_name, strtn + symt->st_name);
        }
        ++symt;
    }
}

void reloct() {
    Elf32_Ehdr *eh = (Elf32_Ehdr *) elf;
    Elf32_Shdr *dynsh;
    Elf32_Shdr *shnt =  (Elf32_Shdr *) (elf + eh->e_shoff + eh->e_shentsize * eh->e_shstrndx);
    char *snames = elf + shnt->sh_offset;
    for (int i = 0; i < eh->e_shnum; i++) {
        dynsh = (Elf32_Shdr *) (elf + eh->e_shoff + eh->e_shentsize * i);
        if (dynsh->sh_type == SHT_DYNSYM)
            break;
    }
    Elf32_Shdr *dynstrh = (Elf32_Shdr *) (elf + eh->e_shoff + eh->e_shentsize * dynsh->sh_link);
    char *names = elf + dynstrh->sh_offset;
    for (int i = 0; i < eh->e_shnum; i++) {
        Elf32_Shdr *relh = (Elf32_Shdr *) (elf + eh->e_shoff + eh->e_shentsize * i);
        if (relh->sh_type != SHT_REL)
            continue;
        unsigned int dyncount = relh->sh_size / relh->sh_entsize;
        printf("Relocation section '%s' at offset 0x%x contains %u entries:\n", snames + relh->sh_name, relh->sh_offset, dyncount);
        Elf32_Rel *rel = (Elf32_Rel *) (elf + relh->sh_offset);
        for (int i = 0; i < dyncount; i++) {
            Elf32_Sym *dyns = (Elf32_Sym *) (elf + dynsh->sh_offset + ELF32_R_SYM(rel->r_info) * dynsh->sh_entsize);
            printf("%x %08x %x %x %s\n", rel->r_offset, rel->r_info, ELF32_R_TYPE(rel->r_info), dyns->st_value, names + dyns->st_name);
            ++rel;
        }
    }
}

void quit() {
    if (debug)
        fprintf(stderr, "quitting\n");
    if (curfd > INVALID_FD) {
        munmap((void *) elf, fsize);
        close(curfd);
    }
    exit(0);
}

char *shtype(Elf32_Shdr *s) {
    static char *stype; 
    switch (s->sh_type) {
        case SHT_NULL:
            stype = "inactive";
            break;
        case SHT_PROGBITS:
            stype = "program";
            break;
        case SHT_SYMTAB:
            stype = "symtab";
            break;
        case SHT_STRTAB:
            stype = "string table";
            break;
        case SHT_RELA:
            stype = "relocation addends";
            break;
        case SHT_HASH:
            stype = "hash";
            break;
        case SHT_DYNAMIC:
            stype = "dynamic";
            break;
        case SHT_NOTE:
            stype = "note";
            break;
        case SHT_NOBITS:
            stype = "nobits";
            break;
        case SHT_REL:
            stype = "relocation";
            break;
        case SHT_SHLIB:
            stype = "lib";
            break;
        case SHT_DYNSYM:
            stype = "dynsym";
            break;
        case SHT_LOPROC:
            stype = "loproc";
            break;
        case SHT_HIPROC:
            stype = "hiproc";
            break;
        case SHT_LOUSER:
            stype = "louser";
            break;
        case SHT_HIUSER:
            stype = "hiuser";
            break;
        default:
            stype = "unknown type";
    }
    return stype;
}
