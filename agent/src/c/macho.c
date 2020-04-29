#define MH_MAGIC 0xfeedface
#define MH_CIGAM 0xcefaedfe
#define MH_MAGIC_64 0xfeedfacf
#define MH_CIGAM_64 0xcffaedfe

#define LC_ENCRYPTION_INFO 0x21
#define LC_ENCRYPTION_INFO_64 0x2C
#ifndef NULL
#define NULL 0
#endif

#define LC_SEGMENT 0x1
#define LC_SEGMENT_64 0x19

#define MH_PIE 0x200000
#define MH_NO_HEAP_EXECUTION 0x1000000

typedef unsigned int uint32_t;
typedef unsigned long long uint64_t;
typedef int integer_t;
typedef unsigned long uintptr_t;

typedef long long __int64_t;
typedef __int64_t __darwin_off_t;
typedef __darwin_off_t off_t;

typedef integer_t cpu_type_t;
typedef integer_t cpu_subtype_t;
typedef int vm_prot_t;

struct mach_header {
  uint32_t magic;
  cpu_type_t cputype;
  cpu_subtype_t cpusubtype;
  uint32_t filetype;
  uint32_t ncmds;
  uint32_t sizeofcmds;
  uint32_t flags;
};

struct mach_header_64 {
  uint32_t magic;
  cpu_type_t cputype;
  cpu_subtype_t cpusubtype;
  uint32_t filetype;
  uint32_t ncmds;
  uint32_t sizeofcmds;
  uint32_t flags;
  uint32_t reserved;
};

struct load_command {
  uint32_t cmd;
  uint32_t cmdsize;
};

struct encryption_info_command {
  uint32_t cmd;
  uint32_t cmdsize;
  uint32_t cryptoff;
  uint32_t cryptsize;
  uint32_t cryptid;
};

struct encryption_info_command_64 {
  uint32_t cmd;
  uint32_t cmdsize;
  uint32_t cryptoff;
  uint32_t cryptsize;
  uint32_t cryptid;
  uint32_t pad;
};

struct segment_command {
  unsigned long cmd;      /* LC_SEGMENT */
  unsigned long cmdsize;  /* includes sizeof section structs */
  char segname[16];       /* segment name */
  unsigned long vmaddr;   /* memory address of this segment */
  unsigned long vmsize;   /* memory size of this segment */
  unsigned long fileoff;  /* file offset of this segment */
  unsigned long filesize; /* amount to map from the file */
  vm_prot_t maxprot;      /* maximum VM protection */
  vm_prot_t initprot;     /* initial VM protection */
  unsigned long nsects;   /* number of sections in segment */
  unsigned long flags;    /* flags */
};

struct segment_command_64 { /* for 64-bit architectures */
  uint32_t cmd;             /* LC_SEGMENT_64 */
  uint32_t cmdsize;         /* includes sizeof section_64 structs */
  char segname[16];         /* segment name */
  uint64_t vmaddr;          /* memory address of this segment */
  uint64_t vmsize;          /* memory size of this segment */
  uint64_t fileoff;         /* file offset of this segment */
  uint64_t filesize;        /* amount to map from the file */
  vm_prot_t maxprot;        /* maximum VM protection */
  vm_prot_t initprot;       /* initial VM protection */
  uint32_t nsects;          /* number of sections in segment */
  uint32_t flags;           /* flags */
};

struct section {           /* for 32-bit architectures */
  char sectname[16];       /* name of this section */
  char segname[16];        /* segment this section goes in */
  unsigned long addr;      /* memory address of this section */
  unsigned long size;      /* size in bytes of this section */
  unsigned long offset;    /* file offset of this section */
  unsigned long align;     /* section alignment (power of 2) */
  unsigned long reloff;    /* file offset of relocation entries */
  unsigned long nreloc;    /* number of relocation entries */
  unsigned long flags;     /* flags (section type and attributes)*/
  unsigned long reserved1; /* reserved */
  unsigned long reserved2; /* reserved */
};

struct section_64 {   /* for 64-bit architectures */
  char sectname[16];  /* name of this section */
  char segname[16];   /* segment this section goes in */
  uint64_t addr;      /* memory address of this section */
  uint64_t size;      /* size in bytes of this section */
  uint32_t offset;    /* file offset of this section */
  uint32_t align;     /* section alignment (power of 2) */
  uint32_t reloff;    /* file offset of relocation entries */
  uint32_t nreloc;    /* number of relocation entries */
  uint32_t flags;     /* flags (section type and attributes)*/
  uint32_t reserved1; /* reserved (for offset or index) */
  uint32_t reserved2; /* reserved (for count or sizeof) */
  uint32_t reserved3; /* reserved */
};

#ifdef __LP64__
typedef struct mach_header_64 mach_header_t;
typedef struct segment_command_64 segment_command_t;
typedef struct section_64 section_t;
typedef struct nlist_64 nlist_t;
#define LC_SEGMENT_ARCH_DEPENDENT LC_SEGMENT_64
#else
typedef struct mach_header mach_header_t;
typedef struct segment_command segment_command_t;
typedef struct section section_t;
typedef struct nlist nlist_t;
#define LC_SEGMENT_ARCH_DEPENDENT LC_SEGMENT
#endif

#ifndef SEG_DATA_CONST
#define SEG_DATA_CONST "__DATA_CONST"
#endif
#ifndef SEG_TEXT
#define SEG_TEXT "__TEXT"
#endif

#define SEG_LINKEDIT "__LINKEDIT"

typedef unsigned int uint;

#define FOR_EACH_SEGMENT(MH, ...)                                              \
  {                                                                            \
    segment_command_t *seg;                                                    \
    uintptr_t cur = (uintptr_t)MH + sizeof(mach_header_t);                     \
    for (uint i = 0; i < MH->ncmds; i++, cur += seg->cmdsize) {                \
      seg = (segment_command_t *)cur;                                          \
      __VA_ARGS__                                                              \
    }                                                                          \
  }

struct result {
  void *ptr;
  uint32_t offset;
  uint32_t size;

  uint32_t offset_id;
  uint32_t size_id;
};

struct result find_encryption_info(struct mach_header *);
int pie(struct mach_header *);

int strcmp(const char *, const char *);
int issection(section_t *, const char *);

struct result find_encryption_info(struct mach_header *mh) {
  struct load_command *lc;
  struct encryption_info_command *eic;
  int i = 0;
  struct result ret = {0};

  if (mh->magic == MH_MAGIC_64 || mh->magic == MH_CIGAM_64) {
    lc = (struct load_command *)((unsigned char *)mh +
                                 sizeof(struct mach_header_64));
  } else {
    lc = (struct load_command *)((unsigned char *)mh +
                                 sizeof(struct mach_header));
  }

  for (i = 0; i < mh->ncmds; i++) {
    if (lc->cmd == LC_ENCRYPTION_INFO || lc->cmd == LC_ENCRYPTION_INFO_64) {
      eic = (struct encryption_info_command *)lc;
      if (!eic->cryptid)
        break;

      ret.ptr = eic;
      ret.offset = eic->cryptoff;
      ret.size = eic->cryptsize;
      ret.offset_id = (uint32_t)((void *)&eic->cryptid - (void *)mh);
      ret.size_id = sizeof(eic->cryptid);
      return ret;
    }

    lc = (struct load_command *)((unsigned char *)lc + lc->cmdsize);
  }

  return ret;
}

int pie(struct mach_header *mh) { return mh->flags & MH_PIE; }

void sections(struct mach_header *mh,
              void (*yield)(const char *, uintptr_t, uintptr_t)) {
#ifdef __LP64__
#define INVALID_MAGIC(mh) mh->magic != MH_MAGIC_64 && mh->magic != MH_CIGAM_64
#else
#define INVALID_MAGIC(mh) mh->magic != MH_MAGIC && mh->magic != MH_CIGAM
#endif

  if (INVALID_MAGIC(mh))
    return;
  uintptr_t slide = 0;
  FOR_EACH_SEGMENT(mh, {
    if (seg->cmd == LC_SEGMENT_ARCH_DEPENDENT &&
        strcmp(seg->segname, SEG_TEXT)) {
      slide = (uintptr_t)mh - (seg->vmaddr - seg->fileoff);
    }
  })

  FOR_EACH_SEGMENT(mh, {
    if (seg->cmd == LC_SEGMENT_ARCH_DEPENDENT) {
      for (uint j = 0; j < seg->nsects; j++) {
        section_t *sect = (section_t *)(cur + sizeof(segment_command_t)) + j;
        uintptr_t p = sect->addr + slide;
        yield(sect->sectname, p, sect->size);

        // printf(">> %s 0x%lx %llx\n", sect->sectname, p, sect->size);
        // if (issection(sect, "__cfstring")) {
        //   // printf("sample: %s\n", (const char *)(*(uintptr_t*)(p + 0x10)));
        // } else if (issection(sect, "__objc_selrefs")) {
        //   // printf("sample: %s\n", *(const char**)p);
        // } else if (issection(sect, "__cstring")) {
        //   // printf("sample: %s\n", (const char *)p);
        // } else if (issection(sect, "__objc_methtype")) {
        //   // printf("sample: %s\n", (const char *)p);
        // } else if (issection(sect, "__objc_classrefs")) {

        // } else if (issection(sect, "__ustring")) {
        //   // p
        // }
      }
    }
  })

  return;
}

int issection(section_t *sec, const char *name) {
  int i = 0;
  const char *s1 = sec->sectname;
  const char *s2 = name;
  while (*s1 && (*s1 == *s2)) {
    s1++;
    s2++;
    if (++i >= sizeof(sec->sectname) - 1)
      break;
  }
  return *(const unsigned char *)s1 - *(const unsigned char *)s2 == 0;
}

int strcmp(const char *s1, const char *s2) {
  while (*s1 && (*s1 == *s2)) {
    s1++;
    s2++;
  }
  return *(const unsigned char *)s1 - *(const unsigned char *)s2;
}
