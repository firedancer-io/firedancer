#define _GNU_SOURCE
#include "fd_backtrace.h"
#include "../fd_util_base.h"

#if FD_HAS_BACKTRACE

#include "../log/fd_log.h"

#include <unistd.h>
#include <string.h>
#include <dlfcn.h>
#include <link.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <elf.h>

/* Maximum number of frames to collect */

#define FD_BACKTRACE_MAX_FRAMES 128

/* Maximum number of cached ELF files */

#define FD_BACKTRACE_MAX_ELFS   16

/* DWARF line number program opcodes */

#define DW_LNS_copy               1
#define DW_LNS_advance_pc         2
#define DW_LNS_advance_line       3
#define DW_LNS_set_file           4
#define DW_LNS_set_column         5
#define DW_LNS_negate_stmt        6
#define DW_LNS_set_basic_block    7
#define DW_LNS_const_add_pc       8
#define DW_LNS_fixed_advance_pc   9
#define DW_LNS_set_prologue_end  10
#define DW_LNS_set_epilogue_begin 11
#define DW_LNS_set_isa           12

#define DW_LNE_end_sequence       1
#define DW_LNE_set_address        2
#define DW_LNE_define_file        3
#define DW_LNE_set_discriminator  4

#define DW_LNCT_path              0x1
#define DW_LNCT_directory_index   0x2

#define DW_FORM_string            0x08
#define DW_FORM_data1             0x0b
#define DW_FORM_data2             0x05
#define DW_FORM_udata             0x0f
#define DW_FORM_line_strp         0x1f

/* Cached mapped ELF file.  Keyed by base_addr which is the link_map
   l_addr (same as dl_phdr_info.dlpi_addr).  This allows signal-safe
   lookup without any syscalls. */

struct fd_backtrace_elf {
  ulong         base_addr;       /* link_map l_addr for this object */
  uchar const * map;
  ulong         map_sz;
  uchar const * debug_line;      /* Pointer into mapped region */
  ulong         debug_line_sz;
  uchar const * debug_line_str;  /* .debug_line_str section (DWARF5) */
  ulong         debug_line_str_sz;
};

typedef struct fd_backtrace_elf fd_backtrace_elf_t;

static fd_backtrace_elf_t fd_backtrace_elf_cache[ FD_BACKTRACE_MAX_ELFS ];
static ulong              fd_backtrace_elf_cnt;

/* DWARF line info result */

struct fd_backtrace_line_info {
  char const * file;
  uint         line;
  uint         col;
};

typedef struct fd_backtrace_line_info fd_backtrace_line_info_t;

/* Read a ULEB128-encoded value from p, advancing p.
   Returns 0 on bounds error. */

static ulong
fd_backtrace_read_uleb128( uchar const ** p,
                           uchar const *  end ) {
  ulong result = 0;
  uint  shift  = 0;
  while( *p<end ) {
    uchar b = *(*p)++;
    result |= (ulong)( b & 0x7f ) << shift;
    if( !(b & 0x80) ) return result;
    shift += 7;
    if( FD_UNLIKELY( shift>=64 ) ) return result;
  }
  return result;
}

/* Read a SLEB128-encoded value from p, advancing p. */

static long
fd_backtrace_read_sleb128( uchar const ** p,
                           uchar const *  end ) {
  long  result = 0;
  uint  shift  = 0;
  uchar b;
  do {
    if( FD_UNLIKELY( *p>=end ) ) return result;
    b = *(*p)++;
    result |= (long)( b & 0x7f ) << shift;
    shift  += 7;
  } while( b & 0x80 );
  if( shift<64 && (b & 0x40) ) {
    result |= -(1L << shift);
  }
  return result;
}

/* Find a cached ELF by its link_map base address.  This is
   async-signal-safe: no syscalls, just a linear scan of the cache.
   Returns NULL if the ELF was not pre-loaded. */

static fd_backtrace_elf_t *
fd_backtrace_elf_find( ulong base_addr ) {
  for( ulong i=0; i<fd_backtrace_elf_cnt; i++ ) {
    if( fd_backtrace_elf_cache[i].base_addr==base_addr ) {
      return &fd_backtrace_elf_cache[i];
    }
  }
  return NULL;
}

/* Open, mmap, and parse an ELF file, caching the result keyed by
   base_addr.  NOT async-signal-safe — must be called before
   sandboxing.  Returns NULL if the file can't be opened or parsed. */

static fd_backtrace_elf_t *
fd_backtrace_elf_open( char const * path,
                       ulong        base_addr ) {
  /* Check cache first */
  fd_backtrace_elf_t * cached = fd_backtrace_elf_find( base_addr );
  if( cached ) return cached;

  if( FD_UNLIKELY( fd_backtrace_elf_cnt>=FD_BACKTRACE_MAX_ELFS ) ) return NULL;

  struct stat st;
  if( FD_UNLIKELY( stat( path, &st )<0 ) ) return NULL;

  int fd = open( path, O_RDONLY );
  if( FD_UNLIKELY( fd<0 ) ) return NULL;

  ulong file_sz = (ulong)st.st_size;
  if( FD_UNLIKELY( file_sz<sizeof(Elf64_Ehdr) ) ) { close( fd ); return NULL; }

  uchar const * map = (uchar const *)mmap( NULL, file_sz, PROT_READ, MAP_PRIVATE, fd, 0 );
  close( fd );
  if( FD_UNLIKELY( map==MAP_FAILED ) ) return NULL;

  /* Parse ELF header */
  Elf64_Ehdr const * ehdr = (Elf64_Ehdr const *)map;
  if( FD_UNLIKELY( memcmp( ehdr->e_ident, ELFMAG, SELFMAG )!=0 ) ) { munmap( (void *)map, file_sz ); return NULL; }
  if( FD_UNLIKELY( ehdr->e_ident[EI_CLASS]!=ELFCLASS64          ) ) { munmap( (void *)map, file_sz ); return NULL; }

  /* Find section header string table */
  if( FD_UNLIKELY( ehdr->e_shoff==0 || ehdr->e_shstrndx==SHN_UNDEF ) ) { munmap( (void *)map, file_sz ); return NULL; }
  if( FD_UNLIKELY( ehdr->e_shoff + (ulong)ehdr->e_shnum * ehdr->e_shentsize > file_sz ) ) { munmap( (void *)map, file_sz ); return NULL; }

  Elf64_Shdr const * shdrs  = (Elf64_Shdr const *)( map + ehdr->e_shoff );
  Elf64_Shdr const * shstrt = &shdrs[ ehdr->e_shstrndx ];

  if( FD_UNLIKELY( shstrt->sh_offset + shstrt->sh_size > file_sz ) ) { munmap( (void *)map, file_sz ); return NULL; }
  char const * shstrtab = (char const *)( map + shstrt->sh_offset );

  /* Find .debug_line and .debug_line_str sections */
  uchar const * debug_line     = NULL;
  ulong         debug_line_sz  = 0;
  uchar const * debug_line_str    = NULL;
  ulong         debug_line_str_sz = 0;

  for( uint i=0; i<ehdr->e_shnum; i++ ) {
    if( FD_UNLIKELY( shdrs[i].sh_name >= shstrt->sh_size ) ) continue;
    char const * name = shstrtab + shdrs[i].sh_name;
    if( FD_UNLIKELY( shdrs[i].sh_offset + shdrs[i].sh_size > file_sz ) ) continue;

    if( !strcmp( name, ".debug_line" ) ) {
      debug_line    = map + shdrs[i].sh_offset;
      debug_line_sz = shdrs[i].sh_size;
    } else if( !strcmp( name, ".debug_line_str" ) ) {
      debug_line_str    = map + shdrs[i].sh_offset;
      debug_line_str_sz = shdrs[i].sh_size;
    }
  }

  /* Cache the result even if no debug_line (so we don't retry) */
  fd_backtrace_elf_t * elf = &fd_backtrace_elf_cache[ fd_backtrace_elf_cnt++ ];
  elf->base_addr        = base_addr;
  elf->map              = map;
  elf->map_sz           = file_sz;
  elf->debug_line       = debug_line;
  elf->debug_line_sz    = debug_line_sz;
  elf->debug_line_str    = debug_line_str;
  elf->debug_line_str_sz = debug_line_str_sz;
  return elf;
}

/* Parse a DWARF4 file name table entry: null-terminated string
   followed by 3 ULEB128 values (directory index, time, size).
   Returns the string or NULL if at end of table. */

static char const *
fd_backtrace_dwarf4_read_file_entry( uchar const ** p,
                                     uchar const *  end ) {
  if( FD_UNLIKELY( *p>=end ) ) return NULL;
  if( **p==0 ) { (*p)++; return NULL; } /* End of list */
  char const * name = (char const *)*p;
  while( *p<end && **p ) (*p)++;
  if( *p<end ) (*p)++; /* Skip null terminator */
  fd_backtrace_read_uleb128( p, end ); /* dir index */
  fd_backtrace_read_uleb128( p, end ); /* time */
  fd_backtrace_read_uleb128( p, end ); /* size */
  return name;
}

/* Resolve an address to file:line:col using DWARF .debug_line.
   addr is relative to the ELF load base (i.e., file offset for
   position-independent code). */

static int
fd_backtrace_resolve_dwarf( fd_backtrace_elf_t *      elf,
                            ulong                     addr,
                            fd_backtrace_line_info_t * out ) {
  if( FD_UNLIKELY( !elf->debug_line ) ) return 0;

  uchar const * section     = elf->debug_line;
  uchar const * section_end = section + elf->debug_line_sz;

  /* Iterate over compilation units in .debug_line */
  while( section < section_end ) {
    uchar const * cu_start = section;

    /* Read unit_length (4 or 12 bytes) */
    if( FD_UNLIKELY( section+4 > section_end ) ) return 0;
    ulong unit_length = *(uint const *)section;
    section += 4;
    int dwarf64 = 0;
    if( FD_UNLIKELY( unit_length==0xFFFFFFFF ) ) {
      if( FD_UNLIKELY( section+8 > section_end ) ) return 0;
      unit_length = *(ulong const *)section;
      section += 8;
      dwarf64 = 1;
    }
    (void)cu_start;

    uchar const * cu_end = section + unit_length;
    if( FD_UNLIKELY( cu_end > section_end ) ) return 0;

    /* Read version */
    if( FD_UNLIKELY( section+2 > cu_end ) ) { section = cu_end; continue; }
    ushort version = *(ushort const *)section;
    section += 2;

    if( FD_UNLIKELY( version<2 || version>5 ) ) { section = cu_end; continue; }

    /* DWARF5 has address_size and segment_selector_size before header_length */
    uchar address_size = 8; /* Default for x86_64 */
    if( version>=5 ) {
      if( FD_UNLIKELY( section+2 > cu_end ) ) { section = cu_end; continue; }
      address_size = *section++;
      section++; /* segment_selector_size */
    }
    (void)address_size;

    /* Read header_length */
    ulong header_length;
    if( dwarf64 ) {
      if( FD_UNLIKELY( section+8 > cu_end ) ) { section = cu_end; continue; }
      header_length = *(ulong const *)section;
      section += 8;
    } else {
      if( FD_UNLIKELY( section+4 > cu_end ) ) { section = cu_end; continue; }
      header_length = *(uint const *)section;
      section += 4;
    }

    uchar const * header_start     = section;
    uchar const * program_start    = header_start + header_length;
    if( FD_UNLIKELY( program_start > cu_end ) ) { section = cu_end; continue; }

    /* Read header fields */
    if( FD_UNLIKELY( section+4 > program_start ) ) { section = cu_end; continue; }
    uchar minimum_instruction_length = *section++;
    uchar maximum_ops_per_insn       = *section++;
    if( version<4 ) { maximum_ops_per_insn = 1; section--; } /* DWARF3 lacks max_ops_per_insn */
    section++; /* default_is_stmt */
    schar line_base  = (schar)*section++;
    uchar line_range = *section++;
    uchar opcode_base = *section++;

    /* Skip standard opcode lengths */
    if( FD_UNLIKELY( section + opcode_base - 1 > program_start ) ) { section = cu_end; continue; }
    uchar const * std_opcode_lens = section;
    section += (opcode_base - 1);

    /* File name table - differs between DWARF4 and DWARF5 */
    #define FD_BACKTRACE_MAX_DIRS  256
    #define FD_BACKTRACE_MAX_FILES 1024

    char const * dirs[ FD_BACKTRACE_MAX_DIRS ];
    ulong        dir_cnt  = 0;
    (void)dirs;
    char const * files[ FD_BACKTRACE_MAX_FILES ];
    ulong        file_cnt = 0;

    if( version>=5 ) {
      /* DWARF5: directory_entry_format_count, then pairs, then directories */
      if( FD_UNLIKELY( section >= program_start ) ) { section = cu_end; continue; }
      uchar dir_format_count = *section++;
      /* Read format pairs (content_type, form) */
      uint dir_forms[16][2];
      for( uchar i=0; i<dir_format_count && i<16; i++ ) {
        dir_forms[i][0] = (uint)fd_backtrace_read_uleb128( &section, program_start );
        dir_forms[i][1] = (uint)fd_backtrace_read_uleb128( &section, program_start );
      }
      ulong dir_count = fd_backtrace_read_uleb128( &section, program_start );
      for( ulong i=0; i<dir_count; i++ ) {
        char const * dir_name = NULL;
        for( uchar f=0; f<dir_format_count && f<16; f++ ) {
          if( dir_forms[f][0]==DW_LNCT_path ) {
            if( dir_forms[f][1]==DW_FORM_string ) {
              dir_name = (char const *)section;
              while( section<program_start && *section ) section++;
              if( section<program_start ) section++;
            } else if( dir_forms[f][1]==DW_FORM_line_strp ) {
              ulong off;
              if( dwarf64 ) { off = *(ulong const *)section; section += 8; }
              else          { off = *(uint const *)section;  section += 4; }
              if( elf->debug_line_str && off<elf->debug_line_str_sz ) {
                dir_name = (char const *)( elf->debug_line_str + off );
              }
            } else {
              /* Unknown form, skip this CU */
              goto next_cu;
            }
          } else {
            /* Skip unknown content type based on form */
            if( dir_forms[f][1]==DW_FORM_data1 )       { section += 1; }
            else if( dir_forms[f][1]==DW_FORM_data2 )   { section += 2; }
            else if( dir_forms[f][1]==DW_FORM_udata )   { fd_backtrace_read_uleb128( &section, program_start ); }
            else if( dir_forms[f][1]==DW_FORM_string )  { while( section<program_start && *section ) section++; if( section<program_start ) section++; }
            else if( dir_forms[f][1]==DW_FORM_line_strp ) { section += dwarf64 ? 8 : 4; }
            else goto next_cu;
          }
        }
        if( dir_name && dir_cnt<FD_BACKTRACE_MAX_DIRS ) dirs[ dir_cnt++ ] = dir_name;
      }

      /* File entry format */
      if( FD_UNLIKELY( section >= program_start ) ) { section = cu_end; continue; }
      uchar file_format_count = *section++;
      uint file_forms[16][2];
      for( uchar i=0; i<file_format_count && i<16; i++ ) {
        file_forms[i][0] = (uint)fd_backtrace_read_uleb128( &section, program_start );
        file_forms[i][1] = (uint)fd_backtrace_read_uleb128( &section, program_start );
      }
      ulong fcount = fd_backtrace_read_uleb128( &section, program_start );
      for( ulong i=0; i<fcount; i++ ) {
        char const * file_name = NULL;
        for( uchar f=0; f<file_format_count && f<16; f++ ) {
          if( file_forms[f][0]==DW_LNCT_path ) {
            if( file_forms[f][1]==DW_FORM_string ) {
              file_name = (char const *)section;
              while( section<program_start && *section ) section++;
              if( section<program_start ) section++;
            } else if( file_forms[f][1]==DW_FORM_line_strp ) {
              ulong off;
              if( dwarf64 ) { off = *(ulong const *)section; section += 8; }
              else          { off = *(uint const *)section;  section += 4; }
              if( elf->debug_line_str && off<elf->debug_line_str_sz ) {
                file_name = (char const *)( elf->debug_line_str + off );
              }
            } else {
              goto next_cu;
            }
          } else {
            if( file_forms[f][1]==DW_FORM_data1 )       { section += 1; }
            else if( file_forms[f][1]==DW_FORM_data2 )   { section += 2; }
            else if( file_forms[f][1]==DW_FORM_udata )   { fd_backtrace_read_uleb128( &section, program_start ); }
            else if( file_forms[f][1]==DW_FORM_string )  { while( section<program_start && *section ) section++; if( section<program_start ) section++; }
            else if( file_forms[f][1]==DW_FORM_line_strp ) { section += dwarf64 ? 8 : 4; }
            else goto next_cu;
          }
        }
        if( file_name && file_cnt<FD_BACKTRACE_MAX_FILES ) files[ file_cnt++ ] = file_name;
      }
    } else {
      /* DWARF4: include directories as null-terminated strings,
         then file names as null-terminated strings + 3 ULEBs */
      while( section<program_start && *section ) {
        if( dir_cnt<FD_BACKTRACE_MAX_DIRS ) dirs[ dir_cnt++ ] = (char const *)section;
        while( section<program_start && *section ) section++;
        if( section<program_start ) section++;
      }
      if( section<program_start ) section++; /* Skip terminating 0 */

      /* File 0 in DWARF4 is the compilation directory, file indices
         are 1-based.  We store a placeholder at index 0. */
      files[0] = "<unknown>";
      file_cnt = 1;
      for(;;) {
        char const * name = fd_backtrace_dwarf4_read_file_entry( &section, program_start );
        if( !name ) break;
        if( file_cnt<FD_BACKTRACE_MAX_FILES ) files[ file_cnt++ ] = name;
      }
    }

    /* Execute the line number program */
    section = program_start;

    /* State machine registers */
    ulong sm_addr   = 0;
    uint  sm_file   = 1;
    uint  sm_line   = 1;
    uint  sm_col    = 0;
    int   sm_end    = 0;

    /* Best match tracking */
    int   found       = 0;
    ulong best_addr   = 0;
    uint  best_file   = 0;
    uint  best_line   = 0;
    uint  best_col    = 0;

    while( section < cu_end ) {
      uchar op = *section++;

      if( op>=opcode_base ) {
        /* Special opcode */
        uint adjusted = (uint)op - (uint)opcode_base;
        uint addr_inc = adjusted / (uint)line_range;
        int  line_inc = (int)line_base + (int)( adjusted % (uint)line_range );
        sm_addr += (ulong)addr_inc * (ulong)minimum_instruction_length;
        sm_line  = (uint)( (int)sm_line + line_inc );
        /* Check if this is a better match */
        if( sm_addr<=addr && ( !found || sm_addr>best_addr ) ) {
          found     = 1;
          best_addr = sm_addr;
          best_file = sm_file;
          best_line = sm_line;
          best_col  = sm_col;
        }
      } else if( op==0 ) {
        /* Extended opcode */
        if( FD_UNLIKELY( section >= cu_end ) ) break;
        ulong ext_len = fd_backtrace_read_uleb128( &section, cu_end );
        uchar const * ext_end = section + ext_len;
        if( FD_UNLIKELY( ext_end > cu_end || section >= cu_end ) ) break;
        uchar ext_op = *section++;
        switch( ext_op ) {
        case DW_LNE_end_sequence:
          /* If addr falls in [best_addr, sm_addr) this CU covers it */
          if( found && addr<sm_addr ) {
            /* We have our answer */
            if( best_file<file_cnt ) out->file = files[ best_file ];
            else                     out->file = "<unknown>";
            out->line = best_line;
            out->col  = best_col;
            return 1;
          }
          /* Reset */
          sm_addr = 0;
          sm_file = 1;
          sm_line = 1;
          sm_col  = 0;
          sm_end  = 0;
          found   = 0;
          best_addr = 0;
          break;
        case DW_LNE_set_address:
          sm_addr = *(ulong const *)section;
          break;
        case DW_LNE_define_file:
          /* Inline file definition - skip for now */
          break;
        case DW_LNE_set_discriminator:
          /* Ignore discriminator */
          break;
        default:
          break;
        }
        section = ext_end;
      } else {
        /* Standard opcode */
        switch( op ) {
        case DW_LNS_copy:
          if( sm_addr<=addr && ( !found || sm_addr>best_addr ) ) {
            found     = 1;
            best_addr = sm_addr;
            best_file = sm_file;
            best_line = sm_line;
            best_col  = sm_col;
          }
          break;
        case DW_LNS_advance_pc:
          sm_addr += fd_backtrace_read_uleb128( &section, cu_end ) * (ulong)minimum_instruction_length;
          break;
        case DW_LNS_advance_line:
          sm_line = (uint)( (int)sm_line + (int)fd_backtrace_read_sleb128( &section, cu_end ) );
          break;
        case DW_LNS_set_file:
          sm_file = (uint)fd_backtrace_read_uleb128( &section, cu_end );
          break;
        case DW_LNS_set_column:
          sm_col = (uint)fd_backtrace_read_uleb128( &section, cu_end );
          break;
        case DW_LNS_negate_stmt:
          break;
        case DW_LNS_set_basic_block:
          break;
        case DW_LNS_const_add_pc: {
          uint adjusted = 255U - (uint)opcode_base;
          sm_addr += (ulong)( adjusted / (uint)line_range ) * (ulong)minimum_instruction_length;
          break;
        }
        case DW_LNS_fixed_advance_pc:
          if( FD_UNLIKELY( section+2 > cu_end ) ) { section = cu_end; break; }
          sm_addr += *(ushort const *)section;
          section += 2;
          break;
        case DW_LNS_set_prologue_end:
        case DW_LNS_set_epilogue_begin:
        case DW_LNS_set_isa:
        default:
          /* Skip operands for unknown/unhandled standard opcodes */
          if( op>=1 && op<opcode_base ) {
            uchar nargs = std_opcode_lens[ op - 1 ];
            for( uchar a=0; a<nargs; a++ ) {
              fd_backtrace_read_uleb128( &section, cu_end );
            }
          }
          break;
        }
      }
    }

    /* If we exited without end_sequence and have a match, return it */
    if( found ) {
      if( best_file<file_cnt ) out->file = files[ best_file ];
      else                     out->file = "<unknown>";
      out->line = best_line;
      out->col  = best_col;
      return 1;
    }

next_cu:
    (void)sm_end;
    (void)maximum_ops_per_insn;
    section = cu_end;
  }

  return 0;
}

/* dl_iterate_phdr callback for fd_backtrace_elf_preload. */

static int
fd_backtrace_elf_preload_cb( struct dl_phdr_info * info,
                              ulong                 size,
                              void *                data ) {
  (void)size; (void)data;

  char const * path = info->dlpi_name;

  /* For the main executable, dlpi_name is typically empty. */
  if( !path || !path[0] ) path = "/proc/self/exe";

  fd_backtrace_elf_open( path, (ulong)info->dlpi_addr );
  return 0;
}

void
fd_backtrace_init( void ) {
  /* Prime dladdr so the dynamic linker loads libgcc/libdl if needed.
     This avoids async-signal-unsafe dynamic linking in the signal
     handler.  We use __builtin_return_address to get a valid code
     pointer without a function-to-object-pointer cast. */
  Dl_info info;
  dladdr( __builtin_return_address( 0 ), &info );
}

void
fd_backtrace_elf_preload( void ) {
  dl_iterate_phdr( (int (*)(struct dl_phdr_info *, size_t, void *))fd_backtrace_elf_preload_cb, NULL );
}

void
fd_backtrace_log( int fd ) {
  /* Collect frames via frame-pointer walking */
  void * frames[ FD_BACKTRACE_MAX_FRAMES ];
  ulong  frame_cnt = 0;

  ulong * fp = (ulong *)__builtin_frame_address( 0 );

  while( fp && frame_cnt<FD_BACKTRACE_MAX_FRAMES ) {
    /* Validate frame pointer: must be 8-byte aligned and non-null */
    if( FD_UNLIKELY( (ulong)fp & 0x7UL ) ) break;

    /* The return address is at fp[1] */
    void * ret_addr = (void *)fp[1];
    if( FD_UNLIKELY( !ret_addr ) ) break;

    frames[ frame_cnt++ ] = ret_addr;

    /* Walk to the next frame */
    ulong * next_fp = (ulong *)fp[0];

    /* Basic sanity: next frame pointer should be higher on the stack
       (stack grows downward on x86_64) and non-null */
    if( FD_UNLIKELY( !next_fp || next_fp<=fp ) ) break;
    fp = next_fp;
  }

  /* Resolve and print each frame */
  for( ulong i=0; i<frame_cnt; i++ ) {
    void * addr = frames[ i ];
    Dl_info info;

    void * _map = NULL;
    if( FD_LIKELY( dladdr1( addr, &info, &_map, RTLD_DL_LINKMAP ) && info.dli_fname && info.dli_fname[0]!='\0' ) ) {
      struct link_map * map = _map;
      info.dli_fbase = (void *)map->l_addr;
      if( FD_UNLIKELY( !info.dli_sname ) ) info.dli_saddr = info.dli_fbase;

      char   sign;
      long   offset;
      if( addr>=info.dli_saddr ) { sign = '+'; offset = (long)( (ulong)addr - (ulong)info.dli_saddr ); }
      else                       { sign = '-'; offset = (long)( (ulong)info.dli_saddr - (ulong)addr ); }

      /* Try DWARF resolution from pre-loaded cache (no syscalls) */
      fd_backtrace_line_info_t line_info;
      int have_line = 0;

      ulong rel_addr = (ulong)addr - map->l_addr;
      fd_backtrace_elf_t * elf = fd_backtrace_elf_find( map->l_addr );
      if( elf ) {
        have_line = fd_backtrace_resolve_dwarf( elf, rel_addr, &line_info );
      }

      if( have_line ) {
        fd_log_private_fprintf_0( fd, "%s:%u:%u: %s(%s%c%#lx) [%p]\n",
                                  line_info.file, line_info.line, line_info.col,
                                  info.dli_fname,
                                  info.dli_sname ? info.dli_sname : "",
                                  sign, (ulong)offset, addr );
      } else if( FD_UNLIKELY( !info.dli_sname && !info.dli_saddr ) ) {
        fd_log_private_fprintf_0( fd, "%s(%s) [%p]\n",
                                  info.dli_fname ? info.dli_fname : "",
                                  info.dli_sname ? info.dli_sname : "",
                                  addr );
      } else {
        fd_log_private_fprintf_0( fd, "%s(%s%c%#lx) [%p]\n",
                                  info.dli_fname ? info.dli_fname : "",
                                  info.dli_sname ? info.dli_sname : "",
                                  sign, (ulong)offset, addr );
      }
    } else {
      fd_log_private_fprintf_0( fd, "%p\n", addr );
    }
  }
}

#endif /* FD_HAS_BACKTRACE */
