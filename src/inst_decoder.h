#ifndef _INST_DECODER_H_
#define _INST_DECODER_H_

#include <stdlib.h>
#include <stdint.h>
#include <pthread.h>
#include <math.h>

#include "x64_cpu.h"
#include "string_struct.h"
#include "io.h"

#define ABS(x) ((x) < 0) ? -(x) : (x)
#define MIN(x, y) ((x) < (y)) ? (x) : (y)

#define PI 3.14159265358979323846L

#define SET_FLAG(flag)   cpu.rflags |= flag
#define CLEAR_FLAG(flag) cpu.rflags &= ~(flag)
#define UPDATE_FLAG(expr, flag) if( expr ) { SET_FLAG(flag); } else { CLEAR_FLAG(flag); }

#define GET_RFLAGS(flag) ((cpu.rflags & flag) / flag)
#define GET_CR0(flag) ((cpu.cr0 & flag) / flag)
#define GET_CR3(flag) ((cpu.cr3 & flag) / flag)
#define GET_CR4(flag) ((cpu.cr4 & flag) / flag)
#define GET_EFER(flag) ((cpu.IA32_EFER & flag) / flag)

#define GET_MSB(val, size) ((val >> (size - 1)) & 0x1)

#define MODRM(var, imm_sz)                                       \
  char tmp[64]; String modrm = { 63, tmp }; ModRM_Info info;     \
  ++(cpu.rip);                                                   \
  read_modrm(operand_sz, address_sz(), imm_sz, modrm, &info, 1); \
  uint8_t* post_modrm = ram_addr_ip();                           \
  uint8_t* var;                                                  \
  if( info.mode == INDIRECT )    var = ram + info.flat_addr;     \
  else if( info.mode == DIRECT ) var = info.reg_addr

typedef struct {
  struct { uint8_t present; uint8_t prefix; } g1;
  struct { uint8_t present; uint8_t prefix; } g2;
  struct { uint8_t present; } g3;
  struct { uint8_t present; } g4;
  struct {
    uint8_t present;
    uint8_t w : 1;
    uint8_t r : 1;
    uint8_t x : 1;
    uint8_t b : 1;
  } rex;
}
InstructionPrefixes;

static InstructionPrefixes prefixes;

extern OperationMode op_mode;
extern x64_CPU cpu;
extern x87_FPU fpu;
extern uint64_t inst_counter;

extern const uint64_t RAM_CAPACITY;
extern const uint64_t DISK_CAPACITY;

extern uint8_t* ram;
extern uint8_t* disk;

extern pthread_mutex_t io_ports_mutex;

extern uint64_t panic_rip;

extern void panic(const char*, ...);
extern void telwin_output(char);

static uint8_t* ram_addr_ip(void) {
  return ram + get_flat_address(CS, get_ip());
}

static void check_legacy_prefixes(void) {
  while( 1 ) {
    switch( *ram_addr_ip() ) {
      // group 1
      case 0xF0: prefixes.g1.present = 1; prefixes.g1.prefix = 0xF0; ++(cpu.rip); break;
      case 0xF2: prefixes.g1.present = 1; prefixes.g1.prefix = 0xF2; ++(cpu.rip); break;
      case 0xF3: prefixes.g1.present = 1; prefixes.g1.prefix = 0xF3; ++(cpu.rip); break;

      // group 2
      case 0x2E: prefixes.g2.present = 1; prefixes.g2.prefix = 0x2E; ++(cpu.rip); break;
      case 0x36: prefixes.g2.present = 1; prefixes.g2.prefix = 0x36; ++(cpu.rip); break;
      case 0x3E: prefixes.g2.present = 1; prefixes.g2.prefix = 0x3E; ++(cpu.rip); break;
      case 0x26: prefixes.g2.present = 1; prefixes.g2.prefix = 0x26; ++(cpu.rip); break;
      case 0x64: prefixes.g2.present = 1; prefixes.g2.prefix = 0x64; ++(cpu.rip); break;
      case 0x65: prefixes.g2.present = 1; prefixes.g2.prefix = 0x65; ++(cpu.rip); break;

      // group 3
      case 0x66: prefixes.g3.present = 1; ++(cpu.rip); break;

      // group 4
      case 0x67: prefixes.g4.present = 1; ++(cpu.rip); break;

      default: return;
    }
  }
}

static void check_rex_prefix(void) {
  const uint8_t byte = *ram_addr_ip();
  
  if( (byte & 0xF0) != 0x40 )
    return;

  prefixes.rex.present = 1;
  prefixes.rex.w       = (byte & 0b1000) >> 3;
  prefixes.rex.r       = (byte & 0b0100) >> 2;
  prefixes.rex.x       = (byte & 0b0010) >> 1;
  prefixes.rex.b       = (byte & 0b0001) >> 0;

  ++(cpu.rip);
}

char* get_ip_str_from_size(uint8_t size) {
  switch( size ) {
    case 2: return "ip";
    case 4: return "eip";
    case 8: return "rip";
  }
}

uint8_t* get_ip_addr_from_size(uint8_t size) {
  switch( size ) {
    case 2: return &(cpu.ip);
    case 4: return &(cpu.eip);
    case 8: return &(cpu.rip);
  }
}

uint64_t get_ip_from_size(uint8_t size) {
  switch( size ) {
    case 2: return cpu.ip;
    case 4: return cpu.eip;
    case 8: return cpu.rip;
  }
}

static uint64_t get_sp(void) {
  switch( op_mode ) {
    case REAL_MODE:      return cpu.sp;
    case LONG_MODE:      if( cpu.cs_cache.l ) return cpu.rsp;
    case PROTECTED_MODE: return cpu.ss_cache.db ? cpu.esp : cpu.sp;
  }
}

static uint8_t not_rex_ext_operand_sz(void) {
  switch( op_mode ) {
    case REAL_MODE: return prefixes.g3.present ? 4 : 2;
    case LONG_MODE: if( cpu.cs_cache.l ) return prefixes.g3.present ? 2 : 8;
    case PROTECTED_MODE: {
      uint8_t operand_sz = cpu.cs_cache.db ? 4 : 2;
      if( prefixes.g3.present ) operand_sz = 6 - operand_sz;
      return operand_sz;
    }
  }
}

static uint8_t rex_ext_operand_sz(void) {
  switch( op_mode ) {
    case REAL_MODE: return prefixes.g3.present ? 4 : 2;
    case LONG_MODE: {
      if( cpu.cs_cache.l ) {
        if( prefixes.rex.present && prefixes.rex.w ) return 8;
        return prefixes.g3.present ? 2 : 4;
      }
    }
    case PROTECTED_MODE: {
      uint8_t operand_sz = cpu.cs_cache.db ? 4 : 2;
      if( prefixes.g3.present ) operand_sz = 6 - operand_sz;
      return operand_sz;
    }
  }
}

static uint8_t four_or_eight_operand_sz(void) {
  switch( op_mode ) {
    case REAL_MODE:
    case PROTECTED_MODE: return 4;
    case LONG_MODE:      return 8;
  }
}

static uint8_t fpu_operand_sz(void) {
  switch( op_mode ) {
    case REAL_MODE:      return 2;
    case PROTECTED_MODE: return 4;
    case LONG_MODE:      return 8;
  }
}

static uint8_t address_sz(void) {
  switch( op_mode ) {
    case REAL_MODE: return prefixes.g4.present ? 4 : 2;
    case LONG_MODE: if( cpu.cs_cache.l ) return prefixes.g4.present ? 4 : 8;
    case PROTECTED_MODE: {
      uint8_t addr_sz = cpu.cs_cache.db ? 4 : 2;
      if( prefixes.g4.present ) addr_sz = 6 - addr_sz;
      return addr_sz;
    }
  }
}

static uint8_t stack_address_sz(void) {
  switch( op_mode ) {
    case REAL_MODE:      return 2;
    case LONG_MODE:      if( cpu.cs_cache.l ) return 8;
    case PROTECTED_MODE: return cpu.ss_cache.db ? 4 : 2;
  }
}

static uint8_t read_reg_in_opcode(uint8_t* rip) {
  uint8_t index = (*rip) & 0b00000111;
  if( prefixes.rex.present )
    index |= prefixes.rex.b << 3;
  return index;
}

uint64_t read_unsigned(uint8_t* addr, uint8_t size) {
  uint64_t u = 0;
  for(uint64_t i = 0; i < size; ++i) {
    u |= (uint64_t)(*addr) << (i<<3);
    ++addr;
  }
  return u;
}

static int64_t read_signed(uint8_t* addr, uint8_t size) {
  uint64_t s = 0;
  for(uint64_t i = 0; i < size; ++i) {
    s |= (uint64_t)(*addr) << (i<<3);
    ++addr;
  }
  // sign extension
  const uint8_t sign = GET_MSB(s, size*8);
  const uint64_t fill = sign ? 0xFF : 0x00;
  for(uint64_t i = size; i < 8; ++i)
    s |= fill << (i<<3);
 
  // doing int = uint is undefined behavior so there u go
  return *(int64_t*)&s;
}

typedef enum { RAX, RCX, RDX, RBX, RSP, RBP, RSI, RDI, R8, R9, R10, R11, R12, R13, R14, R15 } Register;

char* byte_reg_str[] = {"al","cl","dl","bl","ah","ch","dh","bh"};

char* rex_ext_byte_reg_str[] = {"al","cl","dl","bl","spl","bpl","sil","dil",
                                "r8b","r9b","r10b","r11b","r12b","r13b","r14b","r15b"};

char* word_reg_str[] = {"ax","cx","dx","bx","sp","bp","si","di",
                        "r8w","r9w","r10w","r11w","r12w","r13w","r14w","r15w"};

char* dword_reg_str[] = {"eax","ecx","edx","ebx","esp","ebp","esi","edi",
                         "r8d","r9d","r10d","r11d","r12d","r13d","r14d","r15d"};

char* qword_reg_str[] = {"rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi",
                         "r8","r9","r10","r11","r12","r13","r14","r15"};


uint8_t* byte_reg_addr[] = {&(cpu.al),&(cpu.cl),&(cpu.dl),&(cpu.bl),&(cpu.ah),&(cpu.ch),&(cpu.dh),&(cpu.bh)};

uint8_t* rex_ext_byte_reg_addr[] = {&(cpu.al),&(cpu.cl),&(cpu.dl),&(cpu.bl),&(cpu.spl),&(cpu.bpl),&(cpu.sil),
                                    &(cpu.dil),&(cpu.r8b),&(cpu.r9b),&(cpu.r10b),&(cpu.r11b),&(cpu.r12b),
                                    &(cpu.r13b),&(cpu.r14b),&(cpu.r15b)};

uint8_t* word_reg_addr[] = {&(cpu.ax),&(cpu.cx),&(cpu.dx),&(cpu.bx),&(cpu.sp),&(cpu.bp),&(cpu.si),&(cpu.di),
                            &(cpu.r8w),&(cpu.r9w),&(cpu.r10w),&(cpu.r11w),&(cpu.r12w),&(cpu.r13w),&(cpu.r14w),
                            &(cpu.r15w)};

uint8_t* dword_reg_addr[] = {&(cpu.eax),&(cpu.ecx),&(cpu.edx),&(cpu.ebx),&(cpu.esp),&(cpu.ebp),&(cpu.esi),
                             &(cpu.edi),&(cpu.r8d),&(cpu.r9d),&(cpu.r10d),&(cpu.r11d),&(cpu.r12d),&(cpu.r13d),
                             &(cpu.r14d),&(cpu.r15d)};

uint8_t* qword_reg_addr[] = {&(cpu.rax),&(cpu.rcx),&(cpu.rdx),&(cpu.rbx),&(cpu.rsp),&(cpu.rbp),&(cpu.rsi),
                             &(cpu.rdi),&(cpu.r8),&(cpu.r9),&(cpu.r10),&(cpu.r11),&(cpu.r12),&(cpu.r13),
                             &(cpu.r14),&(cpu.r15)};

static char* get_reg_str(uint8_t index, uint8_t size) {
  switch( size ) {
    case 1: {
      if( prefixes.rex.present ) return rex_ext_byte_reg_str[index];
      return byte_reg_str[index];
    }
    case 2: return word_reg_str[index];
    case 4: return dword_reg_str[index];
    case 8: return qword_reg_str[index];
  }
}

static uint8_t* get_reg_addr(uint8_t index, uint8_t size) {
  switch( size ) {
    case 1: {
      if( prefixes.rex.present ) return rex_ext_byte_reg_addr[index];
      return byte_reg_addr[index];
    }
    case 2: return word_reg_addr[index];
    case 4: return dword_reg_addr[index];
    case 8: return qword_reg_addr[index];
  } 
}

static SegmentRegister real_mode_default_segment(uint8_t rm) {
  // default segment is ss when BP is in the calculation
  if( rm == 0b010 ||
      rm == 0b011 ||
      rm == 0b110 )
    return SS;
  
  return DS;
}

static SegmentRegister protected_mode_default_segment(uint8_t rm) {
  // BP has index 5, SP (index 4) is not accessible
  if( rm == 0b101 )
    return SS;

  return DS;
}

static uint64_t real_mode_addr_calc(uint8_t rm) {
  switch( rm ) {
    case 0b000: return cpu.bx + cpu.si;
    case 0b001: return cpu.bx + cpu.di;
    case 0b010: return cpu.bp + cpu.si;
    case 0b011: return cpu.bp + cpu.di;
    case 0b100: return cpu.si;
    case 0b101: return cpu.di;
    case 0b110: return cpu.bp;
    case 0b111: return cpu.bx;
  }
}

static char* seg_reg_str_from_prefix(uint8_t prefix) {
  switch( prefix ) {
    case 0x2E: return "cs";
    case 0x36: return "ss";
    case 0x3E: return "ds";
    case 0x26: return "es";
    case 0x64: return "fs";
    case 0x65: return "gs";
  }
}

static SegmentRegister seg_reg_from_prefix(uint8_t prefix) {
  switch( prefix ) {
    case 0x2E: return CS;
    case 0x36: return SS;
    case 0x3E: return DS;
    case 0x26: return ES;
    case 0x64: return FS;
    case 0x65: return GS;
  }
}

static void update_zf_flag(uint64_t val) {
  UPDATE_FLAG(val == 0, RFLAGS_ZF)
}

static void update_sf_flag(int64_t val) {
  UPDATE_FLAG(val < 0, RFLAGS_SF)
}

static void update_pf_flag(uint64_t val) {
  uint8_t n = 0;
  for(uint64_t mask = 1; mask <= 128; mask *= 2) {
    if( val & mask ) ++n;
  }
  UPDATE_FLAG(n % 2 == 0, RFLAGS_PF)
}

static char* rep_prefix_str(void) {
  if( prefixes.g1.present && prefixes.g1.prefix == 0xF3 )
    return "REP ";

  return "";
}

static char get_str_inst_letter(uint8_t operand_sz) {
  switch( operand_sz ) {
    case 1: return 'B';
    case 2: return 'W';
    case 4: return 'D';
    case 8: return 'Q';
  }
}

// Thanks to https://ctyme.com/intr/
static void bios_interrupt_16(void) {
  switch( cpu.ah ) {
    case 0x0E: {
      // --- TELETYPE OUTPUT ---
      // USED   al = character
      // UNUSED bh = page number
      // USED   bl = foreground color
      telwin_output(cpu.al);
      return;
    }
    case 0x0F: {
      // --- GET CURRENT VIDEO MODE ---
      // UNUSED ah = number of character columns
      // UNUSED al = display mode
      // USED   bh = active page
      cpu.bh = 0; // let's pretend that the page 0 is active
      return;
    }
    case 0x4F: {
      switch( cpu.al ) {
        case 0x02: {
          // --- SET SuperVGA VIDEO MODE ---
          // USED   bx = new video mode
          // 
          // bx == 0x0012 -> text screen size:  80x30;
          //                 char size:         8x16;
          //                 pixel screen size: 640x480;
          //                 color number:      16;
          //                 vram address:      0xA0000; (idk for sure)
          //
          // UNUSED es:[di] = CRTC information block
          cpu.al = 0x4F;
          cpu.ah = 0;
          return;
        }
      }
    }
  }
}

static void bios_interrupt_19(void) {
  switch( cpu.ah ) {
    case 0x42: {
      // --- EXTENDED READ ---
      // UNUSED dl = drive number
      // USED   ds:[si] = disk address packet
      uint8_t* DAP_ptr = ram + get_flat_address(DS, cpu.si);
      if( *DAP_ptr != 0x10 )
        panic("BIOS int 0x13: can't handle 24 byte DAP!");
      const uint64_t sector_num   = *(uint16_t*)(DAP_ptr + 2);
      const uint64_t offset       = *(uint16_t*)(DAP_ptr + 4);
      const uint64_t segment      = *(uint16_t*)(DAP_ptr + 6);
      const uint64_t sector_start = *(uint64_t*)(DAP_ptr + 8);

      uint8_t* src  = disk + sector_start * 2048;
      uint8_t* dest = ram + (segment << 4) + offset;
      memcpy(dest, src, sector_num * 2048);

      CLEAR_FLAG(RFLAGS_CF);
      cpu.ah = 0;
      return;
    }
  }
}

static void bios_interrupt_21(void) {
  switch( cpu.ah ) {
    case 0xE8: {
      switch( cpu.al ) {
        case 0x01: {
          // --- GET MEMORY SIZE FOR >64M CONFIGURATIONS ---
          SET_FLAG(RFLAGS_CF);
          cpu.cx = cpu.ax = 0x3C00; // There's 15 MB of memory after the initial 1 MB
          cpu.dx = cpu.bx = (RAM_CAPACITY - 16*1024*1024) / (64*1024); // Number of 64K blocks after the 16MB
          return;
        }
        case 0x20: {
          // --- GET SYSTEM MEMORY MAP ---
          // UNUSED edx = 534D4150h ('SMAP')
          // WTF    ebx = continuation value or 00000000h to start at beginning of map
          // UNUSED ecx = size of buffer for result, in bytes (should be >= 20 bytes)
          // USED   es:[di] = buffer for result
          SET_FLAG(RFLAGS_CF);
          cpu.eax = 0x534D4150;
          cpu.ebx = 0;
          uint8_t* SMM_ptr = ram + get_flat_address(ES, cpu.di);
          const uint64_t base_addr = 0x100000;
	  const uint64_t capacity = RAM_CAPACITY - 0x100000;
          const uint32_t mem_attributes = 0x1; // All physical memory >1MB is accessible RAM
          memcpy(SMM_ptr + 0, &base_addr, 8);
          memcpy(SMM_ptr + 8, &capacity, 8);
          memcpy(SMM_ptr + 16, &mem_attributes, 4);
          return;
        }
      }
    }
  }
}

static void bios_interrupt_26(void) {
  switch( cpu.ah ) {
    case 0xB1: {
      switch( cpu.al ) {
        case 0x01: {
          // --- PCI BIOS v2.0c+ - INSTALLATION CHECK ---
          cpu.ah = 0x01; // != 0, PCI not installed
          return;
        }
      }
    }
  }
}

static char* overridable_segment_str(SegmentRegister seg_reg) {
  if( !prefixes.g2.present ) return seg_reg_str[seg_reg];
  return seg_reg_str_from_prefix(prefixes.g2.prefix);
}

static SegmentRegister overridable_segment(SegmentRegister seg_reg) {
  if( !prefixes.g2.present ) return seg_reg;
  return seg_reg_from_prefix(prefixes.g2.prefix);
}

static uint8_t get_ext_opcode_in_modrm(uint8_t* modrm) {
  return (*modrm & 0b00111000) >> 3;
}

static char* get_convert_inst_str(uint8_t operand_sz) {
  switch( operand_sz ) {
    case 2: return "CWD";
    case 4: return "CDQ";
    case 8: return "CQO";
  }
}

char* real_mode_addr_modes[] = {"bx+si","bx+di","bp+si","bp+di","si","di","bp","bx"};

char pos_neg[] = {'+','-'};

typedef enum { INDIRECT = 0, DIRECT = 1 } AddressingMode;

typedef struct {
  uint8_t ext_opcode;
  uint8_t reg;
  AddressingMode mode;
  union { uint64_t flat_addr; uint8_t* reg_addr; };
  uint64_t offset;
}
ModRM_Info;

typedef struct {
  SegmentRegister segment;
  uint64_t offset;
}
SIB_Info;

static void read_sib(uint8_t addr_sz, uint8_t mod, String sib, SIB_Info* out) {
  uint32_t len = sib.len;
  char* str = sib.str;
  uint8_t* rip = ram_addr_ip();

  const uint8_t scale = ((*rip) & 0b11000000) >> 6;
  uint8_t index       = ((*rip) & 0b00111000) >> 3;
  uint8_t base        = ((*rip) & 0b00000111) >> 0;

  out->segment = DS;
  out->offset = 0;

  if( prefixes.rex.present )
    index |= prefixes.rex.x << 3;

  const uint8_t base_exists  = !(base == 0b101 && mod == 0);
  const uint8_t index_exists = index != 0b0100;

  if( prefixes.rex.present )
    base |= prefixes.rex.b << 3;

  if( base_exists ) {
    char* base_str = get_reg_str(base, addr_sz);
    snprintf(str, len, "%s", base_str);
    str += strlen(base_str);
    len -= strlen(base_str);
    if( base == 0b100 || base == 0b101 )
      out->segment = SS; // if base is sp or bp then segment is ss
    uint64_t offset = 0;
    memcpy(&offset, get_reg_addr(base, addr_sz), addr_sz);
    out->offset += offset;
  }

  if( index_exists ) {
    if( base_exists ) {
      snprintf(str, len, "+");
      ++str; --len;
    }
    char* index_str = get_reg_str(index, addr_sz);
    snprintf(str, len, "%s", index_str);
    str += strlen(index_str);
    len -= strlen(index_str);
    uint64_t scaled_index = 0;
    memcpy(&scaled_index, get_reg_addr(index, addr_sz), addr_sz);
    switch( scale ) {
      case 0b00: break;
      case 0b01: snprintf(str, len, "*2"); str += 2; len -= 2; scaled_index *= 2; break;
      case 0b10: snprintf(str, len, "*4"); str += 2; len -= 2; scaled_index *= 4; break;
      case 0b11: snprintf(str, len, "*8"); str += 2; len -= 2; scaled_index *= 8; break;
    }
    out->offset += scaled_index;
  }

  if( !base_exists ) {
    if( index_exists ) {
      snprintf(str, len, "+");
      ++str; --len;
    }
    const int64_t disp = read_signed(rip+1, 4);
    cpu.rip += 5;
    snprintf(str, len, "%c0x%lx", pos_neg[disp<0], disp);
    out->offset += disp;
    return;
  }

  ++(cpu.rip);
}

static void read_modrm(uint8_t operand_sz, uint8_t addr_sz, uint8_t imm_sz, String modrm, ModRM_Info* out, uint8_t calc_flat_addr) {
  uint32_t len = modrm.len;
  char* str = modrm.str;
  uint8_t* rip = ram_addr_ip();

  SegmentRegister segment;
  uint8_t segment_override = 0;

  uint8_t mod = ((*rip) & 0b11000000) >> 6;

  out->ext_opcode = out->reg = ((*rip) & 0b00111000) >> 3;
  if( prefixes.rex.present )
    out->reg |= prefixes.rex.r << 3;
  
  uint8_t rm = ((*rip) & 0b00000111) >> 0;

  if( mod != 0b11 && prefixes.g2.present ) {
    snprintf(str, len, "%s:", seg_reg_str_from_prefix(prefixes.g2.prefix));
    str += 3; len -= 3;
    segment = seg_reg_from_prefix(prefixes.g2.prefix);
    segment_override = 1;
  }

  if( mod == 0b11 ) {
    if( prefixes.rex.present )
      rm |= prefixes.rex.b << 3;
    snprintf(str, len, "%s", get_reg_str(rm, operand_sz));
    out->mode = DIRECT;
    out->reg_addr = get_reg_addr(rm, operand_sz);
    ++(cpu.rip);
    return;
  }

  switch( addr_sz ) {
    case 2: {
      switch( mod ) {
        case 0b00: {
          if( rm == 0b110 ) {
            const uint64_t imm = read_unsigned(rip+1, 2);
            cpu.rip += 3;
            snprintf(str, len, "[0x%lx]", imm);
            if( !segment_override ) segment = DS;
            out->mode = INDIRECT;
            out->offset = imm;
            if( calc_flat_addr ) out->flat_addr = get_flat_address(segment, out->offset);
            return;
          }
          snprintf(str, len, "[%s]", real_mode_addr_modes[rm]);
          if( !segment_override ) segment = real_mode_default_segment(rm);
          out->mode = INDIRECT;
          out->offset = real_mode_addr_calc(rm);
          if( calc_flat_addr ) out->flat_addr = get_flat_address(segment, out->offset);
          ++(cpu.rip);
          return;
        }
        case 0b01:
        case 0b10: {
          const uint8_t disp_sz = mod & 0x1 ? 1 : 2;
          const int64_t disp = read_signed(rip+1, disp_sz);
          cpu.rip += 1 + disp_sz;
          snprintf(str, len, "[%s%c0x%lx]", real_mode_addr_modes[rm], pos_neg[disp<0], ABS(disp));
          if( !segment_override ) segment = real_mode_default_segment(rm);
          out->mode = INDIRECT;
          out->offset = real_mode_addr_calc(rm) + disp;
          if( calc_flat_addr ) out->flat_addr = get_flat_address(segment, out->offset);
          return;
        }
      }
    }
    case 4:
    case 8: {
      switch( mod ) {
        case 0b00: {
          if( rm == 0b100 ) {
            char tmp[64]; String sib = { 63, tmp }; SIB_Info info;
            ++(cpu.rip);
            read_sib(addr_sz, mod, sib, &info);
            snprintf(str, len, "[%s]", sib.str);
            if( !segment_override ) segment = info.segment;
            out->mode = INDIRECT;
            out->offset = info.offset;
            if( calc_flat_addr ) out->flat_addr = get_flat_address(segment, out->offset);
            return;
          }
          if( rm == 0b101 ) {
            out->mode = INDIRECT;
            if( !segment_override ) segment = DS;
            if( op_mode == LONG_MODE ) {
              const int64_t disp = read_signed(rip+1, 4);
              cpu.rip += 5;
              snprintf(str, len, "[%s%c0x%lx]", get_ip_str_from_size(addr_sz), pos_neg[disp<0], ABS(disp));
              out->offset = get_ip_from_size(addr_sz) + (int64_t)imm_sz + disp;
              if( calc_flat_addr ) out->flat_addr = get_flat_address(segment, out->offset);
            }
            else {
              const uint64_t imm = read_unsigned(rip+1, 4);
              cpu.rip += 5;
              snprintf(str, len, "[0x%lx]", imm);
              out->offset = imm;
              if( calc_flat_addr ) out->flat_addr = get_flat_address(segment, out->offset);
            }
            return;
          }
          if( prefixes.rex.present )
            rm |= prefixes.rex.b << 3;
          snprintf(str, len, "[%s]", get_reg_str(rm, addr_sz));
          if( !segment_override ) segment = DS;
          out->mode = INDIRECT;
          uint64_t offset = 0;
          memcpy(&offset, get_reg_addr(rm, addr_sz), addr_sz);
          out->offset = offset;
          if( calc_flat_addr ) out->flat_addr = get_flat_address(segment, out->offset);
          ++(cpu.rip);
          return;
        }
        case 0b01:
        case 0b10: {
          const uint8_t disp_sz = mod & 0x1 ? 1 : 4;
          if( rm == 0b100 ) {
            char tmp[64]; String sib = { 63, tmp }; SIB_Info info;
            ++(cpu.rip);
            read_sib(addr_sz, mod, sib, &info);
            const int64_t disp = read_signed(rip+2, disp_sz);
            cpu.rip += disp_sz;
            snprintf(str, len, "[%s%c0x%lx]", sib.str, pos_neg[disp<0], ABS(disp));
            if( !segment_override ) segment = info.segment;
            out->mode = INDIRECT;
            out->offset = info.offset + disp;
            if( calc_flat_addr ) out->flat_addr = get_flat_address(segment, out->offset);
            return;
          }
          if( prefixes.rex.present )
            rm |= prefixes.rex.b << 3;
          const int64_t disp = read_signed(rip+1, disp_sz);
          cpu.rip += 1 + disp_sz;
          snprintf(str, len, "[%s%c0x%lx]", get_reg_str(rm, addr_sz), pos_neg[disp<0], ABS(disp));
          if( !segment_override ) segment = protected_mode_default_segment(rm);
          out->mode = INDIRECT;
          uint64_t offset = 0;
          memcpy(&offset, get_reg_addr(rm, addr_sz), addr_sz);
          out->offset = offset + disp;
          if( calc_flat_addr ) out->flat_addr = get_flat_address(segment, out->offset);
          return;
        }
      }
    }
  }
}

// **************************
// ** INSTRUCTION DECODING **
// **************************

static void decode_gpr_modrm(uint8_t dir, uint8_t operand_sz, char** src_str, uint8_t** src_addr, char** dest_str, uint8_t** dest_addr) {
  static char tmp[64]; String modrm = { 63, tmp }; ModRM_Info info;
  ++(cpu.rip);
  read_modrm(operand_sz, address_sz(), 0, modrm, &info, 1);

  if( dir == 0 ) {
    *src_str = get_reg_str(info.reg, operand_sz);
    *dest_str = modrm.str;

    *src_addr = get_reg_addr(info.reg, operand_sz);
    if( info.mode == INDIRECT ) *dest_addr = ram + info.flat_addr;
    if( info.mode == DIRECT )   *dest_addr = info.reg_addr;
  }
  else {
    *src_str = modrm.str;
    *dest_str = get_reg_str(info.reg, operand_sz);

    if( info.mode == INDIRECT ) *src_addr = ram + info.flat_addr;
    if( info.mode == DIRECT )   *src_addr = info.reg_addr;
    *dest_addr = get_reg_addr(info.reg, operand_sz);
  }
}

// ***************************
// ** INSTRUCTION EXECUTION **
// ***************************

static void exe_mov(uint8_t* dest_addr, uint8_t* src_addr, uint8_t size) {
  if( dest_addr >= &(cpu.al) && dest_addr <= &(cpu.r15b) && size == 4 ) // sketchy as fuck but 100% functional
    memset(dest_addr + 4, 0, 4);
  memcpy(dest_addr, src_addr, size);
  if( dest_addr >= ram + 0xA0000 && dest_addr <= ram + 0xAFFFF )
    VGA_update_vram(dest_addr, size);
}

static void exe_add(uint8_t* dest_addr, uint8_t dest_sz, int64_t a, int64_t b) {
  int64_t c = a + b;
  exe_mov(dest_addr, &c, dest_sz);

  /* OF */ const uint8_t s_a = a < 0, s_b = b < 0, s_c = c < 0;
  if( (s_a == 0 && s_b == 1) || (s_a == 1 && s_b == 0) ) CLEAR_FLAG(RFLAGS_OF); 
  if( s_a == 0 && s_b == 0 ) { UPDATE_FLAG(s_c == 1, RFLAGS_OF) }
  if( s_a == 1 && s_b == 1 ) { UPDATE_FLAG(s_c == 0, RFLAGS_OF) }
  /* SF */ update_sf_flag(c);
  /* ZF */ update_zf_flag(c);
  /* AF */ UPDATE_FLAG( ((uint64_t)a & 0x0F) > ((uint64_t)c & 0x0F), RFLAGS_AF)
  /* PF */ update_pf_flag(c);
  /* CF */ UPDATE_FLAG((uint64_t)a > (uint64_t)c, RFLAGS_CF)
}

static void exe_xor(uint8_t* dest_addr, uint8_t dest_sz, uint64_t a, uint64_t b) {
  uint64_t c = a ^ b;
  exe_mov(dest_addr, &c, dest_sz);

  /* OF */ CLEAR_FLAG(RFLAGS_OF);
  /* SF */ update_sf_flag(c);
  /* ZF */ update_zf_flag(c);
  /* PF */ update_pf_flag(c);
  /* CF */ CLEAR_FLAG(RFLAGS_CF);
}

static void exe_or(uint8_t* dest_addr, uint8_t dest_sz, uint64_t a, uint64_t b) {
  uint64_t c = a | b;
  exe_mov(dest_addr, &c, dest_sz);

  /* OF */ CLEAR_FLAG(RFLAGS_OF);
  /* SF */ update_sf_flag(c);
  /* ZF */ update_zf_flag(c);
  /* PF */ update_pf_flag(c);
  /* CF */ CLEAR_FLAG(RFLAGS_CF);
}

static void exe_and(uint8_t* dest_addr, uint8_t dest_sz, uint64_t a, uint64_t b) {
  uint64_t c = a & b;
  exe_mov(dest_addr, &c, dest_sz);

  /* OF */ CLEAR_FLAG(RFLAGS_OF);
  /* SF */ update_sf_flag(c);
  /* ZF */ update_zf_flag(c);
  /* PF */ update_pf_flag(c);
  /* CF */ CLEAR_FLAG(RFLAGS_CF);
}

static void exe_not(uint8_t* dest_addr, uint8_t dest_sz, uint64_t a) {
  uint64_t c = ~a;
  exe_mov(dest_addr, &c, dest_sz);
}

static void update_sub_flags(int64_t a, int64_t b, int64_t c) {
  /* OF */ const uint8_t s_a = a < 0, s_b = b < 0, s_c = c < 0;
  if( (s_a == 0 && s_b == 0) || (s_a == 1 && s_b == 1) ) CLEAR_FLAG(RFLAGS_OF); 
  if( s_a == 0 && s_b == 1 ) { UPDATE_FLAG(s_c == 1, RFLAGS_OF) }
  if( s_a == 1 && s_b == 0 ) { UPDATE_FLAG(s_c == 0, RFLAGS_OF) }
  /* SF */ update_sf_flag(c);
  /* ZF */ update_zf_flag(c);
  /* AF */ UPDATE_FLAG( ((uint64_t)a & 0x0F) < ((uint64_t)b & 0x0F), RFLAGS_AF)
  /* PF */ update_pf_flag(c);
  /* CF */ UPDATE_FLAG((uint64_t)a < (uint64_t)b, RFLAGS_CF)
}

static void exe_cmp(int64_t a, int64_t b) {
  update_sub_flags(a, b, a - b);
}

static void exe_pop(uint8_t* dest_addr, uint8_t dest_sz) {
  exe_mov(dest_addr, ram + get_flat_address(SS, get_sp()), dest_sz);
  cpu.rsp += dest_sz;
}

void exe_push(uint8_t* src_addr, uint8_t src_sz) {
  cpu.rsp -= src_sz;
  exe_mov(ram + get_flat_address(SS, get_sp()), src_addr, src_sz);
}

char* cc_str[] = {"O","NO","B","NB","E","NE","NA","A",
                  "S","NS","P","NP","L","NL","NG","G"};

static uint8_t eval_cond(uint8_t flag, uint8_t negate) {
  uint8_t cond;
  switch( flag ) {
    case 0: cond = GET_RFLAGS(RFLAGS_OF); break;
    case 1: cond = GET_RFLAGS(RFLAGS_CF); break;
    case 2: cond = GET_RFLAGS(RFLAGS_ZF); break;
    case 3: cond = GET_RFLAGS(RFLAGS_CF) || GET_RFLAGS(RFLAGS_ZF); break;
    case 4: cond = GET_RFLAGS(RFLAGS_SF); break;
    case 5: cond = GET_RFLAGS(RFLAGS_PF); break;
    case 6: cond = GET_RFLAGS(RFLAGS_SF) != GET_RFLAGS(RFLAGS_OF); break;
    case 7: cond = GET_RFLAGS(RFLAGS_ZF) || (GET_RFLAGS(RFLAGS_SF) != GET_RFLAGS(RFLAGS_OF)); break;
  }
  return negate ? !cond : cond;
}

static void exe_jcc(uint8_t flag, uint8_t negate, int64_t disp) {
  if( eval_cond(flag, negate) )
    cpu.rip += disp;
}

static void exe_sub(uint8_t* dest_addr, uint8_t dest_sz, int64_t a, int64_t b) {
  int64_t c = a - b;
  exe_mov(dest_addr, &c, dest_sz);
  update_sub_flags(a, b, c);
}

static void exe_neg(uint8_t* dest_addr, uint8_t dest_sz, int64_t a) {
  exe_sub(dest_addr, dest_sz, 0, a);
  UPDATE_FLAG(a != 0, RFLAGS_CF);
}

// I've deduced that REP is in fact a "while" loop and not a "do while" loop
// from the pseudocode in intel's manual vol. 2 but it's not very clear still

static void exe_movs(uint8_t operand_sz, uint8_t addr_sz) {
  const SegmentRegister segment = overridable_segment(DS);

  const uint64_t src_offset  = read_unsigned(get_reg_addr(RSI, addr_sz), addr_sz);
  const uint64_t dest_offset = read_unsigned(get_reg_addr(RDI, addr_sz), addr_sz);
  uint8_t* src_addr  = ram + get_flat_address(segment, src_offset);
  uint8_t* dest_addr = ram + get_flat_address(ES, dest_offset);
  const int8_t dir   = GET_RFLAGS(RFLAGS_DF) ? -operand_sz : operand_sz;

  if( prefixes.g1.present && prefixes.g1.prefix == 0xF3 ) {
    while( 1 ) {
      const uint64_t cx = read_unsigned(get_reg_addr(RCX, addr_sz), addr_sz);
      if( cx == 0 ) break;

      exe_mov(dest_addr, src_addr, operand_sz);
      cpu.rsi += dir; cpu.rdi += dir;
      src_addr += dir; dest_addr += dir;
      --(cpu.rcx);
    }
  }
  else {
    exe_mov(dest_addr, src_addr, operand_sz);
    cpu.rsi += dir; cpu.rdi += dir;
  }
}

static void exe_stos(uint8_t operand_sz, uint8_t addr_sz) {
  const uint64_t dest_offset = read_unsigned(get_reg_addr(RDI, addr_sz), addr_sz);
  uint8_t* src_addr  = get_reg_addr(RAX, operand_sz);
  uint8_t* dest_addr = ram + get_flat_address(ES, dest_offset);
  const int8_t dir   = GET_RFLAGS(RFLAGS_DF) ? -operand_sz : operand_sz;

  if( prefixes.g1.present && prefixes.g1.prefix == 0xF3 ) {
    while( 1 ) {
      const uint64_t cx = read_unsigned(get_reg_addr(RCX, addr_sz), addr_sz);
      if( cx == 0 ) break;

      exe_mov(dest_addr, src_addr, operand_sz);
      cpu.rdi += dir;
      dest_addr += dir;
      --(cpu.rcx);
    }
  }
  else {
    exe_mov(dest_addr, src_addr, operand_sz);
    cpu.rdi += dir;
  }
}

static void exe_lods(uint8_t operand_sz, uint8_t addr_sz) {
  const SegmentRegister segment = overridable_segment(DS);

  const uint64_t src_offset = read_unsigned(get_reg_addr(RSI, addr_sz), addr_sz);
  uint8_t* src_addr  = ram + get_flat_address(segment, src_offset);
  uint8_t* dest_addr = get_reg_addr(RAX, operand_sz);
  const int8_t dir   = GET_RFLAGS(RFLAGS_DF) ? -operand_sz : operand_sz;

  if( prefixes.g1.present && prefixes.g1.prefix == 0xF3 ) {
    while( 1 ) {
      const uint64_t cx = read_unsigned(get_reg_addr(RCX, addr_sz), addr_sz);
      if( cx == 0 ) break;

      exe_mov(dest_addr, src_addr, operand_sz);
      cpu.rsi += dir;
      src_addr += dir;
      --(cpu.rcx);
    }
  }
  else {
    exe_mov(dest_addr, src_addr, operand_sz);
    cpu.rsi += dir;
  }
}

static void exe_scas(uint8_t operand_sz, uint8_t addr_sz) {
  const uint64_t src_offset = read_unsigned(get_reg_addr(RDI, addr_sz), addr_sz);
  uint8_t* src_addr = ram + get_flat_address(ES, src_offset);
  const int64_t b = read_signed(get_reg_addr(RAX, operand_sz), operand_sz);
  const int8_t dir = GET_RFLAGS(RFLAGS_DF) ? -operand_sz : operand_sz;

  if( prefixes.g1.present && prefixes.g1.prefix == 0xF3 ) {
    while( 1 ) {
      const uint64_t cx = read_unsigned(get_reg_addr(RCX, addr_sz), addr_sz);
      if( cx == 0 ) break;

      const int64_t a = read_signed(src_addr, operand_sz);
      exe_cmp(a, b);
      cpu.rdi += dir;
      src_addr += dir;
      --(cpu.rcx);
    }
  }
  else {
    const int64_t a = read_signed(src_addr, operand_sz);
    exe_cmp(a, b);
    cpu.rdi += dir;
  }
}

static void exe_cmps(uint8_t operand_sz, uint8_t addr_sz) {
  const SegmentRegister segment = overridable_segment(DS);

  const uint64_t src_offset  = read_unsigned(get_reg_addr(RSI, addr_sz), addr_sz);
  const uint64_t dest_offset = read_unsigned(get_reg_addr(RDI, addr_sz), addr_sz);
  uint8_t* src_addr  = ram + get_flat_address(segment, src_offset);
  uint8_t* dest_addr = ram + get_flat_address(ES, dest_offset);
  const int8_t dir   = GET_RFLAGS(RFLAGS_DF) ? -operand_sz : operand_sz;

  if( prefixes.g1.present && prefixes.g1.prefix == 0xF3 ) {
    while( 1 ) {
      const uint64_t cx = read_unsigned(get_reg_addr(RCX, addr_sz), addr_sz);
      if( cx == 0 ) break;

      const int64_t a = read_signed(src_addr, operand_sz);
      const int64_t b = read_signed(dest_addr, operand_sz);
      exe_cmp(a, b);
      cpu.rsi += dir; cpu.rdi += dir;
      src_addr += dir; dest_addr += dir;

      if( GET_RFLAGS(RFLAGS_ZF) == 0 ) break;
      --(cpu.rcx);
    }
  }
  else {
    const int64_t a = read_signed(src_addr, operand_sz);
    const int64_t b = read_signed(dest_addr, operand_sz);
    exe_cmp(a, b);
    cpu.rsi += dir; cpu.rdi += dir;
  }
}

static void exe_sar(uint8_t* dest_addr, uint8_t dest_sz, uint64_t a, uint64_t b) {
  uint64_t c = a;
  const uint64_t sign = a & ((uint64_t)1 << (dest_sz*8 - 1));
  for(uint64_t i = 0; i < b; ++i) {
    UPDATE_FLAG(c & 0x1, RFLAGS_CF)
    c >>= 1;
    c |= sign;
  }
  exe_mov(dest_addr, &c, dest_sz);
  
  if( b == 1 ) CLEAR_FLAG(RFLAGS_OF);
  if( b > 0 ) {
    update_sf_flag(c);
    update_zf_flag(c);
    update_pf_flag(c);
  }
}

static void exe_shr(uint8_t* dest_addr, uint8_t dest_sz, uint64_t a, uint64_t b) {
  uint64_t c = a;
  for(uint64_t i = 0; i < b; ++i) {
    UPDATE_FLAG(c & 0x1, RFLAGS_CF)
    c >>= 1;
  }
  exe_mov(dest_addr, &c, dest_sz);
  
  if( b == 1 ) { UPDATE_FLAG(GET_MSB(a, dest_sz*8), RFLAGS_OF) }
  if( b > 0 ) {
    update_sf_flag(c);
    update_zf_flag(c);
    update_pf_flag(c);
  }
}

static void exe_shrd(uint8_t* dest_addr, uint8_t dest_sz, uint64_t a, uint64_t b) {
  uint64_t c = a;
  for(uint64_t i = 0; i < cpu.cl; ++i) {
    UPDATE_FLAG(c & 0x1, RFLAGS_CF)
    c >>= 1;
    c |= (b & 0x1) << (dest_sz*8 - 1);
    b >>= 1;
  }
  exe_mov(dest_addr, &c, dest_sz);
  
  if( cpu.cl == 1 ) { UPDATE_FLAG(GET_MSB(a, dest_sz*8) ^ GET_MSB(c, dest_sz*8), RFLAGS_OF) }
  if( cpu.cl > 0 ) {
    update_sf_flag(c);
    update_zf_flag(c);
    update_pf_flag(c);
  }
}

static void exe_shl(uint8_t* dest_addr, uint8_t dest_sz, uint64_t a, uint64_t b) {
  uint64_t c = a;
  for(uint64_t i = 0; i < b; ++i) {
    UPDATE_FLAG(GET_MSB(c, dest_sz*8), RFLAGS_CF)
    c <<= 1;
  }
  exe_mov(dest_addr, &c, dest_sz);
  
  if( b == 1 ) { UPDATE_FLAG(GET_MSB(c, dest_sz*8) ^ GET_RFLAGS(RFLAGS_CF), RFLAGS_OF) }
  if( b > 0 ) {
    update_sf_flag(c);
    update_zf_flag(c);
    update_pf_flag(c);
  }
}

static void exe_ror(uint8_t* dest_addr, uint8_t dest_sz, uint64_t a, uint64_t b) {
  uint64_t c = a;
  for(uint64_t i = 0; i < b; ++i) {
    const uint64_t cf = c & 0x1;
    UPDATE_FLAG(cf, RFLAGS_CF)
    c = (c >> 1) | (cf << (dest_sz*8 - 1));
  }
  exe_mov(dest_addr, &c, dest_sz);
  
  if( b == 1 ) { UPDATE_FLAG(GET_MSB(c, dest_sz*8) ^ GET_MSB(c, dest_sz*8 - 1), RFLAGS_OF) }
}

static void exe_int(uint64_t vector) {
  if( op_mode == REAL_MODE ) {
    switch( vector ) {
      case 0x10: bios_interrupt_16(); return;
      case 0x13: bios_interrupt_19(); return;
      case 0x15: bios_interrupt_21(); return;
      case 0x1A: bios_interrupt_26(); return;
    }
  }
  panic("Unknown INT 0x%lx!", vector);
}

typedef struct {
  uint64_t function_addr;
  uint64_t inst_count;
}
FunctionCall;

extern FunctionCall stack_trace[];
extern uint64_t stack_trace_top;

static void exe_call_abs(uint8_t rip_sz, uint64_t addr) {
  exe_push(get_ip_addr_from_size(rip_sz), rip_sz);
  cpu.rip = addr;
  stack_trace[stack_trace_top++] = (FunctionCall){ cpu.rip, inst_counter };
}

static void exe_call_rel(uint8_t rip_sz, int64_t disp) {
  exe_push(get_ip_addr_from_size(rip_sz), rip_sz); 
  cpu.rip += disp;
  stack_trace[stack_trace_top++] = (FunctionCall){ cpu.rip, inst_counter };
}

static void exe_ret_near(uint8_t rip_sz) {
  exe_pop(get_ip_addr_from_size(rip_sz), rip_sz);
  stack_trace_top--;
}

static void exe_ret_far(uint8_t rip_sz) {
  exe_pop(get_ip_addr_from_size(rip_sz), rip_sz);
  uint16_t segment;
  exe_pop(&segment, 2);
  set_seg_reg(CS, segment);
  stack_trace_top--;
}

static void exe_iret(uint8_t rip_sz) {
  if( rip_sz != 8 )
    panic("IRET is only implemented for 64-bit mode!");

  dual_pic.processing_int = 0;

  exe_pop(&(cpu.rip), 8);
  
  uint64_t segment;
  exe_pop(&segment, 8);
  set_seg_reg(CS, segment);

  exe_pop(&(cpu.rflags), 8);

  uint64_t temp_rsp;
  exe_pop(&temp_rsp, 8);

  exe_pop(&segment, 8);
  set_seg_reg(SS, segment);
  
  cpu.rsp = temp_rsp;
}

static void exe_jmp_rel(int64_t disp) {
  cpu.rip += disp;
}

static void exe_imul_one_operand(uint8_t operand_sz, int64_t a, int64_t b) {
  if( operand_sz != 8 )
    panic("IMUL only implemented in 64-bit mode!");

  switch( operand_sz ) {
    case 8: {
      const __int128 r = (__int128)a * (__int128)b;
      cpu.rax = r & 0xFFFFFFFFFFFFFFFF;
      cpu.rdx = r >> 64;
      const uint8_t tmp = (__int128)((int64_t)(r & 0xFFFFFFFFFFFFFFFF)) != r;
      UPDATE_FLAG(tmp, RFLAGS_CF);
      UPDATE_FLAG(tmp, RFLAGS_OF);
      return;
    }
  }
}

static void exe_imul_mult_operands(uint8_t operand_sz, uint8_t* dest_addr, int64_t a, int64_t b) {
  if( operand_sz != 8 )
    panic("IMUL only implemented in 64-bit mode!");

  switch( operand_sz ) {
    case 8: {
      const __int128 r = (__int128)a * (__int128)b;
      const int64_t src = r & 0xFFFFFFFFFFFFFFFF;
      exe_mov(dest_addr, &src, 8);
      const uint8_t tmp = (__int128)src != r;
      UPDATE_FLAG(tmp, RFLAGS_CF);
      UPDATE_FLAG(tmp, RFLAGS_OF);
      return;
    }
  }
}

static void exe_mul(uint8_t operand_sz, uint64_t a, uint64_t b) {
  if( operand_sz != 8 )
    panic("MUL only implemented in 64-bit mode!");

  switch( operand_sz ) {
    case 8: {
      const unsigned __int128 r = (unsigned __int128)a * (unsigned __int128)b;
      cpu.rax = r & 0xFFFFFFFFFFFFFFFF;
      cpu.rdx = r >> 64;
      const uint8_t tmp = (unsigned __int128)((uint64_t)(r & 0xFFFFFFFFFFFFFFFF)) != r;
      UPDATE_FLAG(tmp, RFLAGS_CF);
      UPDATE_FLAG(tmp, RFLAGS_OF);
      return;
    }
  }
}

static void exe_div(uint8_t operand_sz, uint64_t divisor) {
  if( divisor == 0 )
    panic("DIV cannot divide by 0!");

  switch( operand_sz ) {
    case 1: {
      const uint64_t dividend = cpu.ax;
      cpu.al = dividend / divisor;
      cpu.ah = dividend % divisor;
      return;
    }
    case 2: {
      const uint64_t dividend = ((uint64_t)cpu.dx << 16) | cpu.ax;
      cpu.ax = dividend / divisor;
      cpu.dx = dividend % divisor;
      return;
    }
    case 4: {
      const uint64_t dividend = ((uint64_t)cpu.edx << 32) | cpu.eax;
      cpu.rax = (dividend / divisor) & 0xFFFFFFFF;
      cpu.rdx = (dividend % divisor) & 0xFFFFFFFF;
      return;
    }
    case 8: {
      const unsigned __int128 dividend = ((unsigned __int128)cpu.rdx << 64) | cpu.rax;
      cpu.rax = dividend / (unsigned __int128)divisor;
      cpu.rdx = dividend % (unsigned __int128)divisor;
      return;
    }
  }
}

static void exe_idiv(uint8_t operand_sz, int64_t divisor) {
  if( operand_sz != 8 )
    panic("IDIV only implemented in 64-bit mode!");
  if( divisor == 0 )
    panic("Can't divide by 0!");

  switch( operand_sz ) {
    case 8: {
      const __int128 dividend = ((unsigned __int128)cpu.rdx << 64) | cpu.rax;
      cpu.rax = dividend / (__int128)divisor;
      cpu.rdx = dividend % (__int128)divisor;
      return;
    }
  }
}

static void exe_test(uint64_t a, uint64_t b) {
  uint64_t c = a & b;
  update_sf_flag(c);
  update_zf_flag(c);
  update_pf_flag(c);
}

static void exe_inc(uint8_t* dest_addr, uint8_t dest_sz) {
  int64_t a = read_signed(dest_addr, dest_sz);
  int64_t c = a + 1;
  exe_mov(dest_addr, &c, dest_sz);

  /* OF */ const uint8_t s_a = a < 0, s_c = c < 0;
  if( s_a == 1 ) CLEAR_FLAG(RFLAGS_OF); 
  if( s_a == 0 ) { UPDATE_FLAG(s_c == 1, RFLAGS_OF) }
  /* SF */ update_sf_flag(c);
  /* ZF */ update_zf_flag(c);
  /* AF */ UPDATE_FLAG( ((uint64_t)a & 0x0F) > ((uint64_t)c & 0x0F), RFLAGS_AF)
  /* PF */ update_pf_flag(c);
}

static void exe_dec(uint8_t* dest_addr, uint8_t dest_sz) {
  int64_t a = read_signed(dest_addr, dest_sz);
  int64_t c = a - 1;
  exe_mov(dest_addr, &c, dest_sz);

  /* OF */ const uint8_t s_a = a < 0, s_c = c < 0;
  if( s_a == 0 ) CLEAR_FLAG(RFLAGS_OF); 
  if( s_a == 1 ) { UPDATE_FLAG(s_c == 0, RFLAGS_OF) }
  /* SF */ update_sf_flag(c);
  /* ZF */ update_zf_flag(c);
  /* AF */ UPDATE_FLAG( ((uint64_t)a & 0x0F) < 1, RFLAGS_AF)
  /* PF */ update_pf_flag(c);
}

static void exe_loop(uint8_t addr_sz, int64_t disp) {
  --(cpu.rcx);
  const uint64_t cx = read_unsigned(get_reg_addr(RCX, addr_sz), addr_sz);
  if( cx != 0 ) cpu.rip += disp;
}

static void exe_in(uint8_t* dest_addr, uint8_t dest_sz, uint16_t port) {
  pthread_mutex_lock(&io_ports_mutex);

  for(uint64_t i = 0; i < dest_sz; ++i) {
    switch( port ) {
      case 0x20: PIC1_write_IRR(); break;
      case 0x21: PIC1_write_mask(); break;
      case 0x40:
      case 0x41:
      case 0x42: PIT_read_counter(port); break;
      case 0x60: PS2_send_bytes(); break;
      case 0x64: PS2_send_status(); break;
      case 0x61: break; // Keyboard controller: used for A20 line
      case 0x71: break; // CMOS output, see update_RTC function
      case 0x92: break; // A20 line
      case 0xA1: PIC2_write_mask(); break;
      case 0x1F0: ATAPI_send_bytes(); break;
      case 0x1F1: ATAPI_send_features(); break;
      case 0x1F3:
      case 0x1F4:
      case 0x1F5:
      case 0x1F6: break;
      case 0x1F7: ATAPI_send_status(); break;
      case 0x3C9: VGA_send_color_bytes(); break;
      case 0x3DA: VGA_reset_attribute_register(); break;
      default: panic("IN from unknown port 0x%x!", port);
    }
    
    *dest_addr = cpu.io_ports[port];
    ++dest_addr;
  }

  pthread_mutex_unlock(&io_ports_mutex);
}

static void exe_ins(uint8_t operand_sz, uint8_t addr_sz, uint16_t port) {
  uint64_t offset = 0;
  memcpy(&offset, get_reg_addr(RDI, addr_sz), addr_sz);

  uint8_t* dest_addr = ram + get_flat_address(ES, offset);
  const int8_t dir = GET_RFLAGS(RFLAGS_DF) ? -operand_sz : operand_sz;

  if( prefixes.g1.present && prefixes.g1.prefix == 0xF3 ) {
    while( 1 ) {
      const uint64_t cx = read_unsigned(get_reg_addr(RCX, addr_sz), addr_sz);
      if( cx == 0 ) break;

      exe_in(dest_addr, operand_sz, port);
      cpu.rdi += dir;
      dest_addr += dir;
      --(cpu.rcx);
    }
  }
  else {
    exe_in(dest_addr, operand_sz, port);
    cpu.rdi += dir;
  }
}

static void exe_out(uint8_t* src_addr, uint8_t src_sz, uint16_t port) {
  pthread_mutex_lock(&io_ports_mutex);
  
  for(uint64_t i = 0; i < src_sz; ++i) {
    cpu.io_ports[port] = *src_addr;
    ++src_addr;
   
    switch( port ) {
      case 0x20: PIC1_process_command(); break;
      case 0x21: PIC1_initialization(); break;
      case 0x40:
      case 0x41:
      case 0x42: PIT_write_reload_value(port); break;
      case 0x43: PIT_override_mode(); break;
      case 0x60: PS2_receive_bytes(); break;
      case 0x61: break; // Keyboard controller: used for A20 line
      case 0x64: PS2_command(); break;
      case 0x70: update_RTC(); break;
      case 0x92: break; // A20 line
      case 0xA0: PIC2_process_command(); break;
      case 0xA1: PIC2_initialization(); break;
      case 0x1F0: ATAPI_receive_packet(); break;
      case 0x1F1: ATAPI_features(); break;
      case 0x1F2: // sector count reg
      case 0x1F3:
      case 0x1F4:
      case 0x1F5: break; // LBA bytes
      case 0x1F6: ATAPI_drive_selection(); break;
      case 0x1F7: ATAPI_command(); break;
      case 0x3C0: VGA_attribute_register_receive_bytes(); break;
      case 0x3C4: break; // VGA index port
      case 0x3C5: { // VGA data port
        switch( cpu.io_ports[0x3C4] ) {
          case 2: VGA_update_plane_selector(); break;
          default: panic("OUT to 0x3C5 with unknown index %x!", cpu.io_ports[0x3C4]);
        }
        break;
      }
      case 0x3C6: break; // update bit mask register
      case 0x3C7: VGA_get_palette_index2(); break;
      case 0x3C8: VGA_get_palette_index(); break;
      case 0x3C9: VGA_receive_color_bytes(); break;
      default: panic("OUT to unknown port 0x%x!", port);
    }
  }

  pthread_mutex_unlock(&io_ports_mutex);
}

static void exe_convert(uint8_t operand_sz) {
  const uint8_t sign = read_signed(get_reg_addr(RAX, operand_sz), operand_sz) < 0;
  const uint64_t rdx[] = { 0x0000000000000000, 0xFFFFFFFFFFFFFFFF };
  exe_mov(get_reg_addr(RDX, operand_sz), rdx + sign, operand_sz);
}

static void exe_xchg(uint8_t* addr1, uint8_t* addr2, uint8_t operand_sz) {
  const uint64_t tmp = read_unsigned(addr1, operand_sz);
  exe_mov(addr1, addr2, operand_sz);
  exe_mov(addr2, &tmp, operand_sz);
}

static void exe_xlat(uint8_t* addr) {
  exe_mov(&(cpu.al), addr, 1);
}

// ********************** //
// ** FPU INSTRUCTIONS ** //
// ********************** //

uint8_t get_fpu_top(void) {
  return (fpu.status >> 11) & 0b111;
}

static void set_fpu_top(uint8_t top) {
  fpu.status &= 0b1100011111111111;
  fpu.status |= top << 11;
}

static uint8_t reg_st(int8_t disp) {
  return (get_fpu_top() + disp) & 0b111;
}

static f80_t* addr_st(int8_t disp) {
  return fpu.r0 + 10*reg_st(disp);
}

f80_t val_st(int8_t disp) {
  return *addr_st(disp);
}

static void pop_fpu(void) {
  fpu.tags |= (uint16_t)0b11 << (2*reg_st(0));
  set_fpu_top(reg_st(1)); 
}

static void push_fpu(void) {
  set_fpu_top(reg_st(-1));
}

static void store_fpu_st(int8_t disp, f80_t src) {
  memcpy(addr_st(disp), &src, 10);
  fpu.tags &= ~((uint16_t)0b11 << (2*reg_st(disp)));
  fpu.tags |= (uint16_t)(src == 0 ? 0b01 : 0b00) << (2*reg_st(disp));
}

static void exe_fninit(void) {
  fpu.status = 0;
  fpu.control = 0x37F;
  fpu.tags = 0xFFFF;
}

static void exe_fxsave64(uint8_t* dest_addr) {
  memcpy(dest_addr + 0, &(fpu.control), 2);
  memcpy(dest_addr + 2, &(fpu.status), 2);

  uint8_t ftw = 0;
  for(uint64_t i = 0; i < 8; ++i) {
    const uint8_t tag = ((fpu.tags >> (2*i)) & 0b11) == 0b11 ? 0 : 1;
    ftw |= tag << i;
  }
  memcpy(dest_addr + 4, &ftw, 1);

  memcpy(dest_addr + 32, &(fpu.r0), 10);
  memcpy(dest_addr + 48, &(fpu.r1), 10);
  memcpy(dest_addr + 64, &(fpu.r2), 10);
  memcpy(dest_addr + 80, &(fpu.r3), 10);
  memcpy(dest_addr + 96, &(fpu.r4), 10);
  memcpy(dest_addr + 112, &(fpu.r5), 10);
  memcpy(dest_addr + 128, &(fpu.r6), 10);
  memcpy(dest_addr + 144, &(fpu.r7), 10);
}

static void exe_fxrstor64(uint8_t* dest_addr) {
  memcpy(&(fpu.control), dest_addr + 0, 2);
  memcpy(&(fpu.status), dest_addr + 2, 2);

  fpu.tags = 0;
  uint8_t ftw = 0;
  memcpy(&ftw, dest_addr + 4, 1);
  for(uint64_t i = 0; i < 8; ++i) {
    const uint8_t tag = ((ftw >> i) & 0x1) == 0 ? 0b11 : 0b00;
    fpu.tags |= tag << (2*i);
  }

  memcpy(&(fpu.r0), dest_addr + 32, 10);
  memcpy(&(fpu.r1), dest_addr + 48, 10);
  memcpy(&(fpu.r2), dest_addr + 64, 10);
  memcpy(&(fpu.r3), dest_addr + 80, 10);
  memcpy(&(fpu.r4), dest_addr + 96, 10);
  memcpy(&(fpu.r5), dest_addr + 112, 10);
  memcpy(&(fpu.r6), dest_addr + 128, 10);
  memcpy(&(fpu.r7), dest_addr + 144, 10);
}

static void exe_load_fpu(f80_t src) {
  push_fpu();
  store_fpu_st(0, src);
}

static void exe_fadd(f80_t imm) {
  store_fpu_st(0, val_st(0) + imm);
}

static void exe_fsub(f80_t imm) {
  store_fpu_st(0, val_st(0) - imm);
}

static void exe_fsubr(f80_t imm) {
  store_fpu_st(0, imm - val_st(0));
}

static void exe_fmul(f80_t imm) {
  store_fpu_st(0, val_st(0) * imm);
}

static void exe_fdiv(f80_t imm) {
  if( imm == 0 ) panic("FDIV cannot divide by zero!");
  store_fpu_st(0, val_st(0) / imm);
}

static void exe_fdivr(f80_t imm) {
  if( val_st(0) == 0 ) panic("FDIVR cannot divide by zero!");
  store_fpu_st(0, imm / val_st(0));
}

static void exe_fmulp(void) {
  store_fpu_st(1, val_st(0) * val_st(1));
  pop_fpu();
}

static void exe_faddp(void) {
  store_fpu_st(1, val_st(0) + val_st(1));
  pop_fpu();
}

static void exe_fdivp(void) {
  if( val_st(0) == 0 ) panic("FDIVP cannot divide by zero!");
  store_fpu_st(1, val_st(1) / val_st(0));
  pop_fpu();
}

static void exe_fsubrp(void) {
  store_fpu_st(1, val_st(0) - val_st(1));
  pop_fpu();
}

static void exe_fdivrp(void) {
  if( val_st(1) == 0 ) panic("FDIVRP cannot divide by zero!");
  store_fpu_st(1, val_st(0) / val_st(1));
  pop_fpu();
}

static void exe_fsqrt(void) {
  //if( val_st(0) < 0 ) panic("FSQRT cannot take the root of %Lf !", val_st(0));
  store_fpu_st(0, sqrtl( val_st(0) < 0 ? -val_st(0) : val_st(0) ));
}

static void exe_fcos(void) {
  store_fpu_st(0, cosl(val_st(0)));
}

static void exe_fsin(void) {
  store_fpu_st(0, sinl(val_st(0)));
}

static void exe_fpatan(void) {
  store_fpu_st(1, atan2l( val_st(1), val_st(0) ));
  pop_fpu();
}

static void exe_fabs(void) {
  const f80_t st0 = val_st(0);
  store_fpu_st(0, st0 < 0 ? -st0 : st0 );
}

static void exe_fprem(void) {
  store_fpu_st(0, fmodl(val_st(0), val_st(1)));
}

static uint8_t get_fpu_control_rc(void) {
  return (fpu.control >> 10) & 0b11;
}

static void exe_frndint(void) {
  f80_t rnd_st0;
  switch( get_fpu_control_rc() ) {
    case 0b00: rnd_st0 = roundl(val_st(0)); break;
    case 0b01: rnd_st0 = floorl(val_st(0)); break;
    case 0b10: rnd_st0 = ceill(val_st(0)); break;
    case 0b11: rnd_st0 = truncl(val_st(0)); break;
  }
  store_fpu_st(0, rnd_st0);
}

static void exe_f2xm1(void) {
  store_fpu_st(0, powl(2, val_st(0)) - 1.0L);
}

static void exe_fyl2x(void) {
  if( val_st(0) < 0 ) panic("FYL2X cannot take the log2 of %Lf <= 0 with ST(1) = %Lf !", val_st(0), val_st(1));
  store_fpu_st(1, val_st(1) * log2l(val_st(0)));
  pop_fpu();
}

static void exe_fscale(void) {
  store_fpu_st(0, val_st(0) * powl(2, truncl(val_st(1))));
}

static void exe_ffree(int8_t disp) {
  fpu.tags |= (uint16_t)0b11 << (2*reg_st(disp));
}

static void exe_fincstp(void) {
  set_fpu_top(reg_st(1));
}

static void exe_fcomip(int8_t disp) {
  CLEAR_FLAG(RFLAGS_PF);
  UPDATE_FLAG(val_st(0) == val_st(disp), RFLAGS_ZF)
  UPDATE_FLAG(val_st(0) <  val_st(disp), RFLAGS_CF)
  pop_fpu();
}

static void decode_one_byte_opcode(String assembly) {
  uint32_t len = assembly.len;
  char* str = assembly.str;
  uint8_t* opcode = ram_addr_ip();

  switch( *opcode ) {
    case 0x00:
    case 0x01:
    case 0x02:
    case 0x03: {
      const uint8_t w = (*opcode >> 0) & 0x1;
      const uint8_t d = (*opcode >> 1) & 0x1;
      const uint8_t operand_sz = w ? rex_ext_operand_sz() : 1;
      char *src_str, *dest_str;
      uint8_t *src_addr, *dest_addr;
      decode_gpr_modrm(d, operand_sz, &src_str, &src_addr, &dest_str, &dest_addr);
      const int64_t a = read_signed(dest_addr, operand_sz);
      const int64_t b = read_signed(src_addr, operand_sz);

      snprintf(str, len, "ADD  %s, %s", dest_str, src_str);
      exe_add(dest_addr, operand_sz, a, b);
      return;
    }
    case 0x04:
    case 0x05: {
      const uint8_t w = (*opcode >> 0) & 0x1;
      const uint8_t operand_sz = w ? rex_ext_operand_sz() : 1;
      const uint8_t disp_sz = MIN(operand_sz, 4);
      uint8_t* dest_addr = get_reg_addr(RAX, operand_sz);
      const int64_t a = read_signed(dest_addr, operand_sz);
      const int64_t b = read_signed(opcode+1, disp_sz);
      cpu.rip += 1 + disp_sz;

      snprintf(str, len, "ADD  %s, %c0x%lx", get_reg_str(RAX, operand_sz), pos_neg[b<0], ABS(b));
      exe_add(dest_addr, operand_sz, a, b);
      return;
    }
    case 0x06: {
      const uint8_t operand_sz = not_rex_ext_operand_sz();
      const uint64_t es = read_unsigned(&(cpu.es), 2);
      ++(cpu.rip);
      
      snprintf(str, len, "PUSH  es");
      exe_push(&es, operand_sz);
      return;
    }
    case 0x08:
    case 0x09:
    case 0x0A:
    case 0x0B: {
      const uint8_t w = (*opcode >> 0) & 0x1;
      const uint8_t d = (*opcode >> 1) & 0x1;
      const uint8_t operand_sz = w ? rex_ext_operand_sz() : 1;
      char *src_str, *dest_str;
      uint8_t *src_addr, *dest_addr;
      decode_gpr_modrm(d, operand_sz, &src_str, &src_addr, &dest_str, &dest_addr);
      const uint64_t a = read_unsigned(dest_addr, operand_sz);
      const uint64_t b = read_unsigned(src_addr, operand_sz);

      snprintf(str, len, "OR  %s, %s", dest_str, src_str);
      exe_or(dest_addr, operand_sz, a, b);
      return;
    }
    case 0x0C: {
      uint8_t* dest_addr = get_reg_addr(RAX, 1);
      const uint64_t a = read_unsigned(dest_addr, 1);
      const uint64_t b = read_unsigned(opcode+1, 1);
      cpu.rip += 2;

      snprintf(str, len, "OR  %s, 0x%lx", get_reg_str(RAX, 1), b);
      exe_or(dest_addr, 1, a, b);
      return;
    }
    case 0x0D: {
      const uint8_t operand_sz = rex_ext_operand_sz();
      const uint8_t disp_sz = MIN(operand_sz, 4);
      const uint64_t a = read_unsigned(get_reg_addr(RAX, operand_sz), operand_sz);
      const uint64_t b = read_signed(opcode+1, disp_sz);
      cpu.rip += 1 + disp_sz;

      snprintf(str, len, "OR  %s, 0x%lx", get_reg_str(RAX, operand_sz),
                                          b & (((uint64_t)1 << operand_sz*8) - 1));
      exe_or(get_reg_addr(RAX, operand_sz), operand_sz, a, b);
      return;
    }
    case 0x10:
    case 0x11:
    case 0x12:
    case 0x13: {
      const uint8_t w = (*opcode >> 0) & 0x1;
      const uint8_t d = (*opcode >> 1) & 0x1;
      const uint8_t operand_sz = w ? rex_ext_operand_sz() : 1;
      char *src_str, *dest_str;
      uint8_t *src_addr, *dest_addr;
      decode_gpr_modrm(d, operand_sz, &src_str, &src_addr, &dest_str, &dest_addr);
      const int64_t a = read_signed(dest_addr, operand_sz);
      const int64_t b = read_signed(src_addr, operand_sz) + GET_RFLAGS(RFLAGS_CF);

      snprintf(str, len, "ADC  %s, %s", dest_str, src_str);
      exe_add(dest_addr, operand_sz, a, b);
      return;
    }
    case 0x14:
    case 0x15: {
      const uint8_t w = (*opcode >> 0) & 0x1;
      const uint8_t operand_sz = w ? rex_ext_operand_sz() : 1;
      const uint8_t disp_sz = MIN(operand_sz, 4);
      uint8_t* dest_addr = get_reg_addr(RAX, operand_sz);
      const int64_t a = read_signed(dest_addr, operand_sz);
      const int64_t b = read_signed(opcode+1, disp_sz) + GET_RFLAGS(RFLAGS_CF);
      cpu.rip += 1 + disp_sz;

      snprintf(str, len, "ADC  %s, %c0x%lx", get_reg_str(RAX, operand_sz), pos_neg[b<0], ABS(b));
      exe_add(dest_addr, operand_sz, a, b);
      return;
    }
    case 0x18:
    case 0x19:
    case 0x1A:
    case 0x1B: {
      const uint8_t w = (*opcode >> 0) & 0x1;
      const uint8_t d = (*opcode >> 1) & 0x1;
      const uint8_t operand_sz = w ? rex_ext_operand_sz() : 1;
      char *src_str, *dest_str;
      uint8_t *src_addr, *dest_addr;
      decode_gpr_modrm(d, operand_sz, &src_str, &src_addr, &dest_str, &dest_addr);
      const int64_t a = read_signed(dest_addr, operand_sz);
      const int64_t b = read_signed(src_addr, operand_sz) + GET_RFLAGS(RFLAGS_CF);

      snprintf(str, len, "SBB  %s, %s", dest_str, src_str);
      exe_sub(dest_addr, operand_sz, a, b);
      return;
    }
    case 0x1E: {
      const uint8_t operand_sz = not_rex_ext_operand_sz();
      const uint64_t ds = read_unsigned(&(cpu.ds), 2);                
      ++(cpu.rip);
      
      snprintf(str, len, "PUSH  ds");
      exe_push(&ds, operand_sz);
      return;
    }
    case 0x1F: {
      const uint8_t operand_sz = not_rex_ext_operand_sz();
      ++(cpu.rip);
      
      snprintf(str, len, "POP  ds");
      uint64_t segment = 0;
      exe_pop(&segment, operand_sz);
      set_seg_reg(DS, segment);
      return;
    }
    case 0x20:
    case 0x21:
    case 0x22:
    case 0x23: {
      const uint8_t w = (*opcode >> 0) & 0x1;
      const uint8_t d = (*opcode >> 1) & 0x1;
      const uint8_t operand_sz = w ? rex_ext_operand_sz() : 1;
      char *src_str, *dest_str;
      uint8_t *src_addr, *dest_addr;
      decode_gpr_modrm(d, operand_sz, &src_str, &src_addr, &dest_str, &dest_addr);
      const uint64_t a = read_unsigned(dest_addr, operand_sz);
      const uint64_t b = read_unsigned(src_addr, operand_sz);

      snprintf(str, len, "AND  %s, %s", dest_str, src_str);
      exe_and(dest_addr, operand_sz, a, b);
      return;
    }
    case 0x24:
    case 0x25: {
      const uint8_t w = (*opcode >> 0) & 0x1;
      const uint8_t operand_sz = w ? rex_ext_operand_sz() : 1;
      const uint8_t disp_sz = MIN(operand_sz, 4);
      const uint64_t a = read_unsigned(get_reg_addr(RAX, operand_sz), operand_sz);
      const uint64_t b = read_signed(opcode+1, disp_sz);
      cpu.rip += 1 + disp_sz;

      snprintf(str, len, "AND  %s, 0x%lx", get_reg_str(RAX, operand_sz),
                                           b & (((uint64_t)1 << operand_sz*8) - 1));
      exe_and(get_reg_addr(RAX, operand_sz), operand_sz, a, b);
      return;
    }
    case 0x28:
    case 0x29:
    case 0x2A:
    case 0x2B: {
      const uint8_t w = (*opcode >> 0) & 0x1;
      const uint8_t d = (*opcode >> 1) & 0x1;
      const uint8_t operand_sz = w ? rex_ext_operand_sz() : 1;
      char *src_str, *dest_str;
      uint8_t *src_addr, *dest_addr;
      decode_gpr_modrm(d, operand_sz, &src_str, &src_addr, &dest_str, &dest_addr);
      const int64_t a = read_signed(dest_addr, operand_sz);
      const int64_t b = read_signed(src_addr, operand_sz);

      snprintf(str, len, "SUB  %s, %s", dest_str, src_str);
      exe_sub(dest_addr, operand_sz, a, b);
      return;
    }
    case 0x30:
    case 0x31:
    case 0x32:
    case 0x33: {
      const uint8_t w = (*opcode >> 0) & 0x1;
      const uint8_t d = (*opcode >> 1) & 0x1;
      const uint8_t operand_sz = w ? rex_ext_operand_sz() : 1;
      char *src_str, *dest_str;
      uint8_t *src_addr, *dest_addr;
      decode_gpr_modrm(d, operand_sz, &src_str, &src_addr, &dest_str, &dest_addr);
      const uint64_t a = read_unsigned(dest_addr, operand_sz);
      const uint64_t b = read_unsigned(src_addr, operand_sz);

      snprintf(str, len, "XOR  %s, %s", dest_str, src_str);
      exe_xor(dest_addr, operand_sz, a, b);
      return;
    }
    case 0x34:
    case 0x35: {
      const uint8_t w = (*opcode >> 0) & 0x1;
      const uint8_t operand_sz = w ? rex_ext_operand_sz() : 1;
      const uint8_t imm_sz = MIN(operand_sz, 4);
      const uint64_t a = read_unsigned(get_reg_addr(RAX, operand_sz), operand_sz);
      const uint64_t b = read_unsigned(opcode+1, imm_sz);
      cpu.rip += 1 + imm_sz;

      snprintf(str, len, "XOR  %s, 0x%lx", get_reg_str(RAX, operand_sz), b);
      exe_xor(get_reg_addr(RAX, operand_sz), operand_sz, a, b);
      return;
    }
    case 0x38:
    case 0x39:
    case 0x3A:
    case 0x3B: {
      const uint8_t w = (*opcode >> 0) & 0x1;
      const uint8_t d = (*opcode >> 1) & 0x1;
      const uint8_t operand_sz = w ? rex_ext_operand_sz() : 1;
      char *src_str, *dest_str;
      uint8_t *src_addr, *dest_addr;
      decode_gpr_modrm(d, operand_sz, &src_str, &src_addr, &dest_str, &dest_addr);
      const int64_t a = read_signed(dest_addr, operand_sz);
      const int64_t b = read_signed(src_addr, operand_sz);

      snprintf(str, len, "CMP  %s, %s", dest_str, src_str);
      exe_cmp(a, b);
      return;
    }
    case 0x3C:
    case 0x3D: {
      const uint8_t w = (*opcode >> 0) & 0x1;
      const uint8_t operand_sz = w ? rex_ext_operand_sz() : 1;
      const uint8_t imm_sz = MIN(operand_sz, 4);
      const int64_t a = read_signed(get_reg_addr(RAX, operand_sz), operand_sz);
      const int64_t b = read_signed(opcode+1, imm_sz);
      cpu.rip += 1 + imm_sz;

      snprintf(str, len, "CMP  %s, %c0x%lx", get_reg_str(RAX, operand_sz), pos_neg[b<0], ABS(b));
      exe_cmp(a, b);
      return;
    }
    case 0x40:
    case 0x41:
    case 0x42:
    case 0x43:
    case 0x44:
    case 0x45:
    case 0x46:
    case 0x47: {
      const uint8_t operand_sz = not_rex_ext_operand_sz();
      const uint8_t opcode_reg = read_reg_in_opcode(opcode);
      ++(cpu.rip);

      snprintf(str, len, "INC  %s", get_reg_str(opcode_reg, operand_sz));
      exe_inc(get_reg_addr(opcode_reg, operand_sz), operand_sz);
      return;
    }
    case 0x48:
    case 0x49:
    case 0x4A:
    case 0x4B:
    case 0x4C:
    case 0x4D:
    case 0x4E:
    case 0x4F: {
      const uint8_t operand_sz = not_rex_ext_operand_sz();
      const uint8_t opcode_reg = read_reg_in_opcode(opcode);
      ++(cpu.rip);

      snprintf(str, len, "DEC  %s", get_reg_str(opcode_reg, operand_sz));
      exe_dec(get_reg_addr(opcode_reg, operand_sz), operand_sz);
      return;
    }
    case 0x50:
    case 0x51:
    case 0x52:
    case 0x53:
    case 0x54:
    case 0x55:
    case 0x56:
    case 0x57: {
      const uint8_t operand_sz = not_rex_ext_operand_sz();
      const uint8_t opcode_reg = read_reg_in_opcode(opcode);
      ++(cpu.rip);

      snprintf(str, len, "PUSH  %s", get_reg_str(opcode_reg, operand_sz));
      exe_push(get_reg_addr(opcode_reg, operand_sz), operand_sz);
      return;
    }
    case 0x58:
    case 0x59:
    case 0x5A:
    case 0x5B:
    case 0x5C:
    case 0x5D:
    case 0x5E:
    case 0x5F: {
      const uint8_t operand_sz = not_rex_ext_operand_sz();
      const uint8_t opcode_reg = read_reg_in_opcode(opcode);
      ++(cpu.rip);

      snprintf(str, len, "POP  %s", get_reg_str(opcode_reg, operand_sz));
      exe_pop(get_reg_addr(opcode_reg, operand_sz), operand_sz);
      return;
    }
    case 0x63: {
      const uint8_t operand_sz = rex_ext_operand_sz();
      const uint8_t src_sz = MIN(operand_sz, 4);
      char tmp[64]; String modrm = { 63, tmp }; ModRM_Info info;
      ++(cpu.rip);
      read_modrm(src_sz, address_sz(), 0, modrm, &info, 1);
      
      uint8_t* src_addr;
      if( info.mode == INDIRECT )    src_addr = ram + info.flat_addr;
      else if( info.mode == DIRECT ) src_addr = info.reg_addr;

      const uint64_t src = read_signed(src_addr, src_sz);

      snprintf(str, len, "MOVSXD  %s, %s", get_reg_str(info.reg, operand_sz), modrm.str);
      exe_mov(get_reg_addr(info.reg, operand_sz), &src, operand_sz);
      return;
    }
    case 0x68: {
      const uint8_t operand_sz = not_rex_ext_operand_sz();
      const uint8_t imm_sz = MIN(operand_sz, 4);
      const uint64_t imm = read_signed(opcode+1, imm_sz);
      cpu.rip += 1 + imm_sz;

      snprintf(str, len, "PUSH  0x%lx", imm);
      exe_push(&imm, operand_sz);
      return;
    }
    case 0x69: {
      const uint8_t operand_sz = rex_ext_operand_sz();
      const uint8_t imm_sz = MIN(operand_sz, 4);
      MODRM(src_addr, imm_sz);
      const int64_t a = read_signed(src_addr, operand_sz);
      const int64_t b = read_signed(post_modrm, imm_sz);
      cpu.rip += imm_sz;

      snprintf(str, len, "IMUL  %s, %s, %c0x%lx", get_reg_str(info.reg, operand_sz),
                                                  modrm.str,
                                                  pos_neg[b<0],
                                                  ABS(b));
      exe_imul_mult_operands(operand_sz, get_reg_addr(info.reg, operand_sz), a, b);
      return;
    }
    case 0x6A: {
      const uint8_t operand_sz = not_rex_ext_operand_sz();
      const uint64_t imm = read_signed(opcode+1, 1);
      cpu.rip += 2;

      snprintf(str, len, "PUSH  0x%lx", imm);
      exe_push(&imm, operand_sz);
      return;
    }
    case 0x6B: {
      const uint8_t operand_sz = rex_ext_operand_sz();
      MODRM(src_addr, 1);
      const int64_t a = read_signed(src_addr, operand_sz);
      const int64_t b = read_signed(post_modrm, 1);
      ++(cpu.rip);

      snprintf(str, len, "IMUL  %s, %s, %c0x%lx", get_reg_str(info.reg, operand_sz),
                                                  modrm.str,
                                                  pos_neg[b<0],
                                                  ABS(b));
      exe_imul_mult_operands(operand_sz, get_reg_addr(info.reg, operand_sz), a, b);
      return;
    }
    case 0x6C:
    case 0x6D: {
      const uint8_t w = (*opcode >> 0) & 0x1;
      const uint8_t operand_sz = w ? rex_ext_operand_sz() : 1;
      const uint8_t addr_sz = address_sz();
      const uint64_t port = cpu.dx;
      ++(cpu.rip);

      snprintf(str, len, "INS  es:[%s], dx", get_reg_str(RDI, addr_sz));
      exe_ins(operand_sz, addr_sz, port);
      return;
    }
    case 0x70:
    case 0x71:
    case 0x72:
    case 0x73:
    case 0x74:
    case 0x75:
    case 0x76:
    case 0x77:
    case 0x78:
    case 0x79:
    case 0x7A:
    case 0x7B:
    case 0x7C:
    case 0x7D:
    case 0x7E:
    case 0x7F: {
      const uint8_t tttn   = *opcode & 0x0F;
      const uint8_t flag   = (*opcode & 0b1110) >> 1;
      const uint8_t negate = (*opcode & 0b0001) >> 0;
      const int64_t disp = read_signed(opcode+1, 1);
      cpu.rip += 2;

      snprintf(str, len, "J%s  %c0x%lx", cc_str[tttn], pos_neg[disp<0], ABS(disp));
      exe_jcc(flag, negate, disp);
      return;
    }
    case 0x80: {
      const uint8_t operand_sz = 1;
      MODRM(dest_addr, 1);

      switch( info.ext_opcode ) {
        case 0: {
          int64_t a = read_signed(dest_addr, 1);
          int64_t b = read_signed(post_modrm, 1);
          ++(cpu.rip);
          snprintf(str, len, "ADD  %s, %c0x%lx", modrm.str, pos_neg[b<0], ABS(b));
          exe_add(dest_addr, 1, a, b);
          return;
        }
        case 1: {
          uint64_t a = read_unsigned(dest_addr, 1);
          uint64_t b = read_unsigned(post_modrm, 1);
          ++(cpu.rip);
          snprintf(str, len, "OR  %s, 0x%lx", modrm.str, b);
          exe_or(dest_addr, 1, a, b);
          return;
        }
        case 4: {
          uint64_t a = read_unsigned(dest_addr, 1);
          uint64_t b = read_unsigned(post_modrm, 1);
          ++(cpu.rip);
          snprintf(str, len, "AND  %s, 0x%lx", modrm.str, b);
          exe_and(dest_addr, 1, a, b);
          return;
        }
        case 7: {
          int64_t a = read_signed(dest_addr, 1);
          int64_t b = read_signed(post_modrm, 1);
          ++(cpu.rip);
          snprintf(str, len, "CMP  %s, %c0x%lx", modrm.str, pos_neg[b<0], ABS(b));
          exe_cmp(a, b);
          return;
        }
        default: panic("Subop of 0x80 not implemented!");
      }
    }
    case 0x81: {
      const uint8_t operand_sz = rex_ext_operand_sz();
      const uint8_t imm_sz = MIN(operand_sz, 4);
      MODRM(dest_addr, imm_sz);

      int64_t a = read_signed(dest_addr, operand_sz);
      int64_t b = read_signed(post_modrm, imm_sz);
      cpu.rip += imm_sz;

      switch( info.ext_opcode ) {
        case 0: {
          snprintf(str, len, "ADD  %s, %c0x%lx", modrm.str, pos_neg[b<0], ABS(b));
          exe_add(dest_addr, operand_sz, a, b);
          return;
        }
        case 1: {
          snprintf(str, len, "OR  %s, %c0x%lx", modrm.str, pos_neg[b<0], ABS(b));
          exe_or(dest_addr, operand_sz, a, b);
          return;         
        }
        case 4: {
          snprintf(str, len, "AND  %s, %c0x%lx", modrm.str, pos_neg[b<0], ABS(b));
          exe_and(dest_addr, operand_sz, a, b);
          return;
        }
        case 5: {
          snprintf(str, len, "SUB  %s, %c0x%lx", modrm.str, pos_neg[b<0], ABS(b));
          exe_sub(dest_addr, operand_sz, a, b);
          return;
        }
        case 6: {
          snprintf(str, len, "XOR  %s, %c0x%lx", modrm.str, pos_neg[b<0], ABS(b));
          exe_xor(dest_addr, operand_sz, a, b);
          return;
        }
        case 7: {
          snprintf(str, len, "CMP  %s, %c0x%lx", modrm.str, pos_neg[b<0], ABS(b));
          exe_cmp(a, b);
          return;
        }
        default: panic("Subop of 0x81 not implemented!");
      }
    }
    case 0x83: {
      const uint8_t operand_sz = rex_ext_operand_sz();
      MODRM(dest_addr, 1);

      const int64_t a = read_signed(dest_addr, operand_sz);
      const int64_t b = read_signed(post_modrm, 1);
      ++(cpu.rip);

      switch( info.ext_opcode ) {
        case 0: {
          snprintf(str, len, "ADD  %s, %c0x%lx", modrm.str, pos_neg[b<0], ABS(b));
          exe_add(dest_addr, operand_sz, a, b);
          return;
        }
        case 1: {
          snprintf(str, len, "OR  %s, 0x%lx", modrm.str, (uint64_t)b & 0xFF);
          exe_or(dest_addr, operand_sz, a, b);
          return;
        }
        case 2: {
          snprintf(str, len, "ADC  %s, %c0x%lx", modrm.str, pos_neg[b<0], ABS(b));
          exe_add(dest_addr, operand_sz, a, b + GET_RFLAGS(RFLAGS_CF));
          return;
        }
        case 4: {
          snprintf(str, len, "AND  %s, %c0x%lx", modrm.str, pos_neg[b<0], ABS(b));
          exe_and(dest_addr, operand_sz, a, b);
          return;
        }
        case 5: {
          snprintf(str, len, "SUB  %s, %c0x%lx", modrm.str, pos_neg[b<0], ABS(b));
          exe_sub(dest_addr, operand_sz, a, b);
          return;
        }
        case 7: {
          snprintf(str, len, "CMP  %s, %c0x%lx", modrm.str, pos_neg[b<0], ABS(b));
          exe_cmp(a, b);
          return;
        }
        default: panic("Subop of 0x83 not implemented!");
      }
    }
    case 0x84:
    case 0x85: {
      const uint8_t w = (*opcode >> 0) & 0x1;
      const uint8_t operand_sz = w ? rex_ext_operand_sz() : 1;
      char *src_str, *dest_str;
      uint8_t *src_addr, *dest_addr;
      decode_gpr_modrm(0, operand_sz, &src_str, &src_addr, &dest_str, &dest_addr);
      uint64_t a = read_unsigned(dest_addr, operand_sz);
      uint64_t b = read_unsigned(src_addr, operand_sz);

      snprintf(str, len, "TEST  %s, %s", dest_str, src_str);
      exe_test(a, b);
      return; 
    }
    case 0x86: {
      const uint8_t operand_sz = 1;
      MODRM(addr1, 0);
      uint8_t* addr2 = get_reg_addr(info.reg, 1);

      snprintf(str, len, "XCHG  %s, %s", get_reg_str(info.reg, 1), modrm.str);
      exe_xchg(addr1, addr2, 1);
      return;
    }
    case 0x88:
    case 0x89:
    case 0x8A:
    case 0x8B: {
      const uint8_t w = (*opcode >> 0) & 0x1;
      const uint8_t d = (*opcode >> 1) & 0x1;
      const uint8_t operand_sz = w ? rex_ext_operand_sz() : 1;
      char *src_str, *dest_str;
      uint8_t *src_addr, *dest_addr;
      decode_gpr_modrm(d, operand_sz, &src_str, &src_addr, &dest_str, &dest_addr);

      snprintf(str, len, "MOV  %s, %s", dest_str, src_str);
      exe_mov(dest_addr, src_addr, operand_sz);
      return;
    }
    case 0x8C: {
      const uint8_t operand_sz = rex_ext_operand_sz();
      MODRM(dest_addr, 0);
      uint8_t* src_addr = seg_reg_addr[info.reg];

      snprintf(str, len, "MOV  %s, %s", modrm.str, seg_reg_str[info.reg]);
      exe_mov(dest_addr, src_addr, 2);
      return;
    }
    case 0x8D: {
      const uint8_t operand_sz = rex_ext_operand_sz();
      char tmp[64]; String modrm = { 63, tmp }; ModRM_Info info;
      ++(cpu.rip);
      read_modrm(operand_sz, address_sz(), 0, modrm, &info, 0);

      if( info.mode == DIRECT )
        panic("LEA only accepts indirect addressing.");
      uint8_t* dest_addr = get_reg_addr(info.reg, operand_sz);

      snprintf(str, len, "LEA  %s, %s", get_reg_str(info.reg, operand_sz), modrm.str);
      exe_mov(dest_addr, &(info.offset), operand_sz);
      return;
    }
    case 0x8E: {
      const uint8_t operand_sz = rex_ext_operand_sz();
      MODRM(src_addr, 0);

      snprintf(str, len, "MOV  %s, %s", seg_reg_str[info.reg], modrm.str);
      uint16_t segment;
      memcpy(&segment, src_addr, 2);
      set_seg_reg(info.reg, segment);
      return;
    }
    case 0x8F: {
      const uint8_t operand_sz = not_rex_ext_operand_sz();
      MODRM(dest_addr, 0);

      switch( info.ext_opcode ) {
        case 0: {
          snprintf(str, len, "POP  %s", modrm.str);
          exe_pop(dest_addr, operand_sz);
          return;
        }
        default: panic("Subop of 0x8F not implemented!");
      }
    }
    case 0x90: {
      ++(cpu.rip);
      snprintf(str, len, "NOP");
      return;
    }
    case 0x99: {
      const uint8_t operand_sz = rex_ext_operand_sz();
      ++(cpu.rip);

      snprintf(str, len, "%s", get_convert_inst_str(operand_sz));
      exe_convert(operand_sz);
      return;
    }
    case 0x9A: {
      const uint8_t operand_sz = rex_ext_operand_sz();
      const uint64_t segment = read_unsigned(opcode+1+operand_sz, 2);
      const uint64_t offset  = read_unsigned(opcode+1, operand_sz);
      cpu.rip += 1 + operand_sz + 2;
      
      snprintf(str, len, "CALL  0x%lx:0x%lx", segment, offset);
      exe_push(seg_reg_addr[CS], 2);
      exe_push(get_ip_addr_from_size(operand_sz), operand_sz);
      set_seg_reg(CS, segment);
      cpu.rip = offset;
      return;
    }
    case 0x9C: {
      const uint8_t operand_sz = not_rex_ext_operand_sz();
      ++(cpu.rip);

      snprintf(str, len, "PUSHF%c", get_str_inst_letter(operand_sz));
      exe_push(&(cpu.rflags), operand_sz);
      return;
    }
    case 0x9D: {
      const uint8_t operand_sz = not_rex_ext_operand_sz();
      ++(cpu.rip);

      snprintf(str, len, "POPF%c", get_str_inst_letter(operand_sz));
      exe_pop(&(cpu.rflags), operand_sz);
      return;
    }
    case 0xA0:
    case 0xA1:
    case 0xA2:
    case 0xA3: {
      const uint8_t w = (*opcode >> 0) & 0x1;
      const uint8_t d = (*opcode >> 1) & 0x1;
      const uint8_t operand_sz = w ? rex_ext_operand_sz() : 1;
      const uint8_t addr_sz = address_sz();
      const uint64_t imm = read_unsigned(opcode+1, addr_sz);
      cpu.rip += 1 + addr_sz;

      uint8_t *src_addr, *dest_addr;
      if( d == 0 ) {
        snprintf(str, len, "MOV  %s, %s:[0x%lx]", get_reg_str(RAX, operand_sz),
                                                  overridable_segment_str(DS),
                                                  imm);
        src_addr = ram + get_flat_address(overridable_segment(DS), imm);
        dest_addr = get_reg_addr(RAX, operand_sz);
      }
      else {
        snprintf(str, len, "MOV  %s:[0x%lx], %s", overridable_segment_str(DS),
                                                  imm,
                                                  get_reg_str(RAX, operand_sz));
        src_addr = get_reg_addr(RAX, operand_sz);
        dest_addr = ram + get_flat_address(overridable_segment(DS), imm);
      }
      exe_mov(dest_addr, src_addr, operand_sz);
      return;
    }
    case 0xA4:
    case 0xA5: {
      const uint8_t w = (*opcode >> 0) & 0x1;
      const uint8_t operand_sz = w ? rex_ext_operand_sz() : 1;
      const uint8_t addr_sz = address_sz();

      snprintf(str, len, "%sMOVS%c  es:[%s], %s:[%s]", rep_prefix_str(),
                                                       get_str_inst_letter(operand_sz),
                                                       get_reg_str(RDI, addr_sz),
                                                       overridable_segment_str(DS),
                                                       get_reg_str(RSI, addr_sz));
      ++(cpu.rip);
      exe_movs(operand_sz, addr_sz);
      return;
    }
    case 0xA6:
    case 0xA7: {
      const uint8_t w = (*opcode >> 0) & 0x1;
      const uint8_t operand_sz = w ? rex_ext_operand_sz() : 1;
      const uint8_t addr_sz = address_sz();

      snprintf(str, len, "%sCMPS%c  es:[%s], %s:[%s]", rep_prefix_str(),
                                                       get_str_inst_letter(operand_sz),
                                                       get_reg_str(RDI, addr_sz),
                                                       overridable_segment_str(DS),
                                                       get_reg_str(RSI, addr_sz));
      ++(cpu.rip);
      exe_cmps(operand_sz, addr_sz);
      return;
    }
    case 0xA8:
    case 0xA9: {
      const uint8_t w = (*opcode >> 0) & 0x1;
      const uint8_t operand_sz = w ? rex_ext_operand_sz() : 1;
      const uint8_t disp_sz = MIN(operand_sz, 4);
      const uint64_t a = read_unsigned(get_reg_addr(RAX, operand_sz), operand_sz);
      const uint64_t b = read_unsigned(opcode+1, disp_sz);
      cpu.rip += 1 + disp_sz;

      snprintf(str, len, "TEST  %s, 0x%lx", get_reg_str(RAX, operand_sz), b);
      exe_test(a, b);
      return;
    }
    case 0xAA:
    case 0xAB: {
      const uint8_t w = (*opcode >> 0) & 0x1;
      const uint8_t operand_sz = w ? rex_ext_operand_sz() : 1;
      const uint8_t addr_sz = address_sz();

      snprintf(str, len, "%sSTOS%c  es:[%s], %s", rep_prefix_str(),
                                                  get_str_inst_letter(operand_sz),
                                                  get_reg_str(RDI, addr_sz),
                                                  get_reg_str(RAX, operand_sz));
      ++(cpu.rip);
      exe_stos(operand_sz, addr_sz);
      return;
    }
    case 0xAC:
    case 0xAD: {
      const uint8_t w = (*opcode >> 0) & 0x1;
      const uint8_t operand_sz = w ? rex_ext_operand_sz() : 1;
      const uint8_t addr_sz = address_sz();

      snprintf(str, len, "%sLODS%c  %s, %s:[%s]", rep_prefix_str(),
                                                  get_str_inst_letter(operand_sz),
                                                  get_reg_str(RAX, operand_sz),
                                                  overridable_segment_str(DS),
                                                  get_reg_str(RSI, addr_sz));
      ++(cpu.rip);
      exe_lods(operand_sz, addr_sz);
      return;
    }
    case 0xAE:
    case 0xAF: {
      const uint8_t w = (*opcode >> 0) & 0x1;
      const uint8_t operand_sz = w ? rex_ext_operand_sz() : 1;
      const uint8_t addr_sz = address_sz();

      snprintf(str, len, "%sSCAS%c  %s, es:[%s]", rep_prefix_str(),
                                                  get_str_inst_letter(operand_sz),
                                                  get_reg_str(RAX, operand_sz),
                                                  get_reg_str(RDI, addr_sz));
      ++(cpu.rip);
      exe_scas(operand_sz, addr_sz);
      return;
    }
    case 0xB0:
    case 0xB1:
    case 0xB2:
    case 0xB3:
    case 0xB4:
    case 0xB5:
    case 0xB6:
    case 0xB7: {
      const uint8_t opcode_reg = read_reg_in_opcode(opcode);
      const uint64_t imm = read_unsigned(opcode+1, 1);
      cpu.rip += 2;

      snprintf(str, len, "MOV  %s, 0x%lx", get_reg_str(opcode_reg, 1), imm);
      exe_mov(get_reg_addr(opcode_reg, 1), opcode+1, 1);
      return;
    }
    case 0xB8:
    case 0xB9:
    case 0xBA:
    case 0xBB:
    case 0xBC:
    case 0xBD:
    case 0xBE:
    case 0xBF: {
      const uint8_t operand_sz = rex_ext_operand_sz();
      const uint8_t opcode_reg = read_reg_in_opcode(opcode);
      const uint64_t imm = read_unsigned(opcode+1, operand_sz);
      cpu.rip += 1 + operand_sz;

      snprintf(str, len, "MOV  %s, 0x%lx", get_reg_str(opcode_reg, operand_sz), imm);
      exe_mov(get_reg_addr(opcode_reg, operand_sz), opcode+1, operand_sz);
      return;
    }
    case 0xC1: {
      const uint8_t operand_sz = rex_ext_operand_sz();
      MODRM(dest_addr, 1);

      uint64_t a = read_unsigned(dest_addr, operand_sz);
      uint64_t b = read_unsigned(post_modrm, 1);
      if( operand_sz == 8 ) { b &= 0x3F; } else { b &= 0x1F; }
      ++(cpu.rip);

      switch( info.ext_opcode ) {
	case 1: {
          snprintf(str, len, "ROR  %s, 0x%lx", modrm.str, b); 
          exe_ror(dest_addr, operand_sz, a, b);
          return;
	}
        case 4: {
          snprintf(str, len, "SHL  %s, 0x%lx", modrm.str, b); 
          exe_shl(dest_addr, operand_sz, a, b);
          return;
        }
        case 5: {
          snprintf(str, len, "SHR  %s, 0x%lx", modrm.str, b); 
          exe_shr(dest_addr, operand_sz, a, b);
          return;
        }
        case 7: {
          snprintf(str, len, "SAR  %s, 0x%lx", modrm.str, b); 
          exe_sar(dest_addr, operand_sz, a, b);
          return;
        }
        default: panic("Subop of 0xC1 not implemented!");
      }
    }
    case 0xC2: {
      const uint64_t imm = read_unsigned(opcode+1, 2);

      snprintf(str, len, "RET 0x%lx", imm);
      exe_ret_near(not_rex_ext_operand_sz());
      cpu.rsp += imm;
      return;
    }
    case 0xC3: {
      snprintf(str, len, "RET");
      exe_ret_near(not_rex_ext_operand_sz());
      return;
    }
    case 0xC6: {
      const uint8_t operand_sz = 1;
      MODRM(dest_addr, 1);

      const uint64_t imm = read_signed(post_modrm, 1);
      ++(cpu.rip);

      switch( info.ext_opcode ) {
        case 0: {
          snprintf(str, len, "MOV  %s, 0x%lx", modrm.str, imm & 0xFF);
          exe_mov(dest_addr, &imm, operand_sz);
          return;
        }
        default: panic("Subop of 0xC6 not implemented!");
      }
    }
    case 0xC7: {
      const uint8_t operand_sz = rex_ext_operand_sz();
      const uint8_t imm_sz = MIN(operand_sz, 4);
      MODRM(dest_addr, imm_sz);

      const uint64_t imm = read_signed(post_modrm, imm_sz);
      cpu.rip += imm_sz;

      switch( info.ext_opcode ) {
        case 0: {
          snprintf(str, len, "MOV  %s, 0x%lx", modrm.str, imm);
          exe_mov(dest_addr, &imm, operand_sz);
          return;
        }
        default: panic("Subop of 0xC7 not implemented!");
      }
    }
    case 0xC9: {
      const uint8_t operand_sz = not_rex_ext_operand_sz();
      const uint8_t stack_addr_sz = stack_address_sz();
      ++(cpu.rip);

      snprintf(str, len, "LEAVE");
      exe_mov(get_reg_addr(RSP, stack_addr_sz), get_reg_addr(RBP, stack_addr_sz), stack_addr_sz);
      exe_pop(get_reg_addr(RBP, operand_sz), operand_sz);
      return;
    }
    case 0xCB: {
      snprintf(str, len, "RET");
      exe_ret_far(not_rex_ext_operand_sz());
      return;
    }
    case 0xCD: {
      const uint64_t imm = read_unsigned(opcode+1, 1);
      cpu.rip += 2;

      snprintf(str, len, "INT  0x%lx", imm);
      exe_int(imm);
      return;
    }
    case 0xCF: {
      snprintf(str, len, "IRET");
      exe_iret(rex_ext_operand_sz());
      return;
    }
    case 0xD1: {
      const uint8_t operand_sz = rex_ext_operand_sz();
      MODRM(dest_addr, 0);

      uint64_t a = read_unsigned(dest_addr, operand_sz);

      switch( info.ext_opcode ) {
        case 4: {
          snprintf(str, len, "SHL  %s, 0x1", modrm.str); 
          exe_shl(dest_addr, operand_sz, a, 1);
          return;
        }
        case 7: {
          snprintf(str, len, "SAR  %s, 0x1", modrm.str); 
          exe_sar(dest_addr, operand_sz, a, 1);
          return;
        }
        default: panic("Subop of 0xD1 not implemented!");
      }
    }
    case 0xD3: {
      const uint8_t operand_sz = rex_ext_operand_sz();
      MODRM(dest_addr, 0);

      uint64_t a = read_unsigned(dest_addr, operand_sz);
      uint64_t b = cpu.cl;
      if( operand_sz == 8 ) { b &= 0x3F; } else { b &= 0x1F; }

      switch( info.ext_opcode ) {
        case 4: {
          snprintf(str, len, "SHL  %s, cl", modrm.str); 
          exe_shl(dest_addr, operand_sz, a, b);
          return;
        }
        case 5: {
          snprintf(str, len, "SHR  %s, cl", modrm.str); 
          exe_shr(dest_addr, operand_sz, a, b);
          return;
        }
        case 7: {
          snprintf(str, len, "SAR  %s, cl", modrm.str); 
          exe_sar(dest_addr, operand_sz, a, b);
          return;
        }
        default: panic("Subop of 0xD3 not implemented!");
      }
    }
    case 0xD7: {
      const uint8_t addr_sz = address_sz();
      const uint64_t rbx = read_unsigned(get_reg_addr(RBX, addr_sz), addr_sz);
      uint8_t* addr = ram + get_flat_address(overridable_segment(DS), rbx + cpu.al);
      ++(cpu.rip);

      snprintf(str, len, "XLAT  %s:[%s+al]", overridable_segment_str(DS),
                                             get_reg_str(RBX, addr_sz));
      exe_xlat(addr);
      return;
    }
    case 0xD8: {
      switch( *(opcode+1) ) {
        case 0xC8:
        case 0xC9:
        case 0xCA:
        case 0xCB:
        case 0xCC:
        case 0xCD:
        case 0xCE:
        case 0xCF: {
          const int8_t disp = *(opcode+1) - 0xC8;
          cpu.rip += 2;

          snprintf(str, len, "FMUL  st(0), st(%d)", disp);
          exe_fmul(val_st(disp));
          return;
        }
        default: if( *(opcode+1) > 0xBF ) panic("Subop (1) of 0xD8 not implemented!");
      }

      /*
      const uint8_t operand_sz = fpu_operand_sz();
      MODRM(modrm_addr, 0);
      
      switch( info.ext_opcode ) {
        default:
      }
      */
      panic("Subop (2) of 0xD8 not implemented!");
    }
    case 0xD9: {
      switch( *(opcode+1) ) {
        case 0xC0:
        case 0xC1:
        case 0xC2:
        case 0xC3:
        case 0xC4:
        case 0xC5:
        case 0xC6:
        case 0xC7: {
          const int8_t disp = *(opcode+1) & 0b111;
          cpu.rip += 2;

          snprintf(str, len, "FLD  st(%d)", disp);
          exe_load_fpu(val_st(disp));
          return;
        }
        case 0xE0: {
          cpu.rip += 2;
          snprintf(str, len, "FCHS");
          exe_fmul(-1);
          return;
        }
        case 0xE1: {
          cpu.rip += 2;
          snprintf(str, len, "FABS");
          exe_fabs();
          return;
        }
        case 0xE8: {
          cpu.rip += 2;
          snprintf(str, len, "FLD1");
          exe_load_fpu(1);
          return;
        }
        case 0xE9: {
          cpu.rip += 2;
          snprintf(str, len, "FLDL2T");
          exe_load_fpu( log2l(10) );
          return;
        }
        case 0xEA: {
          cpu.rip += 2;
          snprintf(str, len, "FLDL2E");
          exe_load_fpu( log2l(expl(1)) );
          return;
        }
        case 0xEB: {
          cpu.rip += 2;
          snprintf(str, len, "FLDPI");
          exe_load_fpu(PI);
          return;
        }
        case 0xEC: {
          cpu.rip += 2;
          snprintf(str, len, "FLDLG2");
          exe_load_fpu( log10l(2) );
          return;
        }
        case 0xEE: {
          cpu.rip += 2;
          snprintf(str, len, "FLDZ");
          exe_load_fpu(0);
          return;
        }
        case 0xF0: {
          cpu.rip += 2;
          snprintf(str, len, "F2XM1");
          exe_f2xm1();
          return;
        }
        case 0xF1: {
          cpu.rip += 2;
          snprintf(str, len, "FYL2X");
          exe_fyl2x();
          return;
        }
        case 0xF3: {
          cpu.rip += 2;
          snprintf(str, len, "FPATAN");
          exe_fpatan();
          return;
        }
        case 0xF7: {
          cpu.rip += 2;
          snprintf(str, len, "FINCSTP");
          exe_fincstp();
          return;
        }
        case 0xF8: {
          cpu.rip += 2;
          snprintf(str, len, "FPREM");
          exe_fprem();
          return;
        }
        case 0xFA: {
          cpu.rip += 2;
          snprintf(str, len, "FSQRT");
          exe_fsqrt();
          return;
        }
        case 0xFC: {
          cpu.rip += 2;
          snprintf(str, len, "FRNDINT");
          exe_frndint();
          return;
        }
        case 0xFD: {
          cpu.rip += 2;
          snprintf(str, len, "FSCALE");
          exe_fscale();
          return;
        }
        case 0xFE: {
          cpu.rip += 2;
          snprintf(str, len, "FSIN");
          exe_fsin();
          return;
        }
        case 0xFF: {
          cpu.rip += 2;
          snprintf(str, len, "FCOS");
          exe_fcos();
          return;
        }
        default: if( *(opcode+1) > 0xBF ) panic("Subop (1) of 0xD9 not implemented!");
      }

      const uint8_t operand_sz = fpu_operand_sz();
      MODRM(modrm_addr, 0);
      
      switch( info.ext_opcode ) {
        case 5: {
          snprintf(str, len, "FLDCW  %s", modrm.str);
          memcpy(&(fpu.control), modrm_addr, 2);
          return;
        }
        case 7: {
          snprintf(str, len, "FNSTCW  %s", modrm.str);
          exe_mov(modrm_addr, &(fpu.control), 2);
          return;
        }
      }
      panic("Subop (2) of 0xD9 not implemented!");
    }
    case 0xDB: {
      if( *(opcode+1) == 0xE3 ) {
        cpu.rip += 2;
        snprintf(str, len, "FNINIT");
        exe_fninit();
        return;
      }
      panic("Subop of 0xDB not implemented!");
    }
    case 0xDC: {
      const uint8_t operand_sz = fpu_operand_sz();
      MODRM(modrm_addr, 0);

      switch( info.ext_opcode ) {
        case 0: {
          snprintf(str, len, "FADD  %s", modrm.str);
          const f80_t imm = *(f64_t*)modrm_addr;
          exe_fadd(imm);
          return;
        }
        case 1: {
          snprintf(str, len, "FMUL  %s", modrm.str);
          const f80_t imm = *(f64_t*)modrm_addr;
          exe_fmul(imm);
          return;
        }
        case 4: {
          snprintf(str, len, "FSUB  %s", modrm.str);
          const f80_t imm = *(f64_t*)modrm_addr;
          exe_fsub(imm);
          return;
        }
        case 5: {
          snprintf(str, len, "FSUBR  %s", modrm.str);
          const f80_t imm = *(f64_t*)modrm_addr;
          exe_fsubr(imm);
          return;
        }
        case 6: {
          snprintf(str, len, "FDIV  %s", modrm.str);
          const f80_t imm = *(f64_t*)modrm_addr;
          exe_fdiv(imm);
          return;
        }
        case 7: {
          snprintf(str, len, "FDIVR  %s", modrm.str);
          const f80_t imm = *(f64_t*)modrm_addr;
          exe_fdivr(imm);
          return;
        }
      }
      panic("Subop of 0xDC not implemented!");
    }
    case 0xDD: {
      switch( *(opcode+1) ) {
        case 0xC0:
        case 0xC1:
        case 0xC2:
        case 0xC3:
        case 0xC4:
        case 0xC5:
        case 0xC6:
        case 0xC7: {
          cpu.rip += 2;
          snprintf(str, len, "FFREE");
          exe_ffree( *(opcode+1) & 0b111 );
          return;
        }
	default: if( *(opcode+1) > 0xBF ) panic("Subop (1) of 0xDD not implemented!");
      }

      const uint8_t operand_sz = fpu_operand_sz();
      MODRM(modrm_addr, 0);

      switch( info.ext_opcode ) {
        case 0: {
          snprintf(str, len, "FLD  %s", modrm.str);
          const f80_t imm = *(f64_t*)modrm_addr;
          exe_load_fpu(imm);
          return;
        }
        case 1: {
          snprintf(str, len, "FISTTP  %s", modrm.str);
          const int64_t st0 = val_st(0);
          exe_mov(modrm_addr, &st0, 8);
          pop_fpu();
          return;
        }
        case 2: {
          snprintf(str, len, "FST  %s", modrm.str);
          const f64_t st0 = val_st(0);
          exe_mov(modrm_addr, &st0, 8);
          return;
        }
        case 3: {
          snprintf(str, len, "FSTP  %s", modrm.str);
          const f64_t st0 = val_st(0);
          exe_mov(modrm_addr, &st0, 8);
          pop_fpu();
          return;
        }
      }
      panic("Subop (2) of 0xDD not implemented!");
    }
    case 0xDE: {
      switch( *(opcode+1) ) {
        case 0xC1: {
          cpu.rip += 2;
          snprintf(str, len, "FADDP");
          exe_faddp();
          return;
        }
        case 0xC9: {
          cpu.rip += 2;
          snprintf(str, len, "FMULP");
          exe_fmulp();
          return;
        }
        case 0xE1: {
          cpu.rip += 2;
          snprintf(str, len, "FSUBRP");
          exe_fsubrp();
          return;
        }
        case 0xF1: {
          cpu.rip += 2;
          snprintf(str, len, "FDIVRP");
          exe_fdivrp();
          return;
        }
        case 0xF9: {
          cpu.rip += 2;
          snprintf(str, len, "FDIVP");
          exe_fdivp();
          return;
        }
      }
      panic("Subop of 0xDE not implemented!");
    }
    case 0xDF: {
      switch( *(opcode+1) ) {
	case 0xE0: {
          cpu.rip += 2;
          snprintf(str, len, "FNSTSW  ax");
          exe_mov(&(cpu.ax), &(fpu.status), 2);
          return;
	}
        case 0xF0:
        case 0xF1:
        case 0xF2:
        case 0xF3:
        case 0xF4:
        case 0xF5:
        case 0xF6:
        case 0xF7: {
          const int8_t disp = *(opcode+1) & 0b111;
          cpu.rip += 2;

          snprintf(str, len, "FCOMIP  st(%d)", disp);
          exe_fcomip(disp);
          return;
        }
	default: if( *(opcode+1) > 0xBF ) panic("Subop (1) of 0xDF not implemented!");
      }

      switch( get_ext_opcode_in_modrm(opcode+1) ) {
        case 5: {
          const uint8_t operand_sz = fpu_operand_sz();
          MODRM(src_addr, 0);
          const f80_t imm = read_signed(src_addr, 8);

          snprintf(str, len, "FILD  %s", modrm.str);
          exe_load_fpu(imm);
          return;
        }
      }
      panic("Subop (2) of 0xDF not implemented!");
    }
    case 0xE2: {
      const int64_t disp = read_signed(opcode+1, 1);
      cpu.rip += 2;

      snprintf(str, len, "LOOP  %c0x%lx", pos_neg[disp<0], ABS(disp));
      exe_loop(address_sz(), disp);
      return;
    }
    case 0xE4: {
      uint8_t* dest_addr = get_reg_addr(RAX, 1);
      const uint64_t port = read_unsigned(opcode+1, 1);
      cpu.rip += 2;

      snprintf(str, len, "IN  %s, 0x%lx", get_reg_str(RAX, 1), port);
      exe_in(dest_addr, 1, port);
      return;
    }
    case 0xE6: {
      uint8_t* src_addr = get_reg_addr(RAX, 1);
      const uint64_t port = read_unsigned(opcode+1, 1);
      cpu.rip += 2;

      snprintf(str, len, "OUT  0x%lx, %s", port, get_reg_str(RAX, 1));
      exe_out(src_addr, 1, port);
      return;     
    }
    case 0xE8: {
      const uint8_t operand_sz = not_rex_ext_operand_sz();
      const uint8_t disp_sz    = MIN(operand_sz, 4);
      const int64_t disp = read_signed(opcode+1, disp_sz);
      cpu.rip += 1 + disp_sz;
      
      snprintf(str, len, "CALL  %c0x%lx", pos_neg[disp<0], ABS(disp));
      exe_call_rel(operand_sz, disp);
      return;
    }
    case 0xE9: {
      const uint8_t disp_sz = MIN(not_rex_ext_operand_sz(), 4);
      const int64_t disp = read_signed(opcode+1, disp_sz);
      cpu.rip += 1 + disp_sz;
      
      snprintf(str, len, "JMP  %c0x%lx", pos_neg[disp<0], ABS(disp));
      exe_jmp_rel(disp);
      return;
    }
    case 0xEA: {
      const uint8_t operand_sz = rex_ext_operand_sz();
      const uint64_t segment = read_unsigned(opcode+1+operand_sz, 2);
      const uint64_t offset  = read_unsigned(opcode+1, operand_sz);
      
      snprintf(str, len, "JMP  0x%lx:0x%lx", segment, offset);
      set_seg_reg(CS, segment);
      cpu.rip = offset;
      return;
    }
    case 0xEB: {
      const int64_t disp = read_signed(opcode+1, 1);
      cpu.rip += 2;
      
      snprintf(str, len, "JMP  %c0x%lx", pos_neg[disp<0], ABS(disp));
      exe_jmp_rel(disp);
      return;
    }
    case 0xEC: {
      uint8_t* dest_addr = get_reg_addr(RAX, 1);
      const uint64_t port = cpu.dx;
      ++(cpu.rip);

      snprintf(str, len, "IN  %s, dx", get_reg_str(RAX, 1));
      exe_in(dest_addr, 1, port);
      return;
    }
    case 0xEE:
    case 0xEF: {
      const uint8_t w = (*opcode >> 0) & 0x1;
      const uint8_t operand_sz = w ? rex_ext_operand_sz() : 1;
      uint8_t* src_addr = get_reg_addr(RAX, operand_sz);
      const uint64_t port = cpu.dx;
      ++(cpu.rip);

      snprintf(str, len, "OUT  dx, %s", get_reg_str(RAX, operand_sz));
      exe_out(src_addr, operand_sz, port);
      return;
    }
    case 0xF6: {
      const uint8_t operand_sz = 1;
      MODRM(src_addr, 1);
      const uint64_t a = read_unsigned(src_addr, 1);
      const uint64_t b = read_unsigned(post_modrm, 1);
      ++(cpu.rip);

      switch( info.ext_opcode ) {
        case 0: {
          snprintf(str, len, "TEST  %s, 0x%lx", modrm.str, b);
          exe_test(a, b);
          return;
        }
        default: panic("Subop of 0xF6 not implemented!");
      }
    }
    case 0xF7: {
      const uint8_t operand_sz = rex_ext_operand_sz();
      const uint8_t imm_sz = MIN(operand_sz, 4);

      switch( get_ext_opcode_in_modrm(opcode+1) ) {
        case 0: {
          MODRM(src_addr, imm_sz);
          const uint64_t a = read_unsigned(src_addr, operand_sz);
          const uint64_t b = read_unsigned(post_modrm, imm_sz);
          cpu.rip += imm_sz;
          snprintf(str, len, "TEST  %s, 0x%lx", modrm.str, b);
          exe_test(a, b);
          return;
        }
        case 2: {
          MODRM(src_addr, 0);
          const uint64_t a = read_unsigned(src_addr, operand_sz);
          snprintf(str, len, "NOT  %s", modrm.str);
          exe_not(src_addr, operand_sz, a);
          return;
        }
        case 3: {
          MODRM(src_addr, 0);
          const int64_t a = read_signed(src_addr, operand_sz);
          snprintf(str, len, "NEG  %s", modrm.str);
          exe_neg(src_addr, operand_sz, a);
          return;
        }
        case 4: {
          MODRM(src_addr, 0);
          const uint64_t a = read_unsigned(src_addr, operand_sz);
          const uint64_t b = read_unsigned(get_reg_addr(RAX, operand_sz), operand_sz);
          snprintf(str, len, "MUL  %s", modrm.str);
          exe_mul(operand_sz, a, b);
          return;
        }
        case 5: {
          MODRM(src_addr, 0);
          const int64_t a = read_signed(src_addr, operand_sz);
          const int64_t b = read_signed(get_reg_addr(RAX, operand_sz), operand_sz);
          snprintf(str, len, "IMUL  %s", modrm.str);
          exe_imul_one_operand(operand_sz, a, b);
          return;
        }
        case 6: {
          MODRM(src_addr, 0);
          const uint64_t a = read_unsigned(src_addr, operand_sz);
          snprintf(str, len, "DIV  %s", modrm.str);
          exe_div(operand_sz, a);
          return;
        }
        case 7: {
          MODRM(src_addr, 0);
          const int64_t a = read_signed(src_addr, operand_sz);
          snprintf(str, len, "IDIV  %s", modrm.str);
          exe_idiv(operand_sz, a);
          return;
        }
        default: panic("Subop of 0xF7 not implemented!");
      }
    }
    case 0xFA: {
      ++(cpu.rip);
      
      snprintf(str, len, "CLI");
      CLEAR_FLAG(RFLAGS_IF);
      return;
    }
    case 0xFB: {
      ++(cpu.rip);

      snprintf(str, len, "STI");
      SET_FLAG(RFLAGS_IF);
      return;
    }
    case 0xFC: {
      ++(cpu.rip);

      snprintf(str, len, "CLD");
      CLEAR_FLAG(RFLAGS_DF);
      return;
    }
    case 0xFE: {
      switch( get_ext_opcode_in_modrm(opcode+1) ) {
        case 0: {
          const uint8_t operand_sz = 1;
          MODRM(dest_addr, 0);

          snprintf(str, len, "INC  %s", modrm.str);
          exe_inc(dest_addr, 1);
          return;
        }
        default: panic("Subop of 0xFF not implemented!");
      }
    }
    case 0xFF: {
      switch( get_ext_opcode_in_modrm(opcode+1) ) {
        case 0: {
          const uint8_t operand_sz = rex_ext_operand_sz();
          MODRM(dest_addr, 0);

          snprintf(str, len, "INC  %s", modrm.str);
          exe_inc(dest_addr, operand_sz);
          return;
        }
        case 1: {
          const uint8_t operand_sz = rex_ext_operand_sz();
          MODRM(dest_addr, 0);

          snprintf(str, len, "DEC  %s", modrm.str);
          exe_dec(dest_addr, operand_sz);
          return;
        }
        case 2: {
          const uint8_t operand_sz = not_rex_ext_operand_sz();
          MODRM(src_addr, 0);
          const uint64_t addr = read_unsigned(src_addr, operand_sz);

          snprintf(str, len, "CALL  %s", modrm.str);
          exe_call_abs(operand_sz, addr);
          return;
        }
        case 4: {
	        const uint8_t operand_sz = not_rex_ext_operand_sz();
          MODRM(src_addr, 0);

	        uint64_t offset = 0;
	        memcpy(&offset, src_addr, operand_sz);

          snprintf(str, len, "JMP  %s", modrm.str);
          cpu.rip = get_flat_address(CS, offset);
          return;
	      }
        case 6: {
          const uint8_t operand_sz = not_rex_ext_operand_sz();
          MODRM(dest_addr, 0);

          snprintf(str, len, "PUSH  %s", modrm.str);
          exe_push(dest_addr, operand_sz);
          return;
        }
        default: panic("Subop of 0xFF not implemented!");
      }
    }
    default: panic("The 1 byte instruction was not implemented!");
  }
}

static void exe_cpuid(void) {
  switch( cpu.eax ) {
    case 0x1: {
      const uint8_t cache_line_size = 128;
      cpu.ebx = ((uint64_t)cache_line_size / 8) << 8;
      cpu.edx = 0; // No APIC aka singlecore CPU
      break;
    }
    case 0x80000000: {
      // Maximum input value for CPUID of the form 80 00 00 0*
      cpu.eax = 0x80000008;
      break;
    }
    case 0x80000001: {
      // EAX = extended processor signature and feature bits (???)
      // EBX = reserved
      // ECX = some shit
      // EDX = some shit + bit 26: 1GB pages available
      //                 + bit 29: 64-bit mode available
      cpu.edx = (1 << 29) | (1 << 26);
      break;
    }
    default: panic("Value in EAX can't be handled by CPUID!");
  }
}

static void exe_bt(uint8_t* bit_base, uint64_t bit_offset, uint8_t ext_opcode) {
  const uint8_t bit = (bit_base[bit_offset/8] >> (bit_offset%8)) & 0x1;
  UPDATE_FLAG(bit, RFLAGS_CF)

  switch( ext_opcode ) {
    case 5: {
      // BTS set bit
      bit_base[bit_offset/8] |= (uint8_t)1 << (bit_offset%8);
      break;
    }
    case 6: {
      // BTR clear bit
      bit_base[bit_offset/8] &= ~((uint8_t)1 << (bit_offset%8));
      break;
    }
    case 7: {
      // BTC complement bit
      bit_base[bit_offset/8] ^= (uint8_t)1 << (bit_offset%8);
      break;
    }
  }
}

char* bt_inst_str[] = {"","S","R","C"};

static void exe_lgdt(uint8_t* src_addr, uint8_t operand_sz) {
  cpu.gdtr.limit = read_unsigned(src_addr, 2);
  uint64_t base_addr = 0;
  
  switch( operand_sz ) {
    case 2: {
      base_addr = read_unsigned(src_addr + 2, 3);
      break;
    }
    case 4: {
      base_addr = read_unsigned(src_addr + 2, 4);
      break;
    }
    case 8: {
      base_addr = read_unsigned(src_addr + 2, 8);
      break;
    }
  }
  cpu.gdtr.base = base_addr;
}

static void exe_lidt(uint8_t* src_addr, uint8_t operand_sz) {
  cpu.idtr.limit = read_unsigned(src_addr, 2);
  uint64_t base_addr = 0;
  
  switch( operand_sz ) {
    case 2: {
      base_addr = read_unsigned(src_addr + 2, 3);
      break;
    }
    case 4: {
      base_addr = read_unsigned(src_addr + 2, 4);
      break;
    }
    case 8: {
      base_addr = read_unsigned(src_addr + 2, 8);
      break;
    }
  }
  cpu.idtr.base = base_addr;
}

static void exe_bsf(uint8_t* dest_addr, uint8_t dest_sz, uint64_t a) {
  if( a ) {
    uint64_t index = 0;
    while( (a & ((uint64_t)1 << index)) == 0 ) ++index;
    exe_mov(dest_addr, &index, dest_sz);
  }
  update_zf_flag(a);
}

static void exe_bsr(uint8_t* dest_addr, uint8_t dest_sz, uint64_t a) {
  if( a ) {
    uint64_t index = 63;
    while( (a & ((uint64_t)1 << index)) == 0 ) --index;
    exe_mov(dest_addr, &index, dest_sz);
  }
  update_zf_flag(a);
}

static void exe_cmovcc(uint8_t flag, uint8_t negate, uint8_t* dest_addr, uint8_t* src_addr, uint8_t operand_sz) {
  if( eval_cond(flag, negate) )
    exe_mov(dest_addr, src_addr, operand_sz);
}

static void exe_setcc(uint8_t flag, uint8_t negate, uint8_t* dest_addr) {
  uint8_t cond = eval_cond(flag, negate);
  exe_mov(dest_addr, &cond, 1);
}

char* ctrl_reg_str[] = {"cr0","cr1","cr2","cr3","cr4","cr5","cr6","cr7","cr8","cr9","cr10","cr11","cr12","cr13","cr14","cr15"};

uint64_t* ctrl_reg_addr[] = {&(cpu.cr0),&(cpu.cr1),&(cpu.cr2),&(cpu.cr3),&(cpu.cr4)};

static char* get_ctrl_reg_str(uint8_t index) {
  if( prefixes.rex.present )
    index |= prefixes.rex.r << 3;
  
  return ctrl_reg_str[index];
}

static uint64_t* get_ctrl_reg_addr(uint8_t index) {
  if( prefixes.rex.present )
    index |= prefixes.rex.r << 3;
  
  if( index > 4 )
    panic("cr5 and up are not implemented!");

  return ctrl_reg_addr[index];
}

static void decode_two_byte_opcode(String assembly) {
  uint32_t len = assembly.len;
  char* str = assembly.str;
  uint8_t* opcode = ram_addr_ip();

  switch( *opcode ) {
    case 0x01: {
      if( get_ext_opcode_in_modrm(opcode+1) == 7 ) {
        // affects the Translation Lookaside Buffer, which is not emulated
	      char tmp[64]; String modrm = { 63, tmp }; ModRM_Info info;
        ++(cpu.rip);
        read_modrm(not_rex_ext_operand_sz(), address_sz(), 0, modrm, &info, 0);

	      if( info.mode == DIRECT )
	        panic("INVLPG only accepts indirect addressing.");

        snprintf(str, len, "INVLPG  %s", modrm.str);
	      return;
      }

      const uint8_t operand_sz = not_rex_ext_operand_sz();
      MODRM(src_addr, 0);
      if( info.mode == DIRECT )
        panic("Wait, that's illegal! Direct memory addressing with 0F 01 is not allowed.");
      
      switch( info.ext_opcode ) {
        case 2: {
          snprintf(str, len, "LGDT  %s", modrm.str);
          exe_lgdt(src_addr, operand_sz);
          return;
        }
        case 3: {
          snprintf(str, len, "LIDT  %s", modrm.str);
          exe_lidt(src_addr, operand_sz);
          return;
        }
        default: panic("Subop of 0x0F 0x01 not implemented!");
      }
    }
    case 0x20: {
      const uint8_t operand_sz = four_or_eight_operand_sz();
      MODRM(dest_addr, 0);
      if( info.mode == INDIRECT )
        panic("Wait, that's illegal! Indirect memory addressing with 0F 20 is not allowed.");

      snprintf(str, len, "MOV  %s, %s", modrm.str, get_ctrl_reg_str(info.reg));
      exe_mov(dest_addr, get_ctrl_reg_addr(info.reg), operand_sz);
      return;
    }
    case 0x22: {
      const uint8_t operand_sz = four_or_eight_operand_sz();
      MODRM(src_addr, 0);
      if( info.mode == INDIRECT )
        panic("Wait, that's illegal! Indirect memory addressing with 0F 22 is not allowed.");

      snprintf(str, len, "MOV  %s, %s", get_ctrl_reg_str(info.reg), modrm.str);
      exe_mov(get_ctrl_reg_addr(info.reg), src_addr, operand_sz);
      return;
    }
    case 0x30: {
      ++(cpu.rip);

      snprintf(str, len, "WRMSR");
      switch( cpu.ecx ) {
        case 0xC0000080: {
          cpu.IA32_EFER = ((uint64_t)cpu.edx << 32) | (cpu.eax);
          return;
        }
        case 0xC0000100: {
          cpu.fs_cache.base_addr = ((uint64_t)cpu.edx << 32) | (cpu.eax);
          return;
        }
        case 0xC0000101: {
          cpu.gs_cache.base_addr = ((uint64_t)cpu.edx << 32) | (cpu.eax);
          return;
        }
        default: panic("Trying to write to unsupported MSR!");
      }
    }
    case 0x31: {
      ++(cpu.rip);
      snprintf(str, len, "RDTSC");
      cpu.eax = inst_counter & 0xFFFFFFFF;
      cpu.edx = inst_counter >> 32;
      return;
    }
    case 0x40:
    case 0x41:
    case 0x42:
    case 0x43:
    case 0x44:
    case 0x45:
    case 0x46:
    case 0x47:
    case 0x48:
    case 0x49:
    case 0x4A:
    case 0x4B:
    case 0x4C:
    case 0x4D:
    case 0x4E:
    case 0x4F: {
      const uint8_t operand_sz = rex_ext_operand_sz();
      MODRM(src_addr, 0);

      const uint8_t tttn   = *opcode & 0x0F;
      const uint8_t flag   = (*opcode & 0b1110) >> 1;
      const uint8_t negate = (*opcode & 0b0001) >> 0;

      snprintf(str, len, "CMOV%s  %s, %s", cc_str[tttn], get_reg_str(info.reg, operand_sz), modrm.str);
      exe_cmovcc(flag, negate, get_reg_addr(info.reg, operand_sz), src_addr, operand_sz);
      return;
    }
    case 0x80:
    case 0x81:
    case 0x82:
    case 0x83:
    case 0x84:
    case 0x85:
    case 0x86:
    case 0x87:
    case 0x88:
    case 0x89:
    case 0x8A:
    case 0x8B:
    case 0x8C:
    case 0x8D:
    case 0x8E:
    case 0x8F: {
      const uint8_t disp_sz = MIN(rex_ext_operand_sz(), 4);
      const uint8_t tttn   = *opcode & 0x0F;
      const uint8_t flag   = (*opcode & 0b1110) >> 1;
      const uint8_t negate = (*opcode & 0b0001) >> 0;
      const int64_t disp = read_signed(opcode+1, disp_sz);
      cpu.rip += 1 + disp_sz;

      snprintf(str, len, "J%s  %c0x%lx", cc_str[tttn], pos_neg[disp<0], ABS(disp));
      exe_jcc(flag, negate, disp);
      return;
    }
    case 0x90:
    case 0x91:
    case 0x92:
    case 0x93:
    case 0x94:
    case 0x95:
    case 0x96:
    case 0x97:
    case 0x98:
    case 0x99:
    case 0x9A:
    case 0x9B:
    case 0x9C:
    case 0x9D:
    case 0x9E:
    case 0x9F: {
      const uint8_t operand_sz = 1;
      MODRM(dest_addr, 0);

      const uint8_t tttn   = *opcode & 0x0F;
      const uint8_t flag   = (*opcode & 0b1110) >> 1;
      const uint8_t negate = (*opcode & 0b0001) >> 0;

      snprintf(str, len, "SET%s  %s", cc_str[tttn], modrm.str);
      exe_setcc(flag, negate, dest_addr);
      return;
    }
    case 0xA2: {
      ++(cpu.rip);
      snprintf(str, len, "CPUID");
      exe_cpuid();
      return;
    }
    case 0xA3: {
      const uint8_t operand_sz = rex_ext_operand_sz();
      MODRM(bit_base, 0);

      uint64_t bit_offset = read_unsigned(get_reg_addr(info.reg, operand_sz), operand_sz);

      if( info.mode == DIRECT )
        bit_offset %= operand_sz*8;

      snprintf(str, len, "BT  %s, %s", modrm.str, get_reg_str(info.reg, operand_sz));
      exe_bt(bit_base, bit_offset, 4);
      return;
    }
    case 0xAB: {
      const uint8_t operand_sz = rex_ext_operand_sz();
      MODRM(bit_base, 0);

      uint64_t bit_offset = read_unsigned(get_reg_addr(info.reg, operand_sz), operand_sz);

      if( info.mode == DIRECT )
        bit_offset %= operand_sz*8;

      snprintf(str, len, "BTS  %s, %s", modrm.str, get_reg_str(info.reg, operand_sz));
      exe_bt(bit_base, bit_offset, 5);
      return;
    }
    case 0xAD: {
      const uint8_t operand_sz = rex_ext_operand_sz();
      MODRM(dest_addr, 0);

      uint64_t a = read_unsigned(dest_addr, operand_sz);
      uint64_t b = read_unsigned(get_reg_addr(info.reg, operand_sz), operand_sz);
      if( operand_sz == 8 ) { b &= 0x3F; } else { b &= 0x1F; }

      snprintf(str, len, "SHRD  %s, %s, cl", modrm.str, get_reg_str(info.reg, operand_sz)); 
      exe_shrd(dest_addr, operand_sz, a, b);
      return;
    }
    case 0xAE: {
      const uint8_t operand_sz = rex_ext_operand_sz();
      MODRM(dest_addr, 0);

      switch( info.ext_opcode ) {
        case 0: {
          if( !(op_mode == LONG_MODE && cpu.cs_cache.l && prefixes.rex.present && prefixes.rex.w) )
            panic("FXSAVE is only implemented in 64 bit mode with REX.W == 1!");

          snprintf(str, len, "FXSAVE64  %s", modrm.str);
          exe_fxsave64(dest_addr);
          return;
        }
        case 1: {
          if( !(op_mode == LONG_MODE && cpu.cs_cache.l && prefixes.rex.present && prefixes.rex.w) )
            panic("FXRSTOR is only implemented in 64 bit mode with REX.W == 1!");

          snprintf(str, len, "FXRSTOR64  %s", modrm.str);
          exe_fxrstor64(dest_addr);
          return;
        }
        default: panic("Subop of 0x0F 0xAE not implemented!");
      }
    }
    case 0xB3: {
      const uint8_t operand_sz = rex_ext_operand_sz();
      MODRM(bit_base, 0);

      uint64_t bit_offset = read_unsigned(get_reg_addr(info.reg, operand_sz), operand_sz);

      if( info.mode == DIRECT )
        bit_offset %= operand_sz*8;

      snprintf(str, len, "BTR  %s, %s", modrm.str, get_reg_str(info.reg, operand_sz));
      exe_bt(bit_base, bit_offset, 6);
      return;
    }
    case 0xB6:
    case 0xB7: {
      const uint8_t w = (*opcode >> 0) & 0x1;
      const uint8_t src_sz = w ? 2 : 1;
      const uint8_t operand_sz = rex_ext_operand_sz();
      char tmp[64]; String modrm = { 63, tmp }; ModRM_Info info;
      ++(cpu.rip);
      read_modrm(src_sz, address_sz(), 0, modrm, &info, 1);
      
      uint8_t* src_addr;
      if( info.mode == INDIRECT )    src_addr = ram + info.flat_addr;
      else if( info.mode == DIRECT ) src_addr = info.reg_addr;

      const uint64_t src = read_unsigned(src_addr, src_sz);

      snprintf(str, len, "MOVZX  %s, %s", get_reg_str(info.reg, operand_sz), modrm.str);
      exe_mov(get_reg_addr(info.reg, operand_sz), &src, operand_sz);
      return;
    }
    case 0xBA: {
      const uint8_t operand_sz = rex_ext_operand_sz();
      MODRM(bit_base, 1);

      uint64_t bit_offset = read_unsigned(post_modrm, 1);

      if( info.mode == DIRECT )
        bit_offset %= operand_sz*8;

      ++(cpu.rip);

      switch( info.ext_opcode ) {
        case 4:
        case 5:
        case 6:
        case 7: {
          snprintf(str, len, "BT%s  %s, 0x%lx", bt_inst_str[info.reg - 4], modrm.str, bit_offset);
          exe_bt(bit_base, bit_offset, info.ext_opcode);
          return;
        }
        default: panic("Subop of 0x0F 0xBA not implemented!");
      }
    }
    case 0xBC: {
      const uint8_t operand_sz = rex_ext_operand_sz();
      MODRM(src_addr, 0);
      const uint64_t a = read_unsigned(src_addr, operand_sz);

      snprintf(str, len, "BSF  %s, %s", get_reg_str(info.reg, operand_sz), modrm.str);
      exe_bsf(get_reg_addr(info.reg, operand_sz), operand_sz, a);
      return;
    }
    case 0xBE:
    case 0xBF: {
      const uint8_t w = (*opcode >> 0) & 0x1;
      const uint8_t src_sz = w ? 2 : 1;
      const uint8_t operand_sz = rex_ext_operand_sz();
      char tmp[64]; String modrm = { 63, tmp }; ModRM_Info info;
      ++(cpu.rip);
      read_modrm(src_sz, address_sz(), 0, modrm, &info, 1);
      
      uint8_t* src_addr;
      if( info.mode == INDIRECT )    src_addr = ram + info.flat_addr;
      else if( info.mode == DIRECT ) src_addr = info.reg_addr;

      const uint64_t src = read_signed(src_addr, src_sz);

      snprintf(str, len, "MOVSX  %s, %s", get_reg_str(info.reg, operand_sz), modrm.str);
      exe_mov(get_reg_addr(info.reg, operand_sz), &src, operand_sz);
      return;
    }
    case 0xBD: {
      const uint8_t operand_sz = rex_ext_operand_sz();
      MODRM(src_addr, 0);
      const uint64_t a = read_unsigned(src_addr, operand_sz);

      snprintf(str, len, "BSR  %s, %s", get_reg_str(info.reg, operand_sz), modrm.str);
      exe_bsr(get_reg_addr(info.reg, operand_sz), operand_sz, a);
      return;
    }
    default: panic("The 2 byte instruction was not implemented!");
  }
}

static void read_and_decode_opcode(String assembly) {
  if( *ram_addr_ip() == 0x0F ) {
    ++(cpu.rip);
    if( *ram_addr_ip() == 0x38 || *ram_addr_ip() == 0x3A ) {
      panic("3 byte opcodes not supported!");
    }
    else {
      decode_two_byte_opcode(assembly);
    }
  }
  else {
    decode_one_byte_opcode(assembly);
  }
}

void decode_instruction(String assembly) {
  prefixes = (InstructionPrefixes){ 0 };
  panic_rip = cpu.rip;

  check_legacy_prefixes();

  if( op_mode == LONG_MODE && cpu.cs_cache.l )
    check_rex_prefix();
  
  read_and_decode_opcode(assembly);

  cpu_operation_mode_transition();
}

#endif
