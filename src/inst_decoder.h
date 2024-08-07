#ifndef _INST_DECODER_H_
#define _INST_DECODER_H_

#include <stdlib.h>
#include <stdint.h>

#include "x64_cpu.h"
#include "string_struct.h"

#define ABS(x) ((x) < 0) ? -(x) : (x)
#define MIN(x, y) ((x) < (y)) ? (x) : (y)

#define SET_FLAG(flag)   cpu.rflags |= flag
#define CLEAR_FLAG(flag) cpu.rflags &= ~(flag)
#define UPDATE_FLAG(expr, flag) if( expr ) { SET_FLAG(flag); } else { CLEAR_FLAG(flag); }

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
extern uint8_t* ram;

extern void panic(const char* msg);

static uint8_t* ram_addr_ip(void) {
  return ram + get_flat_address(cpu.cs, get_ip());
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

uint64_t get_operand_sz_ip(uint8_t operand_sz) {
  switch( operand_sz ) {
    case 2: return cpu.ip;
    case 4: return cpu.eip;
    case 8: return cpu.rip;
  }
}

static uint64_t get_sp(void) {
  switch( op_mode ) {
    case REAL_MODE:      return cpu.sp;
    case PROTECTED_MODE: panic("get_sp for 32 bit mode isn't implemented!");
    case LONG_MODE:      return cpu.rsp;
  }
}

static uint8_t not_rex_ext_operand_sz(void) {
  switch( op_mode ) {
    case REAL_MODE:      return prefixes.g3.present ? 4 : 2;
    case PROTECTED_MODE: return prefixes.g3.present ? 2 : 4;
    case LONG_MODE:      return prefixes.g3.present ? 2 : 8;
  }
}

static uint8_t rex_ext_operand_sz(void) {
  switch( op_mode ) {
    case REAL_MODE:      return prefixes.g3.present ? 4 : 2;
    case LONG_MODE:      if( prefixes.rex.present && prefixes.rex.w ) return 8;
    case PROTECTED_MODE: return prefixes.g3.present ? 2 : 4;
  }
}

static uint8_t address_sz(void) {
  switch( op_mode ) {
    case REAL_MODE:      return prefixes.g4.present ? 4 : 2;
    case PROTECTED_MODE: return prefixes.g4.present ? 2 : 4;
    case LONG_MODE:      return prefixes.g4.present ? 4 : 8;
  }
}

static uint8_t read_reg_in_opcode(uint8_t* rip) {
  uint8_t index = (*rip) & 0b00000111;
  if( prefixes.rex.present )
    index |= prefixes.rex.b << 3;
  return index;
}

static uint64_t read_immediate(uint8_t* rip, uint8_t size) {
  uint64_t imm = 0;
  for(size_t i = 0; i < size; ++i) {
    imm |= (uint64_t)(*rip) << (i<<3);
    ++rip;
  }
  return imm;
}

static int64_t read_displacement(uint8_t* rip, uint8_t size) {
  uint64_t disp = 0;
  for(uint64_t i = 0; i < size; ++i) {
    disp |= (uint64_t)(*rip) << (i<<3);
    ++rip;
  }
  // sign extension
  const uint8_t sign = (disp >> (size*8 - 1)) & 0x1;
  const uint64_t fill = sign ? 0xFF : 0x00;
  for(uint64_t i = size; i < 8; ++i)
    disp |= fill << (i<<3);
 
  // let's be absolutely sure that it doesn't interfere
  return *(int64_t*)&disp;
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

static uint64_t real_mode_addr_default_segment(uint8_t rm) {
  // default segment is ss when BP is in the calculation
  if( rm == 0b010 ||
      rm == 0b011 ||
      rm == 0b110 )
    return cpu.ss;
  
  return cpu.ds;
}

static uint64_t protected_mode_addr_default_segment(uint8_t rm) {
  // BP has index 5, SP (index 4) is not accessible
  if( rm == 0b101 )
    return cpu.ss;

  return cpu.ds;
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

static uint16_t* seg_reg_addr_from_prefix(uint8_t prefix) {
  switch( prefix ) {
    case 0x2E: return &(cpu.cs);
    case 0x36: return &(cpu.ss);
    case 0x3E: return &(cpu.ds);
    case 0x26: return &(cpu.es);
    case 0x64: return &(cpu.fs);
    case 0x65: return &(cpu.gs);
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

// Thanks to https://ctyme.com/intr/
static void bios_interrupt_16(void) {
  switch( cpu.ah ) {
    case 0x0f: {
      // --- GET CURRENT VIDEO MODE ---
      // UNUSED ah = number of character columns
      // UNUSED al = display mode
      // USED   bh = active page
      cpu.bh = 0; // let's pretend that the page 0 is active
      return;
    }
  }
}

typedef enum { ES, CS, SS, DS, FS, GS } SegmentRegister;

char* seg_reg_str[] = {"es","cs","ss","ds","fs","gs"};

uint16_t* seg_reg_addr[] = {&(cpu.es),&(cpu.cs),&(cpu.ss),&(cpu.ds),&(cpu.fs),&(cpu.gs)};

static char* overridable_segment_str(SegmentRegister seg_reg) {
  if( !prefixes.g2.present ) return seg_reg_str[seg_reg];
  return seg_reg_str_from_prefix(prefixes.g2.prefix);
}

static uint16_t* overridable_segment_addr(SegmentRegister seg_reg) {
  if( !prefixes.g2.present ) return seg_reg_addr[seg_reg];
  return seg_reg_addr_from_prefix(prefixes.g2.prefix);
}

char* real_mode_addr_modes[] = {"bx+si","bx+di","bp+si","bp+di","si","di","bp","bx"};

char pos_neg[] = {'+','-'};

typedef enum { INDIRECT = 0, DIRECT = 1 } AddressingMode;

typedef struct {
  uint8_t reg;
  AddressingMode mode;
  union { uint64_t flat_addr; uint8_t* reg_addr; };
}
ModRM_Info;

typedef struct {
  uint64_t segment;
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

  if( prefixes.rex.present ) {
    index |= prefixes.rex.x << 3;
    base  |= prefixes.rex.b << 3;
  }

  out->segment = cpu.ds;
  out->offset = 0;

  switch( addr_sz ) {
    case 4: {
      const uint8_t base_exists  = !(base == 0b101 && mod == 0);
      const uint8_t index_exists = index != 0b100;

      if( base_exists ) {
        char* base_str = dword_reg_str[base];
        snprintf(str, len, "%s", base_str);
        str += strlen(base_str);
        len -= strlen(base_str);
        if( base == 0b100 || base == 0b101 )
          out->segment = cpu.ss; // if base is esp or ebp then segment is ss
        out->offset += *(uint32_t*)(dword_reg_addr[base]);
      }

      if( index_exists ) {
        if( base_exists ) {
          snprintf(str, len, "+");
          ++str; --len;
        }
        char* index_str = dword_reg_str[index];
        snprintf(str, len, "%s", index_str);
        str += strlen(index_str);
        len -= strlen(index_str);
        uint64_t scaled_index = *(uint32_t*)(dword_reg_addr[index]);
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
        const int64_t disp = read_displacement(rip+1, 4);
        cpu.rip += 5;
        snprintf(str, len, "%c0x%lx", pos_neg[disp<0], disp);
        out->offset += disp;
        return;
      }

      ++(cpu.rip);
      return;
    }
    default: panic("SIB for 64-bit mode not implemented!");
    /*
    case 8: {
      if( !((base & 0b111) == 0b101 && mod == 0) ) {
        const char* reg = reg_opcode_qword[base];
        sprintf(out, "%s+", reg);
        out += strlen(reg) + 1;
      }

      if( index != 0b100 ) {
        const char* reg = reg_opcode_qword[index];
        sprintf(out, "%s", reg);
        out += strlen(reg);
        switch(scale) {
          case 0b00: break;
          case 0b01: sprintf(out, "*2"); out += 2; break;
          case 0b10: sprintf(out, "*4"); out += 2; break;
          case 0b11: sprintf(out, "*8"); out += 2; break;
        }
      }

      if( (base & 0b111) == 0b101 && mod == 0 ) {
        sprintf(out, "+0x%lx", read_displacement(rip+1, 4));
        return rip + 5;
      }

      return rip + 1;
    }*/
  }
}

static void read_modrm(uint8_t operand_sz, uint8_t addr_sz, String modrm, ModRM_Info* out) {
  uint32_t len = modrm.len;
  char* str = modrm.str;
  uint8_t* rip = ram_addr_ip();

  uint64_t segment;
  uint8_t segment_override = 0;

  uint8_t mod = ((*rip) & 0b11000000) >> 6;

  out->reg   = ((*rip) & 0b00111000) >> 3;
  if( prefixes.rex.present )
    out->reg |= prefixes.rex.r << 3;
  
  uint8_t rm  = ((*rip) & 0b00000111) >> 0;

  if( mod != 0b11 && prefixes.g2.present ) {
    snprintf(str, len, "%s:", seg_reg_str_from_prefix(prefixes.g2.prefix));
    str += 3; len -= 3;
    segment = *seg_reg_addr_from_prefix(prefixes.g2.prefix);
    segment_override = 1;
  }

  switch( addr_sz ) {
    case 2: {
      switch( mod ) {
        case 0b00: {
          if( rm == 0b110 ) {
            const uint64_t imm = read_immediate(rip+1, 2);
            cpu.rip += 3;
            snprintf(str, len, "[0x%lx]", imm);
            if( !segment_override ) segment = cpu.ds;
            out->mode = INDIRECT;
            out->flat_addr = get_flat_address(segment, imm);
            return;
          }
          snprintf(str, len, "[%s]", real_mode_addr_modes[rm]);
          if( !segment_override ) segment = real_mode_addr_default_segment(rm);
          out->mode = INDIRECT;
          out->flat_addr = get_flat_address(segment, real_mode_addr_calc(rm));
          ++(cpu.rip);
          return;
        }
        case 0b01: {
          const int64_t disp = read_displacement(rip+1, 1);
          cpu.rip += 2;
          snprintf(str, len, "[%s%c0x%lx]", real_mode_addr_modes[rm], pos_neg[disp<0], ABS(disp));
          if( !segment_override ) segment = real_mode_addr_default_segment(rm);
          out->mode = INDIRECT;
          out->flat_addr = get_flat_address(segment, real_mode_addr_calc(rm) + disp);
          return;
        }
        case 0b10: {
          const int64_t disp = read_displacement(rip+1, 2);
          cpu.rip += 3;
          snprintf(str, len, "[%s%c0x%lx]", real_mode_addr_modes[rm], pos_neg[disp<0], ABS(disp));
          if( !segment_override ) segment = real_mode_addr_default_segment(rm);
          out->mode = INDIRECT;
          out->flat_addr = get_flat_address(segment, real_mode_addr_calc(rm) + disp);
          return;
        }
        case 0b11: {
          snprintf(str, len, "%s", get_reg_str(rm, operand_sz));
          out->mode = DIRECT;
          out->reg_addr = get_reg_addr(rm, operand_sz);
          ++(cpu.rip);
          return;
        }
      }
    }
    case 4: {
      switch( mod ) {
        case 0b00: {
          if( rm == 0b100 ) {
            char tmp[64]; String sib = { 63, tmp }; SIB_Info info;
            ++(cpu.rip);
            read_sib(addr_sz, mod, sib, &info);
            snprintf(str, len, "[%s]", sib.str);
            if( !segment_override ) segment = info.segment;
            out->mode = INDIRECT;
            out->flat_addr = get_flat_address(segment, info.offset);
            return;
          }
          if( rm == 0b101 ) {
            out->mode = INDIRECT;
            if( !segment_override ) segment = cpu.ds;
            if( op_mode == LONG_MODE ) {
              const int64_t disp = read_displacement(rip+1, 4);
              cpu.rip += 5; // always relative to the next instruction
              snprintf(str, len, "[eip%c0x%lx]", pos_neg[disp<0], disp);
              out->flat_addr = get_flat_address(segment, cpu.eip + disp);
            }
            else {
              const uint64_t imm = read_immediate(rip+1, 4);
              cpu.rip += 5;
              snprintf(str, len, "[0x%lx]", imm);
              out->flat_addr = get_flat_address(segment, imm);
            }
            return;
          }
          if( prefixes.rex.present )
            rm |= prefixes.rex.b << 3;
          snprintf(str, len, "[%s]", dword_reg_str[rm]);
          if( !segment_override ) segment = cpu.ds;
          out->mode = INDIRECT;
          out->flat_addr = get_flat_address(segment, *(uint32_t*)(dword_reg_addr[rm]));
          ++(cpu.rip);
          return;
        }
        case 0b01: {
          if( rm == 0b100 ) {
            char tmp[64]; String sib = { 63, tmp }; SIB_Info info;
            ++(cpu.rip);
            read_sib(addr_sz, mod, sib, &info);
            const int64_t disp = read_displacement(rip+2, 1);
            ++(cpu.rip);
            snprintf(str, len, "[%s%c0x%lx]", sib.str, pos_neg[disp<0], disp);
            if( !segment_override ) segment = info.segment;
            out->mode = INDIRECT;
            out->flat_addr = get_flat_address(segment, info.offset + disp);
            return;
          }
          if( prefixes.rex.present )
            rm |= prefixes.rex.b << 3;
          const int64_t disp = read_displacement(rip+1, 1);
          cpu.rip += 2;
          snprintf(str, len, "[%s%c0x%lx]", dword_reg_str[rm], pos_neg[disp<0], disp);
          if( !segment_override ) segment = protected_mode_addr_default_segment(rm);
          out->mode = INDIRECT;
          out->flat_addr = get_flat_address(segment, *(uint32_t*)(dword_reg_addr[rm]) + disp);
          return;
        }
        case 0b10: {
          if( rm == 0b100 ) {
            char tmp[64]; String sib = { 63, tmp }; SIB_Info info;
            ++(cpu.rip);
            read_sib(addr_sz, mod, sib, &info);
            const int64_t disp = read_displacement(rip+2, 4);
            cpu.rip += 4;
            snprintf(str, len, "[%s%c0x%lx]", sib.str, pos_neg[disp<0], disp);
            if( !segment_override ) segment = info.segment;
            out->mode = INDIRECT;
            out->flat_addr = get_flat_address(segment, info.offset + disp);
            return;
          }
          if( prefixes.rex.present )
            rm |= prefixes.rex.b << 3;
          const int64_t disp = read_displacement(rip+1, 4);
          cpu.rip += 5;
          snprintf(str, len, "[%s%c0x%lx]", dword_reg_str[rm], pos_neg[disp<0], disp);
          if( !segment_override ) segment = protected_mode_addr_default_segment(rm);
          out->mode = INDIRECT;
          out->flat_addr = get_flat_address(segment, *(uint32_t*)(dword_reg_addr[rm]) + disp);
          return;
        }
        case 0b11: {
          if( prefixes.rex.present )
            rm |= prefixes.rex.b << 3;
          snprintf(str, len, "%s", get_reg_str(rm, operand_sz));
          out->mode = DIRECT;
          out->reg_addr = get_reg_addr(rm, operand_sz);
          ++(cpu.rip);
          return;
        }
      }
    }
    default: panic("ModRM for 64 bit mode is not implemented!");
    /*
    case 8: {
      switch(mod) {
        case 0b00: {
          if( rm == 0b100 ) {
            char sib[64];
            const uint8_t* next = read_sib(rip+1, mod, 8, inst, sib);
            sprintf(out, "[%s]", sib);
            return next;
          }
          if( rm == 0b101 ) {
            sprintf(out, "[rip+0x%lx]", read_displacement(rip+1, 4));
            return rip + 5;
          }
          if( inst.rex ) rm |= inst.rex_prefix.b << 3;
          sprintf(out, "[%s]", reg_opcode_qword[rm]);
          return rip + 1;
        }
        case 0b01: {
          if( rm == 0b100 ) {
            char sib[64];
            const uint8_t* next = read_sib(rip+1, mod, 8, inst, sib);
            sprintf(out, "[%s+0x%lx]", sib, read_displacement(rip+2, 1));
            return next;
          }
          if( inst.rex ) rm |= inst.rex_prefix.b << 3;
          sprintf(out, "[%s+0x%lx]", reg_opcode_qword[rm], read_displacement(rip+1, 1));
          return rip + 2;
        }
        case 0b10: {
          if( rm == 0b100 ) {
            char sib[64];
            const uint8_t* next = read_sib(rip+1, mod, 8, inst, sib);
            sprintf(out, "[%s+0x%lx]", sib, read_displacement(rip+2, 4));
            return next;
          }
          if( inst.rex ) rm |= inst.rex_prefix.b << 3;
          sprintf(out, "[%s+0x%lx]", reg_opcode_qword[rm], read_displacement(rip+1, 4));
          return rip + 5;
        }
        case 0b11: {
          if( inst.rex ) rm |= inst.rex_prefix.b << 3;
          switch(operand_sz) {
            case 1: sprintf(out, "%s", reg_opcode_byte_ext[rm]); return rip + 1;
            case 2: sprintf(out, "%s", reg_opcode_word[rm]); return rip + 1;
            case 4: sprintf(out, "%s", reg_opcode_dword[rm]); return rip + 1;
            case 8: sprintf(out, "%s", reg_opcode_qword[rm]); return rip + 1;
          }
        }
      }
    } break;*/
  }
}

static void decode_one_byte_opcode(String assembly) {
  uint32_t len = assembly.len;
  char* str = assembly.str;
  uint8_t* opcode = ram_addr_ip();

  switch( *ram_addr_ip() ) {
    case 0x03: {
      const uint8_t operand_sz = rex_ext_operand_sz();
      char tmp[64]; String modrm = { 63, tmp }; ModRM_Info info;
      ++(cpu.rip);
      read_modrm(operand_sz, address_sz(), modrm, &info);
      
      snprintf(str, len, "ADD  %s, %s", get_reg_str(info.reg, operand_sz), modrm.str);
      
      uint8_t* src;
      uint8_t* dest = get_reg_addr(info.reg, operand_sz);
      if( info.mode == INDIRECT ) src = ram + info.flat_addr;
      if( info.mode == DIRECT )   src = info.reg_addr;
      int64_t a = read_displacement(dest, operand_sz);
      int64_t b = read_displacement(src, operand_sz);
      int64_t c = a + b;
      memcpy(dest, &c, operand_sz);
      /* OF */ const uint8_t s_a = a < 0, s_b = b < 0, s_c = c < 0;
      if( (s_a == 0 && s_b == 1) || (s_a == 1 && s_b == 0) ) CLEAR_FLAG(RFLAGS_OF); 
      if( s_a == 0 && s_b == 0 ) { UPDATE_FLAG(s_c == 1, RFLAGS_OF) }
      if( s_a == 1 && s_b == 1 ) { UPDATE_FLAG(s_c == 0, RFLAGS_OF) }
      /* SF */ update_sf_flag(c);
      /* ZF */ update_zf_flag(c);
      /* AF */ UPDATE_FLAG( ((uint64_t)a & 0x0F) > ((uint64_t)c & 0x0F), RFLAGS_AF)
      /* PF */ update_pf_flag(c);
      /* CF */ UPDATE_FLAG((uint64_t)a > (uint64_t)c, RFLAGS_CF)
      return;
    }
    case 0x33: {
      const uint8_t operand_sz = rex_ext_operand_sz();
      char tmp[64]; String modrm = { 63, tmp }; ModRM_Info info;
      ++(cpu.rip);
      read_modrm(operand_sz, address_sz(), modrm, &info);
      
      snprintf(str, len, "XOR  %s, %s", get_reg_str(info.reg, operand_sz), modrm.str);
      
      uint8_t* src;
      uint8_t* dest = get_reg_addr(info.reg, operand_sz);
      if( info.mode == INDIRECT ) src = ram + info.flat_addr;
      if( info.mode == DIRECT )   src = info.reg_addr;
      uint64_t a = read_immediate(dest, operand_sz);
      uint64_t b = read_immediate(src, operand_sz);
      uint64_t c = a ^ b;
      memcpy(dest, &c, operand_sz);
      /* OF */ CLEAR_FLAG(RFLAGS_OF);
      /* SF */ update_sf_flag(c);
      /* ZF */ update_zf_flag(c);
      /* PF */ update_pf_flag(c);
      /* CF */ CLEAR_FLAG(RFLAGS_CF);
      return;
    }
    case 0x3D: {
      const uint8_t operand_sz = rex_ext_operand_sz();
      const uint8_t disp_sz = MIN(operand_sz, 4);
      int64_t a, c;
      int64_t b = read_displacement(opcode+1, disp_sz);
      cpu.rip += 1 + disp_sz;

      snprintf(str, len, "CMP  %s, %c0x%lx", get_reg_str(RAX, operand_sz), pos_neg[b<0], ABS(b));
      
      a = read_displacement(get_reg_addr(RAX, operand_sz), operand_sz);
      c = a - b;
      /* OF */ const uint8_t s_a = a < 0, s_b = b < 0, s_c = c < 0;
      if( (s_a == 0 && s_b == 0) || (s_a == 1 && s_b == 1) ) CLEAR_FLAG(RFLAGS_OF); 
      if( s_a == 0 && s_b == 1 ) { UPDATE_FLAG(s_c == 1, RFLAGS_OF) }
      if( s_a == 1 && s_b == 0 ) { UPDATE_FLAG(s_c == 0, RFLAGS_OF) }
      /* SF */ update_sf_flag(c); 
      /* ZF */ update_zf_flag(c); 
      /* AF */ UPDATE_FLAG( ((uint64_t)a & 0x0F) < ((uint64_t)b & 0x0F), RFLAGS_AF)
      /* PF */ update_pf_flag(c);
      /* CF */ UPDATE_FLAG((uint64_t)a < (uint64_t)b, RFLAGS_CF)
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

      snprintf(str, len, "POP  %s", get_reg_str(opcode_reg, operand_sz));
      
      memcpy(get_reg_addr(opcode_reg, operand_sz), ram + get_flat_address(cpu.ss, get_sp()), operand_sz);
      cpu.rsp += operand_sz;
      ++(cpu.rip);
      return;
    }
    case 0x72: {
      const int64_t disp = read_displacement(opcode+1, 1);
      cpu.rip += 2;

      snprintf(str, len, "JB  %c0x%lx", pos_neg[disp<0], ABS(disp));

      if( cpu.rflags & RFLAGS_CF )
        cpu.rip += disp;
      return;
    }
    case 0x83: {
      const uint8_t operand_sz = rex_ext_operand_sz();
      char tmp[64]; String modrm = { 63, tmp }; ModRM_Info info;
      ++(cpu.rip);
      read_modrm(operand_sz, address_sz(), modrm, &info);
      uint8_t* post_modrm = ram_addr_ip();

      switch( info.reg ) {
        case 5: {
          int64_t a, c;
          int64_t b = read_displacement(post_modrm, 1);
          ++(cpu.rip);

          snprintf(str, len, "SUB  %s, %c0x%lx", modrm.str, pos_neg[b<0], ABS(b));
          
          uint8_t* dest;
          if( info.mode == INDIRECT ) dest = ram + info.flat_addr;
          if( info.mode == DIRECT )   dest = info.reg_addr;
          a = read_displacement(dest, operand_sz);
          c = a - b;
          memcpy(dest, &c, operand_sz);
          /* OF */ const uint8_t s_a = a < 0, s_b = b < 0, s_c = c < 0;
          if( (s_a == 0 && s_b == 0) || (s_a == 1 && s_b == 1) ) CLEAR_FLAG(RFLAGS_OF); 
          if( s_a == 0 && s_b == 1 ) { UPDATE_FLAG(s_c == 1, RFLAGS_OF) }
          if( s_a == 1 && s_b == 0 ) { UPDATE_FLAG(s_c == 0, RFLAGS_OF) }
          /* SF */ update_sf_flag(c); 
          /* ZF */ update_zf_flag(c); 
          /* AF */ UPDATE_FLAG( ((uint64_t)a & 0x0F) < ((uint64_t)b & 0x0F), RFLAGS_AF)
          /* PF */ update_pf_flag(c);
          /* CF */ UPDATE_FLAG((uint64_t)a < (uint64_t)b, RFLAGS_CF)
          return;
        }
      }
    }
    case 0x88: {
      char tmp[64]; String modrm = { 63, tmp }; ModRM_Info info;
      ++(cpu.rip);
      read_modrm(1, address_sz(), modrm, &info);

      snprintf(str, len, "MOV  %s, %s", modrm.str, get_reg_str(info.reg, 1));

      uint8_t* src = get_reg_addr(info.reg, 1);
      if( info.mode == INDIRECT ) memcpy(ram + info.flat_addr, src, 1);
      if( info.mode == DIRECT )   *info.reg_addr = *src;
      return;
    }
    case 0x8C: {
      char tmp[64]; String modrm = { 63, tmp }; ModRM_Info info;
      ++(cpu.rip);
      read_modrm(rex_ext_operand_sz(), address_sz(), modrm, &info);

      snprintf(str, len, "MOV  %s, %s", modrm.str, seg_reg_str[info.reg]);

      uint16_t* seg_reg = seg_reg_addr[info.reg];
      if( info.mode == INDIRECT ) memcpy(ram + info.flat_addr, seg_reg, 2);
      if( info.mode == DIRECT )   *(uint16_t*)(info.reg_addr) = *seg_reg;
      return;
    }
    case 0x8E: {
      char tmp[64]; String modrm = { 63, tmp }; ModRM_Info info;
      ++(cpu.rip);
      read_modrm(rex_ext_operand_sz(), address_sz(), modrm, &info);

      snprintf(str, len, "MOV  %s, %s", seg_reg_str[info.reg], modrm.str);

      uint16_t* seg_reg = seg_reg_addr[info.reg];
      if( info.mode == INDIRECT ) memcpy(seg_reg, ram + info.flat_addr, 2);
      if( info.mode == DIRECT )   *seg_reg = *(uint16_t*)(info.reg_addr);
      return;
    }
    case 0xA4: {
      const uint8_t addr_sz = address_sz();

      snprintf(str, len, "%sMOVSB  es:[%s] %s:[%s]", rep_prefix_str(),
                                                     get_reg_str(RDI, addr_sz),
                                                     overridable_segment_str(DS),
                                                     get_reg_str(RSI, addr_sz));
      
      uint64_t segment = *overridable_segment_addr(DS);
      uint64_t count = 0;
      if( prefixes.g1.present && prefixes.g1.prefix == 0xF3 )
        memcpy(&count, get_reg_addr(RCX, addr_sz), addr_sz);
      else
        count = 1;
      uint64_t dest_offset = 0, src_offset = 0;
      memcpy(&dest_offset, get_reg_addr(RDI, addr_sz), addr_sz);
      memcpy(&src_offset, get_reg_addr(RSI, addr_sz), addr_sz);
      uint8_t* dest = ram + get_flat_address(cpu.es, dest_offset);
      uint8_t* src  = ram + get_flat_address(segment, src_offset);
      int8_t dir    = ((cpu.rflags & RFLAGS_DF) / RFLAGS_DF) * -2 + 1;
      for(uint64_t i = 0; i < count; ++i) {
        //memcpy(dest, src, 1); i was very tired :)
        *dest = *src; // there you go, it was in fact the bottleneck
        cpu.rsi += dir; cpu.rdi += dir;
        src += dir; dest += dir;
      }
      cpu.rcx = 0;
      ++(cpu.rip);
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
      const uint64_t immediate = read_immediate(opcode+1, 1);
      cpu.rip += 2;

      snprintf(str, len, "MOV  %s, 0x%lx", get_reg_str(opcode_reg, 1), immediate);
      
      memcpy(get_reg_addr(opcode_reg, 1), opcode+1, 1);
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
      const uint64_t immediate = read_immediate(opcode+1, operand_sz);
      cpu.rip += 1 + operand_sz;

      snprintf(str, len, "MOV  %s, 0x%lx", get_reg_str(opcode_reg, operand_sz), immediate);
      
      memcpy(get_reg_addr(opcode_reg, operand_sz), opcode+1, operand_sz);
      return;
    }
    case 0xC1: {
      const uint8_t operand_sz = rex_ext_operand_sz();
      char tmp[64]; String modrm = { 63, tmp }; ModRM_Info info;
      ++(cpu.rip);
      read_modrm(operand_sz, address_sz(), modrm, &info);
      uint8_t* post_modrm = ram_addr_ip();

      switch( info.reg ) {
        case 5: {
          uint64_t a, c;
          uint64_t b = read_immediate(post_modrm, 1);
          if( operand_sz == 8 ) { b &= 0x3F; } else { b &= 0x1F; }
          ++(cpu.rip);
          
          snprintf(str, len, "SHR  %s, 0x%lx", modrm.str, b);
          
          uint8_t* dest;
          if( info.mode == INDIRECT ) dest = ram + info.flat_addr;
          if( info.mode == DIRECT )   dest = info.reg_addr;
          c = a = read_immediate(dest, operand_sz);
          for(uint64_t i = 0; i < b; ++i) {
            UPDATE_FLAG(c & 0x1, RFLAGS_CF);
            c >>= 1;
          }
          memcpy(dest, &c, operand_sz);
          
          if( b == 1 ) { UPDATE_FLAG((a >> (operand_sz*8 - 1)) & 0x1, RFLAGS_OF) };
          if( b > 0 ) {
            update_sf_flag(c);
            update_zf_flag(c);
            update_pf_flag(c);
          }
          return;
        }
      }
    }
    case 0xCD: {
      const uint64_t imm = read_immediate(opcode+1, 1);
      cpu.rip += 2;

      snprintf(str, len, "INT  0x%lx", imm);

      if( op_mode == REAL_MODE ) {
        if( imm == 0x10 ) bios_interrupt_16();
      }
      return;
    }
    case 0xE8: {
      const uint8_t operand_sz = not_rex_ext_operand_sz();
      const uint8_t disp_sz    = MIN(operand_sz, 4);
      const int64_t disp = read_displacement(opcode+1, disp_sz);
      
      snprintf(str, len, "CALL  %c0x%lx", pos_neg[disp<0], ABS(disp));
      
      uint64_t n_rip = get_operand_sz_ip(operand_sz) + 1 + disp_sz;
      cpu.rsp -= operand_sz;
      memcpy(ram + get_flat_address(cpu.ss, get_sp()), &n_rip, operand_sz);
      cpu.rip += 1 + disp_sz + disp;
      return;
    }
    case 0xEA: {
      const uint8_t operand_sz = rex_ext_operand_sz();
      const uint64_t segment = read_immediate(opcode+1+operand_sz, 2);
      const uint64_t offset  = read_immediate(opcode+1, operand_sz);
      
      snprintf(str, len, "JMP  0x%lx:0x%lx", segment, offset);
      
      cpu.cs = segment;
      cpu.rip = offset;
      return;
    }
    case 0xFA: {
      snprintf(str, len, "CLI");
      
      CLEAR_FLAG(RFLAGS_IF);
      ++(cpu.rip);
      return;
    }
    case 0xFB: {
      snprintf(str, len, "STI");
      
      SET_FLAG(RFLAGS_IF);
      ++(cpu.rip);
      return;
    }
    case 0xFC: {
      snprintf(str, len, "CLD");
      
      CLEAR_FLAG(RFLAGS_DF);
      ++(cpu.rip);
      return;
    }
    default: panic("The 1 byte instruction was not implemented!");
  }
}

static void decode_two_byte_opcode(String assembly) {
  uint32_t len = assembly.len;
  char* str = assembly.str;
  uint8_t* opcode = ram_addr_ip();

  switch( *ram_addr_ip() ) {
    case 0xA2: {
      snprintf(str, len, "CPUID");

      switch( cpu.eax ) {
        case 0x80000000: {
          // Maximum input value for CPUID of the form 80 00 00 0*
          cpu.eax = 0x80000008;
          break;
        }
        case 0x80000001: {
          // EAX = extended processor signature and feature bits (???)
          // EBX = reserved
          // ECX = some shit
          // EDX = some shit + bit 29: is 64-bit mode available (important)
          cpu.edx = 1 << 29;
          break;
        }
      }
      ++(cpu.rip);
      return;
    }
    case 0xBA: {
      const uint8_t operand_sz = rex_ext_operand_sz();
      char tmp[64]; String modrm = { 63, tmp }; ModRM_Info info;
      ++(cpu.rip);
      read_modrm(operand_sz, address_sz(), modrm, &info);
      uint8_t* post_modrm = ram_addr_ip();

      switch( info.reg ) {
        case 4: {
          const uint64_t bit_offset = read_immediate(post_modrm, 1) % (operand_sz * 8);
          ++(cpu.rip);

          snprintf(str, len, "BT  %s, 0x%lx", modrm.str, bit_offset);
          
          uint8_t* bit_base;
          if( info.mode == INDIRECT ) bit_base = ram + info.flat_addr;
          if( info.mode == DIRECT )   bit_base = info.reg_addr;
          uint64_t tmp = 0;
          memcpy(&tmp, bit_base, operand_sz);
          UPDATE_FLAG((tmp >> bit_offset) & 0x1, RFLAGS_CF);
          return;
        }
      }
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
  op_mode = get_cpu_operation_mode();
  
  prefixes = (InstructionPrefixes){ 0 };
  check_legacy_prefixes();

  if( op_mode == LONG_MODE )
    check_rex_prefix();
  
  read_and_decode_opcode(assembly);
}

#endif
