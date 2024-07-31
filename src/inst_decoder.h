#ifndef _INST_DECODER_H_
#define _INST_DECODER_H_

#include <stdlib.h>
#include <stdint.h>

#include "x64_cpu.h"
#include "string_struct.h"

#define ABS(x) ((x) < 0) ? -(x) : (x)
#define MIN(x, y) ((x) < (y)) ? (x) : (y)

typedef enum { EXECUTE_ONLY = 1, DISASSEMBLE_ONLY = 2, EXECUTE_DISASSEMBLE = 3 } DecodeMode;

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

static uint8_t* check_legacy_prefixes(uint8_t* rip) {
  while( 1 ) {
    switch( *rip ) {
      // group 1
      case 0xF0: prefixes.g1.present = 1; prefixes.g1.prefix = 0xF0; ++rip; break;
      case 0xF2: prefixes.g1.present = 1; prefixes.g1.prefix = 0xF2; ++rip; break;
      case 0xF3: prefixes.g1.present = 1; prefixes.g1.prefix = 0xF3; ++rip; break;

      // group 2
      case 0x2E: prefixes.g2.present = 1; prefixes.g2.prefix = 0x2E; ++rip; break;
      case 0x36: prefixes.g2.present = 1; prefixes.g2.prefix = 0x36; ++rip; break;
      case 0x3E: prefixes.g2.present = 1; prefixes.g2.prefix = 0x3E; ++rip; break;
      case 0x26: prefixes.g2.present = 1; prefixes.g2.prefix = 0x26; ++rip; break;
      case 0x64: prefixes.g2.present = 1; prefixes.g2.prefix = 0x64; ++rip; break;
      case 0x65: prefixes.g2.present = 1; prefixes.g2.prefix = 0x65; ++rip; break;

      // group 3
      case 0x66: prefixes.g3.present = 1; ++rip; break;

      // group 4
      case 0x67: prefixes.g4.present = 1; ++rip; break;

      default: return rip;
    }
  }
}

static uint8_t* check_rex_prefix(uint8_t* rip) {
  if( (*rip & 0xF0) != 0x40 )
    return rip;

  prefixes.rex.present = 1;
  prefixes.rex.w       = (*rip & 0b1000) >> 3;
  prefixes.rex.r       = (*rip & 0b0100) >> 2;
  prefixes.rex.x       = (*rip & 0b0010) >> 1;
  prefixes.rex.b       = (*rip & 0b0001) >> 0;

  return rip + 1;
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

static char* get_reg_string(uint8_t index, uint8_t operand_sz) {
  switch( operand_sz ) {
    case 1: {
      if( prefixes.rex.present ) return rex_ext_byte_reg_str[index];
      return byte_reg_str[index];
    }
    case 2: return word_reg_str[index];
    case 4: return dword_reg_str[index];
    case 8: return qword_reg_str[index];
  }
}

static uint8_t* get_reg_addr(uint8_t index, uint8_t operand_sz) {
  switch( operand_sz ) {
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

char* real_mode_addr_modes[] = {"bx+si","bx+di","bp+si","bp+di","si","di","bp","bx"};

char pos_neg[] = {'+','-'};

typedef enum { INDIRECT = 0, DIRECT = 1 } AddressingMode;

typedef struct {
  uint8_t reg;
  AddressingMode mode;
  uint64_t val;
}
ModRM_Info;

static uint8_t* read_modrm(DecodeMode mode, uint8_t* rip, uint8_t operand_sz, uint8_t address_sz, String modrm, ModRM_Info* info) {
  uint32_t len = modrm.len;
  char* str = modrm.str;

  uint64_t segment;
  uint8_t segment_override = 0;

  uint8_t mod = ((*rip) & 0b11000000) >> 6;
  info->reg   = ((*rip) & 0b00111000) >> 3;
  uint8_t rm  = ((*rip) & 0b00000111) >> 0;

  if( mod != 0b11 && prefixes.g2.present ) {
    if( mode & DISASSEMBLE_ONLY ) {
      snprintf(str, len, "%s:", seg_reg_str_from_prefix(prefixes.g2.prefix));
      str += 3; len -= 3;
    }
    if( mode & EXECUTE_ONLY ) {
      segment = *seg_reg_addr_from_prefix(prefixes.g2.prefix);
      segment_override = 1;
    }
  }

  switch( address_sz ) {
    case 2: {
      switch( mod ) {
        case 0b00: {
          if( rm == 0b110 ) {
            const uint64_t imm = read_immediate(rip+1, 2);
            if( mode & DISASSEMBLE_ONLY )
              snprintf(str, len, "[0x%lx]", imm);
            if( mode & EXECUTE_ONLY ) {
              if( !segment_override ) segment = cpu.ds;
              info->mode = INDIRECT;
              info->val = get_flat_address(segment, imm);
            }
            return rip + 3;
          }
          if( mode & DISASSEMBLE_ONLY )
            snprintf(str, len, "[%s]", real_mode_addr_modes[rm]);
          if( mode & EXECUTE_ONLY ) {
            if( !segment_override ) segment = real_mode_addr_default_segment(rm);
            info->mode = INDIRECT;
            info->val = get_flat_address(segment, real_mode_addr_calc(rm));
          }
          return rip + 1;
        }
        case 0b01: {
          const int64_t disp = read_displacement(rip+1, 1);
          if( mode & DISASSEMBLE_ONLY )
            snprintf(str, len, "[%s%c0x%lx]", real_mode_addr_modes[rm], pos_neg[disp<0], ABS(disp));
          if( mod & EXECUTE_ONLY ) {
            if( !segment_override ) segment = real_mode_addr_default_segment(rm);
            info->mode = INDIRECT;
            info->val = get_flat_address(segment, real_mode_addr_calc(rm) + disp);
          }
          return rip + 2;
        }
        case 0b10: {
          const int64_t disp = read_displacement(rip+1, 2);
          if( mode & DISASSEMBLE_ONLY )
            snprintf(str, len, "[%s%c0x%lx]", real_mode_addr_modes[rm], pos_neg[disp<0], ABS(disp));
          if( mode & EXECUTE_ONLY ) {
            if( !segment_override ) segment = real_mode_addr_default_segment(rm);
            info->mode = INDIRECT;
            info->val = get_flat_address(segment, real_mode_addr_calc(rm) + disp);
          }
          return rip + 3;
        }
        case 0b11: {
          info->mode = DIRECT;
          switch( operand_sz ) {
            case 1: {
              if( mode & DISASSEMBLE_ONLY ) snprintf(str, len, "%s", byte_reg_str[rm]);
              if( mode & EXECUTE_ONLY )     info->val = *(uint8_t*)(byte_reg_addr[rm]);
              return rip + 1;
            }
            case 2: {
              if( mode & DISASSEMBLE_ONLY ) snprintf(str, len, "%s", word_reg_str[rm]);
              if( mode & EXECUTE_ONLY )     info->val = *(uint16_t*)(word_reg_addr[rm]);
              return rip + 1;
            }
            case 4: {
              if( mode & DISASSEMBLE_ONLY ) snprintf(str, len, "%s", dword_reg_str[rm]);
              if( mode & EXECUTE_ONLY )     info->val = *(uint32_t*)(dword_reg_addr[rm]);
              return rip + 1;
            }
          }
        }
      }
    }
    default: panic("ModRM for 32, 64 bit modes is not implemented!");
    /*
    case 4: {
      switch(mod) {
        case 0b00: {
          if( rm == 0b100 ) {
            char sib[64];
            const uint8_t* next = read_sib(rip+1, mod, 4, inst, sib);
            sprintf(out, "[%s]", sib);
            return next;
          }
          if( rm == 0b101 ) {
            sprintf(out, "[0x%lx]", read_displacement(rip+1, 4));
            return rip + 5;
          }
          sprintf(out, "[%s]", reg_opcode_dword[rm]);
          return rip + 1;
        }
        case 0b01: {
          if( rm == 0b100 ) {
            char sib[64];
            const uint8_t* next = read_sib(rip+1, mod, 4, inst, sib);
            sprintf(out, "[%s+0x%lx]", sib, read_displacement(rip+2, 1));
            return next;
          }
          sprintf(out, "[%s+0x%lx]", reg_opcode_dword[rm], read_displacement(rip+1, 1));
          return rip + 2;
        }
        case 0b10: {
          if( rm == 0b100 ) {
            char sib[64];
            const uint8_t* next = read_sib(rip+1, mod, 4, inst, sib);
            sprintf(out, "[%s+0x%lx]", sib, read_displacement(rip+2, 4));
            return next;
          }
          sprintf(out, "[%s+0x%lx]", reg_opcode_dword[rm], read_displacement(rip+1, 4));
          return rip + 5;
        }
        case 0b11: {
          switch(operand_sz) {
            case 1: sprintf(out, "%s", reg_opcode_byte[rm]); return rip + 1;
            case 2: sprintf(out, "%s", reg_opcode_word[rm]); return rip + 1;
            case 4: sprintf(out, "%s", reg_opcode_dword[rm]); return rip + 1;
          }
        }
      }
    } break;
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

char* seg_reg_str[] = {"es","cs","ss","ds","fs","gs"};

uint16_t* seg_reg_addr[] = {&(cpu.es),&(cpu.cs),&(cpu.ss),&(cpu.ds),&(cpu.fs),&(cpu.gs)};

static uint8_t* decode_one_byte_opcode(DecodeMode mode, uint8_t* rip, String assembly) {
  uint32_t len = assembly.len;
  char* str = assembly.str;
  uint8_t* next;

  switch( *rip ) {
    case 0x58:
    case 0x59:
    case 0x5A:
    case 0x5B:
    case 0x5C:
    case 0x5D:
    case 0x5E:
    case 0x5F: {
      const uint8_t operand_sz = not_rex_ext_operand_sz();
      const uint8_t opcode_reg = read_reg_in_opcode(rip);
      if( mode & DISASSEMBLE_ONLY )
        snprintf(str, len, "POP  %s", get_reg_string(opcode_reg, operand_sz));
      if( mode & EXECUTE_ONLY ) {
        memcpy(get_reg_addr(opcode_reg, operand_sz), ram + get_flat_address(cpu.ss, cpu.rsp), operand_sz);
        cpu.rsp += operand_sz;
      }
      return rip + 1;
    }
    case 0x8E: {
      char tmp[64]; String modrm = { 63, tmp }; ModRM_Info info;
      const uint8_t* next_inst = read_modrm(mode, rip+1, rex_ext_operand_sz(), address_sz(), modrm, &info);

      if( mode & DISASSEMBLE_ONLY )
        snprintf(str, len, "MOV  %s, %s", seg_reg_str[info.reg], modrm.str);
      if( mode & EXECUTE_ONLY ) {
        uint16_t* seg_reg = seg_reg_addr[info.reg];
        if( info.mode == INDIRECT ) memcpy(seg_reg, ram + info.val, 2);
        if( info.mode == DIRECT )   *seg_reg = (uint16_t)info.val;
      }
      return next_inst;
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
      const uint8_t opcode_reg = read_reg_in_opcode(rip);
      const uint64_t immediate = read_immediate(rip+1, operand_sz);
      if( mode & DISASSEMBLE_ONLY )
        snprintf(str, len, "MOV  %s, 0x%lx", get_reg_string(opcode_reg, operand_sz), immediate);
      if( mode & EXECUTE_ONLY )
        memcpy(get_reg_addr(opcode_reg, operand_sz), rip+1, operand_sz);
      return rip + 1 + operand_sz;
    }
    case 0xE8: {
      const uint8_t operand_sz = not_rex_ext_operand_sz();
      const uint8_t disp_sz    = MIN(operand_sz, 4);
      const int64_t disp = read_displacement(rip+1, disp_sz);
      if( mode & DISASSEMBLE_ONLY ) {
        snprintf(str, len, "CALL  %c0x%lx", pos_neg[disp<0], ABS(disp));
        next = rip + 1 + disp_sz;
      }
      if( mode & EXECUTE_ONLY ) {
        uint64_t n_rip = cpu.rip + 1 + disp_sz;
        cpu.rsp -= operand_sz;
        memcpy(ram + get_flat_address(cpu.ss, cpu.rsp), &n_rip, operand_sz);
        next = rip + 1 + disp_sz + disp;
      }
      return next;
    }
    case 0xFA: {
      if( mode & DISASSEMBLE_ONLY ) snprintf(str, len, "CLI");
      if( mode & EXECUTE_ONLY )     cpu.rflags &= ~(RFLAGS_IF);
      return rip + 1;
    }
    case 0xFB: {
      if( mode & DISASSEMBLE_ONLY ) snprintf(str, len, "STI");
      if( mode & EXECUTE_ONLY )     cpu.rflags |= RFLAGS_IF;
      return rip + 1;
    }
    case 0xFC: {
      if( mode & DISASSEMBLE_ONLY ) snprintf(str, len, "CLD");
      if( mode & EXECUTE_ONLY )     cpu.rflags &= ~(RFLAGS_DF);
      return rip + 1;
    }
  }
}

static uint8_t* decode_two_byte_opcode(DecodeMode mode, uint8_t* rip, String assembly) {

}

static uint8_t* read_and_decode_opcode(DecodeMode mode, uint8_t* rip, String assembly) {
  if( *rip == 0x0F ) {
    ++rip;
    if( *rip == 0x38 || *rip == 0x3A ) {
      panic("3 byte opcodes not supported!");
    }
    else {
      return decode_two_byte_opcode(mode, rip, assembly);
    }
  }
  else {
    return decode_one_byte_opcode(mode, rip, assembly);
  }
}

uint64_t decode_instruction(DecodeMode mode, String assembly) {
  op_mode = get_cpu_operation_mode();
  
  const uint8_t* rip_base = ram + get_flat_address(cpu.cs, cpu.rip);
  uint8_t*            rip = rip_base;

  prefixes = (InstructionPrefixes){ 0 };
  rip = check_legacy_prefixes(rip);

  if( op_mode == LONG_MODE )
    rip = check_rex_prefix(rip);
  
  rip = read_and_decode_opcode(mode, rip, assembly);
  return cpu.rip + (rip - rip_base);
}

#endif
