#ifndef _INST_DECODER_H_
#define _INST_DECODER_H_

#include <stdlib.h>
#include <stdint.h>

#include "x64_cpu.h"

typedef enum { EXECUTE_ONLY = 1, DISASSEMBLE_ONLY = 2, EXECUTE_DISASSEMBLE = 3 } DecodeMode;

typedef struct {
  uint8_t present;
  enum { DE=0, DB=1, BP=3, OF=4, BR=5, UD=6, NM=7, DF=8, TS=10, NP=11,
         SS=12, GP=13, PF=14, MF=16, AC=17, MC=18, XM=19, VE=20, CP=21 } vector;
}
Exception;

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

static void check_legacy_prefixes(uint64_t* rip, uint8_t** rip_abs) {
  while( 1 ) {
    switch( **rip_abs ) {
      // group 1
      case 0xF0: prefixes.g1.present = 1; prefixes.g1.prefix = 0xF0; ++(*rip); ++(*rip_abs); break;
      case 0xF2: prefixes.g1.present = 1; prefixes.g1.prefix = 0xF2; ++(*rip); ++(*rip_abs); break;
      case 0xF3: prefixes.g1.present = 1; prefixes.g1.prefix = 0xF3; ++(*rip); ++(*rip_abs); break;

      // group 2
      case 0x2E: prefixes.g2.present = 1; prefixes.g2.prefix = 0x2E; ++(*rip); ++(*rip_abs); break;
      case 0x36: prefixes.g2.present = 1; prefixes.g2.prefix = 0x36; ++(*rip); ++(*rip_abs); break;
      case 0x3E: prefixes.g2.present = 1; prefixes.g2.prefix = 0x3E; ++(*rip); ++(*rip_abs); break;
      case 0x26: prefixes.g2.present = 1; prefixes.g2.prefix = 0x26; ++(*rip); ++(*rip_abs); break;
      case 0x64: prefixes.g2.present = 1; prefixes.g2.prefix = 0x64; ++(*rip); ++(*rip_abs); break;
      case 0x65: prefixes.g2.present = 1; prefixes.g2.prefix = 0x65; ++(*rip); ++(*rip_abs); break;

      // group 3
      case 0x66: prefixes.g3.present = 1; ++(*rip); ++(*rip_abs); break;

      // group 4
      case 0x67: prefixes.g4.present = 1; ++(*rip); ++(*rip_abs); break;

      default: return;
    }
  }
}

static void check_rex_prefix(uint64_t* rip, uint8_t** rip_abs) {
  if( (**rip_abs & 0xF0) != 0x40 )
    return;

  prefixes.rex.present = 1;
  prefixes.rex.w       = (**rip_abs & 0b1000) >> 3;
  prefixes.rex.r       = (**rip_abs & 0b0100) >> 2;
  prefixes.rex.x       = (**rip_abs & 0b0010) >> 1;
  prefixes.rex.b       = (**rip_abs & 0b0001) >> 0;

  ++(*rip); ++(*rip_abs);
  return;
}

static uint64_t decode_one_byte_opcode(DecodeMode mode, uint64_t rip, uint8_t* rip_abs, char* assembly, uint64_t assembly_sz, Exception* excep) {
  uint8_t* next;

  switch( *rip_abs ) {
    case 0xFC: {
      if( mode & DISASSEMBLE_ONLY )
        snprintf(assembly, assembly_sz, "CLD");
      if( mode & EXECUTE_ONLY ) {
        if( prefixes.g1.present && prefixes.g1.prefix == 0xF0 ) {
          excep->present = 1; excep->vector  = UD;
          goto cld_exit;
        }
        cpu.rflags &= ~(RFLAGS_DF);
      }
      cld_exit: return rip + 1;
    }
  }
}

static uint64_t decode_two_byte_opcode(DecodeMode mode, uint64_t rip, uint8_t* rip_abs, char* assembly, uint64_t assembly_sz, Exception* excep) {

}

static uint64_t read_and_decode_opcode(DecodeMode mode, uint64_t rip, uint8_t* rip_abs, char* assembly, uint64_t assembly_sz, Exception* excep) {
  if( *rip_abs == 0x0F ) {
    ++rip_abs;
    if( *rip_abs == 0x38 || *rip_abs == 0x3A ) {
      panic("3 byte opcodes not supported!");
    }
    else {
      return decode_two_byte_opcode(mode, rip, rip_abs, assembly, assembly_sz, excep);
    }
  }
  else {
    return decode_one_byte_opcode(mode, rip, rip_abs, assembly, assembly_sz, excep);
  }
}

uint64_t decode_instruction(DecodeMode mode, char* assembly, uint64_t assembly_sz, Exception* excep) {
  op_mode = get_cpu_operation_mode();
  
  uint64_t rip = cpu.rip;
  uint8_t* rip_abs = ram + get_flat_address(cpu.cs, cpu.rip);

  prefixes = (InstructionPrefixes){ 0 };
  check_legacy_prefixes(&rip, &rip_abs);

  if( op_mode == LONG_MODE )
    check_rex_prefix(&rip, &rip_abs);
  
  return read_and_decode_opcode(mode, rip, rip_abs, assembly, assembly_sz, excep);
}

#endif
