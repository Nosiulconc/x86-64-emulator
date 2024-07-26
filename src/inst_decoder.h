#ifndef _INST_DECODER_H_
#define _INST_DECODER_H_

#include <stdlib.h>
#include <stdint.h>

#include "x64_cpu.h"

extern x64_CPU cpu;
extern void panic(const char* msg);

typedef enum { EXECUTE_ONLY, DISASSEMBLE_ONLY, EXECUTE_DISASSEMBLE } DecodeMode;
typedef enum { REAL_MODE, PROTECTED_MODE, LONG_MODE } OperationMode;

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

typedef struct {

}
OpcodeInfo;

static const OpcodeInfo one_byte_opcodes = {};
static const OpcodeInfo two_byte_opcodes = {};

static OperationMode op_mode;

static OperationMode get_cpu_operation_mode(void) {
  if( (cpu.cr0 & CR0_PE) == 0 )
    return REAL_MODE;

  return PROTECTED_MODE;
}

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

static uint8_t* read_and_decode_opcode(uint8_t* rip) {
  if( *rip == 0x0F ) {
    ++rip;
    if( *rip == 0x38 || *rip == 0x3A ) {
      panic("3 byte opcodes not supported!");
    }
    else {
      // 2 byte opcodes
    }
  }
  else {
    // 1 byte opcodes
  }
}

uint8_t* decode_instruction(DecodeMode mode, uint8_t* rip, char* assembly, uint64_t assembly_sz) {
  op_mode = get_cpu_operation_mode();

  prefixes = (InstructionPrefixes){ 0 };
  rip = check_legacy_prefixes(rip);

  if( op_mode == LONG_MODE )
    rip = check_rex_prefix(rip);

  return read_and_decode_opcode(rip);
}

#endif
