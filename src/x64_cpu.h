#ifndef _X64_CPU_H_
#define _X64_CPU_H_

#include <stdint.h>
#include <stdlib.h>

extern void panic(const char* msg);

typedef enum { REAL_MODE, PROTECTED_MODE, LONG_MODE } OperationMode;

typedef struct {
  uint64_t base_addr;
  uint8_t db : 1;
  uint8_t l  : 1;
}
SegRegCache;

typedef struct {
  union { uint64_t rax; uint32_t eax; uint16_t ax; struct { uint8_t al; uint8_t ah; }; };
  union { uint64_t rbx; uint32_t ebx; uint16_t bx; struct { uint8_t bl; uint8_t bh; }; };
  union { uint64_t rcx; uint32_t ecx; uint16_t cx; struct { uint8_t cl; uint8_t ch; }; };
  union { uint64_t rdx; uint32_t edx; uint16_t dx; struct { uint8_t dl; uint8_t dh; }; };

  union { uint64_t rdi; uint32_t edi; uint16_t di; uint8_t dil; };
  union { uint64_t rsi; uint32_t esi; uint16_t si; uint8_t sil; };
  
  union { uint64_t rbp; uint32_t ebp; uint16_t bp; uint8_t bpl; };
  union { uint64_t rsp; uint32_t esp; uint16_t sp; uint8_t spl; };
  
  union { uint64_t r8;  uint32_t r8d;  uint16_t r8w;  uint8_t r8b;  };
  union { uint64_t r9;  uint32_t r9d;  uint16_t r9w;  uint8_t r9b;  };
  union { uint64_t r10; uint32_t r10d; uint16_t r10w; uint8_t r10b; };
  union { uint64_t r11; uint32_t r11d; uint16_t r11w; uint8_t r11b; };
  union { uint64_t r12; uint32_t r12d; uint16_t r12w; uint8_t r12b; };
  union { uint64_t r13; uint32_t r13d; uint16_t r13w; uint8_t r13b; };
  union { uint64_t r14; uint32_t r14d; uint16_t r14w; uint8_t r14b; };
  union { uint64_t r15; uint32_t r15d; uint16_t r15w; uint8_t r15b; };

  union { uint64_t rip;    uint32_t eip;    uint16_t ip;    };
  union { uint64_t rflags; uint32_t eflags; uint16_t flags; };
 
  SegRegCache cs_cache, ss_cache, ds_cache, es_cache, fs_cache, gs_cache;
  uint16_t cs, ss, ds, es, fs, gs;
  
  struct { uint16_t limit; uint64_t base; } gdtr; 
  struct { uint16_t limit; uint64_t base; } idtr;
  uint16_t ldtr;
  uint16_t tr;

  uint64_t cr0, cr1, cr2, cr3, cr4;
  uint64_t IA32_EFER;

  uint8_t io_ports[65536];
}
x64_CPU;

#define RFLAGS_CF (uint64_t)(1 <<  0)
#define RFLAGS_PF (uint64_t)(1 <<  2)
#define RFLAGS_AF (uint64_t)(1 <<  4)
#define RFLAGS_ZF (uint64_t)(1 <<  6)
#define RFLAGS_SF (uint64_t)(1 <<  7)
#define RFLAGS_IF (uint64_t)(1 <<  9)
#define RFLAGS_DF (uint64_t)(1 << 10)
#define RFLAGS_OF (uint64_t)(1 << 11)

#define CR0_PE (uint64_t)(1 << 0) // 0 = 16-bit real mode, 1 = 32-bit protected mode

extern OperationMode op_mode;
extern x64_CPU cpu;
extern uint8_t* ram;

void cpu_operation_mode_transition(void) {
  switch( op_mode ) {
    case REAL_MODE: {
      // The CPU goes to protected mode only after the code segment has been set explicitly
      if( (cpu.cr0 & CR0_PE) == 1 )
        op_mode = PROTECTED_MODE;
      break;
    }
    case PROTECTED_MODE: {
      // TODO transition to long mode
      break;
    }
    case LONG_MODE: break;
  }
}

void init_cpu(void) {
  cpu.rflags     = 0x2;
  
  cpu.rip        = 0x7C00;
  
  cpu.cr0        = 0x60000010;
  cpu.cr2        = 0x0;
  cpu.cr3        = 0x0;
  cpu.cr4        = 0x0;
  
  cpu.cs_cache   = (SegRegCache){ 0 };
  cpu.cs         = 0x0;

  cpu.ss_cache   = (SegRegCache){ 0 };
  cpu.ss         = 0x0;
  
  cpu.ds_cache   = (SegRegCache){ 0 };
  cpu.ds         = 0x0;

  cpu.es_cache   = (SegRegCache){ 0 };
  cpu.es         = 0x0;

  cpu.fs_cache   = (SegRegCache){ 0 };
  cpu.fs         = 0x0;

  cpu.gs_cache   = (SegRegCache){ 0 };
  cpu.gs         = 0x0;

  cpu.rdx        = 0x0; // cleared: model info is not used anyways
  cpu.rax        = 0x0; // BIST successful
  cpu.rbx        = 0x0;
  cpu.rcx        = 0x0;
  cpu.rsi        = 0x0;
  cpu.rdi        = 0x0;
  cpu.rbp        = 0x0;
  cpu.rsp        = 0x0;

  cpu.gdtr.base  = 0x0;
  cpu.gdtr.limit = 0xFFFF;
  cpu.idtr.base  = 0x0;
  cpu.idtr.limit = 0xFFFF;

  cpu.ldtr       = 0x0;
  cpu.tr         = 0x0;

  cpu.r8         = 0x0;
  cpu.r9         = 0x0;
  cpu.r10        = 0x0;
  cpu.r11        = 0x0;
  cpu.r12        = 0x0;
  cpu.r13        = 0x0;
  cpu.r14        = 0x0;
  cpu.r15        = 0x0;

  cpu.IA32_EFER  = 0x0;
}

uint64_t get_segment_descriptor(uint64_t segment) {
  if( segment & 0b100 ) panic("LDT addressing not implemented!");
  return *(uint64_t*)(ram + cpu.gdtr.base + (segment >> 3)*8);
}

typedef enum { ES, CS, SS, DS, FS, GS } SegmentRegister;

char* seg_reg_str[] = {"es","cs","ss","ds","fs","gs"};

uint16_t* seg_reg_addr[] = {&(cpu.es),&(cpu.cs),&(cpu.ss),&(cpu.ds),&(cpu.fs),&(cpu.gs)};

SegRegCache* seg_reg_cache[] = {&(cpu.es_cache),&(cpu.cs_cache),&(cpu.ss_cache),
                                &(cpu.ds_cache),&(cpu.fs_cache),&(cpu.gs_cache)};

static void set_seg_reg(SegmentRegister seg_reg, uint64_t segment) {
  memcpy(seg_reg_addr[seg_reg], &segment, 2);
  switch( op_mode ) {
    case REAL_MODE: seg_reg_cache[seg_reg]->base_addr = segment << 4; break;
    case PROTECTED_MODE: {
      const uint64_t seg_desc = get_segment_descriptor(segment);
      seg_reg_cache[seg_reg]->base_addr = ((seg_desc >> 32) & 0xFF000000) | ((seg_desc >> 16) & 0xFFFFFF);
      seg_reg_cache[seg_reg]->db = (seg_desc >> 54) & 0x1;
      seg_reg_cache[seg_reg]->l = (seg_desc >> 53) & 0x1;
      break;
    }
    default: panic("Setting a segment register in long mode isn't implemented!");
  }
}

uint64_t get_flat_address(SegmentRegister seg_reg, uint64_t offset) {
  return seg_reg_cache[seg_reg]->base_addr + offset;
}

uint64_t get_ip(void) {
  switch( op_mode ) {
    case REAL_MODE:      return cpu.ip;
    case PROTECTED_MODE: return cpu.eip;
    case LONG_MODE:      return cpu.rip;
  }
}

#endif
