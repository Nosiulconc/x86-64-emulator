#ifndef _X64_CPU_H_
#define _X64_CPU_H_

#include <stdint.h>

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

  uint64_t rip;
  uint64_t rflags;
  
  uint16_t cs, ss, ds, es, fs, gs;
  
  struct { uint16_t limit; uint64_t base; } gdtr; 
  struct { uint16_t limit; uint64_t base; } idtr;
  uint16_t ldtr;
  uint16_t tr;

  uint64_t cr0, cr1, cr2, cr3, cr4;
  uint64_t IA32_EFER;
}
x64_CPU;

#define CR0_PE 1 // 0 = 16-bit real mode, 1 = 32-bit protected mode

#endif
