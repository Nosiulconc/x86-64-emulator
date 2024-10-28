WIP x86-64 CPU emulator:

The github is just in case my hardrive dies. Since it makes no guarantees, it will hopefully not be used for something useful.

To get it working, you need the new curses library (v.6.3), SDL2 and a version of GCC that compiles 2011 standard C.

*** TECHNOLOGIES SEEN (not exhaustive, more or less in chronological order): ***

- BIOS 16-BIT VECTOR INTERRUPTS:
  - VGA mode
  - disk access
  - RAM layout

- CPUID instruction:
  - 64-bit capable? yes.
  - 1 GB pages available? yes.
  - cache line size = 128 bytes.

- BIOS32: Protected Mode BIOS interrupts (is PCI available? not clear.)

- RTC: Real Time Clock (CMOS for the date)

- x87 FPU: Floating Point Unit

- PIT: Programmable Interrupt Timer

- HPET: High Precision Event Timer

- PIC: Programmable Interrupt Controller

- ATAPI

*** USEFUL LINKS: ***

Online dis/assembler: https://shell-storm.org/online/Online-Assembler-and-Disassembler/
TempleOS source code (files + symbols): https://templeos.slendi.dev/Wb/Home/Web/TempleOS.html
BIOS 16-bit vector interrupts: https://www.ctyme.com/intr/
x64 opcode tables: http://ref.x86asm.net/index.html
General information: https://wiki.osdev.org/

Intel manuals: https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html
AMD manuals: https://www.amd.com/content/dam/amd/en/documents/processor-tech-docs/programmer-references/40332.pdf

Trust the disassembler more than the manuals.

*** WHERE AM I? ***

Instructions executed: 1670937

At this stage of development, everything should be deterministic to avoid horrors beyond our comprehension.

The stack trace:

- KMain:    https://templeos.xslendi.xyz/Wb/Kernel/KMain.html#l135
  - DskChg:    https://templeos.slendi.dev/Wb/Kernel/BlkDev/DskDrv.html#l237
