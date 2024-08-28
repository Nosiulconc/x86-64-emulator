#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <ncurses.h>

#include "x64_cpu.h"
#include "inst_decoder.h"
#include "string_struct.h"

void panic(const char* msg) {
  endwin();
  printf("ERROR: %s\n", msg);
  exit(1);
}

// ******************* //
// **   EMULATION   ** //
// ******************* // 

x64_CPU cpu;
OperationMode op_mode = REAL_MODE;
uint64_t inst_counter;

x87_FPU fpu;

const uint64_t RAM_CAPACITY = 32000000;
const uint64_t DISK_CAPACITY = 32000000;

uint8_t* ram;
uint8_t* disk;

static void init_ram(void) {
  if( (ram = malloc(RAM_CAPACITY)) == NULL )
    panic("RAM memory couldn't be allocated!");
}

static void init_disk(void) {
  if( (disk = malloc(DISK_CAPACITY)) == NULL )
    panic("Disk memory couldn't be allocated!");
}

static uint64_t load_file_into_disk(const char* path, uint8_t* buffer) {
  FILE* file;
  if( (file = fopen(path, "rb")) == NULL )
    panic("Couldn't open the file!");

  if( fseek(file, 0, SEEK_END) < 0 ) {
    puts("ERROR: Couldn't reach the end of the file!");
    goto close_file_then_exit;
  }
  int64_t file_size;
  if( (file_size = ftell(file)) == -1 ) {
    puts("ERROR: Couldn't get the file size!");
    goto close_file_then_exit;
  }
  if( fseek(file, 0, SEEK_SET) < 0 ) {
    puts("ERROR: Couldn't reach the start of the file!");
    goto close_file_then_exit;
  }
  
  if( !fread(buffer, file_size, 1, file) ) {
    puts("ERROR: Couldn't read the file!");
    goto close_file_then_exit;
  }

  if( fclose(file) == EOF )
    panic("Couldn't close the file!");

  return file_size;

close_file_then_exit:
  if( fclose(file) == EOF )
    panic("Couldn't close the file!");
  endwin();
  exit(1);
}

static void load_inst_counter_from_file(const char* path) {
  FILE* file;
  if( (file = fopen(path, "r")) == NULL )
    panic("Couldn't open the file!");

  if( fscanf(file, "%ld", &inst_counter) < 1 ) {
    puts("Couldn't parse inst_counter!");
    if( fclose(file) == EOF )
      panic("Couldn't close the file!");
    endwin();
    exit(1);
  }

  if( fclose(file) == EOF )
    panic("Couldn't close the file!");
}

static void save_inst_counter_to_file(const char* path) {
  FILE* file;
  if( (file = fopen(path, "w")) == NULL )
    panic("Couldn't open the file!");

  if( fprintf(file, "%ld", inst_counter) == EOF ) {
    puts("Couldn't save inst_counter!");
    if( fclose(file) == EOF )
      panic("Couldn't close the file!");
    endwin();
    exit(1);
  }

  if( fclose(file) == EOF )
    panic("Couldn't close the file!");
}

static void load_bootloader_into_ram(void) {
  // loosely following the EL TORITO specification

  const uint64_t default_entry_ptr = (*(uint32_t*)(disk + 0x8847)) * 2048 + 32;
    
  if( disk[default_entry_ptr] == 0 )
    panic("Default entry is marked as not bootable!");

  if( disk[default_entry_ptr + 1] != 0 )
    panic("Can only handle \"no emulation\" boot media type!");

  uint64_t load_segment = *(uint16_t*)(disk + default_entry_ptr + 2);
  if( load_segment == 0 )
    load_segment = 0x7C0;

  const uint64_t sector_count   = *(uint16_t*)(disk + default_entry_ptr + 6);
  const uint64_t bootloader_ptr = (*(uint32_t*)(disk + default_entry_ptr + 8)) * 2048;

  if( load_segment * 16 + sector_count * 2048 > RAM_CAPACITY )
    panic("Not enought RAM to load the bootloader!");

  memcpy(ram + load_segment * 16, disk + bootloader_ptr, sector_count * 2048);
}

// Thanks to https://wiki.osdev.org/BIOS32 
static void setup_BIOS32(void) {
  uint8_t* BIOS32_ptr = ram + 0xE0000;
  const uint32_t signature = 0x5F32335F;
  const uint32_t entry_point = 0x0E0010; // We'll catch far calls to there
  const uint64_t zero = 0;
  const uint8_t len = 1;
  const uint8_t checksum = 0xBE; // trust
  
  // --- ASM ---
  // mov ebx, PCI_BASE_ADDR
  // mov edx, PCI_OFFSET
  // mov al, 0
  // retf
  uint8_t bios_proc[] = "\xBB\x00\x00\x00\x00\xBA\x00\x00\x00\x00\xB0\x00\xCB"; 
  const uint32_t PCI_BASE_ADDR = 0;
  const uint32_t PCI_OFFSET = 0;

  memcpy(BIOS32_ptr, &signature, 4);
  memcpy(BIOS32_ptr + 4, &entry_point, 4);
  memcpy(BIOS32_ptr + 8, &zero, 1);
  memcpy(BIOS32_ptr + 9, &len, 1);
  memcpy(BIOS32_ptr + 10, &checksum, 1);
  memcpy(BIOS32_ptr + 11, &zero, 5);

  memcpy(BIOS32_ptr + 16, bios_proc, sizeof(bios_proc));
  memcpy(BIOS32_ptr + 17, &PCI_BASE_ADDR, 4);
  memcpy(BIOS32_ptr + 22, &PCI_OFFSET, 4);
}

// ************ //
// **   UI   ** //
// ************ //

char str[29] = "none";
String assembly = { 28, str };
uint64_t phyaddr = 0;
char* phyaddr_seg = "--";

static void draw_bytes(WINDOW* win, uint8_t* base_addr, uint8_t* bytes, uint64_t rel_addr) {
  uint8_t* rip = base_addr + get_flat_address(CS, get_ip());
  const uint8_t vert_offset = 3;

  mvwprintw(win, 1,  1, "----------------");
  mvwprintw(win, 1, 66, "----------------");
  for(uint8_t n = 0; n < 16; ++n)
    mvwprintw(win, 1, n*3 + 18, "%02hhx", n);

  for(int32_t i = 0; i < 16; ++i) {
    mvwprintw(win, i + vert_offset, 1, "%015lx: ", rel_addr);
    rel_addr += 16;
    for(int32_t j = 0; j < 16; ++j) {
      if( bytes == rip ) wattron(win, A_REVERSE);
      mvwprintw(win, i + vert_offset, j*3 + 18, "%02hhx", *bytes);
      if( bytes == rip ) wattroff(win, A_REVERSE);
      
      const char c = ( (*bytes) >= 0x20 && (*bytes) <= 0x7E ) ? (*bytes) : '.';
      mvwprintw(win, i + vert_offset, j + 66, "%c", c);
      
      ++bytes;
    }
  }
}

static void draw_hexwin(WINDOW* win, int32_t width, int32_t height, uint8_t* base_addr, uint8_t* bytes) {
  werase(win);
  box(win, 0, 0);
  
  for(int32_t i = 1; i < width - 1; ++i) mvwprintw(win, height - 3, i, "-");
  draw_bytes(win, base_addr, bytes, bytes - base_addr);
  wrefresh(win);
}

static void draw_ctrlwin(WINDOW* win, int32_t width, int32_t height) {
  box(win, 0, 0);

  mvwprintw(win, 1,  (width - 8) / 2, "CONTROLS");
  mvwprintw(win, 3,  2, "q: quit");
  mvwprintw(win, 4,  2, "up: scroll down");
  mvwprintw(win, 5,  2, "down: scroll up");
  mvwprintw(win, 6,  2, "s: save counter");
  
  mvwprintw(win, 8,  2, "g: goto segment");
  mvwprintw(win, 9,  2, "j: jump to rip");
  mvwprintw(win, 10, 2, "e: execute/step");
  mvwprintw(win, 11, 2, "u: run until");
  wrefresh(win);
}

static void draw_regwin(WINDOW* win, int32_t width, int32_t height) {
  werase(win);
  box(win, 0, 0);

  mvwprintw(win, 1, 1, "rax: %08lx.%04x.%02hhx.%02hhx", cpu.rax >> 32, cpu.eax >> 16, cpu.ah, cpu.al);
  mvwprintw(win, 2, 1, "rbx: %08lx.%04x.%02hhx.%02hhx", cpu.rbx >> 32, cpu.ebx >> 16, cpu.bh, cpu.bl);
  mvwprintw(win, 3, 1, "rcx: %08lx.%04x.%02hhx.%02hhx", cpu.rcx >> 32, cpu.ecx >> 16, cpu.ch, cpu.cl);
  mvwprintw(win, 4, 1, "rdx: %08lx.%04x.%02hhx.%02hhx", cpu.rdx >> 32, cpu.edx >> 16, cpu.dh, cpu.dl);

  mvwprintw(win, 6, 1, "rdi: %08lx.%04x.%02x.%02hhx", cpu.rdi >> 32, cpu.edi >> 16, cpu.di >> 8, cpu.dil);
  mvwprintw(win, 7, 1, "rsi: %08lx.%04x.%02x.%02hhx", cpu.rsi >> 32, cpu.esi >> 16, cpu.si >> 8, cpu.sil);

  mvwprintw(win, 9,  1, "rbp: %08lx.%04x.%02x.%02hhx", cpu.rbp >> 32, cpu.ebp >> 16, cpu.bp >> 8, cpu.bpl);
  mvwprintw(win, 10, 1, "rsp: %08lx.%04x.%02x.%02hhx", cpu.rsp >> 32, cpu.esp >> 16, cpu.sp >> 8, cpu.spl);

  mvwprintw(win, 12, 1, "r8 : %08lx.%04x.%02x.%02hhx", cpu.r8>>32, cpu.r8d>>16, cpu.r8w>>8, cpu.r8b);
  mvwprintw(win, 13, 1, "r9 : %08lx.%04x.%02x.%02hhx", cpu.r9>>32, cpu.r9d>>16, cpu.r9w>>8, cpu.r9b);
  mvwprintw(win, 14, 1, "r10: %08lx.%04x.%02x.%02hhx", cpu.r10>>32, cpu.r10d>>16, cpu.r10w>>8, cpu.r10b);
  mvwprintw(win, 15, 1, "r11: %08lx.%04x.%02x.%02hhx", cpu.r11>>32, cpu.r11d>>16, cpu.r11w>>8, cpu.r11b);
  mvwprintw(win, 16, 1, "r12: %08lx.%04x.%02x.%02hhx", cpu.r12>>32, cpu.r12d>>16, cpu.r12w>>8, cpu.r12b);
  mvwprintw(win, 17, 1, "r13: %08lx.%04x.%02x.%02hhx", cpu.r13>>32, cpu.r13d>>16, cpu.r13w>>8, cpu.r13b);
  mvwprintw(win, 18, 1, "r14: %08lx.%04x.%02x.%02hhx", cpu.r14>>32, cpu.r14d>>16, cpu.r14w>>8, cpu.r14b);
  mvwprintw(win, 19, 1, "r15: %08lx.%04x.%02x.%02hhx", cpu.r15>>32, cpu.r15d>>16, cpu.r15w>>8, cpu.r15b);

  mvwprintw(win, 1, 26, "cs: %04x", cpu.cs);
  mvwprintw(win, 2, 26, "ss: %04x", cpu.ss);
  mvwprintw(win, 3, 26, "ds: %04x", cpu.ds);
  mvwprintw(win, 4, 26, "es: %04x", cpu.es);
  mvwprintw(win, 5, 26, "fs: %04x", cpu.fs);
  mvwprintw(win, 6, 26, "gs: %04x", cpu.gs);

  mvwprintw(win, 8,  26, "RFLAGS");
  mvwprintw(win, 9,  26, "CF:%lu", GET_RFLAGS(RFLAGS_CF));
  mvwprintw(win, 10, 26, "PF:%lu", GET_RFLAGS(RFLAGS_PF));
  mvwprintw(win, 11, 26, "AF:%lu", GET_RFLAGS(RFLAGS_AF));
  mvwprintw(win, 12, 26, "ZF:%lu", GET_RFLAGS(RFLAGS_ZF));
  mvwprintw(win, 13, 26, "SF:%lu", GET_RFLAGS(RFLAGS_SF));
  mvwprintw(win, 14, 26, "IF:%lu", GET_RFLAGS(RFLAGS_IF));
  mvwprintw(win, 15, 26, "DF:%lu", GET_RFLAGS(RFLAGS_DF));
  mvwprintw(win, 16, 26, "OF:%lu", GET_RFLAGS(RFLAGS_OF));

  mvwprintw(win, 8,  33, "CR0");
  mvwprintw(win, 9,  33, "PE:%lu", GET_CR0(CR0_PE));
  mvwprintw(win, 10, 33, "ET:%lu", GET_CR0(CR0_ET));
  mvwprintw(win, 11, 33, "NE:%lu", GET_CR0(CR0_NE));
  mvwprintw(win, 12, 33, "PG:%lu", GET_CR0(CR0_PG));

  mvwprintw(win, 8,  44, "CR3");
  mvwprintw(win, 9,  44, "ADR:%014lx", cpu.cr3 & 0xFFFFFFFFFFFFF000);

  mvwprintw(win, 8,  38, "CR4");
  mvwprintw(win, 9,  38, "PSE:%lu", GET_CR4(CR4_PSE));
  mvwprintw(win, 10, 38, "PAE:%lu", GET_CR4(CR4_PAE));
  mvwprintw(win, 11, 38, "PGE:%lu", GET_CR4(CR4_PGE));

  mvwprintw(win, 14, 33, "EFER");
  mvwprintw(win, 15, 33, "LME:%lu", GET_EFER(EFER_LME));

  mvwprintw(win, 17, 33, "FS_BASE: %016lx", cpu.IA32_FS_BASE);
  mvwprintw(win, 18, 33, "GS_BASE: %016lx", cpu.IA32_GS_BASE);

  mvwprintw(win, 5, 35, "gdtr: %04x:%016lx", cpu.gdtr.limit, cpu.gdtr.base);
  mvwprintw(win, 6, 35, "idtr: %04x:%016lx", cpu.idtr.limit, cpu.idtr.base);

  wattron(win, A_REVERSE);
  mvwprintw(win, 1, 35, "rip:%016lx", cpu.rip);
  mvwprintw(win, 2, 35, "%s", assembly.str);
  mvwprintw(win, 3, 35, "phyaddr:%s:%016lx", phyaddr_seg, phyaddr);
  wattroff(win, A_REVERSE);
  wrefresh(win);
}

static void draw_fpuwin(WINDOW* win, int32_t width, int32_t height) {
  box(win, 0, 0);

  const int32_t regs_x = 1 + (width - 2 - 28) / 2;
  for(int32_t i = 7; i >= 0; --i) {
    uint8_t tag = (fpu.tags >> (2*i)) & 0b11;
    uint8_t* reg = fpu.r0 + (10*i);
    mvwprintw(win, 8 - i, regs_x, "r%u: %04x%016lx  %u%u", i, *(uint16_t*)(reg+8), *(uint64_t*)reg, tag>>1, tag&1);
  }

  mvwprintw(win, 10, 2, "TOP:%01hhx", GET_FPU_TOP);
  mvwprintw(win, 10, 8, "%10.11Lf", *(f80_t*)(fpu.r0 + 10*GET_FPU_TOP));
  wrefresh(win);
}

WINDOW* telwin;
const int32_t tel_width  = 32;
const int32_t tel_height = 22;
int32_t telcur_x = 1, telcur_y = 1;

void telwin_output(char c) {
  mvwprintw(telwin, telcur_y, telcur_x, "%c", c);
  
  ++telcur_x;
  if( telcur_x >= tel_width - 1 ) {
    telcur_x = 1;
    ++telcur_y;
    if( telcur_y >= tel_height - 1 )
      telcur_y = 1;
  }
  wrefresh(telwin);
}

static int32_t get_input_hex(WINDOW* hexwin, int32_t hex_width, int32_t hex_height, uint64_t* seg) {
  wmove(hexwin, hex_height - 2, 1);

  curs_set(TRUE);
  echo();

  char buff[hex_width - 2];
  wgetnstr(hexwin, buff, hex_width - 2);
  
  noecho();
  curs_set(FALSE);

  if( sscanf(buff, "%lx", seg) < 1 ) return 1;

  return 0;
}

int32_t main(void) {
  init_ram();
  init_disk();
  init_cpu();

  setup_BIOS32();
  const uint64_t iso_size = load_file_into_disk("./TempleOS.iso", disk);
  load_bootloader_into_ram();

  uint8_t* hex_addr = ram;
  uint8_t* hex_base_addr = ram;
  uint64_t hex_buffer_size = RAM_CAPACITY;

  WINDOW* stdwin;
  if( (stdwin = initscr()) == NULL )
    panic("Failed to initialize ncurses!");

  cbreak();
  noecho();
  keypad(stdwin, TRUE);
  curs_set(FALSE);

  // hex viewer
  const int32_t hex_width  = 83;
  const int32_t hex_height = 22;
  WINDOW* hexwin = newwin(hex_height, hex_width, 0, 0);
  wrefresh(stdwin);

  draw_hexwin(hexwin, hex_width, hex_height, hex_base_addr, hex_addr);

  // controls
  const int32_t ctrl_width  = 19;
  const int32_t ctrl_height = 21;
  WINDOW* ctrlwin = newwin(ctrl_height, ctrl_width, hex_height, hex_width - ctrl_width);
  wrefresh(stdwin);

  draw_ctrlwin(ctrlwin, ctrl_width, ctrl_height);

  // CPU registers
  const int32_t reg_width  = hex_width - ctrl_width;
  const int32_t reg_height = ctrl_height;
  WINDOW* regwin = newwin(reg_height, reg_width, hex_height, 0);
  wrefresh(stdwin);

  draw_regwin(regwin, reg_width, reg_height);

  // FPU registers
  const int32_t fpu_width  = tel_width;
  const int32_t fpu_height = ctrl_height;
  WINDOW* fpuwin = newwin(fpu_height, fpu_width, hex_height, hex_width);
  wrefresh(stdwin);

  draw_fpuwin(fpuwin, fpu_width, fpu_height);

  // teletype
  telwin = newwin(tel_height, tel_width, 0, hex_width);
  wrefresh(stdwin);

  box(telwin, 0, 0);
  wrefresh(telwin);

  // get up to speed
  load_inst_counter_from_file("./inst_counter.txt");
  for(uint64_t i = 0; i < inst_counter; ++i)
    decode_instruction(assembly);

  draw_hexwin(hexwin, hex_width, hex_height, hex_base_addr, hex_addr);
  draw_regwin(regwin, reg_width, reg_height);
  draw_fpuwin(fpuwin, fpu_width, fpu_height);

  int32_t c;
  while( (c = wgetch(stdwin)) != 'q' ) {
    switch( c ) {
      case KEY_UP: {
        if( hex_addr > hex_base_addr ) {
          hex_addr -= 16;
          draw_hexwin(hexwin, hex_width, hex_height, hex_base_addr, hex_addr);
        }
        break;
      }
      case KEY_DOWN: {
        if( hex_addr + 256 < hex_base_addr + hex_buffer_size ) {
          hex_addr += 16;
          draw_hexwin(hexwin, hex_width, hex_height, hex_base_addr, hex_addr);
        }
        break;
      }
      case 'g': {
        uint64_t seg;
        if( get_input_hex(hexwin, hex_width, hex_height, &seg) )
          goto exit_goto_seg;

        seg = (seg >> 4) << 4;
        if( seg + 256 > hex_buffer_size )
          seg = hex_buffer_size - 256;
        hex_addr = hex_base_addr + seg;

      exit_goto_seg:
        draw_hexwin(hexwin, hex_width, hex_height, hex_base_addr, hex_addr);
        break;
      }
      case 'j': {
        uint64_t seg = (get_flat_address(CS, get_ip()) >> 4) << 4;
        hex_addr = hex_base_addr + seg;

        draw_hexwin(hexwin, hex_width, hex_height, hex_base_addr, hex_addr);
        break;
      }
      case 'e': {
        decode_instruction(assembly);
        ++inst_counter;
        
        draw_hexwin(hexwin, hex_width, hex_height, hex_base_addr, hex_addr);
        draw_regwin(regwin, reg_width, reg_height);
        draw_fpuwin(fpuwin, fpu_width, fpu_height);
        break;
      }
      case 's': {
        save_inst_counter_to_file("./inst_counter.txt");
        break;
      }
      case 'u': {
        uint64_t addr;
        if( get_input_hex(hexwin, hex_width, hex_height, &addr) )
          goto exit_run_until;

        while( get_flat_address(CS, get_ip()) != addr ) {
          decode_instruction(assembly);
          ++inst_counter;
        }

      exit_run_until:
        draw_hexwin(hexwin, hex_width, hex_height, hex_base_addr, hex_addr);
        draw_regwin(regwin, reg_width, reg_height);
        draw_fpuwin(fpuwin, fpu_width, fpu_height);
        break;
      }
    }
  }

  endwin();

  return 0;
}
