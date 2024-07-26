#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <ncurses.h>

#include "x64_cpu.h"
#include "inst_decoder.h"

void panic(const char* msg) {
  printf("ERROR: %s\n", msg);
  exit(1);
}

// ******************* //
// **   EMULATION   ** //
// ******************* // 

x64_CPU cpu;

#define RAM_CAPACITY   32000000 // 512 Mb
#define DISK_CAPACITY  32000000 //  32 Mb

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
  exit(1);
}

static void load_bootloader_into_ram(void) {
  // loosely following the EL TORITO specification

  uint32_t default_entry_ptr = (*(uint32_t*)(disk + 0x8847)) * 2048 + 32;
    
  if( disk[default_entry_ptr] == 0 )
    panic("Default entry is marked as not bootable!");

  if( disk[default_entry_ptr + 1] != 0 )
    panic("Can only handle \"no emulation\" boot media type!");

  uint16_t load_segment = *(uint16_t*)(disk + default_entry_ptr + 2);
  if( load_segment == 0 )
    load_segment = 0x7C0;

  uint16_t sector_count   = *(uint16_t*)(disk + default_entry_ptr + 6);
  uint32_t bootloader_ptr = (*(uint32_t*)(disk + default_entry_ptr + 8)) * 2048;

  if( load_segment * 16 + sector_count * 2048 > RAM_CAPACITY )
    panic("Not enought RAM to load the bootloader!");

  memcpy(ram + load_segment * 16, disk + bootloader_ptr, sector_count * 2048);
}

static void init_cpu(void) {
  cpu.rflags     = 0x2;
  
  cpu.rip        = 0x7C00;
  
  cpu.cr0        = 0x60000010;
  cpu.cr2        = 0x0;
  cpu.cr3        = 0x0;
  cpu.cr4        = 0x0;
  
  cpu.cs         = 0x0;
  cpu.ss         = 0x0;
  cpu.ds         = 0x0;
  cpu.es         = 0x0;
  cpu.fs         = 0x0;
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

// ************ //
// **   UI   ** //
// ************ //

static void draw_bytes(WINDOW* win, uint8_t* bytes, uint64_t addr) {
  for(int32_t i = 0; i < 16; ++i) {
    mvwprintw(win, i + 1, 1, "%015lx: ", addr);
    addr += 16;
    for(int32_t j = 0; j < 16; ++j) {
      mvwprintw(win, i + 1, j*3 + 18, "%02hhx", *bytes);
      
      const char c = ( (*bytes) >= 0x20 && (*bytes) <= 0x7E ) ? (*bytes) : '.';
      mvwprintw(win, i + 1, j + 66, "%c", c);
      
      ++bytes;
    }
  }
}

static void draw_hexwin(WINDOW* win, int32_t width, int32_t height, uint8_t* bytes, uint8_t* addr) {
  box(win, 0, 0);
  for(int32_t i = 1; i < width - 1; ++i) mvwprintw(win, height - 3, i, "-");
  draw_bytes(win, addr, addr - bytes);
}

static void draw_ctrlwin(WINDOW* win, int32_t width, int32_t height) {
  box(win, 0, 0);
  mvwprintw(win, 1, (width - 8) / 2, "CONTROLS");
  mvwprintw(win, 3, 2, "q: quit");
  mvwprintw(win, 4, 2, "up: scroll down");
  mvwprintw(win, 5, 2, "down: scroll up");
  mvwprintw(win, 6, 2, "g: goto segment");
}

static void draw_regwin(WINDOW* win, int32_t width, int32_t height) {
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

  mvwprintw(win, 1, 27, "cs  : %04x", cpu.cs);
  mvwprintw(win, 2, 27, "ss  : %04x", cpu.ss);
  mvwprintw(win, 3, 27, "ds  : %04x", cpu.ds);
  mvwprintw(win, 4, 27, "es  : %04x", cpu.es);
  mvwprintw(win, 5, 27, "fs  : %04x", cpu.fs);
  mvwprintw(win, 6, 27, "gs  : %04x", cpu.gs);

  mvwprintw(win, 1, 39, "rip: %016lx", cpu.rip);
}

int32_t main(void) {
  init_ram();
  init_disk();
  init_cpu();

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
  const int32_t hex_height = 20;
  WINDOW* hexwin = newwin(hex_height, hex_width, 0, 0);
  wrefresh(stdwin);

  draw_hexwin(hexwin, hex_width, hex_height, hex_base_addr, hex_addr);
  wrefresh(hexwin);

  // controls
  const int32_t ctrl_width  = 19;
  const int32_t ctrl_height = 21;
  WINDOW* ctrlwin = newwin(ctrl_height, ctrl_width, hex_height, hex_width - ctrl_width);
  wrefresh(stdwin);

  draw_ctrlwin(ctrlwin, ctrl_width, ctrl_height);
  wrefresh(ctrlwin);

  // registers
  const int32_t reg_width  = hex_width - ctrl_width;
  const int32_t reg_height = ctrl_height;
  WINDOW* regwin = newwin(reg_height, reg_width, hex_height, 0);
  wrefresh(stdwin);

  draw_regwin(regwin, reg_width, reg_height);
  wrefresh(regwin);

  int32_t c;
  while( (c = wgetch(stdwin)) != 'q' ) {
    switch( c ) {
      case KEY_UP: {
        if( hex_addr > hex_base_addr ) {
          hex_addr -= 16;
          draw_hexwin(hexwin, hex_width, hex_height, hex_base_addr, hex_addr);
          wrefresh(hexwin);
        }
        break;
      }
      case KEY_DOWN: {
        if( hex_addr + 256 < hex_base_addr + hex_buffer_size ) {
          hex_addr += 16;
          draw_hexwin(hexwin, hex_width, hex_height, hex_base_addr, hex_addr);
          wrefresh(hexwin);
        }
        break;
      }
      case 'g': {
        wmove(hexwin, hex_height - 2, 1);
        
        curs_set(TRUE);
        echo();

        char buff[hex_width - 2];
        wgetnstr(hexwin, buff, hex_width - 2);
        
        noecho();
        curs_set(FALSE);

        uint64_t seg;
        if( sscanf(buff, "%lx", &seg) < 1 ) {
          werase(hexwin);
          draw_hexwin(hexwin, hex_width, hex_height, hex_base_addr, hex_addr);
          wrefresh(hexwin);
          break;
        }

        seg = (seg >> 4) << 4;
        if( seg + 256 > hex_buffer_size )
          seg = hex_buffer_size - 256;

        hex_addr = hex_base_addr + seg;
        werase(hexwin);
        draw_hexwin(hexwin, hex_width, hex_height, hex_base_addr, hex_addr);
        wrefresh(hexwin);
        break;
      }
    }
  }

  endwin();

  return 0;
}
