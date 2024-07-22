#include <stdint.h>
#include <stdlib.h>
#include <ncurses.h>

// ******************* //
// **   EMULATION   ** //
// ******************* //

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

x64_CPU cpu;

static void init_cpu() {

}

// ************ //
// **   UI   ** //
// ************ //

static void panic(const char* msg) {
  printf("ERROR: %s", msg); exit(1);
}

static void draw_bytes(WINDOW* win, uint8_t* bytes, uint64_t addr) {
  for(int32_t i = 0; i < 16; ++i) {
    mvwprintw(win, i + 1, 1, "%015lx: ", addr);
    addr += 16;
    for(int32_t j = 0; j < 16; ++j) {
      mvwprintw(win, i + 1, j*3 + 1 + 17, "%02hhx", *bytes);
      
      const char c = ( (*bytes) >= 0x20 && (*bytes) <= 0x7E ) ? (*bytes) : '.';
      mvwprintw(win, i + 1, 16 + 1 + 16*2 + 17 + j, "%c", c);
      
      ++bytes;
    }
  }
}

static void draw_win(WINDOW* win, uint8_t* bytes, uint8_t* base_addr) {
  box(win, 0, 0);
  for(int32_t i = 1; i < 82; ++i) mvwprintw(win, 1 + 16, i, "-");
  draw_bytes(win, base_addr, base_addr - bytes);
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

  mvwprintw(win, 1, 1 + 23 + 3, "cs  : %04x", cpu.cs);
  mvwprintw(win, 2, 1 + 23 + 3, "ss  : %04x", cpu.ss);
  mvwprintw(win, 3, 1 + 23 + 3, "ds  : %04x", cpu.ds);
  mvwprintw(win, 4, 1 + 23 + 3, "es  : %04x", cpu.es);
  mvwprintw(win, 5, 1 + 23 + 3, "fs  : %04x", cpu.fs);
  mvwprintw(win, 6, 1 + 23 + 3, "gs  : %04x", cpu.gs);

  mvwprintw(win, 1, 26 + 10 + 3, "rip: %016lx", cpu.rip);
}

int32_t main(void) {
  WINDOW* stdwin;

  if( (stdwin = initscr()) == NULL ) panic("Failed to initialize ncurses!");
  if( has_colors() == FALSE ) {
    endwin();
    panic("No support for colors!");
  }

  //start_color();
  //init_pair(0, COLOR_WHITE, COLOR_MAGENTA);
  //attron(COLOR_PAIR(0));

  cbreak();
  noecho();
  keypad(stdwin, TRUE);
  curs_set(FALSE);

  // hex viewer
  const int32_t width  = 16 + 1 + 16*2 + 17 + 1 + 16;
  const int32_t height = 16 + 2 + 2;
  WINDOW* win = newwin(height, width, 0, 0);
  wrefresh(stdwin);
  
  uint8_t bytes[512] = "Hello, world!";
  uint8_t* base_addr = bytes;

  draw_win(win, bytes, base_addr);
  wrefresh(win);

  // controls
  const int32_t ctrl_width  = 17 + 2;
  const int32_t ctrl_height = 19 + 2;
  WINDOW* ctrlwin = newwin(ctrl_height, ctrl_width, height, width - ctrl_width);
  wrefresh(stdwin);

  draw_ctrlwin(ctrlwin, ctrl_width, ctrl_height);
  wrefresh(ctrlwin);

  // registers
  const int32_t reg_width  = width - ctrl_width;
  const int32_t reg_height = ctrl_height;
  WINDOW* regwin = newwin(reg_height, reg_width, height, 0);
  wrefresh(stdwin);

  draw_regwin(regwin, reg_width, reg_height);
  wrefresh(regwin);

  int32_t c;
  while( (c = wgetch(stdwin)) != 'q' ) {
    switch( c ) {
      case KEY_UP:   if( base_addr > bytes ) base_addr -= 16; break;
      case KEY_DOWN: if( base_addr + 256 < bytes + 512 ) base_addr += 16; break;
      case 'g': {
        wmove(win, 16 + 2, 1);
        
        curs_set(TRUE);
        echo();

        char buff[81];
        wgetnstr(win, buff, 81);
        
        noecho();
        curs_set(FALSE);

        uint64_t seg;
        if( sscanf(buff, "%lx", &seg) < 1 ) goto redraw;

        if( seg % 16 ) goto redraw;
        if( seg < 0 ) goto redraw;
        if( seg + 256 > 512 ) seg = 512 - 256;

        base_addr = bytes + seg;
      
      redraw:
        werase(win);
        draw_win(win, bytes, base_addr);
        wrefresh(win);
      }
    }

    //werase(stdwin);
    //wrefresh(stdwin);

    draw_win(win, bytes, base_addr);
    wrefresh(win);
  }

  endwin();

  return 0;
}
