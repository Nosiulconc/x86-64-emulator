#ifndef _IO_H_
#define _IO_H_

#include <SDL2/SDL.h>
#include <pthread.h>
#include <time.h>

extern uint8_t* ram;
extern pthread_mutex_t io_ports_mutex;

// starts at port 0x40
typedef struct __attribute__((packed)) {
  uint8_t channel_0;
  uint8_t channel_1;
  uint8_t channel_2;

  uint8_t count_mode  : 1;
  uint8_t op_mode     : 3;
  uint8_t access_mode : 2;
  uint8_t select_chan : 2;
}
PIT_Ports;

typedef enum { WAIT_RESET, WRITE_WAIT_LOW_BYTE, WRITE_WAIT_HIGH_BYTE, UPDATE_COUNTER, READ_WAIT_HIGH_BYTE } PIT_State;

typedef struct {
  uint16_t counter;
  uint16_t reload_value;
  PIT_State state;
}
PIT;

// PIT initial state: WAIT_RESET
// 
// WAIT_RESET:
// ON OUT 0x43, al -> goto WRITE_WAIT_LOW_BYTE
//
// WRITE_WAIT_LOW_BYTE:
// ON OUT 0x40, al -> write low byte, goto WRITE_WAIT_HIGH_BYTE
//
// WRITE_WAIT_HIGH_BYTE:
// ON OUT 0x40, al -> write high byte, goto UPDATE_COUNTER
//
// UPDATE_COUNTER:
// decrement counter
// ON counter == 0 -> trigger IRQ0, goto WAIT_RESET
// ON IN al, 0x40 -> give low byte, goto READ_WAIT_HIGH_BYTE
//
// READ_WAIT_HIGH_BYTE:
// ON IN al, 0x40 -> give high byte, goto UPDATE_COUNTER

void reset_PIT(void) {
  // port 0x43 has been written to (only accepts 0)
}

void write_PIT(void) {
  // waits low then high byte for the reload value
}

void read_PIT(void) {
  // give low then high byte
}

void update_PIT_counter(void) {
  // decrement counter
  // if counter is 0 then trigger IRQ0 and wait reset
}

void update_RTC(void) {
  //time_t t = time(NULL);
  //struct tm* date = localtime(&t);

  switch( cpu.io_ports[0x70] ) {
    case 0x00: cpu.io_ports[0x71] = 0; break;//date->tm_sec; break;
    case 0x02: cpu.io_ports[0x71] = 0; break;//date->tm_min; break;
    case 0x04: cpu.io_ports[0x71] = 0; break;//date->tm_hour; break;
    case 0x06: cpu.io_ports[0x71] = 1; break;//date->tm_wday + 1; break;
    case 0x07: cpu.io_ports[0x71] = 0; break;//date->tm_mday; break;
    case 0x08: cpu.io_ports[0x71] = 1; break;//date->tm_mon + 1; break;
    case 0x09: cpu.io_ports[0x71] = 0; break;//date->tm_year % 100; break;
    case 0x0A: cpu.io_ports[0x71] = 0; break;          // bit 7: is the RTC updating? Answer: never;
    case 0x0B: cpu.io_ports[0x71] = 0b00000110; break; // bit 1: 24 hour fmt; bit 2: ints, not BCD;
    default: panic("RTC can't interpret value in io port 0x70!");
  }
}

static void render_vram(SDL_Renderer* renderer, uint8_t* vram, const SDL_Color* palette) {
  uint32_t i = 0;
  for(uint32_t y = 0; y < 480; ++y) {
    for(uint32_t x = 0; x < 640; ++x) {
      const uint32_t color_index = i & 0x1 ? vram[i/2] >> 4 : vram[i/2] & 0b1111;
      const SDL_Color color = palette[color_index];
      ++i;

      SDL_SetRenderDrawColor(renderer, color.r, color.g, color.b, color.a);
      SDL_RenderDrawPoint(renderer, x, y);
    }
  }
}

void* io_thread(void* arg) {
  SDL_Window* window = NULL;
  SDL_Renderer* renderer = NULL;

  /*
  SDL_Init(SDL_INIT_VIDEO);
  SDL_CreateWindowAndRenderer(640, 480, 0, &window, &renderer);

  const SDL_Color palette[16] = {
    {0, 0, 0, 255},       // Black
    {0, 0, 128, 255},     // DarkBlue
    {0, 128, 0, 255},     // DarkGreen
    {0, 128, 128, 255},   // Teal
    {128, 0, 0, 255},     // DarkRed
    {128, 0, 128, 255},   // Purple
    {128, 128, 0, 255},   // Brown
    {192, 192, 192, 255}, // Silver
    {128, 128, 128, 255}, // Gray
    {0, 0, 255, 255},     // Blue
    {0, 255, 0, 255},     // Green
    {0, 255, 255, 255},   // Cyan
    {255, 0, 0, 255},     // Red
    {255, 0, 255, 255},   // Magenta
    {255, 255, 0, 255},   // Yellow
    {255, 255, 255, 255}  // White
  };

  uint8_t* vram = ram + 0xA000;
  */

  SDL_Event event;
  uint8_t running = 1;

  while( running ) {
    while( SDL_PollEvent( &event ) != 0 ) {
      if( event.type == SDL_QUIT ) {
        running = 0;
      }
    }

    /*
    SDL_RenderClear(renderer);
    render_vram(renderer, vram, palette);
    SDL_RenderPresent(renderer);
    */

    SDL_Delay(33);
  }

  /*
  SDL_DestroyRenderer(renderer);
  SDL_DestroyWindow(window);
  */
  SDL_Quit();
}

#endif
