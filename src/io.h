#ifndef _IO_H_
#define _IO_H_

#include <SDL2/SDL.h>
#include <pthread.h>
#include <time.h>

extern x64_CPU cpu;
extern uint8_t* ram;
extern pthread_mutex_t io_ports_mutex;

// starts at port 0x40
typedef struct __attribute__((packed)) {
  uint8_t chan0;
  uint8_t chan1;
  uint8_t chan2;

  uint8_t count_mode  : 1;
  uint8_t op_mode     : 3;
  uint8_t access_mode : 2;
  uint8_t select_chan : 2;
}
PIT_Ports;

typedef enum { LOWBYTE_ONLY = 1, HIGHBYTE_ONLY = 2, LOWBYTE_HIGHBYTE = 3 } PIT_AccessMode;
typedef enum { WAITING_RELOAD_VALUE, COUNTING, WRITE_HIGHBYTE, READ_HIGHBYTE, READ_HIGHBYTE_AND_SAVE_TO_COUNTER } PIT_ChannelState;

typedef struct {
  uint16_t reload_value;
  uint16_t counter;
  PIT_AccessMode access_mode;
  uint8_t op_mode;
  PIT_ChannelState state;
}
PIT_Channel;

typedef struct {
  PIT_Channel chan0;
}
PIT;

extern PIT pit;

// on OUT 0x43, al:
// if read_back command -> panic
// if latch command -> do nothing
// else if not channel 1 -> reconfigure selected channel

// on IN al, 0x40 | 0x42:
// if access_mode is single byte -> write counter byte in 0x40 | 0x42
// else -> if state is COUNTING: ( write lowbyte and go to WRITE_HIGH ) else if WRITE_HIGH: ( write highbyte and go to COUNTING )

// on OUT 0x40 | 0x42, al:
// if access_mode is single byte -> write 0x40 | 0x42 in reload value and counter byte
// else -> if state is COUNTING: ( write lowbyte and go to READ_HIGH ) else if READ_HIGH: ( write highbyte and go to COUNTING ) 

void PIT_override_mode(void) {
  const PIT_Ports ports = *(PIT_Ports*)(cpu.io_ports + 0x40);

  if( ports.select_chan == 0b11 ) panic("PIT can't handle readback commands!");
  if( ports.access_mode == 0b00 ) return; // ignore latch commands

  if( ports.select_chan != 0b00 ) panic("PIT channel 1 and 2 are not implemented!");
  if( ports.op_mode != 2 ) panic("PIT mode 0, 1, 3, 4, 5 are not implemented!");
  if( ports.count_mode == 1 ) panic("PIT BCD counting is not implemented!");
  pit.chan0.access_mode = ports.access_mode;
  pit.chan0.op_mode = ports.op_mode;
  pit.chan0.state = WAITING_RELOAD_VALUE;
}

void PIT_read_counter(uint16_t port) {
  if( port != 0x40 ) panic("PIT Can't read channel 1 and 2 counters!");

  switch( pit.chan0.access_mode ) {
    case LOWBYTE_ONLY: {
      if( pit.chan0.state != COUNTING ) return; 
      cpu.io_ports[port] = pit.chan0.counter & 0xFF;
    } break;
    case HIGHBYTE_ONLY: {
      if( pit.chan0.state != COUNTING ) return; 
      cpu.io_ports[port] = pit.chan0.counter >> 8;
    } break;
    case LOWBYTE_HIGHBYTE: {
      switch( pit.chan0.state ) {
	case COUNTING: {
	  cpu.io_ports[port] = pit.chan0.counter & 0xFF;
	  pit.chan0.state = WRITE_HIGHBYTE;
	} break;
	case WRITE_HIGHBYTE: {
	  cpu.io_ports[port] = pit.chan0.counter >> 8;
          pit.chan0.state = COUNTING;
	} break;
        default:
      }
    } break;
  }
}

void PIT_write_reload_value(uint16_t port) {
  if( port != 0x40 ) panic("PIT Can't write to channel 1 and 2 counters!");

  switch( pit.chan0.access_mode ) {
    case LOWBYTE_ONLY: {
      if( !(pit.chan0.state == COUNTING || pit.chan0.state == WAITING_RELOAD_VALUE) ) return; 
      pit.chan0.reload_value &= 0xFF00;
      pit.chan0.reload_value |= cpu.io_ports[port];
      if( pit.chan0.state == WAITING_RELOAD_VALUE ) {
	pit.chan0.counter = pit.chan0.reload_value;
        pit.chan0.state = COUNTING;
      }
    } break;
    case HIGHBYTE_ONLY: {
      if( !(pit.chan0.state == COUNTING || pit.chan0.state == WAITING_RELOAD_VALUE) ) return; 
      pit.chan0.reload_value &= 0x00FF;
      pit.chan0.reload_value |= cpu.io_ports[port] << 8;
      if( pit.chan0.state == WAITING_RELOAD_VALUE ) {
	pit.chan0.counter = pit.chan0.reload_value;
        pit.chan0.state = COUNTING;
      }
    } break;
    case LOWBYTE_HIGHBYTE: {
      switch( pit.chan0.state ) {
	case WAITING_RELOAD_VALUE: {
	  pit.chan0.reload_value = cpu.io_ports[port];
	  pit.chan0.state = READ_HIGHBYTE_AND_SAVE_TO_COUNTER;
	} break;
	case READ_HIGHBYTE_AND_SAVE_TO_COUNTER: {
	  pit.chan0.reload_value |= cpu.io_ports[port] << 8;
	  pit.chan0.counter = pit.chan0.reload_value;
          pit.chan0.state = COUNTING;
	} break;
	case COUNTING: {
	  pit.chan0.reload_value = cpu.io_ports[port];
	  pit.chan0.state = READ_HIGHBYTE;
	} break;
	case READ_HIGHBYTE: {
	  pit.chan0.reload_value |= cpu.io_ports[port] << 8;
          pit.chan0.state = COUNTING;
	} break;
        default:
      }
    } break;
  }
}

void PIT_update_counter(void) {
  if( pit.chan0.state == WAITING_RELOAD_VALUE || pit.chan0.state == READ_HIGHBYTE_AND_SAVE_TO_COUNTER ) return;
  --pit.chan0.counter;
  if( pit.chan0.counter == 0 ) {
    pit.chan0.counter = pit.chan0.reload_value;
    // send IRQ0
  }
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
