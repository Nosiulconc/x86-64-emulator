#ifndef _IO_H_
#define _IO_H_

#include <SDL2/SDL.h>
#include <pthread.h>

extern uint8_t* ram;

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

  SDL_Event event;
  uint8_t running = 1;

  while( running ) {
    while( SDL_PollEvent( &event ) != 0 ) {
      if( event.type == SDL_QUIT ) {
        running = 0;
      }
    }

    SDL_RenderClear(renderer);
    render_vram(renderer, vram, palette);
    SDL_RenderPresent(renderer);

    SDL_Delay(33);
  }

  SDL_DestroyRenderer(renderer);
  SDL_DestroyWindow(window);
  SDL_Quit();
}

#endif
