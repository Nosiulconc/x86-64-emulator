#ifndef _IO_H_
#define _IO_H_

#include <SDL2/SDL.h>
#include <pthread.h>
#include <time.h>

extern x64_CPU cpu;
extern uint8_t* ram;
extern uint8_t* disk;
extern const uint64_t DISK_CAPACITY;
extern pthread_mutex_t io_ports_mutex;

// *********** //
// ** ATAPI ** //
// *********** //

#define DATA_REG       0x1F0
#define FEATURES_REG   0x1F1
#define LOW_LBA_REG    0x1F3
#define MID_LBA_REG    0x1F4
#define HIGH_LBA_REG   0x1F5
#define DRIVE_HEAD_REG 0x1F6
#define STATUS_REG     0x1F7

typedef enum { DRIVE_WAITING_COMMAND, READY_TO_SEND, READY_TO_RECEIVE } DriveState;

typedef struct {
  uint8_t* buffer;
  uint64_t buffer_size;
  uint8_t* curr_byte;
  uint8_t status;
  DriveState state;
}
Drive;

extern Drive drive;

uint8_t drive_desc[512] = { 0 };
uint8_t packet[12];

void ATAPI_drive_selection(void) {
  if( cpu.io_ports[DRIVE_HEAD_REG] != 0xE0 )
    panic("ATAPI only handles master drive in LBA mode!");
}

void ATAPI_features(void) {
  if( cpu.io_ports[FEATURES_REG] != 0x00 )
    panic("ATAPI only handles PIO mode!");
}

void ATAPI_send_features(void) {
  cpu.io_ports[FEATURES_REG] = 0;
}

void ATAPI_send_status(void) {
  cpu.io_ports[STATUS_REG] = drive.status;
}

void ATAPI_command(void) {
  switch( cpu.io_ports[STATUS_REG] ) {
    case 0x00: {
      // TEST READY aka NOP
      drive.status &= ~0x80; // BSY
      drive.status |=  0x40; // DRDY
    } break;
    case 0x08: {
      // RESET
      drive.status &= ~0x80; // BSY
    } break;
    case 0xA0: {
      // PACKET
      drive.buffer = drive.curr_byte = &packet;
      drive.buffer_size = 12;
      drive.status &= ~0x80; // BSY
      drive.status |=  0x08; // DRQ
      drive.state = READY_TO_RECEIVE; 
    } break;
    case 0xEC: {
      // IDENTIFY
      drive.buffer = drive.curr_byte = &drive_desc;
      drive.buffer_size = 512;
      drive.status &= ~0x80; // BSY
      drive.status |=  0x08; // DRQ
      drive.status |=  0x01; // ERR
      drive.state = READY_TO_SEND;
    } break;
    case 0xF8: {
      // READ NATIVE MAX ADDRESS
      const uint64_t max_addr = DISK_CAPACITY / 2048;
      cpu.io_ports[LOW_LBA_REG] = max_addr & 0xFF;
      cpu.io_ports[MID_LBA_REG] = (max_addr >> 8) & 0xFF;
      cpu.io_ports[HIGH_LBA_REG] = (max_addr >> 16) & 0xFF;
      drive.status &= ~0x80; // BSY
      drive.status |=  0x40; // DRDY
    } break;
    case 0xF9: {
      // SET MAX ADDRESS
      drive.status &= ~0x80; // BSY
    } break;
    default: panic("ATAPI command 0x%x not supported!", cpu.io_ports[STATUS_REG]);
  }
}

void ATAPI_send_bytes(void) {
  if( drive.state != READY_TO_SEND )
    panic("ATAPI can only send bytes when in READY_TO_SEND!");
  cpu.io_ports[DATA_REG] = *drive.curr_byte;
  ++(drive.curr_byte);
  if( drive.curr_byte >= drive.buffer + drive.buffer_size ) {
    drive.status &= ~0x80;
    drive.status &= ~0x08;
    drive.state = DRIVE_WAITING_COMMAND;
  }
}

void ATAPI_execute_packet(void) {
  switch( packet[0] ) {
    case 0x1B: {
      // START/STOP
      drive.status &= ~0x80;
      drive.status &= ~0x08;
      drive.state = DRIVE_WAITING_COMMAND;
    } break;
    case 0xA8: {
      // READ(12)
      drive.buffer = drive.curr_byte = ( ((uint64_t)packet[2]<<24)+
                                         ((uint64_t)packet[3]<<16)+
                                         ((uint64_t)packet[4]<<8)+
                                         ((uint64_t)packet[5]) )*2048 + disk;
      drive.buffer_size = ( ((uint64_t)packet[6]<<24)+
                            ((uint64_t)packet[7]<<16)+
                            ((uint64_t)packet[8]<<8)+
                            ((uint64_t)packet[9]) )*2048;
      drive.status &= ~0x80; // BSY
      drive.status |=  0x08; // DRQ
      drive.state = READY_TO_SEND;
    } break;
    case 0xBB: {
      // SET CD SPEED
      drive.status &= ~0x80;
      drive.status &= ~0x08;
      drive.state = DRIVE_WAITING_COMMAND;
    } break;
    default: panic("ATAPI unknown packet header 0x%x!", packet[0]);
  }
}

void ATAPI_receive_packet(void) {
  if( drive.state != READY_TO_RECEIVE )
    panic("ATAPI can only receive bytes when in READY_TO_RECEIVE!");
  *drive.curr_byte = cpu.io_ports[DATA_REG];
  ++(drive.curr_byte);
  if( drive.curr_byte >= drive.buffer + drive.buffer_size )
    ATAPI_execute_packet();
}

// ********* //
// ** PIC ** //
// ********* //

#define PIC1_COMMAND 0x20
#define PIC1_DATA    0x21
#define PIC2_COMMAND 0xA0
#define PIC2_DATA    0xA1
#define IRQ_QUEUE_SIZE 64

typedef enum { WAITING_COMMAND, READ_IDT_INDEX, READ_CASCADE_PIN, READ_MODE } PIC_State;

typedef struct {
  uint8_t idt_index;
  uint8_t mask;
  PIC_State state;
}
PIC;

typedef struct {
  PIC pic1;
  PIC pic2;
  uint8_t processing_int;

  uint8_t queue_top;
  uint8_t queue_bot;
  uint8_t irq_queue[IRQ_QUEUE_SIZE];
}
Dual_PIC;

extern Dual_PIC dual_pic;

// on OUT 0x20 | 0xA0, al:
// if state is WAITING_COMMAND -> if command is 0x11 go to READ_IDT_INDEX
//
// on OUT 0x21 | 0xA1, al:
// if state is READ_IDT_INDEX -> read and save idt index then go to READ_CASCADE_PIN
// if state is READ_CASCADE_PIN -> read and save cascade pin then go to READ_MODE
// if state is READ_MODE -> read and save mode then go to WAITING_COMMAND
// if state is WAITING_COMMAND -> read and save to mask
//
// on IN al, 0x21 | 0xA1:
// if state is WAITING_COMMAND -> write mask

void PIC1_process_command(void) {
  switch( dual_pic.pic1.state ) {
    case WAITING_COMMAND: {
      if( cpu.io_ports[PIC1_COMMAND] != 0x11 ) panic("PIC1 can only process 0x11 commands!");
      dual_pic.pic1.state = READ_IDT_INDEX;
    } break;
    default: panic("PIC1 only processes commands in WAITING_COMMAND!");
  }
}

void PIC2_process_command(void) {
  switch( dual_pic.pic2.state ) {
    case WAITING_COMMAND: {
      if( cpu.io_ports[PIC2_COMMAND] != 0x11 ) panic("PIC2 can only process 0x11 commands!");
      dual_pic.pic2.state = READ_IDT_INDEX;
    } break;
    default: panic("PIC2 only processes commands in WAITING_COMMAND!");
  }
}

void PIC1_initialization(void) {
  switch( dual_pic.pic1.state ) {
    case READ_IDT_INDEX: {
      dual_pic.pic1.idt_index = cpu.io_ports[PIC1_DATA];
      dual_pic.pic1.state = READ_CASCADE_PIN;
    } break;
    case READ_CASCADE_PIN: {
      if( cpu.io_ports[PIC1_DATA] != 0x04 ) panic("PIC1 only accepts cascade pin 0x04!");
      dual_pic.pic1.state = READ_MODE;
    } break;
    case READ_MODE: {
      if( cpu.io_ports[PIC1_DATA] != 0x0D ) panic("PIC1 only accepts mode 0x0D!");
      dual_pic.pic1.state = WAITING_COMMAND;
    } break;
    case WAITING_COMMAND: {
      dual_pic.pic1.mask = cpu.io_ports[PIC1_DATA];
    } break;
  }
}

void PIC2_initialization(void) {
  switch( dual_pic.pic2.state ) {
    case READ_IDT_INDEX: {
      dual_pic.pic2.idt_index = cpu.io_ports[PIC2_DATA];
      dual_pic.pic2.state = READ_CASCADE_PIN;
    } break;
    case READ_CASCADE_PIN: {
      if( cpu.io_ports[PIC2_DATA] != 0x02 ) panic("PIC2 only accepts cascade pin 0x02!");
      dual_pic.pic2.state = READ_MODE;
    } break;
    case READ_MODE: {
      if( cpu.io_ports[PIC2_DATA] != 0x09 ) panic("PIC2 only accepts mode 0x09!");
      dual_pic.pic2.state = WAITING_COMMAND;
    } break;
    case WAITING_COMMAND: {
      dual_pic.pic2.mask = cpu.io_ports[PIC2_DATA];
    } break;
  }
}

void PIC1_write_mask(void) {
  switch( dual_pic.pic1.state ) {
    case WAITING_COMMAND: {
      cpu.io_ports[PIC1_DATA] = dual_pic.pic1.mask;
    } break;
    default: panic("PIC1 unhandled case in write_mask!");
  }
}

void PIC2_write_mask(void) {
  switch( dual_pic.pic2.state ) {
    case WAITING_COMMAND: {
      cpu.io_ports[PIC2_DATA] = dual_pic.pic2.mask;
    } break;
    default: panic("PIC2 unhandled case in write_mask!");
  }
}

// ********* //
// ** PIT ** //
// ********* //

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
        default: panic("PIT unhandled case in read_counter!");
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
        default: panic("PIT unhandled case in write_reload_value!");
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

// ********* //
// ** RTC ** //
// ********* //

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

// ********* //
// ** VGA ** //
// ********* //

static void render_vram(SDL_Renderer* renderer, uint8_t* vram, const SDL_Color* palette) {
  uint32_t i = 0;
  for(uint32_t y = 0; y < 480; ++y) {
    for(uint32_t x = 0; x < 640; ++x) {
      //const uint32_t color_index = i & 0x1 ? vram[i/2] >> 4 : vram[i/2] & 0b1111;
      //const SDL_Color color = palette[color_index];
      const uint8_t color = 255 * (( vram[i/8] >> (7 - (i%8)) ) & 1);
      ++i;

      SDL_SetRenderDrawColor(renderer, color, color, color, 255);//color.r, color.g, color.b, color.a);
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

  uint8_t* vram = ram + 0xA0000;

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
