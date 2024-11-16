#ifndef _IO_H_
#define _IO_H_

#include <SDL2/SDL.h>
#include <pthread.h>
#include <time.h>

#include "inst_decoder.h"

#define GET_RFLAGS(flag) ((cpu.rflags & flag) / flag)

extern x64_CPU cpu;

extern uint8_t* ram;
extern uint8_t* disk;
extern const uint64_t DISK_CAPACITY;

extern pthread_mutex_t io_ports_mutex;
extern pthread_mutex_t irq_queue_mutex;

extern uint64_t read_unsigned(uint8_t*, uint8_t);
extern void exe_push(uint8_t*, uint8_t);

// ********** //
// ** PS/2 ** //
// ********** //

#define PS2_DATA           0x60
#define PS2_STATUS_COMMAND 0x64

#define OUTPUT_QUEUE_SIZE 64

typedef enum { PS2_WAITING_COMMAND, WRITE_TO_MOUSE, WRITE_CONFIG_BYTE, GET_SCANCODE_SET_INDEX, GET_LED_CONTROL_BYTE, SET_TYPING_RATE } PS2_State;
typedef enum { MS_WAITING_COMMAND, MS_READ_RES, MS_READ_SAMPLE_RATE } MouseState;

typedef struct {
  uint8_t sample_rate;
  uint8_t res;
  MouseState state;
}
Mouse;

typedef struct {
  uint8_t output_queue[OUTPUT_QUEUE_SIZE];
  uint8_t queue_top;
  uint8_t queue_bot;
  uint8_t status;
  uint8_t config;

  Mouse ms;

  PS2_State state;
}
PS2_Controller;

extern PS2_Controller ps2;

void enqueue_output(uint8_t byte) {
  ps2.status |= 0x1;
  ps2.output_queue[ps2.queue_top] = byte;
  ps2.queue_top = (ps2.queue_top + 1) % OUTPUT_QUEUE_SIZE;
  if( ps2.queue_top == ps2.queue_bot )
    panic("OUTPUT queue overflow!");
}

uint8_t dequeue_output(void) {
  const uint8_t byte = ps2.output_queue[ps2.queue_bot];
  ps2.queue_bot = (ps2.queue_bot + 1) % OUTPUT_QUEUE_SIZE;
  if( ps2.queue_top == ps2.queue_bot )
    ps2.status &= ~0x1;
  return byte;
}

void PS2_send_bytes(void) {
  if( (ps2.status & 0x1) == 0 )
    return;
  cpu.io_ports[PS2_DATA] = dequeue_output();
}

void PS2_send_status(void) {
  cpu.io_ports[PS2_STATUS_COMMAND] = ps2.status;
}

void PS2_command(void) {
  if( ps2.state != PS2_WAITING_COMMAND )
    panic("PS2 must be in PS2_WAITING_COMMAND to process commands!");
  switch( cpu.io_ports[PS2_STATUS_COMMAND] ) {
    case 0x20: {
      // READ CONFIG BYTE
      enqueue_output(ps2.config);
    } break;
    case 0x60: {
      // WRITE CONFIG BYTE
      ps2.state = WRITE_CONFIG_BYTE;
    } break;
    case 0xA7: break; // DISABLE SECOND PORT
    case 0xA8: break; // ENABLE SECOND PORT
    case 0xAD: break; // DISABLE FIRST PORT
    case 0xAE: break; // ENABLE FIRST PORT
    case 0xD4: {
      // WRITE BYTE TO INPUT BUFFER
      ps2.status &= ~0x8;
      ps2.state = WRITE_TO_MOUSE;
    } break;
    default: panic("PS2 cannot process 0x%x commands from COMMAND!", cpu.io_ports[PS2_STATUS_COMMAND]);
  }
}

void PS2_mouse_receive_bytes(void) {
  switch( ps2.ms.state ) {
    case MS_WAITING_COMMAND: {
      switch( cpu.io_ports[PS2_DATA] ) {
        case 0xE6: {
          // DISABLE SCALING
          enqueue_output(0xFA);
          return;
        }
        case 0xE8: {
          // SET RESOLUTION
          ps2.ms.state = MS_READ_RES;
          enqueue_output(0xFA);
          return;
        }
        case 0xF2: {
          // GET MOUSE ID
          enqueue_output(0xFA);
          enqueue_output(0x00);
          return;
        }
        case 0xF3: {
          // SET SAMPLE RATE
          ps2.ms.state = MS_READ_SAMPLE_RATE;
          enqueue_output(0xFA);
          return;
        }
        case 0xF4: {
          // START RECORDING
          enqueue_output(0xFA);
          return;
        }
        case 0xFF: {
          // RESET MOUSE
          enqueue_output(0xFA); // ack
          enqueue_output(0xAA); // self-test passed
          enqueue_output(0x00); // id
          return;
        }
        default: panic("Mouse cannot process 0x%x commands!", cpu.io_ports[PS2_DATA]);
      }
    }
    case MS_READ_RES: {
      ps2.ms.res = cpu.io_ports[PS2_DATA];
      ps2.ms.state = MS_WAITING_COMMAND;
      enqueue_output(0xFA);
      return;
    }
    case MS_READ_SAMPLE_RATE: {
      ps2.ms.sample_rate = cpu.io_ports[PS2_DATA];
      ps2.ms.state = MS_WAITING_COMMAND;
      enqueue_output(0xFA);
      return;
    }
    default: panic("Unhandled case in PS2_mouse_receive_bytes!");
  }
}

void PS2_receive_bytes(void) {
  switch( ps2.state ) {
    case PS2_WAITING_COMMAND: {
      switch( cpu.io_ports[PS2_DATA] ) {
        case 0xED: {
          // CONTROL LEDs
          ps2.state = GET_LED_CONTROL_BYTE;
          return;
        }
        case 0xF0: { 
          // SELECT SCANCODE SET
          ps2.state = GET_SCANCODE_SET_INDEX;
          return;
        }
        case 0xF3: {
          // SET TYPING RATE
	  ps2.state = SET_TYPING_RATE;
	  enqueue_output(0xFA);
	  return;
        }
        default: panic("PS2 cannot process 0x%x commands from DATA!", cpu.io_ports[PS2_DATA]);
      }
    }
    case WRITE_TO_MOUSE: {
      if( ps2.status & 0x2 )
        panic("Cannot write to mouse as the input buffer is full!");
      PS2_mouse_receive_bytes();
      ps2.status |= 0x8;
      ps2.state = PS2_WAITING_COMMAND;
      return;
    }
    case WRITE_CONFIG_BYTE: {
      ps2.config = cpu.io_ports[PS2_DATA];
      ps2.state = PS2_WAITING_COMMAND;
      return;
    }
    case GET_SCANCODE_SET_INDEX: {
      if( cpu.io_ports[PS2_DATA] != 0x02 )
        panic("Attempt to change scancode set 2 for %d!", cpu.io_ports[PS2_DATA]);
      ps2.state = PS2_WAITING_COMMAND;
      return;
    }
    case GET_LED_CONTROL_BYTE:
    case SET_TYPING_RATE: {
      ps2.state = PS2_WAITING_COMMAND;
      return;
    }
    default: panic("unhandled case in PS2_receive_bytes!");
  }
}

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
  uint8_t drive_desc[512];
  uint8_t packet[12];

  uint8_t* buffer;
  uint64_t buffer_size;
  uint8_t* curr_byte;
  uint8_t status;
  DriveState state;
}
Drive;

extern Drive drive;

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
      drive.buffer = drive.curr_byte = &(drive.packet);
      drive.buffer_size = 12;
      drive.status &= ~0x80; // BSY
      drive.status |=  0x08; // DRQ
      drive.state = READY_TO_RECEIVE; 
    } break;
    case 0xEC: {
      // IDENTIFY
      drive.buffer = drive.curr_byte = &(drive.drive_desc);
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
  uint8_t* packet = &(drive.packet);
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

void PIC_process_irqs(void) {
  if( GET_RFLAGS(RFLAGS_IF) == 0 ) return;
  if( dual_pic.processing_int ) return;
  
  pthread_mutex_lock(&irq_queue_mutex);

  if( dual_pic.queue_bot == dual_pic.queue_top ) {
    pthread_mutex_unlock(&irq_queue_mutex);
    return;
  }
  
  const uint8_t line = dual_pic.irq_queue[dual_pic.queue_bot];
  dual_pic.queue_bot = (dual_pic.queue_bot + 1) % IRQ_QUEUE_SIZE;

  pthread_mutex_unlock(&irq_queue_mutex);

  if( !(op_mode == LONG_MODE && cpu.cs_cache.l) )
    panic("PIC can only process irqs in 64-bit mode!");
  if( line > 15 )
    panic("0 <= IRQ line <= 15 !");

  //panic("INT!!");
  const uint8_t vector = line + (line <= 7 ? dual_pic.pic1.idt_index : dual_pic.pic2.idt_index);
  uint8_t* int_desc_addr = ram + cpu.idtr.base + 16*vector;
  const uint64_t int_desc_low  = read_unsigned(int_desc_addr, 8);
  const uint64_t int_desc_high = read_unsigned(int_desc_addr + 8, 8);

  if( ((int_desc_low >> 40) & 0b1111) != 0xE )
    panic("PIC can only handle interrupt gates!");

  if( ((int_desc_low >> 32) & 0b111) != 0 )
    panic("PIC does not support the Interrupt Stack Table!");

  const uint64_t segment = (int_desc_low >> 16) & 0xFFFF;
  const uint64_t offset = (int_desc_high << 32) + ((int_desc_low >> 48) << 16) + (int_desc_low & 0xFFFF);

  const uint64_t ss = read_unsigned(&(cpu.ss), 2);
  const uint64_t cs = read_unsigned(&(cpu.cs), 2);
  const uint64_t temp_rsp = cpu.rsp;
  exe_push(&ss, 8);
  exe_push(&temp_rsp, 8);
  exe_push(&(cpu.rflags), 8);
  exe_push(&cs, 8);
  exe_push(&(cpu.rip), 8);

  set_seg_reg(CS, segment);
  cpu.rip = offset;
  dual_pic.processing_int = 1;
}

void IRQ(uint8_t line) {
  if( GET_RFLAGS(RFLAGS_IF) == 0 ) return;
  pthread_mutex_lock(&irq_queue_mutex);

  dual_pic.irq_queue[dual_pic.queue_top] = line;
  dual_pic.queue_top = (dual_pic.queue_top + 1) % IRQ_QUEUE_SIZE;
  if( dual_pic.queue_top == dual_pic.queue_bot )
    panic("IRQ queue overflow!");

  pthread_mutex_unlock(&irq_queue_mutex);
}

void PIC1_process_command(void) {
  switch( dual_pic.pic1.state ) {
    case WAITING_COMMAND: {
      switch( cpu.io_ports[PIC1_COMMAND] ) {
        case 0x11: {
          dual_pic.pic1.state = READ_IDT_INDEX;
        } break;
        case 0x20: break; // End Of Interrupt
        default: panic("PIC1 cannot process 0x%x commands!", cpu.io_ports[PIC1_COMMAND]);
      }
    } break;
    default: panic("PIC1 only processes commands in WAITING_COMMAND!");
  }
}

void PIC2_process_command(void) {
  switch( dual_pic.pic2.state ) {
    case WAITING_COMMAND: {
      switch( cpu.io_ports[PIC2_COMMAND] ) {
        case 0x11: {
          dual_pic.pic2.state = READ_IDT_INDEX;
        } break;
        case 0x20: break;
        default: panic("PIC2 cannot process 0x%x commands!", cpu.io_ports[PIC2_COMMAND]);
      }
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

void PIC1_write_IRR(void) {
  switch( dual_pic.pic1.state ) {
    case WAITING_COMMAND: {
      cpu.io_ports[PIC1_COMMAND] = 0;
    } break;
    default: panic("PIC1 unhandled case in write_ISR!");
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
    IRQ(0);
  }
}

// ********* //
// ** RTC ** //
// ********* //

void update_RTC(void) {
  time_t t = time(NULL);
  struct tm* date = localtime(&t);

  switch( cpu.io_ports[0x70] ) {
    case 0x00: cpu.io_ports[0x71] = /*0; break;*/date->tm_sec; break;
    case 0x02: cpu.io_ports[0x71] = /*0; break;*/date->tm_min; break;
    case 0x04: cpu.io_ports[0x71] = /*0; break;*/date->tm_hour; break;
    case 0x06: cpu.io_ports[0x71] = /*1; break;*/date->tm_wday + 1; break;
    case 0x07: cpu.io_ports[0x71] = /*0; break;*/date->tm_mday; break;
    case 0x08: cpu.io_ports[0x71] = /*1; break;*/date->tm_mon + 1; break;
    case 0x09: cpu.io_ports[0x71] = /*0; break;*/date->tm_year % 100; break;
    case 0x0A: cpu.io_ports[0x71] = 0; break;          // bit 7: is the RTC updating? Answer: never;
    case 0x0B: cpu.io_ports[0x71] = 0b00000110; break; // bit 1: 24 hour fmt; bit 2: ints, not BCD;
    default: panic("RTC can't interpret value in io port 0x70!");
  }
}

// ********* //
// ** VGA ** //
// ********* //

typedef enum { VGA_READ_RED, VGA_READ_GREEN, VGA_READ_BLUE } DAC_State;
typedef enum { VGA_READ_INDEX, VGA_WRITE_COLOR_PALETTE, VGA_WRITE_HORIZONTAL_PIXEL_PANNING } AttributeReg_State;

typedef struct {
  uint8_t vram[640*480];
  SDL_Color palette[16];
  uint8_t plane_selector;
  uint8_t color_index;
  uint8_t attb_color_index;

  DAC_State dac_state;
  AttributeReg_State attb_state;
}
VGA_Controller;

extern VGA_Controller vga;

const SDL_Color EGA_palette[] = {
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

static void VGA_reset_attribute_register(void) {
  vga.attb_state = VGA_READ_INDEX;
}

static void VGA_attribute_register_receive_bytes(void) {
  switch( vga.attb_state ) {
    case VGA_READ_INDEX: {
      switch( cpu.io_ports[0x3C0] ) {
        case 0: case 1: case 2: case 3: case 4: case 5: case 6: case 7:
        case 8: case 9: case 10: case 11: case 12: case 13: case 14: case 15: {
          // SET COLOR PALETTE AT INDEX IN 0x3C0
          vga.attb_color_index = cpu.io_ports[0x3C0];
          vga.attb_state = VGA_WRITE_COLOR_PALETTE;
        } break;
        case 0x20: {
          // SET HORIZONTAL PIXEL PANNING
          vga.attb_state = VGA_WRITE_HORIZONTAL_PIXEL_PANNING;
        } break;
        default: panic("VGA attribute reg cannot process 0x%x commands", cpu.io_ports[0x3C0]);
      }
    } break;
    case VGA_WRITE_COLOR_PALETTE: {
      vga.palette[ vga.attb_color_index ] = EGA_palette[ cpu.io_ports[0x3C0] ];
      vga.attb_state = VGA_READ_INDEX;
    } break;
    case VGA_WRITE_HORIZONTAL_PIXEL_PANNING: {
      if( cpu.io_ports[0x3C0] != 0 )
        panic("VGA attempt to set horizontal pixel panning to not zero!");
      vga.attb_state = VGA_READ_INDEX;
    } break;
    default:
  }
}

static void VGA_get_palette_index(void) {
  vga.color_index = cpu.io_ports[0x3C8];
  vga.dac_state = VGA_READ_RED;
}

static void VGA_receive_color_bytes(void) {
  switch( vga.dac_state ) {
    case VGA_READ_RED: {
      vga.palette[vga.color_index].r = (uint64_t)cpu.io_ports[0x3C9]*255/63;
      vga.dac_state = VGA_READ_GREEN;
    } break;
    case VGA_READ_GREEN: {
      vga.palette[vga.color_index].g = (uint64_t)cpu.io_ports[0x3C9]*255/63;
      vga.dac_state = VGA_READ_BLUE;
    } break;
    case VGA_READ_BLUE: {
      vga.palette[vga.color_index].b = (uint64_t)cpu.io_ports[0x3C9]*255/63;
      vga.dac_state = VGA_READ_RED;
      vga.color_index = (vga.color_index + 1) % 16;
    } break;
    default:
  }
}

static void VGA_update_plane_selector(void) {
  vga.plane_selector = cpu.io_ports[0x3C5];
}

static void VGA_update_vram(uint8_t* addr, uint8_t size) {
  for(uint64_t j = 0; j < size; ++j) {
    uint8_t byte = *addr;
    uint8_t mask = 0x80;
    uint8_t* ptr = vga.vram + (uint64_t)(addr - (ram + 0xA0000))*8;
    for(uint64_t i = 0; i < 8; ++i) {
      *ptr = mask & byte ? *ptr | vga.plane_selector : *ptr & ~vga.plane_selector;
      mask >>= 1;
      ++ptr;
    }
    ++addr;
  }
}

static void VGA_render_vram(SDL_Renderer* renderer) {
  uint32_t i = 0;
  for(uint32_t y = 0; y < 480; ++y) {
    for(uint32_t x = 0; x < 640; ++x) {
      const SDL_Color color = vga.palette[ vga.vram[i] ];
      ++i;

      SDL_SetRenderDrawColor(renderer, color.r, color.g, color.b, 255);
      SDL_RenderDrawPoint(renderer, x, y);
    }
  }
}

void* io_thread(void* arg) {
  SDL_Window* window = NULL;
  SDL_Renderer* renderer = NULL;

  SDL_Init(SDL_INIT_VIDEO);
  SDL_CreateWindowAndRenderer(640, 480, 0, &window, &renderer);

  SDL_Event event;
  uint8_t running = 1;

  while( running ) {
    while( SDL_PollEvent( &event ) != 0 ) {
      if( event.type == SDL_QUIT ) {
        running = 0;
      }
    }

    SDL_RenderClear(renderer);
    VGA_render_vram(renderer);
    SDL_RenderPresent(renderer);

    SDL_Delay(33);
  }

  SDL_DestroyRenderer(renderer);
  SDL_DestroyWindow(window);
  SDL_Quit();
}

#endif
