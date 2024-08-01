#ifndef _STRING_STRUCT_H_
#define _STRING_STRUCT_H_

#include <stdint.h>

typedef struct {
  uint32_t len;
  char* str;
}
String;

#endif
