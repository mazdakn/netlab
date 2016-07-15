#ifndef __MEMORY_H__
#define __MEMORY_H__

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "message.h"

char *allocate_strmem (int len);
uint8_t *allocate_ustrmem (int len);
int *allocate_intmem (int len);

#endif
