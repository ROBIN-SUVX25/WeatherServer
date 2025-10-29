#ifndef __UTILS_H_
#define __UTILS_H_

#define _POSIX_C_SOURCE 200809L
#include <time.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

uint64_t SystemMonotonicMS();

char* utils_strdup(const char* str);

#endif