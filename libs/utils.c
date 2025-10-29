#include "utils.h"

uint64_t SystemMonotonicMS()
{
	long            ms;
	time_t          s;

	struct timespec spec;
	clock_gettime(CLOCK_MONOTONIC, &spec);
	s  = spec.tv_sec;
	ms = (spec.tv_nsec / 1000000);

	uint64_t result = s;
	result *= 1000;
	result += ms;

	return result;
}

char* utils_strdup(const char* str) {
  if (!str) return NULL;
  size_t len = strlen(str) + 1;
  char* copy = (char*)malloc(len);
  if (copy == NULL) {
    return NULL;
  }
  memcpy(copy, str, len);   
  
  return copy; /*Caller needs to free*/
}