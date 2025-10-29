
#include <time.h>
#include <ctype.h>
#include <unistd.h>

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

/*static int read_line(int fd, char* buffer, size_t max_len)
{
	size_t i = 0;
	char c;
	while (i < max_len - 1)
	{
		ssize_t n = read(fd, &c, 1);
		if (n <= 0) return -1; // error
		if (c == '\r') continue;
		if (c == '\n') break;
		buffer[i++] = c;
	}
	buffer[i] = '\0';
	return (int)i;
}*/