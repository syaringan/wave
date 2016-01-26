#include <sys/time.h>
#include <stdint.h>

// @offset: in unit of ms.
uint64_t wsa_exptime(uint64_t offset)
{
	struct timeval time;
	uint64_t sec, usec, res;

	if(gettimeofday(&time, NULL) != 0){
		return 0;
	}

	sec = time.tv_sec;
	usec = time.tv_usec;
	res = sec * 1000000 + usec + offset * 1000;
	return res;
}
