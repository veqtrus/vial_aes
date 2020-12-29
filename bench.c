#include <time.h>
#include <stdio.h>

#include "aes.h"

#ifdef _WIN32
#include <intrin.h>
#else
#include <x86intrin.h>
#endif

int main()
{
	struct vial_aes_key key;
	struct vial_aes_block block;
	key.rounds = 10;
	clock_t dur = clock();
	uint64_t tsc = __rdtsc();
	for (uint32_t i = 0; i < 1000000; ++i)
		vial_aes_block_encrypt(&block, &key);
	tsc = __rdtsc() - tsc;
	dur = clock() - dur;
	printf("AES encryption speed: %f MB/s; %f cpb\n", 16.0 * CLOCKS_PER_SEC / dur, tsc / 16000000.0);
	return 0;
}
