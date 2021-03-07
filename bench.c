/* SPDX-License-Identifier: BSL-1.0
Copyright (c) 2021 Pavlos Georgiou

Distributed under the Boost Software License, Version 1.0.
See accompanying file LICENSE_1_0.txt or copy at
https://www.boost.org/LICENSE_1_0.txt
*/

#include <time.h>
#include <stdio.h>
#include <stdlib.h>

#include "aes.h"

#if defined(_M_AMD64) || defined(__x86_64__) || defined(__amd64__)
#ifdef _WIN32
#include <intrin.h>
#else
#include <x86intrin.h>
#endif
#else
#define __rdtsc() 0
#endif

#define BUFFER_SIZE 4096

int main()
{
	struct vial_aes_key key;
	struct vial_aes_ctr aes;
	uint8_t *buffer = malloc(BUFFER_SIZE);
	for (unsigned i = 0; i < BUFFER_SIZE; ++i)
		buffer[i] = i;
	vial_aes_key_init(&key, 128, (const uint8_t *) "0123456789ABCDEF");
	vial_aes_ctr_init_key(&aes, &key);
	vial_aes_ctr_reset(&aes, (const uint8_t *) "ABCDEF654321", 12);
	clock_t dur = clock();
	uint64_t tsc = __rdtsc();
	vial_aes_ctr_crypt(&aes, buffer, buffer, BUFFER_SIZE);
	tsc = __rdtsc() - tsc;
	dur = clock() - dur;
	free(buffer);
	printf("AES-CTR encryption speed: %f MB/s; %f cpb\n", (BUFFER_SIZE / 1.0e6) * CLOCKS_PER_SEC / dur, tsc / (double) BUFFER_SIZE);
	return 0;
}
