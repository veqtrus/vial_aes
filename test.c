/*
Copyright (c) 2020 Pavlos Georgiou

Distributed under the Boost Software License, Version 1.0.
See accompanying file LICENSE_1_0.txt or copy at
https://www.boost.org/LICENSE_1_0.txt
*/

#include <string.h>
#include <stdio.h> 

#include "aes.h"

struct testcase {
	const char *plain, *key, *cipher;
};

static const struct testcase testcases[] = {
	{
		"6BC1BEE22E409F96E93D7E117393172A",
		"2B7E151628AED2A6ABF7158809CF4F3C",
		"3AD77BB40D7A3660A89ECAF32466EF97"
	}, {
		"AE2D8A571E03AC9C9EB76FAC45AF8E51",
		"2B7E151628AED2A6ABF7158809CF4F3C",
		"F5D3D58503B9699DE785895A96FDBAAF"
	}, {
		"F69F2445DF4F9B17AD2B417BE66C3710",
		"2B7E151628AED2A6ABF7158809CF4F3C",
		"7B0C785E27E8AD3F8223207104725DD4"
	}, { NULL }
};

static int decode_hex(union vial_aes_block *dst, const char *src)
{
	unsigned digit;
	for (unsigned i = 0; i < sizeof(*dst) * 2; ++i) {
		digit = *src++;
		if (digit >= '0' && digit <= '9')
			digit -= '0';
		else if (digit >= 'A' && digit <= 'F')
			digit -= 'A' - 10;
		else if (digit >= 'a' && digit <= 'f')
			digit -= 'a' - 10;
		else
			return -1;
		if (i % 2 == 0)
			dst->bytes[i / 2] = digit * 16;
		else
			dst->bytes[i / 2] += digit;
	}
	return 0;
}

static int test_aes(const struct testcase *test)
{
	union vial_aes_block key, plain, cipher, result;
	struct vial_aes aes;
	decode_hex(&key, test->key);
	decode_hex(&plain, test->plain);
	decode_hex(&cipher, test->cipher);
	vial_aes_init(&aes, VIAL_AES_MODE_ECB, 128, key.bytes, NULL);
	vial_aes_encrypt(&aes, result.bytes, plain.bytes, sizeof(plain));
	if (memcmp(&cipher, &result, sizeof(result))) {
		printf("AES failed encrypting %s\n", test->plain);
		return -2;
	}
	vial_aes_init(&aes, VIAL_AES_MODE_ECB, 128, key.bytes, NULL);
	vial_aes_decrypt(&aes, result.bytes, cipher.bytes, sizeof(cipher));
	if (memcmp(&plain, &result, sizeof(result))) {
		printf("AES failed decrypting %s\n", test->cipher);
		return -3;
	}
	return 0;
}

int main()
{
	int err;
	for (const struct testcase *test = testcases; test->key; ++test) {
		err = test_aes(test);
		if (err) return err;
	}
	puts("AES passed tests");
	return 0;
}
