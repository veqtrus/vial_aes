/*
Copyright (c) 2020 Pavlos Georgiou

Distributed under the Boost Software License, Version 1.0.
See accompanying file LICENSE_1_0.txt or copy at
https://www.boost.org/LICENSE_1_0.txt
*/

#ifndef VIAL_CRYPTO_AES_H
#define VIAL_CRYPTO_AES_H

#include <stddef.h>
#include <stdint.h>

#define VIAL_AES_BLOCK_SIZE 16

#ifdef __cplusplus
extern "C" {
#endif

enum vial_aes_mode {
	VIAL_AES_MODE_ECB,
	VIAL_AES_MODE_CBC,
	VIAL_AES_MODE_CFB
};

union vial_aes_block {
	uint8_t bytes[VIAL_AES_BLOCK_SIZE];
	uint32_t words[VIAL_AES_BLOCK_SIZE / 4];
};

struct vial_aes {
	enum vial_aes_mode mode;
	unsigned rounds;
    union vial_aes_block iv;
	union vial_aes_block keys[15];
};

void vial_aes_init(struct vial_aes *self, enum vial_aes_mode mode,
	unsigned keybits, const uint8_t *key, const uint8_t *iv);

void vial_aes_encrypt(struct vial_aes *self, uint8_t *dst, const uint8_t *src, size_t len);

void vial_aes_decrypt(struct vial_aes *self, uint8_t *dst, const uint8_t *src, size_t len);

#ifdef __cplusplus
}
#endif

#endif
