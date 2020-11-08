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

enum vial_aes_error {
	VIAL_AES_ERROR_NONE = 0,
	VIAL_AES_ERROR_LENGTH,
	VIAL_AES_ERROR_IV,
	VIAL_AES_ERROR_MAC,
	VIAL_AES_ERROR_CIPHER
};

enum vial_aes_mode {
	VIAL_AES_MODE_ECB,
	VIAL_AES_MODE_CBC,
	VIAL_AES_MODE_CTR,
	VIAL_AES_MODE_EAX
};

void vial_aes_increment_be(uint8_t *num, size_t len);

union vial_aes_block {
	uint8_t bytes[VIAL_AES_BLOCK_SIZE];
	uint32_t words[VIAL_AES_BLOCK_SIZE / 4];
};

struct vial_aes_key {
	union vial_aes_block key_exp[15];
	unsigned rounds;
};

void vial_aes_block_encrypt(union vial_aes_block *blk, const struct vial_aes_key *key);

void vial_aes_block_decrypt(union vial_aes_block *blk, const struct vial_aes_key *key);

struct vial_aes_cmac {
	const struct vial_aes_key *key;
	union vial_aes_block mac, buf;
	unsigned buf_len;
};

void vial_aes_cmac_init(struct vial_aes_cmac *self, const struct vial_aes_key *key);

void vial_aes_cmac_update(struct vial_aes_cmac *self, const uint8_t *src, size_t len);

void vial_aes_cmac_final(struct vial_aes_cmac *self, uint8_t *tag, size_t tag_len);

void vial_aes_cmac_tag(const struct vial_aes_key *key, uint8_t *tag, size_t tag_len, const uint8_t *src, size_t len);

struct vial_aes {
	enum vial_aes_mode mode;
	unsigned pad_rem;
	const struct vial_aes_key *key;
	union vial_aes_block iv, pad, auth;
	struct vial_aes_cmac *cmac;
};

enum vial_aes_error vial_aes_key_init(struct vial_aes_key *self, unsigned keybits, const uint8_t *key);

enum vial_aes_error vial_aes_init(struct vial_aes *self, enum vial_aes_mode mode, const struct vial_aes_key *key, const uint8_t *iv);

enum vial_aes_error vial_aes_init_eax(struct vial_aes *self, struct vial_aes_cmac *cmac,
	const struct vial_aes_key *key, const uint8_t *nonce, size_t len);

enum vial_aes_error vial_aes_auth_data(struct vial_aes *self, const uint8_t *src, size_t len);

enum vial_aes_error vial_aes_encrypt(struct vial_aes *self, uint8_t *dst, const uint8_t *src, size_t len);

enum vial_aes_error vial_aes_decrypt(struct vial_aes *self, uint8_t *dst, const uint8_t *src, size_t len);

enum vial_aes_error vial_aes_get_tag(struct vial_aes *self, uint8_t *tag);

enum vial_aes_error vial_aes_check_tag(struct vial_aes *self, const uint8_t *tag);

#ifdef __cplusplus
}
#endif

#endif
