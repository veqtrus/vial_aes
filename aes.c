/* SPDX-License-Identifier: BSL-1.0
Copyright (c) 2020 Pavlos Georgiou

Distributed under the Boost Software License, Version 1.0.
See accompanying file LICENSE_1_0.txt or copy at
https://www.boost.org/LICENSE_1_0.txt
*/

#include "aes.h"

#include <string.h>

static const uint8_t sbox[256] = {
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

static const uint8_t rsbox[256] = {
	0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
	0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
	0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
	0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
	0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
	0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
	0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
	0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
	0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
	0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
	0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
	0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
	0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
	0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
	0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
	0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

#define GDBL(n) (((n) << 1) ^ (0x1B & -(const uint8_t)(((n) >> 7) & 1)))

#define GDBL4(x2, x1, m) \
	m = (x1 & 0x80808080) >> 7; /* get msb */ \
	x2 = (x1 & 0x7F7F7F7F) << 1; \
	/* xor with 0x1B if msb set */ \
	m |= m << 1; \
	m |= m << 3; \
	x2 ^= m

#define READ_BE32(r, b) \
	r = (b)[0]; \
	r <<= 8; \
	r |= (b)[1]; \
	r <<= 8; \
	r |= (b)[2]; \
	r <<= 8; \
	r |= (b)[3]

static void block_xor(struct vial_aes_block *dst, const struct vial_aes_block *src)
{
	dst->words[0] ^= src->words[0];
	dst->words[1] ^= src->words[1];
	dst->words[2] ^= src->words[2];
	dst->words[3] ^= src->words[3];
}

static void expand_keys(uint32_t *w, unsigned n, unsigned r)
{
	uint8_t *p;
	unsigned i;
	uint8_t c = 1;
	for (i = n; i < 4 * r; ++i) {
		if (i % n == 0) {
			p = (uint8_t *) (w + i - 1);
			p[4] = sbox[p[1]] ^ c;
			p[5] = sbox[p[2]];
			p[6] = sbox[p[3]];
			p[7] = sbox[p[0]];
			w[i] ^= w[i - n];
			c = GDBL(c);
		} else if (n > 6 && i % n == 4) {
			p = (uint8_t *) (w + i - 1);
			p[4] = sbox[p[0]];
			p[5] = sbox[p[1]];
			p[6] = sbox[p[2]];
			p[7] = sbox[p[3]];
			w[i] ^= w[i - n];
		} else {
			w[i] = w[i - n] ^ w[i - 1];
		}
	}
}

void vial_aes_increment_be(uint8_t *num, size_t len)
{
	if (len == 0) return;
	do {
		--len;
	} while (++(num[len]) == 0 && len != 0);
}

static void incr_counter(struct vial_aes_block *counter)
{
	vial_aes_increment_be((uint8_t *) counter, VIAL_AES_BLOCK_SIZE);
}

static void galois_double_be(uint8_t *dst, const uint8_t *src)
{
	const unsigned msb = src[0] >> 7;
	for (int i = 0; i < VIAL_AES_BLOCK_SIZE - 1; ++i)
		dst[i] = (src[i] << 1) | (src[i + 1] >> 7);
	dst[VIAL_AES_BLOCK_SIZE - 1] = src[VIAL_AES_BLOCK_SIZE - 1] << 1;
	dst[VIAL_AES_BLOCK_SIZE - 1] ^= 135 & -(msb & 1);
}

void vial_aes_block_encrypt(struct vial_aes_block *blk, const struct vial_aes_key *key)
{
	struct vial_aes_block tblk;
	uint8_t *blk_bytes = (uint8_t *) blk;
	uint8_t *tblk_bytes = (uint8_t *) &tblk;
	uint32_t m, x1, x2;
	unsigned i, j, r;
	for (r = 0; ; ++r) {
		/* AddRoundKey */
		block_xor(blk, &key->key_exp[r]);
		/* SubBytes */
		/* ShiftRows */
		for (i = 0; i < 4; ++i)
			for (j = 0; j < 4; ++j)
				tblk_bytes[4 * i + j] = sbox[blk_bytes[4 * ((i + j) & 3) + j]];
		if (r == key->rounds - 1)
			break;
		/* MixColumns */
		for (i = 0; i < 4; ++i) {
			READ_BE32(x1, tblk_bytes + 4 * i);
			GDBL4(x2, x1, m);
			m = (x2 & 0xFFFF0000) ^ (x1 & 0x00FFFFFF); /* 2 3 1 1 */
			m ^= m >> 16;
			m ^= m >> 8;
			blk_bytes[4 * i + 0] = m;
			m = (x2 & 0x00FFFF00) ^ (x1 & 0xFF00FFFF); /* 1 2 3 1 */
			m ^= m >> 16;
			m ^= m >> 8;
			blk_bytes[4 * i + 1] = m;
			m = (x2 & 0x0000FFFF) ^ (x1 & 0xFFFF00FF); /* 1 1 2 3 */
			m ^= m >> 16;
			m ^= m >> 8;
			blk_bytes[4 * i + 2] = m;
			m = (x2 & 0xFF0000FF) ^ (x1 & 0xFFFFFF00); /* 3 1 1 2 */
			m ^= m >> 16;
			m ^= m >> 8;
			blk_bytes[4 * i + 3] = m;
		}
	}
	/* AddRoundKey */
	blk->words[0] = tblk.words[0] ^ key->key_exp[key->rounds].words[0];
	blk->words[1] = tblk.words[1] ^ key->key_exp[key->rounds].words[1];
	blk->words[2] = tblk.words[2] ^ key->key_exp[key->rounds].words[2];
	blk->words[3] = tblk.words[3] ^ key->key_exp[key->rounds].words[3];
}

void vial_aes_block_decrypt(struct vial_aes_block *blk, const struct vial_aes_key *key)
{
	struct vial_aes_block tblk;
	uint8_t *blk_bytes = (uint8_t *) blk;
	uint8_t *tblk_bytes = (uint8_t *) &tblk;
	uint32_t m, x1, x2, x4, x8;
	unsigned i, j, r;
	/* AddRoundKey */
	block_xor(blk, &key->key_exp[key->rounds]);
	for (r = key->rounds - 1; ; --r) {
		/* ShiftRows */
		/* SubBytes */
		for (i = 0; i < 4; ++i)
			for (j = 0; j < 4; ++j)
				tblk_bytes[4 * i + j] = rsbox[blk_bytes[4 * ((i - j) & 3) + j]];
		/* AddRoundKey */
		block_xor(&tblk, &key->key_exp[r]);
		if (r == 0)
			break;
		/* MixColumns */
		for (i = 0; i < 4; ++i) {
			READ_BE32(x1, tblk_bytes + 4 * i);
			GDBL4(x2, x1, m);
			GDBL4(x4, x2, m);
			GDBL4(x8, x4, m);
			m = x8 ^ (x4 & 0xFF00FF00) ^ (x2 & 0xFFFF0000) ^ (x1 & 0x00FFFFFF); /* 14 11 13 9 */
			m ^= m >> 16;
			m ^= m >> 8;
			blk_bytes[4 * i + 0] = m;
			m = x8 ^ (x4 & 0x00FF00FF) ^ (x2 & 0x00FFFF00) ^ (x1 & 0xFF00FFFF); /* 9 14 11 13 */
			m ^= m >> 16;
			m ^= m >> 8;
			blk_bytes[4 * i + 1] = m;
			m = x8 ^ (x4 & 0xFF00FF00) ^ (x2 & 0x0000FFFF) ^ (x1 & 0xFFFF00FF); /* 13 9 14 11 */
			m ^= m >> 16;
			m ^= m >> 8;
			blk_bytes[4 * i + 2] = m;
			m = x8 ^ (x4 & 0x00FF00FF) ^ (x2 & 0xFF0000FF) ^ (x1 & 0xFFFFFF00); /* 11 13 9 14 */
			m ^= m >> 16;
			m ^= m >> 8;
			blk_bytes[4 * i + 3] = m;
		}
	}
	*blk = tblk;
}

void vial_aes_cmac_init(struct vial_aes_cmac *self, const struct vial_aes_key *key)
{
	self->key = key;
	self->buf_len = 0;
	memset(&self->mac, 0, VIAL_AES_BLOCK_SIZE);
	memset(&self->buf, 0, VIAL_AES_BLOCK_SIZE);
}

void vial_aes_cmac_update(struct vial_aes_cmac *self, const uint8_t *src, size_t len)
{
	size_t tmp_len;
	if (len == 0)
		return;
	if (self->buf_len < VIAL_AES_BLOCK_SIZE) {
		tmp_len = VIAL_AES_BLOCK_SIZE - self->buf_len;
		if (tmp_len > len)
			tmp_len = len;
		memcpy(((uint8_t *) &self->buf) + self->buf_len, src, tmp_len);
		len -= tmp_len;
		src += tmp_len;
		self->buf_len += tmp_len;
		if (len == 0)
			return;
	}
	/* buf_len == 16 */
	block_xor(&self->mac, &self->buf);
	vial_aes_block_encrypt(&self->mac, self->key);
	while (len > VIAL_AES_BLOCK_SIZE) {
		memcpy(&self->buf, src, VIAL_AES_BLOCK_SIZE);
		block_xor(&self->mac, &self->buf);
		vial_aes_block_encrypt(&self->mac, self->key);
		len -= VIAL_AES_BLOCK_SIZE;
		src += VIAL_AES_BLOCK_SIZE;
	}
	self->buf_len = len;
	memset(&self->buf, 0, VIAL_AES_BLOCK_SIZE);
	memcpy(&self->buf, src, len);
}

void vial_aes_cmac_final(struct vial_aes_cmac *self, uint8_t *tag, size_t tag_len)
{
	struct vial_aes_block k0 = {{0}}, k1, k2;
	vial_aes_block_encrypt(&k0, self->key);
	galois_double_be((uint8_t *) &k1, (uint8_t *) &k0);
	galois_double_be((uint8_t *) &k2, (uint8_t *) &k1);
	if (tag_len > VIAL_AES_BLOCK_SIZE)
		tag_len = VIAL_AES_BLOCK_SIZE;
	if (self->buf_len < VIAL_AES_BLOCK_SIZE) {
		((uint8_t *) &self->buf)[self->buf_len] = 0x80;
		block_xor(&self->buf, &k2);
	} else {
		block_xor(&self->buf, &k1);
	}
	block_xor(&self->mac, &self->buf);
	vial_aes_block_encrypt(&self->mac, self->key);
	memcpy(tag, &self->mac, tag_len);
	self->buf_len = 0;
	memset(&self->mac, 0, VIAL_AES_BLOCK_SIZE);
	memset(&self->buf, 0, VIAL_AES_BLOCK_SIZE);
}

void vial_aes_cmac_tag(const struct vial_aes_key *key, uint8_t *tag, size_t tag_len, const uint8_t *src, size_t len)
{
	struct vial_aes_cmac cmac;
	vial_aes_cmac_init(&cmac, key);
	vial_aes_cmac_update(&cmac, src, len);
	vial_aes_cmac_final(&cmac, tag, tag_len);
}

static void aes_ctr_pad(struct vial_aes *self, uint8_t *dst, const uint8_t *src, size_t len)
{
	struct vial_aes_block blk;
	for (;;) {
		while (len > 0 && self->pad_rem > 0) {
			*dst = *src ^ ((uint8_t *) &self->pad)[VIAL_AES_BLOCK_SIZE - self->pad_rem];
			self->pad_rem--;
			len--; src++; dst++;
		}
		while (len >= VIAL_AES_BLOCK_SIZE) {
			self->pad = self->iv;
			vial_aes_block_encrypt(&self->pad, self->key);
			incr_counter(&self->iv);
			memcpy(&blk, src, VIAL_AES_BLOCK_SIZE);
			block_xor(&blk, &self->pad);
			memcpy(dst, &blk, VIAL_AES_BLOCK_SIZE);
			len -= VIAL_AES_BLOCK_SIZE;
			src += VIAL_AES_BLOCK_SIZE;
			dst += VIAL_AES_BLOCK_SIZE;
		}
		if (len > 0) {
			self->pad = self->iv;
			self->pad_rem = VIAL_AES_BLOCK_SIZE;
			vial_aes_block_encrypt(&self->pad, self->key);
			incr_counter(&self->iv);
		} else {
			return;
		}
	}
}

enum vial_aes_error vial_aes_key_init(struct vial_aes_key *self, unsigned keybits, const uint8_t *key)
{
	if (!(keybits == 128 || keybits == 192 || keybits == 256))
		return VIAL_AES_ERROR_LENGTH;
	self->rounds = keybits / 32 + 6;
	memcpy(&self->key_exp[0], key, keybits / 8);
	expand_keys(self->key_exp[0].words, keybits / 32, self->rounds + 1);
	return VIAL_AES_ERROR_NONE;
}

enum vial_aes_error vial_aes_init(struct vial_aes *self, enum vial_aes_mode mode, const struct vial_aes_key *key, const uint8_t *iv)
{
	if (mode == VIAL_AES_MODE_EAX)
		return VIAL_AES_ERROR_CIPHER;
	self->mode = mode;
	self->pad_rem = 0;
	self->key = key;
	if (iv == NULL) {
		if (mode != VIAL_AES_MODE_ECB)
			return VIAL_AES_ERROR_IV;
		memset(&self->iv, 0, VIAL_AES_BLOCK_SIZE);
	} else {
		memcpy(&self->iv, iv, VIAL_AES_BLOCK_SIZE);
	}
	return VIAL_AES_ERROR_NONE;
}

enum vial_aes_error vial_aes_init_eax(struct vial_aes *self, struct vial_aes_cmac *cmac,
	const struct vial_aes_key *key, const uint8_t *nonce, size_t len)
{
	const uint8_t zeros[VIAL_AES_BLOCK_SIZE] = {0};
	self->mode = VIAL_AES_MODE_EAX;
	self->pad_rem = 0;
	self->key = key;
	self->cmac = cmac;
	vial_aes_cmac_init(cmac, key);
	vial_aes_cmac_update(self->cmac, zeros, VIAL_AES_BLOCK_SIZE);
	vial_aes_cmac_update(self->cmac, nonce, len);
	vial_aes_cmac_final(self->cmac, (uint8_t *) &self->iv, VIAL_AES_BLOCK_SIZE);
	return vial_aes_auth_data(self, NULL, 0);
}

static void eax_init_mac(struct vial_aes *self)
{
	uint8_t blk[VIAL_AES_BLOCK_SIZE] = {0};
	blk[VIAL_AES_BLOCK_SIZE - 1] = 2;
	vial_aes_cmac_init(self->cmac, self->key);
	vial_aes_cmac_update(self->cmac, blk, VIAL_AES_BLOCK_SIZE);
}

enum vial_aes_error vial_aes_auth_data(struct vial_aes *self, const uint8_t *src, size_t len)
{
	uint8_t blk[VIAL_AES_BLOCK_SIZE] = {0};
	if (self->mode != VIAL_AES_MODE_EAX)
		return VIAL_AES_ERROR_CIPHER;
	blk[VIAL_AES_BLOCK_SIZE - 1] = 1;
	vial_aes_cmac_init(self->cmac, self->key);
	vial_aes_cmac_update(self->cmac, blk, VIAL_AES_BLOCK_SIZE);
	vial_aes_cmac_update(self->cmac, src, len);
	vial_aes_cmac_final(self->cmac, (uint8_t *) &self->auth, VIAL_AES_BLOCK_SIZE);
	block_xor(&self->auth, &self->iv);
	eax_init_mac(self);
	return VIAL_AES_ERROR_NONE;
}

enum vial_aes_error vial_aes_encrypt(struct vial_aes *self, uint8_t *dst, const uint8_t *src, size_t len)
{
	struct vial_aes_block blk;
	switch (self->mode) {
	case VIAL_AES_MODE_CTR:
		aes_ctr_pad(self, dst, src, len);
		break;
	case VIAL_AES_MODE_EAX:
		aes_ctr_pad(self, dst, src, len);
		vial_aes_cmac_update(self->cmac, dst, len);
		break;
	case VIAL_AES_MODE_ECB:
	case VIAL_AES_MODE_CBC:
		if (len % VIAL_AES_BLOCK_SIZE != 0)
			return VIAL_AES_ERROR_LENGTH;
		while (len > 0) {
			memcpy(&blk, src, VIAL_AES_BLOCK_SIZE);
			if (self->mode == VIAL_AES_MODE_ECB) {
				vial_aes_block_encrypt(&blk, self->key);
			} else {
				block_xor(&blk, &self->iv);
				vial_aes_block_encrypt(&blk, self->key);
				self->iv = blk;
			}
			memcpy(dst, &blk, VIAL_AES_BLOCK_SIZE);
			len -= VIAL_AES_BLOCK_SIZE;
			src += VIAL_AES_BLOCK_SIZE;
			dst += VIAL_AES_BLOCK_SIZE;
		}
		break;
	default:
		return VIAL_AES_ERROR_CIPHER;
	}
	return VIAL_AES_ERROR_NONE;
}

enum vial_aes_error vial_aes_decrypt(struct vial_aes *self, uint8_t *dst, const uint8_t *src, size_t len)
{
	struct vial_aes_block blk;
	switch (self->mode) {
	case VIAL_AES_MODE_CTR:
		aes_ctr_pad(self, dst, src, len);
		break;
	case VIAL_AES_MODE_EAX:
		vial_aes_cmac_update(self->cmac, src, len);
		aes_ctr_pad(self, dst, src, len);
		break;
	case VIAL_AES_MODE_ECB:
	case VIAL_AES_MODE_CBC:
		if (len % VIAL_AES_BLOCK_SIZE != 0)
			return VIAL_AES_ERROR_LENGTH;
		while (len > 0) {
			memcpy(&blk, src, VIAL_AES_BLOCK_SIZE);
			if (self->mode == VIAL_AES_MODE_ECB) {
				vial_aes_block_decrypt(&blk, self->key);
			} else {
				vial_aes_block_decrypt(&blk, self->key);
				block_xor(&blk, &self->iv);
				memcpy(&self->iv, src, VIAL_AES_BLOCK_SIZE);
			}
			memcpy(dst, &blk, VIAL_AES_BLOCK_SIZE);
			len -= VIAL_AES_BLOCK_SIZE;
			src += VIAL_AES_BLOCK_SIZE;
			dst += VIAL_AES_BLOCK_SIZE;
		}
		break;
	default:
		return VIAL_AES_ERROR_CIPHER;
	}
	return VIAL_AES_ERROR_NONE;
}

enum vial_aes_error vial_aes_get_tag(struct vial_aes *self, uint8_t *tag)
{
	struct vial_aes_block blk;
	if (self->mode != VIAL_AES_MODE_EAX)
		return VIAL_AES_ERROR_CIPHER;
	vial_aes_cmac_final(self->cmac, (uint8_t *) &blk, VIAL_AES_BLOCK_SIZE);
	block_xor(&blk, &self->auth);
	memcpy(tag, &blk, VIAL_AES_BLOCK_SIZE);
	eax_init_mac(self);
	return VIAL_AES_ERROR_NONE;
}

enum vial_aes_error vial_aes_check_tag(struct vial_aes *self, const uint8_t *tag)
{
	uint8_t comp_tag[VIAL_AES_BLOCK_SIZE];
	const enum vial_aes_error err = vial_aes_get_tag(self, comp_tag);
	if (err) return err;
	return memcmp(comp_tag, tag, VIAL_AES_BLOCK_SIZE) ? VIAL_AES_ERROR_MAC : VIAL_AES_ERROR_NONE;
}
