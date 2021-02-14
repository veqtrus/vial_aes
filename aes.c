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

void vial_aes_increment_be(uint8_t *num, size_t len)
{
	if (len == 0) return;
	do --len; while (++(num[len]) == 0 && len != 0);
}

static void galois_double_be(uint8_t *dst, const uint8_t *src)
{
	const uint8_t msb = src[0] >> 7;
	for (int i = 0; i < VIAL_AES_BLOCK_SIZE - 1; ++i)
		dst[i] = (src[i] << 1) | (src[i + 1] >> 7);
	dst[VIAL_AES_BLOCK_SIZE - 1] = (src[VIAL_AES_BLOCK_SIZE - 1] << 1) ^ (135 & -msb);
}

static void galois_mult_gcm(const uint32_t *h, uint8_t *x)
{
	uint32_t m,
		h0 = h[0], h1 = h[1], h2 = h[2], h3 = h[3],
		r0 = 0, r1 = 0, r2 = 0, r3 = 0;
	unsigned i;
	uint8_t b;
	for (i = 0; i < 128; ++i) {
		b = (i & 7) ? (b << 1) : x[i / 8];
		m = 0;
		m -= b >> 7;
		r0 ^= h0 & m;
		r1 ^= h1 & m;
		r2 ^= h2 & m;
		r3 ^= h3 & m;
		m = -(h3 & 1);
		h3 = (h3 >> 1) | (h2 << 31);
		h2 = (h2 >> 1) | (h1 << 31);
		h1 = (h1 >> 1) | (h0 << 31);
		h0 = (h0 >> 1) ^ (0xE1000000 & m);
	}
	for (i = 4; i --> 0;) {
		x[i] = r0;
		r0 >>= 8;
		x[i + 4] = r1;
		r1 >>= 8;
		x[i + 8] = r2;
		r2 >>= 8;
		x[i + 12] = r3;
		r3 >>= 8;
	}
}

static void block_zero(struct vial_aes_block *blk)
{
	blk->words[3] = blk->words[2] = blk->words[1] = blk->words[0] = 0;
}

static void block_xor(struct vial_aes_block *dst, const struct vial_aes_block *src)
{
	dst->words[0] ^= src->words[0];
	dst->words[1] ^= src->words[1];
	dst->words[2] ^= src->words[2];
	dst->words[3] ^= src->words[3];
}

static void transpose_in(struct vial_aes_block *blk, const uint8_t *buf)
{
	uint32_t w;
	int i, j;
	for (i = 0; i < 4; ++i) {
		w = 0;
		for (j = 0; j < 4; ++j) {
			w = (w << 8) | buf[i + j * 4];
		}
		blk->words[i] = w;
	}
}

static void transpose_out(const struct vial_aes_block *blk, uint8_t *buf)
{
	uint32_t w;
	int i, j;
	for (i = 0; i < 4; ++i) {
		w = blk->words[i];
		for (j = 4; j --> 0;) {
			buf[i + j * 4] = w;
			w >>= 8;
		}
	}
}

#define ROTL(x, n) ((x << n) | (x >> (32 - n)))

#define GDBL4(x) (((x & 0x7F7F7F7FU) << 1) ^ ((0x40404040U - ((x >> 7) & 0x01010101U)) & 0x1B1B1B1BU))

static void expand_keys(struct vial_aes_block *keys, unsigned n, unsigned r)
{
	struct vial_aes_block blk;
	uint32_t *w = keys->words;
	uint8_t *b = (uint8_t *) (w + n - 1);
	unsigned i, j;
	uint8_t c = 1;
	for (i = n, j = 0; i < 4 * r; ++i, ++j, b += 4) {
		if (j == n) j = 0;
		if (j == 0) {
			b[4] = sbox[b[1]] ^ c;
			b[5] = sbox[b[2]];
			b[6] = sbox[b[3]];
			b[7] = sbox[b[0]];
			w[i] ^= w[i - n];
			c = (c << 1) ^ (0x1B & -(c >> 7));
		} else if (n > 6 && j == 4) {
			b[4] = sbox[b[0]];
			b[5] = sbox[b[1]];
			b[6] = sbox[b[2]];
			b[7] = sbox[b[3]];
			w[i] ^= w[i - n];
		} else {
			w[i] = w[i - n] ^ w[i - 1];
		}
	}
	for (i = 0; i < r; ++i, ++keys) {
		transpose_in(&blk, (uint8_t *) keys);
		*keys = blk;
	}
}

enum vial_aes_error vial_aes_key_init(struct vial_aes_key *self, unsigned keybits, const uint8_t *key)
{
	if (!(keybits == 128 || keybits == 192 || keybits == 256))
		return VIAL_AES_ERROR_LENGTH;
	self->rounds = keybits / 32 + 6;
	memcpy(&self->key_exp[0], key, keybits / 8);
	expand_keys(self->key_exp, keybits / 32, self->rounds + 1);
	return VIAL_AES_ERROR_NONE;
}

void vial_aes_block_encrypt(const struct vial_aes_key *key, uint8_t *dst, const uint8_t *src)
{
	struct vial_aes_block blk;
	uint32_t a1, b1, c1, d1, a2, b2, c2, d2;
	unsigned i, r;
	transpose_in(&blk, src);
	for (r = 0; ; ++r) {
		/* AddRoundKey */
		block_xor(&blk, &key->key_exp[r]);
		/* SubBytes */
		for (i = 0; i < VIAL_AES_BLOCK_SIZE; ++i)
			((uint8_t *) &blk)[i] = sbox[((uint8_t *) &blk)[i]];
		/* ShiftRows */
		a1 = blk.words[0];
		b1 = blk.words[1];
		c1 = blk.words[2];
		d1 = blk.words[3];
		b1 = ROTL(b1, 8);
		c1 = ROTL(c1, 16);
		d1 = ROTL(d1, 24);
		if (r == key->rounds - 1)
			break;
		/* MixColumns */
		a2 = GDBL4(a1) ^ b1;
		b2 = GDBL4(b1) ^ c1;
		c2 = GDBL4(c1) ^ d1;
		d2 = GDBL4(d1) ^ a1;
		blk.words[0] = a2 ^ b2 ^ d1; /* 2 3 1 1 */
		blk.words[1] = b2 ^ c2 ^ a1; /* 1 2 3 1 */
		blk.words[2] = c2 ^ d2 ^ b1; /* 1 1 2 3 */
		blk.words[3] = d2 ^ a2 ^ c1; /* 3 1 1 2 */
	}
	/* AddRoundKey */
	blk.words[0] = key->key_exp[key->rounds].words[0] ^ a1;
	blk.words[1] = key->key_exp[key->rounds].words[1] ^ b1;
	blk.words[2] = key->key_exp[key->rounds].words[2] ^ c1;
	blk.words[3] = key->key_exp[key->rounds].words[3] ^ d1;
	transpose_out(&blk, dst);
}

void vial_aes_block_decrypt(const struct vial_aes_key *key, uint8_t *dst, const uint8_t *src)
{
	struct vial_aes_block blk;
	uint32_t a1, b1, c1, d1, a2, b2, c2, d2, ac4, bd4, m;
	unsigned i, r;
	transpose_in(&blk, src);
	/* AddRoundKey */
	block_xor(&blk, &key->key_exp[key->rounds]);
	for (r = key->rounds - 1; ; --r) {
		/* SubBytes */
		for (i = 0; i < VIAL_AES_BLOCK_SIZE; ++i)
			((uint8_t *) &blk)[i] = rsbox[((uint8_t *) &blk)[i]];
		/* ShiftRows */
		a1 = blk.words[0];
		b1 = blk.words[1];
		c1 = blk.words[2];
		d1 = blk.words[3];
		b1 = ROTL(b1, 24);
		c1 = ROTL(c1, 16);
		d1 = ROTL(d1, 8);
		/* AddRoundKey */
		a1 ^= key->key_exp[r].words[0];
		b1 ^= key->key_exp[r].words[1];
		c1 ^= key->key_exp[r].words[2];
		d1 ^= key->key_exp[r].words[3];
		if (r == 0)
			break;
		/* MixColumns */
		a2 = GDBL4(a1);
		b2 = GDBL4(b1);
		c2 = GDBL4(c1);
		d2 = GDBL4(d1);
		ac4 = a2 ^ c2;
		bd4 = b2 ^ d2;
		ac4 = GDBL4(ac4);
		bd4 = GDBL4(bd4);
		m = ac4 ^ bd4;
		m = GDBL4(m) ^ a1 ^ b1 ^ c1 ^ d1;
		ac4 ^= m, bd4 ^= m;
		blk.words[0] = ac4 ^ a2 ^ b2 ^ a1; /* 14 11 13 9 */
		blk.words[1] = bd4 ^ b2 ^ c2 ^ b1; /* 9 14 11 13 */
		blk.words[2] = ac4 ^ c2 ^ d2 ^ c1; /* 13 9 14 11 */
		blk.words[3] = bd4 ^ d2 ^ a2 ^ d1; /* 11 13 9 14 */
	}
	blk.words[0] = a1;
	blk.words[1] = b1;
	blk.words[2] = c1;
	blk.words[3] = d1;
	transpose_out(&blk, dst);
}

void vial_aes_cmac_init(struct vial_aes_cmac *self, const struct vial_aes_key *key)
{
	uint8_t k0[VIAL_AES_BLOCK_SIZE] = {0};
	self->key = key;
	self->buf_len = 0;
	block_zero(&self->mac);
	vial_aes_block_encrypt(self->key, k0, k0);
	galois_double_be((uint8_t *) &self->k1, k0);
}

void vial_aes_cmac_update(struct vial_aes_cmac *self, const uint8_t *src, size_t len)
{
	struct vial_aes_block blk;
	if (self->buf_len > 0) {
		while (len > 0 && self->buf_len < VIAL_AES_BLOCK_SIZE) {
			((uint8_t *) &self->mac)[self->buf_len++] ^= *src++;
			len--;
		}
		if (len == 0)
			return;
		self->buf_len = 0;
		vial_aes_block_encrypt(self->key, (uint8_t *) &self->mac, (uint8_t *) &self->mac);
	}
	while (len > VIAL_AES_BLOCK_SIZE) {
		memcpy(&blk, src, VIAL_AES_BLOCK_SIZE);
		block_xor(&self->mac, &blk);
		vial_aes_block_encrypt(self->key, (uint8_t *) &self->mac, (uint8_t *) &self->mac);
		len -= VIAL_AES_BLOCK_SIZE;
		src += VIAL_AES_BLOCK_SIZE;
	}
	while (len --> 0) {
		((uint8_t *) &self->mac)[self->buf_len++] ^= *src++;
	}
}

void vial_aes_cmac_final(struct vial_aes_cmac *self, uint8_t *tag, size_t tag_len)
{
	struct vial_aes_block k2;
	if (tag_len > VIAL_AES_BLOCK_SIZE)
		tag_len = VIAL_AES_BLOCK_SIZE;
	if (self->buf_len < VIAL_AES_BLOCK_SIZE) {
		((uint8_t *) &self->mac)[self->buf_len] ^= 0x80;
		galois_double_be((uint8_t *) &k2, (uint8_t *) &self->k1);
		block_xor(&self->mac, &k2);
	} else {
		block_xor(&self->mac, &self->k1);
	}
	vial_aes_block_encrypt(self->key, (uint8_t *) &self->mac, (uint8_t *) &self->mac);
	memcpy(tag, &self->mac, tag_len);
	self->buf_len = 0;
	block_zero(&self->mac);
}

void vial_aes_cmac_tag(const struct vial_aes_key *key, uint8_t *tag, size_t tag_len, const uint8_t *src, size_t len)
{
	struct vial_aes_cmac cmac;
	vial_aes_cmac_init(&cmac, key);
	vial_aes_cmac_update(&cmac, src, len);
	vial_aes_cmac_final(&cmac, tag, tag_len);
}

static void ghash_init(struct vial_aes_ghash *self, const uint8_t *key)
{
	uint32_t h0 = 0, h1 = 0, h2 = 0, h3 = 0;
	for (int i = 0; i < 4; ++i) {
		h0 = (h0 << 8) | key[i];
		h1 = (h1 << 8) | key[i + 4];
		h2 = (h2 << 8) | key[i + 8];
		h3 = (h3 << 8) | key[i + 12];
	}
	self->key.words[0] = h0;
	self->key.words[1] = h1;
	self->key.words[2] = h2;
	self->key.words[3] = h3;
	block_zero(&self->acc);
	self->a_len = 0;
	self->c_len = 0;
	self->buf_len = 0;
}

static void ghash_update(struct vial_aes_ghash *self, const uint8_t *src, size_t len)
{
	struct vial_aes_block blk;
	if (self->buf_len > 0) {
		while (len > 0 && self->buf_len < VIAL_AES_BLOCK_SIZE) {
			((uint8_t *) &self->acc)[self->buf_len++] ^= *src++;
			len--;
		}
		if (self->buf_len != VIAL_AES_BLOCK_SIZE)
			return;
		self->buf_len = 0;
		galois_mult_gcm(self->key.words, (uint8_t *) &self->acc);
	}
	while (len >= VIAL_AES_BLOCK_SIZE) {
		memcpy(&blk, src, VIAL_AES_BLOCK_SIZE);
		block_xor(&self->acc, &blk);
		galois_mult_gcm(self->key.words, (uint8_t *) &self->acc);
		len -= VIAL_AES_BLOCK_SIZE;
		src += VIAL_AES_BLOCK_SIZE;
	}
	while (len --> 0) {
		((uint8_t *) &self->acc)[self->buf_len++] ^= *src++;
	}
}

static void ghash_final(struct vial_aes_ghash *self, struct vial_aes_block *hash)
{
	uint64_t a_len, c_len;
	uint8_t last[VIAL_AES_BLOCK_SIZE];
	if (self->buf_len > 0) self->buf_len = VIAL_AES_BLOCK_SIZE;
	a_len = self->a_len * 8;
	c_len = self->c_len * 8;
	self->a_len = 0;
	self->c_len = 0;
	for (int i = 8; i --> 0;) {
		last[i] = a_len;
		a_len >>= 8;
		last[i + 8] = c_len;
		c_len >>= 8;
	}
	ghash_update(self, last, VIAL_AES_BLOCK_SIZE);
	*hash = self->acc;
	block_zero(&self->acc);
}

static void aes_ctr_pad(struct vial_aes *self, uint8_t *dst, const uint8_t *src, size_t len)
{
	struct vial_aes_block blk;
	while (len > 0 && self->pad_used < VIAL_AES_BLOCK_SIZE) {
		*dst = *src ^ ((uint8_t *) &self->pad)[self->pad_used++];
		len--; src++; dst++;
	}
	while (len >= VIAL_AES_BLOCK_SIZE) {
		vial_aes_block_encrypt(self->key, (uint8_t *) &self->pad, (uint8_t *) &self->iv);
		vial_aes_increment_be((uint8_t *) &self->iv, VIAL_AES_BLOCK_SIZE);
		memcpy(&blk, src, VIAL_AES_BLOCK_SIZE);
		block_xor(&blk, &self->pad);
		memcpy(dst, &blk, VIAL_AES_BLOCK_SIZE);
		len -= VIAL_AES_BLOCK_SIZE;
		src += VIAL_AES_BLOCK_SIZE;
		dst += VIAL_AES_BLOCK_SIZE;
	}
	if (len > 0) {
		vial_aes_block_encrypt(self->key, (uint8_t *) &self->pad, (uint8_t *) &self->iv);
		vial_aes_increment_be((uint8_t *) &self->iv, VIAL_AES_BLOCK_SIZE);
		self->pad_used = 0;
		while (len > 0) {
			*dst = *src ^ ((uint8_t *) &self->pad)[self->pad_used++];
			len--; src++; dst++;
		}
	}
}

enum vial_aes_error vial_aes_init(struct vial_aes *self, enum vial_aes_mode mode,
	const struct vial_aes_key *key, const uint8_t *iv, size_t iv_len)
{
	uint8_t blk[VIAL_AES_BLOCK_SIZE] = {0};
	self->mode = mode;
	self->pad_used = VIAL_AES_BLOCK_SIZE;
	self->key = key;
	switch (mode) {
	case VIAL_AES_MODE_ECB:
		break;
	case VIAL_AES_MODE_CBC:
		if (iv_len != VIAL_AES_BLOCK_SIZE)
			return VIAL_AES_ERROR_IV;
		memcpy(&self->iv, iv, VIAL_AES_BLOCK_SIZE);
		break;
	case VIAL_AES_MODE_CTR:
		if (iv_len > VIAL_AES_BLOCK_SIZE)
			return VIAL_AES_ERROR_IV;
		block_zero(&self->iv);
		memcpy(&self->iv, iv, iv_len);
		break;
	case VIAL_AES_MODE_EAX:
		vial_aes_cmac_init(self->cmac, key);
		self->cmac->buf_len = VIAL_AES_BLOCK_SIZE;
		vial_aes_cmac_update(self->cmac, iv, iv_len);
		vial_aes_cmac_final(self->cmac, (uint8_t *) &self->iv, VIAL_AES_BLOCK_SIZE);
		return vial_aes_auth_data(self, NULL, 0);
	case VIAL_AES_MODE_GCM:
		if (iv_len != 12)
			return VIAL_AES_ERROR_IV;
		memcpy(&self->iv, iv, 12);
		self->iv.words[3] = 0;
		self->auth = self->iv;
		((uint8_t *) &self->iv)[VIAL_AES_BLOCK_SIZE - 1] = 2;
		((uint8_t *) &self->auth)[VIAL_AES_BLOCK_SIZE - 1] = 1;
		vial_aes_block_encrypt(self->key, blk, blk);
		vial_aes_block_encrypt(self->key, (uint8_t *) &self->auth, (uint8_t *) &self->auth);
		ghash_init(self->ghash, blk);
		break;
	default:
		return VIAL_AES_ERROR_CIPHER;
	}
	return VIAL_AES_ERROR_NONE;
}

enum vial_aes_error vial_aes_auth_data(struct vial_aes *self, const uint8_t *src, size_t len)
{
	switch (self->mode) {
	case VIAL_AES_MODE_EAX:
		self->cmac->buf_len = VIAL_AES_BLOCK_SIZE;
		((uint8_t *) &self->cmac->mac)[VIAL_AES_BLOCK_SIZE - 1] = 1;
		vial_aes_cmac_update(self->cmac, src, len);
		vial_aes_cmac_final(self->cmac, (uint8_t *) &self->auth, VIAL_AES_BLOCK_SIZE);
		block_xor(&self->auth, &self->iv);
		((uint8_t *) &self->cmac->mac)[VIAL_AES_BLOCK_SIZE - 1] = 2;
		self->cmac->buf_len = VIAL_AES_BLOCK_SIZE;
		return VIAL_AES_ERROR_NONE;
	case VIAL_AES_MODE_GCM:
		if (self->ghash->a_len > 0 || self->ghash->c_len > 0)
			return VIAL_AES_ERROR_CIPHER;
		self->ghash->a_len += len;
		ghash_update(self->ghash, src, len);
		if (self->ghash->buf_len > 0)
			self->ghash->buf_len = VIAL_AES_BLOCK_SIZE;
		return VIAL_AES_ERROR_NONE;
	default:
		return VIAL_AES_ERROR_CIPHER;
	}
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
	case VIAL_AES_MODE_GCM:
		self->ghash->c_len += len;
		aes_ctr_pad(self, dst, src, len);
		ghash_update(self->ghash, dst, len);
		break;
	case VIAL_AES_MODE_ECB:
		if (len % VIAL_AES_BLOCK_SIZE != 0)
			return VIAL_AES_ERROR_LENGTH;
		while (len > 0) {
			vial_aes_block_encrypt(self->key, dst, src);
			len -= VIAL_AES_BLOCK_SIZE;
			src += VIAL_AES_BLOCK_SIZE;
			dst += VIAL_AES_BLOCK_SIZE;
		}
		break;
	case VIAL_AES_MODE_CBC:
		if (len % VIAL_AES_BLOCK_SIZE != 0)
			return VIAL_AES_ERROR_LENGTH;
		while (len > 0) {
			memcpy(&blk, src, VIAL_AES_BLOCK_SIZE);
			block_xor(&blk, &self->iv);
			vial_aes_block_encrypt(self->key, (uint8_t *) &blk, (uint8_t *) &blk);
			memcpy(dst, &blk, VIAL_AES_BLOCK_SIZE);
			self->iv = blk;
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
	case VIAL_AES_MODE_GCM:
		self->ghash->c_len += len;
		ghash_update(self->ghash, src, len);
		aes_ctr_pad(self, dst, src, len);
		break;
	case VIAL_AES_MODE_ECB:
		if (len % VIAL_AES_BLOCK_SIZE != 0)
			return VIAL_AES_ERROR_LENGTH;
		while (len > 0) {
			vial_aes_block_decrypt(self->key, dst, src);
			len -= VIAL_AES_BLOCK_SIZE;
			src += VIAL_AES_BLOCK_SIZE;
			dst += VIAL_AES_BLOCK_SIZE;
		}
		break;
	case VIAL_AES_MODE_CBC:
		if (len % VIAL_AES_BLOCK_SIZE != 0)
			return VIAL_AES_ERROR_LENGTH;
		while (len > 0) {
			vial_aes_block_decrypt(self->key, (uint8_t *) &blk, src);
			block_xor(&blk, &self->iv);
			memcpy(&self->iv, src, VIAL_AES_BLOCK_SIZE);
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
	switch (self->mode) {
	case VIAL_AES_MODE_EAX:
		vial_aes_cmac_final(self->cmac, (uint8_t *) &blk, VIAL_AES_BLOCK_SIZE);
		break;
	case VIAL_AES_MODE_GCM:
		ghash_final(self->ghash, &blk);
		break;
	default:
		return VIAL_AES_ERROR_CIPHER;
	}
	block_xor(&blk, &self->auth);
	memcpy(tag, &blk, VIAL_AES_BLOCK_SIZE);
	return VIAL_AES_ERROR_NONE;
}

enum vial_aes_error vial_aes_check_tag(struct vial_aes *self, const uint8_t *tag)
{
	uint8_t comp_tag[VIAL_AES_BLOCK_SIZE];
	const enum vial_aes_error err = vial_aes_get_tag(self, comp_tag);
	if (err) return err;
	return memcmp(comp_tag, tag, VIAL_AES_BLOCK_SIZE) ? VIAL_AES_ERROR_MAC : VIAL_AES_ERROR_NONE;
}
