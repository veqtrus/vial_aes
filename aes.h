/* SPDX-License-Identifier: BSL-1.0
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
	VIAL_AES_ERROR_NONE = 0, /**< No error */
	VIAL_AES_ERROR_LENGTH, /**< Input of invalid length */
	VIAL_AES_ERROR_IV, /**< IV missing when required or does not meet requirements */
	VIAL_AES_ERROR_MAC, /**< Message authentication failed */
	VIAL_AES_ERROR_CIPHER /**< Operation not valid for selected cipher mode */
};

/**
 * Block cipher mode of operation
 */
enum vial_aes_mode {
	VIAL_AES_MODE_ECB, /**< Encrypts each block independently, should generally not be used */
	VIAL_AES_MODE_CBC, /**< Provides confidentiality but not integrity, data must be padded */
	VIAL_AES_MODE_CTR, /**< Stream-cipher-like mode, does not check integrity */
	VIAL_AES_MODE_EAX, /**< Recommended mode, as it provides confidentiality and integrity */
	VIAL_AES_MODE_GCM /**< Provides confidentiality and integrity */
};

/**
 * Increments a big-endian integer by one
 */
void vial_aes_increment_be(uint8_t *num, size_t len);

struct vial_aes_block {
	uint32_t words[VIAL_AES_BLOCK_SIZE / 4];
};

/**
 * Represents an expanded AES key
 */
struct vial_aes_key {
	struct vial_aes_block key_exp[15];
	unsigned rounds;
};

/**
 * Encrypts a single AES block in-place.
 * Should not be called directly unless as part of a more elaborate scheme.
 */
void vial_aes_block_encrypt(const struct vial_aes_key *key, uint8_t *dst, const uint8_t *src);

/**
 * Decrypts a single AES block in-place.
 * Should not be called directly unless as part of a more elaborate scheme.
 */
void vial_aes_block_decrypt(const struct vial_aes_key *key, uint8_t *dst, const uint8_t *src);

/**
 * Stores the state/context for computing a CMAC (OMAC1) tag
 */
struct vial_aes_cmac {
	const struct vial_aes_key *key;
	struct vial_aes_block mac;
	unsigned buf_len;
};

/**
 * Initialises the CMAC state
 */
void vial_aes_cmac_init(struct vial_aes_cmac *self, const struct vial_aes_key *key);

/**
 * Processes data for authentication
 */
void vial_aes_cmac_update(struct vial_aes_cmac *self, const uint8_t *src, size_t len);

/**
 * Finalises computing the authentication tag
 */
void vial_aes_cmac_final(struct vial_aes_cmac *self, uint8_t *tag, size_t tag_len);

/**
 * Computes a CMAC(OMAC1) tag for the given data.
 * Provided for convenience when a small amount of data needs to be authenticated.
 */
void vial_aes_cmac_tag(const struct vial_aes_key *key, uint8_t *tag, size_t tag_len, const uint8_t *src, size_t len);

/**
 * Stores the state/context for computing GHASH as part of GCM
 */
struct vial_aes_ghash {
	uint64_t key[2];
	struct vial_aes_block acc;
	size_t a_len, c_len;
	unsigned buf_len;
};

/**
 * Stores the state/context for performing AES encryption/decryption
 */
struct vial_aes {
	enum vial_aes_mode mode;
	unsigned pad_used;
	const struct vial_aes_key *key;
	struct vial_aes_block iv, pad, auth;
	struct vial_aes_cmac *cmac;
	struct vial_aes_ghash *ghash;
};

/**
 * Initialises a key structure.
 * Accepted key lengths are 128, 192, 256 bits.
 */
enum vial_aes_error vial_aes_key_init(struct vial_aes_key *self, unsigned keybits, const uint8_t *key);

/**
 * Initialises AES encryption/decryption state.
 * A random 16 byte initialisation vector is required for CBC mode.
 * A unique nonce is required for CTR mode (up to 16 bytes).
 * EAX/GCM modes: The pointer to the CMAC/GHASH state
 * (which will be initialised internally)
 * must be set before calling this function.
 * A unique nonce must be provided for each new message,
 * e.g. by incrementing a randomly initialised counter.
 */
enum vial_aes_error vial_aes_init(struct vial_aes *self, enum vial_aes_mode mode,
	const struct vial_aes_key *key, const uint8_t *iv, size_t len);

/**
 * Sets the associated data to be authenticated alongside the encrypted message.
 * Must be provided after each reinitialisation, before encryption/decryption.
 */
enum vial_aes_error vial_aes_auth_data(struct vial_aes *self, const uint8_t *src, size_t len);

/**
 * Encrypts (part of) a message
 */
enum vial_aes_error vial_aes_encrypt(struct vial_aes *self, uint8_t *dst, const uint8_t *src, size_t len);

/**
 * Decrypts (part of) a message
 */
enum vial_aes_error vial_aes_decrypt(struct vial_aes *self, uint8_t *dst, const uint8_t *src, size_t len);

/**
 * Computes the authentication tag for the processed message.
 * Further data will be authenticated separately.
 */
enum vial_aes_error vial_aes_get_tag(struct vial_aes *self, uint8_t *tag);

/**
 * Verifies the authentication tag for the processed message.
 * Further data will be authenticated separately.
 */
enum vial_aes_error vial_aes_check_tag(struct vial_aes *self, const uint8_t *tag);

#ifdef __cplusplus
}
#endif

#endif
