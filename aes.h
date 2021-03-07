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
 * Initialises a key structure.
 * Accepted key lengths are 128, 192, 256 bits.
 */
enum vial_aes_error vial_aes_key_init(struct vial_aes_key *self, unsigned keybits, const uint8_t *key);

/**
 * Encrypts a single AES block.
 * Should not be called directly unless as part of a more elaborate scheme.
 */
void vial_aes_block_encrypt(const struct vial_aes_key *key, uint8_t *dst, const uint8_t *src);

/**
 * Decrypts a single AES block.
 * Should not be called directly unless as part of a more elaborate scheme.
 */
void vial_aes_block_decrypt(const struct vial_aes_key *key, uint8_t *dst, const uint8_t *src);

/**
 * Stores the state/context for computing a CMAC (OMAC1) tag
 */
struct vial_aes_cmac {
	const struct vial_aes_key *key;
	struct vial_aes_block k1, mac;
	unsigned buf_len;
};

/**
 * Initialises the CMAC state
 */
void vial_aes_cmac_init(struct vial_aes_cmac *self, const struct vial_aes_key *key);

/**
 * Resets the CMAC state. Called by `init` and `final`.
 */
void vial_aes_cmac_reset(struct vial_aes_cmac *self);

/**
 * Processes data for authentication
 */
void vial_aes_cmac_update(struct vial_aes_cmac *self, const uint8_t *src, size_t len);

/**
 * Finalises computing the authentication tag
 */
void vial_aes_cmac_final(struct vial_aes_cmac *self, uint8_t *tag, size_t tag_len);

/**
 * Computes a CMAC (OMAC1) tag for the given data.
 * Provided for convenience when a small amount of data needs to be authenticated.
 */
void vial_aes_cmac_tag(const struct vial_aes_key *key, uint8_t *tag, size_t tag_len, const uint8_t *src, size_t len);

struct vial_aes_vtable;

struct vial_aes_base {
	const struct vial_aes_vtable *vtable;
};

struct vial_aes_vtable {
	enum vial_aes_mode mode;
	enum vial_aes_error (*init_key)(struct vial_aes_base *self, const struct vial_aes_key *key);
	enum vial_aes_error (*reset)(struct vial_aes_base *self, const uint8_t *iv, size_t len);
	enum vial_aes_error (*auth_update)(struct vial_aes_base *self, const uint8_t *src, size_t len);
	enum vial_aes_error (*auth_final)(struct vial_aes_base *self, const uint8_t *src, size_t len);
	enum vial_aes_error (*encrypt)(struct vial_aes_base *self, uint8_t *dst, const uint8_t *src, size_t len);
	enum vial_aes_error (*decrypt)(struct vial_aes_base *self, uint8_t *dst, const uint8_t *src, size_t len);
	enum vial_aes_error (*get_tag)(struct vial_aes_base *self, uint8_t *tag);
	enum vial_aes_error (*check_tag)(struct vial_aes_base *self, const uint8_t *tag);
};

/**
 * Context for Electronic Code Book (ECB) mode
 */
struct vial_aes_ecb {
	struct vial_aes_base base;
	const struct vial_aes_key *key;
};

/**
 * Initialises the ECB context
 */
enum vial_aes_error vial_aes_ecb_init(struct vial_aes_ecb *self);

/**
 * Initialises the ECB context with a key
 */
enum vial_aes_error vial_aes_ecb_init_key(struct vial_aes_ecb *self, const struct vial_aes_key *key);

/**
 * Encrypts (part of) a message in ECB mode.
 * The length must be a multiple of 16 bytes.
 */
enum vial_aes_error vial_aes_ecb_encrypt(struct vial_aes_ecb *self, uint8_t *dst, const uint8_t *src, size_t len);

/**
 * Decrypts (part of) a message in ECB mode.
 * The length must be a multiple of 16 bytes.
 */
enum vial_aes_error vial_aes_ecb_decrypt(struct vial_aes_ecb *self, uint8_t *dst, const uint8_t *src, size_t len);

/**
 * Context for Cipher Block Chaining (CBC) mode
 */
struct vial_aes_cbc {
	struct vial_aes_base base;
	const struct vial_aes_key *key;
	struct vial_aes_block iv;
};


/**
 * Initialises the CBC context
 */
enum vial_aes_error vial_aes_cbc_init(struct vial_aes_cbc *self);

/**
 * Initialises the CBC context with a key
 */
enum vial_aes_error vial_aes_cbc_init_key(struct vial_aes_cbc *self, const struct vial_aes_key *key);

/**
 * Resets the CBC context with a random 16 byte initialisation vector (IV)
 */
enum vial_aes_error vial_aes_cbc_reset(struct vial_aes_cbc *self, const uint8_t *iv, size_t len);

/**
 * Encrypts (part of) a message in CBC mode.
 * The length must be a multiple of 16 bytes.
 */
enum vial_aes_error vial_aes_cbc_encrypt(struct vial_aes_cbc *self, uint8_t *dst, const uint8_t *src, size_t len);

/**
 * Decrypts (part of) a message in CBC mode.
 * The length must be a multiple of 16 bytes.
 */
enum vial_aes_error vial_aes_cbc_decrypt(struct vial_aes_cbc *self, uint8_t *dst, const uint8_t *src, size_t len);

/**
 * Context for counter (CTR) mode
 */
struct vial_aes_ctr {
	struct vial_aes_base base;
	const struct vial_aes_key *key;
	struct vial_aes_block counter, pad;
	unsigned pad_used;
};

/**
 * Initialises the CTR context
 */
enum vial_aes_error vial_aes_ctr_init(struct vial_aes_ctr *self);

/**
 * Initialises the CTR context with a key
 */
enum vial_aes_error vial_aes_ctr_init_key(struct vial_aes_ctr *self, const struct vial_aes_key *key);

/**
 * Resets the CTR context with a unique initialisation vector (IV) of up to 16 byte length
 */
enum vial_aes_error vial_aes_ctr_reset(struct vial_aes_ctr *self, const uint8_t *iv, size_t len);

/**
 * Encrypts or decrypts (part of) a message in CTR mode
 */
enum vial_aes_error vial_aes_ctr_crypt(struct vial_aes_ctr *self, uint8_t *dst, const uint8_t *src, size_t len);

/**
 * Context for EAX mode
 */
struct vial_aes_eax {
	struct vial_aes_base base;
	struct vial_aes_ctr ctr;
	struct vial_aes_cmac cmac;
	struct vial_aes_block auth;
	int auth_done;
};

/**
 * Initialises the EAX context
 */
enum vial_aes_error vial_aes_eax_init(struct vial_aes_eax *self);

/**
 * Initialises the EAX context with a key
 */
enum vial_aes_error vial_aes_eax_init_key(struct vial_aes_eax *self, const struct vial_aes_key *key);

/**
 * Resets the EAX context with a unique nonce
 */
enum vial_aes_error vial_aes_eax_reset(struct vial_aes_eax *self, const uint8_t *nonce, size_t len);

/**
 * Processes associated data for authentication.
 * Must be done before encryption/decryption.
 */
enum vial_aes_error vial_aes_eax_auth_update(struct vial_aes_eax *self, const uint8_t *src, size_t len);

/**
 * Processes final associated data for authentication.
 * Must be done before encryption/decryption.
 */
enum vial_aes_error vial_aes_eax_auth_final(struct vial_aes_eax *self, const uint8_t *src, size_t len);

/**
 * Encrypts (part of) a message in EAX mode
 */
enum vial_aes_error vial_aes_eax_encrypt(struct vial_aes_eax *self, uint8_t *dst, const uint8_t *src, size_t len);

/**
 * Decrypts (part of) a message in EAX mode
 */
enum vial_aes_error vial_aes_eax_decrypt(struct vial_aes_eax *self, uint8_t *dst, const uint8_t *src, size_t len);

/**
 * Computes the authentication tag for the processed message
 */
enum vial_aes_error vial_aes_eax_get_tag(struct vial_aes_eax *self, uint8_t *tag);

/**
 * Verifies the authentication tag for the processed message
 */
enum vial_aes_error vial_aes_eax_check_tag(struct vial_aes_eax *self, const uint8_t *tag);

/**
 * Context for Galois/Counter Mode (GCM)
 */
struct vial_aes_gcm {
	struct vial_aes_base base;
	struct vial_aes_ctr ctr;
	struct vial_aes_block auth, hash_key, hash_acc;
	uint64_t a_len, c_len;
	unsigned buf_len;
};

/**
 * Initialises the GCM context
 */
enum vial_aes_error vial_aes_gcm_init(struct vial_aes_gcm *self);

/**
 * Initialises the GCM context with a key
 */
enum vial_aes_error vial_aes_gcm_init_key(struct vial_aes_gcm *self, const struct vial_aes_key *key);

/**
 * Resets the GCM context with a unique 12 byte nonce
 */
enum vial_aes_error vial_aes_gcm_reset(struct vial_aes_gcm *self, const uint8_t *nonce, size_t len);

/**
 * Processes associated data for authentication.
 * Must be done before encryption/decryption.
 */
enum vial_aes_error vial_aes_gcm_auth_update(struct vial_aes_gcm *self, const uint8_t *src, size_t len);

/**
 * Processes final associated data for authentication.
 * Must be done before encryption/decryption.
 */
enum vial_aes_error vial_aes_gcm_auth_final(struct vial_aes_gcm *self, const uint8_t *src, size_t len);

/**
 * Encrypts (part of) a message in GCM
 */
enum vial_aes_error vial_aes_gcm_encrypt(struct vial_aes_gcm *self, uint8_t *dst, const uint8_t *src, size_t len);

/**
 * Encrypts (part of) a message in GCM
 */
enum vial_aes_error vial_aes_gcm_decrypt(struct vial_aes_gcm *self, uint8_t *dst, const uint8_t *src, size_t len);

/**
 * Computes the authentication tag for the processed message
 */
enum vial_aes_error vial_aes_gcm_get_tag(struct vial_aes_gcm *self, uint8_t *tag);

/**
 * Verifies the authentication tag for the processed message
 */
enum vial_aes_error vial_aes_gcm_check_tag(struct vial_aes_gcm *self, const uint8_t *tag);

/**
 * Stores the state/context for performing AES encryption/decryption
 */
union vial_aes {
	struct vial_aes_base base;
	struct vial_aes_ecb ecb;
	struct vial_aes_cbc cbc;
	struct vial_aes_ctr ctr;
	struct vial_aes_eax eax;
	struct vial_aes_gcm gcm;
};

/**
 * Initialises a generic AES context according to the given mode
 */
static inline enum vial_aes_error vial_aes_init(union vial_aes *self, enum vial_aes_mode mode)
{
	switch (mode) {
	case VIAL_AES_MODE_ECB:
		return vial_aes_ecb_init(&self->ecb);
	case VIAL_AES_MODE_CBC:
		return vial_aes_cbc_init(&self->cbc);
	case VIAL_AES_MODE_CTR:
		return vial_aes_ctr_init(&self->ctr);
	case VIAL_AES_MODE_EAX:
		return vial_aes_eax_init(&self->eax);
	case VIAL_AES_MODE_GCM:
		return vial_aes_gcm_init(&self->gcm);
	default:
		return VIAL_AES_ERROR_CIPHER;
	}
}

/**
 * Initialises the AES context with a key
 */
static inline enum vial_aes_error vial_aes_init_key(union vial_aes *self, const struct vial_aes_key *key)
{
	return self->base.vtable->init_key(&self->base, key);
}

/**
 * Resets the AES context with an initialisation vector (IV).
 * The properties of the IV depend on the chosen mode.
 */
static inline enum vial_aes_error vial_aes_reset(union vial_aes *self, const uint8_t *iv, size_t len)
{
	return self->base.vtable->reset(&self->base, iv, len);
}

/**
 * Processes associated data for authentication.
 * Must be done before encryption/decryption.
 */
static inline enum vial_aes_error vial_aes_auth_update(union vial_aes *self, const uint8_t *src, size_t len)
{
	return self->base.vtable->auth_update(&self->base, src, len);
}

/**
 * Processes final associated data for authentication.
 * Must be done before encryption/decryption.
 */
static inline enum vial_aes_error vial_aes_auth_final(union vial_aes *self, const uint8_t *src, size_t len)
{
	return self->base.vtable->auth_final(&self->base, src, len);
}

/**
 * Encrypts (part of) a message
 */
static inline enum vial_aes_error vial_aes_encrypt(union vial_aes *self, uint8_t *dst, const uint8_t *src, size_t len)
{
	return self->base.vtable->encrypt(&self->base, dst, src, len);
}

/**
 * Decrypts (part of) a message
 */
static inline enum vial_aes_error vial_aes_decrypt(union vial_aes *self, uint8_t *dst, const uint8_t *src, size_t len)
{
	return self->base.vtable->decrypt(&self->base, dst, src, len);
}

/**
 * Computes the authentication tag for the processed message
 */
static inline enum vial_aes_error vial_aes_get_tag(union vial_aes *self, uint8_t *tag)
{
	return self->base.vtable->get_tag(&self->base, tag);
}

/**
 * Verifies the authentication tag for the processed message
 */
static inline enum vial_aes_error vial_aes_check_tag(union vial_aes *self, const uint8_t *tag)
{
	return self->base.vtable->check_tag(&self->base, tag);
}

#ifdef __cplusplus
}
#endif

#endif
