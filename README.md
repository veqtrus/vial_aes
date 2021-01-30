`vial_aes`: An AES implementation in C with abstractions
========================================================

Implements encryption and decryption with ECB, CBC, CTR, GCM, and EAX modes of operation,
as well as the CMAC (a.k.a. OMAC1) message authentication algorithm.

The implementation does not use large precomputed tables, making cache-timing attacks harder.
It is tested using the vectors provided in the algorithm specifications.

Compiling
---------

To use this library in your project, all you need are the files `aes.h` and `aes.c`.
You can compile the tests with `make` and run them with `make check`.

Usage
-----

**TL;DR: Use EAX with a unique nonce, as it provides both confidentiality and integrity protection.**
Alternatively you can use GCM which offers similar protection.
The other modes will need a separate authentication method,
otherwise an attacker could trick you to accept altered data.

Take a look at the [testing code](./test.c) for example code.

### Key expansion

Before you start encrypting or decrypting, the expansion of the AES key needs to be computed.
This is done with the `vial_aes_key_init()` function and the expansion is stored in `struct vial_aes_key`.

### Initialisation of AES context

The function `vial_aes_init()` is used. For ECB, CBC, and CTR modes you have to supply a pointer
to your expanded key, and a random 16 byte initialisation vector (IV).

For EAX you need to set the pointer to a `struct vial_aes_cmac` before calling `vial_aes_init()`.
The CMAC context will be initialised internally. The nonce can be of any length.

For GCM you need to set the pointer to a `struct vial_aes_ghash` before calling `vial_aes_init()`.
The GHASH context will be initialised internally. The nonce must be 12 bytes long.

While the nonce in EAX and GCM does not need to be random, it must never be reused with the same key.
One approach is to generate a random nonce at the start of the session and then increment it
for each new message using the helper function `vial_aes_increment_be()`.

The IV in CTR mode is incremented internally for each block. Therefore care must be taken to properly
generate a new one. For example you may choose to use 12 byte IVs and generate new ones by incrementing,
provided that each message does not exceed 2^32 blocks (64 GiB). The EAX mode deals with this internally.

### Encryption/ decryption

In ECB and CBC modes, the size of your data needs to be a multiple of the AES block size (16 bytes),
otherwise they will need to be padded with a scheme like PKCS#7. If you don't know what that means,
you should be using a mode like EAX.

### Authentication

The EAX and GCM modes can be used to authenticate the encrypted message,
as well as some additional plaintext data. If you need to authenticate such associated data,
`vial_aes_auth_data()` needs to be called before encryption/decryption.

After your message is processed, you must append the tag at the end of the encrypted message,
or when decrypting, check the received tag. The tag is 16 bytes long (unless truncated,
which is not recommended for GCM).

After each message you need to reinitialise the context with a new unique nonce.

Alternatively you can compute your own CMAC tags with the respective functions,
however if you encrypt in CBC mode a different key needs to be used for CMAC.
