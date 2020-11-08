`vial_aes`: An AES implementation in C with abstractions
========================================================

Implements encryption and decryption with ECB, CBC, CTR, and EAX modes of operation,
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
The other modes will need a separate authentication method, otherwise an attacker could trick you
to accept altered data.

Take a look at the [testing code](./test.c) for example code.

### Key exansion

Before you start encrypting or decrypting, the expansion of the AES key needs to be computed.
This is done with the `vial_aes_key_init()` function and the expansion is stored in `struct vial_aes_key`.

### Initialisation of AES context

For ECB, CBC, and CTR modes the function `vial_aes_init()` is used. You have to supply a pointer
to your expanded key, and a random 16 byte initialisation vector (IV).

For EAX you also need to provide a pointer to a `struct vial_aes_cmac`. The CMAC context will be
initialised internally.

### Encryption/ decryption

In ECB and CBC modes, the size of your data needs to be a multiple of the AES block size (16 bytes),
otherwise they will need to be padded with a scheme like PKCS#7. If you don't know what that means,
you should be using a mode like EAX.

### Authentication

The EAX mode can be used to authenticate the encrypted message, as well as some additional
plaintext data. If you need to authenticate such associated data, `vial_aes_auth_data()`
needs to be called before encryption/decryption.

After your message is processed, you must append the tag at the end of the encrypted message,
or when decrypting, check the received tag. The EAX tag is 16 bytes long (unless truncated).

For compliance with the EAX specification, you need to reinitialise with a new unique nonce.
You can produce a new one by simply incrementing your current one with the helper function
`vial_aes_increment_be()`.

Alternatively you can compute your own CMAC tags with the respective functions.
