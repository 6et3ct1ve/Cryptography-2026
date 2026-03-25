#ifndef CRYPTO_RC4_H
#define CRYPTO_RC4_H

#include "core.h"
#include <stddef.h>

/**
 * @brief Encrypt/decrypt data using RC4 stream cipher
 * 
 * RC4 with 8-byte state array and 2-byte key.
 * All calculations performed mod 8.
 * Operation is symmetric: same function for encryption and decryption.
 * 
 * KSA: S = {0..7}, j = (j + S[i] + K[i mod 2]) mod 8, swap(S[i], S[j])
 * PRGA: i = (i+1) mod 8, j = (j+S[i]) mod 8, swap, output S[(S[i]+S[j]) mod 8]
 * 
 * @param input Input data to encrypt/decrypt
 * @param len Length of input data in bytes
 * @param key 2-byte key array
 * @param output Output pointer for result (caller must free)
 * @return CRYPTO_SUCCESS on success, error code otherwise
 */
enum crypto_status rc4_crypt(
    const unsigned char* input,
    size_t len,
    const unsigned char key[2],
    unsigned char** output
);

#endif