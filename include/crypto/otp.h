#ifndef OTP_H
#define OTP_H

#include "core.h"
#include <stddef.h>

/**
 * @brief Encrypt/decrypt data using One-Time Pad (Vernam cipher)
 * 
 * Formula: output[i] = input[i] XOR key[i]
 * Operation is symmetric: same function for encryption and decryption.
 * Key must be at least as long as input.
 * 
 * @param input Input data to encrypt/decrypt
 * @param len Length of input data in bytes
 * @param key Key (gamma) bytes, must be >= len
 * @param key_len Length of key in bytes
 * @param output Output pointer for result (caller must free)
 * @return CRYPTO_SUCCESS on success, error code otherwise
 */
enum crypto_status otp_crypt(
    const unsigned char* input,
    size_t len,
    const unsigned char* key,
    size_t key_len,
    unsigned char** output
);

#endif