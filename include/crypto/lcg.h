#ifndef CRYPTO_LCG_H
#define CRYPTO_LCG_H

#include "core.h"
#include <stddef.h>
#include <stdint.h>

/**
 * @brief Encrypt/decrypt data using Linear Congruential Generator stream cipher
 * 
 * Generates keystream using LCG: x[i+1] = (a * xi + d) mod m
 * Each generated value is used as a key byte via XOR with input.
 * Operation is symmetric: same function for encryption and decryption.
 * 
 * @param input Input data to encrypt/decrypt
 * @param len Length of input data in bytes
 * @param x0 Initial seed value
 * @param a Multiplier
 * @param d Increment
 * @param m Modulus
 * @param output Output pointer for result (caller must free)
 * @return CRYPTO_SUCCESS on success, error code otherwise
 */
enum crypto_status lcg_crypt(
    const unsigned char* input,
    size_t len,
    uint64_t x0,
    uint64_t a,
    uint64_t d,
    uint64_t m,
    unsigned char** output
);

#endif