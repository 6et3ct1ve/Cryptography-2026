/**
 * @file gamma.h
 * @brief Gamma cipher with block transposition
 * 
 * Combines bit-level transposition with XOR encryption.
 * Text converted to bit matrix, rows encrypted separately, then reconstructed.
 */

#ifndef CRYPTO_GAMMA_H
#define CRYPTO_GAMMA_H

#include "core.h"
#include <stddef.h>
#include <stdint.h>

/**
 * @brief Encrypt using gamma cipher with transposition
 * 
 * Process:
 * 1. Convert bytes to bit matrix (columns = bytes, rows = bits)
 * 2. XOR each row with PRNG-generated gamma
 * 3. Reconstruct bytes from encrypted bit matrix
 * 
 * @param plaintext Input bytes
 * @param plaintext_len Data length
 * @param seed PRNG seed
 * @param ciphertext Output buffer
 * @return Status code
 */
enum crypto_status encrypt_gamma(
    const unsigned char* plaintext,
    size_t plaintext_len,
    uint32_t seed,
    unsigned char** ciphertext
);

/**
 * @brief Decrypt using gamma cipher
 * 
 * Same process as encryption.
 * 
 * @param ciphertext Input bytes
 * @param ciphertext_len Data length
 * @param seed PRNG seed (same as encryption)
 * @param plaintext Output buffer
 * @return Status code
 */
enum crypto_status decrypt_gamma(
    const unsigned char* ciphertext,
    size_t ciphertext_len,
    uint32_t seed,
    unsigned char** plaintext
);

#endif