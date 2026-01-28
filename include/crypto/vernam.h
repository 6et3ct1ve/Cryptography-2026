/**
 * @file vernam.h
 * @brief Vernam cipher (One-Time Pad) - XOR encryption
 * 
 * Theoretically unbreakable cipher using XOR operation.
 * Key must be truly random, same length as data, and used only once.
 */

#ifndef CRYPTO_VERNAM_H
#define CRYPTO_VERNAM_H

#include "core.h"
#include <stddef.h>

/**
 * @brief Encrypt using Vernam cipher
 * 
 * Formula: S[i] = C[i] ⊕ K[i]
 * Key length must equal or exceed data length.
 * 
 * @param data Input bytes
 * @param data_len Data length
 * @param key Random key bytes
 * @param key_len Key length (must be >= data_len)
 * @param result Output
 * @return Status code
 */
enum crypto_status encrypt_vernam(
    const unsigned char* data, 
    size_t data_len,
    const unsigned char* key, 
    size_t key_len,
    unsigned char** result
);

/**
 * @brief Decrypt using Vernam cipher
 * 
 * Formula: C[i] = S[i] ⊕ K[i]
 * 
 * @param data Input bytes
 * @param data_len Data length
 * @param key Key bytes
 * @param key_len Key length
 * @param result Output
 * @return Status code
 */
enum crypto_status decrypt_vernam(
    const unsigned char* data, 
    size_t data_len,
    const unsigned char* key, 
    size_t key_len,
    unsigned char** result
);

#endif