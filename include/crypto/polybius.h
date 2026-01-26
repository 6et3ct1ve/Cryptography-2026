#ifndef CRYPTO_POLYBIUS_H
#define CRYPTO_POLYBIUS_H

#include "core.h"

/**
 * @file polybius.h
 * @brief Polybius square cipher implementation.
 *
 * Substitution cipher using a 5x5 grid (I/J combined).
 * Each letter is encoded as a pair of coordinates (row, column).
 * Only alphabetic characters are encrypted, output is numeric pairs.
 */

/**
 * @brief Encrypts plaintext using Polybius square.
 *
 * Converts each letter to coordinate pair (row, column).
 * Non-alphabetic characters are skipped.
 * Example: A -> 11, B -> 12, etc.
 *
 * @param plaintext Input string to encrypt. Must not be NULL.
 * @param key Optional key for square permutation (unused in basic version, pass 0).
 * @param ciphertext Pointer to output buffer.
 * @return CRYPTO_SUCCESS on success, error code otherwise.
 */
enum crypto_status encrypt_polybius(const char* plaintext, int key, char** ciphertext);

/**
 * @brief Decrypts ciphertext using Polybius square.
 *
 * Converts coordinate pairs back to letters.
 * Input must be valid numeric pairs.
 *
 * @param ciphertext Input string with coordinate pairs.
 * @param key Optional key used during encryption (pass 0 for basic version).
 * @param plaintext Pointer to output buffer.
 * @return CRYPTO_SUCCESS on success, error code otherwise.
 */
enum crypto_status decrypt_polybius(const char* ciphertext, int key, char** plaintext);

#endif