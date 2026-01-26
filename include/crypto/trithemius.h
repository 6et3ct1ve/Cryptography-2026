#ifndef CRYPTO_TRITHEMIUS_H
#define CRYPTO_TRITHEMIUS_H

#include "core.h"

/**
 * @file trithemius.h
 * @brief Trithemius cipher implementation.
 *
 * Progressive key cipher where the shift increases with each character.
 * Formula: shift = key + position
 * Only alphabetic characters (A-Z, a-z) are encrypted.
 */

/**
 * @brief Encrypts plaintext using Trithemius cipher.
 *
 * Applies progressive shift: each character shifted by (key + position).
 * Non-alphabetic characters remain unchanged.
 *
 * @param plaintext Input string to encrypt.
 * @param key Initial shift value.
 * @param ciphertext Pointer to output buffer.
 * @return CRYPTO_SUCCESS on success, error code otherwise.
 */
enum crypto_status encrypt_trithemius(const char* plaintext, int key, char** ciphertext);

/**
 * @brief Decrypts ciphertext using Trithemius cipher.
 *
 * Reverses progressive shift encryption.
 * Non-alphabetic characters remain unchanged.
 *
 * @param ciphertext Input string to decrypt.
 * @param key Initial shift value used during encryption.
 * @param plaintext Pointer to output buffer.
 * @return CRYPTO_SUCCESS on success, error code otherwise.
 */
enum crypto_status decrypt_trithemius(const char* ciphertext, int key, char** plaintext);

#endif