#ifndef CRYPTO_CAESAR_H
#define CRYPTO_CAESAR_H

#include "core.h"

/**
 * @file caesar.h
 * @brief Caesar cipher implementation.
 *
 * Classic substitution cipher with fixed alphabet shift.
 * Formula: Ciphertext = (Plaintext + Key) mod Alphabet
 * Only alphabetic characters (A-Z, a-z) are encrypted.
 */

/**
 * @brief Encrypts plaintext using Caesar cipher.
 *
 * Shifts each alphabetic character by the specified key value.
 * Non-alphabetic characters remain unchanged.
 *
 * @param plaintext Input string to encrypt. Must not be NULL.
 * @param key Shift value 0-25 for standard alphabet.
 * @param ciphertext Pointer to output buffer.
 * @return CRYPTO_SUCCESS on success, error code otherwise.
 */
enum crypto_status encrypt_caesar(const char* plaintext, int key, char** ciphertext);

/**
 * @brief Decrypts ciphertext using Caesar cipher.
 *
 * Reverses the encryption by shifting in opposite direction.
 * Non-alphabetic characters remain unchanged.
 *
 * @param ciphertext Input string to decrypt. Must not be NULL.
 * @param key Shift value used during encryption.
 * @param plaintext Pointer to output buffer.
 * @return CRYPTO_SUCCESS on success, error code otherwise.
 */
enum crypto_status decrypt_caesar(const char* ciphertext, int key, char** plaintext);

#endif