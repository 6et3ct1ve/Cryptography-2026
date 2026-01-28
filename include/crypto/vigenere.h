#ifndef CRYPTO_VIGENERE_H
#define CRYPTO_VIGENERE_H

#include "core.h"

/**
 * @brief Encrypt plaintext using Vigenere cipher
 * 
 * Formula: C[i] = (M[i] + K[i mod L]) mod 26
 * where L is key length, key repeats cyclically.
 * 
 * @param plaintext Input text to encrypt
 * @param key Keyword (only letters, case insensitive)
 * @param ciphertext Output pointer for encrypted text (caller must free)
 * @return CRYPTO_SUCCESS on success, error code otherwise
 */
enum crypto_status encrypt_vigenere(const char* plaintext, const char* key, char** ciphertext);

/**
 * @brief Decrypt ciphertext using Vigenere cipher
 * 
 * Formula: M[i] = (C[i] - K[i mod L] + 26) mod 26
 * 
 * @param ciphertext Input text to decrypt
 * @param key Keyword used for encryption
 * @param plaintext Output pointer for decrypted text (caller must free)
 * @return CRYPTO_SUCCESS on success, error code otherwise
 */
enum crypto_status decrypt_vigenere(const char* ciphertext, const char* key, char** plaintext);

#endif