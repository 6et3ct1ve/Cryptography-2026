#include "crypto/trithemius.h"
#include <stdlib.h>
#include <string.h>

/**
 * @brief Checks if character is a letter (A-Z, a-z).
 * 
 * Uses bitwise trick for fast validation:
 * - (c | 32) converts to lowercase (sets 6th bit)
 * - Subtract 'a' to get position in alphabet (0-25)
 * - Cast to unsigned to handle non-letters (become > 25)
 * 
 * @param c Character to check
 * @return 1 if letter (A-Z or a-z), 0 otherwise
 */
static int is_letter(char c) 
{
    return ((unsigned char)((c | 32) - 'a')) < 26;
}

/**
 * @brief Shifts a single character by key positions with wraparound.
 * 
 * Formula: C = (M + K) mod n, where n=26 for English alphabet.
 * Uses bitwise operations for fast case detection:
 * - 6th bit (32) distinguishes uppercase (0) from lowercase (1)
 * 
 * @param c Character to shift (must be a letter A-Z or a-z)
 * @param key Shift amount (any integer)
 * @return Shifted character with same case
 */
static char shift_char(char c, int key) 
{
    key = ((key % 26) + 26) % 26;
    char base = 'A' + (c & 32);
    return (c - base + key) % 26 + base;
}

/**
 * @brief Encrypt plaintext using Trithemius cipher.
 * 
 * Formula: C[i] = (M[i] + K + i) mod 26
 * where i is the letter position in text (0-indexed, non-letters don't count).
 * 
 * @param plaintext Input text to encrypt
 * @param key Initial shift amount (any integer)
 * @param ciphertext Output pointer for encrypted text (caller must free)
 * @return CRYPTO_SUCCESS on success, error code otherwise
 */
enum crypto_status encrypt_trithemius(const char* plaintext, int key, char** ciphertext) 
{
    if (!plaintext || !ciphertext) 
        return CRYPTO_ERROR_NULL_POINTER;
    
    size_t len = strlen(plaintext);
    char* result = (char*)malloc(len + 1);
    if (!result) 
        return CRYPTO_ERROR_MEMORY;
    
    size_t letter_pos = 0;
    
    for (size_t i = 0; i < len; i++) 
    {
        if (is_letter(plaintext[i])) 
        {
            result[i] = shift_char(plaintext[i], key + letter_pos);
            letter_pos++;
        }
        else
            result[i] = plaintext[i];
    }
    
    result[len] = '\0';
    *ciphertext = result;
    return CRYPTO_SUCCESS;
}

/**
 * @brief Decrypt ciphertext using Trithemius cipher.
 * 
 * Formula: M[i] = (C[i] - K - i) mod 26
 * where i is the letter position in text (0-indexed, non-letters don't count).
 * 
 * @param ciphertext Input text to decrypt
 * @param key Initial shift amount used for encryption
 * @param plaintext Output pointer for decrypted text (caller must free)
 * @return CRYPTO_SUCCESS on success, error code otherwise
 */
enum crypto_status decrypt_trithemius(const char* ciphertext, int key, char** plaintext) 
{
    if (!ciphertext || !plaintext) 
        return CRYPTO_ERROR_NULL_POINTER;
    
    size_t len = strlen(ciphertext);
    char* result = (char*)malloc(len + 1);
    if (!result) 
        return CRYPTO_ERROR_MEMORY;
    
    size_t letter_pos = 0;
    
    for (size_t i = 0; i < len; i++) 
    {
        if (is_letter(ciphertext[i])) 
        {
            result[i] = shift_char(ciphertext[i], -(key + letter_pos));
            letter_pos++;
        }
        else
            result[i] = ciphertext[i];
    }
    
    result[len] = '\0';
    *plaintext = result;
    return CRYPTO_SUCCESS;
}