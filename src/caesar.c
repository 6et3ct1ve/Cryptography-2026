#include "crypto/caesar.h"
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

enum crypto_status encrypt_caesar(const char* plaintext, int key, char** ciphertext)
{
    if (!plaintext || !ciphertext)
        return CRYPTO_ERROR_NULL_POINTER;
    
    size_t len = strlen(plaintext);
    
    char* result = (char*)malloc(len + 1);
    if (!result)
        return CRYPTO_ERROR_MEMORY;
    

    for (size_t i = 0; i < len; i++)
    {
        if (is_letter(plaintext[i]))
            result[i] = shift_char(plaintext[i], key);
        else  
            result[i] = plaintext[i];
    }
    
    result[len] = '\0';
    
    *ciphertext = result;
    
    return CRYPTO_SUCCESS;
}

enum crypto_status decrypt_caesar(const char* ciphertext, int key, char** plaintext)
{
    return encrypt_caesar(ciphertext, -key, plaintext);
}