#include "crypto/vigenere.h"
#include <stdlib.h>
#include <string.h>

/**
 * @brief Check if character is a letter
 * 
 * @param c Character to check
 * @return 1 if letter, 0 otherwise
 */
static int is_letter(char c)
{
    return ((unsigned char)((c | 32) - 'a')) < 26;
}

/**
 * @brief Convert letter to shift value (A=0, Z=25)
 * 
 * @param c Letter from key (A-Z, a-z)
 * @return Shift value 0-25
 */
static int char_to_pos(char c)
{
    char upper = c & ~32;
    return upper - 'A';
}

/**
 * @brief Validate key (only letters allowed)
 * 
 * @param key Keyword to validate
 * @return 1 if valid, 0 if invalid
 */
static int is_valid_key(const char* key)
{
    if (!key || strlen(key) == 0)
        return 0;
    
    for (size_t i = 0; key[i]; i++)
    {
        if (!is_letter(key[i]))
            return 0;
    }
    
    return 1;
}

/**
 * @brief Encrypt plaintext using Vigenere cipher
 * 
 * Formula: C[i] = (M[i] + K[i mod L]) mod 26
 */
enum crypto_status encrypt_vigenere(const char* plaintext, const char* key, char** ciphertext)
{
    if (!plaintext || !key || !ciphertext)
        return CRYPTO_ERROR_NULL_POINTER;
    
    if (!is_valid_key(key))
        return CRYPTO_ERROR_INVALID_KEY;
    
    size_t len = strlen(plaintext);
    size_t key_len = strlen(key);
    
    char* result = (char*)malloc(len + 1);
    if (!result)
        return CRYPTO_ERROR_MEMORY;
    
    size_t key_pos = 0;
    
    
    for (size_t i = 0; i < len; i++)
    {
        if (is_letter(plaintext[i]))
        {
            int shift = char_to_pos(key[key_pos % key_len]);
            
            char base = 'A' + (plaintext[i] & 32);
            result[i] = (plaintext[i] - base + shift) % 26 + base;
            
            key_pos++;
        }
        else 
        {
            result[i] = plaintext[i];
        }
    }
    
    result[len] = '\0';
    *ciphertext = result;
    return CRYPTO_SUCCESS;
}


/**
 * @brief Decrypt ciphertext using Vigenere cipher
 * 
 * Formula: M[i] = (C[i] - K[i mod L] + 26) mod 26
 */
enum crypto_status decrypt_vigenere(const char* ciphertext, const char* key, char** plaintext)
{
    if (!ciphertext || !key || !plaintext)
        return CRYPTO_ERROR_NULL_POINTER;
    
    if (!is_valid_key(key))
        return CRYPTO_ERROR_INVALID_KEY;
    
    size_t len = strlen(ciphertext);
    size_t key_len = strlen(key);
    
    char* result = (char*)malloc(len + 1);
    if (!result)
        return CRYPTO_ERROR_MEMORY;
    
    size_t key_pos = 0;
    
    for (size_t i = 0; i < len; i++)
    {
        if (is_letter(ciphertext[i]))
        {
            int shift = char_to_pos(key[key_pos % key_len]);
            
            char base = 'A' + (ciphertext[i] & 32);
            result[i] = (ciphertext[i] - base - shift + 26) % 26 + base;
            
            key_pos++;
        }
        else 
        {
            result[i] = ciphertext[i];
        }
    }
    
    result[len] = '\0';
    *plaintext = result;
    return CRYPTO_SUCCESS;
}