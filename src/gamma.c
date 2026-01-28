#include "crypto/gamma.h"
#include <stdlib.h>
#include <string.h>

/**
 * @brief Xorshift32 PRNG
 */
static uint32_t prng_state;

static void prng_init(uint32_t seed)
{
    prng_state = seed ? seed : 2463534242U;
}

static uint8_t prng_next_bit(void)
{
    prng_state ^= prng_state << 13;
    prng_state ^= prng_state >> 17;
    prng_state ^= prng_state << 5;
    return prng_state & 1;
}

/**
 * @brief Convert bytes to bit matrix
 * 
 * @param data Input bytes
 * @param len Number of bytes
 * @param matrix Output bit matrix
 */
static void bytes_to_matrix(const unsigned char* data, size_t len, uint8_t matrix[8][len])
{
    for (size_t byte_idx = 0; byte_idx < len; byte_idx++)
    {
        unsigned char byte = data[byte_idx];
        
        for (size_t bit_idx = 0; bit_idx < 8; bit_idx++)
            matrix[bit_idx][byte_idx] = (byte >> bit_idx) & 1;
    }
}

/**
 * @brief Convert bit matrix back to bytes
 * 
 * @param matrix Input bit matrix
 * @param len Number of bytes
 * @param data Output bytes
 */
static void matrix_to_bytes(size_t len, uint8_t matrix[8][len], unsigned char* data)
{
    for (size_t byte_idx = 0; byte_idx < len; byte_idx++)
    {
        unsigned char byte = 0;
        
        for (size_t bit_idx = 0; bit_idx < 8; bit_idx++)
        {
            if (matrix[bit_idx][byte_idx])
                byte |= (1 << bit_idx);
        }
        
        data[byte_idx] = byte;
    }
}

/**
 * @brief Encrypt using gamma cipher
 */
enum crypto_status encrypt_gamma(
    const unsigned char* plaintext,
    size_t plaintext_len,
    uint32_t seed,
    unsigned char** ciphertext
)
{
    if (!plaintext || !ciphertext)
        return CRYPTO_ERROR_NULL_POINTER;
    
    if (plaintext_len == 0)
        return CRYPTO_ERROR_INVALID_INPUT;
    
    unsigned char* result = (unsigned char*)malloc(plaintext_len);
    if (!result)
        return CRYPTO_ERROR_MEMORY;
    
    uint8_t matrix[8][plaintext_len];
    
    bytes_to_matrix(plaintext, plaintext_len, matrix);
    
    prng_init(seed);
    
    for (size_t row = 0; row < 8; row++)
    {
        for (size_t col = 0; col < plaintext_len; col++)
        {
            uint8_t gamma_bit = prng_next_bit();
            matrix[row][col] ^= gamma_bit;
        }
    }
    
    matrix_to_bytes(plaintext_len, matrix, result);
    
    *ciphertext = result;
    return CRYPTO_SUCCESS;
}

/**
 * @brief Decrypt using gamma cipher
 */
enum crypto_status decrypt_gamma(
    const unsigned char* ciphertext,
    size_t ciphertext_len,
    uint32_t seed,
    unsigned char** plaintext
)
{
    if (!ciphertext || !plaintext)
        return CRYPTO_ERROR_NULL_POINTER;
    
    if (ciphertext_len == 0)
        return CRYPTO_ERROR_INVALID_INPUT;
    
    unsigned char* result = (unsigned char*)malloc(ciphertext_len);
    if (!result)
        return CRYPTO_ERROR_MEMORY;
    
    uint8_t matrix[8][ciphertext_len];
    
    bytes_to_matrix(ciphertext, ciphertext_len, matrix);
    
    prng_init(seed);
    
    for (size_t row = 0; row < 8; row++)
    {
        for (size_t col = 0; col < ciphertext_len; col++)
        {
            uint8_t gamma_bit = prng_next_bit();
            matrix[row][col] ^= gamma_bit;
        }
    }
    
    matrix_to_bytes(ciphertext_len, matrix, result);
    
    *plaintext = result;
    return CRYPTO_SUCCESS;
}