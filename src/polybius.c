#include "crypto/polybius.h"
#include <stdlib.h>
#include <string.h>

/**
 * @brief Get Polybius coordinates for letter
 * 
 * @param letter Input letter (A-Z, case insensitive, J→I)
 * @param row Output: row coordinate (1-5)
 * @param col Output: column coordinate (1-5)
 * @return 1 if valid letter, 0 otherwise
 */
static int letter_to_coords(char letter, int* row, int* col) 
{
    if (((unsigned char)((letter | 32) - 'a')) >= 26)
        return 0;
    
    char upper = letter & ~32;
    int pos = upper - 'A';
    
    if (pos > 8)
        pos--;
    
    *row = pos / 5 + 1;
    *col = pos % 5 + 1;
    
    return 1;
}

/**
 * @brief Get letter from Polybius coordinates
 * 
 * @param row Row coordinate (1-5)
 * @param col Column coordinate (1-5)
 * @return Letter at position, or '\0' if invalid
 */
static char coords_to_letter(int row, int col) 
{
    unsigned int r = (unsigned int)(row - 1);
    unsigned int c = (unsigned int)(col - 1);
    
    if (r >= 5 || c >= 5)
        return '\0';
    
    int pos = r * 5 + c;
    
    if (pos > 8)
        pos++;
    
    return 'A' + pos;
}

/**
 * @brief Encrypt plaintext using Polybius square
 * 
 * Each letter becomes 2 digits (row, column).
 * Non-letters are ignored. Output is always digits.
 * 
 * @param plaintext Input text
 * @param ciphertext Output pointer (caller must free)
 * @return Status code
 */
enum crypto_status encrypt_polybius(const char* plaintext, char** ciphertext) 
{
    if (!plaintext || !ciphertext) 
        return CRYPTO_ERROR_NULL_POINTER;
    
    size_t letter_count = 0;
    for (size_t i = 0; plaintext[i]; i++) 
    {
        int row, col;
        if (letter_to_coords(plaintext[i], &row, &col))
            letter_count++;
    }
    
    size_t output_size = letter_count * 2 + 1;
    char* result = (char*)malloc(output_size);
    if (!result) 
        return CRYPTO_ERROR_MEMORY;
    
    size_t pos = 0;
    for (size_t i = 0; plaintext[i]; i++) 
    {
        int row, col;
        if (letter_to_coords(plaintext[i], &row, &col)) 
        {
            result[pos++] = '0' + row;
            result[pos++] = '0' + col;
        }
    }
    
    result[pos] = '\0';
    *ciphertext = result;
    return CRYPTO_SUCCESS;
}

/**
 * @brief Decrypt ciphertext using Polybius square
 * 
 * Pairs of digits become letters.
 * Input must have even length and contain only digits 1-5.
 * Output is always uppercase (case information lost).
 * 
 * @param ciphertext Input digits (pairs of 1-5)
 * @param plaintext Output pointer (caller must free)
 * @return Status code
 */
enum crypto_status decrypt_polybius(const char* ciphertext, char** plaintext) 
{
    if (!ciphertext || !plaintext) 
        return CRYPTO_ERROR_NULL_POINTER;
    
    size_t len = strlen(ciphertext);
    
    if (len % 2 != 0)
        return CRYPTO_ERROR_INVALID_INPUT;
    
    size_t output_size = len / 2 + 1;
    char* result = (char*)malloc(output_size);
    if (!result) 
        return CRYPTO_ERROR_MEMORY;
    
    size_t pos = 0;
    for (size_t i = 0; i < len; i += 2) 
    {
        if (ciphertext[i] < '1' || ciphertext[i] > '5' ||
            ciphertext[i+1] < '1' || ciphertext[i+1] > '5') 
        {
            free(result);
            return CRYPTO_ERROR_INVALID_INPUT;
        }
        
        int row = ciphertext[i] - '0';
        int col = ciphertext[i+1] - '0';
        
        char letter = coords_to_letter(row, col);
        if (letter == '\0') 
        {
            free(result);
            return CRYPTO_ERROR_INVALID_INPUT;
        }
        
        result[pos++] = letter;
    }
    
    result[pos] = '\0';
    *plaintext = result;
    return CRYPTO_SUCCESS;
}