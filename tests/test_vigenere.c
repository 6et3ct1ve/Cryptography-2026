#include <check.h>
#include <stdlib.h>
#include "crypto/vigenere.h"
#include "crypto/core.h"

/**
 * @brief Test basic encryption
 */
START_TEST(test_encrypt_basic)
{
    char* result = NULL;
    enum crypto_status status;
    
    status = encrypt_vigenere("HELLO", "KEY", &result);
    
    ck_assert_int_eq(status, CRYPTO_SUCCESS);
    ck_assert_ptr_nonnull(result);
    ck_assert_str_eq(result, "RIJVS");
    
    free(result);
} 
END_TEST

/**
 * @brief Test basic decryption
 */
START_TEST(test_decrypt_basic)
{
    char* result = NULL;
    enum crypto_status status;
    
    status = decrypt_vigenere("RIJVS", "KEY", &result);
    
    ck_assert_int_eq(status, CRYPTO_SUCCESS);
    ck_assert_ptr_nonnull(result);
    ck_assert_str_eq(result, "HELLO");
    
    free(result);
} 
END_TEST

/**
 * @brief Test key repetition (key shorter than text)
 */
START_TEST(test_key_repetition)
{
    char* result = NULL;
    enum crypto_status status;
    
    // "AAA" + "BC" → "BCB" (B, C, B repeats)
    status = encrypt_vigenere("AAA", "BC", &result);
    
    ck_assert_int_eq(status, CRYPTO_SUCCESS);
    ck_assert_ptr_nonnull(result);
    ck_assert_str_eq(result, "BCB");
    
    free(result);
} 
END_TEST


/**
 * @brief Test case preservation
 */
START_TEST(test_case_preservation)
{
    char* result = NULL;
    enum crypto_status status;
    
    status = encrypt_vigenere("HeLLo", "KEY", &result);
    
    ck_assert_int_eq(status, CRYPTO_SUCCESS);
    ck_assert_ptr_nonnull(result);
    ck_assert_str_eq(result, "RiJVs");
    
    free(result);
} 
END_TEST

/**
 * @brief Test non-letters (don't affect key position)
 */

START_TEST(test_non_letters)
{
    char* result = NULL;
    enum crypto_status status;
    
    status = encrypt_vigenere("A B C", "KEY", &result);
    
    ck_assert_int_eq(status, CRYPTO_SUCCESS);
    ck_assert_ptr_nonnull(result);
    ck_assert_str_eq(result, "K F A");
    
    free(result);
} 
END_TEST

/**
 * @brief Test invalid key with digits
 */
START_TEST(test_invalid_key_digits)
{
    char* result = NULL;
    enum crypto_status status;
    
    status = encrypt_vigenere("HELLO", "KEY123", &result);
    
    ck_assert_int_eq(status, CRYPTO_ERROR_INVALID_KEY);
} 
END_TEST

/**
 * @brief Test empty key
 */
START_TEST(test_empty_key)
{
    char* result = NULL;
    enum crypto_status status;
    
    status = encrypt_vigenere("HELLO", "", &result);
    
    ck_assert_int_eq(status, CRYPTO_ERROR_INVALID_KEY);
} 
END_TEST

/**
 * @brief Test NULL input handling
 */
START_TEST(test_null_input)
{
    char* result = NULL;
    enum crypto_status status;
    
    status = encrypt_vigenere(NULL, "KEY", &result);
    ck_assert_int_eq(status, CRYPTO_ERROR_NULL_POINTER);
    
    status = encrypt_vigenere("HELLO", NULL, &result);
    ck_assert_int_eq(status, CRYPTO_ERROR_NULL_POINTER);
    
    status = encrypt_vigenere("HELLO", "KEY", NULL);
    ck_assert_int_eq(status, CRYPTO_ERROR_NULL_POINTER);
} 
END_TEST

/**
 * @brief Test single letter key (behaves like Caesar)
 */
START_TEST(test_single_letter_key)
{
    char* result = NULL;
    enum crypto_status status;
    

    status = encrypt_vigenere("ABC", "D", &result);
    
    ck_assert_int_eq(status, CRYPTO_SUCCESS);
    ck_assert_ptr_nonnull(result);
    ck_assert_str_eq(result, "DEF");
    
    free(result);
} 
END_TEST

/**
 * @brief Create test suite
 */
Suite* vigenere_suite(void)
{
    Suite* s;
    TCase* tc_core;
    
    s = suite_create("Vigenere Cipher");
    tc_core = tcase_create("Core");
    
    tcase_add_test(tc_core, test_encrypt_basic);
    tcase_add_test(tc_core, test_decrypt_basic);
    tcase_add_test(tc_core, test_key_repetition);
    tcase_add_test(tc_core, test_case_preservation);
    tcase_add_test(tc_core, test_non_letters);
    tcase_add_test(tc_core, test_invalid_key_digits);
    tcase_add_test(tc_core, test_empty_key);
    tcase_add_test(tc_core, test_null_input);
    tcase_add_test(tc_core, test_single_letter_key);
    
    suite_add_tcase(s, tc_core);
    
    return s;
}

/**
 * @brief Main test runner
 */
int main(void)
{
    int number_failed;
    Suite* s;
    SRunner* sr;
    
    s = vigenere_suite();
    sr = srunner_create(s);
    
    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}