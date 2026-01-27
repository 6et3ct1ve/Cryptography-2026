/**
 * @file test_trithemius.c
 * @brief Unit tests for Trithemius cipher implementation
 * 
 * Tests progressive encryption, decryption, edge cases, and error handling
 * using the Check framework.
 */

#include <check.h>
#include <stdlib.h>
#include "crypto/trithemius.h"
#include "crypto/core.h"

/**
 * @brief Test basic encryption with progressive shift
 */
START_TEST(test_encrypt_basic) 
{
    char* result = NULL;
    enum crypto_status status;
    
    status = encrypt_trithemius("ABC", 1, &result);
    
    ck_assert_int_eq(status, CRYPTO_SUCCESS);
    ck_assert_ptr_nonnull(result);
    ck_assert_str_eq(result, "BDF");
    
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
    
    status = decrypt_trithemius("BDF", 1, &result);
    
    ck_assert_int_eq(status, CRYPTO_SUCCESS);
    ck_assert_ptr_nonnull(result);
    ck_assert_str_eq(result, "ABC");
    
    free(result);
} 
END_TEST

/**
 * @brief Test progressive shift starting from 0
 */
START_TEST(test_progressive_shift) 
{
    char* result = NULL;
    enum crypto_status status;
    
    status = encrypt_trithemius("AAA", 0, &result);
    
    ck_assert_int_eq(status, CRYPTO_SUCCESS);
    ck_assert_ptr_nonnull(result);
    ck_assert_str_eq(result, "ABC");
    
    free(result);
} 
END_TEST

/**
 * @brief Test that spaces don't affect letter position counter
 */
START_TEST(test_with_spaces) 
{
    char* result = NULL;
    enum crypto_status status;
    
    status = encrypt_trithemius("A B C", 1, &result);
    
    ck_assert_int_eq(status, CRYPTO_SUCCESS);
    ck_assert_ptr_nonnull(result);
    ck_assert_str_eq(result, "B D F");
    
    free(result);
} 
END_TEST

/**
 * @brief Test wraparound (Z->A)
 */
START_TEST(test_wraparound) 
{
    char* result = NULL;
    enum crypto_status status;
    
    status = encrypt_trithemius("XYZ", 3, &result);
    
    ck_assert_int_eq(status, CRYPTO_SUCCESS);
    ck_assert_ptr_nonnull(result);
    ck_assert_str_eq(result, "ACE");
    
    free(result);
} 
END_TEST

/**
 * @brief Test negative key
 */
START_TEST(test_negative_key) 
{
    char* result = NULL;
    enum crypto_status status;
    
    status = encrypt_trithemius("BDF", -1, &result);
    
    ck_assert_int_eq(status, CRYPTO_SUCCESS);
    ck_assert_ptr_nonnull(result);
    ck_assert_str_eq(result, "ADG");
    
    free(result);
} 
END_TEST

/**
 * @brief Test NULL input handling
 */
START_TEST(test_null_input) 
{
    char* result = NULL;
    enum crypto_status status;
    
    status = encrypt_trithemius(NULL, 1, &result);
    ck_assert_int_eq(status, CRYPTO_ERROR_NULL_POINTER);
    
    status = encrypt_trithemius("ABC", 1, NULL);
    ck_assert_int_eq(status, CRYPTO_ERROR_NULL_POINTER);
} 
END_TEST

/**
 * @brief Test uppercase/lowercase preservation
 */
START_TEST(test_case_preservation) 
{
    char* result = NULL;
    enum crypto_status status;
    
    status = encrypt_trithemius("AbC", 1, &result);
    
    ck_assert_int_eq(status, CRYPTO_SUCCESS);
    ck_assert_ptr_nonnull(result);
    ck_assert_str_eq(result, "BdF");
    
    free(result);
} 
END_TEST

/**
 * @brief Create test suite
 */
Suite* trithemius_suite(void) 
{
    Suite* s;
    TCase* tc_core;
    
    s = suite_create("Trithemius Cipher");
    tc_core = tcase_create("Core");
    
    tcase_add_test(tc_core, test_encrypt_basic);
    tcase_add_test(tc_core, test_decrypt_basic);
    tcase_add_test(tc_core, test_progressive_shift);
    tcase_add_test(tc_core, test_with_spaces);
    tcase_add_test(tc_core, test_wraparound);
    tcase_add_test(tc_core, test_negative_key);
    tcase_add_test(tc_core, test_null_input);
    tcase_add_test(tc_core, test_case_preservation);
    
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
    
    s = trithemius_suite();
    sr = srunner_create(s);
    
    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}