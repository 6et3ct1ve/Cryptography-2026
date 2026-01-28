#include <cryptography.h>
#include <check.h>
#include <stdlib.h>

START_TEST(test_encrypt_basic)
{
    char* result = NULL;
    enum crypto_status status;
    
    status = encrypt_caesar("ABC", 3, &result);
    
    ck_assert_int_eq(status, CRYPTO_SUCCESS);
    ck_assert_ptr_nonnull(result);
    ck_assert_str_eq(result, "DEF");
    
    free(result);
} 
END_TEST

START_TEST(test_decrypt_basic)
{
    char* result = NULL;
    enum crypto_status status;
    
    status = decrypt_caesar("DEF", 3, &result);
    
    ck_assert_int_eq(status, CRYPTO_SUCCESS);
    ck_assert_ptr_nonnull(result);
    ck_assert_str_eq(result, "ABC");
    
    free(result);
} 
END_TEST

START_TEST(test_wraparound)
{
    char* result = NULL;
    enum crypto_status status;
    
    status = encrypt_caesar("XYZ", 3, &result);
    
    ck_assert_int_eq(status, CRYPTO_SUCCESS);
    ck_assert_ptr_nonnull(result);
    ck_assert_str_eq(result, "ABC");
    
    free(result);
} 
END_TEST

START_TEST(test_negative_key)
{
    char* result = NULL;
    enum crypto_status status;
    
    status = encrypt_caesar("ABC", -1, &result);
    
    ck_assert_int_eq(status, CRYPTO_SUCCESS);
    ck_assert_ptr_nonnull(result);
    ck_assert_str_eq(result, "ZAB");
    
    free(result);
} 
END_TEST

START_TEST(test_large_key)
{
    char* result = NULL;
    enum crypto_status status;
    
    status = encrypt_caesar("ABC", 29, &result);
    
    ck_assert_int_eq(status, CRYPTO_SUCCESS);
    ck_assert_ptr_nonnull(result);
    ck_assert_str_eq(result, "DEF");
    
    free(result);
} 
END_TEST

START_TEST(test_non_letters)
{
    char* result = NULL;
    enum crypto_status status;
    
    status = encrypt_caesar("Hello World! 123", 3, &result);
    
    ck_assert_int_eq(status, CRYPTO_SUCCESS);
    ck_assert_ptr_nonnull(result);
    ck_assert_str_eq(result, "Khoor Zruog! 123");
    
    free(result);
} 
END_TEST

START_TEST(test_null_input)
{
    char* result = NULL;
    enum crypto_status status;
    
    status = encrypt_caesar(NULL, 3, &result);
    ck_assert_int_eq(status, CRYPTO_ERROR_NULL_POINTER);
    
    status = encrypt_caesar("ABC", 3, NULL);
    ck_assert_int_eq(status, CRYPTO_ERROR_NULL_POINTER);
} 
END_TEST

START_TEST(test_case_preservation)
{
    char* result = NULL;
    enum crypto_status status;
    
    status = encrypt_caesar("AbCdEf", 1, &result);
    
    ck_assert_int_eq(status, CRYPTO_SUCCESS);
    ck_assert_ptr_nonnull(result);
    ck_assert_str_eq(result, "BcDeFg");
    
    free(result);
} 
END_TEST

Suite* caesar_suite(void)
{
    Suite* s;
    TCase* tc_core;
    
    s = suite_create("Caesar");
    tc_core = tcase_create("Core");
    
    tcase_add_test(tc_core, test_encrypt_basic);
    tcase_add_test(tc_core, test_decrypt_basic);
    tcase_add_test(tc_core, test_wraparound);
    tcase_add_test(tc_core, test_negative_key);
    tcase_add_test(tc_core, test_large_key);
    tcase_add_test(tc_core, test_non_letters);
    tcase_add_test(tc_core, test_null_input);
    tcase_add_test(tc_core, test_case_preservation);
    
    suite_add_tcase(s, tc_core);
    
    return s;
}

int main(void)
{
    int number_failed;
    Suite* s;
    SRunner* sr;
    
    s = caesar_suite();
    sr = srunner_create(s);
    
    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    
    return (number_failed == 0) ? 0 : 1;
}