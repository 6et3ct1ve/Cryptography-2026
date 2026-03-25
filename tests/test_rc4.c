#include <check.h>
#include <stdlib.h>
#include "crypto/rc4.h"
#include "crypto/core.h"

/**
 * @brief Test known values
 * K = {6, 2}, expected output: t1=0, t2=3, t3=6, t4=3
 */
START_TEST(test_known_values)
{
    unsigned char input[] = {0x00, 0x00, 0x00, 0x00};
    unsigned char key[] = {6, 2};
    unsigned char* result = NULL;

    enum crypto_status status = rc4_crypt(input, 4, key, &result);

    ck_assert_int_eq(status, CRYPTO_SUCCESS);
    ck_assert_ptr_nonnull(result);
    ck_assert_int_eq(result[0], 0); /* t1 = 0 */
    ck_assert_int_eq(result[1], 3); /* t2 = 3 */
    ck_assert_int_eq(result[2], 6); /* t3 = 6 */
    ck_assert_int_eq(result[3], 3); /* t4 = 3 */

    free(result);
}
END_TEST

/**
 * @brief Test symmetry: encrypt(encrypt(x)) == x
 */
START_TEST(test_symmetry)
{
    unsigned char input[] = {0x41, 0x42, 0x43};
    unsigned char key[] = {6, 2};
    unsigned char* first  = NULL;
    unsigned char* second = NULL;

    rc4_crypt(input, 3, key, &first);
    rc4_crypt(first, 3, key, &second);

    ck_assert_int_eq(second[0], input[0]);
    ck_assert_int_eq(second[1], input[1]);
    ck_assert_int_eq(second[2], input[2]);

    free(first);
    free(second);
}
END_TEST

/**
 * @brief Test NULL pointer handling
 */
START_TEST(test_null_input)
{
    unsigned char input[] = {0x01};
    unsigned char key[] = {6, 2};
    unsigned char* result = NULL;

    ck_assert_int_eq(rc4_crypt(NULL, 1, key, &result), CRYPTO_ERROR_NULL_POINTER);
    ck_assert_int_eq(rc4_crypt(input, 1, NULL, &result), CRYPTO_ERROR_NULL_POINTER);
    ck_assert_int_eq(rc4_crypt(input, 1, key, NULL), CRYPTO_ERROR_NULL_POINTER);
}
END_TEST

/**
 * @brief Test single byte
 */
START_TEST(test_single_byte)
{
    unsigned char input[] = {0x00};
    unsigned char key[] = {6, 2};
    unsigned char* result = NULL;

    enum crypto_status status = rc4_crypt(input, 1, key, &result);

    ck_assert_int_eq(status, CRYPTO_SUCCESS);
    ck_assert_ptr_nonnull(result);
    ck_assert_int_eq(result[0], 0); /* t1 = S[0] = 0 */

    free(result);
}
END_TEST

/**
 * @brief Test encrypt/decrypt roundtrip
 */
START_TEST(test_roundtrip)
{
    unsigned char input[] = {0x48, 0x65, 0x6C, 0x6C, 0x6F};
    unsigned char key[] = {6, 2};
    unsigned char* encrypted = NULL;
    unsigned char* decrypted = NULL;

    rc4_crypt(input, 5, key, &encrypted);
    rc4_crypt(encrypted, 5, key, &decrypted);

    for (size_t i = 0; i < 5; i++)
        ck_assert_int_eq(decrypted[i], input[i]);

    free(encrypted);
    free(decrypted);
}
END_TEST

/**
 * @brief Create test suite
 */
Suite* rc4_suite(void)
{
    Suite* s;
    TCase* tc_core;

    s = suite_create("RC4 Cipher");
    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_known_values);
    tcase_add_test(tc_core, test_symmetry);
    tcase_add_test(tc_core, test_null_input);
    tcase_add_test(tc_core, test_single_byte);
    tcase_add_test(tc_core, test_roundtrip);

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

    s = rc4_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}