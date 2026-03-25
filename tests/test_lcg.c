#include <check.h>
#include <stdlib.h>
#include "crypto/lcg.h"
#include "crypto/core.h"

/**
 * @brief Test basic encryption
 */
START_TEST(test_encrypt_basic)
{
    unsigned char input[] = {0x00, 0x00, 0x00};
    unsigned char* result = NULL;

    enum crypto_status status = lcg_crypt(input, 3, 3, 5, 3, 8, &result);

    ck_assert_int_eq(status, CRYPTO_SUCCESS);
    ck_assert_ptr_nonnull(result);

    free(result);
}
END_TEST

/**
 * @brief Test symmetry: encrypt(encrypt(x)) == x
 */
START_TEST(test_symmetry)
{
    unsigned char input[] = {0x41, 0x42, 0x43};
    unsigned char* first  = NULL;
    unsigned char* second = NULL;

    lcg_crypt(input, 3, 3, 5, 3, 8, &first);
    lcg_crypt(first, 3, 3, 5, 3, 8, &second);

    ck_assert_int_eq(second[0], input[0]);
    ck_assert_int_eq(second[1], input[1]);
    ck_assert_int_eq(second[2], input[2]);

    free(first);
    free(second);
}
END_TEST

/**
 * @brief Test known values from example 2 (PDF)
 * LCG: x[i+1] = (5*x + 3) mod 8, x0=3
 * Sequence: 3, 2, 5, 4, 7, 6, 1
 * Keystream bits: 011 010 101 100 111 110 001
 */
START_TEST(test_known_sequence)
{
    /* input zeros to get raw keystream */
    unsigned char input[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    unsigned char* result = NULL;

    enum crypto_status status = lcg_crypt(input, 7, 3, 5, 3, 8, &result);

    ck_assert_int_eq(status, CRYPTO_SUCCESS);
    ck_assert_int_eq(result[0], 3); /* x0 = 3 */
    ck_assert_int_eq(result[1], 2); /* x1 = 2 */
    ck_assert_int_eq(result[2], 5); /* x2 = 5 */
    ck_assert_int_eq(result[3], 4); /* x3 = 4 */
    ck_assert_int_eq(result[4], 7); /* x4 = 7 */
    ck_assert_int_eq(result[5], 6); /* x5 = 6 */
    ck_assert_int_eq(result[6], 1); /* x6 = 1 */

    free(result);
}
END_TEST

/**
 * @brief Test NULL pointer handling
 */
START_TEST(test_null_input)
{
    unsigned char input[] = {0x01};
    unsigned char* result = NULL;

    ck_assert_int_eq(lcg_crypt(NULL, 1, 3, 5, 3, 8, &result), CRYPTO_ERROR_NULL_POINTER);
    ck_assert_int_eq(lcg_crypt(input, 1, 3, 5, 3, 8, NULL), CRYPTO_ERROR_NULL_POINTER);
}
END_TEST

/**
 * @brief Test m == 0 (invalid)
 */
START_TEST(test_zero_modulus)
{
    unsigned char input[] = {0x01};
    unsigned char* result = NULL;

    enum crypto_status status = lcg_crypt(input, 1, 3, 5, 3, 0, &result);

    ck_assert_int_eq(status, CRYPTO_ERROR_INVALID_KEY);
}
END_TEST

/**
 * @brief Test single byte
 */
START_TEST(test_single_byte)
{
    unsigned char input[] = {0x00};
    unsigned char* result = NULL;

    enum crypto_status status = lcg_crypt(input, 1, 5, 5, 3, 8, &result);

    ck_assert_int_eq(status, CRYPTO_SUCCESS);
    ck_assert_int_eq(result[0], 5);

    free(result);
}
END_TEST

/**
 * @brief Create test suite
 */
Suite* lcg_suite(void)
{
    Suite* s;
    TCase* tc_core;

    s = suite_create("LCG Cipher");
    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_encrypt_basic);
    tcase_add_test(tc_core, test_symmetry);
    tcase_add_test(tc_core, test_known_sequence);
    tcase_add_test(tc_core, test_null_input);
    tcase_add_test(tc_core, test_zero_modulus);
    tcase_add_test(tc_core, test_single_byte);

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

    s = lcg_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}