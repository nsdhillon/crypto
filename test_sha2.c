/**
 * @Author: ndhillon
 * @Date:   2018-03-20T16:15:07-04:00
 * @Last modified by:   ndhillon
 * @Last modified time: 2018-03-26T11:17:54-04:00
 */

/**

gcc test_sha2.c sha2.c -o test_check -I . -lcheck

./test_check
Running suite(s): test-sha2
100%: Checks: 3, Failures: 0, Errors: 0
test_sha2.c:123:P:sha2:test_sha1:0: Passed
test_sha2.c:195:P:sha2:test_sha256:0: Passed
test_sha2.c:295:P:sha2:test_sha512:0: Passed
PASSED ALL TESTS

*/

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <check.h>

#include "sha2.h"

// to generate a private key, simply generate 32 bytes from a secure
// cryptographic source
typedef unsigned char ed25519_secret_key[32];

#define TEST1 "abc"
#define TEST2_1 "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
#define TEST2_2a "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
#define TEST2_2b "hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
#define TEST2_2 TEST2_2a TEST2_2b
#define TEST3 "a" /* times 1000000 */
#define TEST4a "01234567012345670123456701234567"
#define TEST4b "01234567012345670123456701234567"
/* an exact multiple of 512 bits */
#define TEST4 TEST4a TEST4b /* times 10 */

#define TEST7_1 "\x49\xb2\xae\xc2\x59\x4b\xbe\x3a\x3b\x11\x75\x42\xd9\x4a\xc8"
#define TEST8_1                                                                \
  "\x9a\x7d\xfd\xf1\xec\xea\xd0\x6e\xd6\x46\xaa\x55\xfe\x75\x71\x46"
#define TEST9_1                                                                \
  "\x65\xf9\x32\x99\x5b\xa4\xce\x2c\xb1\xb4\xa2\xe7\x1a\xe7\x02\x20"           \
  "\xaa\xce\xc8\x96\x2d\xd4\x49\x9c\xbd\x7c\x88\x7a\x94\xea\xaa\x10"           \
  "\x1e\xa5\xaa\xbc\x52\x9b\x4e\x7e\x43\x66\x5a\x5a\xf2\xcd\x03\xfe"           \
  "\x67\x8e\xa6\xa5\x00\x5b\xba\x3b\x08\x22\x04\xc2\x8b\x91\x09\xf4"           \
  "\x69\xda\xc9\x2a\xaa\xb3\xaa\x7c\x11\xa1\xb3\x2a"
#define TEST10_1                                                               \
  "\xf7\x8f\x92\x14\x1b\xcd\x17\x0a\xe8\x9b\x4f\xba\x15\xa1\xd5\x9f"           \
  "\x3f\xd8\x4d\x22\x3c\x92\x51\xbd\xac\xbb\xae\x61\xd0\x5e\xd1\x15"           \
  "\xa0\x6a\x7c\xe1\x17\xb7\xbe\xea\xd2\x44\x21\xde\xd9\xc3\x25\x92"           \
  "\xbd\x57\xed\xea\xe3\x9c\x39\xfa\x1f\xe8\x94\x6a\x84\xd0\xcf\x1f"           \
  "\x7b\xee\xad\x17\x13\xe2\xe0\x95\x98\x97\x34\x7f\x67\xc8\x0b\x04"           \
  "\x00\xc2\x09\x81\x5d\x6b\x10\xa6\x83\x83\x6f\xd5\x56\x2a\x56\xca"           \
  "\xb1\xa2\x8e\x81\xb6\x57\x66\x54\x63\x1c\xf1\x65\x66\xb8\x6e\x3b"           \
  "\x33\xa1\x08\xb0\x53\x07\xc0\x0a\xff\x14\xa7\x68\xed\x73\x50\x60"           \
  "\x6a\x0f\x85\xe6\xa9\x1d\x39\x6f\x5b\x5c\xbe\x57\x7f\x9b\x38\x80"           \
  "\x7c\x7d\x52\x3d\x6d\x79\x2f\x6e\xbc\x24\xa4\xec\xf2\xb3\xa4\x27"           \
  "\xcd\xbb\xfb"

#define length(x) (sizeof(x) - 1)

// helper function to convert test data
const uint8_t *fromhex(const char *str) {

  static uint8_t buf[512];
  size_t len = strlen(str) / 2;
  if (len > 512)
    len = 512;
  for (size_t i = 0; i < len; i++) {
    uint8_t c = 0;
    if (str[i * 2] >= '0' && str[i * 2] <= '9')
      c += (str[i * 2] - '0') << 4;

    if ((str[i * 2] & ~0x20) >= 'A' && (str[i * 2] & ~0x20) <= 'F')
      c += (10 + (str[i * 2] & ~0x20) - 'A') << 4;

    if (str[i * 2 + 1] >= '0' && str[i * 2 + 1] <= '9')
      c += (str[i * 2 + 1] - '0');

    if ((str[i * 2 + 1] & ~0x20) >= 'A' && (str[i * 2 + 1] & ~0x20) <= 'F')
      c += (10 + (str[i * 2 + 1] & ~0x20) - 'A');
    buf[i] = c;
  }
  return buf;
}

void nem_private_key(const char *reversed_hex, ed25519_secret_key private_key) {
  const uint8_t *reversed_key = fromhex(reversed_hex);
  for (size_t j = 0; j < sizeof(ed25519_secret_key); j++) {
    private_key[j] = reversed_key[sizeof(ed25519_secret_key) - j - 1];
  }
}

// test vectors from rfc-4634
START_TEST(test_sha1) {
  struct {
    const char *test;
    int length;
    int repeatcount;
    int extrabits;
    int numberExtrabits;
    const char *result;
  } tests[] = {
      /* 1 */
      {TEST1, length(TEST1), 1, 0, 0,
      "A9993E364706816ABA3E25717850C26C9CD0D89D"},
      /* 2 */
      {TEST2_1, length(TEST2_1), 1, 0, 0,
       "84983E441C3BD26EBAAE4AA1F95129E5E54670F1"},
      /* 3 */
      {TEST3, length(TEST3), 1000000, 0, 0,
       "34AA973CD4C4DAA4F61EEB2BDBAD27316534016F"},
      /* 4 */
      {TEST4, length(TEST4), 10, 0, 0,
       "DEA356A2CDDD90C7A7ECEDC5EBB563934F460452"},
      /* 5 */
      {"", 0, 0, 0x98, 5, "29826B003B906E660EFF4027CE98AF3531AC75BA"},
      /* 6 */ {"\x5e", 1, 1, 0, 0, "5E6F80A34A9798CAFC6A5DB96CC57BA4C4DB59C2"},
      /* 7 */
      {TEST7_1, length(TEST7_1), 1, 0x80, 3,
       "6239781E03729919C01955B3FFA8ACB60B988340"},
      /* 8 */
      {TEST8_1, length(TEST8_1), 1, 0, 0,
       "82ABFF6605DBE1C17DEF12A394FA22A82B544A35"},
      /* 9 */
      {TEST9_1, length(TEST9_1), 1, 0xE0, 3,
       "8C5B2A5DDAE5A97FC7F9D85661C672ADBF7933D4"},
      /* 10 */
      {TEST10_1, length(TEST10_1), 1, 0, 0,
       "CB0082C8F197D260991BA6A460E76E202BAD27B3"}};

  for (int i = 0; i < 10; i++) {
    SHA1_CTX ctx;
    uint8_t digest[SHA1_DIGEST_LENGTH];
    sha1_Init(&ctx);
    /* extra bits are not supported */
    if (tests[i].numberExtrabits)
      continue;
    for (int j = 0; j < tests[i].repeatcount; j++) {
      sha1_Update(&ctx, (const uint8_t *)tests[i].test, tests[i].length);
    }
    sha1_Final(&ctx, digest);
    ck_assert_mem_eq(digest, fromhex(tests[i].result), SHA1_DIGEST_LENGTH);
  }
}
END_TEST

#define TEST7_256 "\xbe\x27\x46\xc6\xdb\x52\x76\x5f\xdb\x2f\x88\x70\x0f\x9a\x73"
#define TEST8_256                                                              \
  "\xe3\xd7\x25\x70\xdc\xdd\x78\x7c\xe3\x88\x7a\xb2\xcd\x68\x46\x52"
#define TEST9_256                                                              \
  "\x3e\x74\x03\x71\xc8\x10\xc2\xb9\x9f\xc0\x4e\x80\x49\x07\xef\x7c"           \
  "\xf2\x6b\xe2\x8b\x57\xcb\x58\xa3\xe2\xf3\xc0\x07\x16\x6e\x49\xc1"           \
  "\x2e\x9b\xa3\x4c\x01\x04\x06\x91\x29\xea\x76\x15\x64\x25\x45\x70"           \
  "\x3a\x2b\xd9\x01\xe1\x6e\xb0\xe0\x5d\xeb\xa0\x14\xeb\xff\x64\x06"           \
  "\xa0\x7d\x54\x36\x4e\xff\x74\x2d\xa7\x79\xb0\xb3"
#define TEST10_256                                                             \
  "\x83\x26\x75\x4e\x22\x77\x37\x2f\x4f\xc1\x2b\x20\x52\x7a\xfe\xf0"           \
  "\x4d\x8a\x05\x69\x71\xb1\x1a\xd5\x71\x23\xa7\xc1\x37\x76\x00\x00"           \
  "\xd7\xbe\xf6\xf3\xc1\xf7\xa9\x08\x3a\xa3\x9d\x81\x0d\xb3\x10\x77"           \
  "\x7d\xab\x8b\x1e\x7f\x02\xb8\x4a\x26\xc7\x73\x32\x5f\x8b\x23\x74"           \
  "\xde\x7a\x4b\x5a\x58\xcb\x5c\x5c\xf3\x5b\xce\xe6\xfb\x94\x6e\x5b"           \
  "\xd6\x94\xfa\x59\x3a\x8b\xeb\x3f\x9d\x65\x92\xec\xed\xaa\x66\xca"           \
  "\x82\xa2\x9d\x0c\x51\xbc\xf9\x33\x62\x30\xe5\xd7\x84\xe4\xc0\xa4"           \
  "\x3f\x8d\x79\xa3\x0a\x16\x5c\xba\xbe\x45\x2b\x77\x4b\x9c\x71\x09"           \
  "\xa9\x7d\x13\x8f\x12\x92\x28\x96\x6f\x6c\x0a\xdc\x10\x6a\xad\x5a"           \
  "\x9f\xdd\x30\x82\x57\x69\xb2\xc6\x71\xaf\x67\x59\xdf\x28\xeb\x39"           \
  "\x3d\x54\xd6"

// test vectors from rfc-4634
START_TEST(test_sha256) {
  struct {
    const char *test;
    int length;
    int repeatcount;
    int extrabits;
    int numberExtrabits;
    const char *result;
  } tests[] = {
      /* 1 */ {TEST1, length(TEST1), 1, 0, 0,
               "BA7816BF8F01CFEA4141"
               "40DE5DAE2223B00361A396177A9CB410FF61F20015AD"},
      /* 2 */
      {TEST2_1, length(TEST2_1), 1, 0, 0,
       "248D6A61D20638B8"
       "E5C026930C3E6039A33CE45964FF2167F6ECEDD419DB06C1"},
      /* 3 */
      {TEST3, length(TEST3), 1000000, 0, 0,
       "CDC76E5C9914FB92"
       "81A1C7E284D73E67F1809A48A497200E046D39CCC7112CD0"},
      /* 4 */
      {TEST4, length(TEST4), 10, 0, 0,
       "594847328451BDFA"
       "85056225462CC1D867D877FB388DF0CE35F25AB5562BFBB5"},
      /* 5 */
      {"", 0, 0, 0x68, 5,
       "D6D3E02A31A84A8CAA9718ED6C2057BE"
       "09DB45E7823EB5079CE7A573A3760F95"},
      /* 6 */
      {"\x19", 1, 1, 0, 0,
       "68AA2E2EE5DFF96E3355E6C7EE373E3D"
       "6A4E17F75F9518D843709C0C9BC3E3D4"},
      /* 7 */
      {TEST7_256, length(TEST7_256), 1, 0x60, 3,
       "77EC1DC8"
       "9C821FF2A1279089FA091B35B8CD960BCAF7DE01C6A7680756BEB972"},
      /* 8 */
      {TEST8_256, length(TEST8_256), 1, 0, 0,
       "175EE69B02BA"
       "9B58E2B0A5FD13819CEA573F3940A94F825128CF4209BEABB4E8"},
      /* 9 */
      {TEST9_256, length(TEST9_256), 1, 0xA0, 3,
       "3E9AD646"
       "8BBBAD2AC3C2CDC292E018BA5FD70B960CF1679777FCE708FDB066E9"},
      /* 10 */
      {TEST10_256, length(TEST10_256), 1, 0, 0,
       "97DBCA7D"
       "F46D62C8A422C941DD7E835B8AD3361763F7E9B2D95F4F0DA6E1CCBC"},
  };

  for (int i = 0; i < 10; i++) {
    SHA256_CTX ctx;
    uint8_t digest[SHA256_DIGEST_LENGTH];
    sha256_Init(&ctx);
    /* extra bits are not supported */
    if (tests[i].numberExtrabits)
      continue;
    for (int j = 0; j < tests[i].repeatcount; j++) {
      sha256_Update(&ctx, (const uint8_t *)tests[i].test, tests[i].length);
    }
    sha256_Final(&ctx, digest);
    ck_assert_mem_eq(digest, fromhex(tests[i].result), SHA256_DIGEST_LENGTH);
  }
}
END_TEST

#define TEST7_512 "\x08\xec\xb5\x2e\xba\xe1\xf7\x42\x2d\xb6\x2b\xcd\x54\x26\x70"
#define TEST8_512                                                              \
  "\x8d\x4e\x3c\x0e\x38\x89\x19\x14\x91\x81\x6e\x9d\x98\xbf\xf0\xa0"
#define TEST9_512                                                              \
  "\x3a\xdd\xec\x85\x59\x32\x16\xd1\x61\x9a\xa0\x2d\x97\x56\x97\x0b"           \
  "\xfc\x70\xac\xe2\x74\x4f\x7c\x6b\x27\x88\x15\x10\x28\xf7\xb6\xa2"           \
  "\x55\x0f\xd7\x4a\x7e\x6e\x69\xc2\xc9\xb4\x5f\xc4\x54\x96\x6d\xc3"           \
  "\x1d\x2e\x10\xda\x1f\x95\xce\x02\xbe\xb4\xbf\x87\x65\x57\x4c\xbd"           \
  "\x6e\x83\x37\xef\x42\x0a\xdc\x98\xc1\x5c\xb6\xd5\xe4\xa0\x24\x1b"           \
  "\xa0\x04\x6d\x25\x0e\x51\x02\x31\xca\xc2\x04\x6c\x99\x16\x06\xab"           \
  "\x4e\xe4\x14\x5b\xee\x2f\xf4\xbb\x12\x3a\xab\x49\x8d\x9d\x44\x79"           \
  "\x4f\x99\xcc\xad\x89\xa9\xa1\x62\x12\x59\xed\xa7\x0a\x5b\x6d\xd4"           \
  "\xbd\xd8\x77\x78\xc9\x04\x3b\x93\x84\xf5\x49\x06"
#define TEST10_512                                                             \
  "\xa5\x5f\x20\xc4\x11\xaa\xd1\x32\x80\x7a\x50\x2d\x65\x82\x4e\x31"           \
  "\xa2\x30\x54\x32\xaa\x3d\x06\xd3\xe2\x82\xa8\xd8\x4e\x0d\xe1\xde"           \
  "\x69\x74\xbf\x49\x54\x69\xfc\x7f\x33\x8f\x80\x54\xd5\x8c\x26\xc4"           \
  "\x93\x60\xc3\xe8\x7a\xf5\x65\x23\xac\xf6\xd8\x9d\x03\xe5\x6f\xf2"           \
  "\xf8\x68\x00\x2b\xc3\xe4\x31\xed\xc4\x4d\xf2\xf0\x22\x3d\x4b\xb3"           \
  "\xb2\x43\x58\x6e\x1a\x7d\x92\x49\x36\x69\x4f\xcb\xba\xf8\x8d\x95"           \
  "\x19\xe4\xeb\x50\xa6\x44\xf8\xe4\xf9\x5e\xb0\xea\x95\xbc\x44\x65"           \
  "\xc8\x82\x1a\xac\xd2\xfe\x15\xab\x49\x81\x16\x4b\xbb\x6d\xc3\x2f"           \
  "\x96\x90\x87\xa1\x45\xb0\xd9\xcc\x9c\x67\xc2\x2b\x76\x32\x99\x41"           \
  "\x9c\xc4\x12\x8b\xe9\xa0\x77\xb3\xac\xe6\x34\x06\x4e\x6d\x99\x28"           \
  "\x35\x13\xdc\x06\xe7\x51\x5d\x0d\x73\x13\x2e\x9a\x0d\xc6\xd3\xb1"           \
  "\xf8\xb2\x46\xf1\xa9\x8a\x3f\xc7\x29\x41\xb1\xe3\xbb\x20\x98\xe8"           \
  "\xbf\x16\xf2\x68\xd6\x4f\x0b\x0f\x47\x07\xfe\x1e\xa1\xa1\x79\x1b"           \
  "\xa2\xf3\xc0\xc7\x58\xe5\xf5\x51\x86\x3a\x96\xc9\x49\xad\x47\xd7"           \
  "\xfb\x40\xd2"

// test vectors from rfc-4634
START_TEST(test_sha512) {
  struct {
    const char *test;
    int length;
    int repeatcount;
    int extrabits;
    int numberExtrabits;
    const char *result;
  } tests[] = {/* 1 */ {TEST1, length(TEST1), 1, 0, 0,
                        "DDAF35A193617ABACC417349AE20413112E6FA4E89A97EA2"
                        "0A9EEEE64B55D39A2192992A274FC1A836BA3C23A3FEEBBD"
                        "454D4423643CE80E2A9AC94FA54CA49F"},
               /* 2 */
               {TEST2_2, length(TEST2_2), 1, 0, 0,
                "8E959B75DAE313DA8CF4F72814FC143F8F7779C6EB9F7FA1"
                "7299AEADB6889018501D289E4900F7E4331B99DEC4B5433A"
                "C7D329EEB6DD26545E96E55B874BE909"},
               /* 3 */
               {TEST3, length(TEST3), 1000000, 0, 0,
                "E718483D0CE769644E2E42C7BC15B4638E1F98B13B204428"
                "5632A803AFA973EBDE0FF244877EA60A4CB0432CE577C31B"
                "EB009C5C2C49AA2E4EADB217AD8CC09B"},
               /* 4 */
               {TEST4, length(TEST4), 10, 0, 0,
                "89D05BA632C699C31231DED4FFC127D5A894DAD412C0E024"
                "DB872D1ABD2BA8141A0F85072A9BE1E2AA04CF33C765CB51"
                "0813A39CD5A84C4ACAA64D3F3FB7BAE9"},
               /* 5 */
               {"", 0, 0, 0xB0, 5,
                "D4EE29A9E90985446B913CF1D1376C836F4BE2C1CF3CADA0"
                "720A6BF4857D886A7ECB3C4E4C0FA8C7F95214E41DC1B0D2"
                "1B22A84CC03BF8CE4845F34DD5BDBAD4"},
               /* 6 */
               {"\xD0", 1, 1, 0, 0,
                "9992202938E882E73E20F6B69E68A0A7149090423D93C81B"
                "AB3F21678D4ACEEEE50E4E8CAFADA4C85A54EA8306826C4A"
                "D6E74CECE9631BFA8A549B4AB3FBBA15"},
               /* 7 */
               {TEST7_512, length(TEST7_512), 1, 0x80, 3,
                "ED8DC78E8B01B69750053DBB7A0A9EDA0FB9E9D292B1ED71"
                "5E80A7FE290A4E16664FD913E85854400C5AF05E6DAD316B"
                "7359B43E64F8BEC3C1F237119986BBB6"},
               /* 8 */
               {TEST8_512, length(TEST8_512), 1, 0, 0,
                "CB0B67A4B8712CD73C9AABC0B199E9269B20844AFB75ACBD"
                "D1C153C9828924C3DDEDAAFE669C5FDD0BC66F630F677398"
                "8213EB1B16F517AD0DE4B2F0C95C90F8"},
               /* 9 */
               {TEST9_512, length(TEST9_512), 1, 0x80, 3,
                "32BA76FC30EAA0208AEB50FFB5AF1864FDBF17902A4DC0A6"
                "82C61FCEA6D92B783267B21080301837F59DE79C6B337DB2"
                "526F8A0A510E5E53CAFED4355FE7C2F1"},
               /* 10 */
               {TEST10_512, length(TEST10_512), 1, 0, 0,
                "C665BEFB36DA189D78822D10528CBF3B12B3EEF726039909"
                "C1A16A270D48719377966B957A878E720584779A62825C18"
                "DA26415E49A7176A894E7510FD1451F5"}};

  for (int i = 0; i < 10; i++) {
    SHA512_CTX ctx;
    uint8_t digest[SHA512_DIGEST_LENGTH];
    sha512_Init(&ctx);
    /* extra bits are not supported */
    if (tests[i].numberExtrabits)
      continue;
    for (int j = 0; j < tests[i].repeatcount; j++) {
      sha512_Update(&ctx, (const uint8_t *)tests[i].test, tests[i].length);
    }
    sha512_Final(&ctx, digest);
    ck_assert_mem_eq(digest, fromhex(tests[i].result), SHA512_DIGEST_LENGTH);
  }
}
END_TEST

// define test suite and cases

Suite *create_test_suite(void) {

  Suite *sha2_suite = suite_create("test-sha2");

  TCase *test_case;

  test_case = tcase_create("sha2");
  tcase_add_test(test_case, test_sha1);
  tcase_add_test(test_case, test_sha256);
  tcase_add_test(test_case, test_sha512);

  suite_add_tcase(sha2_suite, test_case);

  return sha2_suite;
}

// run suite
int main(void) {

  // run libcheck tests
  Suite *s = create_test_suite();

  SRunner *sr = srunner_create(s);

  // execute test cases
  srunner_run_all(sr, CK_VERBOSE);

  int number_failed = srunner_ntests_failed(sr);

  srunner_free(sr);
  if (number_failed == 0) {
    printf("PASSED ALL TESTS\n");
  }

  return number_failed;
}
