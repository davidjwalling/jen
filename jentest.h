#pragma once

#include "api.h"
#include "des.h"
#include "aes.h"

typedef struct _digestTest {
    const char* label;
    int count;
    uint8_t* vector;
    uint8_t* digest;
    int len;
    int iter;
} DIGESTTEST;

typedef struct _hmacTest {
    const char* label;
    int count;
    uint8_t* key;
    int keylen;
    uint8_t* data;
    int datalen;
    uint8_t* digest;
    int digestlen;
} HMACTEST;

typedef struct _cipherTest {
    const char* label;
    int count;
    uint8_t* key;
    uint8_t* iv;
    uint8_t* plain;
    uint8_t* cipher;
    int len;
} CIPHERTEST;

const char Bin2AscHex[] = {
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'
};

const char Bin2AscPrt[] = {
    ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ',
    ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ',
    ' ', '!', '"', '#', '$', '%', '&', '\'', '(', ')', '*', '+', ',', '-', '.', '/',
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', ':', ';', '<', '=', '>', '?',
    '@', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O',
    'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '[', '\\', ']', '^', '_',
    '`', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o',
    'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '{', '|', '}', '~', ' ',
    ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ',
    ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ',
    ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ',
    ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ',
    ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ',
    ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ',
    ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ',
    ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' '
};

uint32_t ByteOnes[256] = {
    0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4, // 00-0F
    1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5, // 10-1F
    1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5, // 20-2F
    2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, // 30-3F
    1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5, // 40-4F
    2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, // 50-5F
    2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, // 60-6F
    3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7, // 70-7F
    1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5, // 80-8F
    2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, // 90-9F
    2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, // A0-AF
    3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7, // B0-BF
    2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, // C0-CF
    3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7, // D0-DF
    3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7, // E0-EF
    4, 5, 5, 6, 5, 6, 6, 7, 5, 6, 6, 7, 6, 7, 7, 8 // FF-FF
};

uint8_t ByteRuns[128][8] = {
    { 8, 0, 0, 0, 0, 0, 0, 0 }, //  00000000 11111111
    { 7, 1, 0, 0, 0, 0, 0, 0 }, //  00000001 11111110
    { 6, 1, 1, 0, 0, 0, 0, 0 }, //  00000010 11111101
    { 6, 2, 0, 0, 0, 0, 0, 0 }, //  00000011 11111100
    { 5, 1, 2, 0, 0, 0, 0, 0 }, //  00000100 11111011
    { 5, 1, 1, 1, 0, 0, 0, 0 }, //  00000101 11111010
    { 5, 2, 1, 0, 0, 0, 0, 0 }, //  00000110 11111001
    { 5, 3, 0, 0, 0, 0, 0, 0 }, //  00000111 11111000

    { 4, 1, 3, 0, 0, 0, 0, 0 }, //  00001000
    { 4, 1, 2, 1, 0, 0, 0, 0 }, //  00001001
    { 4, 1, 1, 1, 1, 0, 0, 0 }, //  00001010
    { 4, 1, 1, 2, 0, 0, 0, 0 }, //  00001011
    { 4, 2, 2, 0, 0, 0, 0, 0 }, //  00001100
    { 4, 2, 1, 1, 0, 0, 0, 0 }, //  00001101
    { 4, 3, 1, 0, 0, 0, 0, 0 }, //  00001110
    { 4, 4, 0, 0, 0, 0, 0, 0 }, //  00001111

    { 3, 1, 4, 0, 0, 0, 0, 0 }, //  00010000
    { 3, 1, 3, 1, 0, 0, 0, 0 }, //  00010001
    { 3, 1, 2, 1, 1, 0, 0, 0 }, //  00010010
    { 3, 1, 2, 2, 0, 0, 0, 0 }, //  00010011
    { 3, 1, 1, 1, 2, 0, 0, 0 }, //  00010100
    { 3, 1, 1, 1, 1, 1, 0, 0 }, //  00010101
    { 3, 1, 1, 2, 1, 0, 0, 0 }, //  00010110
    { 3, 1, 1, 3, 0, 0, 0, 0 }, //  00010111

    { 3, 2, 3, 0, 0, 0, 0, 0 }, //  00011000
    { 3, 2, 2, 1, 0, 0, 0, 0 }, //  00011001
    { 3, 2, 1, 1, 1, 0, 0, 0 }, //  00011010
    { 3, 2, 1, 2, 0, 0, 0, 0 }, //  00011011
    { 3, 3, 2, 0, 0, 0, 0, 0 }, //  00011100
    { 3, 3, 1, 1, 0, 0, 0, 0 }, //  00011101
    { 3, 4, 1, 0, 0, 0, 0, 0 }, //  00011110
    { 3, 5, 0, 0, 0, 0, 0, 0 }, //  00011111

    { 2, 1, 5, 0, 0, 0, 0, 0 }, //  00100000
    { 2, 1, 4, 1, 0, 0, 0, 0 }, //  00100001
    { 2, 1, 3, 1, 1, 0, 0, 0 }, //  00100010
    { 2, 1, 3, 2, 0, 0, 0, 0 }, //  00100011
    { 2, 1, 2, 1, 2, 0, 0, 0 }, //  00100100
    { 2, 1, 2, 1, 1, 1, 0, 0 }, //  00100101
    { 2, 1, 2, 2, 1, 0, 0, 0 }, //  00100110
    { 2, 1, 2, 3, 0, 0, 0, 0 }, //  00100111

    { 2, 1, 1, 1, 3, 0, 0, 0 }, //  00101000
    { 2, 1, 1, 1, 2, 1, 0, 0 }, //  00101001
    { 2, 1, 1, 1, 1, 1, 1, 0 }, //  00101010
    { 2, 1, 1, 1, 1, 2, 0, 0 }, //  00101011
    { 2, 1, 1, 2, 2, 0, 0, 0 }, //  00101100
    { 2, 1, 1, 2, 1, 1, 0, 0 }, //  00101101
    { 2, 1, 1, 3, 1, 0, 0, 0 }, //  00101110
    { 2, 1, 1, 4, 0, 0, 0, 0 }, //  00101111

    { 2, 2, 4, 0, 0, 0, 0, 0 }, //  00110000
    { 2, 2, 3, 1, 0, 0, 0, 0 }, //  00110001
    { 2, 2, 2, 1, 1, 0, 0, 0 }, //  00110010
    { 2, 2, 2, 2, 0, 0, 0, 0 }, //  00110011
    { 2, 2, 1, 1, 2, 0, 0, 0 }, //  00110100
    { 2, 2, 1, 1, 1, 1, 0, 0 }, //  00110101
    { 2, 2, 1, 2, 1, 0, 0, 0 }, //  00110110
    { 2, 2, 1, 3, 0, 0, 0, 0 }, //  00110111

    { 2, 3, 3, 0, 0, 0, 0, 0 }, //  00111000
    { 2, 3, 2, 1, 0, 0, 0, 0 }, //  00111001
    { 2, 3, 1, 1, 1, 0, 0, 0 }, //  00111010
    { 2, 3, 1, 2, 0, 0, 0, 0 }, //  00111011
    { 2, 4, 2, 0, 0, 0, 0, 0 }, //  00111100
    { 2, 4, 1, 1, 0, 0, 0, 0 }, //  00111101
    { 2, 5, 1, 0, 0, 0, 0, 0 }, //  00111110
    { 2, 6, 0, 0, 0, 0, 0, 0 }, //  00111111

    { 1, 1, 6, 0, 0, 0, 0, 0 }, //  01000000
    { 1, 1, 5, 1, 0, 0, 0, 0 }, //  01000001
    { 1, 1, 4, 1, 1, 0, 0, 0 }, //  01000010
    { 1, 1, 4, 2, 0, 0, 0, 0 }, //  01000011
    { 1, 1, 3, 1, 2, 0, 0, 0 }, //  01000100
    { 1, 1, 3, 1, 1, 1, 0, 0 }, //  01000101
    { 1, 1, 3, 2, 1, 0, 0, 0 }, //  01000110
    { 1, 1, 3, 3, 0, 0, 0, 0 }, //  01000111

    { 1, 1, 2, 1, 3, 0, 0, 0 }, //  01001000
    { 1, 1, 2, 1, 2, 1, 0, 0 }, //  01001001
    { 1, 1, 2, 1, 1, 1, 1, 0 }, //  01001010
    { 1, 1, 2, 1, 1, 2, 0, 0 }, //  01001011
    { 1, 1, 2, 2, 2, 0, 0, 0 }, //  01001100
    { 1, 1, 2, 2, 1, 1, 0, 0 }, //  01001101
    { 1, 1, 2, 3, 1, 0, 0, 0 }, //  01001110
    { 1, 1, 2, 4, 0, 0, 0, 0 }, //  01001111

    { 1, 1, 1, 1, 4, 0, 0, 0 }, //  01010000
    { 1, 1, 1, 1, 3, 1, 0, 0 }, //  01010001
    { 1, 1, 1, 1, 2, 1, 1, 0 }, //  01010010
    { 1, 1, 1, 1, 2, 2, 0, 0 }, //  01010011
    { 1, 1, 1, 1, 1, 1, 2, 0 }, //  01010100
    { 1, 1, 1, 1, 1, 1, 1, 1 }, //  01010101
    { 1, 1, 1, 1, 1, 2, 1, 0 }, //  01010110
    { 1, 1, 1, 1, 1, 3, 0, 0 }, //  01010111

    { 1, 1, 1, 2, 3, 0, 0, 0 }, //  01011000
    { 1, 1, 1, 2, 2, 1, 0, 0 }, //  01011001
    { 1, 1, 1, 2, 1, 1, 1, 0 }, //  01011010
    { 1, 1, 1, 2, 1, 2, 0, 0 }, //  01011011
    { 1, 1, 1, 3, 2, 0, 0, 0 }, //  01011100
    { 1, 1, 1, 3, 1, 1, 0, 0 }, //  01011101
    { 1, 1, 1, 4, 1, 0, 0, 0 }, //  01011110
    { 1, 1, 1, 5, 0, 0, 0, 0 }, //  01011111

    { 1, 2, 5, 0, 0, 0, 0, 0 }, //  01100000
    { 1, 2, 4, 1, 0, 0, 0, 0 }, //  01100001
    { 1, 2, 3, 1, 1, 0, 0, 0 }, //  01100010
    { 1, 2, 3, 2, 0, 0, 0, 0 }, //  01100011
    { 1, 2, 2, 1, 2, 0, 0, 0 }, //  01100100
    { 1, 2, 2, 1, 1, 1, 0, 0 }, //  01100101 10011010
    { 1, 2, 2, 2, 1, 0, 0, 0 }, //  01100110 10011001
    { 1, 2, 2, 3, 0, 0, 0, 0 }, //  01100111 10011000

    { 1, 2, 1, 1, 3, 0, 0, 0 }, //  01101000 10010111
    { 1, 2, 1, 1, 2, 1, 0, 0 }, //  01101001 10010110
    { 1, 2, 1, 1, 1, 1, 1, 0 }, //  01101010 10010101
    { 1, 2, 1, 1, 1, 2, 0, 0 }, //  01101011 10010100
    { 1, 2, 1, 2, 2, 0, 0, 0 }, //  01101100 10010011
    { 1, 2, 1, 2, 1, 1, 0, 0 }, //  01101101 10010010
    { 1, 2, 1, 3, 1, 0, 0, 0 }, //  01101110 10010001
    { 1, 2, 1, 4, 0, 0, 0, 0 }, //  01101111 10010000

    { 1, 3, 4, 0, 0, 0, 0, 0 }, //  01110000 10001111
    { 1, 3, 3, 1, 0, 0, 0, 0 }, //  01110001 10001110
    { 1, 3, 2, 1, 1, 0, 0, 0 }, //  01110010 10001101
    { 1, 3, 2, 2, 0, 0, 0, 0 }, //  01110011 10001100
    { 1, 3, 1, 1, 2, 0, 0, 0 }, //  01110100 10001011
    { 1, 3, 1, 1, 1, 1, 0, 0 }, //  01110101 10001010
    { 1, 3, 1, 2, 1, 0, 0, 0 }, //  01110110 10001001
    { 1, 3, 1, 3, 0, 0, 0, 0 }, //  01110111 10001000

    { 1, 4, 3, 0, 0, 0, 0, 0 }, //  01111000 10000111
    { 1, 4, 2, 1, 0, 0, 0, 0 }, //  01111001 10000110
    { 1, 4, 1, 1, 1, 0, 0, 0 }, //  01111010 10000101
    { 1, 4, 1, 2, 0, 0, 0, 0 }, //  01111011 10000100
    { 1, 5, 2, 0, 0, 0, 0, 0 }, //  01111100 10000011
    { 1, 5, 1, 1, 0, 0, 0, 0 }, //  01111101 10000010
    { 1, 6, 1, 0, 0, 0, 0, 0 }, //  01111110 10000001
    { 1, 7, 0, 0, 0, 0, 0, 0 } //  01111111 10000000
};

//  MD5 test vectors 1-7: RFC 1321

uint8_t* const md5_vector_1 = (uint8_t*)"";
uint8_t* const md5_vector_2 = (uint8_t*)"a";
uint8_t* const md5_vector_3 = (uint8_t*)"abc";
uint8_t* const md5_vector_4 = (uint8_t*)"message digest";
uint8_t* const md5_vector_5 = (uint8_t*)"abcdefghijklmnopqrstuvwxyz";
uint8_t* const md5_vector_6 = (uint8_t*)"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
uint8_t* const md5_vector_7 = (uint8_t*)"12345678901234567890123456789012345678901234567890123456789012345678901234567890";

uint8_t* const md5_digest_1 = (uint8_t*)"\xD4\x1D\x8C\xD9\x8F\x00\xB2\x04\xE9\x80\x09\x98\xEC\xF8\x42\x7E";
uint8_t* const md5_digest_2 = (uint8_t*)"\x0C\xC1\x75\xB9\xC0\xF1\xB6\xA8\x31\xC3\x99\xE2\x69\x77\x26\x61";
uint8_t* const md5_digest_3 = (uint8_t*)"\x90\x01\x50\x98\x3C\xD2\x4F\xB0\xD6\x96\x3F\x7D\x28\xE1\x7F\x72";
uint8_t* const md5_digest_4 = (uint8_t*)"\xF9\x6B\x69\x7D\x7C\xB7\x93\x8D\x52\x5A\x2F\x31\xAA\xF1\x61\xD0";
uint8_t* const md5_digest_5 = (uint8_t*)"\xC3\xFC\xD3\xD7\x61\x92\xE4\x00\x7D\xFB\x49\x6C\xCA\x67\xE1\x3B";
uint8_t* const md5_digest_6 = (uint8_t*)"\xD1\x74\xAB\x98\xD2\x77\xD9\xF5\xA5\x61\x1C\x2C\x9F\x41\x9D\x9F";
uint8_t* const md5_digest_7 = (uint8_t*)"\x57\xED\xF4\xA2\x2B\xE3\xC9\x55\xAC\x49\xDA\x2E\x21\x07\xB6\x7A";

DIGESTTEST md5_tests[] = {
    { "MD5", 7, md5_vector_1, md5_digest_1, 0, 1 },
    { "MD5", 7, md5_vector_2, md5_digest_2, 1, 1 },
    { "MD5", 7, md5_vector_3, md5_digest_3, 3, 1 },
    { "MD5", 7, md5_vector_4, md5_digest_4, 14, 1 },
    { "MD5", 7, md5_vector_5, md5_digest_5, 26, 1 },
    { "MD5", 7, md5_vector_6, md5_digest_6, 62, 1 },
    { "MD5", 7, md5_vector_7, md5_digest_7, 80, 1 }
};

// SHA1 test vectors 1-3: FIPS pub 180-2 appendix A examples 1-3
// SHA1 test vectors 4-6: NIST pub SHAVS appendix A.1 examples 2, 4 and appendix A.2 example 2

uint8_t* const sha1_vector_1 = (uint8_t*)"abc";
uint8_t* const sha1_vector_2 = (uint8_t*)"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
uint8_t* const sha1_vector_3 = (uint8_t*)"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
uint8_t* const sha1_vector_4 = (uint8_t*)"\x5e";
uint8_t* const sha1_vector_5 = (uint8_t*)"\x9a\x7d\xfd\xf1\xec\xea\xd0\x6e\xd6\x46\xaa\x55\xfe\x75\x71\x46";
uint8_t* const sha1_vector_6 = (uint8_t*)"\xf7\x8f\x92\x14\x1b\xcd\x17\x0a\xe8\x9b\x4f\xba\x15\xa1\xd5\x9f\x3f\xd8\x4d\x22\x3c\x92\x51\xbd\xac\xbb\xae\x61\xd0\x5e\xd1\x15"
"\xa0\x6a\x7c\xe1\x17\xb7\xbe\xea\xd2\x44\x21\xde\xd9\xc3\x25\x92\xbd\x57\xed\xea\xe3\x9c\x39\xfa\x1f\xe8\x94\x6a\x84\xd0\xcf\x1f"
"\x7b\xee\xad\x17\x13\xe2\xe0\x95\x98\x97\x34\x7f\x67\xc8\x0b\x04\x00\xc2\x09\x81\x5d\x6b\x10\xa6\x83\x83\x6f\xd5\x56\x2a\x56\xca"
"\xb1\xa2\x8e\x81\xb6\x57\x66\x54\x63\x1c\xf1\x65\x66\xb8\x6e\x3b\x33\xa1\x08\xb0\x53\x07\xc0\x0a\xff\x14\xa7\x68\xed\x73\x50\x60"
"\x6a\x0f\x85\xe6\xa9\x1d\x39\x6f\x5b\x5c\xbe\x57\x7f\x9b\x38\x80\x7c\x7d\x52\x3d\x6d\x79\x2f\x6e\xbc\x24\xa4\xec\xf2\xb3\xa4\x27"
"\xcd\xbb\xfb";

uint8_t* const sha1_digest_1 = (uint8_t*)"\xA9\x99\x3E\x36\x47\x06\x81\x6A\xBA\x3E\x25\x71\x78\x50\xC2\x6C\x9C\xD0\xD8\x9D";
uint8_t* const sha1_digest_2 = (uint8_t*)"\x84\x98\x3E\x44\x1C\x3B\xD2\x6E\xBA\xAE\x4A\xA1\xF9\x51\x29\xE5\xE5\x46\x70\xF1";
uint8_t* const sha1_digest_3 = (uint8_t*)"\x34\xAA\x97\x3C\xD4\xC4\xDA\xA4\xF6\x1E\xEB\x2B\xDB\xAD\x27\x31\x65\x34\x01\x6F";
uint8_t* const sha1_digest_4 = (uint8_t*)"\x5e\x6f\x80\xa3\x4a\x97\x98\xca\xfc\x6a\x5d\xb9\x6c\xc5\x7b\xa4\xc4\xdb\x59\xc2";
uint8_t* const sha1_digest_5 = (uint8_t*)"\x82\xab\xff\x66\x05\xdb\xe1\xc1\x7d\xef\x12\xa3\x94\xfa\x22\xa8\x2b\x54\x4a\x35";
uint8_t* const sha1_digest_6 = (uint8_t*)"\xcb\x00\x82\xc8\xf1\x97\xd2\x60\x99\x1b\xa6\xa4\x60\xe7\x6e\x20\x2b\xad\x27\xb3";

DIGESTTEST sha1_tests[] = {
    { "SHA1", 6, sha1_vector_1, sha1_digest_1, 3, 1 },
    { "SHA1", 6, sha1_vector_2, sha1_digest_2, 56, 1 },
    { "SHA1", 6, sha1_vector_3, sha1_digest_3, 100, 10000 },
    { "SHA1", 6, sha1_vector_4, sha1_digest_4, 1, 1 },
    { "SHA1", 6, sha1_vector_5, sha1_digest_5, 16, 1 },
    { "SHA1", 6, sha1_vector_6, sha1_digest_6, 163, 1 }
};

// SHA256 test vectors 1-3: FIPS pub 180-2 appendix B examples 1-3
// SHA256 test vectors 4-6: NIST pub SHAVS appendix C.1 examples 2, 4 and appendix C.2 example 2

uint8_t* const sha256_vector_1 = (uint8_t*)"abc";
uint8_t* const sha256_vector_2 = (uint8_t*)"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
uint8_t* const sha256_vector_3 = (uint8_t*)"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
uint8_t* const sha256_vector_4 = (uint8_t*)"\x19";
uint8_t* const sha256_vector_5 = (uint8_t*)"\xe3\xd7\x25\x70\xdc\xdd\x78\x7c\xe3\x88\x7a\xb2\xcd\x68\x46\x52";
uint8_t* const sha256_vector_6 = (uint8_t*)"\x83\x26\x75\x4e\x22\x77\x37\x2f\x4f\xc1\x2b\x20\x52\x7a\xfe\xf0\x4d\x8a\x05\x69\x71\xb1\x1a\xd5\x71\x23\xa7\xc1\x37\x76\x00\x00"
"\xd7\xbe\xf6\xf3\xc1\xf7\xa9\x08\x3a\xa3\x9d\x81\x0d\xb3\x10\x77\x7d\xab\x8b\x1e\x7f\x02\xb8\x4a\x26\xc7\x73\x32\x5f\x8b\x23\x74"
"\xde\x7a\x4b\x5a\x58\xcb\x5c\x5c\xf3\x5b\xce\xe6\xfb\x94\x6e\x5b\xd6\x94\xfa\x59\x3a\x8b\xeb\x3f\x9d\x65\x92\xec\xed\xaa\x66\xca"
"\x82\xa2\x9d\x0c\x51\xbc\xf9\x33\x62\x30\xe5\xd7\x84\xe4\xc0\xa4\x3f\x8d\x79\xa3\x0a\x16\x5c\xba\xbe\x45\x2b\x77\x4b\x9c\x71\x09"
"\xa9\x7d\x13\x8f\x12\x92\x28\x96\x6f\x6c\x0a\xdc\x10\x6a\xad\x5a\x9f\xdd\x30\x82\x57\x69\xb2\xc6\x71\xaf\x67\x59\xdf\x28\xeb\x39"
"\x3d\x54\xd6";

uint8_t* const sha256_digest_1 = (uint8_t*)"\xba\x78\x16\xbf\x8f\x01\xcf\xea\x41\x41\x40\xde\x5d\xae\x22\x23\xb0\x03\x61\xa3\x96\x17\x7a\x9c\xb4\x10\xff\x61\xf2\x00\x15\xad";
uint8_t* const sha256_digest_2 = (uint8_t*)"\x24\x8d\x6a\x61\xd2\x06\x38\xb8\xe5\xc0\x26\x93\x0c\x3e\x60\x39\xa3\x3c\xe4\x59\x64\xff\x21\x67\xf6\xec\xed\xd4\x19\xdb\x06\xc1";
uint8_t* const sha256_digest_3 = (uint8_t*)"\xcd\xc7\x6e\x5c\x99\x14\xfb\x92\x81\xa1\xc7\xe2\x84\xd7\x3e\x67\xf1\x80\x9a\x48\xa4\x97\x20\x0e\x04\x6d\x39\xcc\xc7\x11\x2c\xd0";
uint8_t* const sha256_digest_4 = (uint8_t*)"\x68\xaa\x2e\x2e\xe5\xdf\xf9\x6e\x33\x55\xe6\xc7\xee\x37\x3e\x3d\x6a\x4e\x17\xf7\x5f\x95\x18\xd8\x43\x70\x9c\x0c\x9b\xc3\xe3\xd4";
uint8_t* const sha256_digest_5 = (uint8_t*)"\x17\x5e\xe6\x9b\x02\xba\x9b\x58\xe2\xb0\xa5\xfd\x13\x81\x9c\xea\x57\x3f\x39\x40\xa9\x4f\x82\x51\x28\xcf\x42\x09\xbe\xab\xb4\xe8";
uint8_t* const sha256_digest_6 = (uint8_t*)"\x97\xdb\xca\x7d\xf4\x6d\x62\xc8\xa4\x22\xc9\x41\xdd\x7e\x83\x5b\x8a\xd3\x36\x17\x63\xf7\xe9\xb2\xd9\x5f\x4f\x0d\xa6\xe1\xcc\xbc";

DIGESTTEST sha256_tests[] = {
    { "SHA256", 6, sha256_vector_1, sha256_digest_1, 3, 1 },
    { "SHA256", 6, sha256_vector_2, sha256_digest_2, 56, 1 },
    { "SHA256", 6, sha256_vector_3, sha256_digest_3, 100, 10000 },
    { "SHA256", 6, sha256_vector_4, sha256_digest_4, 1, 1 },
    { "SHA256", 6, sha256_vector_5, sha256_digest_5, 16, 1 },
    { "SHA256", 6, sha256_vector_6, sha256_digest_6, 163, 1 }
};

// SHA224 test vectors 1-3: FIPS pub 180-2 change notice 1 examples 1-3
// SHA224 test vectors 4-6: NIST pub SHAVS appendix B.1 examples 2, 4 and appendix B.2 example 2

uint8_t* const sha224_vector_1 = (uint8_t*)"abc";
uint8_t* const sha224_vector_2 = (uint8_t*)"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
uint8_t* const sha224_vector_3 = (uint8_t*)"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
uint8_t* const sha224_vector_4 = (uint8_t*)"\x07";
uint8_t* const sha224_vector_5 = (uint8_t*)"\x18\x80\x40\x05\xdd\x4f\xbd\x15\x56\x29\x9d\x6f\x9d\x93\xdf\x62";
uint8_t* const sha224_vector_6 = (uint8_t*)"\x55\xb2\x10\x07\x9c\x61\xb5\x3a\xdd\x52\x06\x22\xd1\xac\x97\xd5\xcd\xbe\x8c\xb3\x3a\xa0\xae\x34\x45\x17\xbe\xe4\xd7\xba\x09\xab"
"\xc8\x53\x3c\x52\x50\x88\x7a\x43\xbe\xbb\xac\x90\x6c\x2e\x18\x37\xf2\x6b\x36\xa5\x9a\xe3\xbe\x78\x14\xd5\x06\x89\x6b\x71\x8b\x2a"
"\x38\x3e\xcd\xac\x16\xb9\x61\x25\x55\x3f\x41\x6f\xf3\x2c\x66\x74\xc7\x45\x99\xa9\x00\x53\x86\xd9\xce\x11\x12\x24\x5f\x48\xee\x47"
"\x0d\x39\x6c\x1e\xd6\x3b\x92\x67\x0c\xa5\x6e\xc8\x4d\xee\xa8\x14\xb6\x13\x5e\xca\x54\x39\x2b\xde\xdb\x94\x89\xbc\x9b\x87\x5a\x8b"
"\xaf\x0d\xc1\xae\x78\x57\x36\x91\x4a\xb7\xda\xa2\x64\xbc\x07\x9d\x26\x9f\x2c\x0d\x7e\xdd\xd8\x10\xa4\x26\x14\x5a\x07\x76\xf6\x7c"
"\x87\x82\x73";

uint8_t* const sha224_digest_1 = (uint8_t*)"\x23\x09\x7d\x22\x34\x05\xd8\x22\x86\x42\xa4\x77\xbd\xa2\x55\xb3\x2a\xad\xbc\xe4\xbd\xa0\xb3\xf7\xe3\x6c\x9d\xa7";
uint8_t* const sha224_digest_2 = (uint8_t*)"\x75\x38\x8b\x16\x51\x27\x76\xcc\x5d\xba\x5d\xa1\xfd\x89\x01\x50\xb0\xc6\x45\x5c\xb4\xf5\x8b\x19\x52\x52\x25\x25";
uint8_t* const sha224_digest_3 = (uint8_t*)"\x20\x79\x46\x55\x98\x0c\x91\xd8\xbb\xb4\xc1\xea\x97\x61\x8a\x4b\xf0\x3f\x42\x58\x19\x48\xb2\xee\x4e\xe7\xad\x67";
uint8_t* const sha224_digest_4 = (uint8_t*)"\x00\xec\xd5\xf1\x38\x42\x2b\x8a\xd7\x4c\x97\x99\xfd\x82\x6c\x53\x1b\xad\x2f\xca\xbc\x74\x50\xbe\xe2\xaa\x8c\x2a";
uint8_t* const sha224_digest_5 = (uint8_t*)"\xdf\x90\xd7\x8a\xa7\x88\x21\xc9\x9b\x40\xba\x4c\x96\x69\x21\xac\xcd\x8f\xfb\x1e\x98\xac\x38\x8e\x56\x19\x1d\xb1";
uint8_t* const sha224_digest_6 = (uint8_t*)"\x0b\x31\x89\x4e\xc8\x93\x7a\xd9\xb9\x1b\xdf\xbc\xba\x29\x4d\x9a\xde\xfa\xa1\x8e\x09\x30\x5e\x9f\x20\xd5\xc3\xa4";

DIGESTTEST sha224_tests[] = {
    { "SHA224", 6, sha224_vector_1, sha224_digest_1, 3, 1 },
    { "SHA224", 6, sha224_vector_2, sha224_digest_2, 56, 1 },
    { "SHA224", 6, sha224_vector_3, sha224_digest_3, 100, 10000 },
    { "SHA224", 6, sha224_vector_4, sha224_digest_4, 1, 1 },
    { "SHA224", 6, sha224_vector_5, sha224_digest_5, 16, 1 },
    { "SHA224", 6, sha224_vector_6, sha224_digest_6, 163, 1 }
};

// SHA512 test vectors 1-3: FIPS pub 180-2 appendix C examples 1-3
// SHA512 test vectors 4-6: NIST pub SHAVS appendix E.1 examples 2, 4 and appendix E.2 example 2

uint8_t* const sha512_vector_1 = (uint8_t*)"abc";
uint8_t* const sha512_vector_2 = (uint8_t*)"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
uint8_t* const sha512_vector_3 = (uint8_t*)"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
uint8_t* const sha512_vector_4 = (uint8_t*)"\xd0";
uint8_t* const sha512_vector_5 = (uint8_t*)"\x8d\x4e\x3c\x0e\x38\x89\x19\x14\x91\x81\x6e\x9d\x98\xbf\xf0\xa0";
uint8_t* const sha512_vector_6 = (uint8_t*)"\xa5\x5f\x20\xc4\x11\xaa\xd1\x32\x80\x7a\x50\x2d\x65\x82\x4e\x31\xa2\x30\x54\x32\xaa\x3d\x06\xd3\xe2\x82\xa8\xd8\x4e\x0d\xe1\xde"
"\x69\x74\xbf\x49\x54\x69\xfc\x7f\x33\x8f\x80\x54\xd5\x8c\x26\xc4\x93\x60\xc3\xe8\x7a\xf5\x65\x23\xac\xf6\xd8\x9d\x03\xe5\x6f\xf2"
"\xf8\x68\x00\x2b\xc3\xe4\x31\xed\xc4\x4d\xf2\xf0\x22\x3d\x4b\xb3\xb2\x43\x58\x6e\x1a\x7d\x92\x49\x36\x69\x4f\xcb\xba\xf8\x8d\x95"
"\x19\xe4\xeb\x50\xa6\x44\xf8\xe4\xf9\x5e\xb0\xea\x95\xbc\x44\x65\xc8\x82\x1a\xac\xd2\xfe\x15\xab\x49\x81\x16\x4b\xbb\x6d\xc3\x2f"
"\x96\x90\x87\xa1\x45\xb0\xd9\xcc\x9c\x67\xc2\x2b\x76\x32\x99\x41\x9c\xc4\x12\x8b\xe9\xa0\x77\xb3\xac\xe6\x34\x06\x4e\x6d\x99\x28"
"\x35\x13\xdc\x06\xe7\x51\x5d\x0d\x73\x13\x2e\x9a\x0d\xc6\xd3\xb1\xf8\xb2\x46\xf1\xa9\x8a\x3f\xc7\x29\x41\xb1\xe3\xbb\x20\x98\xe8"
"\xbf\x16\xf2\x68\xd6\x4f\x0b\x0f\x47\x07\xfe\x1e\xa1\xa1\x79\x1b\xa2\xf3\xc0\xc7\x58\xe5\xf5\x51\x86\x3a\x96\xc9\x49\xad\x47\xd7"
"\xfb\x40\xd2";

uint8_t* const sha512_digest_1 = (uint8_t*)"\xdd\xaf\x35\xa1\x93\x61\x7a\xba\xcc\x41\x73\x49\xae\x20\x41\x31\x12\xe6\xfa\x4e\x89\xa9\x7e\xa2\x0a\x9e\xee\xe6\x4b\x55\xd3\x9a"
"\x21\x92\x99\x2a\x27\x4f\xc1\xa8\x36\xba\x3c\x23\xa3\xfe\xeb\xbd\x45\x4d\x44\x23\x64\x3c\xe8\x0e\x2a\x9a\xc9\x4f\xa5\x4c\xa4\x9f";
uint8_t* const sha512_digest_2 = (uint8_t*)"\x8e\x95\x9b\x75\xda\xe3\x13\xda\x8c\xf4\xf7\x28\x14\xfc\x14\x3f\x8f\x77\x79\xc6\xeb\x9f\x7f\xa1\x72\x99\xae\xad\xb6\x88\x90\x18"
"\x50\x1d\x28\x9e\x49\x00\xf7\xe4\x33\x1b\x99\xde\xc4\xb5\x43\x3a\xc7\xd3\x29\xee\xb6\xdd\x26\x54\x5e\x96\xe5\x5b\x87\x4b\xe9\x09";
uint8_t* const sha512_digest_3 = (uint8_t*)"\xe7\x18\x48\x3d\x0c\xe7\x69\x64\x4e\x2e\x42\xc7\xbc\x15\xb4\x63\x8e\x1f\x98\xb1\x3b\x20\x44\x28\x56\x32\xa8\x03\xaf\xa9\x73\xeb"
"\xde\x0f\xf2\x44\x87\x7e\xa6\x0a\x4c\xb0\x43\x2c\xe5\x77\xc3\x1b\xeb\x00\x9c\x5c\x2c\x49\xaa\x2e\x4e\xad\xb2\x17\xad\x8c\xc0\x9b";
uint8_t* const sha512_digest_4 = (uint8_t*)"\x99\x92\x20\x29\x38\xe8\x82\xe7\x3e\x20\xf6\xb6\x9e\x68\xa0\xa7\x14\x90\x90\x42\x3d\x93\xc8\x1b\xab\x3f\x21\x67\x8d\x4a\xce\xee"
"\xe5\x0e\x4e\x8c\xaf\xad\xa4\xc8\x5a\x54\xea\x83\x06\x82\x6c\x4a\xd6\xe7\x4c\xec\xe9\x63\x1b\xfa\x8a\x54\x9b\x4a\xb3\xfb\xba\x15";
uint8_t* const sha512_digest_5 = (uint8_t*)"\xcb\x0b\x67\xa4\xb8\x71\x2c\xd7\x3c\x9a\xab\xc0\xb1\x99\xe9\x26\x9b\x20\x84\x4a\xfb\x75\xac\xbd\xd1\xc1\x53\xc9\x82\x89\x24\xc3"
"\xdd\xed\xaa\xfe\x66\x9c\x5f\xdd\x0b\xc6\x6f\x63\x0f\x67\x73\x98\x82\x13\xeb\x1b\x16\xf5\x17\xad\x0d\xe4\xb2\xf0\xc9\x5c\x90\xf8";
uint8_t* const sha512_digest_6 = (uint8_t*)"\xc6\x65\xbe\xfb\x36\xda\x18\x9d\x78\x82\x2d\x10\x52\x8c\xbf\x3b\x12\xb3\xee\xf7\x26\x03\x99\x09\xc1\xa1\x6a\x27\x0d\x48\x71\x93"
"\x77\x96\x6b\x95\x7a\x87\x8e\x72\x05\x84\x77\x9a\x62\x82\x5c\x18\xda\x26\x41\x5e\x49\xa7\x17\x6a\x89\x4e\x75\x10\xfd\x14\x51\xf5";

DIGESTTEST sha512_tests[] = {
    { "SHA512", 6, sha512_vector_1, sha512_digest_1, 3, 1 },
    { "SHA512", 6, sha512_vector_2, sha512_digest_2, 112, 1 },
    { "SHA512", 6, sha512_vector_3, sha512_digest_3, 100, 10000 },
    { "SHA512", 6, sha512_vector_4, sha512_digest_4, 1, 1 },
    { "SHA512", 6, sha512_vector_5, sha512_digest_5, 16, 1 },
    { "SHA512", 6, sha512_vector_6, sha512_digest_6, 227, 1 }
};

// SHA384 test vectors 1-3: FIPS pub 180-2 appendix D examples 1-3
// SHA384 test vectors 4-6: NIST pub SHAVS appendix D.1 examples 2, 4 and appendix D.2 example 2

uint8_t* const sha384_vector_1 = (uint8_t*)"abc";
uint8_t* const sha384_vector_2 = (uint8_t*)"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
uint8_t* const sha384_vector_3 = (uint8_t*)"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
uint8_t* const sha384_vector_4 = (uint8_t*)"\xb9";
uint8_t* const sha384_vector_5 = (uint8_t*)"\xa4\x1c\x49\x77\x79\xc0\x37\x5f\xf1\x0a\x7f\x4e\x08\x59\x17\x39";
uint8_t* const sha384_vector_6 = (uint8_t*)"\x39\x96\x69\xe2\x8f\x6b\x9c\x6d\xbc\xbb\x69\x12\xec\x10\xff\xcf\x74\x79\x03\x49\xb7\xdc\x8f\xbe\x4a\x8e\x7b\x3b\x56\x21\xdb\x0f"
"\x3e\x7d\xc8\x7f\x82\x32\x64\xbb\xe4\x0d\x18\x11\xc9\xea\x20\x61\xe1\xc8\x4a\xd1\x0a\x23\xfa\xc1\x72\x7e\x72\x02\xfc\x3f\x50\x42"
"\xe6\xbf\x58\xcb\xa8\xa2\x74\x6e\x1f\x64\xf9\xb9\xea\x35\x2c\x71\x15\x07\x05\x3c\xf4\xe5\x33\x9d\x52\x86\x5f\x25\xcc\x22\xb5\xe8"
"\x77\x84\xa1\x2f\xc9\x61\xd6\x6c\xb6\xe8\x95\x73\x19\x9a\x2c\xe6\x56\x5c\xbd\xf1\x3d\xca\x40\x38\x32\xcf\xcb\x0e\x8b\x72\x11\xe8"
"\x3a\xf3\x2a\x11\xac\x17\x92\x9f\xf1\xc0\x73\xa5\x1c\xc0\x27\xaa\xed\xef\xf8\x5a\xad\x7c\x2b\x7c\x5a\x80\x3e\x24\x04\xd9\x6d\x2a"
"\x77\x35\x7b\xda\x1a\x6d\xae\xed\x17\x15\x1c\xb9\xbc\x51\x25\xa4\x22\xe9\x41\xde\x0c\xa0\xfc\x50\x11\xc2\x3e\xcf\xfe\xfd\xd0\x96"
"\x76\x71\x1c\xf3\xdb\x0a\x34\x40\x72\x0e\x16\x15\xc1\xf2\x2f\xbc\x3c\x72\x1d\xe5\x21\xe1\xb9\x9b\xa1\xbd\x55\x77\x40\x86\x42\x14"
"\x7e\xd0\x96";

uint8_t* const sha384_digest_1 = (uint8_t*)"\xcb\x00\x75\x3f\x45\xa3\x5e\x8b\xb5\xa0\x3d\x69\x9a\xc6\x50\x07\x27\x2c\x32\xab\x0e\xde\xd1\x63\x1a\x8b\x60\x5a\x43\xff\x5b\xed"
"\x80\x86\x07\x2b\xa1\xe7\xcc\x23\x58\xba\xec\xa1\x34\xc8\x25\xa7";
uint8_t* const sha384_digest_2 = (uint8_t*)"\x09\x33\x0c\x33\xf7\x11\x47\xe8\x3d\x19\x2f\xc7\x82\xcd\x1b\x47\x53\x11\x1b\x17\x3b\x3b\x05\xd2\x2f\xa0\x80\x86\xe3\xb0\xf7\x12"
"\xfc\xc7\xc7\x1a\x55\x7e\x2d\xb9\x66\xc3\xe9\xfa\x91\x74\x60\x39";
uint8_t* const sha384_digest_3 = (uint8_t*)"\x9d\x0e\x18\x09\x71\x64\x74\xcb\x08\x6e\x83\x4e\x31\x0a\x4a\x1c\xed\x14\x9e\x9c\x00\xf2\x48\x52\x79\x72\xce\xc5\x70\x4c\x2a\x5b"
"\x07\xb8\xb3\xdc\x38\xec\xc4\xeb\xae\x97\xdd\xd8\x7f\x3d\x89\x85";
uint8_t* const sha384_digest_4 = (uint8_t*)"\xbc\x80\x89\xa1\x90\x07\xc0\xb1\x41\x95\xf4\xec\xc7\x40\x94\xfe\xc6\x4f\x01\xf9\x09\x29\x28\x2c\x2f\xb3\x92\x88\x15\x78\x20\x8a"
"\xd4\x66\x82\x8b\x1c\x6c\x28\x3d\x27\x22\xcf\x0a\xd1\xab\x69\x38";
uint8_t* const sha384_digest_5 = (uint8_t*)"\xc9\xa6\x84\x43\xa0\x05\x81\x22\x56\xb8\xec\x76\xb0\x05\x16\xf0\xdb\xb7\x4f\xab\x26\xd6\x65\x91\x3f\x19\x4b\x6f\xfb\x0e\x91\xea"
"\x99\x67\x56\x6b\x58\x10\x9c\xbc\x67\x5c\xc2\x08\xe4\xc8\x23\xf7";
uint8_t* const sha384_digest_6 = (uint8_t*)"\x4f\x44\x0d\xb1\xe6\xed\xd2\x89\x9f\xa3\x35\xf0\x95\x15\xaa\x02\x5e\xe1\x77\xa7\x9f\x4b\x4a\xaf\x38\xe4\x2b\x5c\x4d\xe6\x60\xf5"
"\xde\x8f\xb2\xa5\xb2\xfb\xd2\xa3\xcb\xff\xd2\x0c\xff\x12\x88\xc0";

DIGESTTEST sha384_tests[] = {
    { "SHA384", 6, sha384_vector_1, sha384_digest_1, 3, 1 },
    { "SHA384", 6, sha384_vector_2, sha384_digest_2, 112, 1 },
    { "SHA384", 6, sha384_vector_3, sha384_digest_3, 100, 10000 },
    { "SHA384", 6, sha384_vector_4, sha384_digest_4, 1, 1 },
    { "SHA384", 6, sha384_vector_5, sha384_digest_5, 16, 1 },
    { "SHA384", 6, sha384_vector_6, sha384_digest_6, 227, 1 }
};

// HMAC-MD5 test vectors: RFC 2202

uint8_t* hmac_md5_key_1 = (uint8_t*)"\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b";
uint8_t* hmac_md5_key_2 = (uint8_t*)"Jefe";
uint8_t* hmac_md5_key_3 = (uint8_t*)"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa";
uint8_t* hmac_md5_key_4 = (uint8_t*)"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19";
uint8_t* hmac_md5_key_5 = (uint8_t*)"\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c";
uint8_t* hmac_md5_key_6 = (uint8_t*)"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa";
uint8_t* hmac_md5_key_7 = (uint8_t*)"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa";

uint8_t* hmac_md5_data_1 = (uint8_t*)"Hi There";
uint8_t* hmac_md5_data_2 = (uint8_t*)"what do ya want for nothing?";
uint8_t* hmac_md5_data_3 = (uint8_t*)"\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd";
uint8_t* hmac_md5_data_4 = (uint8_t*)"\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd";
uint8_t* hmac_md5_data_5 = (uint8_t*)"Test With Truncation";
uint8_t* hmac_md5_data_6 = (uint8_t*)"Test Using Larger Than Block-Size Key - Hash Key First";
uint8_t* hmac_md5_data_7 = (uint8_t*)"Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data";

uint8_t* hmac_md5_digest_1 = (uint8_t*)"\x92\x94\x72\x7a\x36\x38\xbb\x1c\x13\xf4\x8e\xf8\x15\x8b\xfc\x9d";
uint8_t* hmac_md5_digest_2 = (uint8_t*)"\x75\x0c\x78\x3e\x6a\xb0\xb5\x03\xea\xa8\x6e\x31\x0a\x5d\xb7\x38";
uint8_t* hmac_md5_digest_3 = (uint8_t*)"\x56\xbe\x34\x52\x1d\x14\x4c\x88\xdb\xb8\xc7\x33\xf0\xe8\xb3\xf6";
uint8_t* hmac_md5_digest_4 = (uint8_t*)"\x69\x7e\xaf\x0a\xca\x3a\x3a\xea\x3a\x75\x16\x47\x46\xff\xaa\x79";
uint8_t* hmac_md5_digest_5 = (uint8_t*)"\x56\x46\x1e\xf2\x34\x2e\xdc\x00\xf9\xba\xb9\x95\x69\x0e\xfd\x4c";
uint8_t* hmac_md5_digest_6 = (uint8_t*)"\x6b\x1a\xb7\xfe\x4b\xd7\xbf\x8f\x0b\x62\xe6\xce\x61\xb9\xd0\xcd";
uint8_t* hmac_md5_digest_7 = (uint8_t*)"\x6f\x63\x0f\xad\x67\xcd\xa0\xee\x1f\xb1\xf5\x62\xdb\x3a\xa5\x3e";

HMACTEST hmac_md5_tests[] = {
    { "HMAC-MD5", 7, hmac_md5_key_1, 16, hmac_md5_data_1,  8, hmac_md5_digest_1, 16 },
    { "HMAC-MD5", 7, hmac_md5_key_2,  4, hmac_md5_data_2, 28, hmac_md5_digest_2, 16 },
    { "HMAC-MD5", 7, hmac_md5_key_3, 16, hmac_md5_data_3, 50, hmac_md5_digest_3, 16 },
    { "HMAC-MD5", 7, hmac_md5_key_4, 25, hmac_md5_data_4, 50, hmac_md5_digest_4, 16 },
    { "HMAC-MD5", 7, hmac_md5_key_5, 16, hmac_md5_data_5, 20, hmac_md5_digest_5, 16 },
    { "HMAC-MD5", 7, hmac_md5_key_6, 80, hmac_md5_data_6, 54, hmac_md5_digest_6, 16 },
    { "HMAC-MD5", 7, hmac_md5_key_7, 80, hmac_md5_data_7, 73, hmac_md5_digest_7, 16 }
};

// HMAC-SHA1 test vectors: RFC 2202

uint8_t* hmac_sha_key_1 = (uint8_t*)"\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b";
uint8_t* hmac_sha_key_2 = (uint8_t*)"Jefe";
uint8_t* hmac_sha_key_3 = (uint8_t*)"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa";
uint8_t* hmac_sha_key_4 = (uint8_t*)"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19";
uint8_t* hmac_sha_key_5 = (uint8_t*)"\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c";
uint8_t* hmac_sha_key_n = (uint8_t*)"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa";

uint8_t* hmac_sha_data_1 = (uint8_t*)"Hi There";
uint8_t* hmac_sha_data_2 = (uint8_t*)"what do ya want for nothing?";
uint8_t* hmac_sha_data_3 = (uint8_t*)"\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd";
uint8_t* hmac_sha_data_4 = (uint8_t*)"\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd";
uint8_t* hmac_sha_data_5 = (uint8_t*)"Test With Truncation";
uint8_t* hmac_sha_data_6 = (uint8_t*)"Test Using Larger Than Block-Size Key - Hash Key First";
uint8_t* hmac_sha_data_7 = (uint8_t*)"Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data";

uint8_t* hmac_sha1_digest_1 = (uint8_t*)"\xb6\x17\x31\x86\x55\x05\x72\x64\xe2\x8b\xc0\xb6\xfb\x37\x8c\x8e\xf1\x46\xbe\x00";
uint8_t* hmac_sha1_digest_2 = (uint8_t*)"\xef\xfc\xdf\x6a\xe5\xeb\x2f\xa2\xd2\x74\x16\xd5\xf1\x84\xdf\x9c\x25\x9a\x7c\x79";
uint8_t* hmac_sha1_digest_3 = (uint8_t*)"\x12\x5d\x73\x42\xb9\xac\x11\xcd\x91\xa3\x9a\xf4\x8a\xa1\x7b\x4f\x63\xf1\x75\xd3";
uint8_t* hmac_sha1_digest_4 = (uint8_t*)"\x4c\x90\x07\xf4\x02\x62\x50\xc6\xbc\x84\x14\xf9\xbf\x50\xc8\x6c\x2d\x72\x35\xda";
uint8_t* hmac_sha1_digest_5 = (uint8_t*)"\x4c\x1a\x03\x42\x4b\x55\xe0\x7f\xe7\xf2\x7b\xe1\xd5\x8b\xb9\x32\x4a\x9a\x5a\x04";
uint8_t* hmac_sha1_digest_6 = (uint8_t*)"\xaa\x4a\xe5\xe1\x52\x72\xd0\x0e\x95\x70\x56\x37\xce\x8a\x3b\x55\xed\x40\x21\x12";
uint8_t* hmac_sha1_digest_7 = (uint8_t*)"\xe8\xe9\x9d\x0f\x45\x23\x7d\x78\x6d\x6b\xba\xa7\x96\x5c\x78\x08\xbb\xff\x1a\x91";

HMACTEST hmac_sha1_tests[] = {
    { "HMAC-SHA1", 7, hmac_sha_key_1, 20, hmac_sha_data_1,  8, hmac_sha1_digest_1, 20 },
    { "HMAC-SHA1", 7, hmac_sha_key_2,  4, hmac_sha_data_2, 28, hmac_sha1_digest_2, 20 },
    { "HMAC-SHA1", 7, hmac_sha_key_3, 20, hmac_sha_data_3, 50, hmac_sha1_digest_3, 20 },
    { "HMAC-SHA1", 7, hmac_sha_key_4, 25, hmac_sha_data_4, 50, hmac_sha1_digest_4, 20 },
    { "HMAC-SHA1", 7, hmac_sha_key_5, 20, hmac_sha_data_5, 20, hmac_sha1_digest_5, 20 },
    { "HMAC-SHA1", 7, hmac_sha_key_n, 80, hmac_sha_data_6, 54, hmac_sha1_digest_6, 20 },
    { "HMAC-SHA1", 7, hmac_sha_key_n, 80, hmac_sha_data_7, 73, hmac_sha1_digest_7, 20 }
};

// HMAC-SHA256, 224, 512, 384 test vectors: RFC 4231

uint8_t* hmac_sha2_key_n = (uint8_t*)"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
"\xaa\xaa\xaa\xaa\xaa\xaa";

uint8_t* hmac_sha2_data_7 = (uint8_t*)"This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.";

uint8_t* hmac_sha256_digest_1 = (uint8_t*)"\xb0\x34\x4c\x61\xd8\xdb\x38\x53\x5c\xa8\xaf\xce\xaf\x0b\xf1\x2b\x88\x1d\xc2\x00\xc9\x83\x3d\xa7\x26\xe9\x37\x6c\x2e\x32\xcf\xf7";
uint8_t* hmac_sha256_digest_2 = (uint8_t*)"\x5b\xdc\xc1\x46\xbf\x60\x75\x4e\x6a\x04\x24\x26\x08\x95\x75\xc7\x5a\x00\x3f\x08\x9d\x27\x39\x83\x9d\xec\x58\xb9\x64\xec\x38\x43";
uint8_t* hmac_sha256_digest_3 = (uint8_t*)"\x77\x3e\xa9\x1e\x36\x80\x0e\x46\x85\x4d\xb8\xeb\xd0\x91\x81\xa7\x29\x59\x09\x8b\x3e\xf8\xc1\x22\xd9\x63\x55\x14\xce\xd5\x65\xfe";
uint8_t* hmac_sha256_digest_4 = (uint8_t*)"\x82\x55\x8a\x38\x9a\x44\x3c\x0e\xa4\xcc\x81\x98\x99\xf2\x08\x3a\x85\xf0\xfa\xa3\xe5\x78\xf8\x07\x7a\x2e\x3f\xf4\x67\x29\x66\x5b";
uint8_t* hmac_sha256_digest_5 = (uint8_t*)"\xa3\xb6\x16\x74\x73\x10\x0e\xe0\x6e\x0c\x79\x6c\x29\x55\x55\x2b";
uint8_t* hmac_sha256_digest_6 = (uint8_t*)"\x60\xe4\x31\x59\x1e\xe0\xb6\x7f\x0d\x8a\x26\xaa\xcb\xf5\xb7\x7f\x8e\x0b\xc6\x21\x37\x28\xc5\x14\x05\x46\x04\x0f\x0e\xe3\x7f\x54";
uint8_t* hmac_sha256_digest_7 = (uint8_t*)"\x9b\x09\xff\xa7\x1b\x94\x2f\xcb\x27\x63\x5f\xbc\xd5\xb0\xe9\x44\xbf\xdc\x63\x64\x4f\x07\x13\x93\x8a\x7f\x51\x53\x5c\x3a\x35\xe2";

HMACTEST hmac_sha256_tests[] = {
    { "HMAC-256", 7, hmac_sha_key_1,   20, hmac_sha_data_1,    8, hmac_sha256_digest_1, 32 },
    { "HMAC-256", 7, hmac_sha_key_2,    4, hmac_sha_data_2,   28, hmac_sha256_digest_2, 32  },
    { "HMAC-256", 7, hmac_sha_key_3,   20, hmac_sha_data_3,   50, hmac_sha256_digest_3, 32  },
    { "HMAC-256", 7, hmac_sha_key_4,   25, hmac_sha_data_4,   50, hmac_sha256_digest_4, 32  },
    { "HMAC-256", 7, hmac_sha_key_5,   20, hmac_sha_data_5,   20, hmac_sha256_digest_5, 16  },
    { "HMAC-256", 7, hmac_sha2_key_n, 131, hmac_sha_data_6,   54, hmac_sha256_digest_6, 32  },
    { "HMAC-256", 7, hmac_sha2_key_n, 131, hmac_sha2_data_7, 152, hmac_sha256_digest_7, 32  }
};

uint8_t* hmac_sha224_digest_1 = (uint8_t*)"\x89\x6f\xb1\x12\x8a\xbb\xdf\x19\x68\x32\x10\x7c\xd4\x9d\xf3\x3f\x47\xb4\xb1\x16\x99\x12\xba\x4f\x53\x68\x4b\x22";
uint8_t* hmac_sha224_digest_2 = (uint8_t*)"\xa3\x0e\x01\x09\x8b\xc6\xdb\xbf\x45\x69\x0f\x3a\x7e\x9e\x6d\x0f\x8b\xbe\xa2\xa3\x9e\x61\x48\x00\x8f\xd0\x5e\x44";
uint8_t* hmac_sha224_digest_3 = (uint8_t*)"\x7f\xb3\xcb\x35\x88\xc6\xc1\xf6\xff\xa9\x69\x4d\x7d\x6a\xd2\x64\x93\x65\xb0\xc1\xf6\x5d\x69\xd1\xec\x83\x33\xea";
uint8_t* hmac_sha224_digest_4 = (uint8_t*)"\x6c\x11\x50\x68\x74\x01\x3c\xac\x6a\x2a\xbc\x1b\xb3\x82\x62\x7c\xec\x6a\x90\xd8\x6e\xfc\x01\x2d\xe7\xaf\xec\x5a";
uint8_t* hmac_sha224_digest_5 = (uint8_t*)"\x0e\x2a\xea\x68\xa9\x0c\x8d\x37\xc9\x88\xbc\xdb\x9f\xca\x6f\xa8";
uint8_t* hmac_sha224_digest_6 = (uint8_t*)"\x95\xe9\xa0\xdb\x96\x20\x95\xad\xae\xbe\x9b\x2d\x6f\x0d\xbc\xe2\xd4\x99\xf1\x12\xf2\xd2\xb7\x27\x3f\xa6\x87\x0e";
uint8_t* hmac_sha224_digest_7 = (uint8_t*)"\x3a\x85\x41\x66\xac\x5d\x9f\x02\x3f\x54\xd5\x17\xd0\xb3\x9d\xbd\x94\x67\x70\xdb\x9c\x2b\x95\xc9\xf6\xf5\x65\xd1";

HMACTEST hmac_sha224_tests[] = {
    { "HMAC-224", 7, hmac_sha_key_1,   20, hmac_sha_data_1,    8, hmac_sha224_digest_1, 28 },
    { "HMAC-224", 7, hmac_sha_key_2,    4, hmac_sha_data_2,   28, hmac_sha224_digest_2, 28 },
    { "HMAC-224", 7, hmac_sha_key_3,   20, hmac_sha_data_3,   50, hmac_sha224_digest_3, 28 },
    { "HMAC-224", 7, hmac_sha_key_4,   25, hmac_sha_data_4,   50, hmac_sha224_digest_4, 28 },
    { "HMAC-224", 7, hmac_sha_key_5,   20, hmac_sha_data_5,   20, hmac_sha224_digest_5, 16 },
    { "HMAC-224", 7, hmac_sha2_key_n, 131, hmac_sha_data_6,   54, hmac_sha224_digest_6, 28 },
    { "HMAC-224", 7, hmac_sha2_key_n, 131, hmac_sha2_data_7, 152, hmac_sha224_digest_7, 28 }
};

uint8_t* hmac_sha512_digest_1 = (uint8_t*)"\x87\xaa\x7c\xde\xa5\xef\x61\x9d\x4f\xf0\xb4\x24\x1a\x1d\x6c\xb0\x23\x79\xf4\xe2\xce\x4e\xc2\x78\x7a\xd0\xb3\x05\x45\xe1\x7c\xde\xda\xa8\x33\xb7\xd6\xb8\xa7\x02\x03\x8b\x27\x4e\xae\xa3\xf4\xe4\xbe\x9d\x91\x4e\xeb\x61\xf1\x70\x2e\x69\x6c\x20\x3a\x12\x68\x54";
uint8_t* hmac_sha512_digest_2 = (uint8_t*)"\x16\x4b\x7a\x7b\xfc\xf8\x19\xe2\xe3\x95\xfb\xe7\x3b\x56\xe0\xa3\x87\xbd\x64\x22\x2e\x83\x1f\xd6\x10\x27\x0c\xd7\xea\x25\x05\x54\x97\x58\xbf\x75\xc0\x5a\x99\x4a\x6d\x03\x4f\x65\xf8\xf0\xe6\xfd\xca\xea\xb1\xa3\x4d\x4a\x6b\x4b\x63\x6e\x07\x0a\x38\xbc\xe7\x37";
uint8_t* hmac_sha512_digest_3 = (uint8_t*)"\xfa\x73\xb0\x08\x9d\x56\xa2\x84\xef\xb0\xf0\x75\x6c\x89\x0b\xe9\xb1\xb5\xdb\xdd\x8e\xe8\x1a\x36\x55\xf8\x3e\x33\xb2\x27\x9d\x39\xbf\x3e\x84\x82\x79\xa7\x22\xc8\x06\xb4\x85\xa4\x7e\x67\xc8\x07\xb9\x46\xa3\x37\xbe\xe8\x94\x26\x74\x27\x88\x59\xe1\x32\x92\xfb";
uint8_t* hmac_sha512_digest_4 = (uint8_t*)"\xb0\xba\x46\x56\x37\x45\x8c\x69\x90\xe5\xa8\xc5\xf6\x1d\x4a\xf7\xe5\x76\xd9\x7f\xf9\x4b\x87\x2d\xe7\x6f\x80\x50\x36\x1e\xe3\xdb\xa9\x1c\xa5\xc1\x1a\xa2\x5e\xb4\xd6\x79\x27\x5c\xc5\x78\x80\x63\xa5\xf1\x97\x41\x12\x0c\x4f\x2d\xe2\xad\xeb\xeb\x10\xa2\x98\xdd";
uint8_t* hmac_sha512_digest_5 = (uint8_t*)"\x41\x5f\xad\x62\x71\x58\x0a\x53\x1d\x41\x79\xbc\x89\x1d\x87\xa6";
uint8_t* hmac_sha512_digest_6 = (uint8_t*)"\x80\xb2\x42\x63\xc7\xc1\xa3\xeb\xb7\x14\x93\xc1\xdd\x7b\xe8\xb4\x9b\x46\xd1\xf4\x1b\x4a\xee\xc1\x12\x1b\x01\x37\x83\xf8\xf3\x52\x6b\x56\xd0\x37\xe0\x5f\x25\x98\xbd\x0f\xd2\x21\x5d\x6a\x1e\x52\x95\xe6\x4f\x73\xf6\x3f\x0a\xec\x8b\x91\x5a\x98\x5d\x78\x65\x98";
uint8_t* hmac_sha512_digest_7 = (uint8_t*)"\xe3\x7b\x6a\x77\x5d\xc8\x7d\xba\xa4\xdf\xa9\xf9\x6e\x5e\x3f\xfd\xde\xbd\x71\xf8\x86\x72\x89\x86\x5d\xf5\xa3\x2d\x20\xcd\xc9\x44\xb6\x02\x2c\xac\x3c\x49\x82\xb1\x0d\x5e\xeb\x55\xc3\xe4\xde\x15\x13\x46\x76\xfb\x6d\xe0\x44\x60\x65\xc9\x74\x40\xfa\x8c\x6a\x58";

HMACTEST hmac_sha512_tests[] = {
    { "HMAC-512", 7, hmac_sha_key_1,   20, hmac_sha_data_1,    8, hmac_sha512_digest_1, 64 },
    { "HMAC-512", 7, hmac_sha_key_2,    4, hmac_sha_data_2,   28, hmac_sha512_digest_2, 64 },
    { "HMAC-512", 7, hmac_sha_key_3,   20, hmac_sha_data_3,   50, hmac_sha512_digest_3, 64 },
    { "HMAC-512", 7, hmac_sha_key_4,   25, hmac_sha_data_4,   50, hmac_sha512_digest_4, 64 },
    { "HMAC-512", 7, hmac_sha_key_5,   20, hmac_sha_data_5,   20, hmac_sha512_digest_5, 16 },
    { "HMAC-512", 7, hmac_sha2_key_n, 131, hmac_sha_data_6,   54, hmac_sha512_digest_6, 64 },
    { "HMAC-512", 7, hmac_sha2_key_n, 131, hmac_sha2_data_7, 152, hmac_sha512_digest_7, 64 }
};

uint8_t* hmac_sha384_digest_1 = (uint8_t*)"\xaf\xd0\x39\x44\xd8\x48\x95\x62\x6b\x08\x25\xf4\xab\x46\x90\x7f\x15\xf9\xda\xdb\xe4\x10\x1e\xc6\x82\xaa\x03\x4c\x7c\xeb\xc5\x9c\xfa\xea\x9e\xa9\x07\x6e\xde\x7f\x4a\xf1\x52\xe8\xb2\xfa\x9c\xb6";
uint8_t* hmac_sha384_digest_2 = (uint8_t*)"\xaf\x45\xd2\xe3\x76\x48\x40\x31\x61\x7f\x78\xd2\xb5\x8a\x6b\x1b\x9c\x7e\xf4\x64\xf5\xa0\x1b\x47\xe4\x2e\xc3\x73\x63\x22\x44\x5e\x8e\x22\x40\xca\x5e\x69\xe2\xc7\x8b\x32\x39\xec\xfa\xb2\x16\x49";
uint8_t* hmac_sha384_digest_3 = (uint8_t*)"\x88\x06\x26\x08\xd3\xe6\xad\x8a\x0a\xa2\xac\xe0\x14\xc8\xa8\x6f\x0a\xa6\x35\xd9\x47\xac\x9f\xeb\xe8\x3e\xf4\xe5\x59\x66\x14\x4b\x2a\x5a\xb3\x9d\xc1\x38\x14\xb9\x4e\x3a\xb6\xe1\x01\xa3\x4f\x27";
uint8_t* hmac_sha384_digest_4 = (uint8_t*)"\x3e\x8a\x69\xb7\x78\x3c\x25\x85\x19\x33\xab\x62\x90\xaf\x6c\xa7\x7a\x99\x81\x48\x08\x50\x00\x9c\xc5\x57\x7c\x6e\x1f\x57\x3b\x4e\x68\x01\xdd\x23\xc4\xa7\xd6\x79\xcc\xf8\xa3\x86\xc6\x74\xcf\xfb";
uint8_t* hmac_sha384_digest_5 = (uint8_t*)"\x3a\xbf\x34\xc3\x50\x3b\x2a\x23\xa4\x6e\xfc\x61\x9b\xae\xf8\x97";
uint8_t* hmac_sha384_digest_6 = (uint8_t*)"\x4e\xce\x08\x44\x85\x81\x3e\x90\x88\xd2\xc6\x3a\x04\x1b\xc5\xb4\x4f\x9e\xf1\x01\x2a\x2b\x58\x8f\x3c\xd1\x1f\x05\x03\x3a\xc4\xc6\x0c\x2e\xf6\xab\x40\x30\xfe\x82\x96\x24\x8d\xf1\x63\xf4\x49\x52";
uint8_t* hmac_sha384_digest_7 = (uint8_t*)"\x66\x17\x17\x8e\x94\x1f\x02\x0d\x35\x1e\x2f\x25\x4e\x8f\xd3\x2c\x60\x24\x20\xfe\xb0\xb8\xfb\x9a\xdc\xce\xbb\x82\x46\x1e\x99\xc5\xa6\x78\xcc\x31\xe7\x99\x17\x6d\x38\x60\xe6\x11\x0c\x46\x52\x3e";

HMACTEST hmac_sha384_tests[] = {
    { "HMAC-384", 7, hmac_sha_key_1,   20, hmac_sha_data_1,    8, hmac_sha384_digest_1, 48 },
    { "HMAC-384", 7, hmac_sha_key_2,    4, hmac_sha_data_2,   28, hmac_sha384_digest_2, 48 },
    { "HMAC-384", 7, hmac_sha_key_3,   20, hmac_sha_data_3,   50, hmac_sha384_digest_3, 48 },
    { "HMAC-384", 7, hmac_sha_key_4,   25, hmac_sha_data_4,   50, hmac_sha384_digest_4, 48 },
    { "HMAC-384", 7, hmac_sha_key_5,   20, hmac_sha_data_5,   20, hmac_sha384_digest_5, 16 },
    { "HMAC-384", 7, hmac_sha2_key_n, 131, hmac_sha_data_6,   54, hmac_sha384_digest_6, 48 },
    { "HMAC-384", 7, hmac_sha2_key_n, 131, hmac_sha2_data_7, 152, hmac_sha384_digest_7, 48 }
};

// DES-ECB variable plaintext test vectors

uint8_t* desecb_vp_key = (uint8_t*)"\x01\x01\x01\x01\x01\x01\x01\x01";

uint8_t* desecb_vp_plain_1 = (uint8_t*)"\x80\x00\x00\x00\x00\x00\x00\x00";
uint8_t* desecb_vp_plain_2 = (uint8_t*)"\x40\x00\x00\x00\x00\x00\x00\x00";
uint8_t* desecb_vp_plain_3 = (uint8_t*)"\x20\x00\x00\x00\x00\x00\x00\x00";
uint8_t* desecb_vp_plain_4 = (uint8_t*)"\x10\x00\x00\x00\x00\x00\x00\x00";

uint8_t* desecb_vp_cipher_1 = (uint8_t*)"\x95\xF8\xA5\xE5\xDD\x31\xD9\x00";
uint8_t* desecb_vp_cipher_2 = (uint8_t*)"\xDD\x7F\x12\x1C\xA5\x01\x56\x19";
uint8_t* desecb_vp_cipher_3 = (uint8_t*)"\x2E\x86\x53\x10\x4F\x38\x34\xEA";
uint8_t* desecb_vp_cipher_4 = (uint8_t*)"\x4B\xD3\x88\xFF\x6C\xD8\x1D\x4F";

CIPHERTEST desecb_vp_tests[] = {
    { "DES-ECB Variable Plaintext", 4, desecb_vp_key, nullptr, desecb_vp_plain_1, desecb_vp_cipher_1, des::recsize },
    { "DES-ECB Variable Plaintext", 4, desecb_vp_key, nullptr, desecb_vp_plain_2, desecb_vp_cipher_2, des::recsize },
    { "DES-ECB Variable Plaintext", 4, desecb_vp_key, nullptr, desecb_vp_plain_3, desecb_vp_cipher_3, des::recsize },
    { "DES-ECB Variable Plaintext", 4, desecb_vp_key, nullptr, desecb_vp_plain_4, desecb_vp_cipher_4, des::recsize }
};

// DES-ECB inverse permutation test vectors

uint8_t* desecb_ip_key = (uint8_t*)"\x01\x01\x01\x01\x01\x01\x01\x01";

uint8_t* desecb_ip_plain_1 = (uint8_t*)"\x2B\x9F\x98\x2F\x20\x03\x7F\xA9";
uint8_t* desecb_ip_plain_2 = (uint8_t*)"\x88\x9D\xE0\x68\xA1\x6F\x0B\xE6";
uint8_t* desecb_ip_plain_3 = (uint8_t*)"\xE1\x9E\x27\x5D\x84\x6A\x12\x98";
uint8_t* desecb_ip_plain_4 = (uint8_t*)"\x32\x9A\x8E\xD5\x23\xD7\x1A\xEC";

uint8_t* desecb_ip_cipher_1 = (uint8_t*)"\x00\x00\x80\x00\x00\x00\x00\x00";
uint8_t* desecb_ip_cipher_2 = (uint8_t*)"\x00\x00\x40\x00\x00\x00\x00\x00";
uint8_t* desecb_ip_cipher_3 = (uint8_t*)"\x00\x00\x20\x00\x00\x00\x00\x00";
uint8_t* desecb_ip_cipher_4 = (uint8_t*)"\x00\x00\x10\x00\x00\x00\x00\x00";

CIPHERTEST desecb_ip_tests[] = {
    { "DES-ECB Inverse Permutation", 4, desecb_ip_key, nullptr, desecb_ip_plain_1, desecb_ip_cipher_1, des::recsize },
    { "DES-ECB Inverse Permutation", 4, desecb_ip_key, nullptr, desecb_ip_plain_2, desecb_ip_cipher_2, des::recsize },
    { "DES-ECB Inverse Permutation", 4, desecb_ip_key, nullptr, desecb_ip_plain_3, desecb_ip_cipher_3, des::recsize },
    { "DES-ECB Inverse Permutation", 4, desecb_ip_key, nullptr, desecb_ip_plain_4, desecb_ip_cipher_4, des::recsize }
};

// DES-ECB variable key test vectors

uint8_t* desecb_vk_key_1 = (uint8_t*)"\x80\x01\x01\x01\x01\x01\x01\x01";
uint8_t* desecb_vk_key_2 = (uint8_t*)"\x40\x01\x01\x01\x01\x01\x01\x01";
uint8_t* desecb_vk_key_3 = (uint8_t*)"\x20\x01\x01\x01\x01\x01\x01\x01";
uint8_t* desecb_vk_key_4 = (uint8_t*)"\x10\x01\x01\x01\x01\x01\x01\x01";

uint8_t* desecb_vk_plain = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00";

uint8_t* desecb_vk_cipher_1 = (uint8_t*)"\x95\xA8\xD7\x28\x13\xDA\xA9\x4D";
uint8_t* desecb_vk_cipher_2 = (uint8_t*)"\x0E\xEC\x14\x87\xDD\x8C\x26\xD5";
uint8_t* desecb_vk_cipher_3 = (uint8_t*)"\x7A\xD1\x6F\xFB\x79\xC4\x59\x26";
uint8_t* desecb_vk_cipher_4 = (uint8_t*)"\xD3\x74\x62\x94\xCA\x6A\x6C\xF3";

CIPHERTEST desecb_vk_tests[] = {
    { "DES-ECB Variable Key", 4, desecb_vk_key_1, nullptr, desecb_vk_plain, desecb_vk_cipher_1, des::recsize },
    { "DES-ECB Variable Key", 4, desecb_vk_key_2, nullptr, desecb_vk_plain, desecb_vk_cipher_2, des::recsize },
    { "DES-ECB Variable Key", 4, desecb_vk_key_3, nullptr, desecb_vk_plain, desecb_vk_cipher_3, des::recsize },
    { "DES-ECB Variable Key", 4, desecb_vk_key_4, nullptr, desecb_vk_plain, desecb_vk_cipher_4, des::recsize }
};

// DES-ECB permutation operation test vectors

uint8_t* desecb_po_key_1 = (uint8_t*)"\x10\x46\x91\x34\x89\x98\x01\x31";
uint8_t* desecb_po_key_2 = (uint8_t*)"\x10\x07\x10\x34\x89\x98\x80\x20";
uint8_t* desecb_po_key_3 = (uint8_t*)"\x10\x07\x10\x34\xC8\x98\x01\x20";
uint8_t* desecb_po_key_4 = (uint8_t*)"\x10\x46\x10\x34\x89\x98\x80\x20";

uint8_t* desecb_po_plain = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00";

uint8_t* desecb_po_cipher_1 = (uint8_t*)"\x88\xD5\x5E\x54\xF5\x4C\x97\xB4";
uint8_t* desecb_po_cipher_2 = (uint8_t*)"\x0C\x0C\xC0\x0C\x83\xEA\x48\xFD";
uint8_t* desecb_po_cipher_3 = (uint8_t*)"\x83\xBC\x8E\xF3\xA6\x57\x01\x83";
uint8_t* desecb_po_cipher_4 = (uint8_t*)"\xDF\x72\x5D\xCA\xD9\x4E\xA2\xE9";

CIPHERTEST desecb_po_tests[] = {
    { "DES-ECB Permutation Operation", 4, desecb_po_key_1, nullptr, desecb_po_plain, desecb_po_cipher_1, des::recsize },
    { "DES-ECB Permutation Operation", 4, desecb_po_key_2, nullptr, desecb_po_plain, desecb_po_cipher_2, des::recsize },
    { "DES-ECB Permutation Operation", 4, desecb_po_key_3, nullptr, desecb_po_plain, desecb_po_cipher_3, des::recsize },
    { "DES-ECB Permutaiton Operation", 4, desecb_po_key_4, nullptr, desecb_po_plain, desecb_po_cipher_4, des::recsize }
};

// DES-ECB substitution table test vectors

uint8_t* desecb_st_key_1 = (uint8_t*)"\x7C\xA1\x10\x45\x4A\x1A\x6E\x57";
uint8_t* desecb_st_key_2 = (uint8_t*)"\x01\x31\xD9\x61\x9D\xC1\x37\x6E";
uint8_t* desecb_st_key_3 = (uint8_t*)"\x07\xA1\x13\x3E\x4A\x0B\x26\x86";
uint8_t* desecb_st_key_4 = (uint8_t*)"\x38\x49\x67\x4C\x26\x02\x31\x9E";

uint8_t* desecb_st_plain_1 = (uint8_t*)"\x01\xA1\xD6\xD0\x39\x77\x67\x42";
uint8_t* desecb_st_plain_2 = (uint8_t*)"\x5C\xD5\x4C\xA8\x3D\xEF\x57\xDA";
uint8_t* desecb_st_plain_3 = (uint8_t*)"\x02\x48\xD4\x38\x06\xF6\x71\x72";
uint8_t* desecb_st_plain_4 = (uint8_t*)"\x51\x45\x4B\x58\x2D\xDF\x44\x0A";

uint8_t* desecb_st_cipher_1 = (uint8_t*)"\x69\x0F\x5B\x0D\x9A\x26\x93\x9B";
uint8_t* desecb_st_cipher_2 = (uint8_t*)"\x7A\x38\x9D\x10\x35\x4B\xD2\x71";
uint8_t* desecb_st_cipher_3 = (uint8_t*)"\x86\x8E\xBB\x51\xCA\xB4\x59\x9A";
uint8_t* desecb_st_cipher_4 = (uint8_t*)"\x71\x78\x87\x6E\x01\xF1\x9B\x2A";

CIPHERTEST desecb_st_tests[] = {
    { "DES-ECB Substitution Table", 4, desecb_st_key_1, nullptr, desecb_st_plain_1, desecb_st_cipher_1, des::recsize },
    { "DES-ECB Substitution Table", 4, desecb_st_key_2, nullptr, desecb_st_plain_2, desecb_st_cipher_2, des::recsize },
    { "DES-ECB Substitution Table", 4, desecb_st_key_3, nullptr, desecb_st_plain_3, desecb_st_cipher_3, des::recsize },
    { "DES-ECB Substitution Table", 4, desecb_st_key_4, nullptr, desecb_st_plain_4, desecb_st_cipher_4, des::recsize }
};

// DES-CBC variable plaintext test vectors

uint8_t* descbc_vp_key = (uint8_t*)"\x01\x01\x01\x01\x01\x01\x01\x01";

uint8_t* descbc_vp_iv = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00";

uint8_t* descbc_vp_plain_1 = (uint8_t*)"\x08\x00\x00\x00\x00\x00\x00\x00";
uint8_t* descbc_vp_plain_2 = (uint8_t*)"\x04\x00\x00\x00\x00\x00\x00\x00";
uint8_t* descbc_vp_plain_3 = (uint8_t*)"\x02\x00\x00\x00\x00\x00\x00\x00";
uint8_t* descbc_vp_plain_4 = (uint8_t*)"\x01\x00\x00\x00\x00\x00\x00\x00";

uint8_t* descbc_vp_cipher_1 = (uint8_t*)"\x20\xB9\xE7\x67\xB2\xFB\x14\x56";
uint8_t* descbc_vp_cipher_2 = (uint8_t*)"\x55\x57\x93\x80\xD7\x71\x38\xEF";
uint8_t* descbc_vp_cipher_3 = (uint8_t*)"\x6C\xC5\xDE\xFA\xAF\x04\x51\x2F";
uint8_t* descbc_vp_cipher_4 = (uint8_t*)"\x0D\x9F\x27\x9B\xA5\xD8\x72\x60";

CIPHERTEST descbc_vp_tests[] = {
    { "DES-CBC Variable Plaintext", 4, descbc_vp_key, descbc_vp_iv, descbc_vp_plain_1, descbc_vp_cipher_1, des::recsize },
    { "DES-CBC Variable Plaintext", 4, descbc_vp_key, descbc_vp_iv, descbc_vp_plain_2, descbc_vp_cipher_2, des::recsize },
    { "DES-CBC Variable Plaintext", 4, descbc_vp_key, descbc_vp_iv, descbc_vp_plain_3, descbc_vp_cipher_3, des::recsize },
    { "DES-CBC Variable Plaintext", 4, descbc_vp_key, descbc_vp_iv, descbc_vp_plain_4, descbc_vp_cipher_4, des::recsize }
};

// DES-CBC inverse permutation test vectors

uint8_t* descbc_ip_key = (uint8_t*)"\x01\x01\x01\x01\x01\x01\x01\x01";

uint8_t* descbc_ip_iv = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00";

uint8_t* descbc_ip_plain_1 = (uint8_t*)"\xE7\xFC\xE2\x25\x57\xD2\x3C\x97";
uint8_t* descbc_ip_plain_2 = (uint8_t*)"\x12\xA9\xF5\x81\x7F\xF2\xD6\x5D";
uint8_t* descbc_ip_plain_3 = (uint8_t*)"\xA4\x84\xC3\xAD\x38\xDC\x9C\x19";
uint8_t* descbc_ip_plain_4 = (uint8_t*)"\xFB\xE0\x0A\x8A\x1E\xF8\xAD\x72";

uint8_t* descbc_ip_cipher_1 = (uint8_t*)"\x00\x00\x08\x00\x00\x00\x00\x00";
uint8_t* descbc_ip_cipher_2 = (uint8_t*)"\x00\x00\x04\x00\x00\x00\x00\x00";
uint8_t* descbc_ip_cipher_3 = (uint8_t*)"\x00\x00\x02\x00\x00\x00\x00\x00";
uint8_t* descbc_ip_cipher_4 = (uint8_t*)"\x00\x00\x01\x00\x00\x00\x00\x00";

CIPHERTEST descbc_ip_tests[] = {
    { "DES-CBC Inverse Permutation", 4, descbc_ip_key, descbc_ip_iv, descbc_ip_plain_1, descbc_ip_cipher_1, des::recsize },
    { "DES-CBC Inverse Permutation", 4, descbc_ip_key, descbc_ip_iv, descbc_ip_plain_2, descbc_ip_cipher_2, des::recsize },
    { "DES-CBC Inverse Permutation", 4, descbc_ip_key, descbc_ip_iv, descbc_ip_plain_3, descbc_ip_cipher_3, des::recsize },
    { "DES-CBC Inverse Permutation", 4, descbc_ip_key, descbc_ip_iv, descbc_ip_plain_4, descbc_ip_cipher_4, des::recsize }
};

// DES-CBC variable key test vectors

uint8_t* descbc_vk_key_1 = (uint8_t*)"\x08\x01\x01\x01\x01\x01\x01\x01";
uint8_t* descbc_vk_key_2 = (uint8_t*)"\x04\x01\x01\x01\x01\x01\x01\x01";
uint8_t* descbc_vk_key_3 = (uint8_t*)"\x02\x01\x01\x01\x01\x01\x01\x01";
uint8_t* descbc_vk_key_4 = (uint8_t*)"\x01\x80\x01\x01\x01\x01\x01\x01";

uint8_t* descbc_vk_iv = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00";

uint8_t* descbc_vk_plain = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00";

uint8_t* descbc_vk_cipher_1 = (uint8_t*)"\x80\x9F\x5F\x87\x3C\x1F\xD7\x61";
uint8_t* descbc_vk_cipher_2 = (uint8_t*)"\xC0\x2F\xAF\xFE\xC9\x89\xD1\xFC";
uint8_t* descbc_vk_cipher_3 = (uint8_t*)"\x46\x15\xAA\x1D\x33\xE7\x2F\x10";
uint8_t* descbc_vk_cipher_4 = (uint8_t*)"\x20\x55\x12\x33\x50\xC0\x08\x58";

CIPHERTEST descbc_vk_tests[] = {
    { "DES-CBC Variable Key", 4, descbc_vk_key_1, descbc_vk_iv, descbc_vk_plain, descbc_vk_cipher_1, des::recsize },
    { "DES-CBC Variable Key", 4, descbc_vk_key_2, descbc_vk_iv, descbc_vk_plain, descbc_vk_cipher_2, des::recsize },
    { "DES-CBC Variable Key", 4, descbc_vk_key_3, descbc_vk_iv, descbc_vk_plain, descbc_vk_cipher_3, des::recsize },
    { "DES-CBC Variable Key", 4, descbc_vk_key_4, descbc_vk_iv, descbc_vk_plain, descbc_vk_cipher_4, des::recsize }
};

// DES-CBC permutation operation test vectors

uint8_t* descbc_po_key_1 = (uint8_t*)"\x10\x86\x91\x15\x19\x19\x01\x01";
uint8_t* descbc_po_key_2 = (uint8_t*)"\x10\x86\x91\x15\x19\x58\x01\x01";
uint8_t* descbc_po_key_3 = (uint8_t*)"\x51\x07\xB0\x15\x19\x58\x01\x01";
uint8_t* descbc_po_key_4 = (uint8_t*)"\x10\x07\xB0\x15\x19\x19\x01\x01";

uint8_t* descbc_po_iv = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00";

uint8_t* descbc_po_plain = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00";

uint8_t* descbc_po_cipher_1 = (uint8_t*)"\xE6\x52\xB5\x3B\x55\x0B\xE8\xB0";
uint8_t* descbc_po_cipher_2 = (uint8_t*)"\xAF\x52\x71\x20\xC4\x85\xCB\xB0";
uint8_t* descbc_po_cipher_3 = (uint8_t*)"\x0F\x04\xCE\x39\x3D\xB9\x26\xD5";
uint8_t* descbc_po_cipher_4 = (uint8_t*)"\xC9\xF0\x0F\xFC\x74\x07\x90\x67";

CIPHERTEST descbc_po_tests[] = {
    { "DES-CBC Permutation Operation", 4, descbc_po_key_1, descbc_po_iv, descbc_po_plain, descbc_po_cipher_1, des::recsize },
    { "DES-CBC Permutation Operation", 4, descbc_po_key_2, descbc_po_iv, descbc_po_plain, descbc_po_cipher_2, des::recsize },
    { "DES-CBC Permutation Operation", 4, descbc_po_key_3, descbc_po_iv, descbc_po_plain, descbc_po_cipher_3, des::recsize },
    { "DES-CBC Permutation Operation", 4, descbc_po_key_4, descbc_po_iv, descbc_po_plain, descbc_po_cipher_4, des::recsize }
};

// DES-CBC substitution table test vectors

uint8_t* descbc_st_key_1 = (uint8_t*)"\x04\xB9\x15\xBA\x43\xFE\xB5\xB6";
uint8_t* descbc_st_key_2 = (uint8_t*)"\x01\x13\xB9\x70\xFD\x34\xF2\xCE";
uint8_t* descbc_st_key_3 = (uint8_t*)"\x01\x70\xF1\x75\x46\x8F\xB5\xE6";
uint8_t* descbc_st_key_4 = (uint8_t*)"\x43\x29\x7F\xAD\x38\xE3\x73\xFE";

uint8_t* descbc_st_iv = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00";

uint8_t* descbc_st_plain_1 = (uint8_t*)"\x42\xFD\x44\x30\x59\x57\x7F\xA2";
uint8_t* descbc_st_plain_2 = (uint8_t*)"\x05\x9B\x5E\x08\x51\xCF\x14\x3A";
uint8_t* descbc_st_plain_3 = (uint8_t*)"\x07\x56\xD8\xE0\x77\x47\x61\xD2";
uint8_t* descbc_st_plain_4 = (uint8_t*)"\x76\x25\x14\xB8\x29\xBF\x48\x6A";

uint8_t* descbc_st_cipher_1 = (uint8_t*)"\xAF\x37\xFB\x42\x1F\x8C\x40\x95";
uint8_t* descbc_st_cipher_2 = (uint8_t*)"\x86\xA5\x60\xF1\x0E\xC6\xD8\x5B";
uint8_t* descbc_st_cipher_3 = (uint8_t*)"\x0C\xD3\xDA\x02\x00\x21\xDC\x09";
uint8_t* descbc_st_cipher_4 = (uint8_t*)"\xEA\x67\x6B\x2C\xB7\xDB\x2B\x7A";

CIPHERTEST descbc_st_tests[] = {
    { "DES-CBC Substitution Table", 4, descbc_st_key_1, descbc_st_iv, descbc_st_plain_1, descbc_st_cipher_1, des::recsize },
    { "DES-CBC Substitution Table", 4, descbc_st_key_2, descbc_st_iv, descbc_st_plain_2, descbc_st_cipher_2, des::recsize },
    { "DES-CBC Substitution Table", 4, descbc_st_key_3, descbc_st_iv, descbc_st_plain_3, descbc_st_cipher_3, des::recsize },
    { "DES-CBC Substitution Table", 4, descbc_st_key_4, descbc_st_iv, descbc_st_plain_4, descbc_st_cipher_4, des::recsize }
};

// DES-CFB variable plaintext test vectors

uint8_t* descfb_vp_key = (uint8_t*)"\x01\x01\x01\x01\x01\x01\x01\x01";

uint8_t* descfb_vp_iv_1 = (uint8_t*)"\x00\x80\x00\x00\x00\x00\x00\x00";
uint8_t* descfb_vp_iv_2 = (uint8_t*)"\x00\x40\x00\x00\x00\x00\x00\x00";
uint8_t* descfb_vp_iv_3 = (uint8_t*)"\x00\x20\x00\x00\x00\x00\x00\x00";
uint8_t* descfb_vp_iv_4 = (uint8_t*)"\x00\x10\x00\x00\x00\x00\x00\x00";

uint8_t* descfb_vp_plain = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00";

uint8_t* descfb_vp_cipher_1 = (uint8_t*)"\xD9\x03\x1B\x02\x71\xBD\x5A\x0A";
uint8_t* descfb_vp_cipher_2 = (uint8_t*)"\x42\x42\x50\xB3\x7C\x3D\xD9\x51";
uint8_t* descfb_vp_cipher_3 = (uint8_t*)"\xB8\x06\x1B\x7E\xCD\x9A\x21\xE5";
uint8_t* descfb_vp_cipher_4 = (uint8_t*)"\xF1\x5D\x0F\x28\x6B\x65\xBD\x28";

CIPHERTEST descfb_vp_tests[] = {
    { "DES-CFB Variable Plaintext", 4, descfb_vp_key, descfb_vp_iv_1, descfb_vp_plain, descfb_vp_cipher_1, des::recsize },
    { "DES-CFB Variable Plaintext", 4, descfb_vp_key, descfb_vp_iv_2, descfb_vp_plain, descfb_vp_cipher_2, des::recsize },
    { "DES-CFB Variable Plaintext", 4, descfb_vp_key, descfb_vp_iv_3, descfb_vp_plain, descfb_vp_cipher_3, des::recsize },
    { "DES-CFB Variable Plaintext", 4, descfb_vp_key, descfb_vp_iv_4, descfb_vp_plain, descfb_vp_cipher_4, des::recsize }
};

// DES-CFB inverse permutation test vectors

uint8_t* descfb_ip_key = (uint8_t*)"\x01\x01\x01\x01\x01\x01\x01\x01";

uint8_t* descfb_ip_iv_1 = (uint8_t*)"\x75\x0D\x07\x94\x07\x52\x13\x63";
uint8_t* descfb_ip_iv_2 = (uint8_t*)"\x64\xFE\xED\x9C\x72\x4C\x2F\xAF";
uint8_t* descfb_ip_iv_3 = (uint8_t*)"\xF0\x2B\x26\x3B\x32\x8E\x2B\x60";
uint8_t* descfb_ip_iv_4 = (uint8_t*)"\x9D\x64\x55\x5A\x9A\x10\xB8\x52";

uint8_t* descfb_ip_plain = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00";

uint8_t* descfb_ip_cipher_1 = (uint8_t*)"\x00\x00\x00\x80\x00\x00\x00\x00";
uint8_t* descfb_ip_cipher_2 = (uint8_t*)"\x00\x00\x00\x40\x00\x00\x00\x00";
uint8_t* descfb_ip_cipher_3 = (uint8_t*)"\x00\x00\x00\x20\x00\x00\x00\x00";
uint8_t* descfb_ip_cipher_4 = (uint8_t*)"\x00\x00\x00\x10\x00\x00\x00\x00";

CIPHERTEST descfb_ip_tests[] = {
    { "DES-CFB Inverse Permutation", 4, descfb_ip_key, descfb_ip_iv_1, descfb_ip_plain, descfb_ip_cipher_1, des::recsize },
    { "DES-CFB Inverse Permutation", 4, descfb_ip_key, descfb_ip_iv_2, descfb_ip_plain, descfb_ip_cipher_2, des::recsize },
    { "DES-CFB Inverse Permutation", 4, descfb_ip_key, descfb_ip_iv_3, descfb_ip_plain, descfb_ip_cipher_3, des::recsize },
    { "DES-CFB Inverse Permutation", 4, descfb_ip_key, descfb_ip_iv_4, descfb_ip_plain, descfb_ip_cipher_4, des::recsize }
};

// DES-CFB variable key test vectors

uint8_t* descfb_vk_key_1 = (uint8_t*)"\x01\x40\x01\x01\x01\x01\x01\x01";
uint8_t* descfb_vk_key_2 = (uint8_t*)"\x01\x20\x01\x01\x01\x01\x01\x01";
uint8_t* descfb_vk_key_3 = (uint8_t*)"\x01\x10\x01\x01\x01\x01\x01\x01";
uint8_t* descfb_vk_key_4 = (uint8_t*)"\x01\x08\x01\x01\x01\x01\x01\x01";

uint8_t* descfb_vk_iv = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00";

uint8_t* descfb_vk_plain = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00";

uint8_t* descfb_vk_cipher_1 = (uint8_t*)"\xDF\x3B\x99\xD6\x57\x73\x97\xC8";
uint8_t* descfb_vk_cipher_2 = (uint8_t*)"\x31\xFE\x17\x36\x9B\x52\x88\xC9";
uint8_t* descfb_vk_cipher_3 = (uint8_t*)"\xDF\xDD\x3C\xC6\x4D\xAE\x16\x42";
uint8_t* descfb_vk_cipher_4 = (uint8_t*)"\x17\x8C\x83\xCE\x2B\x39\x9D\x94";

CIPHERTEST descfb_vk_tests[] = {
    { "DES-CFB Variable Key", 4, descfb_vk_key_1, descfb_vk_iv, descfb_vk_plain, descfb_vk_cipher_1, des::recsize },
    { "DES-CFB Variable Key", 4, descfb_vk_key_2, descfb_vk_iv, descfb_vk_plain, descfb_vk_cipher_2, des::recsize },
    { "DES-CFB Variable Key", 4, descfb_vk_key_3, descfb_vk_iv, descfb_vk_plain, descfb_vk_cipher_3, des::recsize },
    { "DES-CFB Variable Key", 4, descfb_vk_key_4, descfb_vk_iv, descfb_vk_plain, descfb_vk_cipher_4, des::recsize }
};

// DES-CFB permutation operation test vectors

uint8_t* descfb_po_key_1 = (uint8_t*)"\x31\x07\x91\x54\x98\x08\x01\x01";
uint8_t* descfb_po_key_2 = (uint8_t*)"\x31\x07\x91\x94\x98\x08\x01\x01";
uint8_t* descfb_po_key_3 = (uint8_t*)"\x10\x07\x91\x15\xB9\x08\x01\x40";
uint8_t* descfb_po_key_4 = (uint8_t*)"\x31\x07\x91\x15\x98\x08\x01\x40";

uint8_t* descfb_po_iv = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00";

uint8_t* descfb_po_plain = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00";

uint8_t* descfb_po_cipher_1 = (uint8_t*)"\x7C\xFD\x82\xA5\x93\x25\x2B\x4E";
uint8_t* descfb_po_cipher_2 = (uint8_t*)"\xCB\x49\xA2\xF9\xE9\x13\x63\xE3";
uint8_t* descfb_po_cipher_3 = (uint8_t*)"\x00\xB5\x88\xBE\x70\xD2\x3F\x56";
uint8_t* descfb_po_cipher_4 = (uint8_t*)"\x40\x6A\x9A\x6A\xB4\x33\x99\xAE";

CIPHERTEST descfb_po_tests[] = {
    { "DES-CFB Permutation Operation", 4, descfb_po_key_1, descfb_po_iv, descfb_po_plain, descfb_po_cipher_1, des::recsize },
    { "DES-CFB Permutation Operation", 4, descfb_po_key_2, descfb_po_iv, descfb_po_plain, descfb_po_cipher_2, des::recsize },
    { "DES-CFB Permutation Operation", 4, descfb_po_key_3, descfb_po_iv, descfb_po_plain, descfb_po_cipher_3, des::recsize },
    { "DES-CFB Permutation Operation", 4, descfb_po_key_4, descfb_po_iv, descfb_po_plain, descfb_po_cipher_4, des::recsize }
};

// DES-CFB substitution table test vectors

uint8_t* descfb_st_key_1 = (uint8_t*)"\x07\xA7\x13\x70\x45\xDA\x2A\x16";
uint8_t* descfb_st_key_2 = (uint8_t*)"\x04\x68\x91\x04\xC2\xFD\x3B\x2F";
uint8_t* descfb_st_key_3 = (uint8_t*)"\x37\xD0\x6B\xB5\x16\xCB\x75\x46";
uint8_t* descfb_st_key_4 = (uint8_t*)"\x1F\x08\x26\x0D\x1A\xC2\x46\x5E";

uint8_t* descfb_st_iv_1 = (uint8_t*)"\x3B\xDD\x11\x90\x49\x37\x28\x02";
uint8_t* descfb_st_iv_2 = (uint8_t*)"\x26\x95\x5F\x68\x35\xAF\x60\x9A";
uint8_t* descfb_st_iv_3 = (uint8_t*)"\x16\x4D\x5E\x40\x4F\x27\x52\x32";
uint8_t* descfb_st_iv_4 = (uint8_t*)"\x6B\x05\x6E\x18\x75\x9F\x5C\xCA";

uint8_t* descfb_st_plain = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00";

uint8_t* descfb_st_cipher_1 = (uint8_t*)"\xDF\xD6\x4A\x81\x5C\xAF\x1A\x0F";
uint8_t* descfb_st_cipher_2 = (uint8_t*)"\x5C\x51\x3C\x9C\x48\x86\xC0\x88";
uint8_t* descfb_st_cipher_3 = (uint8_t*)"\x0A\x2A\xEE\xAE\x3F\xF4\xAB\x77";
uint8_t* descfb_st_cipher_4 = (uint8_t*)"\xEF\x1B\xF0\x3E\x5D\xFA\x57\x5A";

CIPHERTEST descfb_st_tests[] = {
    { "DES-CFB Substitution Table", 4, descfb_st_key_1, descfb_st_iv_1, descfb_st_plain, descfb_st_cipher_1, des::recsize },
    { "DES-CFB Substitution Table", 4, descfb_st_key_2, descfb_st_iv_2, descfb_st_plain, descfb_st_cipher_2, des::recsize },
    { "DES-CFB Substitution Table", 4, descfb_st_key_3, descfb_st_iv_3, descfb_st_plain, descfb_st_cipher_3, des::recsize },
    { "DES-CFB Substitution Table", 4, descfb_st_key_4, descfb_st_iv_4, descfb_st_plain, descfb_st_cipher_4, des::recsize }
};

// DES-OFB variable plaintext test vectors

uint8_t* desofb_vp_key = (uint8_t*)"\x01\x01\x01\x01\x01\x01\x01\x01";

uint8_t* desofb_vp_iv_1 = (uint8_t*)"\x00\x08\x00\x00\x00\x00\x00\x00";
uint8_t* desofb_vp_iv_2 = (uint8_t*)"\x00\x04\x00\x00\x00\x00\x00\x00";
uint8_t* desofb_vp_iv_3 = (uint8_t*)"\x00\x02\x00\x00\x00\x00\x00\x00";
uint8_t* desofb_vp_iv_4 = (uint8_t*)"\x00\x01\x00\x00\x00\x00\x00\x00";

uint8_t* desofb_vp_plain = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00";

uint8_t* desofb_vp_cipher_1 = (uint8_t*)"\xAD\xD0\xCC\x8D\x6E\x5D\xEB\xA1";
uint8_t* desofb_vp_cipher_2 = (uint8_t*)"\xE6\xD5\xF8\x27\x52\xAD\x63\xD1";
uint8_t* desofb_vp_cipher_3 = (uint8_t*)"\xEC\xBF\xE3\xBD\x3F\x59\x1A\x5E";
uint8_t* desofb_vp_cipher_4 = (uint8_t*)"\xF3\x56\x83\x43\x79\xD1\x65\xCD";

CIPHERTEST desofb_vp_tests[] = {
    { "DES-OFB Variable Plaintext", 4, desofb_vp_key, desofb_vp_iv_1, desofb_vp_plain, desofb_vp_cipher_1, des::recsize },
    { "DES-OFB Variable Plaintext", 4, desofb_vp_key, desofb_vp_iv_2, desofb_vp_plain, desofb_vp_cipher_2, des::recsize },
    { "DES-OFB Variable Plaintext", 4, desofb_vp_key, desofb_vp_iv_3, desofb_vp_plain, desofb_vp_cipher_3, des::recsize },
    { "DES-OFB Variable Plaintext", 4, desofb_vp_key, desofb_vp_iv_4, desofb_vp_plain, desofb_vp_cipher_4, des::recsize }
};

// DES-OFB inverse permutation test vectors

uint8_t* desofb_ip_key = (uint8_t*)"\x01\x01\x01\x01\x01\x01\x01\x01";

uint8_t* desofb_ip_iv_1 = (uint8_t*)"\xD1\x06\xFF\x0B\xED\x52\x55\xD7";
uint8_t* desofb_ip_iv_2 = (uint8_t*)"\xE1\x65\x2C\x6B\x13\x8C\x64\xA5";
uint8_t* desofb_ip_iv_3 = (uint8_t*)"\xE4\x28\x58\x11\x86\xEC\x8F\x46";
uint8_t* desofb_ip_iv_4 = (uint8_t*)"\xAE\xB5\xF5\xED\xE2\x2D\x1A\x36";

uint8_t* desofb_ip_plain = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00";

uint8_t* desofb_ip_cipher_1 = (uint8_t*)"\x00\x00\x00\x08\x00\x00\x00\x00";
uint8_t* desofb_ip_cipher_2 = (uint8_t*)"\x00\x00\x00\x04\x00\x00\x00\x00";
uint8_t* desofb_ip_cipher_3 = (uint8_t*)"\x00\x00\x00\x02\x00\x00\x00\x00";
uint8_t* desofb_ip_cipher_4 = (uint8_t*)"\x00\x00\x00\x01\x00\x00\x00\x00";

CIPHERTEST desofb_ip_tests[] = {
    { "DES-OFB Inverse Permutation", 4, desofb_ip_key, desofb_ip_iv_1, desofb_ip_plain, desofb_ip_cipher_1, des::recsize },
    { "DES-OFB Inverse Permutation", 4, desofb_ip_key, desofb_ip_iv_2, desofb_ip_plain, desofb_ip_cipher_2, des::recsize },
    { "DES-OFB Inverse Permutation", 4, desofb_ip_key, desofb_ip_iv_3, desofb_ip_plain, desofb_ip_cipher_3, des::recsize },
    { "DES-OFB Inverse Permutation", 4, desofb_ip_key, desofb_ip_iv_4, desofb_ip_plain, desofb_ip_cipher_4, des::recsize }
};

// DES-OFB variable key test vectors

uint8_t* desofb_vk_key_1 = (uint8_t*)"\x01\x04\x01\x01\x01\x01\x01\x01";
uint8_t* desofb_vk_key_2 = (uint8_t*)"\x01\x02\x01\x01\x01\x01\x01\x01";
uint8_t* desofb_vk_key_3 = (uint8_t*)"\x01\x01\x80\x01\x01\x01\x01\x01";
uint8_t* desofb_vk_key_4 = (uint8_t*)"\x01\x01\x40\x01\x01\x01\x01\x01";

uint8_t* desofb_vk_iv = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00";

uint8_t* desofb_vk_plain = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00";

uint8_t* desofb_vk_cipher_1 = (uint8_t*)"\x50\xF6\x36\x32\x4A\x9B\x7F\x80";
uint8_t* desofb_vk_cipher_2 = (uint8_t*)"\xA8\x46\x8E\xE3\xBC\x18\xF0\x6D";
uint8_t* desofb_vk_cipher_3 = (uint8_t*)"\xA2\xDC\x9E\x92\xFD\x3C\xDE\x92";
uint8_t* desofb_vk_cipher_4 = (uint8_t*)"\xCA\xC0\x9F\x79\x7D\x03\x12\x87";

CIPHERTEST desofb_vk_tests[] = {
    { "DES-OFB Variable Key", 4, desofb_vk_key_1, desofb_vk_iv, desofb_vk_plain, desofb_vk_cipher_1, des::recsize },
    { "DES-OFB Variable Key", 4, desofb_vk_key_2, desofb_vk_iv, desofb_vk_plain, desofb_vk_cipher_2, des::recsize },
    { "DES-OFB Variable Key", 4, desofb_vk_key_3, desofb_vk_iv, desofb_vk_plain, desofb_vk_cipher_3, des::recsize },
    { "DES-OFB Variable Key", 4, desofb_vk_key_4, desofb_vk_iv, desofb_vk_plain, desofb_vk_cipher_4, des::recsize }
};

// DES-OFB permutation operation test vectors

uint8_t* desofb_po_key_1 = (uint8_t*)"\x10\x07\xD0\x15\x89\x98\x01\x01";
uint8_t* desofb_po_key_2 = (uint8_t*)"\x91\x07\x91\x15\x89\x98\x01\x01";
uint8_t* desofb_po_key_3 = (uint8_t*)"\x91\x07\xD0\x15\x89\x19\x01\x01";
uint8_t* desofb_po_key_4 = (uint8_t*)"\x10\x07\xD0\x15\x98\x98\x01\x20";

uint8_t* desofb_po_iv = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00";

uint8_t* desofb_po_plain = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00";

uint8_t* desofb_po_cipher_1 = (uint8_t*)"\x6C\xB7\x73\x61\x1D\xCA\x9A\xDA";
uint8_t* desofb_po_cipher_2 = (uint8_t*)"\x67\xFD\x21\xC1\x7D\xBB\x5D\x70";
uint8_t* desofb_po_cipher_3 = (uint8_t*)"\x95\x92\xCB\x41\x10\x43\x07\x87";
uint8_t* desofb_po_cipher_4 = (uint8_t*)"\xA6\xB7\xFF\x68\xA3\x18\xDD\xD3";

CIPHERTEST desofb_po_tests[] = {
    { "DES-OFB Permutation Operation", 4, desofb_po_key_1, desofb_po_iv, desofb_po_plain, desofb_po_cipher_1, des::recsize },
    { "DES-OFB Permutation Operation", 4, desofb_po_key_2, desofb_po_iv, desofb_po_plain, desofb_po_cipher_2, des::recsize },
    { "DES-OFB Permutation Operation", 4, desofb_po_key_3, desofb_po_iv, desofb_po_plain, desofb_po_cipher_3, des::recsize },
    { "DES-OFB Permutation Operation", 4, desofb_po_key_4, desofb_po_iv, desofb_po_plain, desofb_po_cipher_4, des::recsize }
};

// DES-OFB substitution table test vectors

uint8_t* desofb_st_key_1 = (uint8_t*)"\x58\x40\x23\x64\x1A\xBA\x61\x76";
uint8_t* desofb_st_key_2 = (uint8_t*)"\x02\x58\x16\x16\x46\x29\xB0\x07";
uint8_t* desofb_st_key_3 = (uint8_t*)"\x49\x79\x3E\xBC\x79\xB3\x25\x8F";
uint8_t* desofb_st_key_4 = (uint8_t*)"\x4F\xB0\x5E\x15\x15\xAB\x73\xA7";

uint8_t* desofb_st_iv_1 = (uint8_t*)"\x00\x4B\xD6\xEF\x09\x17\x60\x62";
uint8_t* desofb_st_iv_2 = (uint8_t*)"\x48\x0D\x39\x00\x6E\xE7\x62\xF2";
uint8_t* desofb_st_iv_3 = (uint8_t*)"\x43\x75\x40\xC8\x69\x8F\x3C\xFA";
uint8_t* desofb_st_iv_4 = (uint8_t*)"\x07\x2D\x43\xA0\x77\x07\x52\x92";

uint8_t* desofb_st_plain = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00";

uint8_t* desofb_st_cipher_1 = (uint8_t*)"\x88\xBF\x0D\xB6\xD7\x0D\xEE\x56";
uint8_t* desofb_st_cipher_2 = (uint8_t*)"\xA1\xF9\x91\x55\x41\x02\x0B\x56";
uint8_t* desofb_st_cipher_3 = (uint8_t*)"\x6F\xBF\x1C\xAF\xCF\xFD\x05\x56";
uint8_t* desofb_st_cipher_4 = (uint8_t*)"\x2F\x22\xE4\x9B\xAB\x7C\xA1\xAC";

CIPHERTEST desofb_st_tests[] = {
    { "DES-OFB Substitution Table", 4, desofb_st_key_1, desofb_st_iv_1, desofb_st_plain, desofb_st_cipher_1, des::recsize },
    { "DES-OFB Substitution Table", 4, desofb_st_key_2, desofb_st_iv_2, desofb_st_plain, desofb_st_cipher_2, des::recsize },
    { "DES-OFB Substitution Table", 4, desofb_st_key_3, desofb_st_iv_3, desofb_st_plain, desofb_st_cipher_3, des::recsize },
    { "DES-OFB Substitution Table", 4, desofb_st_key_4, desofb_st_iv_4, desofb_st_plain, desofb_st_cipher_4, des::recsize }
};

// DES-EDE-ECB variable plaintext test vectors

uint8_t* des3ecb_vp_key = (uint8_t*)"\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01";

uint8_t* des3ecb_vp_plain_1 = (uint8_t*)"\x00\x00\x00\x00\x80\x00\x00\x00";
uint8_t* des3ecb_vp_plain_2 = (uint8_t*)"\x00\x00\x00\x00\x40\x00\x00\x00";
uint8_t* des3ecb_vp_plain_3 = (uint8_t*)"\x00\x00\x00\x00\x20\x00\x00\x00";
uint8_t* des3ecb_vp_plain_4 = (uint8_t*)"\x00\x00\x00\x00\x10\x00\x00\x00";

uint8_t* des3ecb_vp_cipher_1 = (uint8_t*)"\xE9\x43\xD7\x56\x8A\xEC\x0C\x5C";
uint8_t* des3ecb_vp_cipher_2 = (uint8_t*)"\xDF\x98\xC8\x27\x6F\x54\xB0\x4B";
uint8_t* des3ecb_vp_cipher_3 = (uint8_t*)"\xB1\x60\xE4\x68\x0F\x6C\x69\x6F";
uint8_t* des3ecb_vp_cipher_4 = (uint8_t*)"\xFA\x07\x52\xB0\x7D\x9C\x4A\xB8";

CIPHERTEST des3ecb_vp_tests[] = {
    { "DES-EDE-ECB Variable Plaintext", 4, des3ecb_vp_key, nullptr, des3ecb_vp_plain_1, des3ecb_vp_cipher_1, des3::recsize },
    { "DES-EDE-ECB Variable Plaintext", 4, des3ecb_vp_key, nullptr, des3ecb_vp_plain_2, des3ecb_vp_cipher_2, des3::recsize },
    { "DES-EDE-ECB Variable Plaintext", 4, des3ecb_vp_key, nullptr, des3ecb_vp_plain_3, des3ecb_vp_cipher_3, des3::recsize },
    { "DES-EDE-ECB Variable Plaintext", 4, des3ecb_vp_key, nullptr, des3ecb_vp_plain_4, des3ecb_vp_cipher_4, des3::recsize }
};

// DES-EDE-ECB inverse permutation test vectors

uint8_t* des3ecb_ip_key = (uint8_t*)"\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01";

uint8_t* des3ecb_ip_plain_1 = (uint8_t*)"\x10\x29\xD5\x5E\x88\x0E\xC2\xD0";
uint8_t* des3ecb_ip_plain_2 = (uint8_t*)"\x5D\x86\xCB\x23\x63\x9D\xBE\xA9";
uint8_t* des3ecb_ip_plain_3 = (uint8_t*)"\x1D\x1C\xA8\x53\xAE\x7C\x0C\x5F";
uint8_t* des3ecb_ip_plain_4 = (uint8_t*)"\xCE\x33\x23\x29\x24\x8F\x32\x28";

uint8_t* des3ecb_ip_cipher_1 = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x80\x00";
uint8_t* des3ecb_ip_cipher_2 = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x40\x00";
uint8_t* des3ecb_ip_cipher_3 = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x20\x00";
uint8_t* des3ecb_ip_cipher_4 = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x10\x00";

CIPHERTEST des3ecb_ip_tests[] = {
    { "DES-EDE-ECB Inverse Permutation", 4, des3ecb_ip_key, nullptr, des3ecb_ip_plain_1, des3ecb_ip_cipher_1, des3::recsize },
    { "DES-EDE-ECB Inverse Permutation", 4, des3ecb_ip_key, nullptr, des3ecb_ip_plain_2, des3ecb_ip_cipher_2, des3::recsize },
    { "DES-EDE-ECB Inverse Permutation", 4, des3ecb_ip_key, nullptr, des3ecb_ip_plain_3, des3ecb_ip_cipher_3, des3::recsize },
    { "DES-EDE-ECB Inverse Permutation", 4, des3ecb_ip_key, nullptr, des3ecb_ip_plain_4, des3ecb_ip_cipher_4, des3::recsize }
};

// DES-EDE-ECB variable key test vectors

uint8_t* des3ecb_vk_key_1 = (uint8_t*)"\x01\x01\x20\x01\x01\x01\x01\x01\x01\x01\x20\x01\x01\x01\x01\x01\x01\x01\x20\x01\x01\x01\x01\x01";
uint8_t* des3ecb_vk_key_2 = (uint8_t*)"\x01\x01\x10\x01\x01\x01\x01\x01\x01\x01\x10\x01\x01\x01\x01\x01\x01\x01\x10\x01\x01\x01\x01\x01";
uint8_t* des3ecb_vk_key_3 = (uint8_t*)"\x01\x01\x08\x01\x01\x01\x01\x01\x01\x01\x08\x01\x01\x01\x01\x01\x01\x01\x08\x01\x01\x01\x01\x01";
uint8_t* des3ecb_vk_key_4 = (uint8_t*)"\x01\x01\x04\x01\x01\x01\x01\x01\x01\x01\x04\x01\x01\x01\x01\x01\x01\x01\x04\x01\x01\x01\x01\x01";

uint8_t* des3ecb_vk_plain = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00";

uint8_t* des3ecb_vk_cipher_1 = (uint8_t*)"\x90\xBA\x68\x0B\x22\xAE\xB5\x25";
uint8_t* des3ecb_vk_cipher_2 = (uint8_t*)"\xCE\x7A\x24\xF3\x50\xE2\x80\xB6";
uint8_t* des3ecb_vk_cipher_3 = (uint8_t*)"\x88\x2B\xFF\x0A\xA0\x1A\x0B\x87";
uint8_t* des3ecb_vk_cipher_4 = (uint8_t*)"\x25\x61\x02\x88\x92\x45\x11\xC2";

CIPHERTEST des3ecb_vk_tests[] = {
    { "DES-EDE-ECB Variable Key", 4, des3ecb_vk_key_1, nullptr, des3ecb_vk_plain, des3ecb_vk_cipher_1, des3::recsize },
    { "DES-EDE-ECB Variable Key", 4, des3ecb_vk_key_2, nullptr, des3ecb_vk_plain, des3ecb_vk_cipher_2, des3::recsize },
    { "DES-EDE-ECB Variable Key", 4, des3ecb_vk_key_3, nullptr, des3ecb_vk_plain, des3ecb_vk_cipher_3, des3::recsize },
    { "DES-EDE-ECB Variable Key", 4, des3ecb_vk_key_4, nullptr, des3ecb_vk_plain, des3ecb_vk_cipher_4, des3::recsize }
};

// DES-EDE-ECB permutation operation test vectors

uint8_t* des3ecb_po_key_1 = (uint8_t*)"\x10\x07\x94\x04\x98\x19\x01\x01\x10\x07\x94\x04\x98\x19\x01\x01\x10\x07\x94\x04\x98\x19\x01\x01";
uint8_t* des3ecb_po_key_2 = (uint8_t*)"\x01\x07\x91\x04\x91\x19\x04\x01\x01\x07\x91\x04\x91\x19\x04\x01\x01\x07\x91\x04\x91\x19\x04\x01";
uint8_t* des3ecb_po_key_3 = (uint8_t*)"\x01\x07\x91\x04\x91\x19\x01\x01\x01\x07\x91\x04\x91\x19\x01\x01\x01\x07\x91\x04\x91\x19\x01\x01";
uint8_t* des3ecb_po_key_4 = (uint8_t*)"\x01\x07\x94\x04\x91\x19\x04\x01\x01\x07\x94\x04\x91\x19\x04\x01\x01\x07\x94\x04\x91\x19\x04\x01";

uint8_t* des3ecb_po_plain = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00";

uint8_t* des3ecb_po_cipher_1 = (uint8_t*)"\x4D\x10\x21\x96\xC9\x14\xCA\x16";
uint8_t* des3ecb_po_cipher_2 = (uint8_t*)"\x2D\xFA\x9F\x45\x73\x59\x49\x65";
uint8_t* des3ecb_po_cipher_3 = (uint8_t*)"\xB4\x66\x04\x81\x6C\x0E\x07\x74";
uint8_t* des3ecb_po_cipher_4 = (uint8_t*)"\x6E\x7E\x62\x21\xA4\xF3\x4E\x87";

CIPHERTEST des3ecb_po_tests[] = {
    { "DES-EDE-ECB Permutation Operation", 4, des3ecb_po_key_1, nullptr, des3ecb_po_plain, des3ecb_po_cipher_1, des3::recsize },
    { "DES-EDE-ECB Permutation Operation", 4, des3ecb_po_key_2, nullptr, des3ecb_po_plain, des3ecb_po_cipher_2, des3::recsize },
    { "DES-EDE-ECB Permutation Operation", 4, des3ecb_po_key_3, nullptr, des3ecb_po_plain, des3ecb_po_cipher_3, des3::recsize },
    { "DES-EDE-ECB Permutation Operation", 4, des3ecb_po_key_4, nullptr, des3ecb_po_plain, des3ecb_po_cipher_4, des3::recsize }
};

// DES-EDE-ECB substitution table test vectors

uint8_t* des3ecb_st_key_1 = (uint8_t*)"\x7C\xA1\x10\x45\x4A\x1A\x6E\x57\x7C\xA1\x10\x45\x4A\x1A\x6E\x57\x7C\xA1\x10\x45\x4A\x1A\x6E\x57";
uint8_t* des3ecb_st_key_2 = (uint8_t*)"\x01\x31\xD9\x61\x9D\xC1\x37\x6E\x01\x31\xD9\x61\x9D\xC1\x37\x6E\x01\x31\xD9\x61\x9D\xC1\x37\x6E";
uint8_t* des3ecb_st_key_3 = (uint8_t*)"\x07\xA1\x13\x3E\x4A\x0B\x26\x86\x07\xA1\x13\x3E\x4A\x0B\x26\x86\x07\xA1\x13\x3E\x4A\x0B\x26\x86";
uint8_t* des3ecb_st_key_4 = (uint8_t*)"\x38\x49\x67\x4C\x26\x02\x31\x9E\x38\x49\x67\x4C\x26\x02\x31\x9E\x38\x49\x67\x4C\x26\x02\x31\x9E";

uint8_t* des3ecb_st_plain_1 = (uint8_t*)"\x01\xA1\xD6\xD0\x39\x77\x67\x42";
uint8_t* des3ecb_st_plain_2 = (uint8_t*)"\x5C\xD5\x4C\xA8\x3D\xEF\x57\xDA";
uint8_t* des3ecb_st_plain_3 = (uint8_t*)"\x02\x48\xD4\x38\x06\xF6\x71\x72";
uint8_t* des3ecb_st_plain_4 = (uint8_t*)"\x51\x45\x4B\x58\x2D\xDF\x44\x0A";

uint8_t* des3ecb_st_cipher_1 = (uint8_t*)"\x69\x0F\x5B\x0D\x9A\x26\x93\x9B";
uint8_t* des3ecb_st_cipher_2 = (uint8_t*)"\x7A\x38\x9D\x10\x35\x4B\xD2\x71";
uint8_t* des3ecb_st_cipher_3 = (uint8_t*)"\x86\x8E\xBB\x51\xCA\xB4\x59\x9A";
uint8_t* des3ecb_st_cipher_4 = (uint8_t*)"\x71\x78\x87\x6E\x01\xF1\x9B\x2A";

CIPHERTEST des3ecb_st_tests[] = {
    { "DES-EDE-ECB Substitution Table", 4, des3ecb_st_key_1, nullptr, des3ecb_st_plain_1, des3ecb_st_cipher_1, des3::recsize },
    { "DES-EDE-ECB Substitution Table", 4, des3ecb_st_key_2, nullptr, des3ecb_st_plain_2, des3ecb_st_cipher_2, des3::recsize },
    { "DES-EDE-ECB Substitution Table", 4, des3ecb_st_key_3, nullptr, des3ecb_st_plain_3, des3ecb_st_cipher_3, des3::recsize },
    { "DES-EDE-ECB Substitution Table", 4, des3ecb_st_key_4, nullptr, des3ecb_st_plain_4, des3ecb_st_cipher_4, des3::recsize }
};

// DES-EDE-CBC variable plaintext test vectors

uint8_t* des3cbc_vp_key = (uint8_t*)"\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01";

uint8_t* des3cbc_vp_iv = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00";

uint8_t* des3cbc_vp_plain_1 = (uint8_t*)"\x00\x00\x00\x00\x08\x00\x00\x00";
uint8_t* des3cbc_vp_plain_2 = (uint8_t*)"\x00\x00\x00\x00\x04\x00\x00\x00";
uint8_t* des3cbc_vp_plain_3 = (uint8_t*)"\x00\x00\x00\x00\x02\x00\x00\x00";
uint8_t* des3cbc_vp_plain_4 = (uint8_t*)"\x00\x00\x00\x00\x01\x00\x00\x00";

uint8_t* des3cbc_vp_cipher_1 = (uint8_t*)"\xCA\x3A\x2B\x03\x6D\xBC\x85\x02";
uint8_t* des3cbc_vp_cipher_2 = (uint8_t*)"\x5E\x09\x05\x51\x7B\xB5\x9B\xCF";
uint8_t* des3cbc_vp_cipher_3 = (uint8_t*)"\x81\x4E\xEB\x3B\x91\xD9\x07\x26";
uint8_t* des3cbc_vp_cipher_4 = (uint8_t*)"\x4D\x49\xDB\x15\x32\x91\x9C\x9F";

CIPHERTEST des3cbc_vp_tests[] = {
    { "DES-EDE-CBC Variable Plaintext", 4, des3cbc_vp_key, des3cbc_vp_iv, des3cbc_vp_plain_1, des3cbc_vp_cipher_1, des3::recsize },
    { "DES-EDE-CBC Variable Plaintext", 4, des3cbc_vp_key, des3cbc_vp_iv, des3cbc_vp_plain_2, des3cbc_vp_cipher_2, des3::recsize },
    { "DES-EDE-CBC Variable Plaintext", 4, des3cbc_vp_key, des3cbc_vp_iv, des3cbc_vp_plain_3, des3cbc_vp_cipher_3, des3::recsize },
    { "DES-EDE-CBC Variable Plaintext", 4, des3cbc_vp_key, des3cbc_vp_iv, des3cbc_vp_plain_4, des3cbc_vp_cipher_4, des3::recsize }
};

// DES-EDE-CBC inverse permutation test vectors

uint8_t* des3cbc_ip_key = (uint8_t*)"\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01";

uint8_t* des3cbc_ip_iv = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00";

uint8_t* des3cbc_ip_plain_1 = (uint8_t*)"\x84\x05\xD1\xAB\xE2\x4F\xB9\x42";
uint8_t* des3cbc_ip_plain_2 = (uint8_t*)"\xE6\x43\xD7\x80\x90\xCA\x42\x07";
uint8_t* des3cbc_ip_plain_3 = (uint8_t*)"\x48\x22\x1B\x99\x37\x74\x8A\x23";
uint8_t* des3cbc_ip_plain_4 = (uint8_t*)"\xDD\x7C\x0B\xBD\x61\xFA\xFD\x54";

uint8_t* des3cbc_ip_cipher_1 = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x08\x00";
uint8_t* des3cbc_ip_cipher_2 = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x04\x00";
uint8_t* des3cbc_ip_cipher_3 = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x02\x00";
uint8_t* des3cbc_ip_cipher_4 = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x01\x00";

CIPHERTEST des3cbc_ip_tests[] = {
    { "DES-EDE-CBC Inverse Permutation", 4, des3cbc_ip_key, des3cbc_ip_iv, des3cbc_ip_plain_1, des3cbc_ip_cipher_1, des3::recsize },
    { "DES-EDE-CBC Inverse Permutation", 4, des3cbc_ip_key, des3cbc_ip_iv, des3cbc_ip_plain_2, des3cbc_ip_cipher_2, des3::recsize },
    { "DES-EDE-CBC Inverse Permutation", 4, des3cbc_ip_key, des3cbc_ip_iv, des3cbc_ip_plain_3, des3cbc_ip_cipher_3, des3::recsize },
    { "DES-EDE-CBC Inverse Permutation", 4, des3cbc_ip_key, des3cbc_ip_iv, des3cbc_ip_plain_4, des3cbc_ip_cipher_4, des3::recsize }
};

// DES-EDE-CBC variable key test vectors

uint8_t* des3cbc_vk_key_1 = (uint8_t*)"\x01\x01\x02\x01\x01\x01\x01\x01\x01\x01\x02\x01\x01\x01\x01\x01\x01\x01\x02\x01\x01\x01\x01\x01";
uint8_t* des3cbc_vk_key_2 = (uint8_t*)"\x01\x01\x01\x80\x01\x01\x01\x01\x01\x01\x01\x80\x01\x01\x01\x01\x01\x01\x01\x80\x01\x01\x01\x01";
uint8_t* des3cbc_vk_key_3 = (uint8_t*)"\x01\x01\x01\x40\x01\x01\x01\x01\x01\x01\x01\x40\x01\x01\x01\x01\x01\x01\x01\x40\x01\x01\x01\x01";
uint8_t* des3cbc_vk_key_4 = (uint8_t*)"\x01\x01\x01\x20\x01\x01\x01\x01\x01\x01\x01\x20\x01\x01\x01\x01\x01\x01\x01\x20\x01\x01\x01\x01";

uint8_t* des3cbc_vk_iv = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00";

uint8_t* des3cbc_vk_plain = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00";

uint8_t* des3cbc_vk_cipher_1 = (uint8_t*)"\xC7\x15\x16\xC2\x9C\x75\xD1\x70";
uint8_t* des3cbc_vk_cipher_2 = (uint8_t*)"\x51\x99\xC2\x9A\x52\xC9\xF0\x59";
uint8_t* des3cbc_vk_cipher_3 = (uint8_t*)"\xC2\x2F\x0A\x29\x4A\x71\xF2\x9F";
uint8_t* des3cbc_vk_cipher_4 = (uint8_t*)"\xEE\x37\x14\x83\x71\x4C\x02\xEA";

CIPHERTEST des3cbc_vk_tests[] = {
    { "DES-EDE-CBC Variable Key", 4, des3cbc_vk_key_1, des3cbc_vk_iv, des3cbc_vk_plain, des3cbc_vk_cipher_1, des3::recsize },
    { "DES-EDE-CBC Variable Key", 4, des3cbc_vk_key_2, des3cbc_vk_iv, des3cbc_vk_plain, des3cbc_vk_cipher_2, des3::recsize },
    { "DES-EDE-CBC Variable Key", 4, des3cbc_vk_key_3, des3cbc_vk_iv, des3cbc_vk_plain, des3cbc_vk_cipher_3, des3::recsize },
    { "DES-EDE-CBC Variable Key", 4, des3cbc_vk_key_4, des3cbc_vk_iv, des3cbc_vk_plain, des3cbc_vk_cipher_4, des3::recsize }
};

// DES-EDE-CBC permutation operation test vectors

uint8_t* des3cbc_po_key_1 = (uint8_t*)"\x19\x07\x92\x10\x98\x1A\x01\x01\x19\x07\x92\x10\x98\x1A\x01\x01\x19\x07\x92\x10\x98\x1A\x01\x01";
uint8_t* des3cbc_po_key_2 = (uint8_t*)"\x10\x07\x91\x19\x98\x19\x08\x01\x10\x07\x91\x19\x98\x19\x08\x01\x10\x07\x91\x19\x98\x19\x08\x01";
uint8_t* des3cbc_po_key_3 = (uint8_t*)"\x10\x07\x91\x19\x98\x1A\x08\x01\x10\x07\x91\x19\x98\x1A\x08\x01\x10\x07\x91\x19\x98\x1A\x08\x01";
uint8_t* des3cbc_po_key_4 = (uint8_t*)"\x10\x07\x92\x10\x98\x19\x01\x01\x10\x07\x92\x10\x98\x19\x01\x01\x10\x07\x92\x10\x98\x19\x01\x01";

uint8_t* des3cbc_po_iv = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00";

uint8_t* des3cbc_po_plain = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00";

uint8_t* des3cbc_po_cipher_1 = (uint8_t*)"\xAA\x85\xE7\x46\x43\x23\x31\x99";
uint8_t* des3cbc_po_cipher_2 = (uint8_t*)"\x2E\x5A\x19\xDB\x4D\x19\x62\xD6";
uint8_t* des3cbc_po_cipher_3 = (uint8_t*)"\x23\xA8\x66\xA8\x09\xD3\x08\x94";
uint8_t* des3cbc_po_cipher_4 = (uint8_t*)"\xD8\x12\xD9\x61\xF0\x17\xD3\x20";

CIPHERTEST des3cbc_po_tests[] = {
    { "DES-EDE-CBC Permutation Operation", 4, des3cbc_po_key_1, des3cbc_po_iv, des3cbc_po_plain, des3cbc_po_cipher_1, des3::recsize },
    { "DES-EDE-CBC Permutation Operation", 4, des3cbc_po_key_2, des3cbc_po_iv, des3cbc_po_plain, des3cbc_po_cipher_2, des3::recsize },
    { "DES-EDE-CBC Permutation Operation", 4, des3cbc_po_key_3, des3cbc_po_iv, des3cbc_po_plain, des3cbc_po_cipher_3, des3::recsize },
    { "DES-EDE-CBC Permutation Operation", 4, des3cbc_po_key_4, des3cbc_po_iv, des3cbc_po_plain, des3cbc_po_cipher_4, des3::recsize }
};

// DES-EDE-CBC substitution table test vectors

uint8_t* des3cbc_st_key_1 = (uint8_t*)"\x04\xB9\x15\xBA\x43\xFE\xB5\xB6\x04\xB9\x15\xBA\x43\xFE\xB5\xB6\x04\xB9\x15\xBA\x43\xFE\xB5\xB6";
uint8_t* des3cbc_st_key_2 = (uint8_t*)"\x01\x13\xB9\x70\xFD\x34\xF2\xCE\x01\x13\xB9\x70\xFD\x34\xF2\xCE\x01\x13\xB9\x70\xFD\x34\xF2\xCE";
uint8_t* des3cbc_st_key_3 = (uint8_t*)"\x01\x70\xF1\x75\x46\x8F\xB5\xE6\x01\x70\xF1\x75\x46\x8F\xB5\xE6\x01\x70\xF1\x75\x46\x8F\xB5\xE6";
uint8_t* des3cbc_st_key_4 = (uint8_t*)"\x43\x29\x7F\xAD\x38\xE3\x73\xFE\x43\x29\x7F\xAD\x38\xE3\x73\xFE\x43\x29\x7F\xAD\x38\xE3\x73\xFE";

uint8_t* des3cbc_st_iv = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00";

uint8_t* des3cbc_st_plain_1 = (uint8_t*)"\x42\xFD\x44\x30\x59\x57\x7F\xA2";
uint8_t* des3cbc_st_plain_2 = (uint8_t*)"\x05\x9B\x5E\x08\x51\xCF\x14\x3A";
uint8_t* des3cbc_st_plain_3 = (uint8_t*)"\x07\x56\xD8\xE0\x77\x47\x61\xD2";
uint8_t* des3cbc_st_plain_4 = (uint8_t*)"\x76\x25\x14\xB8\x29\xBF\x48\x6A";

uint8_t* des3cbc_st_cipher_1 = (uint8_t*)"\xAF\x37\xFB\x42\x1F\x8C\x40\x95";
uint8_t* des3cbc_st_cipher_2 = (uint8_t*)"\x86\xA5\x60\xF1\x0E\xC6\xD8\x5B";
uint8_t* des3cbc_st_cipher_3 = (uint8_t*)"\x0C\xD3\xDA\x02\x00\x21\xDC\x09";
uint8_t* des3cbc_st_cipher_4 = (uint8_t*)"\xEA\x67\x6B\x2C\xB7\xDB\x2B\x7A";

CIPHERTEST des3cbc_st_tests[] = {
    { "DES-EDE-CBC Substitution Table", 4, des3cbc_st_key_1, des3cbc_st_iv, des3cbc_st_plain_1, des3cbc_st_cipher_1, des3::recsize },
    { "DES-EDE-CBC Substitution Table", 4, des3cbc_st_key_2, des3cbc_st_iv, des3cbc_st_plain_2, des3cbc_st_cipher_2, des3::recsize },
    { "DES-EDE-CBC Substitution Table", 4, des3cbc_st_key_3, des3cbc_st_iv, des3cbc_st_plain_3, des3cbc_st_cipher_3, des3::recsize },
    { "DES-EDE-CBC Substitution Table", 4, des3cbc_st_key_4, des3cbc_st_iv, des3cbc_st_plain_4, des3cbc_st_cipher_4, des3::recsize }
};

// DES-EDE-CFB variable plaintext test vectors

uint8_t* des3cfb_vp_key = (uint8_t*)"\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01";

uint8_t* des3cfb_vp_iv_1 = (uint8_t*)"\x00\x00\x00\x00\x00\x80\x00\x00";
uint8_t* des3cfb_vp_iv_2 = (uint8_t*)"\x00\x00\x00\x00\x00\x40\x00\x00";
uint8_t* des3cfb_vp_iv_3 = (uint8_t*)"\x00\x00\x00\x00\x00\x20\x00\x00";
uint8_t* des3cfb_vp_iv_4 = (uint8_t*)"\x00\x00\x00\x00\x00\x10\x00\x00";

uint8_t* des3cfb_vp_plain = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00";

uint8_t* des3cfb_vp_cipher_1 = (uint8_t*)"\x25\xEB\x5F\xC3\xF8\xCF\x06\x21";
uint8_t* des3cfb_vp_cipher_2 = (uint8_t*)"\xAB\x6A\x20\xC0\x62\x0D\x1C\x6F";
uint8_t* des3cfb_vp_cipher_3 = (uint8_t*)"\x79\xE9\x0D\xBC\x98\xF9\x2C\xCA";
uint8_t* des3cfb_vp_cipher_4 = (uint8_t*)"\x86\x6E\xCE\xDD\x80\x72\xBB\x0E";

CIPHERTEST des3cfb_vp_tests[] = {
    { "DES-EDE-CFB Variable Plaintext", 4, des3cfb_vp_key, des3cfb_vp_iv_1, des3cfb_vp_plain, des3cfb_vp_cipher_1, des3::recsize },
    { "DES-EDE-CFB Variable Plaintext", 4, des3cfb_vp_key, des3cfb_vp_iv_2, des3cfb_vp_plain, des3cfb_vp_cipher_2, des3::recsize },
    { "DES-EDE-CFB Variable Plaintext", 4, des3cfb_vp_key, des3cfb_vp_iv_3, des3cfb_vp_plain, des3cfb_vp_cipher_3, des3::recsize },
    { "DES-EDE-CFB Variable Plaintext", 4, des3cfb_vp_key, des3cfb_vp_iv_4, des3cfb_vp_plain, des3cfb_vp_cipher_4, des3::recsize }
};

// DES-EDE-CFB inverse permutation test vectors

uint8_t* des3cfb_ip_key = (uint8_t*)"\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01";

uint8_t* des3cfb_ip_iv_1 = (uint8_t*)"\x2F\xBC\x29\x1A\x57\x0D\xB5\xC4";
uint8_t* des3cfb_ip_iv_2 = (uint8_t*)"\xE0\x7C\x30\xD7\xE4\xE2\x6E\x12";
uint8_t* des3cfb_ip_iv_3 = (uint8_t*)"\x09\x53\xE2\x25\x8E\x8E\x90\xA1";
uint8_t* des3cfb_ip_iv_4 = (uint8_t*)"\x5B\x71\x1B\xC4\xCE\xEB\xF2\xEE";

uint8_t* des3cfb_ip_plain = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00";

uint8_t* des3cfb_ip_cipher_1 = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x80";
uint8_t* des3cfb_ip_cipher_2 = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x40";
uint8_t* des3cfb_ip_cipher_3 = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x20";
uint8_t* des3cfb_ip_cipher_4 = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x10";

CIPHERTEST des3cfb_ip_tests[] = {
    { "DES-EDE-CFB Inverse Permuatation", 4, des3cfb_ip_key, des3cfb_ip_iv_1, des3cfb_ip_plain, des3cfb_ip_cipher_1, des3::recsize },
    { "DES-EDE-CFB Inverse Permuatation", 4, des3cfb_ip_key, des3cfb_ip_iv_2, des3cfb_ip_plain, des3cfb_ip_cipher_2, des3::recsize },
    { "DES-EDE-CFB Inverse Permuatation", 4, des3cfb_ip_key, des3cfb_ip_iv_3, des3cfb_ip_plain, des3cfb_ip_cipher_3, des3::recsize },
    { "DES-EDE-CFB Inverse Permuatation", 4, des3cfb_ip_key, des3cfb_ip_iv_4, des3cfb_ip_plain, des3cfb_ip_cipher_4, des3::recsize }
};

// DES-EDE-CFB variable key test vectors

uint8_t* des3cfb_vk_key_1 = (uint8_t*)"\x01\x01\x01\x10\x01\x01\x01\x01\x01\x01\x01\x10\x01\x01\x01\x01\x01\x01\x01\x10\x01\x01\x01\x01";
uint8_t* des3cfb_vk_key_2 = (uint8_t*)"\x01\x01\x01\x08\x01\x01\x01\x01\x01\x01\x01\x08\x01\x01\x01\x01\x01\x01\x01\x08\x01\x01\x01\x01";
uint8_t* des3cfb_vk_key_3 = (uint8_t*)"\x01\x01\x01\x04\x01\x01\x01\x01\x01\x01\x01\x04\x01\x01\x01\x01\x01\x01\x01\x04\x01\x01\x01\x01";
uint8_t* des3cfb_vk_key_4 = (uint8_t*)"\x01\x01\x01\x02\x01\x01\x01\x01\x01\x01\x01\x02\x01\x01\x01\x01\x01\x01\x01\x02\x01\x01\x01\x01";

uint8_t* des3cfb_vk_iv = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00";

uint8_t* des3cfb_vk_plain = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00";

uint8_t* des3cfb_vk_cipher_1 = (uint8_t*)"\xA8\x1F\xBD\x44\x8F\x9E\x52\x2F";
uint8_t* des3cfb_vk_cipher_2 = (uint8_t*)"\x4F\x64\x4C\x92\xE1\x92\xDF\xED";
uint8_t* des3cfb_vk_cipher_3 = (uint8_t*)"\x1A\xFA\x9A\x66\xA6\xDF\x92\xAE";
uint8_t* des3cfb_vk_cipher_4 = (uint8_t*)"\xB3\xC1\xCC\x71\x5C\xB8\x79\xD8";

CIPHERTEST des3cfb_vk_tests[] = {
    { "DES-EDE-CFB Variable Key", 4, des3cfb_vk_key_1, des3cfb_vk_iv, des3cfb_vk_plain, des3cfb_vk_cipher_1, des3::recsize },
    { "DES-EDE-CFB Variable Key", 4, des3cfb_vk_key_2, des3cfb_vk_iv, des3cfb_vk_plain, des3cfb_vk_cipher_2, des3::recsize },
    { "DES-EDE-CFB Variable Key", 4, des3cfb_vk_key_3, des3cfb_vk_iv, des3cfb_vk_plain, des3cfb_vk_cipher_3, des3::recsize },
    { "DES-EDE-CFB Variable Key", 4, des3cfb_vk_key_4, des3cfb_vk_iv, des3cfb_vk_plain, des3cfb_vk_cipher_4, des3::recsize }
};

// DES-EDE-CFB permutation operation test vectors

uint8_t* des3cfb_po_key_1 = (uint8_t*)"\x10\x07\x91\x15\x98\x19\x01\x0B\x10\x07\x91\x15\x98\x19\x01\x0B\x10\x07\x91\x15\x98\x19\x01\x0B";
uint8_t* des3cfb_po_key_2 = (uint8_t*)"\x10\x04\x80\x15\x98\x19\x01\x01\x10\x04\x80\x15\x98\x19\x01\x01\x10\x04\x80\x15\x98\x19\x01\x01";
uint8_t* des3cfb_po_key_3 = (uint8_t*)"\x10\x04\x80\x15\x98\x19\x01\x02\x10\x04\x80\x15\x98\x19\x01\x02\x10\x04\x80\x15\x98\x19\x01\x02";
uint8_t* des3cfb_po_key_4 = (uint8_t*)"\x10\x04\x80\x15\x98\x19\x01\x08\x10\x04\x80\x15\x98\x19\x01\x08\x10\x04\x80\x15\x98\x19\x01\x08";

uint8_t* des3cfb_po_iv = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00";

uint8_t* des3cfb_po_plain = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00";

uint8_t* des3cfb_po_cipher_1 = (uint8_t*)"\x05\x56\x05\x81\x6E\x58\x60\x8F";
uint8_t* des3cfb_po_cipher_2 = (uint8_t*)"\xAB\xD8\x8E\x8B\x1B\x77\x16\xF1";
uint8_t* des3cfb_po_cipher_3 = (uint8_t*)"\x53\x7A\xC9\x5B\xE6\x9D\xA1\xE1";
uint8_t* des3cfb_po_cipher_4 = (uint8_t*)"\xAE\xD0\xF6\xAE\x3C\x25\xCD\xD8";

CIPHERTEST des3cfb_po_tests[] = {
    { "DES-EDE-CFB Permutation Operation", 4, des3cfb_po_key_1, des3cfb_po_iv, des3cfb_po_plain, des3cfb_po_cipher_1, des3::recsize },
    { "DES-EDE-CFB Permutation Operation", 4, des3cfb_po_key_2, des3cfb_po_iv, des3cfb_po_plain, des3cfb_po_cipher_2, des3::recsize },
    { "DES-EDE-CFB Permutation Operation", 4, des3cfb_po_key_3, des3cfb_po_iv, des3cfb_po_plain, des3cfb_po_cipher_3, des3::recsize },
    { "DES-EDE-CFB Permutation Operation", 4, des3cfb_po_key_4, des3cfb_po_iv, des3cfb_po_plain, des3cfb_po_cipher_4, des3::recsize }
};

// DES-EDE-CFB substitution table test vectors

uint8_t* des3cfb_st_key_1 = (uint8_t*)"\x07\xA7\x13\x70\x45\xDA\x2A\x16\x07\xA7\x13\x70\x45\xDA\x2A\x16\x07\xA7\x13\x70\x45\xDA\x2A\x16";
uint8_t* des3cfb_st_key_2 = (uint8_t*)"\x04\x68\x91\x04\xC2\xFD\x3B\x2F\x04\x68\x91\x04\xC2\xFD\x3B\x2F\x04\x68\x91\x04\xC2\xFD\x3B\x2F";
uint8_t* des3cfb_st_key_3 = (uint8_t*)"\x37\xD0\x6B\xB5\x16\xCB\x75\x46\x37\xD0\x6B\xB5\x16\xCB\x75\x46\x37\xD0\x6B\xB5\x16\xCB\x75\x46";
uint8_t* des3cfb_st_key_4 = (uint8_t*)"\x1F\x08\x26\x0D\x1A\xC2\x46\x5E\x1F\x08\x26\x0D\x1A\xC2\x46\x5E\x1F\x08\x26\x0D\x1A\xC2\x46\x5E";

uint8_t* des3cfb_st_iv_1 = (uint8_t*)"\x3B\xDD\x11\x90\x49\x37\x28\x02";
uint8_t* des3cfb_st_iv_2 = (uint8_t*)"\x26\x95\x5F\x68\x35\xAF\x60\x9A";
uint8_t* des3cfb_st_iv_3 = (uint8_t*)"\x16\x4D\x5E\x40\x4F\x27\x52\x32";
uint8_t* des3cfb_st_iv_4 = (uint8_t*)"\x6B\x05\x6E\x18\x75\x9F\x5C\xCA";

uint8_t* des3cfb_st_plain = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00";

uint8_t* des3cfb_st_cipher_1 = (uint8_t*)"\xDF\xD6\x4A\x81\x5C\xAF\x1A\x0F";
uint8_t* des3cfb_st_cipher_2 = (uint8_t*)"\x5C\x51\x3C\x9C\x48\x86\xC0\x88";
uint8_t* des3cfb_st_cipher_3 = (uint8_t*)"\x0A\x2A\xEE\xAE\x3F\xF4\xAB\x77";
uint8_t* des3cfb_st_cipher_4 = (uint8_t*)"\xEF\x1B\xF0\x3E\x5D\xFA\x57\x5A";

CIPHERTEST des3cfb_st_tests[] = {
    { "DES-EDE-CFB Substitution Table", 4, des3cfb_st_key_1, des3cfb_st_iv_1, des3cfb_st_plain, des3cfb_st_cipher_1, des3::recsize },
    { "DES-EDE-CFB Substitution Table", 4, des3cfb_st_key_2, des3cfb_st_iv_2, des3cfb_st_plain, des3cfb_st_cipher_2, des3::recsize },
    { "DES-EDE-CFB Substitution Table", 4, des3cfb_st_key_3, des3cfb_st_iv_3, des3cfb_st_plain, des3cfb_st_cipher_3, des3::recsize },
    { "DES-EDE-CFB Substitution Table", 4, des3cfb_st_key_4, des3cfb_st_iv_4, des3cfb_st_plain, des3cfb_st_cipher_4, des3::recsize }
};

// DES-EDE-OFB variable plaintext test vectors

uint8_t* des3ofb_vp_key = (uint8_t*)"\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01";

uint8_t* des3ofb_vp_iv_1 = (uint8_t*)"\x00\x00\x00\x00\x00\x08\x00\x00";
uint8_t* des3ofb_vp_iv_2 = (uint8_t*)"\x00\x00\x00\x00\x00\x04\x00\x00";
uint8_t* des3ofb_vp_iv_3 = (uint8_t*)"\x00\x00\x00\x00\x00\x02\x00\x00";
uint8_t* des3ofb_vp_iv_4 = (uint8_t*)"\x00\x00\x00\x00\x00\x01\x00\x00";

uint8_t* des3ofb_vp_plain = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00";

uint8_t* des3ofb_vp_cipher_1 = (uint8_t*)"\x8B\x54\x53\x6F\x2F\x3E\x64\xA8";
uint8_t* des3ofb_vp_cipher_2 = (uint8_t*)"\xEA\x51\xD3\x97\x55\x95\xB8\x6B";
uint8_t* des3ofb_vp_cipher_3 = (uint8_t*)"\xCA\xFF\xC6\xAC\x45\x42\xDE\x31";
uint8_t* des3ofb_vp_cipher_4 = (uint8_t*)"\x8D\xD4\x5A\x2D\xDF\x90\x79\x6C";

CIPHERTEST des3ofb_vp_tests[] = {
    { "DES-EDE-OFB Variable Plaintext", 4, des3ofb_vp_key, des3ofb_vp_iv_1, des3ofb_vp_plain, des3ofb_vp_cipher_1, des3::recsize },
    { "DES-EDE-OFB Variable Plaintext", 4, des3ofb_vp_key, des3ofb_vp_iv_2, des3ofb_vp_plain, des3ofb_vp_cipher_2, des3::recsize },
    { "DES-EDE-OFB Variable Plaintext", 4, des3ofb_vp_key, des3ofb_vp_iv_3, des3ofb_vp_plain, des3ofb_vp_cipher_3, des3::recsize },
    { "DES-EDE-OFB Variable Plaintext", 4, des3ofb_vp_key, des3ofb_vp_iv_4, des3ofb_vp_plain, des3ofb_vp_cipher_4, des3::recsize }
};

// DES-EDE-OFB inverse permutation test vectors

uint8_t* des3ofb_ip_key = (uint8_t*)"\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01";

uint8_t* des3ofb_ip_iv_1 = (uint8_t*)"\xCC\x08\x3F\x1E\x6D\x9E\x85\xF6";
uint8_t* des3ofb_ip_iv_2 = (uint8_t*)"\xD2\xFD\x88\x67\xD5\x0D\x2D\xFE";
uint8_t* des3ofb_ip_iv_3 = (uint8_t*)"\x06\xE7\xEA\x22\xCE\x92\x70\x8F";
uint8_t* des3ofb_ip_iv_4 = (uint8_t*)"\x16\x6B\x40\xB4\x4A\xBA\x4B\xD6";

uint8_t* des3ofb_ip_plain = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00";

uint8_t* des3ofb_ip_cipher_1 = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x08";
uint8_t* des3ofb_ip_cipher_2 = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x04";
uint8_t* des3ofb_ip_cipher_3 = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x02";
uint8_t* des3ofb_ip_cipher_4 = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x01";

CIPHERTEST des3ofb_ip_tests[] = {
    { "DES-EDE-OFB Inverse Permutation", 4, des3ofb_ip_key, des3ofb_ip_iv_1, des3ofb_ip_plain, des3ofb_ip_cipher_1, des3::recsize },
    { "DES-EDE-OFB Inverse Permutation", 4, des3ofb_ip_key, des3ofb_ip_iv_2, des3ofb_ip_plain, des3ofb_ip_cipher_2, des3::recsize },
    { "DES-EDE-OFB Inverse Permutation", 4, des3ofb_ip_key, des3ofb_ip_iv_3, des3ofb_ip_plain, des3ofb_ip_cipher_3, des3::recsize },
    { "DES-EDE-OFB Inverse Permutation", 4, des3ofb_ip_key, des3ofb_ip_iv_4, des3ofb_ip_plain, des3ofb_ip_cipher_4, des3::recsize }
};

// DES-EDE-OFB variable key test vectors

uint8_t* des3ofb_vk_key_1 = (uint8_t*)"\x01\x01\x01\x01\x80\x01\x01\x01\x01\x01\x01\x01\x80\x01\x01\x01\x01\x01\x01\x01\x80\x01\x01\x01";
uint8_t* des3ofb_vk_key_2 = (uint8_t*)"\x01\x01\x01\x01\x40\x01\x01\x01\x01\x01\x01\x01\x40\x01\x01\x01\x01\x01\x01\x01\x40\x01\x01\x01";
uint8_t* des3ofb_vk_key_3 = (uint8_t*)"\x01\x01\x01\x01\x20\x01\x01\x01\x01\x01\x01\x01\x20\x01\x01\x01\x01\x01\x01\x01\x20\x01\x01\x01";
uint8_t* des3ofb_vk_key_4 = (uint8_t*)"\x01\x01\x01\x01\x10\x01\x01\x01\x01\x01\x01\x01\x10\x01\x01\x01\x01\x01\x01\x01\x10\x01\x01\x01";

uint8_t* des3ofb_vk_iv = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00";

uint8_t* des3ofb_vk_plain = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00";

uint8_t* des3ofb_vk_cipher_1 = (uint8_t*)"\x19\xD0\x32\xE6\x4A\xB0\xBD\x8B";
uint8_t* des3ofb_vk_cipher_2 = (uint8_t*)"\x3C\xFA\xA7\xA7\xDC\x87\x20\xDC";
uint8_t* des3ofb_vk_cipher_3 = (uint8_t*)"\xB7\x26\x5F\x7F\x44\x7A\xC6\xF3";
uint8_t* des3ofb_vk_cipher_4 = (uint8_t*)"\x9D\xB7\x3B\x3C\x0D\x16\x3F\x54";

CIPHERTEST des3ofb_vk_tests[] = {
    { "DES-EDE-OFB Variable Key", 4, des3ofb_vk_key_1, des3ofb_vk_iv, des3ofb_vk_plain, des3ofb_vk_cipher_1, des3::recsize },
    { "DES-EDE-OFB Variable Key", 4, des3ofb_vk_key_2, des3ofb_vk_iv, des3ofb_vk_plain, des3ofb_vk_cipher_2, des3::recsize },
    { "DES-EDE-OFB Variable Key", 4, des3ofb_vk_key_3, des3ofb_vk_iv, des3ofb_vk_plain, des3ofb_vk_cipher_3, des3::recsize },
    { "DES-EDE-OFB Variable Key", 4, des3ofb_vk_key_4, des3ofb_vk_iv, des3ofb_vk_plain, des3ofb_vk_cipher_4, des3::recsize }
};

// DES-EDE-OFB permutation operation test vectors

uint8_t* des3ofb_po_key_1 = (uint8_t*)"\x10\x02\x91\x15\x98\x10\x01\x04\x10\x02\x91\x15\x98\x10\x01\x04\x10\x02\x91\x15\x98\x10\x01\x04";
uint8_t* des3ofb_po_key_2 = (uint8_t*)"\x10\x02\x91\x15\x98\x19\x01\x04\x10\x02\x91\x15\x98\x19\x01\x04\x10\x02\x91\x15\x98\x19\x01\x04";
uint8_t* des3ofb_po_key_3 = (uint8_t*)"\x10\x02\x91\x15\x98\x10\x02\x01\x10\x02\x91\x15\x98\x10\x02\x01\x10\x02\x91\x15\x98\x10\x02\x01";
uint8_t* des3ofb_po_key_4 = (uint8_t*)"\x10\x02\x91\x16\x98\x10\x01\x01\x10\x02\x91\x16\x98\x10\x01\x01\x10\x02\x91\x16\x98\x10\x01\x01";

uint8_t* des3ofb_po_iv = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00";

uint8_t* des3ofb_po_plain = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00";

uint8_t* des3ofb_po_cipher_1 = (uint8_t*)"\xB3\xE3\x5A\x5E\xE5\x3E\x7B\x8D";
uint8_t* des3ofb_po_cipher_2 = (uint8_t*)"\x61\xC7\x9C\x71\x92\x1A\x2E\xF8";
uint8_t* des3ofb_po_cipher_3 = (uint8_t*)"\xE2\xF5\x72\x8F\x09\x95\x01\x3C";
uint8_t* des3ofb_po_cipher_4 = (uint8_t*)"\x1A\xEA\xC3\x9A\x61\xF0\xA4\x64";

CIPHERTEST des3ofb_po_tests[] = {
    { "DES-EDE-OFB Permutation Operation", 4, des3ofb_po_key_1, des3ofb_po_iv, des3ofb_po_plain, des3ofb_po_cipher_1, des3::recsize },
    { "DES-EDE-OFB Permutation Operation", 4, des3ofb_po_key_2, des3ofb_po_iv, des3ofb_po_plain, des3ofb_po_cipher_2, des3::recsize },
    { "DES-EDE-OFB Permutation Operation", 4, des3ofb_po_key_3, des3ofb_po_iv, des3ofb_po_plain, des3ofb_po_cipher_3, des3::recsize },
    { "DES-EDE-OFB Permutation Operation", 4, des3ofb_po_key_4, des3ofb_po_iv, des3ofb_po_plain, des3ofb_po_cipher_4, des3::recsize }
};

// DES-EDE-OFB substitution table test vectors

uint8_t* des3ofb_st_key_1 = (uint8_t*)"\x58\x40\x23\x64\x1A\xBA\x61\x76\x58\x40\x23\x64\x1A\xBA\x61\x76\x58\x40\x23\x64\x1A\xBA\x61\x76";
uint8_t* des3ofb_st_key_2 = (uint8_t*)"\x02\x58\x16\x16\x46\x29\xB0\x07\x02\x58\x16\x16\x46\x29\xB0\x07\x02\x58\x16\x16\x46\x29\xB0\x07";
uint8_t* des3ofb_st_key_3 = (uint8_t*)"\x49\x79\x3E\xBC\x79\xB3\x25\x8F\x49\x79\x3E\xBC\x79\xB3\x25\x8F\x49\x79\x3E\xBC\x79\xB3\x25\x8F";
uint8_t* des3ofb_st_key_4 = (uint8_t*)"\x4F\xB0\x5E\x15\x15\xAB\x73\xA7\x4F\xB0\x5E\x15\x15\xAB\x73\xA7\x4F\xB0\x5E\x15\x15\xAB\x73\xA7";

uint8_t* des3ofb_st_iv_1 = (uint8_t*)"\x00\x4B\xD6\xEF\x09\x17\x60\x62";
uint8_t* des3ofb_st_iv_2 = (uint8_t*)"\x48\x0D\x39\x00\x6E\xE7\x62\xF2";
uint8_t* des3ofb_st_iv_3 = (uint8_t*)"\x43\x75\x40\xC8\x69\x8F\x3C\xFA";
uint8_t* des3ofb_st_iv_4 = (uint8_t*)"\x07\x2D\x43\xA0\x77\x07\x52\x92";

uint8_t* des3ofb_st_plain = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00";

uint8_t* des3ofb_st_cipher_1 = (uint8_t*)"\x88\xBF\x0D\xB6\xD7\x0D\xEE\x56";
uint8_t* des3ofb_st_cipher_2 = (uint8_t*)"\xA1\xF9\x91\x55\x41\x02\x0B\x56";
uint8_t* des3ofb_st_cipher_3 = (uint8_t*)"\x6F\xBF\x1C\xAF\xCF\xFD\x05\x56";
uint8_t* des3ofb_st_cipher_4 = (uint8_t*)"\x2F\x22\xE4\x9B\xAB\x7C\xA1\xAC";

CIPHERTEST des3ofb_st_tests[] = {
    { "DES-EDE-OFB Substitution Table", 4, des3ofb_st_key_1, des3ofb_st_iv_1, des3ofb_st_plain, des3ofb_st_cipher_1, des3::recsize },
    { "DES-EDE-OFB Substitution Table", 4, des3ofb_st_key_2, des3ofb_st_iv_2, des3ofb_st_plain, des3ofb_st_cipher_2, des3::recsize },
    { "DES-EDE-OFB Substitution Table", 4, des3ofb_st_key_3, des3ofb_st_iv_3, des3ofb_st_plain, des3ofb_st_cipher_3, des3::recsize },
    { "DES-EDE-OFB Substitution Table", 4, des3ofb_st_key_4, des3ofb_st_iv_4, des3ofb_st_plain, des3ofb_st_cipher_4, des3::recsize }
};

// AES-ECB-128 test vectors

uint8_t* aes128ecb_key_1 = (uint8_t*)"\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c";
uint8_t* aes128ecb_key_2 = (uint8_t*)"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f";
uint8_t* aes128ecb_key_3 = (uint8_t*)"\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
uint8_t* aes128ecb_key_4 = (uint8_t*)"\x10\xa5\x88\x69\xd7\x4b\xe5\xa3\x74\xcf\x86\x7c\xfb\x47\x38\x59";
uint8_t* aes128ecb_key_5 = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

uint8_t* aes128ecb_plain_1 = (uint8_t*)"\x32\x43\xf6\xa8\x88\x5a\x30\x8d\x31\x31\x98\xa2\xe0\x37\x07\x34";
uint8_t* aes128ecb_plain_2 = (uint8_t*)"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff";
uint8_t* aes128ecb_plain_3 = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
uint8_t* aes128ecb_plain_4 = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
uint8_t* aes128ecb_plain_5 = (uint8_t*)"\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

uint8_t* aes128ecb_cipher_1 = (uint8_t*)"\x39\x25\x84\x1d\x02\xdc\x09\xfb\xdc\x11\x85\x97\x19\x6a\x0b\x32";
uint8_t* aes128ecb_cipher_2 = (uint8_t*)"\x69\xc4\xe0\xd8\x6a\x7b\x04\x30\xd8\xcd\xb7\x80\x70\xb4\xc5\x5a";
uint8_t* aes128ecb_cipher_3 = (uint8_t*)"\x0e\xdd\x33\xd3\xc6\x21\xe5\x46\x45\x5b\xd8\xba\x14\x18\xbe\xc8";
uint8_t* aes128ecb_cipher_4 = (uint8_t*)"\x6d\x25\x1e\x69\x44\xb0\x51\xe0\x4e\xaa\x6f\xb4\xdb\xf7\x84\x65";
uint8_t* aes128ecb_cipher_5 = (uint8_t*)"\x3a\xd7\x8e\x72\x6c\x1e\xc0\x2b\x7e\xbf\xe9\x2b\x23\xd9\xec\x34";

CIPHERTEST aes128ecb_tests[] = {
    { "AES-128-ECB", 5, aes128ecb_key_1, nullptr, aes128ecb_plain_1, aes128ecb_cipher_1, aes::blockbytes },
    { "AES-128-ECB", 5, aes128ecb_key_2, nullptr, aes128ecb_plain_2, aes128ecb_cipher_2, aes::blockbytes },
    { "AES-128-ECB", 5, aes128ecb_key_3, nullptr, aes128ecb_plain_3, aes128ecb_cipher_3, aes::blockbytes },
    { "AES-128-ECB", 5, aes128ecb_key_4, nullptr, aes128ecb_plain_4, aes128ecb_cipher_4, aes::blockbytes },
    { "AES-128-ECB", 5, aes128ecb_key_5, nullptr, aes128ecb_plain_5, aes128ecb_cipher_5, aes::blockbytes }
};

// AES-ECB-192 test vectors

uint8_t* aes192ecb_key_1 = (uint8_t*)"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17";
uint8_t* aes192ecb_key_2 = (uint8_t*)"\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
uint8_t* aes192ecb_key_3 = (uint8_t*)"\xe9\xf0\x65\xd7\xc1\x35\x73\x58\x7f\x78\x75\x35\x7d\xfb\xb1\x6c\x53\x48\x9f\x6a\x4b\xd0\xf7\xcd";
uint8_t* aes192ecb_key_4 = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

uint8_t* aes192ecb_plain_1 = (uint8_t*)"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff";
uint8_t* aes192ecb_plain_2 = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
uint8_t* aes192ecb_plain_3 = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
uint8_t* aes192ecb_plain_4 = (uint8_t*)"\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

uint8_t* aes192ecb_cipher_1 = (uint8_t*)"\xdd\xa9\x7c\xa4\x86\x4c\xdf\xe0\x6e\xaf\x70\xa0\xec\x0d\x71\x91";
uint8_t* aes192ecb_cipher_2 = (uint8_t*)"\xde\x88\x5d\xc8\x7f\x5a\x92\x59\x40\x82\xd0\x2c\xc1\xe1\xb4\x2c";
uint8_t* aes192ecb_cipher_3 = (uint8_t*)"\x09\x56\x25\x9c\x9c\xd5\xcf\xd0\x18\x1c\xca\x53\x38\x0c\xde\x06";
uint8_t* aes192ecb_cipher_4 = (uint8_t*)"\x6c\xd0\x25\x13\xe8\xd4\xdc\x98\x6b\x4a\xfe\x08\x7a\x60\xbd\x0c";

CIPHERTEST aes192ecb_tests[] = {
    { "AES-192-ECB", 4, aes192ecb_key_1, nullptr, aes192ecb_plain_1, aes192ecb_cipher_1, aes::blockbytes },
    { "AES-192-ECB", 4, aes192ecb_key_2, nullptr, aes192ecb_plain_2, aes192ecb_cipher_2, aes::blockbytes },
    { "AES-192-ECB", 4, aes192ecb_key_3, nullptr, aes192ecb_plain_3, aes192ecb_cipher_3, aes::blockbytes },
    { "AES-192-ECB", 4, aes192ecb_key_4, nullptr, aes192ecb_plain_4, aes192ecb_cipher_4, aes::blockbytes }
};

// AES-ECB-256 test vectors

uint8_t* aes256ecb_key_1 = (uint8_t*)"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f";
uint8_t* aes256ecb_key_2 = (uint8_t*)"\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
uint8_t* aes256ecb_key_3 = (uint8_t*)"\xc4\x7b\x02\x94\xdb\xbb\xee\x0f\xec\x47\x57\xf2\x2f\xfe\xee\x35\x87\xca\x47\x30\xc3\xd3\x3b\x69\x1d\xf3\x8b\xab\x07\x6b\xc5\x58";
uint8_t* aes256ecb_key_4 = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

uint8_t* aes256ecb_plain_1 = (uint8_t*)"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff";
uint8_t* aes256ecb_plain_2 = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
uint8_t* aes256ecb_plain_3 = (uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
uint8_t* aes256ecb_plain_4 = (uint8_t*)"\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

uint8_t* aes256ecb_cipher_1 = (uint8_t*)"\x8e\xa2\xb7\xca\x51\x67\x45\xbf\xea\xfc\x49\x90\x4b\x49\x60\x89";
uint8_t* aes256ecb_cipher_2 = (uint8_t*)"\xe3\x5a\x6d\xcb\x19\xb2\x01\xa0\x1e\xbc\xfa\x8a\xa2\x2b\x57\x59";
uint8_t* aes256ecb_cipher_3 = (uint8_t*)"\x46\xf2\xfb\x34\x2d\x6f\x0a\xb4\x77\x47\x6f\xc5\x01\x24\x2c\x5f";
uint8_t* aes256ecb_cipher_4 = (uint8_t*)"\xdd\xc6\xbf\x79\x0c\x15\x76\x0d\x8d\x9a\xeb\x6f\x9a\x75\xfd\x4e";

CIPHERTEST aes256ecb_tests[] = {
    { "AES-256-ECB", 4, aes256ecb_key_1, nullptr, aes256ecb_plain_1, aes256ecb_cipher_1, aes::blockbytes },
    { "AES-256-ECB", 4, aes256ecb_key_2, nullptr, aes256ecb_plain_2, aes256ecb_cipher_2, aes::blockbytes },
    { "AES-256-ECB", 4, aes256ecb_key_3, nullptr, aes256ecb_plain_3, aes256ecb_cipher_3, aes::blockbytes },
    { "AES-256-ECB", 4, aes256ecb_key_4, nullptr, aes256ecb_plain_4, aes256ecb_cipher_4, aes::blockbytes }
};

// AES-CBC-128 test vectors

uint8_t* aes128cbc_key_1 = (uint8_t*)"\x2B\x7E\x15\x16\x28\xAE\xD2\xA6\xAB\xF7\x15\x88\x09\xCF\x4F\x3C";
uint8_t* aes128cbc_key_2 = (uint8_t*)"\x2B\x7E\x15\x16\x28\xAE\xD2\xA6\xAB\xF7\x15\x88\x09\xCF\x4F\x3C";
uint8_t* aes128cbc_key_3 = (uint8_t*)"\x2B\x7E\x15\x16\x28\xAE\xD2\xA6\xAB\xF7\x15\x88\x09\xCF\x4F\x3C";
uint8_t* aes128cbc_key_4 = (uint8_t*)"\x2B\x7E\x15\x16\x28\xAE\xD2\xA6\xAB\xF7\x15\x88\x09\xCF\x4F\x3C";

uint8_t* aes128cbc_iv_1 = (uint8_t*)"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F";
uint8_t* aes128cbc_iv_2 = (uint8_t*)"\x76\x49\xAB\xAC\x81\x19\xB2\x46\xCE\xE9\x8E\x9B\x12\xE9\x19\x7D";
uint8_t* aes128cbc_iv_3 = (uint8_t*)"\x50\x86\xCB\x9B\x50\x72\x19\xEE\x95\xDB\x11\x3A\x91\x76\x78\xB2";
uint8_t* aes128cbc_iv_4 = (uint8_t*)"\x73\xBE\xD6\xB8\xE3\xC1\x74\x3B\x71\x16\xE6\x9E\x22\x22\x95\x16";

uint8_t* aes128cbc_plain_1 = (uint8_t*)"\x6B\xC1\xBE\xE2\x2E\x40\x9F\x96\xE9\x3D\x7E\x11\x73\x93\x17\x2A";
uint8_t* aes128cbc_plain_2 = (uint8_t*)"\xAE\x2D\x8A\x57\x1E\x03\xAC\x9C\x9E\xB7\x6F\xAC\x45\xAF\x8E\x51";
uint8_t* aes128cbc_plain_3 = (uint8_t*)"\x30\xC8\x1C\x46\xA3\x5C\xE4\x11\xE5\xFB\xC1\x19\x1A\x0A\x52\xEF";
uint8_t* aes128cbc_plain_4 = (uint8_t*)"\xF6\x9F\x24\x45\xDF\x4F\x9B\x17\xAD\x2B\x41\x7B\xE6\x6C\x37\x10";

uint8_t* aes128cbc_cipher_1 = (uint8_t*)"\x76\x49\xAB\xAC\x81\x19\xB2\x46\xCE\xE9\x8E\x9B\x12\xE9\x19\x7D";
uint8_t* aes128cbc_cipher_2 = (uint8_t*)"\x50\x86\xCB\x9B\x50\x72\x19\xEE\x95\xDB\x11\x3A\x91\x76\x78\xB2";
uint8_t* aes128cbc_cipher_3 = (uint8_t*)"\x73\xBE\xD6\xB8\xE3\xC1\x74\x3B\x71\x16\xE6\x9E\x22\x22\x95\x16";
uint8_t* aes128cbc_cipher_4 = (uint8_t*)"\x3F\xF1\xCA\xA1\x68\x1F\xAC\x09\x12\x0E\xCA\x30\x75\x86\xE1\xA7";

CIPHERTEST aes128cbc_tests[] = {
    { "AES-128-CBC", 4, aes128cbc_key_1, aes128cbc_iv_1, aes128cbc_plain_1, aes128cbc_cipher_1, aes::blockbytes },
    { "AES-128-CBC", 4, aes128cbc_key_2, aes128cbc_iv_2, aes128cbc_plain_2, aes128cbc_cipher_2, aes::blockbytes },
    { "AES-128-CBC", 4, aes128cbc_key_3, aes128cbc_iv_3, aes128cbc_plain_3, aes128cbc_cipher_3, aes::blockbytes },
    { "AES-128-CBC", 4, aes128cbc_key_4, aes128cbc_iv_4, aes128cbc_plain_4, aes128cbc_cipher_4, aes::blockbytes }
};

// AES-CBC-192 test vectors

uint8_t* aes192cbc_key_1 = (uint8_t*)"\x8E\x73\xB0\xF7\xDA\x0E\x64\x52\xC8\x10\xF3\x2B\x80\x90\x79\xE5\x62\xF8\xEA\xD2\x52\x2C\x6B\x7B";
uint8_t* aes192cbc_key_2 = (uint8_t*)"\x8E\x73\xB0\xF7\xDA\x0E\x64\x52\xC8\x10\xF3\x2B\x80\x90\x79\xE5\x62\xF8\xEA\xD2\x52\x2C\x6B\x7B";
uint8_t* aes192cbc_key_3 = (uint8_t*)"\x8E\x73\xB0\xF7\xDA\x0E\x64\x52\xC8\x10\xF3\x2B\x80\x90\x79\xE5\x62\xF8\xEA\xD2\x52\x2C\x6B\x7B";
uint8_t* aes192cbc_key_4 = (uint8_t*)"\x8E\x73\xB0\xF7\xDA\x0E\x64\x52\xC8\x10\xF3\x2B\x80\x90\x79\xE5\x62\xF8\xEA\xD2\x52\x2C\x6B\x7B";

uint8_t* aes192cbc_iv_1 = (uint8_t*)"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F";
uint8_t* aes192cbc_iv_2 = (uint8_t*)"\x4F\x02\x1D\xB2\x43\xBC\x63\x3D\x71\x78\x18\x3A\x9F\xA0\x71\xE8";
uint8_t* aes192cbc_iv_3 = (uint8_t*)"\xB4\xD9\xAD\xA9\xAD\x7D\xED\xF4\xE5\xE7\x38\x76\x3F\x69\x14\x5A";
uint8_t* aes192cbc_iv_4 = (uint8_t*)"\x57\x1B\x24\x20\x12\xFB\x7A\xE0\x7F\xA9\xBA\xAC\x3D\xF1\x02\xE0";

uint8_t* aes192cbc_plain_1 = (uint8_t*)"\x6B\xC1\xBE\xE2\x2E\x40\x9F\x96\xE9\x3D\x7E\x11\x73\x93\x17\x2A";
uint8_t* aes192cbc_plain_2 = (uint8_t*)"\xAE\x2D\x8A\x57\x1E\x03\xAC\x9C\x9E\xB7\x6F\xAC\x45\xAF\x8E\x51";
uint8_t* aes192cbc_plain_3 = (uint8_t*)"\x30\xC8\x1C\x46\xA3\x5C\xE4\x11\xE5\xFB\xC1\x19\x1A\x0A\x52\xEF";
uint8_t* aes192cbc_plain_4 = (uint8_t*)"\xF6\x9F\x24\x45\xDF\x4F\x9B\x17\xAD\x2B\x41\x7B\xE6\x6C\x37\x10";

uint8_t* aes192cbc_cipher_1 = (uint8_t*)"\x4F\x02\x1D\xB2\x43\xBC\x63\x3D\x71\x78\x18\x3A\x9F\xA0\x71\xE8";
uint8_t* aes192cbc_cipher_2 = (uint8_t*)"\xB4\xD9\xAD\xA9\xAD\x7D\xED\xF4\xE5\xE7\x38\x76\x3F\x69\x14\x5A";
uint8_t* aes192cbc_cipher_3 = (uint8_t*)"\x57\x1B\x24\x20\x12\xFB\x7A\xE0\x7F\xA9\xBA\xAC\x3D\xF1\x02\xE0";
uint8_t* aes192cbc_cipher_4 = (uint8_t*)"\x08\xB0\xE2\x79\x88\x59\x88\x81\xD9\x20\xA9\xE6\x4F\x56\x15\xCD";

CIPHERTEST aes192cbc_tests[] = {
    { "AES-192-CBC", 4, aes192cbc_key_1, aes192cbc_iv_1, aes192cbc_plain_1, aes192cbc_cipher_1, aes::blockbytes },
    { "AES-192-CBC", 4, aes192cbc_key_2, aes192cbc_iv_2, aes192cbc_plain_2, aes192cbc_cipher_2, aes::blockbytes },
    { "AES-192-CBC", 4, aes192cbc_key_3, aes192cbc_iv_3, aes192cbc_plain_3, aes192cbc_cipher_3, aes::blockbytes },
    { "AES-192-CBC", 4, aes192cbc_key_4, aes192cbc_iv_4, aes192cbc_plain_4, aes192cbc_cipher_4, aes::blockbytes }
};

// AES-CBC-256 test vectors

uint8_t* aes256cbc_key_1 = (uint8_t*)"\x60\x3D\xEB\x10\x15\xCA\x71\xBE\x2B\x73\xAE\xF0\x85\x7D\x77\x81\x1F\x35\x2C\x07\x3B\x61\x08\xD7\x2D\x98\x10\xA3\x09\x14\xDF\xF4";
uint8_t* aes256cbc_key_2 = (uint8_t*)"\x60\x3D\xEB\x10\x15\xCA\x71\xBE\x2B\x73\xAE\xF0\x85\x7D\x77\x81\x1F\x35\x2C\x07\x3B\x61\x08\xD7\x2D\x98\x10\xA3\x09\x14\xDF\xF4";
uint8_t* aes256cbc_key_3 = (uint8_t*)"\x60\x3D\xEB\x10\x15\xCA\x71\xBE\x2B\x73\xAE\xF0\x85\x7D\x77\x81\x1F\x35\x2C\x07\x3B\x61\x08\xD7\x2D\x98\x10\xA3\x09\x14\xDF\xF4";
uint8_t* aes256cbc_key_4 = (uint8_t*)"\x60\x3D\xEB\x10\x15\xCA\x71\xBE\x2B\x73\xAE\xF0\x85\x7D\x77\x81\x1F\x35\x2C\x07\x3B\x61\x08\xD7\x2D\x98\x10\xA3\x09\x14\xDF\xF4";

uint8_t* aes256cbc_iv_1 = (uint8_t*)"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F";
uint8_t* aes256cbc_iv_2 = (uint8_t*)"\xF5\x8C\x4C\x04\xD6\xE5\xF1\xBA\x77\x9E\xAB\xFB\x5F\x7B\xFB\xD6";
uint8_t* aes256cbc_iv_3 = (uint8_t*)"\x9C\xFC\x4E\x96\x7E\xDB\x80\x8D\x67\x9F\x77\x7B\xC6\x70\x2C\x7D";
uint8_t* aes256cbc_iv_4 = (uint8_t*)"\x39\xF2\x33\x69\xA9\xD9\xBA\xCF\xA5\x30\xE2\x63\x04\x23\x14\x61";

uint8_t* aes256cbc_plain_1 = (uint8_t*)"\x6B\xC1\xBE\xE2\x2E\x40\x9F\x96\xE9\x3D\x7E\x11\x73\x93\x17\x2A";
uint8_t* aes256cbc_plain_2 = (uint8_t*)"\xAE\x2D\x8A\x57\x1E\x03\xAC\x9C\x9E\xB7\x6F\xAC\x45\xAF\x8E\x51";
uint8_t* aes256cbc_plain_3 = (uint8_t*)"\x30\xC8\x1C\x46\xA3\x5C\xE4\x11\xE5\xFB\xC1\x19\x1A\x0A\x52\xEF";
uint8_t* aes256cbc_plain_4 = (uint8_t*)"\xF6\x9F\x24\x45\xDF\x4F\x9B\x17\xAD\x2B\x41\x7B\xE6\x6C\x37\x10";

uint8_t* aes256cbc_cipher_1 = (uint8_t*)"\xF5\x8C\x4C\x04\xD6\xE5\xF1\xBA\x77\x9E\xAB\xFB\x5F\x7B\xFB\xD6";
uint8_t* aes256cbc_cipher_2 = (uint8_t*)"\x9C\xFC\x4E\x96\x7E\xDB\x80\x8D\x67\x9F\x77\x7B\xC6\x70\x2C\x7D";
uint8_t* aes256cbc_cipher_3 = (uint8_t*)"\x39\xF2\x33\x69\xA9\xD9\xBA\xCF\xA5\x30\xE2\x63\x04\x23\x14\x61";
uint8_t* aes256cbc_cipher_4 = (uint8_t*)"\xB2\xEB\x05\xE2\xC3\x9B\xE9\xFC\xDA\x6C\x19\x07\x8C\x6A\x9D\x1B";

CIPHERTEST aes256cbc_tests[]{
    { "AES-256-CBC", 4, aes256cbc_key_1, aes256cbc_iv_1, aes256cbc_plain_1, aes256cbc_cipher_1, aes::blockbytes },
    { "AES-256-CBC", 4, aes256cbc_key_2, aes256cbc_iv_2, aes256cbc_plain_2, aes256cbc_cipher_2, aes::blockbytes },
    { "AES-256-CBC", 4, aes256cbc_key_3, aes256cbc_iv_3, aes256cbc_plain_3, aes256cbc_cipher_3, aes::blockbytes },
    { "AES-256-CBC", 4, aes256cbc_key_4, aes256cbc_iv_4, aes256cbc_plain_4, aes256cbc_cipher_4, aes::blockbytes }
};

// ANSI X9.31 test vectors: ANSI X9.31 Appendix A.2.4 using Triple-DES

uint8_t* x931des3_key = (uint8_t*)"\xfb\xf7\x31\x26\xd0\xd3\xbf\x51\xae\xce\x9d\x98\xa1\x13\xc8\x68\xb9\x16\x15\xb9\x1f\x6d\xb9\x26";
uint8_t* x931des3_dt = (uint8_t*)"\x5c\x8d\x9e\x2d\x2b\x61\x9b\x0e";
uint8_t* x931des3_v = (uint8_t*)"\x80\x00\x00\x00\x00\x00\x00\x00";
uint8_t* x931des3_r = (uint8_t*)"\xF7\xdf\x53\x33\x3a\x5b\x44\xeb";

// PBKDF2 test vectors: https://tools.ietf.org/html/draft-josefsson-ppkdf2-test-vectors-06

uint8_t* pbkdf2_p_1 = (uint8_t*)"password";
uint8_t* pbkdf2_s_1 = (uint8_t*)"salt";
uint32_t pbkdf2_c_1 = 1;
uint32_t pbkdf2_dklen_1 = 20;
uint8_t* pbkdf2_o_1 = (uint8_t*)"\x0c\x60\xc8\x0f\x96\x1f\x0e\x71\xf3\xa9\xb5\x24\xaf\x60\x12\x06\x2f\xe0\x37\xa6";

uint8_t* pbkdf2_p_2 = (uint8_t*)"password";
uint8_t* pbkdf2_s_2 = (uint8_t*)"salt";
uint32_t pbkdf2_c_2 = 2;
uint32_t pbkdf2_dklen_2 = 20;
uint8_t* pbkdf2_o_2 = (uint8_t*)"\xea\x6c\x01\x4d\xc7\x2d\x6f\x8c\xcd\x1e\xd9\x2a\xce\x1d\x41\xf0\xd8\xde\x89\x57";

// large integer test vectors

uint8_t* inthex_vector_1 = (uint8_t*)
"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
"\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
"\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f";

// complression test value

#define COMPRESS_RECORD     "When in the Course of human events it becomes necessary " \
                            "for one people to dissolve the political bands which have " \
                            "connected them with another and to assume among the powers " \
                            "of the earth, the separate and equal station to which the " \
                            "Laws of Nature and of Nature's God entitle them, a decent " \
                            "respect to the opinions of mankind requires that they " \
                            "should declare the causes which impel them to the separation."

const uint16_t encPassPhrase[] = {

 0X2FF, 0X15D,  0X6B, 0X1FF, 0X16F,  0X75, 0X3BF,  0XF7,
 0X1BD,  0XFD,  0X0D,  0X6F, 0X155,  0X07, 0X17B,  0XD7,  //   !"#$%&'()*+,-./
  0X1B,  0X7D,  0XAF, 0X1AF,  0XBF,  0X2B,  0X0B,  0XAB,
 0X1ED, 0X1AD,  0X05, 0X1B7, 0X1EF, 0X1FB,  0X1D, 0X1D5,  //  0123456789:;<=>?
 0X1AB,  0XFB,  0X7F,  0X3B,  0XDD, 0X1FD, 0X1DF,  0X55,
 0X1DD,  0X0F,  0X1F,  0XB7,  0X5B, 0X17D, 0X157, 0X1BB,  //  @ABCDEFGHIJKLMNO
 0X1B5,  0XB5,  0XAD,  0XDF,  0X3D,  0X03,  0XED, 0X177,
 0X1DB, 0X15B, 0X175, 0X3EF,  0XFF, 0X37F,  0X37,  0X3F,  //  PQRSTUVWXYZ[\]^_
 0X16D,  0X5F, 0X17F,  0XBD,  0X15, 0X1F7, 0X1EB,  0XBB,
  0X77,  0X2D,  0XEB, 0X15F,  0XD5, 0X1D7,  0X6D,  0X35,  //  `abcdefghijklmno
  0X01,  0X57, 0X1F5,  0XF5,  0X7B,  0X2F,  0X17,  0XEF,
 0X16B,  0XDB,  0X5D, 0X3F7, 0X3DF, 0X3FF, 0X1BF,     0   //  pqrstuvwxyz{|}~
};

const uint16_t distrPassPhrase[] = {

  39,  89, 200, 162, 280, 111, 147,  17,     60, 255, 304, 132, 177,  48, 226,   4,
 239, 269, 293,  99,  26,  72, 152, 264,    313, 115,  47, 219,  12, 141, 260, 298,
  21, 210, 281, 309,  30,  78, 187, 245,     62,   1, 125, 192, 275, 171, 103, 137,
  55, 230, 316, 248, 194,  81,  34, 284,     42,  83, 181, 290, 251, 242,  24,  94,
 204, 156, 234, 121,   9,  53, 165, 296,    235, 107,  67, 223, 261, 154, 196,   8,
 143, 212, 252, 184, 301, 312,  97,  74,     36, 266, 306, 237, 318,  65,  14,  44,
  70, 128, 216, 188, 286, 232, 272, 314,    258, 138, 116, 149,  32,   6,  57,   0,
 159, 277, 307, 256, 108,  86, 123,  28,     10,  91,  41, 198, 291, 310, 250, 134,

  50,  87,  11, 319, 288, 246, 201, 220,    173, 100,  79, 140, 175, 206, 130, 118,
  76, 214, 302,  45,   3, 294, 207, 109,    145,  18, 221, 299,  16, 270, 243,  80,
  20, 135, 253, 287, 126, 112,  38,  46,      7, 167, 183, 227, 202, 190, 102, 127,
 233, 292, 169, 139,  23,  15, 150, 229,    267, 105,  85, 228, 148, 120, 164, 217,
 240, 124,  68,  51, 178, 241, 224, 208,    185, 129,  27,  59, 300, 179, 213, 144,
 104,  95, 155, 142,  66,  49, 273, 297,    157,  92,  64,  22, 153, 236, 282, 161,
  52,  25, 182, 244, 262, 199, 131,  29,    146, 254, 158, 211, 278, 303, 231, 160,
  82,  13, 163, 133, 249, 289, 317, 151,    174, 106, 257,  54,  33, 114, 166,  93,

 193, 225, 274, 222, 285, 308, 276,  19,    238, 283, 113,  84,  35,  40,   2, 218,
 263, 305, 259, 180, 209,  96,  75, 119,     56,   5,  88, 215, 170, 271, 176, 195,
  98,  77, 122,  37, 189, 279, 191, 168,    268, 315,  71, 110,  63, 172, 186, 311,
  73, 117,  61, 101, 205,  69, 203, 197
};

