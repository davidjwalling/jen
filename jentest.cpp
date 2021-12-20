#include "jentest.h"
#include "base64.h"
#include "compress.h"
#include "file.h"
#include "hmac.h"
#include "md5.h"
#include "num.h"
#include "passphrase.h"
#include "pbc2.h"
#include "prng.h"
#include "random.h"
#include "rsa.h"
#include "sha.h"
#include "x509.h"

#include <chrono>

bool _all = false;
bool _dump = false;

void queryRun(const char* prompt, void(*fn)())
{
    char ch[3] = { 0 };
    if (!_all) {
        printf("Run %s Tests? (y/N) ", prompt);
        fflush(stdin);
        fgets(ch, sizeof(ch), stdin);
        if (('y' == ch[0]) || ('Y' == ch[0]))
            fn();
    } else
        fn();
}

void dumpMem(uint8_t* p, size_t len)
{
    uint16_t adr = 0;
    uint16_t col = 0;
    uint8_t byte;
    char line[73];
    memset(line, ' ', sizeof(line));
    line[54] = '|';
    line[71] = '|';
    line[72] = '\0';
    for (; len; adr += 16) {
        line[0] = Bin2AscHex[(adr >> 12) & 15];
        line[1] = Bin2AscHex[(adr >> 8) & 15];
        line[2] = Bin2AscHex[(adr >> 4) & 15];
        line[3] = Bin2AscHex[(adr) & 15];
        for (col = 0; col < 16; col++) {
            if (len) {
                len--;
                byte = *p++;
                line[col + 55] = Bin2AscPrt[byte];
                line[col * 3 + 6] = Bin2AscHex[(byte >> 4) & 15];
                line[col * 3 + 7] = Bin2AscHex[(byte) & 15];
            } else {
                line[col + 55] = ' ';
                line[col * 3 + 6] = ' ';
                line[col * 3 + 7] = ' ';
            }
        }
        printf("%s\n", line);
    }
}

void testDigest(Digest& digest, uint8_t* hash, DIGESTTEST* tests)
{
    printf("Testing %s\n", tests[0].label);
    if (!_dump)
        printf("\n");
    for (int x = 0; x < tests[0].count; x++) {
        digest.Begin();
        for (int i = tests[x].iter; i; i--)
            digest.Update(tests[x].vector, tests[x].len);
        digest.End();
        digest.GetDigest(hash);
        if (_dump) {
            printf("\n");
            printf("Vector (iterated %i %s):\n", tests[x].iter, tests[x].iter > 1 ? "times" : "time");
            dumpMem(tests[x].vector, tests[x].len);
            printf("Digest:\n");
            dumpMem(hash, digest._hashBytes);
            printf("\n");
        }
        printf("%-5s %s %i of %i\n", memcmp(hash, tests[x].digest, digest._hashBytes) ? "FAIL" : "OK", tests[x].label, x + 1, tests[x].count);
    }
    printf("\n");
}

void testMD5()
{
    uint8_t hash[md5::hashbytes] = { 0 };
    MD5 digest;
    testDigest(digest, hash, md5_tests);
}

void testSHA1()
{
    uint8_t hash[sha1::hashbytes] = { 0 };
    SHA1 sha;
    testDigest(sha, hash, sha1_tests);
}

void testSHA256()
{
    uint8_t hash[sha256::hashbytes] = { 0 };
    SHA256 sha;
    testDigest(sha, hash, sha256_tests);
}

void testSHA224()
{
    uint8_t hash[sha224::hashbytes] = { 0 };
    SHA224 sha;
    testDigest(sha, hash, sha224_tests);
}

void testSHA512()
{
    uint8_t hash[sha512::hashbytes] = { 0 };
    SHA512 sha;
    testDigest(sha, hash, sha512_tests);
}

void testSHA384()
{
    uint8_t hash[sha384::hashbytes] = { 0 };
    SHA384 sha;
    testDigest(sha, hash, sha384_tests);
}

void testDigestAlgs()
{
    queryRun(md5_tests[0].label, testMD5);
    queryRun(sha1_tests[0].label, testSHA1);
    queryRun(sha256_tests[0].label, testSHA256);
    queryRun(sha224_tests[0].label, testSHA224);
    queryRun(sha512_tests[0].label, testSHA512);
    queryRun(sha384_tests[0].label, testSHA384);
}

void testHMAC(uint8_t alg, HMACTEST* tests)
{
    uint8_t buf[hmac::maxhashbytes] = { 0 };
    HMAC hmac;
    printf("Testing %s\n", tests[0].label);
    if (!_dump)
        printf("\n");
    hmac.SetDigestAlg(alg);
    for (int x = 0; x < tests[0].count; x++) {
        hmac.SetKey(tests[x].key, tests[x].keylen);
        hmac.Begin();
        hmac.Update(tests[x].data, tests[x].datalen);
        hmac.End();
        hmac.GetMAC(buf, sizeof(buf));
        if (_dump) {
            printf("\n");
            printf("Key:\n");
            dumpMem(tests[x].key, tests[x].keylen);
            printf("Data:\n");
            dumpMem(tests[x].data, tests[x].datalen);
            printf("Digest:\n");
            dumpMem(tests[x].digest, tests[x].digestlen);
            printf("HMAC:\n");
            dumpMem(buf, tests[x].digestlen);
            printf("\n");
        }
        printf("%-5s %s %i of %i\n", memcmp(buf, tests[x].digest, tests[x].digestlen) ? "FAIL" : "OK", tests[x].label, x + 1, tests[x].count);
    }
    printf("\n");
}

void testHMACMD5()
{
    testHMAC(hmac::alg::md5, hmac_md5_tests);
}

void testHMACSHA1()
{
    testHMAC(hmac::alg::sha1, hmac_sha1_tests);
}

void testHMACSHA256()
{
    testHMAC(hmac::alg::sha256, hmac_sha256_tests);
}

void testHMACSHA224()
{
    testHMAC(hmac::alg::sha224, hmac_sha224_tests);
}

void testHMACSHA512()
{
    testHMAC(hmac::alg::sha512, hmac_sha512_tests);
}

void testHMACSHA384()
{
    testHMAC(hmac::alg::sha384, hmac_sha384_tests);
}

void testHMACAlgs()
{
    queryRun("HMAC-MD5", testHMACMD5);
    queryRun("HMAC-SHA1", testHMACSHA1);
    queryRun("HMAC-SHA256", testHMACSHA256);
    queryRun("HMAC-SHA224", testHMACSHA224);
    queryRun("HMAC-SHA512", testHMACSHA512);
    queryRun("HMAC-SHA384", testHMACSHA384);
}

void testCipher(Cipher& cipher, uint8_t* ct, uint8_t* pt, CIPHERTEST* tests)
{
    printf("Testing %s\n", tests[0].label);
    if (!_dump)
        printf("\n");
    for (int x = 0; x < tests[0].count; x++) {
        cipher.SetKey(tests[x].key);
        if (tests[x].iv) cipher.SetIV(tests[x].iv);
        cipher.Encrypt(tests[x].plain, ct);
        if (tests[x].iv) cipher.SetIV(tests[x].iv);
        cipher.Decrypt(ct, pt);
        if (_dump) {
            printf("\n");
            printf("Key:\n");
            dumpMem(tests[x].key, tests[x].len);
            if (tests[x].iv) {
                printf("IV:\n");
                dumpMem(tests[x].iv, cipher.GetBlockBytes());
            }
            printf("Plain:\n");
            dumpMem(tests[x].plain, tests[x].len);
            printf("Cipher:\n");
            dumpMem(tests[x].cipher, tests[x].len);
            printf("Encrypted:\n");
            dumpMem(ct, cipher.GetBlockBytes());
            printf("Decrypted:\n");
            dumpMem(pt, cipher.GetBlockBytes());
            printf("\n");
        }
        printf("%-5s %s %i of %i Encryption\n", memcmp(ct, tests[x].cipher, cipher.GetBlockBytes()) ? "FAIL" : "OK", tests[x].label, x + 1, tests[x].count);
        printf("%-5s %s %i of %i Decryption\n", memcmp(pt, tests[x].plain, cipher.GetBlockBytes()) ? "FAIL" : "OK", tests[x].label, x + 1, tests[x].count);
    }
    printf("\n");
}

void testDESECB()
{
    uint8_t ct[des::recsize];
    uint8_t pt[des::recsize];
    DES des;
    testCipher(des, ct, pt, desecb_vp_tests);
    testCipher(des, ct, pt, desecb_ip_tests);
    testCipher(des, ct, pt, desecb_vk_tests);
    testCipher(des, ct, pt, desecb_po_tests);
    testCipher(des, ct, pt, desecb_st_tests);
}

void testDESCBC()
{
    uint8_t ct[des::recsize];
    uint8_t pt[des::recsize];
    DESCBC des;
    testCipher(des, ct, pt, descbc_vp_tests);
    testCipher(des, ct, pt, descbc_ip_tests);
    testCipher(des, ct, pt, descbc_vk_tests);
    testCipher(des, ct, pt, descbc_po_tests);
    testCipher(des, ct, pt, descbc_st_tests);
}

void testDESCFB()
{
    uint8_t ct[des::recsize];
    uint8_t pt[des::recsize];
    DESCFB des;
    testCipher(des, ct, pt, descfb_vp_tests);
    testCipher(des, ct, pt, descfb_ip_tests);
    testCipher(des, ct, pt, descfb_vk_tests);
    testCipher(des, ct, pt, descfb_po_tests);
    testCipher(des, ct, pt, descfb_st_tests);
}

void testDESOFB()
{
    uint8_t ct[des::recsize];
    uint8_t pt[des::recsize];
    DESOFB des;
    testCipher(des, ct, pt, desofb_vp_tests);
    testCipher(des, ct, pt, desofb_ip_tests);
    testCipher(des, ct, pt, desofb_vk_tests);
    testCipher(des, ct, pt, desofb_po_tests);
    testCipher(des, ct, pt, desofb_st_tests);
}

void testDES()
{
    queryRun("DES-ECB", testDESECB);
    queryRun("DES-CBC", testDESCBC);
    queryRun("DES-CFB", testDESCFB);
    queryRun("DES-OFB", testDESOFB);
}

void testDES3ECB()
{
    uint8_t ct[des3::recsize];
    uint8_t pt[des3::recsize];
    DES3 des;
    testCipher(des, ct, pt, des3ecb_vp_tests);
    testCipher(des, ct, pt, des3ecb_ip_tests);
    testCipher(des, ct, pt, des3ecb_vk_tests);
    testCipher(des, ct, pt, des3ecb_po_tests);
    testCipher(des, ct, pt, des3ecb_st_tests);
}

void testDES3CBC()
{
    uint8_t ct[des3::recsize];
    uint8_t pt[des3::recsize];
    DES3CBC des;
    testCipher(des, ct, pt, des3cbc_vp_tests);
    testCipher(des, ct, pt, des3cbc_ip_tests);
    testCipher(des, ct, pt, des3cbc_vk_tests);
    testCipher(des, ct, pt, des3cbc_po_tests);
    testCipher(des, ct, pt, des3cbc_st_tests);
}

void testDES3CFB()
{
    uint8_t ct[des3::recsize];
    uint8_t pt[des3::recsize];
    DES3CFB des;
    testCipher(des, ct, pt, des3cfb_vp_tests);
    testCipher(des, ct, pt, des3cfb_ip_tests);
    testCipher(des, ct, pt, des3cfb_vk_tests);
    testCipher(des, ct, pt, des3cfb_po_tests);
    testCipher(des, ct, pt, des3cfb_st_tests);
}

void testDES3OFB()
{
    uint8_t ct[des3::recsize];
    uint8_t pt[des3::recsize];
    DES3OFB des;
    testCipher(des, ct, pt, des3ofb_vp_tests);
    testCipher(des, ct, pt, des3ofb_ip_tests);
    testCipher(des, ct, pt, des3ofb_vk_tests);
    testCipher(des, ct, pt, des3ofb_po_tests);
    testCipher(des, ct, pt, des3ofb_st_tests);
}

void testDES3()
{
    queryRun("DES-EDE-ECB", testDES3ECB);
    queryRun("DES-EDE-CBC", testDES3CBC);
    queryRun("DES-EDE-CFB", testDES3CFB);
    queryRun("DES-EDE-OFB", testDES3OFB);
}

void testAESECB()
{
    uint8_t ct[aes::blockbytes];
    uint8_t pt[aes::blockbytes];
    AES128ECB aes128ecb;
    testCipher(aes128ecb, ct, pt, aes128ecb_tests);
    AES192ECB aes192ecb;
    testCipher(aes192ecb, ct, pt, aes192ecb_tests);
    AES256ECB aes256ecb;
    testCipher(aes256ecb, ct, pt, aes256ecb_tests);
}

void testAESCBC()
{
    uint8_t ct[aes::blockbytes];
    uint8_t pt[aes::blockbytes];
    AES128CBC aes128cbc;
    testCipher(aes128cbc, ct, pt, aes128cbc_tests);
    AES192CBC aes192cbc;
    testCipher(aes192cbc, ct, pt, aes192cbc_tests);
    AES256CBC aes256cbc;
    testCipher(aes256cbc, ct, pt, aes256cbc_tests);
}

void testAES()
{
    queryRun("AES-ECB", testAESECB);
    queryRun("AES-CBC", testAESCBC);
}

void testSymmetricEncryption()
{
    queryRun("DES", testDES);
    queryRun("DES-EDE (Triple-DES)", testDES3);
    queryRun("AES", testAES);
}

void testFastRandom()
{
    int i;
    uint32_t h, j;
    union {
        uint32_t k[640]; // 20,480 bits
        uint8_t kb[2560];
    } kval;
    uint32_t nybs[16]; // nybble accumulators
    uint32_t a[8]; // 1's run lengths
    uint32_t b[8]; // 0's run lengths
    double dbl, dbl2;
    uint8_t l, m, v, x, y, z;
    Random rand;
    printf("Testing Fast Pseudo-Random Algorithm\n\n");
    for (i = 0; i < 80; i++) {
        for (j = 0; j < 8; j++) {
            h = rand.Rand();
            printf(" %08X", h);
            kval.k[(i * 8) + j] = h;
        }
        printf("\n");
    }
    printf("\nRandom Distribution by Bit\n\n");
    dbl2 = 0;
    for (i = 1; i; i <<= 1) {
        dbl = 0;
        for (j = 0; j < 640; j++) {
            if (kval.k[j] & i)
                dbl++;
        }
        dbl /= 640;
        printf(" 0x%08X = %lf %s\n", i, dbl, ((dbl >= 0.55) || (dbl < 0.45) ? "<--" : " "));
        dbl2 += dbl;
    }
    printf("\nAverage Distribution by Bit = %lf\n", (dbl2 / 32));
    printf("\nCounting the number of one's in a 20,000 bit random stream (\"monobit\" test)\n");
    h = 0;
    for (i = 0; i < 625; i++) {
        j = kval.k[i];
        h += ByteOnes[(j >> 24) & 0xFF];
        h += ByteOnes[(j >> 16) & 0xFF];
        h += ByteOnes[(j >> 8) & 0xFF];
        h += ByteOnes[(j) & 0xFF];
    }
    printf("\n Total ones in 20,000 random bits = %d", h);
    printf("\n This is %s the FIPS 140-2 acceptable range of 9,725 to 10,275\n", ((h <= 9725) || (h >= 10275)) ? "outside" : "within");
    printf("\nCounting the number of instance of distinct nybbles in 20,000 bit random stream (\"poker\" test)\n\n");
    for (i = 0; i < 16; i++) { nybs[i] = 0; }
    for (i = 0; i < 625; i++) {
        j = kval.k[i];
        nybs[(j >> 28) & 0x0f]++;
        nybs[(j >> 24) & 0x0f]++;
        nybs[(j >> 20) & 0x0f]++;
        nybs[(j >> 16) & 0x0f]++;
        nybs[(j >> 12) & 0x0f]++;
        nybs[(j >> 8) & 0x0f]++;
        nybs[(j >> 4) & 0x0f]++;
        nybs[(j) & 0x0f]++;
    }
    for (i = 0; i < 16; i++) printf(" 0x%02X : %d\n", i, nybs[i]);
    for (i = 0, dbl = 0; i < 16; i++) dbl += ((uint64_t)nybs[i] * nybs[i]);
    dbl2 = 16;
    dbl2 /= 5000;
    dbl2 *= dbl;
    dbl2 -= 5000;
    printf("\n Poker test result = %lf\n", (dbl2));
    printf(" This is %s the FIPS 140-2 acceptable range of 2.16 to 46.17\n", ((dbl2 <= 2.16) || (dbl2 >= 46.17)) ? "outside" : "within");
    printf("\nPerforming \"runs\" test on 20,000 bit random stream\n\n");
    for (i = 0; i < 8; i++) { a[i] = 0, b[i] = 0; }
    for (i = 0, m = 6, z = 0xFF; i < 2500; i++) {
        x = kval.kb[i];
        y = (uint8_t)(x & 0x80);
        v = (uint8_t)(y ? ~x : x);
        if (y == z) {
            if (m < 6) {
                if (y)
                    a[m]--;
                else
                    b[m]--;
                m = (uint8_t)(m + ByteRuns[v][0]);
                if (m > 6)
                    m = 6;
                if (y)
                    a[m]++;
                else
                    b[m]++;
            }
            j = 1;
        } else
            j = 0;
        for (; j < 8; j++) {
            l = ByteRuns[v][j];
            if (!l)
                break;
            m = (uint8_t)(l > 5 ? 6 : l);
            if (y)
                if (!(j & 1))
                    a[m]++;
                else
                    b[m]++;
            else if (j & 1)
                a[m]++;
            else
                b[m]++;
        }
        z = (uint8_t)(x & 1 ? 0x80 : 0);
    }
    printf(" 1 one  = %4d %4s   1 zero  = %4d %4s\n", a[1], ((a[1] < 2343) || (a[1] > 2657)) ? "FAIL" : "OK", b[1], ((b[1] < 2343) || (b[1] > 2657)) ? "FAIL" : "OK");
    printf(" 2 ones = %4d %4s   2 zeros = %4d %4s\n", a[2], ((a[2] < 1135) || (a[2] > 1365)) ? "FAIL" : "OK", b[2], ((b[2] < 1135) || (b[2] > 1365)) ? "FAIL" : "OK");
    printf(" 3 ones = %4d %4s   3 zeros = %4d %4s\n", a[3], ((a[3] < 542) || (a[3] > 708)) ? "FAIL" : "OK", b[3], ((b[3] < 542) || (b[3] > 708)) ? "FAIL" : "OK");
    printf(" 4 ones = %4d %4s   4 zeros = %4d %4s\n", a[4], ((a[4] < 251) || (a[4] > 373)) ? "FAIL" : "OK", b[4], ((b[4] < 251) || (b[4] > 373)) ? "FAIL" : "OK");
    printf(" 5 ones = %4d %4s   5 zeros = %4d %4s\n", a[5], ((a[5] < 111) || (a[5] > 201)) ? "FAIL" : "OK", b[5], ((b[5] < 111) || (b[5] > 201)) ? "FAIL" : "OK");
    printf(">5 ones = %4d %4s  >5 zeros = %4d %4s\n\n", a[6], ((a[6] < 111) || (a[6] > 201)) ? "FAIL" : "OK", b[6], ((b[6] < 111) || (b[6] > 201)) ? "FAIL" : "OK");

    printf("Measuring 1,000 iterations of RANDOM::random()\n");
    auto start = std::chrono::steady_clock::now();
    for (i = 0; i < 1000; i++) {
        rand.Rand();
    }
    auto end = std::chrono::steady_clock::now();
    std::chrono::duration<double> elapsed = end - start;
    printf("RANDOM::Random() time: %0.4fms  avg: %0.6fms\n\n", elapsed.count() * 1000, elapsed.count());
}

void testX931Random()
{
    uint32_t h;
    uint8_t plain[cipher::recsize];
    uint8_t cipher_pre[cipher::recsize];
    uint8_t mask[cipher::recsize];
    uint8_t cipher[cipher::recsize];
    uint8_t random_pre[cipher::recsize];
    uint8_t random[cipher::recsize];
    DES3 des3;
    PRNG prng;
    printf("Testing ANSI X9.31 Pseudo-Random Generation\n");
    if (!_dump)
        printf("\n");
    des3.SetKey(x931des3_key);
    memcpy(plain, x931des3_dt, sizeof(plain));
    memcpy(mask, x931des3_v, sizeof(mask));
    des3.Encrypt(plain, cipher_pre);
    for (h = 0; h < sizeof(cipher); h++) { cipher[h] = cipher_pre[h] ^ mask[h]; }
    des3.Encrypt(cipher, random_pre);
    for (h = 0; h < sizeof(random); h++) { random[h] = random_pre[h] ^ mask[h]; }
    if (_dump) {
        printf("\n");
        printf("Key:\n");
        dumpMem(x931des3_key, 24);
        printf("Plain:\n");
        dumpMem(plain, sizeof(plain));
        printf("Mask:\n");
        dumpMem(mask, sizeof(mask));
        printf("Cipher (before mask):\n");
        dumpMem(cipher_pre, sizeof(cipher_pre));
        printf("Cipher (after mask):\n");
        dumpMem(cipher, sizeof(cipher));
        printf("Random (before mask):\n");
        dumpMem(random_pre, sizeof(random_pre));
        printf("Random (after mask):\n");
        dumpMem(random, sizeof(random));
        printf("\n");
    }
    printf("%-5s ANSI X9.31 1 of 1\n\n", !memcmp(random, x931des3_r, sizeof(random)) ? "OK" : "FAIL");
}

void testPBKDF2()
{
    PBC2 pbc2;
    uint8_t dk[20] = { 0 };
    printf("Testing Password-Based Key Derivation Function 2 (PBKDF2)\n");
    if (!_dump)
        printf("\n");
    pbc2.SetPassword(pbkdf2_p_1, 8);
    pbc2.SetSalt(pbkdf2_s_1, 4);
    pbc2.SetCount(1);
    pbc2.DeriveKey(dk, sizeof(dk));
    if (_dump) {
        printf("\n");
        printf("Password:\n");
        dumpMem(pbkdf2_p_1, 8);
        printf("Salt\n");
        dumpMem(pbkdf2_s_1, 4);
        printf("Count: %u\n", 1);
        printf("Derived Key Length: %u\n", 20);
        printf("Derived Key:\n");
        dumpMem(dk, sizeof(dk));
        printf("\n");
    }
    printf("%-5s PBKDF2 1 of 1\n\n", !memcmp(dk, pbkdf2_o_1, sizeof(dk)) ? "OK" : "FAIL");
}

void testRandom()
{
    queryRun("Fast Random", testFastRandom);
    queryRun("X9.31 Random", testX931Random);
    queryRun("PBKDF2 Key Derivation", testPBKDF2);
}

void testInt()
{
    size_t bits;
    uint32_t i, j;
    Num A, B, C, D, E, X, Y, G;
    Random rand;
    uint8_t bytebuf[256];

    printf("Testing Large Integer Arithmetic\n\n");

    printf("Testing Num::bits()\n\n");
    A.Init();
    printf("%-5s Num::bits() 1 of 4\n", 1 == A.bits() ? "OK" : "FAIL");
    A._word[21] = 0x00000008;
    A._hiword = 21;
    printf("%-5s Num::bits() 2 of 4\n", num::wordbits * 21 + 4 == A.bits() ? "OK" : "FAIL");
    A._byte[num::bytes - 1] = 0x80;
    A._hiword = num::words - 1;
    printf("%-5s Num::bits() 3 of 4\n", num::bits == A.bits() ? "OK" : "FAIL");
    A.Init();
    for (i = 0; i < num::words; i++) {
        A._hiword = i;
        bits = A.bits();
        if (bits >> num::bit2word != i)
            break;
    }
    printf("%-5s Num::bits() 4 of 4\n\n", i == num::words ? "OK" : "FAIL");

    printf("Measuring 1,000 iterations of Num::bits()\n");
    A.Init();
    A._hiword = (num::words >> 1) - 1;
    for (i = 0; i <= A._hiword; i++) {
        A._word[i] = rand.Rand();
    }
    auto start = std::chrono::steady_clock::now();
    for (i = 0; i < 1000; i++) {
        A.bits();
    }
    auto end = std::chrono::steady_clock::now();
    std::chrono::duration<double> elapsed = end - start;
    printf("Num::bits() time: %0.4fms  avg: %0.6fms\n\n", elapsed.count() * 1000, elapsed.count());

    printf("Testing Num::bytes()\n\n");
    A.Init();
    printf("%-5s Num::bytes() 1 of 3\n", 1 == A.bytes() ? "OK" : "FAIL");
    A._byte[44] = 0xff;
    A._hiword = (44 >> num::byte2word);
    printf("%-5s Num::bytes() 2 of 3\n", 45 == A.bytes() ? "OK" : "FAIL");
    A._byte[num::hibyte] = 0xff;
    A._hiword = num::hiword;
    printf("%-5s Num::bytes() 3 of 3\n\n", num::bytes == A.bytes() ? "OK" : "FAIL");

    printf("Measuring 1,000 iterations of Num::bytes()\n");
    A.Init();
    A._hiword = (num::words >> 1) - 1;
    for (i = 0; i <= A._hiword; i++) { A._word[i] = rand.Rand(); }
    start = std::chrono::steady_clock::now();
    for (i = 0; i < 1000; i++) { A.bytes(); }
    end = std::chrono::steady_clock::now();
    elapsed = end - start;
    printf("Num::bytes() time: %0.4fms  avg: %0.6fms\n\n", elapsed.count() * 1000, elapsed.count());

    printf("Testing Num::words()\n\n");
    A.Init();
    A._hiword = 31;
    printf("%-5s Num::words() 1 of 1\n\n", 32 == A.words() ? "OK" : "FAIL");

    printf("Measuring 1,000 iterations of Num::words()\n");
    start = std::chrono::steady_clock::now();
    for (i = 0; i < 1000; i++) { A.words(); }
    end = std::chrono::steady_clock::now();
    elapsed = end - start;
    printf("Num::words() time: %0.4fms  avg: %0.6fms\n\n", elapsed.count() * 1000, elapsed.count());

    printf("Testing Num::bit()\n\n");
    A.Init();
    A._word[0] = 0x12345678;
    A._word[1] = 0xfedcba98;
    A._word[num::hiword] = (uint32_t)num::hibitmask - 1;
    printf("%-5s Num::bit() 1 of 3\n", 1 == A.bit(18) ? "OK" : "FAIL");
    printf("%-5s Num::bit() 2 of 3\n", 0 == A.bit(53) ? "OK" : "FAIL");
    printf("%-5s Num::bit() 3 of 3\n\n", 0 == A.bit(num::bits - 1) ? "OK" : "FAIL");

    printf("Measuring 1,000 iterations of Num::bit()\n");
    start = std::chrono::steady_clock::now();
    for (i = 0; i < 1000; i++) { A.bit(269); }
    end = std::chrono::steady_clock::now();
    elapsed = end - start;
    printf("Num::bit() time: %0.4fms  avg: %0.6fms\n\n", elapsed.count() * 1000, elapsed.count());

    printf("Testing Num::byte()\n\n");
    A.Init();
    A._byte[0] = 0x12;
    A._byte[6] = 0xdc;
    A._byte[num::hibyte] = 0x7f;
    printf("%-5s Num::byte() 1 of 3\n", 0x12 == A.byte(0) ? "OK" : "FAIL");
    printf("%-5s Num::byte() 2 of 3\n", 0xdc == A.byte(6) ? "OK" : "FAIL");
    printf("%-5s Num::byte() 3 of 3\n\n", 0x7f == A.byte(num::hibyte) ? "OK" : "FAIL");

    printf("Measuring 1,000 iterations of Num::byte()\n");
    start = std::chrono::steady_clock::now();
    for (i = 0; i < 1000; i++) { A.byte(44); }
    end = std::chrono::steady_clock::now();
    elapsed = end - start;
    printf("Num::byte() time: %0.4fms  avg: %0.6fms\n\n", elapsed.count() * 1000, elapsed.count());

    printf("Testing Num::word()\n\n");
    A.Init();
    A._word[0] = 0x76543210;
    A._word[1] = 0xfedcba98;
    A._word[num::hiword] = (uint32_t)num::hibitmask - 1;
    printf("%-5s Num::word() 1 of 3\n", (0x76543210 == A.word(0)) ? "OK" : "FAIL");
    printf("%-5s Num::word() 2 of 3\n", (0xfedcba98 == A.word(1)) ? "OK" : "FAIL");
    printf("%-5s Num::word() 3 of 3\n\n", (uint32_t)num::hibitmask - 1 == A.word(num::hiword) ? "OK" : "FAIL");

    printf("Measuring 1,000 iterations of Num::word()\n");
    start = std::chrono::steady_clock::now();
    for (i = 0; i < 1000; i++) { A.word(17); }
    end = std::chrono::steady_clock::now();
    elapsed = end - start;
    printf("Num::word() time: %0.4fms  avg: %0.6fms\n\n", elapsed.count() * 1000, elapsed.count());

    printf("Testing Num::resetBit()\n\n");
    A.Init();
    A._word[0] = (uint32_t)-1;
    A.resetBit(23);
    printf("%-5s Num::resetBit() 1 of 4\n", (0x7f == A._byte[2]) ? "OK" : "FAIL");
    A.resetBit(0);
    printf("%-5s Num::resetBit() 2 of 4\n", (0xfe == A._byte[0]) ? "OK" : "FAIL");
    A._word[num::hiword] = (uint32_t)-1;
    A.resetBit(num::bits - 1);
    printf("%-5s Num::resetBit() 3 of 4\n", (0x7f == A._byte[num::hibyte]) ? "OK" : "FAIL");
    A._word[1] = (uint32_t)num::hibitmask - 1;
    A.resetBit(num::wordbits);
    printf("%-5s Num::resetBit() 4 of 4\n\n", (0xfe == A._byte[num::wordbytes]) ? "OK" : "FAIL");

    printf("Measuring 1,000 iterations of Num::resetBit()\n");
    start = std::chrono::steady_clock::now();
    for (i = 0; i < 1000; i++) { A.resetBit(147); }
    end = std::chrono::steady_clock::now();
    elapsed = end - start;
    printf("Num::resetBit() time: %0.4fms  avg: %0.6fms\n\n", elapsed.count() * 1000, elapsed.count());

    printf("Testing Num::resetByte()\n\n");
    A.Init();
    A._byte[73] = 0xff;
    A.resetByte(73);
    printf("%-5s Num::resetByte() 1 of 3\n", (0x00 == A._byte[73]) ? "OK" : "FAIL");
    A.Init();
    A._byte[0] = 0xff;
    A.resetByte(0);
    printf("%-5s Num::resetByte() 2 of 3\n", (0x00 == A._byte[0]) ? "OK" : "FAIL");
    A.Init();
    A._byte[num::hibyte] = 0xff;
    A.resetByte(num::hibyte);
    printf("%-5s Num::resetByte() 3 of 3\n\n", (0x00 == A._byte[num::hibyte]) ? "OK" : "FAIL");

    printf("Measuring 1,000 iterations of Num::resetByte()\n");
    start = std::chrono::steady_clock::now();
    for (i = 0; i < 1000; i++) { A.resetByte(66); }
    end = std::chrono::steady_clock::now();
    elapsed = end - start;
    printf("Num::resetByte() time: %0.4fms  avg: %0.6fms\n\n", elapsed.count() * 1000, elapsed.count());

    printf("Testing Num::resetWord()\n\n");
    A.Init();
    A._word[2] = 1;
    A.resetWord(2);
    printf("%-5s Num::resetWord() 1 of 1\n\n", (0 == A._word[0]) ? "OK" : "FAIL");

    printf("Measuring 1,000 iterations of Num::resetWord()\n");
    start = std::chrono::steady_clock::now();
    for (i = 0; i < 1000; i++) { A.resetWord(2); }
    end = std::chrono::steady_clock::now();
    elapsed = end - start;
    printf("Num::resetWord() time: %0.4fms  avg: %0.6fms\n\n", elapsed.count() * 1000, elapsed.count());

    printf("Testing Num::setBit()\n\n");
    A.Init();
    A.setBit(196);
    printf("%-5s Num::setBit() 1 of 3\n", (0x10 == A._byte[24]) ? "OK" : "FAIL");
    A.Init();
    A._byte[0] = 0x5a;
    A.setBit(0);
    printf("%-5s Num::setBit() 2 of 3\n", (0x5b == A._byte[0]) ? "OK" : "FAIL");
    A.Init();
    A._word[num::hiword] = 0;
    A.setBit(num::hibit);
    printf("%-5s Num::setBit() 3 of 3\n\n", (0x80 == A._byte[num::hibyte]) ? "OK" : "FAIL");

    printf("Measuring 1,000 iterations of Num::setBit()\n");
    start = std::chrono::steady_clock::now();
    for (i = 0; i < 1000; i++) { A.setBit(147); }
    end = std::chrono::steady_clock::now();
    elapsed = end - start;
    printf("Num::setBit() time: %0.4fms  avg: %0.6fms\n\n", elapsed.count() * 1000, elapsed.count());

    printf("Testing Num::setByte()\n\n");
    A.Init();
    A.setByte(73, 0x5a);
    printf("%-5s Num::setByte() 1 of 3\n", (0x5a == A._byte[73]) ? "OK" : "FAIL");
    A.Init();
    A.setByte(0, 0xbb);
    printf("%-5s Num::setByte() 2 of 3\n", (0xbb == A._byte[0]) ? "OK" : "FAIL");
    A.Init();
    A.setByte(num::hibyte, 0xa2);
    printf("%-5s Num::setByte() 3 of 3\n\n", (0xa2 == A._byte[num::hibyte]) ? "OK" : "FAIL");

    printf("Measuring 1,000 iterations of Num::setByte()\n");
    start = std::chrono::steady_clock::now();
    for (i = 0; i < 1000; i++) { A.setByte(66, 0x33); }
    end = std::chrono::steady_clock::now();
    elapsed = end - start;
    printf("Num::setByte() time: %0.4fms  avg: %0.6fms\n\n", elapsed.count() * 1000, elapsed.count());

    printf("Testing Num::setWord()\n\n");
    A.Init();
    A.setWord(2, 0x69696969);
    printf("%-5s Num::setWord() 1 of 1\n\n", (0x69696969 == A._word[2]) ? "OK" : "FAIL");

    printf("Measuring 1,000 iterations of Num::setWord()\n");
    start = std::chrono::steady_clock::now();
    for (i = 0; i < 1000; i++) { A.setWord(2, 0x69696969); }
    end = std::chrono::steady_clock::now();
    elapsed = end - start;
    printf("Num::setWord() time: %0.4fms  avg: %0.6fms\n\n", elapsed.count() * 1000, elapsed.count());

    printf("Testing Num::bin()\n\n");
    A.Init();
    for (i = 0; i < 48; A._byte[i] = inthex_vector_1[47 - i], i++);
    A._hiword = 47 >> num::byte2word;
    memset(bytebuf, 0, sizeof(bytebuf));
    A.bin(bytebuf, 48);
    printf("%-5s Num::bin() 1 of 1\n\n", (!memcmp(bytebuf, inthex_vector_1, 48)) ? "OK" : "FAIL");

    printf("Measuring 1,000 iterations of Num::bin()\n");
    start = std::chrono::steady_clock::now();
    for (i = 0; i < 1000; i++) { A.bin(bytebuf, 48); }
    end = std::chrono::steady_clock::now();
    elapsed = end - start;
    printf("Num::bin() time: %0.4fms  avg: %0.6fms\n\n", elapsed.count() * 1000, elapsed.count());

    printf("Testing Num::putZero()\n\n");
    A.putZero();
    printf("%-5s Num::putZero() 1 of 1\n\n", ((0 == A.word(0)) && (1 == A.bits()) && (1 == A.bytes()) && (1 == A.words())) ? "OK" : "FAIL");

    printf("Measuring 1,000 iterations of Num::putZero()\n");
    start = std::chrono::steady_clock::now();
    for (i = 0; i < 1000; i++) { A.putZero(); }
    end = std::chrono::steady_clock::now();
    elapsed = end - start;
    printf("Num::putZero() time: %0.4fms  avg: %0.6fms\n\n", elapsed.count() * 1000, elapsed.count());

    printf("Testing Num::putOne()\n\n");
    A.putOne();
    printf("%-5s Num::putOne() 1 of 1\n\n", ((1 == A.word(0)) && (1 == A.bits()) && (1 == A.bytes()) && (1 == A.words())) ? "OK" : "FAIL");

    printf("Measuring 1,000 iterations of Num::putOne()\n");
    start = std::chrono::steady_clock::now();
    for (i = 0; i < 1000; i++) { A.putOne(); }
    end = std::chrono::steady_clock::now();
    elapsed = end - start;
    printf("Num::putOne() time: %0.4fms  avg: %0.6fms\n\n", elapsed.count() * 1000, elapsed.count());

    printf("Testing Num::putTwo()\n\n");
    A.putTwo();
    printf("%-5s Num::putTwo() 1 of 1\n", ((2 == A.word(0)) && (2 == A.bits()) && (1 == A.bytes()) && (1 == A.words())) ? "OK" : "FAIL");

    printf("Measuring 1,000 iterations of Num::putTwo()\n");
    start = std::chrono::steady_clock::now();
    for (i = 0; i < 1000; i++) { A.putTwo(); }
    end = std::chrono::steady_clock::now();
    elapsed = end - start;
    printf("Num::putTwo() time: %0.4fms  avg: %0.6fms\n\n", elapsed.count() * 1000, elapsed.count());

    printf("Testing Num::putRandom()\n\n");
    A.putRandom(rand, 1);
    printf("%-5s Num:putRandom() 1 of 5\n", ((0 == A._sign) && (1 >= A.bits()) && (1 == A.words())) ? "OK" : "FAIL");
    A.putRandom(rand, 8);
    printf("%-5s Num:putRandom() 2 of 5\n", ((0 == A._sign) && (8 >= A.bits()) && (1 == A.words())) ? "OK" : "FAIL");
    A.putRandom(rand, 32);
    printf("%-5s Num:putRandom() 3 of 5\n", ((0 == A._sign) && (32 >= A.bits()) && (1 == A.words())) ? "OK" : "FAIL");
    A.putRandom(rand, 63);
    printf("%-5s Num:putRandom() 4 of 5\n", ((0 == A._sign) && (63 >= A.bits()) && (2 >= A.words())) ? "OK" : "FAIL");
    A.putRandom(rand, 69);
    printf("%-5s Num:putRandom() 5 of 5\n\n", ((0 == A._sign) && (69 >= A.bits()) && (3 >= A.words())) ? "OK" : "FAIL");

    printf("Measuring 1,000 iterations of Num::putRandom()\n");
    start = std::chrono::steady_clock::now();
    for (i = 0; i < 1000; i++) { A.putRandom(rand, 509); }
    end = std::chrono::steady_clock::now();
    elapsed = end - start;
    printf("Num::putRandom() time: %0.4fms  avg: %0.6fms\n\n", elapsed.count() * 1000, elapsed.count());

    printf("Testing Num::putWord()\n\n");
    A.putWord(0);
    printf("%-5s Num:putWord() 1 of 5\n", ((0 == A._sign) && (1 == A.words()) && (1 == A.bytes()) && (1 == A.bits()) && (0 == A.word(0))) ? "OK" : "FAIL");
    A.putWord(1);
    printf("%-5s Num:putWord() 2 of 5\n", ((0 == A._sign) && (1 == A.words()) && (1 == A.bytes()) && (1 == A.bits()) && (1 == A.word(0))) ? "OK" : "FAIL");
    A.putWord(2);
    printf("%-5s Num:putWord() 3 of 5\n", ((0 == A._sign) && (1 == A.words()) && (1 == A.bytes()) && (2 == A.bits()) && (2 == A.word(0))) ? "OK" : "FAIL");
    A.putWord(0x12345);
    printf("%-5s Num:putWord() 4 of 5\n", ((0 == A._sign) && (1 == A.words()) && (3 == A.bytes()) && (17 == A.bits()) && (0x12345 == A.word(0))) ? "OK" : "FAIL");
    A.putWord((uint32_t)-1);
    printf("%-5s Num:putWord() 5 of 5\n\n", ((0 == A._sign) && (1 == A.words()) && (num::wordbytes == A.bytes()) && (num::wordbits == A.bits()) && ((uint32_t)-1 == A.word(0))) ? "OK" : "FAIL");

    printf("Measuring 1,000 iterations of Num::putWord()\n");
    start = std::chrono::steady_clock::now();
    for (i = 0; i < 1000; i++) { A.putWord(0x12345678); }
    end = std::chrono::steady_clock::now();
    elapsed = end - start;
    printf("Num::putWord() time: %0.4fms  avg: %0.6fms\n\n", elapsed.count() * 1000, elapsed.count());

    printf("Testing Num::putLong()\n\n");
    A.putLong(0);
    printf("%-5s Num:putLong() 1 of 7\n", ((0 == A._sign) && (1 == A.words()) && (1 == A.bytes()) && (1 == A.bits()) && (0 == A.word(0))) ? "OK" : "FAIL");
    A.putLong(1);
    printf("%-5s Num:putLong() 2 of 7\n", ((0 == A._sign) && (1 == A.words()) && (1 == A.bytes()) && (1 == A.bits()) && (1 == A.word(0))) ? "OK" : "FAIL");
    A.putLong(2);
    printf("%-5s Num:putLong() 3 of 7\n", ((0 == A._sign) && (1 == A.words()) && (1 == A.bytes()) && (2 == A.bits()) && (2 == A.word(0))) ? "OK" : "FAIL");
    A.putLong(0x7fffffff);
    printf("%-5s Num:putLong() 4 of 7\n", ((0 == A._sign) && (1 == A.words()) && (4 == A.bytes()) && (num::wordbits - 1 == A.bits()) && (0x7fffffff == A.word(0))) ? "OK" : "FAIL");
    A.putLong(num::hibitmask);
    printf("%-5s Num:putLong() 5 of 7\n", (((uint32_t)-1 == A._sign) && (1 == A.words()) && (num::wordbytes == A.bytes()) && (num::wordbits == A.bits()) && (num::hibitmask == A.word(0))) ? "OK" : "FAIL");
    A.putLong((uint32_t)-1);
    printf("%-5s Num:putLong() 6 of 7\n", (((uint32_t)-1 == A._sign) && (1 == A.words()) && (1 == A.bytes()) && (1 == A.bits()) && (1 == A.word(0))) ? "OK" : "FAIL");
    A.putLong((uint32_t)-98765);
    printf("%-5s Num:putLong() 7 of 7\n\n", (((uint32_t)-1 == A._sign) && (1 == A.words()) && (3 == A.bytes()) && (17 == A.bits()) && (0x181cd == A.word(0))) ? "OK" : "FAIL");

    printf("Measuring 1,000 iterations of Num::putLong()\n");
    start = std::chrono::steady_clock::now();
    for (i = 0; i < 1000; i++) { A.putLong(-9999); }
    end = std::chrono::steady_clock::now();
    elapsed = end - start;
    printf("Num::putLong() time: %0.4fms  avg: %0.6fms\n\n", elapsed.count() * 1000, elapsed.count());

    printf("Testing Num::putBin()\n\n");
    A.putBin((uint8_t*)"\x00\x00\x01\x23\x45\x67\x89\xab\xcd\xef", 10);
    printf("%-5s Num:putBin() 1 of 1\n\n", ((0 == A._sign) && (2 == A.words()) && (0x89abcdef == A.word(0)) && (0x01234567 == A.word(1))) ? "OK" : "FAIL");

    printf("Measuring 1,000 iterations of Num::putBin()\n");
    start = std::chrono::steady_clock::now();
    for (i = 0; i < 1000; i++) { A.putBin((uint8_t*)"\x01\x23\x45\x67\x89\xab\xcd\xef\x01\x23\x45\x67\x89\xab\xcd\xef\x01", 17); }
    end = std::chrono::steady_clock::now();
    elapsed = end - start;
    printf("Num::putBin() time: %0.4fms  avg: %0.6fms\n\n", elapsed.count() * 1000, elapsed.count());

    printf("Testing Num::putHex()\n\n");
    A.putHex((uint8_t*)"0123456789abcdef", 16);
    printf("%-5s Num:putHex() 1 of 1\n\n", ((0 == A._sign) && (2 == A.words()) && (0x89abcdef == A.word(0)) && (0x01234567 == A.word(1))) ? "OK" : "FAIL");

    printf("Measuring 1,000 iterations of Num::putHex()\n");
    start = std::chrono::steady_clock::now();
    for (i = 0; i < 1000; i++) { A.putHex((uint8_t*)"123456789abcdef01", 17); }
    end = std::chrono::steady_clock::now();
    elapsed = end - start;
    printf("Num::putHex() time: %0.4fms  avg: %0.6fms\n\n", elapsed.count() * 1000, elapsed.count());

    printf("Testing Num::copy()\n\n");
    A.putRandom(rand, 1024);
    B.copy(A);
    printf("%-5s Num::copy() 1 of 1\n\n", (!memcmp(&A, &B, num::bytes) && (A._overflow == B._overflow) && (A._sign == B._sign) && (A._hiword == B._hiword)) ? "OK" : "FAIL");

    printf("Measuring 1,000 iterations of Num::copy()\n");
    start = std::chrono::steady_clock::now();
    for (i = 0; i < 1000; i++) { B.copy(A); }
    end = std::chrono::steady_clock::now();
    elapsed = end - start;
    printf("Num::copy() time: %0.4fms  avg: %0.6fms\n\n", elapsed.count() * 1000, elapsed.count());

    printf("Testing Num::compare()\n\n");
    A.putLong(-2);
    B.putLong(-1);
    C.putLong(0);
    D.putLong(1);
    E.putLong(2);
    printf("%-5s Num::compare() 1 of 16\n", (1 == E.compare(D)) ? "OK" : "FAIL"); // 2 > 1
    printf("%-5s Num::compare() 2 of 16\n", (-1 == D.compare(E)) ? "OK" : "FAIL"); // 1 < 2
    printf("%-5s Num::compare() 3 of 16\n", (0 == E.compare(E)) ? "OK" : "FAIL"); // 2 = 2
    printf("%-5s Num::compare() 4 of 16\n", (0 == C.compare(C)) ? "OK" : "FAIL"); // 0 = 0
    printf("%-5s Num::compare() 5 of 16\n", (-1 == C.compare(D)) ? "OK" : "FAIL"); // 0 < 1
    printf("%-5s Num::compare() 6 of 16\n", (1 == D.compare(C)) ? "OK" : "FAIL"); // 1 > 0
    printf("%-5s Num::compare() 7 of 16\n", (0 == D.compare(D)) ? "OK" : "FAIL"); // 1 = 1
    printf("%-5s Num::compare() 8 of 16\n", (1 == C.compare(B)) ? "OK" : "FAIL"); // 0 > -1
    printf("%-5s Num::compare() 9 of 16\n", (-1 == B.compare(C)) ? "OK" : "FAIL"); // -1 < 0
    printf("%-5s Num::compare() 10 of 16\n", (1 == D.compare(B)) ? "OK" : "FAIL"); // 1 > -1
    printf("%-5s Num::compare() 11 of 16\n", (-1 == B.compare(D)) ? "OK" : "FAIL"); // -1 < 1
    printf("%-5s Num::compare() 12 of 16\n", (0 == B.compare(B)) ? "OK" : "FAIL"); // -1 = -1
    printf("%-5s Num::compare() 13 of 16\n", (1 == B.compare(A)) ? "OK" : "FAIL"); // -1 > -2
    printf("%-5s Num::compare() 14 of 16\n", (-1 == A.compare(B)) ? "OK" : "FAIL"); // -2 < -1
    A.putZero();
    A.setWord(21, 1);
    A.setWord(24, 1);
    A._hiword = 24;
    A._loword = 21;
    B.putZero();
    B.setWord(20, 1);
    B.setWord(25, 1);
    B._hiword = 25;
    B._loword = 20;
    printf("%-5s Num::compare() 15 of 16\n", (-1 == A.compare(B)) ? "OK" : "FAIL");
    B.putZero();
    B.setWord(20, 1);
    B.setWord(24, 1);
    B.setWord(25, 0);
    B._hiword = 24;
    B._loword = 20;
    printf("%-5s Num::compare() 16 of 16\n\n", (1 == A.compare(B)) ? "OK" : "FAIL");

    printf("Measuring 1,000 iterations of Num::compareAbs() 1024-bit comparators w/_loword = 0\n");
    A.putZero();
    for (i = 0; i < 32; A.setWord(i, (uint32_t)-1), i--);
    A._hiword = 31;
    A._loword = 0;
    B.copy(A);
    start = std::chrono::steady_clock::now();
    for (i = 0; i < 1000; i++) { A.compareAbs(B); }
    end = std::chrono::steady_clock::now();
    elapsed = end - start;
    printf("Num::compareAbs() time: %0.4fms  avg: %0.6fms\n\n", elapsed.count() * 1000, elapsed.count());

    printf("Measuring 1,000 iterations of Num::compareAbs() 1024-bit comparators w/_loword = 16\n");
    A.putZero();
    for (i = 16; i < 32; A.setWord(i, (uint32_t)-1), i--);
    A._hiword = 31;
    A._loword = 16;
    B.copy(A);
    start = std::chrono::steady_clock::now();
    for (i = 0; i < 1000; i++) { A.compareAbs(B); }
    end = std::chrono::steady_clock::now();
    elapsed = end - start;
    printf("Num::compareAbs() time: %0.4fms  avg: %0.6fms\n\n", elapsed.count() * 1000, elapsed.count());

    printf("Measuring 1,000 iterations of Num::compare() 1024-bit comparators w/_loword = 16\n");
    start = std::chrono::steady_clock::now();
    for (i = 0; i < 1000; i++) { A.compare(B); }
    end = std::chrono::steady_clock::now();
    elapsed = end - start;
    printf("Num::compare() time: %0.4fms  avg: %0.6fms\n\n", elapsed.count() * 1000, elapsed.count());

    printf("Testing Num::neg()\n\n");
    A.putRandom(rand, 512);
    B.copy(A);
    B.neg();
    printf("%-5s Num::neg() 1 of 1\n\n", (!memcmp(&A._word[0], &B._word[0], num::bytes) && !A._sign && (uint32_t)-1 == B._sign) ? "OK" : "FAIL");

    printf("Measuring 1,000 iterations of Num::neg()\n");
    start = std::chrono::steady_clock::now();
    for (i = 0; i < 1000; i++) { A.neg(); }
    end = std::chrono::steady_clock::now();
    elapsed = end - start;
    printf("Num::neg() time: %0.4fms  avg: %0.6fms\n\n", elapsed.count() * 1000, elapsed.count());

    printf("Testing Num::mul2()\n\n");
    A.putZero();
    A.mul2();
    printf("%-5s Num::mul2() 1 of 5\n", (1 == A.words() && !A.word(0) && !A._overflow) ? "OK" : "FAIL"); // 0 = 0.mul2()
    A.putOne();
    A.mul2();
    printf("%-5s Num::mul2() 2 of 5\n", (1 == A.words() && 2 == A.word(0) && !A._overflow) ? "OK" : "FAIL"); // 2 = 1.mul2()
    A.putWord(0xb4b4b4b4);
    A.mul2();
    printf("%-5s Num::mul2() 3 of 5\n", (2 == A.words() && 0x00000001 == A.word(1) && 0x69696968 == A.word(0) && !A._overflow) ? "OK" : "FAIL"); // 0x1 0x69696968 = 0xb4b4b4b4.mul2()
    A.putBin((uint8_t*)"\xff\xff\xff\xff\x80\x00\x00\x00", 8);
    A.mul2();
    printf("%-5s Num::mul2() 4 of 5\n", (3 == A.words() && 0x00000001 == A.word(2) && 0xffffffff == A.word(1) && 0 == A.word(0) && 2 == A._hiword && 1 == A._loword && !A._overflow) ? "OK" : "FAIL"); // 0x1 0xffffffff 0x0 = 0xffffffff 0x80000000 .mul2() 
    A.putZero();
    A.setWord(num::hiword, (uint32_t)num::hibitmask);
    A._hiword = num::hiword;
    A._loword = num::hiword;
    A.mul2();
    printf("%-5s Num::mul2() 5 of 5\n\n", (1 == A.words() && !A.word(0) && !A._overflow) ? "OK" : "FAIL"); // 0 = num::hibit .mul2()

    printf("Measuring 1,000 iterations of Num::mul2() 2048-bit integers w/_loword = 0\n");
    A.putRandom(rand, 2048);
    start = std::chrono::steady_clock::now();
    for (i = 0; i < 1000; i++) { A.mul2(); }
    end = std::chrono::steady_clock::now();
    elapsed = end - start;
    printf("Num::mul2() time: %0.4fms  avg: %0.6fms\n\n", elapsed.count() * 1000, elapsed.count());

    printf("Measuring 1,000 iterations of Num::mul2() 2048-bit integers w/_loword = 32\n");
    A.putRandom(rand, 2048);
    for (i = 0; i < 32; A.setWord(i, 0), i++);
    A._loword = 32;
    start = std::chrono::steady_clock::now();
    for (i = 0; i < 1000; i++) { A.mul2(); }
    end = std::chrono::steady_clock::now();
    elapsed = end - start;
    printf("Num::mul2() time: %0.4fms  avg: %0.6fms\n\n", elapsed.count() * 1000, elapsed.count());

    printf("Testing Num::div2()\n\n");
    A.putZero();
    A.div2();
    printf("%-5s Num::div2() 1 of 5\n", (1 == A.words() && !A.word(0) && !A._overflow) ? "OK" : "FAIL"); // 0 == 0.div2()
    A.putOne();
    A.div2();
    printf("%-5s Num::div2() 2 of 5\n", (1 == A.words() && !A.word(0) && !A._overflow) ? "OK" : "FAIL"); // 0 == 1.div2()
    A.putTwo();
    A.div2();
    printf("%-5s Num::div2() 3 of 5\n", (1 == A.words() && 1 == A.word(0) && !A._overflow) ? "OK" : "FAIL"); // 1 == 2.div2()
    A.putZero();
    A.setWord(1, 0x00000001);
    A.setWord(0, 0x69696969);
    A._hiword = 1;
    A.div2();
    printf("%-5s Num::div2() 4 of 5\n", (1 == A.words() && 0xb4b4b4b4 == A.word(0) && !A._hiword && !A._loword && !A._overflow) ? "OK" : "FAIL"); // 0xb4b4b4b4 == 0x1 0x69696969.div2()
    A.putZero();
    A.setWord(2, 0x00000001);
    A.setWord(1, 0xffffffff);
    A.setWord(0, 0x00000000);
    A._hiword = 2;
    A._loword = 1;
    A.div2();
    printf("%-5s Num::div2() 5 of 5\n\n", (2 == A.words() && 0x80000000 == A.word(0) && 0xffffffff == A.word(1) && 1 == A._hiword && !A._loword && !A._overflow) ? "OK" : "FAIL"); // 0xb4b4b4b4 == 0x1 0x69696969.div2()

    printf("Measuring 1,000 iterations of Num::div2() 3072-bit integers w/_loword = 0\n");
    A.putRandom(rand, 3072);
    start = std::chrono::steady_clock::now();
    for (i = 0; i < 1000; i++) { A.div2(); }
    end = std::chrono::steady_clock::now();
    elapsed = end - start;
    printf("Num::div2() time: %0.4fms  avg: %0.6fms\n\n", elapsed.count() * 1000, elapsed.count());

    printf("Measuring 1,000 iterations of Num::div2() 3072-bit integers w/_loword = 32\n");
    A.putRandom(rand, 3072);
    start = std::chrono::steady_clock::now();
    for (i = 0; i < 1000; i++) { A.div2(); }
    end = std::chrono::steady_clock::now();
    elapsed = end - start;
    printf("Num::div2() time: %0.4fms  avg: %0.6fms\n\n", elapsed.count() * 1000, elapsed.count());

    printf("Testing Num::shiftLeft() and Num::shiftRight()\n\n");
    A.putRandom(rand, 512);
    B.copy(A);
    A.shiftLeft(0);
    printf("%-5s Num::shiftLeft() 1 of 8\n", (!A.compare(B)) ? "OK" : "FAIL"); // B = A; B = A >> 0
    A.putZero();
    B.copy(A);
    A.shiftLeft(57);
    printf("%-5s Num::shiftLeft() 2 of 8\n", (!A.compare(B)) ? "OK" : "FAIL"); // B = A; B = A = 0 >> 57
    A.putRandom(rand, 512);
    B.putZero();
    A.shiftLeft(num::bits);
    printf("%-5s Num::shiftLeft() 3 of 8\n", (!A.compare(B)) ? "OK" : "FAIL"); // A.rand() << num::bits = 0
    A.putHex((uint8_t*)"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000000", 64);
    B.copy(A);
    for (i = 0; i < 16; i++) A.shiftLeft(i);
    A.shiftLeft(8);
    A.shiftRight(64);
    A.shiftRight(32);
    A.shiftRight(16);
    A.shiftRight(8);
    A.shiftRight(4);
    A.shiftRight(2);
    A.shiftRight(1);
    A.shiftRight(1);
    printf("%-5s Num::shiftLeft() 4 of 8\n", (!A.compare(B)) ? "OK" : "FAIL"); // word intensity; no bit shift
    A.putRandom(rand, 512);
    B.copy(A);
    A.shiftLeft(23);
    A.shiftRight(23);
    printf("%-5s Num::shiftLeft() 5 of 8\n", (!A.compare(B)) ? "OK" : "FAIL"); // bit shift; no word intensity
    A.putRandom(rand, 512);
    B.copy(A);
    A.shiftLeft(57);
    A.shiftRight(57);
    printf("%-5s Num::shiftLeft() 6 of 8\n", !(A.compare(B)) ? "OK" : "FAIL"); // 1-word intensity and bit shift
    A.putRandom(rand, 512);
    B.copy(A);
    A.shiftLeft(108);
    A.shiftRight(108);
    printf("%-5s Num::shiftLeft() 7 of 8\n", (!A.compare(B)) ? "OK" : "FAIL"); // multiple-word intensity and bit shift
    A.putRandom(rand, 2048);
    B.copy(A);
    A.shiftLeft(num::bits - 1024);
    A.shiftRight(num::bits - 1024);
    printf("%-5s Num::shiftLeft() 8 of 8\n\n", (A.compare(B)) ? "OK" : "FAIL"); // shift partial beyond limit

    printf("Measuring 1,000 iterations of Num::shiftLeft() and Num::ShiftRight()\n");
    printf("(512-bit integer shifted left and right 57 bits w/_loword = 0)\n");
    A.putRandom(rand, 512);
    start = std::chrono::steady_clock::now();
    for (i = 0; i < 500; i++) { A.shiftLeft(57); A.shiftRight(57); }
    end = std::chrono::steady_clock::now();
    elapsed = end - start;
    printf("Num::shiftLeft() and Num::shiftRight() time: %0.4fms  avg: %0.6fms\n\n", elapsed.count() * 1000, elapsed.count());

    printf("Measuring 1,000 iterations of Num::ShiftLeft() and Num::ShiftRight()\n");
    printf("(2048-bit integer shifted left 999 bits w/_loword = 0)\n");
    A.putRandom(rand, 2048);
    start = std::chrono::steady_clock::now();
    for (i = 0; i < 500; i++) { A.shiftLeft(999); A.shiftRight(999); }
    end = std::chrono::steady_clock::now();
    elapsed = end - start;
    printf("Num::shiftLeft() and Num::shiftRight() time: %0.4fms  avg: %0.6fms\n\n", elapsed.count() * 1000, elapsed.count());

    printf("Testing Num::IncrementAbs\n\n");
    A.putZero();
    A.incrementAbs();
    printf("%-5s Num::incrementAbs() 1 of 10\n", (!A._sign && !A._hiword && !A._loword && 1 == A.bits() && 1 == A.words() && 1 == A.word(0)) ? "OK" : "FAIL"); // 00 00 00 --> 00 00 01
    A.putOne();
    A.incrementAbs();
    printf("%-5s Num::incrementAbs() 2 of 10\n", (!A._sign && !A._hiword && !A._loword && 2 == A.bits() && 1 == A.words() && 2 == A.word(0)) ? "OK" : "FAIL"); // 00 00 01 --> 00 00 02
    A.setWord(0, (uint32_t)-1);
    A._hiword = 0;
    A._loword = 0;
    A.incrementAbs();
    printf("%-5s Num::incrementAbs() 3 of 10\n", (!A._sign && 1 == A._hiword && 1 == A._loword && (num::wordbits + 1) == A.bits() && 2 == A.words() && 1 == A.word(1) && !A.word(0)) ? "OK" : "FAIL"); // 00 00 FF --> 00 01 00
    A.setWord(0, 0);
    A.setWord(1, 1);
    A._hiword = 1;
    A._loword = 1;
    A.incrementAbs();
    printf("%-5s Num::incrementAbs() 4 of 10\n", (!A._sign && 1 == A._hiword && !A._loword && (num::wordbits + 1) == A.bits() && 2 == A.words() && 1 == A.word(1) && 1 == A.word(0)) ? "OK" : "FAIL"); // 00 01 00 --> 00 01 01
    A.setWord(0, 1);
    A.setWord(1, 1);
    A._hiword = 1;
    A._loword = 0;
    A.incrementAbs();
    printf("%-5s Num::incrementAbs() 5 of 10\n", (!A._sign && 1 == A._hiword && !A._loword && (num::wordbits + 1) == A.bits() && 2 == A.words() && 1 == A.word(1) && 2 == A.word(0)) ? "OK" : "FAIL"); // 00 01 01 --> 00 01 02
    A.setWord(0, (uint32_t)-1);
    A.setWord(1, 1);
    A._hiword = 1;
    A._loword = 0;
    A.incrementAbs();
    printf("%-5s Num::incrementAbs() 6 of 10\n", (!A._sign && 1 == A._hiword && 1 == A._loword && (num::wordbits + 2) == A.bits() && 2 == A.words() && 2 == A.word(1) && !A.word(0)) ? "OK" : "FAIL"); // 00 01 FF --> 00 02 00
    A.setWord(0, (uint32_t)-1);
    A.setWord(1, 0);
    A.setWord(2, 1);
    A._hiword = 2;
    A._loword = 0;
    A.incrementAbs();
    printf("%-5s Num::incrementAbs() 7 of 10\n", (!A._sign && 2 == A._hiword && 1 == A._loword && (num::wordbits * 2 + 1) == A.bits() && 3 == A.words() && 1 == A.word(2) && 1 == A.word(1) && !A.word(0)) ? "OK" : "FAIL"); // 01 00 FF --> 01 01 00
    A.setWord(0, (uint32_t)-1);
    A.setWord(1, 1);
    A.setWord(2, 1);
    A._hiword = 2;
    A._loword = 0;
    A.incrementAbs();
    printf("%-5s Num::incrementAbs() 8 of 10\n", (!A._sign && 2 == A._hiword && 1 == A._loword && (num::wordbits * 2 + 1) == A.bits() && 3 == A.words() && 1 == A.word(2) && 2 == A.word(1) && !A.word(0)) ? "OK" : "FAIL"); // 01 01 FF --> 01 02 00
    A.setWord(0, (uint32_t)-1);
    A.setWord(1, (uint32_t)-1);
    A.setWord(2, 1);
    A._hiword = 2;
    A._loword = 0;
    A.incrementAbs();
    printf("%-5s Num::incrementAbs() 9 of 10\n", (!A._sign && 2 == A._hiword && 2 == A._loword && (num::wordbits * 2 + 2) == A.bits() && 3 == A.words() && 2 == A.word(2) && !A.word(1) && !A.word(0)) ? "OK" : "FAIL"); // 01 FF FF --> 02 00 00
    A.putZero();
    for (i = 0; i < num::words; i++) A.setWord(i, (uint32_t)-1);
    A._hiword = num::hiword;
    A.incrementAbs();
    printf("%-5s Num::incrementAbs() 10 of 10\n\n", (!A._sign && !A._hiword && !A._loword && 1 == A.bits() && 1 == A.words() && !A.word(0)) ? "OK" : "FAIL"); // FF FF FF --> 00 00 00

    printf("Measuring 1,000 iterations of Num::incrementAbs()\n");
    printf("(2048-bit integer incremented 1,000 times)\n");
    A.putRandom(rand, 2048);
    start = std::chrono::steady_clock::now();
    for (i = 0; i < 1000; i++) { A.incrementAbs(); }
    end = std::chrono::steady_clock::now();
    elapsed = end - start;
    printf("Num::incrementAbs() time: %0.4fms  avg: %0.6fms\n\n", elapsed.count() * 1000, elapsed.count());

    printf("Testing Num::decrementAbs()\n\n");
    A.putZero();
    A.decrementAbs();
    printf("%-5s Num::decrementAbs() 1 of 9\n", ((uint32_t)-1 == A._sign && 1 == A.bits() && 1 == A.words() && 1 == A.word(0)) ? "OK" : "FAIL"); // 00 00 00 --> -(00 00 01)
    A.putOne();
    A.decrementAbs();
    printf("%-5s Num::decrementAbs() 2 of 9\n", (!A._sign && 1 == A.bits() && 1 == A.words() && !A.word(0)) ? "OK" : "FAIL"); // 00 00 01 --> 00 00 00
    A.putTwo();
    A.decrementAbs();
    printf("%-5s Num::decrementAbs() 3 of 9\n", (!A._sign && 1 == A.bits() && 1 == A.words() && 1 == A.word(0)) ? "OK" : "FAIL"); // 00 00 02 --> 00 00 01
    A.setWord(0, 0);
    A.setWord(1, 1);
    A._hiword = 1;
    A._loword = 1;
    A.decrementAbs();
    printf("%-5s Num::decrementAbs() 4 of 9\n", (!A._sign && !A._hiword && !A._loword && num::wordbits == A.bits() && 1 == A.words() && !A.word(1) && (uint32_t)-1 == A.word(0)) ? "OK" : "FAIL"); // 00 01 00 --> 00 00 FF
    A.setWord(0, 0);
    A.setWord(1, 2);
    A._hiword = 1;
    A._loword = 1;
    A.decrementAbs();
    printf("%-5s Num::decrementAbs() 5 of 9\n", (!A._sign && 1 == A._hiword && !A._loword && num::wordbits + 1 == A.bits() && 2 == A.words() && 1 == A.word(1) && (uint32_t)-1 == A.word(0)) ? "OK" : "FAIL"); // 00 02 00 --> 00 01 FF
    A.setWord(0, 1);
    A.setWord(1, 2);
    A._hiword = 1;
    A._loword = 0;
    A.decrementAbs();
    printf("%-5s Num::decrementAbs() 6 of 9\n", (!A._sign && 1 == A._hiword && 1 == A._loword && num::wordbits + 2 == A.bits() && 2 == A.words() && 2 == A.word(1) && !A.word(0)) ? "OK" : "FAIL"); // 00 02 01 --> 00 02 00
    A.setWord(0, 2);
    A.setWord(1, 2);
    A._hiword = 1;
    A._loword = 0;
    A.decrementAbs();
    printf("%-5s Num::decrementAbs() 7 of 9\n", (!A._sign && 1 == A._hiword && !A._loword && num::wordbits + 2 == A.bits() && 2 == A.words() && 2 == A.word(1) && 1 == A.word(0)) ? "OK" : "FAIL"); // 00 02 02 --> 00 02 01
    A.setWord(0, 0);
    A.setWord(1, 1);
    A.setWord(2, 1);
    A._hiword = 2;
    A._loword = 1;
    A.decrementAbs();
    printf("%-5s Num::decrementAbs() 8 of 9\n", (!A._sign && 2 == A._hiword && !A._loword && num::wordbits * 2 + 1 == A.bits() && 3 == A.words() && 1 == A.word(2) && !A.word(1) && (uint32_t)-1 == A.word(0)) ? "OK" : "FAIL"); // 01 01 00 --> 01 00 FF
    for (i = 0; i < num::words; A.setWord(i, (uint32_t)-1), i++);
    A._hiword = num::hiword;
    A._loword = 0;
    A.decrementAbs();
    printf("%-5s Num::decrementAbs() 9 of 9\n\n", (!A._sign && num::hiword == A._hiword && !A._loword && num::bits == A.bits() && num::words == A.words() && (uint32_t)-1 == A.word(num::hiword) && (uint32_t)-2 == A.word(0)) ? "OK" : "FAIL"); // FF FF FF --> FF FF FE

    printf("Measuring 1,000 iterations of Num::decrementAbs()\n");
    printf("(2048-bit integer decremented 1,000 times)\n");
    A.putRandom(rand, 2048);
    start = std::chrono::steady_clock::now();
    for (i = 0; i < 1000; i++) { A.decrementAbs(); }
    end = std::chrono::steady_clock::now();
    elapsed = end - start;
    printf("Num::decrementAbs() time: %0.4fms  avg: %0.6fms\n\n", elapsed.count() * 1000, elapsed.count());

    printf("Testing Num::addAbs()\n\n");
    A.putWord(0x5a5a5a5a);
    A.addAbs(A);
    printf("%-5s Num::addAbs() 1 of 10\n", (0xb4b4b4b4 == A.word(0) && 1 == A.words() && !A._overflow) ? "OK" : "FAIL"); // 1-word + 1-word --> no word overflow
    A.addAbs(A);
    printf("%-5s Num::addAbs() 2 of 10\n", (0x69696968 == A.word(0) && 1 == A.word(1) && 2 == A.words() && !A._overflow) ? "OK" : "FAIL"); // 1-word + 1-word --> word overflow
    A.putZero();
    A.setWord(0, 0x89abcdef);
    A.setWord(1, 0x01234567);
    A._hiword = 1;
    B.putWord(0x55555555);
    A.addAbs(B);
    printf("%-5s Num::addAbs() 3 of 10\n", (0xdf012344 == A.word(0) && 0x01234567 == A.word(1) && 2 == A.words() && !A._overflow) ? "OK" : "FAIL"); // 1-word + 2-word --> no word overflow
    A.putZero();
    A.setWord(0, 0x89abcdef);
    A.setWord(1, 0x01234567);
    A._hiword = 1;
    B.putWord(0xaaaaaaaa);
    A.addAbs(B);
    printf("%-5s Num::addAbs() 4 of 10\n", (0x34567899 == A.word(0) && 0x01234568 == A.word(1) && 2 == A.words() && !A._overflow) ? "OK" : "FAIL"); // 1-word + 2-word --> word overflow
    A.putZero();
    A.setWord(0, 0xffffffff);
    A.setWord(1, 0xffffffff);
    A.setWord(2, 0xffffffff);
    A.setWord(3, 0xffffffff);
    A._hiword = 3;
    B.putTwo();
    A.addAbs(B);
    printf("%-5s Num::addAbs() 5 of 10\n", (1 == A.word(0) && !A.word(1) && !A.word(2) && !A.word(3) && 1 == A.word(4) && 5 == A.words() && !A._overflow) ? "OK" : "FAIL"); // 1-word + n-word --> n-word overflow
    A.putZero();
    A.setWord(0, 0xffffffff);
    A.setWord(1, 0xffffffff);
    A.setWord(2, 0xffffffff);
    A.setWord(3, 0xffffffff);
    A._hiword = 3;
    B.putZero();
    B.setWord(0, 0x00000001);
    B.setWord(1, 0x00000001);
    B._hiword = 1;
    A.addAbs(B);
    printf("%-5s Num::addAbs() 6 of 10\n", (!A.word(0) && 1 == A.word(1) && !A.word(2) && !A.word(3) && 1 == A.word(4) && 5 == A.words() && !A._overflow) ? "OK" : "FAIL"); // n-word + n-word --> n-word overflow
    A.putZero();
    A.setWord(0, 0xffffffff);
    A.setWord(1, 0xffffffff);
    A.setWord(2, 0xffffffff);
    A.setWord(3, 0x33333333);
    A.setWord(4, 0x22222222);
    A.setWord(5, 0x11111111);
    A._hiword = 5;
    B.putTwo();
    A.addAbs(B);
    printf("%-5s Num::addAbs() 7 of 10\n", (1 == A.word(0) && !A.word(1) && !A.word(2) && 0x33333334 == A.word(3) && 0x22222222 == A.word(4) && 0x11111111 == A.word(5) && 6 == A.words() && !A._overflow) ? "OK" : "FAIL"); // 1-word + n-word --> word overflow, no increase in A.words()
    A.putZero();
    A.setWord(0, 0xffffffff);
    A.setWord(1, 0xffffffff);
    A.setWord(2, 0xffffffff);
    A.setWord(3, 0x33333333);
    A.setWord(4, 0x22222222);
    A.setWord(5, 0x11111111);
    A._hiword = 5;
    B.putZero();
    B.setWord(0, 1);
    B.setWord(1, 1);
    B._hiword = 1;
    A.addAbs(B);
    printf("%-5s Num::addAbs() 8 of 10\n", (!A.word(0) && 1 == A.word(1) && !A.word(2) && 0x33333334 == A.word(3) && 0x22222222 == A.word(4) && 0x11111111 == A.word(5) && 6 == A.words() && !A._overflow) ? "OK" : "FAIL"); // n-word + n-word --> n-word overflow, no increase in A.words()
    A.putZero();
    for (i = 0; i < num::words; A.setWord(i, 0xffffffff), i++);
    A._hiword = num::hiword;
    B.putTwo();
    A.addAbs(B);
    printf("%-5s Num::addAbs() 9 of 10\n", (1 == A.word(0) && 1 == A.words() && !A._overflow) ? "OK" : "FAIL"); // (-1) + 2 --> overflow
    A.putZero();
    for (i = 0; i < num::words; A.setWord(i, 0xffffffff), i++);
    A._hiword = num::hiword;
    B.putZero();
    B.setWord(0, 1);
    B.setWord(1, 1);
    B._hiword = 1;
    A.addAbs(B);
    printf("%-5s Num::addAbs() 10 of 10\n\n", (!A.word(0) && 1 == A.word(1) && 2 == A.words() && !A._overflow) ? "OK" : "FAIL"); // (-1) + n-word --> overflow 

    printf("Measuring 1,000 iterations of Num::addAbs()\n");
    printf("(512-bits plus 128 bits)\n");
    A.putRandom(rand, 512);
    B.putRandom(rand, 128);
    start = std::chrono::steady_clock::now();
    for (i = 0; i < 1000; i++) { A.addAbs(B); }
    end = std::chrono::steady_clock::now();
    elapsed = end - start;
    printf("Num::addAbs() time: %0.4fms  avg: %0.6fms\n\n", elapsed.count() * 1000, elapsed.count());

    printf("Testing Num::subAbs()\n\n");
    A.putWord(0xffffffff);
    B.putWord(0xffffffff);
    A.subAbs(B);
    printf("%-5s Num::subAbs() 1 of 8\n", (1 == A.words() && !A.word(0) && !A._overflow) ? "OK" : "FAIL"); // 1-word - same --> zero
    A.putWord(0xffffffff);
    B.putWord(0xdddddddd);
    A.subAbs(B);
    printf("%-5s Num::subAbs() 2 of 8\n", (1 == A.words() && 0x22222222 == A.word(0) && !A._overflow) ? "OK" : "FAIL"); // 1-word - 1-word --> positive value
    A.putZero();
    A.setWord(1, 1);
    A.setWord(0, 0x69696968);
    A._hiword = 1;
    B.copy(A);
    A.subAbs(B);
    printf("%-5s Num::subAbs() 3 of 8\n", (1 == A.words() && !A.word(0) && !A._overflow) ? "OK" : "FAIL"); // n-word - same --> zero
    A.putZero();
    A.setWord(0, 0x69696968);
    A.setWord(1, 1);
    A._hiword = 1;
    B.putWord(0xb4b4b4b4);
    A.subAbs(B);
    printf("%-5s Num::subAbs() 4 of 8\n", (1 == A.words() && 0xb4b4b4b4 == A.word(0) && !A._overflow) ? "OK" : "FAIL"); // n-word - n-word --> positive value
    B.putWord(0x5a5a5a5a);
    A.subAbs(B);
    printf("%-5s Num::subAbs() 5 of 8\n", (1 == A.words() && 0x5a5a5a5a == A.word(0) && !A._hiword) ? "OK" : "FAIL"); // n-word - half-value --> 1-word value
    A.putZero();
    A.setWord(0, 0x89abcdef);
    A.setWord(1, 0x01234567);
    A._hiword = 1;
    B.putWord(0x55555555);
    A.subAbs(B);
    printf("%-5s Num::subAbs() 6 of 8\n", (2 == A.words() && 0x3456789a == A.word(0) && 0x01234567 == A.word(1) && !A._overflow) ? "OK" : "FAIL"); // n-word - 1-word --> n-word
    A.putZero();
    A.setWord(0, 1);
    A.setWord(3, 1);
    A._hiword = 3;
    B.putTwo();
    A.subAbs(B);
    printf("%-5s Num::subAbs() 7 of 8\n", (3 == A.words() && 0xffffffff == A.word(0) && 0xffffffff == A.word(1) && 0xffffffff == A.word(2) && !A.word(3) && !A._overflow) ? "OK" : "FAIL"); // n-word - 1-word --> n-word w/fewer words
    A.putZero();
    A.setWord(0, 1);
    A.setWord(3, 1);
    A._hiword = 3;
    B.putZero();
    B.setWord(0, 1);
    B.setWord(1, 1);
    B._hiword = 1;
    A.subAbs(B);
    printf("%-5s Num::subAbs() 8 of 8\n\n", (3 == A.words() && !A.word(0) && 0xffffffff == A.word(1) && 0xffffffff == A.word(2) && !A._overflow) ? "OK" : "FAIL"); // n-word - n-word --> n-word w/fewer words

    printf("Measuring 1,000 iterations of Num::subAbs()\n");
    printf("(512-bits minus 128 bits)\n");
    A.putRandom(rand, 512);
    B.putRandom(rand, 128);
    start = std::chrono::steady_clock::now();
    for (i = 0; i < 1000; i++) { A.subAbs(B); }
    end = std::chrono::steady_clock::now();
    elapsed = end - start;
    printf("Num::subAbs() time: %0.4fms  avg: %0.6fms\n\n", elapsed.count() * 1000, elapsed.count());

    printf("Testing Num::mulAbs()\n\n");
    A.putWord(93492);
    B.putWord(63861);
    A.mulAbs(B);
    printf("%-5s Num::mulAbs() 1 of 3\n", (2 == A.words() && 0x63de7cc4 == A.word(0) && 1 == A.word(1) && !A._overflow) ? "OK" : "FAIL");
    A.putString((uint8_t*)"5555555555");
    B.putString((uint8_t*)"4444444444");
    A.mulAbs(B);
    printf("%-5s Num::mulAbs() 2 of 3\n", (3 == A.words() && 0x6d600dd4 == A.word(0) && 0x56a9534c == A.word(1) && 1 == A.word(2) && !A._overflow) ? "OK" : "FAIL");
    A.mulAbs(B);
    printf("%-5s Num::mulAbs() 3 of 3\n\n", (4 == A.words() && 0xca3e8f30 == A.word(0) && 0xfd887986 == A.word(1) && 0x62964747 == A.word(2) && 1 == A.word(3) && !A._overflow) ? "OK" : "FAIL");

    printf("Measuring 1,000 iterations of Num::copy and Num::mulAbs()\n");
    printf("(1024 bits times 1024 bits)\n");
    B.putRandom(rand, 1024);
    start = std::chrono::steady_clock::now();
    for (i = 0; i < 1000; i++) { A.copy(B);  A.mulAbs(B); }
    end = std::chrono::steady_clock::now();
    elapsed = end - start;
    printf("Num::copy() and Num::mulAbs() time: %0.4fms  avg: %0.6fms\n\n", elapsed.count() * 1000, elapsed.count());

    printf("Testing Num::divAbs()\n\n");
    A.putZero();
    A.setWord(0, 0x63de7cc4);
    A.setWord(1, 1);
    A._hiword = 1;
    B.putWord(93492);
    A.divAbs(B);
    printf("%-5s Num::divAbs() 1 of 1\n\n", (1 == A.words() && 63861 == A.word(0) && !A.word(1) && !A._overflow) ? "OK" : "FAIL");

    printf("Measuring 1,000 iterations of Num::copy and Num::divAbs()\n");
    printf("(2048 bits divided by 256 bits with _loword = 0)\n");
    B.putRandom(rand, 2048);
    C.putRandom(rand, 256);
    start = std::chrono::steady_clock::now();
    for (i = 0; i < 1000; i++) { A.copy(B); A.divAbs(C); }
    end = std::chrono::steady_clock::now();
    elapsed = end - start;
    printf("Num::copy() and Num::divAbs() time: %0.4fms  avg: %0.6fms\n\n", elapsed.count() * 1000, elapsed.count());

    printf("Measuring 1,000 iterations of Num::copy and Num::divAbs()\n");
    printf("(2048 bits divided by 256 bits with _loword = 4)\n");
    B.putRandom(rand, 2048);
    C.putRandom(rand, 256);
    for (i = 0; i < 4; B.setWord(i, 0), C.setWord(i, 0), i++);
    B._loword = 4;
    C._loword = 4;
    start = std::chrono::steady_clock::now();
    for (i = 0; i < 1000; i++) { A.copy(B); A.divAbs(C); }
    end = std::chrono::steady_clock::now();
    elapsed = end - start;
    printf("Num::copy() and Num::divAbs() time: %0.4fms  avg: %0.6fms\n\n", elapsed.count() * 1000, elapsed.count());

    printf("Testing Num::modAbs()\n\n");
    A.putWord(88888888);
    B.putWord(12345);
    A.modAbs(B);
    printf("%-5s Num::modAbs() 1 of 2\n", (1 == A.words() && 4888 == A.word(0) && 13 == A.bits()) ? "OK" : "FAIL");
    A.putString((uint8_t*)"55555555555555555555");
    B.putString((uint8_t*)"444444444444");
    A.modAbs(B);
    printf("%-5s Num::modAbs() 2 of 2\n\n", (1 == A.words() && 0x034fb5e3 == A.word(0) && 26 == A.bits()) ? "OK" : "FAIL");

    printf("Measuring 1,000 iterations of Num::copy and Num::modAbs()\n");
    printf("(2048 bits modulo 256 bits with _loword = 0)\n");
    B.putRandom(rand, 2048);
    C.putRandom(rand, 256);
    start = std::chrono::steady_clock::now();
    for (i = 0; i < 1000; i++) { A.copy(B); A.modAbs(C); }
    end = std::chrono::steady_clock::now();
    elapsed = end - start;
    printf("Num::copy() and Num::modAbs() time: %0.4fms  avg: %0.6fms\n\n", elapsed.count() * 1000, elapsed.count());

    printf("Measuring 1,000 iterations of Num::copy and Num::modAbs()\n");
    printf("(2048 bits modulo 256 bits with _loword = 4)\n");
    B.putRandom(rand, 2048);
    C.putRandom(rand, 256);
    for (i = 0; i < 4; B.setWord(i, 0), C.setWord(i, 0), i++);
    B._loword = 4;
    C._loword = 4;
    start = std::chrono::steady_clock::now();
    for (i = 0; i < 1000; i++) { A.copy(B); A.modAbs(C); }
    end = std::chrono::steady_clock::now();
    elapsed = end - start;
    printf("Num::copy() and Num::modAbs() time: %0.4fms  avg: %0.6fms\n\n", elapsed.count() * 1000, elapsed.count());

    printf("Testing Num::increment()\n\n");
    A.putLong(-3);
    A.increment();
    printf("%-5s Num::increment() 1 of 6\n", ((uint32_t)-1 == A._sign && 2 == A.bits() && 1 == A.words() && 2 == A.word(0)) ? "OK" : "FAIL"); // (-3)++ = -2
    A.increment();
    printf("%-5s Num::increment() 2 of 6\n", ((uint32_t)-1 == A._sign && 1 == A.bits() && 1 == A.words() && 1 == A.word(0)) ? "OK" : "FAIL"); // (-2)++ = -1
    A.increment();
    printf("%-5s Num::increment() 3 of 6\n", (!A._sign && 1 == A.bits() && 1 == A.words() && !A.word(0)) ? "OK" : "FAIL"); // (-1)++ = 0
    A.increment();
    printf("%-5s Num::increment() 4 of 6\n", (!A._sign && 1 == A.bits() && 1 == A.words() && 1 == A.word(0)) ? "OK" : "FAIL"); // (0)++ = 1
    A.increment();
    printf("%-5s Num::increment() 5 of 6\n", (!A._sign && 2 == A.bits() && 1 == A.words() && 2 == A.word(0)) ? "OK" : "FAIL"); // (1)++ = 2
    A.increment();
    printf("%-5s Num::increment() 6 of 6\n\n", (!A._sign && 2 == A.bits() && 1 == A.words() && 3 == A.word(0)) ? "OK" : "FAIL"); // (2)++ = 3

    printf("Measuring 1,000 iterations of Num::increment()\n");
    printf("(2048 bits incremented 1,000 times)\n");
    A.putRandom(rand, 2048);
    start = std::chrono::steady_clock::now();
    for (i = 0; i < 1000; i++) { A.increment(); }
    end = std::chrono::steady_clock::now();
    elapsed = end - start;
    printf("Num::increment() time: %0.4fms  avg: %0.6fms\n\n", elapsed.count() * 1000, elapsed.count());

    printf("Testing Num::decrement()\n\n");
    A.putWord(3);
    A.decrement();
    printf("%-5s Num::decrement() 1 of 6\n", (!A._sign && 2 == A.bits() && 1 == A.words() && 2 == A.word(0)) ? "OK" : "FAIL"); // (3)-- = 2
    A.decrement();
    printf("%-5s Num::decrement() 2 of 6\n", (!A._sign && 1 == A.bits() && 1 == A.words() && 1 == A.word(0)) ? "OK" : "FAIL"); // (2)-- = 1
    A.decrement();
    printf("%-5s Num::decrement() 3 of 6\n", (!A._sign && 1 == A.bits() && 1 == A.words() && !A.word(0)) ? "OK" : "FAIL"); // (1)-- = 0
    A.decrement();
    printf("%-5s Num::decrement() 4 of 6\n", ((uint32_t)-1 == A._sign && 1 == A.bits() && 1 == A.words() && 1 == A.word(0)) ? "OK" : "FAIL"); // (0)-- = -1
    A.decrement();
    printf("%-5s Num::decrement() 5 of 6\n", ((uint32_t)-1 == A._sign && 2 == A.bits() && 1 == A.words() && 2 == A.word(0)) ? "OK" : "FAIL"); // (-1)-- = -2
    A.decrement();
    printf("%-5s Num::decrement() 6 of 6\n\n", ((uint32_t)-1 == A._sign && 2 == A.bits() && 1 == A.words() && 3 == A.word(0)) ? "OK" : "FAIL"); // (-2)-- = -3

    printf("Measuring 1,000 iterations of Num::decrement()\n");
    printf("(2048 bits decremented 1,000 times)\n");
    A.putRandom(rand, 2048);
    start = std::chrono::steady_clock::now();
    for (i = 0; i < 1000; i++) { A.decrement(); }
    end = std::chrono::steady_clock::now();
    elapsed = end - start;
    printf("Num::decrement() time: %0.4fms  avg: %0.6fms\n\n", elapsed.count() * 1000, elapsed.count());

    printf("Testing Num::add()\n\n");
    A.putWord(0x5a5a5a5a);
    A.add(A);
    printf("%-5s Num::add() 1 of 10\n", (0xb4b4b4b4 == A.word(0) && 1 == A.words() && !A._overflow) ? "OK" : "FAIL"); // 1-word + 1-word --> no word overflow
    A.add(A);
    printf("%-5s Num::add() 2 of 10\n", (0x69696968 == A.word(0) && 1 == A.word(1) && 2 == A.words() && !A._overflow) ? "OK" : "FAIL"); // 1-word + 1-word --> word overflow
    A.putZero();
    A.setWord(0, 0x89abcdef);
    A.setWord(1, 0x01234567);
    A._hiword = 1;
    B.putWord(0x55555555);
    A.add(B);
    printf("%-5s Num::add() 3 of 10\n", (0xdf012344 == A.word(0) && 0x01234567 == A.word(1) && 2 == A.words() && !A._overflow) ? "OK" : "FAIL"); // 1-word + 2-word --> no word overflow
    A.putZero();
    A.setWord(0, 0x89abcdef);
    A.setWord(1, 0x01234567);
    A._hiword = 1;
    B.putWord(0xaaaaaaaa);
    A.add(B);
    printf("%-5s Num::add() 4 of 10\n", (0x34567899 == A.word(0) && 0x01234568 == A.word(1) && 2 == A.words() && !A._overflow) ? "OK" : "FAIL"); // 1-word + 2-word --> word overflow
    A.putZero();
    A.setWord(0, 0xffffffff);
    A.setWord(1, 0xffffffff);
    A.setWord(2, 0xffffffff);
    A.setWord(3, 0xffffffff);
    A._hiword = 3;
    B.putTwo();
    A.add(B);
    printf("%-5s Num::add() 5 of 10\n", (1 == A.word(0) && !A.word(1) && !A.word(2) && !A.word(3) && 1 == A.word(4) && 5 == A.words() && !A._overflow) ? "OK" : "FAIL"); // 1-word + n-word --> n-word overflow
    A.putZero();
    A.setWord(0, 0xffffffff);
    A.setWord(1, 0xffffffff);
    A.setWord(2, 0xffffffff);
    A.setWord(3, 0xffffffff);
    A._hiword = 3;
    B.putZero();
    B.setWord(0, 0x00000001);
    B.setWord(1, 0x00000001);
    B._hiword = 1;
    A.add(B);
    printf("%-5s Num::add() 6 of 10\n", (!A.word(0) && 1 == A.word(1) && !A.word(2) && !A.word(3) && 1 == A.word(4) && 5 == A.words() && !A._overflow) ? "OK" : "FAIL"); // n-word + n-word --> n-word overflow
    A.putZero();
    A.setWord(0, 0xffffffff);
    A.setWord(1, 0xffffffff);
    A.setWord(2, 0xffffffff);
    A.setWord(3, 0x33333333);
    A.setWord(4, 0x22222222);
    A.setWord(5, 0x11111111);
    A._hiword = 5;
    B.putTwo();
    A.add(B);
    printf("%-5s Num::add() 7 of 10\n", (1 == A.word(0) && !A.word(1) && !A.word(2) && 0x33333334 == A.word(3) && 0x22222222 == A.word(4) && 0x11111111 == A.word(5) && 6 == A.words() && !A._overflow) ? "OK" : "FAIL"); // 1-word + n-word --> word overflow, no increase in A.words()
    A.putZero();
    A.setWord(0, 0xffffffff);
    A.setWord(1, 0xffffffff);
    A.setWord(2, 0xffffffff);
    A.setWord(3, 0x33333333);
    A.setWord(4, 0x22222222);
    A.setWord(5, 0x11111111);
    A._hiword = 5;
    B.putZero();
    B.setWord(0, 1);
    B.setWord(1, 1);
    B._hiword = 1;
    A.add(B);
    printf("%-5s Num::add() 8 of 10\n", (!A.word(0) && 1 == A.word(1) && !A.word(2) && 0x33333334 == A.word(3) && 0x22222222 == A.word(4) && 0x11111111 == A.word(5) && 6 == A.words() && !A._overflow) ? "OK" : "FAIL"); // n-word + n-word --> n-word overflow, no increase in A.words()
    A.putZero();
    for (i = 0; i < num::words; A.setWord(i, 0xffffffff), i++);
    A._hiword = num::hiword;
    B.putTwo();
    A.add(B);
    printf("%-5s Num::add() 9 of 10\n", (1 == A.word(0) && 1 == A.words() && !A._overflow) ? "OK" : "FAIL"); // (-1) + 2 --> overflow
    A.putZero();
    for (i = 0; i < num::words; A.setWord(i, 0xffffffff), i++);
    A._hiword = num::hiword;
    B.putZero();
    B.setWord(0, 1);
    B.setWord(1, 1);
    B._hiword = 1;
    A.add(B);
    printf("%-5s Num::add() 10 of 10\n\n", (!A.word(0) && 1 == A.word(1) && 2 == A.words() && !A._overflow) ? "OK" : "FAIL"); // (-1) + n-word --> overflow 

    printf("Measuring 1,000 iterations of Num::add()\n");
    printf("(512-bits plus 128 bits)\n");
    A.putRandom(rand, 512);
    B.putRandom(rand, 128);
    start = std::chrono::steady_clock::now();
    for (i = 0; i < 1000; i++) { A.add(B); }
    end = std::chrono::steady_clock::now();
    elapsed = end - start;
    printf("Num::add() time: %0.4fms  avg: %0.6fms\n\n", elapsed.count() * 1000, elapsed.count());

    printf("Testing Num::sub()\n\n");
    A.putWord(0xffffffff);
    B.putWord(0xffffffff);
    A.sub(B);
    printf("%-5s Num::sub() 1 of 8\n", (1 == A.words() && !A.word(0) && !A._overflow) ? "OK" : "FAIL"); // 1-word - same --> zero
    A.putWord(0xffffffff);
    B.putWord(0xdddddddd);
    A.sub(B);
    printf("%-5s Num::sub() 2 of 8\n", (1 == A.words() && 0x22222222 == A.word(0) && !A._overflow) ? "OK" : "FAIL"); // 1-word - 1-word --> positive value
    A.putZero();
    A.setWord(1, 1);
    A.setWord(0, 0x69696968);
    A._hiword = 1;
    B.copy(A);
    A.sub(B);
    printf("%-5s Num::sub() 3 of 8\n", (1 == A.words() && !A.word(0) && !A._overflow) ? "OK" : "FAIL"); // n-word - same --> zero
    A.putZero();
    A.setWord(0, 0x69696968);
    A.setWord(1, 1);
    A._hiword = 1;
    B.putWord(0xb4b4b4b4);
    A.sub(B);
    printf("%-5s Num::sub() 4 of 8\n", (1 == A.words() && 0xb4b4b4b4 == A.word(0) && !A._overflow) ? "OK" : "FAIL"); // n-word - n-word --> positive value
    B.putWord(0x5a5a5a5a);
    A.sub(B);
    printf("%-5s Num::sub() 5 of 8\n", (1 == A.words() && 0x5a5a5a5a == A.word(0) && !A._hiword) ? "OK" : "FAIL"); // n-word - half-value --> 1-word value
    A.putZero();
    A.setWord(0, 0x89abcdef);
    A.setWord(1, 0x01234567);
    A._hiword = 1;
    B.putWord(0x55555555);
    A.sub(B);
    printf("%-5s Num::sub() 6 of 8\n", (2 == A.words() && 0x3456789a == A.word(0) && 0x01234567 == A.word(1) && !A._overflow) ? "OK" : "FAIL"); // n-word - 1-word --> n-word
    A.putZero();
    A.setWord(0, 1);
    A.setWord(3, 1);
    A._hiword = 3;
    B.putTwo();
    A.sub(B);
    printf("%-5s Num::sub() 7 of 8\n", (3 == A.words() && 0xffffffff == A.word(0) && 0xffffffff == A.word(1) && 0xffffffff == A.word(2) && !A.word(3) && !A._overflow) ? "OK" : "FAIL"); // n-word - 1-word --> n-word w/fewer words
    A.putZero();
    A.setWord(0, 1);
    A.setWord(3, 1);
    A._hiword = 3;
    B.putZero();
    B.setWord(0, 1);
    B.setWord(1, 1);
    B._hiword = 1;
    A.sub(B);
    printf("%-5s Num::sub() 8 of 8\n\n", (3 == A.words() && !A.word(0) && 0xffffffff == A.word(1) && 0xffffffff == A.word(2) && !A._overflow) ? "OK" : "FAIL"); // n-word - n-word --> n-word w/fewer words

    printf("Measuring 1,000,000 iterations of Num::sub()\n");
    printf("(512-bits minus 128 bits)\n");
    A.putRandom(rand, 512);
    B.putRandom(rand, 128);
    start = std::chrono::steady_clock::now();
    for (i = 0; i < 1000; i++) { A.sub(B); }
    end = std::chrono::steady_clock::now();
    elapsed = end - start;
    printf("Num::sub() time: %0.4fms  avg: %0.6fms\n\n", elapsed.count() * 1000, elapsed.count());

    printf("Testing Num::mul()\n\n");
    A.putWord(93492);
    B.putWord(63861);
    A.mul(B);
    printf("%-5s Num::mul() 1 of 3\n", (2 == A.words() && 0x63de7cc4 == A.word(0) && 1 == A.word(1) && !A._overflow) ? "OK" : "FAIL");
    A.putString((uint8_t*)"5555555555");
    B.putString((uint8_t*)"4444444444");
    A.mul(B);
    printf("%-5s Num::mul() 2 of 3\n", (3 == A.words() && 0x6d600dd4 == A.word(0) && 0x56a9534c == A.word(1) && 1 == A.word(2) && !A._overflow) ? "OK" : "FAIL");
    A.mul(B);
    printf("%-5s Num::mul() 3 of 3\n\n", (4 == A.words() && 0xca3e8f30 == A.word(0) && 0xfd887986 == A.word(1) && 0x62964747 == A.word(2) && 1 == A.word(3) && !A._overflow) ? "OK" : "FAIL");

    printf("Measuring 1,000 iterations of Num::copy and Num::mul()\n");
    printf("(512 bits times 512 bits)\n");
    B.putRandom(rand, 512);
    start = std::chrono::steady_clock::now();
    for (i = 0; i < 1000; i++) { A.copy(B); A.mul(B); }
    end = std::chrono::steady_clock::now();
    elapsed = end - start;
    printf("Num::sub() time: %0.4fms  avg: %0.6fms\n\n", elapsed.count() * 1000, elapsed.count());

    printf("Testing Num::div()\n\n");
    A.putZero();
    A.setWord(0, 0x63de7cc4);
    A.setWord(1, 1);
    A._hiword = 1;
    B.putWord(93492);
    A.div(B);
    printf("%-5s Num::div() 1 of 1\n\n", (1 == A.words() && 63861 == A.word(0) && !A.word(1) && !A._overflow) ? "OK" : "FAIL");

    printf("Measuring 1,000 iterations of Num::copy and Num::div()\n");
    printf("(2048 bits divided by 256 bits with _loword = 0)\n");
    B.putRandom(rand, 2048);
    C.putRandom(rand, 256);
    start = std::chrono::steady_clock::now();
    for (i = 0; i < 1000; i++) { A.copy(B); A.div(C); }
    end = std::chrono::steady_clock::now();
    elapsed = end - start;
    printf("Num::copy() and Num::div() time: %0.4fms  avg: %0.6fms\n\n", elapsed.count() * 1000, elapsed.count());

    printf("Testing Num::mod()\n\n");
    A.putWord(88888888);
    B.putWord(12345);
    A.mod(B);
    printf("%-5s Num::mod() 1 of 2\n", (1 == A.words() && 4888 == A.word(0) && 13 == A.bits()) ? "OK" : "FAIL");
    A.putString((uint8_t*)"55555555555555555555");
    B.putString((uint8_t*)"444444444444");
    A.mod(B);
    printf("%-5s Num::mod() 2 of 2\n\n", (1 == A.words() && 0x034fb5e3 == A.word(0) && 26 == A.bits()) ? "OK" : "FAIL");

    printf("Measuring 1,000 iterations of Num::copy and Num::mod()\n");
    printf("(2048 bits modulo 256 bits with _loword = 0)\n");
    B.putRandom(rand, 2048);
    C.putRandom(rand, 256);
    start = std::chrono::steady_clock::now();
    for (i = 0; i < 1000; i++) { A.copy(B); A.mod(C); }
    end = std::chrono::steady_clock::now();
    elapsed = end - start;
    printf("Num::copy() and Num::mod() time: %0.4fms  avg: %0.6fms\n\n", elapsed.count() * 1000, elapsed.count());

    printf("Testing Num::montMul(), Num::montExp()\n\n");
    A.putWord(17);
    B.putWord(5);
    C.putWord(35);
    D.putWord(29);
    E.montExp(A, B, C);
    printf("%-5s Num::montExp() 1 of 2\n", (12 == E.word(0)) ? "OK" : "FAIL");
    E.montExp(E, D, C);
    printf("%-5s Num::montExp() 2 of 2\n\n", (17 == E.word(0)) ? "OK" : "FAIL");

    printf("Measuring 1,000 iterations of Num::montExp() (17^5 mod 35)\n");
    A = 17;
    B = 5;
    C = 35;
    start = std::chrono::steady_clock::now();
    for (i = 0; i < 1000; i++) { E.montExp(A, B, C); }
    end = std::chrono::steady_clock::now();
    elapsed = end - start;
    printf("Num::montExp() time: %0.4fms  avg: %0.6fms\n\n", elapsed.count() * 1000, elapsed.count());

    printf("Testing Num::isPrime()\n\n");
    A.putZero();
    printf("%-5s Num::isPrime() 1 of 8\n", (!A.isPrime()) ? "OK" : "FAIL");
    A.putOne();
    printf("%-5s Num::isPrime() 2 of 8\n", (!A.isPrime()) ? "OK" : "FAIL");
    A.putTwo();
    printf("%-5s Num::isPrime() 3 of 8\n", (A.isPrime()) ? "OK" : "FAIL");
    A.putWord(3);
    printf("%-5s Num::isPrime() 4 of 8\n", (A.isPrime()) ? "OK" : "FAIL");
    A.putWord(997);
    printf("%-5s Num::isPrime() 5 of 8\n", (A.isPrime()) ? "OK" : "FAIL");
    A.putWord(2000);
    printf("%-5s Num::isPrime() 6 of 8\n", (!A.isPrime()) ? "OK" : "FAIL");
    A.putWord(55555);
    printf("%-5s Num::isPrime() 7 of 8\n", (!A.isPrime()) ? "OK" : "FAIL");
    A.putString((uint8_t*)"9572039759");
    printf("%-5s Num::isPrime() 8 of 8\n\n", (!A.isPrime()) ? "OK" : "FAIL");

    printf("Testing Num::putPrime()\n\n");
    for (j = 0; j < 6; j++) {
        A.putPrime(rand, (size_t)32 << j);
        printf("%-5s Num::putPrime(%u)\n", (A.isPrime()) ? "OK" : "FAIL", 32 << j);
    }
    printf("\n");

    printf("Measuring 100 iterations of Num::isPrime()\n");
    A.putPrime(rand, 512);
    start = std::chrono::steady_clock::now();
    for (i = 0; i < 100; i++) { A.isPrime(); }
    end = std::chrono::steady_clock::now();
    elapsed = end - start;
    printf("Num::isPrime() time: %0.4fms  avg: %0.6fms\n\n", elapsed.count() * 1000, elapsed.count() * 10);

    for (j = 0; j < 6; j++) {
        printf("Measuring 10 iterations of Num::putPrime(%u)\n", 32 << j);
        start = std::chrono::steady_clock::now();
        for (i = 0; i < 10; i++) { A.putPrime(rand, (size_t)32 << j); }
        end = std::chrono::steady_clock::now();
        elapsed = end - start;
        printf("Num::putPrime(%u) time: %0.4fms  avg: %0.6fms\n\n", 32 << j, elapsed.count() * 1000, elapsed.count() * 100);
    }

    printf("Testing Num::GCD()\n\n");
    X.putWord(383);
    Y.putWord(271);
    G.GCD(X, Y);
    printf("%-5s Num::GCD() 1 of 5\n", (1 == G.word(0)) ? "OK" : "FAIL");
    X.putWord(877);
    Y.putWord(557);
    G.GCD(X, Y);
    printf("%-5s Num::GCD() 2 of 5\n", (1 == G.word(0)) ? "OK" : "FAIL");
    X.putWord(1783);
    Y.putWord(1063);
    G.GCD(X, Y);
    printf("%-5s Num::GCD() 3 of 5\n", (1 == G.word(0)) ? "OK" : "FAIL");
    X.putWord(3041);
    Y.putWord(2903);
    G.GCD(X, Y);
    printf("%-5s Num::GCD() 4 of 5\n", (1 == G.word(0)) ? "OK" : "FAIL");
    X.putWord(768454923);
    Y.putWord(542167814);
    G.GCD(X, Y);
    printf("%-5s Num::GCD() 5 of 5\n\n", (1 == G.word(0)) ? "OK" : "FAIL");

    printf("Measuring 1,000 iterations of Num::GCD()\n");
    printf("(512-bit prime, 512-bit prime)\n");
    X.putPrime(rand, 512);
    Y.putPrime(rand, 512);
    start = std::chrono::steady_clock::now();
    for (i = 0; i < 1000; i++) { G.GCD(X, Y); }
    end = std::chrono::steady_clock::now();
    elapsed = end - start;
    printf("Num::GCD() time: %0.4fms  avg: %0.6fms\n\n", elapsed.count() * 1000, elapsed.count());

    printf("Testing Num::mulInvGCD()\n\n");
    X.putWord(383);                               //  m
    Y.putWord(271);                               //  a
    G.mulInvGCD(X, Y, D);                         //  1 ~= ad (mod m)
    D.mul(Y);                                     //  ad
    D.mod(X);                                     //  ad (mod m )
    printf("%-5s Num::mulInvGCD() 1 of 5\n", (!G._hiword && 1 == G.word(0) && !D._hiword && 1 == D.word(0)) ? "OK" : "FAIL");
    X.putWord(877);                               //  m
    Y.putWord(557);                               //  a
    G.mulInvGCD(X, Y, D);                         //  1 ~= ad (mod m)
    D.mul(Y);                                     //  ad
    D.mod(X);                                     //  ad (mod m )
    printf("%-5s Num::mulInvGCD() 2 of 5\n", (!G._hiword && 1 == G.word(0) && !D._hiword && 1 == D.word(0)) ? "OK" : "FAIL");
    X.putWord(1783);                              //  m
    Y.putWord(1063);                              //  a
    G.mulInvGCD(X, Y, D);                         //  1 ~= ad (mod m)
    D.mul(Y);                                     //  ad
    D.mod(X);                                     //  ad (mod m )
    printf("%-5s Num::mulInvGCD() 3 of 5\n", (!G._hiword && 1 == G.word(0) && !D._hiword && 1 == D.word(0)) ? "OK" : "FAIL");
    X.putWord(3041);                              //  m
    Y.putWord(2903);                              //  a
    G.mulInvGCD(X, Y, D);                         //  1 ~= ad (mod m)
    D.mul(Y);                                     //  ad
    D.mod(X);                                     //  ad (mod m )
    printf("%-5s Num::mulInvGCD() 4 of 5\n", (!G._hiword && 1 == G.word(0) && !D._hiword && 1 == D.word(0)) ? "OK" : "FAIL");
    X.putWord(768454923);                         //  m
    Y.putWord(542167814);                         //  a
    G.mulInvGCD(X, Y, D);                         //  1 ~= ad (mod m)
    D.mul(Y);                                     //  ad
    D.mod(X);                                     //  ad (mod m )
    printf("%-5s Num::mulInvGCD() 5 of 5\n\n", (!G._hiword && 1 == G.word(0) && !D._hiword && 1 == D.word(0)) ? "OK" : "FAIL");

    printf("Measuring 1,000 iterations of Num::mulInvGCD()\n");
    printf("(512-bit prime, 512-bit prime )\n");
    X.putPrime(rand, 512);
    Y.putPrime(rand, 512);
    if (Y > X) {
        A = Y;
        Y = X;
        X = A;
    }
    start = std::chrono::steady_clock::now();
    for (i = 0; i < 1000; i++) { G.mulInvGCD(X, Y, D); }
    end = std::chrono::steady_clock::now();
    elapsed = end - start;
    printf("Num::mulInvGCD() time: %0.4fms  avg: %0.6fms\n\n", elapsed.count() * 1000, elapsed.count());

    printf("Testing Num::mulInvWord\n\n");
    i = Num::mulInvWord(3);
    printf("%-5s Num::mulInvWord(3) = %u\n", (i * 3 == 1) ? "OK" : "FAIL", i);
    i = Num::mulInvWord(237);
    printf("%-5s Num::mulInvWord(237) = %u\n", (i * 237 == 1) ? "OK" : "FAIL", i);
    i = Num::mulInvWord(4911);
    printf("%-5s Num::mulInvWord(4911) = %u\n", (i * 4911 == 1) ? "OK" : "FAIL", i);
    i = Num::mulInvWord(5437);
    printf("%-5s Num::mulInvWord(5437) = %u\n", (i * 5437 == 1) ? "OK" : "FAIL", i);
    i = Num::mulInvWord(38625);
    printf("%-5s Num::mulInvWord(38625) = %u\n", (i * 38625 == 1) ? "OK" : "FAIL", i);
    i = Num::mulInvWord(373823);
    printf("%-5s Num::mulInvWord(373823) = %u\n", (i * 373823 == 1) ? "OK" : "FAIL", i);
    i = Num::mulInvWord(7856321);
    printf("%-5s Num::mulInvWord(7856321) = %u\n", (i * 7856321 == 1) ? "OK" : "FAIL", i);
    i = Num::mulInvWord(62489019);
    printf("%-5s Num::mulInvWord(62489019) = %u\n", (i * 62489019 == 1) ? "OK" : "FAIL", i);
    i = Num::mulInvWord(0xCF977871);
    printf("%-5s Num::mulInvWord(3482810481L) = %u\n\n", (i * 0xcf977871 == 1) ? "OK" : "FAIL", i);

    printf("Measuring 1,000 iterations of Num::mulInvWord()\n");
    start = std::chrono::steady_clock::now();
    for (i = 0; i < 1000; i++) { Num::mulInvWord(0xcf977871); }
    end = std::chrono::steady_clock::now();
    elapsed = end - start;
    printf("Num::mulInvWord time: %0.4fms  avg: %0.6fms\n\n", elapsed.count() * 1000, elapsed.count());
}

void testDSA()
{
}

void testRSA()
{
    size_t len;
    Random rnd;
    Num N, C, T, xp, xp1, xp2, p1;
    RSA rsa;
    uint8_t in[32];
    uint8_t out[256];
    uint8_t dec[32];

    printf("Testing RSA\n\n");
    printf("Testing RSA::create(1024)\n\n");
    rsa.Create(1024);
    N.putRandom(rnd, 512);
    C.montExp(N, rsa.E, rsa.N);
    T.montExp(C, rsa.D, rsa.N);
    printf("%-5s RSA::create() 1 of 1\n\n", (!N.compare(T) ? "OK" : "FAIL"));

    printf("Testing RSA::sign() and RSA::verify()\n\n");
    memcpy(in, "abcdefghijklmnopqrstuvwxyz01234\x00", 32);
    rsa.Sign(out, in, 32);
    len = 128;
    printf("%-5s RSA::sign() and verify() 1 of 1\n\n", rsa.Verify(dec, out, &len) ? "OK" : "FAIL");

    printf("Testing RSA::encrypt() and RSA::decrypt()\n\n");
    len = 32;
    rsa.Encrypt(out, in, &len);
    rsa.Decrypt(dec, out, &len);
    printf("%-5s RSA::encrypt() and decrypt() 1 of 1\n\n", !memcmp(in, dec, 32) ? "OK" : "FAIL");
}

void testAsymmetricEncryption()
{
    queryRun("DSA", testDSA);
    queryRun("RSA", testRSA);
}

void testCRC32()
{
}

void testZlib()
{
    uint8_t rec[4096] = { 0 };
    uint8_t cmp[4096] = { 0 };
    uint8_t dec[4096] = { 0 };
    z_stream z = { 0 };

    printf("Testing Zlib Compression\n");
    if (!_dump)
        printf("\n");
    size_t len = strlen(COMPRESS_RECORD);
    memcpy(rec, COMPRESS_RECORD, len);
    if (_dump) {
        printf("Test Data:\n");
        dumpMem(rec, len);
    }
    if (Z_OK != DeflateInit(&z)) {
        printf("FAIL  Unable to initialize ZLIB for compression\n");
        dumpMem((uint8_t*)&z, sizeof(z));
        return;
    }
    size_t totalIn = 0;
    size_t totalOut = 0;
    size_t in = 0;
    size_t out = 0;
    size_t loops = 0;
    do {
        z.next_in = &rec[in];
        z.avail_in = (uInt)(len - in);
        z.next_out = &cmp[out];
        z.avail_out = (uInt)(sizeof cmp - out);
        int zrc = DeflateNext(&z);
        if (Z_OK != zrc && Z_STREAM_END != zrc) {
            printf("FAIL  Unable to compress data\n");
            dumpMem((uint8_t*)&z, sizeof(z));
            break;
        }
        in = z.total_in;
        out = z.total_out;
        loops++;
    } while (in < len && loops < 100);
    if (_dump)
        printf("\n");
    printf("OK    (%zd) bytes compressed to (%zd) bytes in (%zd) iteration(s)\n", len, out, loops);
    z.next_in = 0;
    z.avail_in = 0;
    z.next_out = &cmp[out];
    z.avail_out = (uInt)(sizeof cmp - out);
    int zrc = DeflateFinal(&z);
    if (Z_OK != zrc && Z_STREAM_END != zrc) {
        printf("FAIL  Unable to finalize compression\n");
        dumpMem((uint8_t*)&z, sizeof(z));
        return;
    }
    zrc = DeflateEnd(&z);
    if (Z_OK != zrc) {
        printf("FAIL  Unable to release ZLIB resources\n");
        dumpMem((uint8_t*)&z, sizeof(z));
        return;
    }
    if (_dump) {
        printf("\nCompressed Data:\n");
        dumpMem(cmp, out);
    }
    len = out;
    memset(&z, 0, sizeof(z));
    if (Z_OK != InflateInit(&z)) {
        printf("FAIL  Unable to initialize ZLIB for decompression\n");
        dumpMem((uint8_t*)&z, sizeof(z));
        return;
    }
    totalIn = 0;
    totalOut = 0;
    in = 0;
    out = 0;
    loops = 0;
    do {
        z.next_in = &cmp[in];
        z.avail_in = (uInt)(len - in);
        z.next_out = &dec[out];
        z.avail_out = (uInt)(sizeof dec - out);
        zrc = InflateNext(&z);
        if (Z_OK != zrc && Z_STREAM_END != zrc) {
            printf("FAIL  Unable to decompress data\n");
            dumpMem((uint8_t*)&z, sizeof(z));
            break;
        }
        in = z.total_in;
        out = z.total_out;
        loops++;
    } while (in < len && loops < 100);
    if (_dump)
        printf("\n");
    printf("OK    (%zd) bytes decompressed to (%zd) bytes in (%zd) iteration(s)\n", len, out, loops);
    zrc = InflateEnd(&z);
    if (Z_OK != zrc) {
        printf("FAIL  Unable to release ZLIB resources\n");
        dumpMem((uint8_t*)&z, sizeof(z));
        return;
    }
    if (_dump) {
        printf("\nDecompressed Data:\n");
        dumpMem(dec, out);
        printf("\n");
    }
    printf("%-5s deflate() and inflate() 1 of 1\n\n", !memcmp(rec, dec, sizeof(rec)) ? "OK" : "FAIL");
}

void testCompression()
{
    //queryRun("CRC-32", testCRC32);
    queryRun("ZLIB", testZlib);
}

void testBase64()
{
    size_t len, i;
    uint8_t rec[128] = { 0 };
    uint8_t enc[256] = { 0 };
    uint8_t dec[128] = { 0 };
    Random rand;

    printf("Testing Base64 Encoding\n");
    if (!_dump)
        printf("\n");
    for (i = 0; i < 112; i++) { rec[i] = (uint8_t)(rand.Rand()); }
    len = i;
    base64enc(enc, rec, &len);
    base64dec(dec, enc, &len);
    if (_dump) {
        printf("\n");
        printf("Plain:\n");
        dumpMem(rec, i);
        printf("Encoded:\n");
        dumpMem(enc, strlen((const char*)enc));
        printf("Decoded:\n");
        dumpMem(dec, i);
        printf("\n");
    }
    printf("%-5s Base64 1 of 4\n", !memcmp(rec, dec, sizeof(rec)) ? "OK" : "FAIL");

    memset(rec, 0, sizeof(rec));
    memset(enc, 0, sizeof(enc));

    for (i = 0; i < 113; i++) { rec[i] = (uint8_t)(rand.Rand()); }
    len = i;
    base64enc(enc, rec, &len);
    base64dec(dec, enc, &len);
    if (_dump) {
        printf("\n");
        printf("Plain:\n");
        dumpMem(rec, i);
        printf("Encoded:\n");
        dumpMem(enc, strlen((const char*)enc));
        printf("Decoded:\n");
        dumpMem(dec, i);
        printf("\n");
    }
    printf("%-5s Base64 2 of 4\n", !memcmp(rec, dec, sizeof(rec)) ? "OK" : "FAIL");

    memset(rec, 0, sizeof(rec));
    memset(enc, 0, sizeof(enc));

    for (i = 0; i < 114; i++) { rec[i] = (uint8_t)(rand.Rand()); }
    len = i;
    base64enc(enc, rec, &len);
    base64dec(dec, enc, &len);
    if (_dump) {
        printf("\n");
        printf("Plain:\n");
        dumpMem(rec, i);
        printf("Encoded:\n");
        dumpMem(enc, strlen((const char*)enc));
        printf("Decoded:\n");
        dumpMem(dec, i);
        printf("\n");
    }
    printf("%-5s Base64 3 of 4\n", !memcmp(rec, dec, sizeof(rec)) ? "OK" : "FAIL");

    memset(rec, 0, sizeof(rec));
    memset(enc, 0, sizeof(enc));

    for (i = 0; i < 115; i++) { rec[i] = (uint8_t)(rand.Rand()); }
    len = i;
    base64enc(enc, rec, &len);
    base64dec(dec, enc, &len);
    if (_dump) {
        printf("\n");
        printf("Plain:\n");
        dumpMem(rec, i);
        printf("Encoded:\n");
        dumpMem(enc, strlen((const char*)enc));
        printf("Decoded:\n");
        dumpMem(dec, i);
        printf("\n");
    }
    printf("%-5s Base64 4 of 4\n\n", !memcmp(rec, dec, sizeof(rec)) ? "OK" : "FAIL");
}

const char* x509_passphrase = "abcdefghijklmnopqrstuvwxyz";
RSA _rsa;
RSA _rsa_chk;
X509 _X;

void testX509()
{
    printf("Testing X.509 Encoding\n\n");
    size_t len = 4096;
    uint8_t* phr_enc = new uint8_t[len];
    uint8_t* phr_chk = new uint8_t[len];

    Passphrase phr;
    memset(phr_enc, 0, len);
    phr.Encode(phr_enc, x509_passphrase);
    FILE* file = fopen("test.phr", "w+b");
    fwrite(phr_enc, 1, strlen((char*)phr_enc), file);
    fclose(file);
    printf("OK    Encoded passphrase exported to test.phr\n");

    file = fopen("test.phr", "rb");
    len = 4096;
    memset(phr_enc, 0, 4096);
    fread(phr_enc, 1, len, file);
    fclose(file);

    memset(phr_chk, 0, 4096);
    if (!phr.Decode(phr_chk, (char*)phr_enc)) {
        printf("FAIL  Unable to decode passphrase\n\n");
        delete[] phr_enc;
        delete[] phr_chk;
        phr_enc = nullptr;
        phr_chk = nullptr;
        return;
    }
    if (strcmp((char*)phr_chk, x509_passphrase)) {
        printf("FAIL  Passphrase incorrectly decoded\n\n");
        delete[] phr_enc;
        delete[] phr_chk;
        phr_enc = nullptr;
        phr_chk = nullptr;
        return;
    }
    printf("OK    Passphrase decoded\n");
    delete[] phr_enc;
    phr_enc = nullptr;

    len = 4096;
    uint8_t* key_enc = new uint8_t[len];
    uint8_t* key_dec = new uint8_t[len];
    uint8_t* key_chk = new uint8_t[len];

    _rsa.Create(1024);
    printf("OK    Key-pair created\n");
    memset(key_dec, 0, 4096);
    _rsa.ExportKey(key_dec, &len);
    file = fopen("test.prv", "w+b");
    fwrite(key_dec, 1, len, file);
    fclose(file);
    printf("OK    Private key exported to test.prv\n");

    memset(key_enc, 0, 4096);
    _rsa.ExportEncryptedKey(key_enc, &len, phr_chk, strlen((char*)phr_chk));
    file = fopen("test.p8", "w+b");
    fwrite(key_enc, 1, len, file);
    fclose(file);
    printf("OK    Encrypted private key exported to test.p8\n");

    file = fopen("test.p8", "rb");
    len = 4096;
    memset(key_enc, 0, 4096);
    fread(key_enc, 1, len, file);
    fclose(file);

    uint8_t* imp = key_enc;
    _rsa_chk.Import(&imp, &len, phr_chk, strlen((char*)phr_chk));
    delete[] phr_chk;
    phr_chk = nullptr;

    if (_rsa.N != _rsa_chk.N) {
        printf("FAIL  Imported RSA key modulus differs\n\n");
        delete[] key_enc;
        delete[] key_chk;
        key_enc = nullptr;
        key_chk = nullptr;
        return;
    }
    if (_rsa.E != _rsa_chk.E) {
        printf("FAIL  Imported RSA key public exponent differs\n\n");
        delete[] key_enc;
        delete[] key_chk;
        key_enc = nullptr;
        key_chk = nullptr;
        return;
    }
    if (_rsa.D != _rsa_chk.D) {
        printf("FAIL  Imported RSA key private exponent differs\n\n");
        delete[] key_enc;
        delete[] key_chk;
        key_enc = nullptr;
        key_chk = nullptr;
        return;
    }
    printf("OK    Encrypted private key imported\n");

    memset(key_dec, 0, 4096);
    strcpy((char*)key_dec, "abcdefghijklmnopqrstuvwxyz01234");
    len = strlen((const char*)key_dec);
    memset(key_enc, 0, 4096);
    _rsa_chk.Encrypt(key_enc, key_dec, &len);

    memset(key_chk, 0, 4096);
    _rsa_chk.Decrypt(key_chk, key_enc, &len);
    printf("%-5s Encrypt/decrypt with imported key\n", !memcmp(key_dec, key_chk, len) ? "OK" : "FAIL");

    delete[] key_enc;
    delete[] key_chk;
    key_enc = nullptr;
    key_chk = nullptr;

    _X.PutIssuer("E=jen@proserio.com;O=Proserio;CN=Jen");
    _X.PutSerNo((uint8_t*)"1001");
    _X.PutSubject("E=jen@proserio.com;O=Proserio;CN=Jen");
    _X.PutNotBefore((uint8_t*)"20200101000000");
    _X.PutNotAfter((uint8_t*)"20300101000000");
    _X.PutPubKey(_rsa_chk);
    _X.PutPrvKey(_rsa_chk);
    _X._flags |= x509::flags::cacert;
    _X._pathLen = 3;
    _X.ExportCert(key_dec, &len);

    file = fopen("test.cer", "w+b");
    fwrite(key_dec, 1, len, file);
    fclose(file);
    printf("OK    Certificate exported to test.cer\n");

    delete[] key_dec;
    key_dec = nullptr;
    printf("\n");
}

void testEncoding()
{
    queryRun("Base64 Encoding", testBase64);
    queryRun("X.509 Encoding", testX509);
}

void runTests()
{
    printf("\n");
    printf("sizeof(short)     %2zd bytes\n", sizeof(short));
    printf("sizeof(int)       %2zd bytes\n", sizeof(int));
    printf("sizeof(long)      %2zd bytes\n", sizeof(long));
    printf("sizeof(long long) %2zd bytes\n", sizeof(long long));
    printf("\n");

    queryRun("Message Digest", testDigestAlgs);
    queryRun("Hashed MAC", testHMACAlgs);
    queryRun("Symmetric Encryption", testSymmetricEncryption);
    queryRun("Pseudo-Random", testRandom);
    queryRun("Large Integer", testInt);
    queryRun("Asymmetric Encryption", testAsymmetricEncryption);
    queryRun("Compression", testCompression);
    queryRun("Encoding", testEncoding);

    printf("Tests Completed\n");
}

int usage()
{
    printf( \
        "Usage: jentest test [all] [dump]\n" \
        "       jentest gen  [license]\n");
    return 0;
}

int __cdecl main(int argc, char* argv[])
{
    printf("Jen Test Program [Version 0.X]\nCopyright 2021 Proserio, LLC. All rights reserved.\n");
    if (argc > 4 || (argc == 2 && !strcmp(argv[1], "help")))
        return usage();
    char* args[4] = { 0 };
    for (int n = 0; n < argc; n++)
        args[n] = argv[n];
    if (1 == argc) {
        char cmd[256] = { 0 };
        fflush(stdin);
        fgets(cmd, sizeof cmd - 1, stdin);
        char* nexttok = cmd;
        for (int n = 1; nexttok && n < 4; n++)
            args[n] = tokstrx(nexttok, " \t", " \t\n", &nexttok);
    }
    if (args[1] && !strcmp(args[1], "test")) {
        for (int n = 2; n < 4 && args[n]; n++) {
            if (!strcmp(args[n], "all"))
                _all = true;
            else if (!strcmp(args[n], "dump"))
                _dump = true;
        }
        runTests();
    } else
        return usage();
    return 0;
}
