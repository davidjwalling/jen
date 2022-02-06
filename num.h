#pragma once

#include "api.h"
#include "random.h"

namespace num {
    enum {
        bit2byte = 3,                     // bit >> 3 = byte
        bit2word = 5,                     // bit >> 5 = word
        byte2word = bit2word - bit2byte,  // byte >> 2 = word
        wordbits = 1 << bit2word,         // 1 << bit2word = 32
        wordbytes = wordbits >> bit2byte, // 32 >> 3 = 4
        hibitmask = 1 << (wordbits - 1),  // 1 << wordbits - 1 = 2^31 = 0x80000000
        wordmask = wordbits - 1,          // 2 ^ 32 - 1 = high-values
        size = 4096,                      // 2^4096 = largest int
        bits = size + wordbits,
        hibit = bits - 1,
        bytes = bits >> bit2byte,
        hibyte = bytes - 1,
        words = bits >> bit2word,
        hiword = words - 1,
        smallprimes = 564,
        maxsmallprime = 4093,
        maxsquare = 16752649,
        primerounds = 600,
        primedivs = 300,
        primesteps = 125
    };
}

class Num {
public:
    union {
        uint8_t _byte[num::bytes];
        uint32_t _word[num::words];
    };
    uint32_t _overflow;
    uint32_t _sign;
    size_t _loword;
    size_t _hiword;

    EXPORT Num();
    EXPORT Num(uint32_t val);
    EXPORT ~Num();
    EXPORT void Init();
    void Reset();

    size_t loWord();
    size_t hiWord();
    EXPORT size_t bits();
    EXPORT size_t bytes();
    EXPORT  size_t words();

    EXPORT bool bit(size_t bit);
    EXPORT uint8_t byte(size_t byte);
    EXPORT uint32_t word(size_t word);

    EXPORT void resetBit(size_t bit);
    EXPORT void resetByte(size_t byte);
    EXPORT void resetWord(size_t word);

    EXPORT void setBit(size_t bit);
    EXPORT void setByte(size_t n, uint8_t val);
    EXPORT void setWord(size_t n, uint32_t val);

    EXPORT uint8_t* bin(uint8_t* buf, size_t len);

    EXPORT void putZero();
    EXPORT void putOne();
    EXPORT void putTwo();

    EXPORT void putRandom(Random& rand, size_t bits);
    EXPORT void putWord(uint32_t val);
    EXPORT void putLong(int32_t val);
    EXPORT void putBin(uint8_t* val, size_t len);
    EXPORT void putHex(uint8_t* str, size_t len);

    EXPORT void copy(Num& Y);
    EXPORT int compareAbs(Num& Y);
    EXPORT int compare(Num& Y);

    EXPORT void neg();
    EXPORT void mul2();
    EXPORT void div2();
    EXPORT void shiftLeft(size_t bits);
    EXPORT void shiftRight(size_t bits);

    EXPORT void incrementAbs();
    EXPORT void decrementAbs();
    EXPORT void addAbs(Num& Y);
    EXPORT void subAbs(Num& Y);
    EXPORT void mulAbs(Num& Y);
    EXPORT int divAbs(Num& Y);
    EXPORT void modAbs(Num& Y);

    EXPORT void mul10();
    EXPORT void putDecimal(uint8_t* str, size_t len);
    EXPORT void putOctal(uint8_t* str, size_t len);
    EXPORT void putString(uint8_t* str);

    EXPORT void increment();
    EXPORT void decrement();
    EXPORT void add(Num& Y);
    EXPORT void sub(Num& Y);
    EXPORT void mul(Num& Y);
    EXPORT void div(Num& Y);
    EXPORT void mod(Num& Y);

    EXPORT void montMul(Num& A, Num& B, Num& N, uint32_t ni);
    EXPORT static uint32_t mulInvWord(uint32_t n);
    EXPORT void montExp(Num& A, Num& E, Num& M);
    EXPORT bool isMRPrime(size_t rounds);
    EXPORT uint32_t modWord(uint32_t val);
    EXPORT bool isPrime();
    EXPORT bool putPrime(Random& rand, size_t bits);
    EXPORT void GCD(Num& X, Num& Y);
    EXPORT void mulInvGCD(Num& X, Num& Y, Num& D);
    EXPORT uint8_t* BER(uint8_t* buf);

    EXPORT Num& operator = (const long val);
    EXPORT Num& operator = (Num& val);

    EXPORT bool operator > (long val);
    EXPORT bool operator > (Num& val);
    EXPORT bool operator >= (Num& val);

    EXPORT const int operator == (uint32_t val);
    EXPORT const int operator == (Num& val);
    EXPORT const int operator != (uint32_t val);
    EXPORT const int operator != (Num& val);

    EXPORT const void operator <<= (size_t bits);
    EXPORT const void operator >>= (size_t bits);
    EXPORT const void operator ++ ();
    EXPORT const void operator -- ();
    EXPORT const void operator += (uint32_t val);
    EXPORT const void operator += (Num& val);
    EXPORT const void operator -= (uint32_t val);
    EXPORT const void operator -= (Num& val);
    EXPORT const void operator *= (Num& val);
    EXPORT const void operator /= (Num& val);
    EXPORT const void operator %= (Num& val);
};
