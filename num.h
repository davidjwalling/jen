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

    Num();
    Num(uint32_t val);
    ~Num();
    void Init();
    void Reset();

    size_t loWord();
    size_t hiWord();
    size_t bits();
    size_t bytes();
    size_t words();

    bool bit(size_t bit);
    uint8_t byte(size_t byte);
    uint32_t word(size_t word);

    void resetBit(size_t bit);
    void resetByte(size_t byte);
    void resetWord(size_t word);

    void setBit(size_t bit);
    void setByte(size_t n, uint8_t val);
    void setWord(size_t n, uint32_t val);

    uint8_t* bin(uint8_t* buf, size_t len);

    void putZero();
    void putOne();
    void putTwo();

    void putRandom(Random& rand, size_t bits);
    void putWord(uint32_t val);
    void putLong(int32_t val);
    void putBin(uint8_t* val, size_t len);
    void putHex(uint8_t* str, size_t len);

    void copy(Num& Y);
    int compareAbs(Num& Y);
    int compare(Num& Y);

    void neg();
    void mul2();
    void div2();
    void shiftLeft(size_t bits);
    void shiftRight(size_t bits);

    void incrementAbs();
    void decrementAbs();
    void addAbs(Num& Y);
    void subAbs(Num& Y);
    void mulAbs(Num& Y);
    int divAbs(Num& Y);
    void modAbs(Num& Y);

    void mul10();
    void putDecimal(uint8_t* str, size_t len);
    void putOctal(uint8_t* str, size_t len);
    void putString(uint8_t* str);

    void increment();
    void decrement();
    void add(Num& Y);
    void sub(Num& Y);
    void mul(Num& Y);
    void div(Num& Y);
    void mod(Num& Y);

    void montMul(Num& A, Num& B, Num& N, uint32_t ni);
    static uint32_t mulInvWord(uint32_t n);
    void montExp(Num& A, Num& E, Num& M);
    bool isMRPrime(size_t rounds);
    uint32_t modWord(uint32_t val);
    bool isPrime();
    bool putPrime(Random& rand, size_t bits);
    void GCD(Num& X, Num& Y);
    void mulInvGCD(Num& X, Num& Y, Num& D);
    uint8_t* BER(uint8_t* buf);

    Num& operator = (const long val);
    Num& operator = (Num& val);

    bool operator > (long val);
    bool operator > (Num& val);
    bool operator >= (Num& val);

    const int operator == (uint32_t val);
    const int operator == (Num& val);
    const int operator != (uint32_t val);
    const int operator != (Num& val);

    const void operator <<= (size_t bits);
    const void operator >>= (size_t bits);
    const void operator ++ ();
    const void operator -- ();
    const void operator += (uint32_t val);
    const void operator += (Num& val);
    const void operator -= (uint32_t val);
    const void operator -= (Num& val);
    const void operator *= (Num& val);
    const void operator /= (Num& val);
    const void operator %= (Num& val);
};
