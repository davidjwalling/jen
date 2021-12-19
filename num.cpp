#include "num.h"
#include "asn.h"

const size_t BYTEBITS[] = {
    0,  1,  2,  2,  3,  3,  3,  3,  4,  4,  4,  4,  4,  4,  4,  4,
    5,  5,  5,  5,  5,  5,  5,  5,  5,  5,  5,  5,  5,  5,  5,  5,
    6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,
    6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,  6,
    7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,
    7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,
    7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,
    7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,
    8,  8,  8,  8,  8,  8,  8,  8,  8,  8,  8,  8,  8,  8,  8,  8,
    8,  8,  8,  8,  8,  8,  8,  8,  8,  8,  8,  8,  8,  8,  8,  8,
    8,  8,  8,  8,  8,  8,  8,  8,  8,  8,  8,  8,  8,  8,  8,  8,
    8,  8,  8,  8,  8,  8,  8,  8,  8,  8,  8,  8,  8,  8,  8,  8,
    8,  8,  8,  8,  8,  8,  8,  8,  8,  8,  8,  8,  8,  8,  8,  8,
    8,  8,  8,  8,  8,  8,  8,  8,  8,  8,  8,  8,  8,  8,  8,  8,
    8,  8,  8,  8,  8,  8,  8,  8,  8,  8,  8,  8,  8,  8,  8,  8,
    8,  8,  8,  8,  8,  8,  8,  8,  8,  8,  8,  8,  8,  8,  8,  8
};

const uint8_t ASCHEX2BIN[] = {
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
    0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  0,  0,  0,  0,  0,  0,
    0, 10, 11, 12, 13, 14, 15,  0,  0,  0,  0,  0,  0,  0,  0,  0,
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
    0, 10, 11, 12, 13, 14, 15,  0,  0,  0,  0,  0,  0,  0,  0,  0,
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0
};

const uint32_t ASCDEC2BIN[] = {
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
    0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  0,  0,  0,  0,  0,  0,
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0
};

const uint32_t ASCOCT2BIN[] = {
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
    0,  1,  2,  3,  4,  5,  6,  7,  0,  0,  0,  0,  0,  0,  0,  0,
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0
};

const size_t LOWORDERZEROS[] = {
    8,  0,  1,  0,  2,  0,  1,  0,  3,  0,  1,  0,  2,  0,  1,  0,
    4,  0,  1,  0,  2,  0,  1,  0,  3,  0,  1,  0,  2,  0,  1,  0,
    5,  0,  1,  0,  2,  0,  1,  0,  3,  0,  1,  0,  2,  0,  1,  0,
    4,  0,  1,  0,  2,  0,  1,  0,  3,  0,  1,  0,  2,  0,  1,  0,
    6,  0,  1,  0,  2,  0,  1,  0,  3,  0,  1,  0,  2,  0,  1,  0,
    4,  0,  1,  0,  2,  0,  1,  0,  3,  0,  1,  0,  2,  0,  1,  0,
    5,  0,  1,  0,  2,  0,  1,  0,  3,  0,  1,  0,  2,  0,  1,  0,
    4,  0,  1,  0,  2,  0,  1,  0,  3,  0,  1,  0,  2,  0,  1,  0,
    7,  0,  1,  0,  2,  0,  1,  0,  3,  0,  1,  0,  2,  0,  1,  0,
    4,  0,  1,  0,  2,  0,  1,  0,  3,  0,  1,  0,  2,  0,  1,  0,
    5,  0,  1,  0,  2,  0,  1,  0,  3,  0,  1,  0,  2,  0,  1,  0,
    4,  0,  1,  0,  2,  0,  1,  0,  3,  0,  1,  0,  2,  0,  1,  0,
    6,  0,  1,  0,  2,  0,  1,  0,  3,  0,  1,  0,  2,  0,  1,  0,
    4,  0,  1,  0,  2,  0,  1,  0,  3,  0,  1,  0,  2,  0,  1,  0,
    5,  0,  1,  0,  2,  0,  1,  0,  3,  0,  1,  0,  2,  0,  1,  0,
    4,  0,  1,  0,  2,  0,  1,  0,  3,  0,  1,  0,  2,  0,  1,  0
};

const uint32_t SMALLPRIMES[] = {
       2,    3,    5,    7,   11,   13,   17,   19,   23,   29,   31,   37,
      41,   43,   47,   53,   59,   61,   67,   71,   73,   79,   83,   89,
      97,  101,  103,  107,  109,  113,  127,  131,  137,  139,  149,  151,
     157,  163,  167,  173,  179,  181,  191,  193,  197,  199,  211,  223,
     227,  229,  233,  239,  241,  251,  257,  263,  269,  271,  277,  281,
     283,  293,  307,  311,  313,  317,  331,  337,  347,  349,  353,  359,
     367,  373,  379,  383,  389,  397,  401,  409,  419,  421,  431,  433,
     439,  443,  449,  457,  461,  463,  467,  479,  487,  491,  499,  503,
     509,  521,  523,  541,  547,  557,  563,  569,  571,  577,  587,  593,
     599,  601,  607,  613,  617,  619,  631,  641,  643,  647,  653,  659,
     661,  673,  677,  683,  691,  701,  709,  719,  727,  733,  739,  743,
     751,  757,  761,  769,  773,  787,  797,  809,  811,  821,  823,  827,
     829,  839,  853,  857,  859,  863,  877,  881,  883,  887,  907,  911,
     919,  929,  937,  941,  947,  953,  967,  971,  977,  983,  991,  997,
    1009, 1013, 1019, 1021, 1031, 1033, 1039, 1049, 1051, 1061, 1063, 1069,
    1087, 1091, 1093, 1097, 1103, 1109, 1117, 1123, 1129, 1151, 1153, 1163,
    1171, 1181, 1187, 1193, 1201, 1213, 1217, 1223, 1229, 1231, 1237, 1249,
    1259, 1277, 1279, 1283, 1289, 1291, 1297, 1301, 1303, 1307, 1319, 1321,
    1327, 1361, 1367, 1373, 1381, 1399, 1409, 1423, 1427, 1429, 1433, 1439,
    1447, 1451, 1453, 1459, 1471, 1481, 1483, 1487, 1489, 1493, 1499, 1511,
    1523, 1531, 1543, 1549, 1553, 1559, 1567, 1571, 1579, 1583, 1597, 1601,
    1607, 1609, 1613, 1619, 1621, 1627, 1637, 1657, 1663, 1667, 1669, 1693,
    1697, 1699, 1709, 1721, 1723, 1733, 1741, 1747, 1753, 1759, 1777, 1783,
    1787, 1789, 1801, 1811, 1823, 1831, 1847, 1861, 1867, 1871, 1873, 1877,
    1879, 1889, 1901, 1907, 1913, 1931, 1933, 1949, 1951, 1973, 1979, 1987,
    1993, 1997, 1999, 2003, 2011, 2017, 2027, 2029, 2039, 2053, 2063, 2069,
    2081, 2083, 2087, 2089, 2099, 2111, 2113, 2129, 2131, 2137, 2141, 2143,
    2153, 2161, 2179, 2203, 2207, 2213, 2221, 2237, 2239, 2243, 2251, 2267,
    2269, 2273, 2281, 2287, 2293, 2297, 2309, 2311, 2333, 2339, 2341, 2347,
    2351, 2357, 2371, 2377, 2381, 2383, 2389, 2393, 2399, 2411, 2417, 2423,
    2437, 2441, 2447, 2459, 2467, 2473, 2477, 2503, 2521, 2531, 2539, 2543,
    2549, 2551, 2557, 2579, 2591, 2593, 2609, 2617, 2621, 2633, 2647, 2657,
    2659, 2663, 2671, 2677, 2683, 2687, 2689, 2693, 2699, 2707, 2711, 2713,
    2719, 2729, 2731, 2741, 2749, 2753, 2767, 2777, 2789, 2791, 2797, 2801,
    2803, 2819, 2833, 2837, 2843, 2851, 2857, 2861, 2879, 2887, 2897, 2903,
    2909, 2917, 2927, 2939, 2953, 2957, 2963, 2969, 2971, 2999, 3001, 3011,
    3019, 3023, 3037, 3041, 3049, 3061, 3067, 3079, 3083, 3089, 3109, 3119,
    3121, 3137, 3163, 3167, 3169, 3181, 3187, 3191, 3203, 3209, 3217, 3221,
    3229, 3251, 3253, 3257, 3259, 3271, 3299, 3301, 3307, 3313, 3319, 3323,
    3329, 3331, 3343, 3347, 3359, 3361, 3371, 3373, 3389, 3391, 3407, 3413,
    3433, 3449, 3457, 3461, 3463, 3467, 3469, 3491, 3499, 3511, 3517, 3527,
    3529, 3533, 3539, 3541, 3547, 3557, 3559, 3571, 3581, 3583, 3593, 3607,
    3613, 3617, 3623, 3631, 3637, 3643, 3659, 3671, 3673, 3677, 3691, 3697,
    3701, 3709, 3719, 3727, 3733, 3739, 3761, 3767, 3769, 3779, 3793, 3797,
    3803, 3821, 3823, 3833, 3847, 3851, 3853, 3863, 3877, 3881, 3889, 3907,
    3911, 3917, 3919, 3923, 3929, 3931, 3943, 3947, 3967, 3989, 4001, 4003,
    4007, 4013, 4019, 4021, 4027, 4049, 4051, 4057, 4073, 4079, 4091, 4093,
    0
};

Num::Num()
{ 
    Init();
}

Num::Num(uint32_t val)
{ 
    putWord(val); 
}

Num::~Num()
{ 
    Reset(); 
}

void Num::Init()
{
    memset(_byte, 0, sizeof(_byte));
    _overflow = _sign = 0;
    _loword = _hiword = 0;
}

void Num::Reset()
{
    Init();
}

size_t Num::loWord()
{
    uint32_t* q = &_word[0];
    uint32_t* r = &_word[num::hiword];
    uint32_t* p = q;
    while ((p <= r) && !(*p)) { p++; }
    _loword = (p <= r ? (p - q) : 0);
    return _loword;
}

size_t Num::hiWord()
{
    uint32_t* q = &_word[num::hiword];
    uint32_t* r = &_word[0];
    uint32_t* p = q;
    while ((p > r) && !(*p)) { p--; }
    _hiword = (p - r);
    return _hiword;
}

size_t Num::bits()
{
    size_t bits = _hiword << num::bit2word;
    uint32_t hiword = _word[_hiword];
    if (0xff000000 & hiword)
        bits += (size_t)24 + BYTEBITS[hiword >> 24];
    else if (0x00ff0000 & hiword)
        bits += (size_t)16 + BYTEBITS[hiword >> 16];
    else if (0x0000ff00 & hiword)
        bits += (size_t)8 + BYTEBITS[hiword >> 8];
    else
        bits += BYTEBITS[hiword];
    return bits ? bits : 1;
}

size_t Num::bytes()
{
    size_t bytes = _hiword << num::byte2word;
    uint32_t hiword = _word[_hiword];
    if (0xff000000 & hiword)
        bytes += 4;
    else if (0x00ff0000 & hiword)
        bytes += 3;
    else if (0x0000ff00 & hiword)
        bytes += 2;
    else
        bytes += 1;
    return bytes ? bytes : 1;
}

size_t Num::words() { return _hiword + 1; }

bool Num::bit(size_t bit)
{
    return (bit < num::bits ? (_word[bit >> num::bit2word] & ((uint32_t)1 << (bit & (num::wordmask))) ? 1 : 0) : 0);
}

uint8_t Num::byte(size_t n)
{
    return (n < num::bytes ? _byte[n] : 0);
}

uint32_t Num::word(size_t n)
{
    return (n < num::words ? _word[n] : 0);
}

void Num::resetBit(size_t n)
{
    if (n < num::bits)
        _word[n >> num::bit2word] &= ~((uint32_t)1 << (n & num::wordmask));
}

void Num::resetByte(size_t n)
{
    if (n < num::bytes)
        _byte[n] = 0;
}

void Num::resetWord(size_t n)
{
    if (n < num::words)
        _word[n] = 0;
}

void Num::setBit(size_t n)
{
    if (n < num::bits)
        _word[n >> num::bit2word] |= ((uint32_t)1 << (n & num::wordmask));
}

void Num::setByte(size_t n, uint8_t val)
{
    if (n < num::bytes)
        _byte[n] = val;
}

void Num::setWord(size_t n, uint32_t val)
{
    if (n < num::words)
        _word[n] = val;
}

uint8_t* Num::bin(uint8_t* buf, size_t len)
{
    size_t b;
    uint8_t* p, * q, * r;
    for (q = buf, b = bytes(); len > b; *q++ = 0x00, len--);
    r = &_byte[0];
    p = &_byte[len];
    while (p > r) *q++ = *--p;
    return q;
}

void Num::putZero()
{
    Init();
}

void Num::putOne()
{
    Init();
    _byte[0] = 1;
}

void Num::putTwo()
{
    Init();
    _byte[0] = 2;
}

void Num::putRandom(Random& rand, size_t bits)
{
    uint32_t mod, random, * p, * q, * r;
    putZero();
    if (bits) {
        _hiword = (bits - 1) >> num::bit2word;
        mod = bits & num::wordbits - 1;
        random = rand.Rand();
        if (mod)
            random &= ~((uint32_t)-1 << mod);
        p = q = &_word[0];
        r = &_word[_hiword];
        while (q < r) *q++ = rand.Rand();
        if (random)
            *q = random;
        loWord();
    }
}

void Num::putWord(uint32_t val)
{
    Init();
    _word[0] = val;
}

void Num::putLong(int32_t val)
{
    Init();
    if (val & num::hibitmask) {
        val = ~(val & ~num::hibitmask);
        val = (val & ~num::hibitmask) + 1;
        _word[0] = val;
        _sign = (uint32_t)-1;
    } else {
        _word[0] = (uint32_t)val;
    }
}

void Num::putBin(uint8_t* val, size_t len)
{
    uint8_t* p, * q, * r;
    memset(&_byte[0], 0, sizeof(_byte));
    for (p = val; len > num::bytes; p++, len--);
    for (; (len) && !(*p); p++, len--);
    r = &_byte[0];
    q = &_byte[len];
    for (; (q > r); *--q = *p++);
    _overflow = _sign = 0;
    _hiword = ((len - 1) >> num::byte2word);
    loWord();
}

void Num::putHex(uint8_t* str, size_t len)
{
    size_t n, b;
    uint8_t val;
    putZero();
    n = (len >> 1) + (len & 1);
    b = (n - 1);
    if (len & 1) {
        val = ASCHEX2BIN[*str++];
        setByte(b--, val);
    }
    while (b < num::bytes) {
        val = ASCHEX2BIN[*str++] << 4;
        val += ASCHEX2BIN[*str++];
        setByte(b--, val);
    }
    _hiword = ((n - 1) >> num::byte2word);
    loWord();
}

void Num::copy(Num& val)
{
    memcpy(&_byte[0], &val._byte[0], sizeof(_byte));
    _overflow = val._overflow;
    _sign = val._sign;
    _loword = val._loword;
    _hiword = val._hiword;
}

int Num::compareAbs(Num& Y)
{
    size_t h;
    uint32_t* x, * y;
    if (_hiword > Y._hiword)
        return 1;
    if (_hiword < Y._hiword)
        return -1;
    if (_loword > Y._loword)
        h = _hiword - Y._loword;
    else
        h = _hiword - _loword;
    x = &_word[_hiword];
    y = &Y._word[_hiword];
    for (h++; h; x--, y--, h--) {
        if (*x > * y)
            return 1;
        if (*x < *y)
            return -1;
    }
    return 0;
}

int Num::compare(Num& Y)
{
    if (!_sign) {
        if (!Y._sign)
            return compareAbs(Y);
        else
            return 1;
    } else {
        if (Y._sign)
            return Y.compareAbs(*this);
        else
            return -1;
    }
}

void Num::neg() { _sign = ~(_sign); }

void Num::mul2()
{
    size_t w;
    uint32_t u, v, * q, * r;
    if ((!_hiword) && (!_word[0]))
        return;
    q = &_word[_loword];
    r = &_word[_hiword];
    for (v = 0; q <= r; v = (u & 0x80000000) ? 1 : 0) {
        u = *q;
        *q++ = (u << 1) | v;
    }
    if (v) {
        *q = v;
        _hiword++;
        if (_overflow) {
            _overflow = 0;
            q = &_word[num::hiword];
            for (w = num::words; (w) && (0 == *q); w--) {
                q--;
            }
            _hiword = w ? w - 1 : 0;
        }
    }
    if (!_word[_loword]) {
        if (_loword == num::hiword)
            _loword = 0;
        else
            _loword++;
    }
}

void Num::div2()
{
    uint32_t u, v, * q, * r;
    if ((!_hiword) && (!_word[0]))
        return;
    q = &_word[_hiword];
    r = &_word[_loword];
    for (v = 0; q >= r; v = (u & 1) ? 0x80000000 : 0) {
        u = *q;
        *q-- = (u >> 1) | v;
    }
    if (_hiword && !_word[_hiword])
        _hiword--;
    if ((v) && (_loword)) {
        *q = v;
        _loword--;
    }
}

void Num::shiftLeft(size_t bits)
{
    size_t i, m, p, q, u, d;
    uint32_t l;
    if (!bits)
        return;
    if (1 == bits) {
        mul2();
        return;
    }
    if ((!_hiword) && (!_word[0]))
        return;
    i = bits >> num::bit2word;
    if (_loword + i > (num::hiword)) {
        Init();
        return;
    }
    u = bits & (num::wordbits - 1);
    d = u ? num::wordbits - u : 0;
    if (_hiword + i > (num::hiword)) {
        q = num::hiword;
        p = q - i;
        m = (p - _loword) + 1;
        l = _word[p];
        _hiword = num::hiword;
    } else {
        q = _hiword + i;
        p = _hiword;
        m = (_hiword - _loword) + 1;
        l = _word[p];
        if ((l && d) && (l >> d))
            _hiword++;
        _hiword += i;
    }
    _loword += i;
    while (m) {
        l = _word[p--];
        if (l && u) {
            _word[q + 1] |= (l >> d);
            l <<= u;
        }
        _word[q--] = l;
        m--;
    }
    for (; i; i--) {
        _word[q--] = 0;
    };
    if (_overflow) {
        _overflow = 0;
        for (_hiword = num::hiword; _hiword && !_word[_hiword]; _hiword--);
    }
    if (_loword > _hiword)
        _loword = _hiword;
    for (; _loword <= _hiword && !_word[_loword]; _loword++); // 2020.08.13
    if (_loword > _hiword)
        _loword = _hiword = 0;
}

void Num::shiftRight(size_t bits)
{
    size_t i, m, p, q, u, d;
    uint32_t l;
    if (!bits)
        return;
    if (1 == bits) {
        div2();
        return;
    }
    if ((!_hiword) && (!_word[0]))
        return;
    i = bits >> num::bit2word;
    if (i > _hiword) {
        Init();
        return;
    }
    _overflow = 0;
    d = bits & (num::wordbits - 1);
    u = d ? num::wordbits - d : 0;
    if (i > _loword) {
        q = 0;
        p = i;
        m = (_hiword + 1) - i;
        _loword = 0;
    } else {
        q = _loword - i;
        p = _loword;
        m = (_hiword + 1) - _loword;
        _loword -= i;
    }
    l = _word[_hiword];
    if ((l && d) && !(l >> d))
        _hiword--;
    _hiword -= i;
    while (m) {
        l = _word[p++];
        if (l && d) {
            if (q)
                _word[q - 1] |= (l << u);
            l >>= d;
        }
        _word[q++] = l;
        m--;
    }
    for (; i; i--) {
        _word[q++] = 0;
    }
    for (; _loword && _word[_loword - 1]; _loword--);
    if (_loword > _hiword)
        _loword = _hiword = 0;
}

void Num::incrementAbs()
{
    size_t w;
    uint32_t* p, * q, c, t;
    _overflow = 0;
    c = 1;
    q = p = &_word[0];
    do {
        t = *q + c;
        if (t > * q)
            c = 0;
        *q++ = t;
    } while (c);
    if (_overflow) {
        _overflow = _sign = 0;
        _loword = _hiword = 0;
    } else {
        w = (q - p) - 1;
        _loword = w;
        if (w > _hiword)
            _hiword = w;
    }
}

void Num::decrementAbs()
{
    uint32_t* p, * q, t, c;
    if (!(_hiword | _word[0])) {
        _word[0] = 1;
        _sign = (uint32_t)-1;
        return;
    }
    c = (uint32_t)-1;
    q = p = &_word[0];
    do {
        t = *q + c;
        if (t < *q)
            c = 0;
        *q++ = t;
    } while (c);
    _overflow = 0;
    if ((!t) && (_hiword) && (!_word[_hiword]))
        _hiword--;
    for (_loword = 0; (!_word[_loword]) && (_loword < _hiword);) {
        _loword++;
    }
    if ((_sign) && (!_loword) && (!_word[0]))
        _sign = 0;
}

void Num::addAbs(Num& val)
{
    uint32_t c, t;
    uint32_t* x, * y, * h, * l;
    h = &val._word[val._hiword];
    if (_loword > val._loword) {
        l = &val._word[_loword];
        y = &val._word[val._loword];
        x = &_word[val._loword];
        for (; y < l;) {
            *x++ = *y++;
        }
        _loword = val._loword;
    } else {
        x = &_word[val._loword];
        y = &val._word[val._loword];
    }
    _overflow = val._overflow = c = 0;
    do {
        t = *x + c;
        if (t >= *x)
            c = 0;
        t += *y;
        if (t < *y)
            c = 1;
        *x++ = t;
    } while ((++y <= h) || (c));
    l = &_word[0];
    if (_overflow) {
        _overflow = 0;
        for (x = &_word[num::hiword]; !(*x) && (x > l);) {
            x--;
        }
        _hiword = (x - l);
    } else if (_word[_hiword + 1])
        _hiword++;
    h = &_word[_hiword];
    if (_loword > _hiword)
        _loword = _hiword;
    for (x = &_word[_loword]; !(*x) && (x < h);) {
        x++;
    }
    _loword = (x - l);
}

void Num::subAbs(Num& val)
{
    uint32_t c, a, b, * x, * y, * h, * l;
    x = &_word[val._loword];
    y = &val._word[val._loword];
    h = &val._word[val._hiword];
    _overflow = val._overflow = c = 0;
    do {
        b = *y + c;
        if (b >= *y)
            c = 0;
        a = *x - b;
        if (a > * x)
            c = 1;
        *x++ = a;
    } while ((++y <= h) || (c));
    l = &_word[0];
    for (x = &_word[_hiword]; !(*x) && (x > l);) {
        x--;
    }
    _hiword = (x - l);
    h = x;
    if (_loword > _hiword)
        _loword = _hiword;
    for (x = &_word[_loword]; !(*x) && (x < h); x++)
        ;
    _loword = (x - l);
}

void Num::mulAbs(Num& Y)
{
    size_t pow;
    uint32_t i, j, a, b, c, t, v, * w;
    uint64_t uv;
    Num T;
    if ((!_hiword) && (!_word[0]))
        return;
    if (!Y._hiword) {
        if (2 == Y._word[0]) {
            mul2();
            return;
        }
    }
    pow = 0;
    if (_loword) {
        shiftRight(_loword << num::bit2word);
        pow += _loword;
    }
    if (Y._loword) {
        Y.shiftRight(Y._loword << num::bit2word);
        pow += Y._loword;
    }
    for (i = j = 0; i <= Y._hiword; i++) {
        b = Y._word[i];
        c = 0;
        for (j = 0; j <= _hiword; j++) {
            a = _word[j];
            t = T._word[i + j];
            uv = (uint64_t)a * b + c + t;
            c = (uint32_t)(uv >> num::wordbits);
            v = (uint32_t)(uv);
            T._word[i + j] = v;
        }
        T._word[i + j] = c;
    }
    t = i + j;
    if (t > num::words)
        t = num::words;
    w = &T._word[t - 1];
    for (; (t) && (0 == *w); w--, t--)
        ;
    T._hiword = t ? t - 1 : 0;
    copy(T);
    if (pow)
        shiftLeft(pow << num::bit2word);
}

int Num::divAbs(Num& Y)
{
    size_t pow, c, k;
    Num T;
    if (!Y._hiword && !Y.word(0))
        return -1;
    if (-1 == compare(Y)) {
        putZero();
        return 0;
    }
    pow = 0;
    if (_loword && Y._loword) {
        pow = _loword > Y._loword ? Y._loword : _loword;
        shiftRight(pow << num::bit2word);
        Y.shiftRight(pow << num::bit2word);
    }
    c = bits() - Y.bits();
    if (c) {
        Y.shiftLeft(c);
        if (-1 == compare(Y)) {
            Y.div2();
            c--;
        }
    }
    T._hiword = (c >> num::bit2word);
    for (;;) {
        subAbs(Y);
        T.setBit(c);
        if (!c)
            break;
        k = Y.bits() - bits();
        if (k) {
            if (k > c)
                k = c;
            Y.shiftRight(k);
            c -= k;
            if (-1 == compare(Y)) {
                if (!c)
                    break;
                Y.div2();
                c--;
            }
        } else if (-1 == compare(Y)) {
            Y.div2();
            c--;
        }
    }
    copy(T);
    return 0;
}

void Num::modAbs(Num& Y)
{
    size_t pow, vbits, cbits, tbits, ybits, i, j, w;
    uint32_t n;
    Num T;
    if ((!_hiword) && (!_word[0]))
        return;
    pow = 0;
    i = _loword << num::bit2word;
    n = _word[_loword];
    if (0x000000ff & n)
        i += LOWORDERZEROS[n & 0xff];
    else if (0x0000ff00 & n)
        i += LOWORDERZEROS[(n >> 8) & 0xff];
    else if (0x00ff0000 & n)
        i += LOWORDERZEROS[(n >> 16) & 0xff];
    else if (0xff000000 & n)
        i += LOWORDERZEROS[(n >> 24) & 0xff];
    if (i) {
        j = (Y._loword << num::bit2word);
        n = Y._word[Y._loword];
        if (0x000000ff & n)
            j += LOWORDERZEROS[n & 0xff];
        else if (0x0000ff00 & n)
            j += LOWORDERZEROS[(n >> 8) & 0xff];
        else if (0x00ff0000 & n)
            j += LOWORDERZEROS[(n >> 16) & 0xff];
        else if (0xff000000 & n)
            j += LOWORDERZEROS[(n >> 24) & 0xff];
        pow = j ? i > j ? j : i : 0;
        if (pow) {
            shiftRight(pow);
            Y.shiftRight(pow);
        }
    }
    T.copy(*this);
    cbits = 0;
    tbits = T.bits();
    ybits = Y.bits();
    cbits = 0; // ?
    w = tbits - ybits;
    if (w > 2) {
        w--;
        Y.shiftLeft(w);
        ybits += w;
        cbits = w;
    }
L10:
    w = tbits - ybits;
    if (w < 2) {
        T.subAbs(Y);
    } else {
        T.subAbs(Y);
        T.subAbs(Y);
    }
    tbits = T.bits();
L20:
    if (T.compareAbs(Y) >= 0)
        goto L10;
    if (!cbits) {
        copy(T);
        if (pow)
            shiftLeft(pow);
        return;
    }
    vbits = (ybits - tbits) + 2;
    if (vbits > cbits) {
        vbits = cbits;
        Y.shiftRight(vbits);
        ybits -= vbits;
        cbits = 0;
        goto L20;
    } else {
        Y.shiftRight(vbits);
        ybits -= vbits;
        cbits -= vbits;
        goto L10;
    }
}

void Num::mul10()
{
    mul2();
    Num T(*this);
    mul2();
    mul2();
    addAbs(T);
}

void Num::putDecimal(uint8_t* str, size_t len)
{
    Num T;
    putZero();
    for (; len; len--) {
        mul10();
        T.putWord(ASCDEC2BIN[*str++]);
        addAbs(T);
    }
}

void Num::putOctal(uint8_t* cStr, size_t len)
{
    Num T;
    putZero();
    for (; len; len--) {
        shiftLeft(3);
        T.putWord(ASCOCT2BIN[*cStr++]);
        addAbs(T);
    }
}

void Num::putString(uint8_t* str)
{
    size_t len = strlen((const char*)str);
    if ('0' == str[0])
        if (('X' == str[1]) || ('x' == str[1]))
            if (len > 2)
                putHex(str + 2, len - 2);
            else
                putZero();
        else
            putOctal(str + 1, len - 1);
    else
        putDecimal(str, len);
}

void Num::increment()
{
    if (_sign)
        decrementAbs();
    else
        incrementAbs();
}

void Num::decrement()
{
    if (_sign)
        incrementAbs();
    else
        decrementAbs();
}

void Num::add(Num& Y)
{
    Num T;
    if ((!_sign && !Y._sign) || (_sign && Y._sign)) {
        if (_hiword >= Y._hiword) {
            addAbs(Y);
        } else {
            T.copy(Y);
            T.addAbs(*this);
            copy(T);
        }
    } else {
        if (compareAbs(Y) >= 0) {
            subAbs(Y);
        } else {
            T.copy(Y);
            T.subAbs(*this);
            copy(T);
        }
    }
}

void Num::sub(Num& Y)
{
    Num T;
    if (!_sign) {
        if (!Y._sign) {
            if (compareAbs(Y) >= 0) {
                subAbs(Y);
            } else {
                T.copy(Y);
                T.subAbs(*this);
                copy(T);
                neg();
            }
        } else {
            if (compareAbs(Y) >= 0) {
                addAbs(Y);
            } else {
                T.copy(Y);
                T.addAbs(*this);
                copy(T);
                neg();
            }
        }
    } else {
        if (Y._sign) {
            if (compareAbs(Y) >= 0) {
                subAbs(Y);
            } else {
                T.copy(Y);
                T.subAbs(*this);
                copy(T);
                neg();
            }
        } else {
            if (compareAbs(Y) >= 0) {
                addAbs(Y);
            } else {
                T.copy(Y);
                T.addAbs(*this);
                copy(T);
                neg();
            }
        }
    }
}

void Num::mul(Num& Y)
{
    if (((!_sign) && (!Y._sign)) || ((_sign) && (Y._sign))) {
        mulAbs(Y);
    } else {
        mulAbs(Y);
        neg();
    }
}

void Num::div(Num& Y)
{
    if ((!_sign && !Y._sign) || (_sign && Y._sign))
        divAbs(Y);
    else {
        divAbs(Y);
        neg();
    }
}

void Num::mod(Num& Y)
{
    int c;
    c = compareAbs(Y);
    if (c > 0) {
        modAbs(Y);
    } else if (!c) {
        putZero();
    }
}

//------------------------------------------------------------------------------
//
//      Compute a Montgomery modular multiplication of A and B modulo N.
//      The word ni is the precomputed negative multiplicative inverse of N[0].
//
//------------------------------------------------------------------------------

void Num::montMul(Num& A, Num& B, Num& N, uint32_t ni)
{
    size_t s, j, i;
    uint32_t* q, d, m, u;
    uint64_t uv;
    Num T;
    s = A.words();
    if (s < B.words())
        s = B.words();
    for (i = 0; i < s; i++) {
        u = 0;
        d = B._word[i];
        for (j = 0; j < s; j++) {
            uv = ((uint64_t)A._word[j] * d) + T._word[j] + u;
            u = (uint32_t)(uv >> num::wordbits);
            T._word[j] = (uint32_t)(uv);
        }
        uv = (uint64_t)T._word[s] + u;
        T._word[s] = (uint32_t)(uv);
        T._word[s + 1] = (uint32_t)(uv >> num::wordbits);
        m = T._word[0] * ni;
        uv = ((uint64_t)N._word[0] * m) + T._word[0];
        u = (uint32_t)(uv >> num::wordbits);
        for (j = 1; j < s; j++) {
            uv = ((uint64_t)N._word[j] * m) + T._word[j] + u;
            u = (uint32_t)(uv >> num::wordbits);
            T._word[j - 1] = (uint32_t)(uv);
        }
        uv = (uint64_t)T._word[s] + u;
        u = (uint32_t)(uv >> num::wordbits);
        T._word[s - 1] = (uint32_t)(uv);
        uv = (uint64_t)T._word[s + 1] + u;
        T._word[s] = (uint32_t)(uv);
    }
    for (i = (s + 1), q = &T._word[i - 1]; (i) && !(*q); q--, i--)
        ;
    T._hiword = (i - 1);
    for (i = 0, q = &T._word[0]; (i < num::words) && !(*q); q++, i++)
        ;
    T._loword = (i < num::words) ? i : 0;
    if (T.compare(N) > 0)
        T.subAbs(N);
    copy(T);
}

//------------------------------------------------------------------------------
//
//      Compute the multiplicative inverse of word n mod word bits. Used to
//      accelerate Montgomery exponentiation.
//
//------------------------------------------------------------------------------

uint32_t Num::mulInvWord(uint32_t n)
{
    uint32_t r, a, t, i;
    r = a = n;
    t = 1;
    for (i = 2; i; i <<= 1) {
        r <<= 1;
        if (a & i) {
            t |= i;
            a += r;
        }
    }
    return t;
}

//------------------------------------------------------------------------------
//
//      Compute a Montgomery modular exponentiation of A to E modulo M.
//
//------------------------------------------------------------------------------

void Num::montExp(Num& A, Num& E, Num& M)
{
    size_t i, w;
    uint32_t mi;
    Num T, U, Z(1);
    mi = mulInvWord(M._word[0]) * -1;
    w = M.words();
    T.Init();
    T._word[w] = 1;
    T._hiword = w;
    T.modAbs(M);
    if (A > M) {
        U.Init();
        U._word[w] = 1;
        U._hiword = w;
        U.mulAbs(A);
        U.modAbs(M);
    } else {
        w <<= 1;
        U.Init();
        U._word[w] = 1;
        U._hiword = w;
        U.modAbs(M);
        U.montMul(A, U, M, mi);
    }
    for (i = E.bits(); i; i--) {
        T.montMul(T, T, M, mi);
        if (E.bit(i - 1))
            T.montMul(T, U, M, mi);
    }
    montMul(T, Z, M, mi);
}

//------------------------------------------------------------------------------
//
//      Perform a Miller-Rabin primality probability test for the given number
//      of rounds.
//
//------------------------------------------------------------------------------

bool Num::isMRPrime(size_t rounds)
{
    int k;
    size_t s, i, j;
    uint32_t* p, * q, u;
    Random rand;
    Num W, R, A, Y, two(2);
    if (!bit(0))
        return false;
    if ((1 == words()) && (1 == _word[0]))
        return false;
    W.copy(*this);
    W.resetBit(0);
    R.copy(W);
    p = &R._word[R._hiword];
    q = &R._word[0];
    s = 0;
    while ((q <= p) && !(*q)) {
        s += num::wordbits;
        q++;
    }
    u = *q;
    if (0x000000ff & u)
        s += LOWORDERZEROS[(u) & 0xff];
    else if (0x0000ff00 & u)
        s += ((size_t)8 + LOWORDERZEROS[(u >> 8) & 0xff]);
    else if (0x00ff0000 & u)
        s += ((size_t)16 + LOWORDERZEROS[(u >> 16) & 0xff]);
    else if (0xff000000 & u)
        s += ((size_t)24 + LOWORDERZEROS[(u >> 24) & 0xff]);
    if (s)
        R.shiftRight(s);
    for (i = W.bits() - 1; rounds; rounds--) {
        A.putRandom(rand, i);
        Y.montExp(A, R, *this);
        if ((1 == Y.words()) && (1 == Y._word[0]))
            continue;
        k = Y.compare(W);
        if (!k)
            continue;
        for (j = s - 1; j; j--) {
            Y.montExp(Y, two, *this);
            if ((1 == Y.words()) && (1 == Y._word[0]))
                return false;
            k = Y.compare(W);
            if (!k)
                break;
        }
        if (k)
            return false;
    }
    return true;
}

//------------------------------------------------------------------------------
//
//      Compute the modulus of the division by the given word val.
//
//------------------------------------------------------------------------------

uint32_t Num::modWord(uint32_t val)
{
    uint64_t uv = 0;
    size_t i = words();
    uint32_t* p = &_word[_hiword];
    for (; i; i--) {
        uv |= *p--;
        uv = (uv % val) << 32;
    }
    return (uint32_t)(uv >> 32);
}

//------------------------------------------------------------------------------
//
//      Perform a probabalistic primality test.
//
//------------------------------------------------------------------------------

bool Num::isPrime()
{
    size_t i, e, b, bitc;
    uint32_t loword;
    uint64_t nn, zz;
    loword = _word[0];
    if (1 == words()) {
        if (1 == loword)
            return false;
        if (2 == loword)
            return true;
        if (!(1 & loword))
            return false;
    }
    bitc = bits();
    if (bitc > 32) {
        for (i = 1; i < num::primedivs; i++) {
            if (!modWord(SMALLPRIMES[i]))
                return false;
        }
        if (bitc >= 1024)
            i = 2;
        else if (bitc >= 512)
            i = 3;
        else if (bitc >= 256)
            i = 13;
        else if (bitc >= 128)
            i = 15;
        else if (bitc >= 64)
            i = 19;
        else
            i = 23;
        if (!isMRPrime(i))
            return false;
        return true;
    }
    if (loword > num::maxsquare) {
        nn = 3;
        zz = 1;
        for (e = loword - 1, b = 1; b && b <= e; b <<= 1) {
            if (b & e)
                zz = (zz * nn) % loword;
            nn = (nn * nn) % loword;
        }
        if (1 == zz)
            return true;
        return false;
    }
    if (loword > num::maxsmallprime) {
        for (i = 0; i < num::smallprimes; i++) {
            if (!(loword % SMALLPRIMES[i]))
                return false;
        }
        return true;
    }
    for (i = 0; i < num::smallprimes; i++) {
        if (loword == SMALLPRIMES[i])
            return true;
    }
    return false;
}

//------------------------------------------------------------------------------
//
//      Set the value to a probable prime if the given size.
//
//------------------------------------------------------------------------------

bool Num::putPrime(Random& rand, size_t pbits)
{
    size_t n, p;
    Num two(2);
    for (n = num::primerounds; n; n--) {
        putRandom(rand, pbits);
        setBit(0);
        setBit(pbits - 1);
        _hiword = ((pbits - 1) >> num::bit2word);
        for (p = num::primesteps; p; p--) {
            if (isPrime())
                break;
            addAbs(two);
            if (bits() > pbits)
                resetBit(pbits - 1);
        }
        if (p)
            break;
    }
    if (n)
        return true;
    return false;
}

//------------------------------------------------------------------------------
//
//      A simplified Euclidean algorithm to compute the greatest common divisor
//      without computing the multipicative inverse.
//
//------------------------------------------------------------------------------

void Num::GCD(Num& X, Num& Y)
{
    Num U, V;

    //  Return zero if either X or Y is not positive.
    if (X._sign || Y._sign || (!X._hiword && !X._word[0]) || (!Y._hiword && !Y._word[0])) {
        putZero();
        return;
    }

    //  Let U be the greater of X and Y.
    if (Y > X) {
        U = Y;
        V = X;
    } else {
        U = X;
        V = Y;
    }

    //  Initialize GCD to one.
    putOne();

    //  Raise GCD to the common power of two of U and V.
    while (!(U._word[0] & 1) && !(V._word[0] & 1)) {
        mul2();
        U.div2();
        V.div2();
    }

    //  Continue until dividend is zero.
    do {
        //  Reduce U anv V to next significant bit.
        while (!(U._word[0] & 1)) U.div2();
        while (!(V._word[0] & 1)) V.div2();

        //  Subtract divisor to clear bit zero and reduce.
        if (U.compareAbs(V) >= 0) {
            U.subAbs(V);
            U.div2();
        } else {
            V.subAbs(U);
            V.div2();
        }
    } while ((U._hiword) || (U._word[0]));

    //  GCD is highest common power of two times remaining divisor.
    mul(V);
}

//------------------------------------------------------------------------------
//
//      Compute the greatest common divisor of positive integers P and Q.
//      If the GCD is zero, then D is the multiplicative inverse Z such that
//      QZ ~= 1 mod P.
//
//------------------------------------------------------------------------------

void Num::mulInvGCD(Num& P, Num& Q, Num& D)
{
    Num X, Y, U, V, A, B, C;

    //  Return zero if with er P or Q are not positive.
    if (P._sign || Q._sign || (!P._hiword && !P._word[0]) || (!Q._hiword && !Q._word[0])) {
        D.putZero();
        putZero();
        return;
    }
    X = P;
    Y = Q;
    while (!(X._word[0] & 1) && !(Y._word[0] & 1)) {
        mul2();
        X.div2();
        Y.div2();
    }
    U = X;
    V = Y;
    putOne();
    A.putOne();
    B.putZero();
    C.putZero();
    D.putOne();
    do {
        while (!(U._word[0] & 1)) {
            U.div2();
            if (!(A._word[0] & 1) && !(B._word[0] & 1)) {
                A.div2();
                B.div2();
            } else {
                A.add(Y);
                A.div2();
                B.sub(X);
                B.div2();
            }
        }
        while (!(V._word[0] & 1)) {
            V.div2();
            if (!(C._word[0] & 1) && !(D._word[0] & 1)) {
                C.div2();
                D.div2();
            } else {
                C.add(Y);
                C.div2();
                D.sub(X);
                D.div2();
            }
        }
        if (U.compare(V) >= 0) {
            U.sub(V);
            A.sub(C);
            B.sub(D);
        } else {
            V.sub(U);
            C.sub(A);
            D.sub(B);
        }
    } while (U._hiword || U._word[0]);
    mul(V);
    if (D._sign)
        D.add(P);
}

uint8_t* Num::BER(uint8_t* buf)
{
    Num T;
    T.copy(*this);
    size_t words = T.words();
    size_t bytes = T.bytes();
    uint32_t sign = T._sign;
    if (sign) {
        for (uint32_t j = 0; j < words; j++)
            T._word[j] = ~T._word[j];
        ++T;
    }
    uint8_t* q = buf;
    uint8_t* p = &T._byte[bytes - 1]; // msb
    uint8_t* r = &T._byte[0]; // lsb
    *q++ = asn::integer;
    if (!sign) {
        if (8 == BYTEBITS[*p]) {
            q = asnPutLength(q, bytes + 1);
            *q++ = 0;
        } else
            q = asnPutLength(q, bytes);
    } else if (8 == BYTEBITS[*p])
        q = asnPutLength(q, bytes);
    else {
        q = asnPutLength(q, bytes + 1);
        *q++ = 255;
    }
    while (p >= r)
        *q++ = *p--;
    return q;
}

Num& Num::operator = (const long val)
{
    putLong(val);
    return *this;
}

Num& Num::operator = (Num& val)
{
    copy(val);
    return *this;
}

bool Num::operator > (long val)
{
    Num Y(val);
    return 1 == compare(Y) ? true : false;
}

bool Num::operator > (Num& val) { return 1 == compare(val) ? true : false; }

bool Num::operator >= (Num& val) { return -1 != compare(val) ? true : false; }

const int Num::operator == (uint32_t val)
{
    if (!_hiword && (val == _word[0]))
        return 1;
    else
        return 0;
}

const int Num::operator == (Num& val)
{
    if (!compare(val))
        return 1;
    else
        return 0;
}

const int Num::operator != (uint32_t val)
{
    if (_hiword || (val != _word[0]))
        return 0;
    else
        return 1;
}

const int Num::operator != (Num& val)
{
    if (!compare(val))
        return 0;
    else
        return 1;
}

const void Num::operator <<= (size_t bits) { shiftLeft(bits); }

const void Num::operator >>= (size_t bits) { shiftRight(bits); }

const void Num::operator ++() { increment(); }

const void Num::operator --() { decrement(); }

const void Num::operator += (uint32_t val)
{
    Num Y(val);
    add(Y);
}

const void Num::operator += (Num& Y) { add(Y); }

const void Num::operator -= (uint32_t val)
{
    Num Y(val);
    sub(Y);
}

const void Num::operator -= (Num& Y) { sub(Y); }

const void Num::operator *= (Num& Y) { mul(Y); }

const void Num::operator /= (Num& Y) { div(Y); }

const void Num::operator %= (Num& Y) { mod(Y); }
