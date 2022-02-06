#pragma once

#include "api.h"
#include "num.h"
#include "random.h"

namespace rsa {
    enum {
        maxlen = 4096
    };
}

class RSA {
public:
    Random _rand;
    Num N;
    Num E;
    Num D;
    Num P;
    Num Q;
    Num DP;
    Num DQ;
    Num QINV;
    Num PINV;

    EXPORT RSA();
    EXPORT ~RSA();
    void Init();
    void Reset();
    EXPORT bool Create(size_t bits);
    EXPORT void Sign(uint8_t* out, uint8_t* in, size_t len);
    EXPORT bool Verify(uint8_t* out, uint8_t* in, size_t* len);
    EXPORT void Encrypt(uint8_t* out, uint8_t* in, size_t* len);
    EXPORT bool Decrypt(uint8_t* out, uint8_t* in, size_t* len);
    void Decode(uint8_t* out, uint8_t* in, size_t* len);
    bool ImportKey(uint8_t** in, size_t* inLen);
    bool ImportEncryptedKey(uint8_t** in, size_t* inLen, uint8_t* pswd, size_t pswdLen);
    EXPORT bool Import(uint8_t** in, size_t* inLen, uint8_t* pswd, size_t pswdLen);
    EXPORT void Export(uint8_t* out, size_t* len);
    EXPORT void ExportKey(uint8_t* out, size_t* len);
    EXPORT void ExportEncryptedKey(uint8_t* out, size_t* len, uint8_t* password, size_t passwordLen);
    EXPORT RSA& operator = (RSA& val);
};
