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

    RSA();
    ~RSA();
    void Init();
    void Reset();
    bool Create(size_t bits);
    void Sign(uint8_t* out, uint8_t* in, size_t len);
    bool Verify(uint8_t* out, uint8_t* in, size_t* len);
    void Encrypt(uint8_t* out, uint8_t* in, size_t* len);
    bool Decrypt(uint8_t* out, uint8_t* in, size_t* len);
    void Decode(uint8_t* out, uint8_t* in, size_t* len);
    bool ImportKey(uint8_t** in, size_t* inLen);
    bool ImportEncryptedKey(uint8_t** in, size_t* inLen, uint8_t* pswd, size_t pswdLen);
    bool Import(uint8_t** in, size_t* inLen, uint8_t* pswd, size_t pswdLen);
    void Export(uint8_t* out, size_t* len);
    void ExportKey(uint8_t* out, size_t* len);
    void ExportEncryptedKey(uint8_t* out, size_t* len, uint8_t* password, size_t passwordLen);
    RSA& operator = (RSA& val);
};
