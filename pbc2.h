#pragma once

#include "api.h"
#include "hmac.h"
#include "prng.h"

namespace pbc2 {
    enum {
        maxdkbytes = 32
    };
}

class PBC2 : public HMAC {
public:
    size_t _passwordLen;
    size_t _saltLen;
    size_t _count;
    uint8_t* _password;
    uint8_t* _salt;
    uint8_t* _iv;
    PRNG _prng;

    PBC2();
    ~PBC2();
    void Init();
    void Reset();
    void DeriveKey(uint8_t* key, size_t keyLen);
    void Transform(uint8_t* out, size_t round);
    void Encrypt(uint8_t* out, uint8_t* in, size_t* len);
    void Decrypt(uint8_t* out, uint8_t* in, size_t* len);
    void GenSalt(size_t len);
    size_t GetCount();
    uint8_t* GetIV(uint8_t* out);
    uint8_t* GetSalt(uint8_t* out);
    void SetCount(size_t count);
    void SetIV(uint8_t* iv);
    void SetPassword(uint8_t* password, size_t len);
    void SetSalt(uint8_t* salt, size_t len);
};
