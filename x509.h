#pragma once

#include "api.h"
#include "rsa.h"

#define X509_CERTPREFIX "-----BEGIN CERTIFICATE-----"
#define X509_CERTPREFIXLEN 27
#define X509_CERTPOSTFIX "-----END CERTIFICATE-----"
#define X509_CERTPOSTFIXLEN 25

namespace x509 {
    namespace flags {
        enum {
            cacert = 1
        };
    }
}

class X509 {
public:
    int32_t _pathLen;
    size_t _issuerLen;
    size_t _sernoLen;
    size_t _subjectLen;
    size_t _notBeforeLen;
    size_t _notAfterLen;
    size_t _keyLen;
    size_t _certLen;
    uint8_t* _issuer;
    uint8_t* _serno;
    uint8_t* _subject;
    uint8_t* _notBefore;
    uint8_t* _notAfter;
    uint8_t* _key;
    uint8_t* _cert;
    uint32_t _flags;
    RSA _prvKey;
    RSA _pubKey;

    X509();
    ~X509();
    void Init();
    void Reset();
    bool PutDateTime(char* out, size_t* len, uint8_t* val);
    uint8_t* PutNamePart(uint8_t* buf, char* attr, char* val);
    void PutIssuer(const char* val);
    void PutSerNo(uint8_t* val);
    void PutSubject(const char* val);
    void PutNotBefore(uint8_t* val);
    void PutNotAfter(uint8_t* val);
    void PutPubKey(RSA& pubkey);
    void PutPrvKey(RSA& prvkey);
    void SetKeyBuf(uint8_t* key, size_t len) { setptr(&_key, key, len); }
    void SetKeyLen(size_t len) { _keyLen = len; }
    void SetCertBuf(uint8_t* cert, size_t len) { setptr(&_cert, cert, len); }
    void SetCertLen(size_t len) { _certLen = len; }
    bool ImportKey(uint8_t* in, size_t inLen, uint8_t* pswd, size_t pswdLen);
    bool ImportCert(uint8_t* in);
    bool Import(uint8_t* in, size_t len);
    void Export(uint8_t* buf, size_t* len);
    void ExportCert(uint8_t* buf, size_t* len);
};
