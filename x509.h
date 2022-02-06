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

    EXPORT X509();
    EXPORT ~X509();
    void Init();
    void Reset();
    bool PutDateTime(char* out, size_t* len, uint8_t* val);
    uint8_t* PutNamePart(uint8_t* buf, char* attr, char* val);
    EXPORT void PutIssuer(const char* val);
    EXPORT void PutSerNo(uint8_t* val);
    EXPORT void PutSubject(const char* val);
    EXPORT void PutNotBefore(uint8_t* val);
    EXPORT void PutNotAfter(uint8_t* val);
    EXPORT void PutPubKey(RSA& pubkey);
    EXPORT void PutPrvKey(RSA& prvkey);
    EXPORT void SetKeyBuf(uint8_t* key, size_t len) { setptr(&_key, key, len); }
    EXPORT void SetKeyLen(size_t len) { _keyLen = len; }
    EXPORT void SetCertBuf(uint8_t* cert, size_t len) { setptr(&_cert, cert, len); }
    EXPORT void SetCertLen(size_t len) { _certLen = len; }
    EXPORT bool ImportKey(uint8_t* in, size_t inLen, uint8_t* pswd, size_t pswdLen);
    EXPORT bool ImportCert(uint8_t* in);
    EXPORT bool Import(uint8_t* in, size_t len);
    EXPORT void Export(uint8_t* buf, size_t* len);
    EXPORT void ExportCert(uint8_t* buf, size_t* len);
};
