#include "rsa.h"
#include "asn.h"
#include "base64.h"
#include "oid.h"
#include "pbc2.h"

RSA::RSA()
{
    Init();
}

RSA::~RSA()
{
    Reset();
}

void RSA::Init()
{
}

void RSA::Reset()
{
    N.Reset();
    E.Reset();
    D.Reset();
    P.Reset();
    Q.Reset();
    DP.Reset();
    DQ.Reset();
    QINV.Reset();
    PINV.Reset();
    _rand.Reset();

    Init();
}

bool RSA::Create(size_t bits)
{
    int k;
    Num U, V, T, phiR, GCD;
L10:
    if (!U.putPrime(_rand, bits >> 1))
        return false;
    if (!V.putPrime(_rand, bits >> 1))
        return false;
    k = U.compare(V);
    if (!k)
        goto L10;
    if (k > 0) {
        T.copy(U);
        U.copy(V);
        V.copy(T);
    }
    N.copy(U);
    N.mul(V);
    --U;
    --V;
    phiR.copy(U);
    phiR.mul(V);
    E.putWord(65537);
    GCD.mulInvGCD(phiR, E, D);
    if ((1 != GCD.words()) || (1 != GCD.word(0))) {
        E.putWord(17);
        GCD.mulInvGCD(phiR, E, D);
        if ((1 != GCD.words()) || (1 != GCD.word(0))) {
            E.putWord(7);
            GCD.mulInvGCD(phiR, E, D);
            if ((1 != GCD.words()) || (1 != GCD.word(0))) {
                E.putWord(3);
                GCD.mulInvGCD(phiR, E, D);
                if ((1 != GCD.words()) || (1 != GCD.word(0)))
                    goto L10;
            }
        }
    }
    GCD.copy(E);
    GCD.mul(D);
    GCD.modAbs(phiR);
    if ((1 != GCD.words()) || (1 != GCD.word(0)))
        goto L10;
    DP = D;
    DP %= U;
    DQ = D;
    DQ %= V;
    ++U;
    ++V;
    GCD.mulInvGCD(U, V, QINV);
    GCD.mulInvGCD(V, U, PINV);
    P = U;
    Q = V;
    return true;
}

void RSA::Sign(uint8_t* out, uint8_t* in, size_t len)
{
    size_t i, j, k;
    uint8_t em[num::bytes];
    Num A, H, M1, M2;
    j = ((size_t)(N.bits() - 1) >> 3) + 1;
    k = j - len;
    memset(em, 0, num::bytes);
    for (i = 0; i < j; i++) em[i] = 0xff;
    em[0] = 0;
    em[1] = 1;
    em[k - 1] = 0;
    memcpy(&em[k], in, len);
    A.putBin(em, j);
    M1.montExp(A, DP, P);
    M2.montExp(A, DQ, Q);
    if (M1 > M2) {
        H = M1;
        H.sub(M2);
        H.mul(QINV);
        H.mod(P);
        H.mul(Q);
        H.addAbs(M2);
    } else {
        H = M2;
        H.sub(M1);
        H.mul(PINV);
        H.mod(Q);
        H.mul(P);
        H.addAbs(M1);
    }
    H.bin(out, j);
}

bool RSA::Verify(uint8_t* out, uint8_t* in, size_t* len)
{
    uint8_t* pp;
    uint8_t* qq;
    uint8_t DM[num::bytes];
    size_t bytes;
    Num A, V;
    A.putBin(in, *len);
    V.montExp(A, E, N);
    memset(DM, 0, num::bytes);
    bytes = (size_t)V.words() << num::byte2word;
    V.bin(DM, bytes);
    if (DM[0] || 1 != DM[1])
        return false;
    pp = &DM[2];
    qq = &DM[bytes - 1];
    for (; pp < qq && *pp; ++pp);
    memcpy(out, pp + 1, qq - pp);
    *len = qq - pp;
    return true;
}

void RSA::Encrypt(uint8_t* out, uint8_t* in, size_t* len)
{
    size_t i, j, k;
    uint8_t uc, em[num::bytes];
    Num A;
    j = (size_t)N.words() << num::byte2word;
    k = j - *len;
    memset(em, 0, num::bytes);
    for (i = 0; i < j; i++) {
        uc = (uint8_t)_rand.Rand();
        em[i] = (uc ? uc : 0x69);
    }
    em[0] = 0;
    em[1] = 2;
    em[k - 1] = 0;
    memcpy(&em[k], in, *len);
    A.putBin(em, j);
    A.montExp(A, E, N);
    A.bin(out, j);
    *len = j;
}

bool RSA::Decrypt(uint8_t* out, uint8_t* in, size_t* len)
{
    uint8_t* pp;
    uint8_t* qq;
    uint8_t DM[num::bytes];
    size_t bytes;
    Num A, V, M1, M2;
    A.putBin(in, *len);
    M1.montExp(A, DP, P);
    M2.montExp(A, DQ, Q);
    if (M1 > M2) {
        V = M1;
        V.sub(M2);
        V.mul(QINV);
        V.mod(P);
        V.mul(Q);
        V.addAbs(M2);
    } else {
        V = M2;
        V.sub(M1);
        V.mul(PINV);
        V.mod(Q);
        V.mul(P);
        V.addAbs(M1);
    }
    memset(DM, 0, num::bytes);
    bytes = (size_t)V.words() << num::byte2word;
    V.bin(DM, bytes);
    if (DM[0] || 2 != DM[1])
        return false;
    pp = &DM[2];
    qq = &DM[bytes - 1];
    for (; pp < qq && *pp; ++pp);
    memcpy(out, pp + 1, qq - pp);
    *len = qq - pp;
    return true;
}

void RSA::Decode(uint8_t* out, uint8_t* in, size_t* len)
{
    if (!out || !in || !len)
        return;
    uint8_t* q = out;
    uint8_t* p = in;
    uint8_t* r = in + *len;
    char uc;
    while (p < r) {
        uc = *p++;
        if ('-' == uc)
            break;
        if ((uc >= 'A' && uc <= 'Z') || (uc >= 'a' && uc <= 'z') || (uc >= '0' && uc <= '9') || uc == '/' || uc == '+' || uc == '=')
            *q++ = uc;
    }
    size_t h = (size_t)(q - out);
    base64dec(out, out, &h);
    *len = h;
}

bool RSA::ImportKey(uint8_t** in, size_t* inLen)
{
    uint8_t* p;
    size_t h, indef = 0;
    bool result = false;
    do {
        if (!in || !(*in) || !inLen || !(*inLen))
            break;
        p = *in;
        //  PrivateKeyInfo sequence or RSAPrivateKey sequence
        if (asn::sequence != *p)
            break;
        p = asnInto(p, &h, &indef);
        //  PrivateKeyInfo version integer or RSAPrivateKey version integer
        if (asn::integer != *p)
            break;
        p = asnInto(p, &h, &indef);
        if (1 != h)
            break;
        if (asn::version1 != *p)
            break;
        p += h;
        //  PrivateKeyAlgorithm sequence
        if (asn::sequence == *p) {
            p = asnInto(p, &h, &indef);
            //  PrivateKeyAlgorithm OID
            if (asn::oid != *p)
                break;
            p = asnInto(p, &h, &indef);
            if (9 != h)
                break;
            if (memcmp(p, OID_RSA, h))
                break;
            p += h;
            //  PrivateKeyAlgorithm OID param
            if (asn::null != *p)
                break;
            p++;
            if ('\0' != *p)
                break;
            p++;
            //  PrivateKey octet-string
            if (asn::octetstring != *p)
                break;
            p = asnInto(p, &h, &indef);
            //  RSAPrivateKey sequence
            if (asn::sequence != *p)
                break;
            p = asnInto(p, &h, &indef);
            //  RSAPrivateKey version integer
            if (asn::integer != *p)
                break;
            p = asnInto(p, &h, &indef);
            if (1 != h)
                break;
            if (asn::version1 != *p)
                break;
            p += h;
        }
        //  RSAPrivateKey modulus integer
        if (asn::integer != *p)
            break;
        p = asnInto(p, &h, &indef);
        N.putBin(p, h);
        p += h;
        //  RSAPrivateKey public exponent integer
        if (asn::integer != *p)
            break;
        p = asnInto(p, &h, &indef);
        E.putBin(p, h);
        p += h;
        //  RSAPrivateKey private exponent integer
        if (asn::integer != *p)
            break;
        p = asnInto(p, &h, &indef);
        D.putBin(p, h);
        p += h;
        //  RSAPrivateKey prime-p integer
        if (asn::integer != *p)
            break;
        p = asnInto(p, &h, &indef);
        P.putBin(p, h);
        p += h;
        //  RSAPrivateKey prime-q integer
        if (asn::integer != *p)
            break;
        p = asnInto(p, &h, &indef);
        Q.putBin(p, h);
        p += h;
        //  RSAPrivateKey d mod (p-1) integer
        if (asn::integer != *p)
            break;
        p = asnInto(p, &h, &indef);
        DP.putBin(p, h);
        p += h;
        //  RSAPrivateKey d mod (q-1) integer
        if (asn::integer != *p)
            break;
        p = asnInto(p, &h, &indef);
        DQ.putBin(p, h);
        p += h;
        //  RSAPrivateKey q^-1 integer
        if (asn::integer != *p)
            break;
        p = asnInto(p, &h, &indef);
        QINV.putBin(p, h);

        Num G = 1;
        G.mulInvGCD(Q, P, PINV);

        p += h;
        *inLen = (size_t)(p - *in);
        result = true;
    } while (0);
    return result;
}

bool RSA::ImportEncryptedKey(uint8_t** in, size_t* inLen, uint8_t* pswd, size_t pswdLen)
{
    uint8_t* p;
    size_t h, j, count, indef = 0;
    PBC2 pbc2;

    bool result = false;
    do {
        if (!in || !(*in) || !inLen || !(*inLen) || !pswd || !pswdLen)
            break;
        p = *in;
        //  EncryptedPrivateKey sequence
        if (asn::sequence != *p)
            break;
        p = asnInto(p, &h, &indef);
        //  EncryptionAlgorithm sequence
        if (asn::sequence != *p) {
            result = ImportKey(in, inLen);
            break;
        }
        p = asnInto(p, &h, &indef);
        //  EncryptionAlgorithm OID
        if (asn::oid != *p)
            break;
        p = asnInto(p, &h, &indef);
        if (9 != h)
            break;
        if (memcmp(p, OID_PBES2, h)) {
            //  Try unencrypted private key
            result = ImportKey(in, inLen);
            break;
        }
        p += h;
        pbc2.SetPassword(pswd, pswdLen);
        //  EncryptionAlgorithm params sequence
        if (asn::sequence != *p)
            break;
        p = asnInto(p, &h, &indef);
        //  KeyDerivationAlgorithm sequence
        if (asn::sequence != *p)
            break;
        p = asnInto(p, &h, &indef);
        //  KeyDerivationAlgorithm OID
        if (asn::oid != *p)
            break;
        p = asnInto(p, &h, &indef);
        if (9 != h)
            break;
        if (memcmp(p, OID_PBKDF2, h))
            break;
        p += h;
        //  KeyDerivationAlgorithm params sequence
        if (asn::sequence != *p)
            break;
        p = asnInto(p, &h, &indef);
        //  KeyDerivationAlgorithm params salt octet-string
        if (asn::octetstring != *p)
            break;
        p = asnInto(p, &h, &indef);
        pbc2.SetSalt(p, h);
        p += h;
        //  KeyDerivationAlgorithm params count integer
        if (asn::integer != *p)
            break;
        p = asnInto(p, &h, &indef);
        if (h > 4)
            break;
        for (j = 0, count = 0; j < h; j++) {
            count <<= 8;
            count += p[j];
        }
        pbc2.SetCount(count);
        p += h;
        //  EncryptionAlgorithm sequence
        if (asn::sequence != *p)
            break;
        p = asnInto(p, &h, &indef);
        //  EncryptionAlgorithm OID
        if (asn::oid != *p)
            break;
        p = asnInto(p, &h, &indef);
        if (8 != h)
            break;
        if (memcmp(p, OID_DESEDECBC, h))
            break;
        p += h;
        //  EncryptionAlgorithm params IV octet-string
        if (asn::octetstring != *p)
            break;
        p = asnInto(p, &h, &indef);
        if (8 != h)
            break;
        pbc2.SetIV(p);
        p += h;
        //  EncryptedData octet-string
        if (asn::octetstring != *p)
            break;
        p = asnInto(p, &h, &indef);
        //  Decrypt the encrypted private key
        pbc2.Decrypt(p, p, &h);
        result = ImportKey(&p, &h);
        *in = p;
        *inLen = h;
    } while (0);
    return result;
}

bool RSA::Import(uint8_t** in, size_t* inLen, uint8_t* pswd, size_t pswdLen)
{
    if (!in || !*in || !inLen || !*inLen)
        return false;
    uint8_t* p = *in;
    uint8_t* q = p;
    uint8_t* r = p + *inLen;
    if (!strncmp((char*)p, "-----BEGIN RSA PRIVATE KEY-----", 31)) {
        p += 31;
        *inLen = (size_t)(r - p);
        Decode(q, p, inLen);
        if (!ImportKey(&q, inLen))
            return false;
        *in = q;
        return true;
    }
    if (!strncmp((char*)p, "-----BEGIN ENCRYPTED PRIVATE KEY-----", 37)) {
        p += 37;
        *inLen = (size_t)(r - p);
        Decode(q, p, inLen);
    }
    if (!ImportEncryptedKey(&q, inLen, pswd, pswdLen))
        return false;
    *in = q;
    return true;
}

void RSA::Export(uint8_t* out, size_t* len)
{
    uint8_t* q = out;
    *q++ = asn::sequence;
    *q++ = asn::twobytes;
    *q++ = 0;
    *q++ = 0;
    uint8_t* s0 = q;

    *q++ = asn::integer; // RSAPrivateKey version integer
    *q++ = 1;
    *q++ = asn::version1;

    q = N.BER(q);
    q = E.BER(q);
    q = D.BER(q);
    q = P.BER(q);
    q = Q.BER(q);
    q = DP.BER(q);
    q = DQ.BER(q);
    q = QINV.BER(q);

    q = derfix(q, s0);
    *len = q - out;
}

void RSA::ExportKey(uint8_t* out, size_t* len)
{
    size_t h = 0;
    uint8_t* q = out;
    catstr(&q, "-----BEGIN RSA PRIVATE KEY-----\r\n", &h);
    uint8_t* e0 = q;
    uint8_t* p = (uint8_t*)calloc(4096, 1);
    q = p;
    h = *len;
    h = h - (e0 - out);
    Export(q, &h);
    q = e0;
    base64enc(q, p, &h, 64);
    free(p);
    q += h;
    catstr(&q, "-----END RSA PRIVATE KEY-----\r\n", &h);
    *len = q - out;
}

void RSA::ExportEncryptedKey(uint8_t* out, size_t* len, uint8_t* password, size_t passwordLen)
{
    Random rand;
    PBC2 pbc2;
    pbc2.SetPassword(password, passwordLen);
    pbc2.GenSalt(8);
    pbc2.SetCount(rand.RandInRange(1000, 2000));
    uint8_t* q = out;
    size_t h = 0;
    catstr(&q, "-----BEGIN ENCRYPTED PRIVATE KEY-----\r\n", &h);
    uint8_t* e0 = q;
    uint8_t* p = new uint8_t[4096];
    memset(p, 0, 4096);
    q = p;
    *q++ = asn::sequence; // encryptedPrivateKeyInfo sequence
    *q++ = asn::twobytes;
    *q++ = 0;
    *q++ = 0;
    uint8_t* s0 = q;

    *q++ = asn::sequence; // encryptionAlgorithmIdentifier seequence
    *q++ = 64;
    *q++ = asn::oid;
    *q++ = 9;

    *q++ = OID_BYTE1(oid::iso, oid::isombr);
    *q++ = OID_HI(oid::isombrus);
    *q++ = OID_LO(oid::isombrus);
    *q++ = OID_HIHI(oid::isombrus_rsadsi);
    *q++ = OID_HI(oid::isombrus_rsadsi);
    *q++ = OID_LO(oid::isombrus_rsadsi);
    *q++ = oid::isombrus_rsadsi_pkcs;
    *q++ = oid::isombrus_rsadsi_pkcs5;
    *q++ = oid::isombrus_rsadsi_pkcs5_pbes2;

    *q++ = asn::sequence; // PBES parameters sequence
    *q++ = 51;
    *q++ = asn::sequence; // key-derivation-function parameter sequence
    *q++ = 27;
    *q++ = asn::oid;
    *q++ = 9;
    *q++ = OID_BYTE1(oid::iso, oid::isombr);
    *q++ = OID_HI(oid::isombrus);
    *q++ = OID_LO(oid::isombrus);
    *q++ = OID_HIHI(oid::isombrus_rsadsi);
    *q++ = OID_HI(oid::isombrus_rsadsi);
    *q++ = OID_LO(oid::isombrus_rsadsi);
    *q++ = oid::isombrus_rsadsi_pkcs;
    *q++ = oid::isombrus_rsadsi_pkcs5;
    *q++ = oid::isombrus_rsadsi_pkcs5_pbkdf2;
    *q++ = asn::sequence; // KDF parameters sequence
    *q++ = 14;

    *q++ = asn::octetstring; // KDF SALT parameter
    *q++ = 8;
    q = pbc2.GetSalt(q);

    size_t count = pbc2.GetCount();
    *q++ = asn::integer; // count integer
    *q++ = 2;
    *q++ = (uint8_t)(count >> 8);
    *q++ = (uint8_t)(count & 255);

    *q++ = asn::sequence; // encryption-algorithm parameter sequence
    *q++ = 20;
    *q++ = asn::oid;
    *q++ = 8;
    *q++ = OID_BYTE1(oid::iso, oid::isombr);
    *q++ = OID_HI(oid::isombrus);
    *q++ = OID_LO(oid::isombrus);
    *q++ = OID_HIHI(oid::isombrus_rsadsi);
    *q++ = OID_HI(oid::isombrus_rsadsi);
    *q++ = OID_LO(oid::isombrus_rsadsi);
    *q++ = oid::isombrus_rsadsi_enc;
    *q++ = oid::isombrus_rsadsi_encdes3cbc;

    *q++ = asn::octetstring; // IV parameter
    *q++ = 8;
    uint8_t* c0 = q;
    q += 8;

    *q++ = asn::octetstring; // encrypted-data octet-string
    *q++ = asn::twobytes;
    *q++ = 0;
    *q++ = 0;
    uint8_t* s1 = q;

    *q++ = asn::sequence; // privateKeyInfo sequence
    *q++ = asn::twobytes;
    *q++ = 0;
    *q++ = 0;
    uint8_t* s2 = q;

    *q++ = asn::integer; // version integer
    *q++ = 1;
    *q++ = asn::version1;
    *q++ = asn::sequence; // privateKeyAlgorithm sequence
    *q++ = 13;
    *q++ = asn::oid;
    *q++ = 9;
    *q++ = OID_BYTE1(oid::iso, oid::isombr);
    *q++ = OID_HI(oid::isombrus);
    *q++ = OID_LO(oid::isombrus);
    *q++ = OID_HIHI(oid::isombrus_rsadsi);
    *q++ = OID_HI(oid::isombrus_rsadsi);
    *q++ = OID_LO(oid::isombrus_rsadsi);
    *q++ = oid::isombrus_rsadsi_pkcs;
    *q++ = oid::isombrus_rsadsi_pkcs1;
    *q++ = oid::isombrus_rsadsi_pkcs1_rsa;
    *q++ = asn::null;
    *q++ = 0;

    *q++ = asn::octetstring; // privateKey octet-string
    *q++ = asn::twobytes;
    *q++ = 0;
    *q++ = 0;
    uint8_t* s3 = q;

    h = *len;
    h = h - (q - out);
    Export(q, &h); // privateKey BER
    q += h;
    q = derfix(q, s3);
    q = derfix(q, s2);

    h = (q - s1);
    pbc2.Encrypt(s1, s1, &h); // encrypt
    q = s1 + h;
    pbc2.GetIV(c0); // store IV
    q = derfix(q, s1);
    q = derfix(q, s0);

    h = q - p;
    q = e0;
    base64enc(q, p, &h, 64); // encode
    delete[] p;
    q += h;
    catstr(&q, "-----END ENCRYPTED PRIVATE KEY-----\r\n", &h);
    *len = q - out;
}

RSA& RSA::operator = (RSA& val)
{
    Reset();

    N = val.N;
    E = val.E;
    D = val.D;
    P = val.P;
    Q = val.Q;
    DP = val.DP;
    DQ = val.DQ;
    QINV = val.QINV;
    PINV = val.PINV;
    return *this;
}
