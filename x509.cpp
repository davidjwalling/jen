#include "x509.h"
#include "asn.h"
#include "base64.h"
#include "oid.h"
#include "sha.h"

X509::X509()
{
    Init();
}

X509::~X509()
{
    Reset();
}

void X509::Init()
{
    _pathLen = 0;
    _issuerLen = 0;
    _sernoLen = 0;
    _subjectLen = 0;
    _notBeforeLen = 0;
    _notAfterLen = 0;
    _keyLen = 0;
    _certLen = 0;
    _issuer = nullptr;
    _serno = nullptr;
    _subject = nullptr;
    _notBefore = nullptr;
    _notAfter = nullptr;
    _key = nullptr;
    _cert = nullptr;
    _flags = 0;
}

void X509::Reset()
{
    freeptr(&_issuer);
    freeptr(&_serno);
    freeptr(&_subject);
    freeptr(&_notBefore);
    freeptr(&_notAfter);
    freeptr(&_key);
    freeptr(&_cert);
    Init();
}

bool X509::PutDateTime(char* out, size_t* len, uint8_t* val)
{
    struct tm tmT = { 0 };
    if (!datetimecheck(val, &tmT))
        return false;
    char* q = out;
    if (tmT.tm_year + 1900 < 2050) {
        *q++ = asn::utctime;
        *q++ = 13;
        sprintf((char* const)q, "%02d%02d%02d%02d%02d%02d",
            tmT.tm_year % 100, tmT.tm_mon + 1, tmT.tm_mday,
            tmT.tm_hour, tmT.tm_min, tmT.tm_sec);
        q += 12;
    } else {
        *q++ = asn::gentime;
        *q++ = 15;
        sprintf((char* const)q, "%04d%02d%02d%02d%02d%02d",
            tmT.tm_year + 1900, tmT.tm_mon + 1, tmT.tm_mday,
            tmT.tm_hour, tmT.tm_min, tmT.tm_sec);
        q += 14;
    }
    *q++ = 'Z';
    *len = q - out;
    return true;
}

uint8_t* X509::PutNamePart(uint8_t* buf, char* attr_s, char* val)
{
    if (!buf || !attr_s || !val)
        return buf;
    char* u = ltrim(rtrim(attr_s));
    if (!u || !*u)
        return buf;
    char* v = ltrim(rtrim(val));
    if (!v || !*v)
        return buf;
    //uint8_t* d = nullptr;
    //uint8_t* u = tokstrx(attr_s, " \t", " \t", &d);
    //if (!u || !(*u))
    //    return buf;
    //d = nullptr;
    //uint8_t* v = tokstrq(val, " \t", " \t", &d);
    //if (!v || !(*v))
    //    return buf;
    uint8_t* q = buf;
    *q++ = asn::set;
    *q++ = asn::twobytes;
    *q++ = 0;
    *q++ = 0;
    uint8_t* s0 = q;
    *q++ = asn::sequence;
    *q++ = asn::twobytes;
    *q++ = 0;
    *q++ = 0;
    uint8_t* s1 = q;
    uint8_t attr = 0;
    if (!cmpstr("FAX", u))
        attr = oid::ccittdsat_fax;
    else if (!cmpstr("TEL", u))
        attr = oid::ccittdsat_tel;
    else if (!cmpstr("E", u))
        attr = oid::ccittdsat_email;
    else if (!cmpstr("P", u))
        attr = oid::ccittdsat_p;
    else if (!cmpstr("C", u))
        attr = oid::ccittdsat_c;
    else if (!cmpstr("S", u))
        attr = oid::ccittdsat_s;
    else if (!cmpstr("L", u))
        attr = oid::ccittdsat_l;
    else if (!cmpstr("R", u))
        attr = oid::ccittdsat_street;
    else if (!cmpstr("O", u))
        attr = oid::ccittdsat_o;
    else if (!cmpstr("OU", u))
        attr = oid::ccittdsat_ou;
    else if (!cmpstr("T", u))
        attr = oid::ccittdsat_t;
    else if (!cmpstr("SN", u))
        attr = oid::ccittdsat_surname;
    else if (!cmpstr("NAME", u))
        attr = oid::ccittdsat_name;
    else if (!cmpstr("CN", u))
        attr = oid::ccittdsat_cn;
    else
        attr = oid::ccittdsat_ou;
    *q++ = asn::oid;
    if (attr > 200) {
        *q++ = 9;
        *q++ = OID_BYTE1(oid::iso, oid::isombr);
        *q++ = OID_HI(oid::isombrus);
        *q++ = OID_LO(oid::isombrus);
        *q++ = OID_HIHI(oid::isombrus_rsadsi);
        *q++ = OID_HI(oid::isombrus_rsadsi);
        *q++ = OID_LO(oid::isombrus_rsadsi);
        *q++ = oid::isombrus_rsadsi_pkcs;
        *q++ = oid::isombrus_rsadsi_pkcs9;
        *q++ = (uint8_t)(attr - 200);
        *q++ = asn::ia5string;
    } else {
        *q++ = 3;
        *q++ = OID_BYTE1(oid::ccitt, oid::ccittds);
        *q++ = oid::ccittdsat;
        *q++ = attr;
        *q++ = asn::prtstring;
    }
    *q++ = asn::twobytes;
    *q++ = 0;
    *q++ = 0;
    uint8_t* s2 = q;
    catmem(&q, (uint8_t*)v, strlen(v));
    q = derfix(q, s2);
    q = derfix(q, s1);
    q = derfix(q, s0);
    return q;
}

void X509::PutIssuer(const char* val)
{
    size_t len = 0;
    char work[256] = { 0 };
    uint8_t issuer[512] = { 0 };
    strncpy((char*)work, (const char*)val, sizeof(work) - 1);
    uint8_t* q = issuer;
    char* d = nullptr;
    char* u = tokstrq(work, " \t", ";", &d);
    while (u) {
        char* e = nullptr;
        char* v = tokstrx(u, " \t", "=", &e);
        if (v && e)
            q = PutNamePart(q, v, e);
        u = tokstrq(0, " \t", ";", &d);
    }
    len = q - issuer;
    setptr(&_issuer, issuer, len);
    _issuerLen = len;
}

void X509::PutSerNo(uint8_t* val)
{
    uint8_t serno[512] = { 0 };
    Num T;
    T.putString(val);
    size_t len = T.bytes();
    T.bin(serno, len);
    setptr(&_serno, serno, len);
    _sernoLen = len;
}

void X509::PutSubject(const char* val)
{
    size_t len = 0;
    char work[512] = { 0 };
    uint8_t subject[512] = { 0 };
    strncpy((char*)work, (const char*)val, sizeof(work) - 1);
    uint8_t* q = subject;
    char* d = nullptr;
    char* u = tokstrq(work, " \t", ";", &d);
    while (u) {
        char* e = nullptr;
        char* v = tokstrx(u, " \t", "=", &e);
        if (v && e)
            q = PutNamePart(q, v, e);
        u = tokstrq(0, " \t", ";", &d);
    }
    len = q - subject;
    setptr(&_subject, subject, len);
    _subjectLen = len;
}

void X509::PutNotBefore(uint8_t* val)
{
    if (!val)
        return;
    size_t len = strlen((const char*)val);
    char datetime[24] = { 0 };
    if (!PutDateTime(datetime, &len, val))
        return;
    setptr(&_notBefore, (uint8_t*)datetime, len);
    _notBeforeLen = len;
}

void X509::PutNotAfter(uint8_t* val)
{
    if (!val)
        return;
    size_t len = strlen((const char*)val);
    char datetime[24] = { 0 };
    if (!PutDateTime(datetime, &len, val))
        return;
    setptr(&_notAfter, (uint8_t*)datetime, len);
    _notAfterLen = len;
}

void X509::PutPubKey(RSA& key)
{
    _pubKey.N = key.N;
    _pubKey.E = key.E;
}

void X509::PutPrvKey(RSA& key)
{
    _prvKey.N = key.N;
    _prvKey.E = key.E;
    _prvKey.D = key.D;
    _prvKey.P = key.P;
    _prvKey.Q = key.Q;
    _prvKey.DP = key.DP;
    _prvKey.DQ = key.DQ;
    _prvKey.QINV = key.QINV;
    _prvKey.PINV = key.PINV;
}

bool X509::ImportKey(uint8_t* in, size_t inLen, uint8_t* pswd, size_t pswdLen)
{
    if (!_prvKey.Import(&in, &inLen, pswd, pswdLen))
        return false;
    SetKeyBuf(in, inLen);
    SetKeyLen(inLen);
    return true;
}

bool X509::ImportCert(uint8_t* in)
{
    uint8_t* p;
    size_t h, indef = 0;
    Num M;
    bool result = false;
    do {
        if (!in)
            break;
        p = in;
        //  Certificate sequence
        if (asn::sequence != *p)
            break;
        p = asnInto(p, &h, &indef);
        //  TBSCertificate sequence
        if (asn::sequence != *p)
            break;
        p = asnInto(p, &h, &indef);
        //  TBSCertificate.Version [0] explicit
        if (asn::part0 == *p) {
            p = asnInto(p, &h, &indef);
            //  TBSCertificate.Version [0] integer
            if (asn::integer != *p)
                break;
            p = asnInto(p, &h, &indef);
            //  Validate X.509 version
            M.putBin(p, h);
            if (M != 0 && M != 1 && M != 2)
                break;
            p += h;
        }
        //  TBSCertificate.CertificateSerialNumber integer
        if (asn::integer != *p)
            break;
        p = asnInto(p, &h, &indef);
        setptr(&_serno, p, h);
        _sernoLen = h;
        p += h;
        //  TBSCertificate.AlgorithmIdentifier sequence
        if (asn::sequence != *p)
            break;
        p = asnInto(p, &h, &indef);
        //  TBSCertificate.AlgorithmIdentifier.algorithm OID
        if (asn::oid != *p)
            break;
        p = asnInto(p, &h, &indef);
        p += h;
        //  TBSCertificate.AlgorithmIdentifier.parameters optional
        if (asn::null == *p)
            p = asnOver(p, &h, &indef);
        //  TBSCertificate.Issuer sequence
        if (asn::sequence != *p)
            break;
        p = asnInto(p, &h, &indef);
        setptr(&_issuer, p, h);
        _issuerLen = h;
        p += h;
        //  TBSCertificate.Validity sequence
        if (asn::sequence != *p)
            break;
        p = asnInto(p, &h, &indef);
        //  TBSCertificate.Validity.notBefore time
        if (asn::utctime != *p && asn::gentime != *p)
            break;
        p = asnInto(p, &h, &indef);
        setptr(&_notBefore, p, h);
        _notBeforeLen = h;
        p += h;
        //  TBSCertificate.Validity.notAfter time
        if (asn::utctime != *p && asn::gentime != *p)
            break;
        p = asnInto(p, &h, &indef);
        setptr(&_notAfter, p, h);
        _notAfterLen = h;
        p += h;
        //  TBSCertificate.Subject sequence
        if (asn::sequence != *p)
            break;
        p = asnInto(p, &h, &indef);
        setptr(&_subject, p, h);
        _subjectLen = h;
        p += h;
        //  TBSCertificate.SubjectPublicKeyInfo sequence
        if (asn::sequence != *p)
            break;
        p = asnInto(p, &h, &indef);
        //  TBSCertificate.SubjectPublicKeyInfo.algorithm sequence
        if (asn::sequence != *p)
            break;
        p = asnInto(p, &h, &indef);
        //  TBSCertificate.SubjectPublicKeyInfo.algorithm OID
        if (asn::oid != *p)
            break;
        p = asnInto(p, &h, &indef);
        if (9 != h)
            break;
        if (memcmp(p, OID_RSA, h))
            break;
        p += h;
        if (asn::null == *p)
            p = asnOver(p, &h, &indef);
        //  TBSCertificate.SubjectPublicKeyInfo.subjectPublicKey bit-string
        if (asn::bitstring != *p)
            break;
        p = asnInto(p, &h, &indef);
        //  skip over unused bits
        if ('\0' == *p)
            p++;
        //  RSAPublicKey sequence
        if (asn::sequence != *p)
            break;
        p = asnInto(p, &h, &indef);
        //  RSAPublicKey.modulus integer
        if (asn::integer != *p)
            break;
        p = asnInto(p, &h, &indef);
        _pubKey.N.putBin(p, h);
        p += h;
        //  RSAPublicKey.publicExponent integer
        if (asn::integer != *p)
            break;
        p = asnInto(p, &h, &indef);
        _pubKey.E.putBin(p, h);
        result = true;
    } while (0);
    return result;
}

bool X509::Import(uint8_t* in, size_t len)
{
    bool result = false;
    do {
        if (!in || !len)
            break;
        if ('-' == *in) {
            if (len < X509_CERTPREFIXLEN || memcmp(in, X509_CERTPREFIX, X509_CERTPREFIXLEN))
                break;
            len -= X509_CERTPREFIXLEN;
            _pubKey.Decode(in, &in[X509_CERTPREFIXLEN], &len);
        }
        if (!ImportCert(in))
            break;
        SetCertBuf(in, len);
        SetCertLen(len);
        result = true;
    } while (0);
    return result;
}

void X509::Export(uint8_t* out, size_t* len)
{
    uint8_t authKey[sha1::hashbytes] = { 0 };
    uint8_t subjKey[sha1::hashbytes] = { 0 };
    uint8_t digestInfo[128] = { 0 };

    SHA1 sha1;

    uint8_t* q = out;
    uint8_t* k0 = q;

    *q++ = asn::sequence;
    *q++ = asn::twobytes;
    *q++ = 0;
    *q++ = 0;
    uint8_t* s1 = q;

    q = _prvKey.N.BER(q);
    q = _pubKey.E.BER(q);
    q = derfix(q, s1);
    uint8_t* k1 = q;

    sha1.HashBuf(k0, k1 - k0);
    sha1.GetDigest(authKey);

    q = out;
    *q++ = asn::sequence; // Certificate
    *q++ = asn::twobytes;
    *q++ = 0;
    *q++ = 0;
    s1 = q;

    *q++ = asn::sequence; // TBSCertificate
    *q++ = asn::twobytes;
    *q++ = 0;
    *q++ = 0;
    uint8_t* s2 = q;

    *q++ = asn::part0; // version part sequence
    *q++ = 3;
    *q++ = asn::integer;
    *q++ = 1;
    *q++ = asn::version3;

    *q++ = asn::integer; // CertificateSerialNumber integer
    *q++ = asn::twobytes;
    *q++ = 0;
    *q++ = 0;
    uint8_t* s3 = q;

    catmem(&q, _serno, _sernoLen);
    q = derfix(q, s3);

    *q++ = asn::sequence; // signature AlgorithmIdentifier sequence
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
    *q++ = oid::isombrus_rsadsi_pkcs1_sha1;
    *q++ = asn::null;
    *q++ = 0;

    *q++ = asn::sequence; // issuer name sequence
    *q++ = asn::twobytes;
    *q++ = 0;
    *q++ = 0;
    s3 = q;

    catmem(&q, _issuer, _issuerLen);
    q = derfix(q, s3);

    *q++ = asn::sequence; // validity sequence
    *q++ = asn::twobytes;
    *q++ = 0;
    *q++ = 0;
    s3 = q;

    catmem(&q, _notBefore, _notBeforeLen);
    catmem(&q, (uint8_t*)_notAfter, _notAfterLen);
    q = derfix(q, s3);

    *q++ = asn::sequence; // subject sequence
    *q++ = asn::twobytes;
    *q++ = 0;
    *q++ = 0;
    s3 = q;

    catmem(&q, _subject, _subjectLen);
    q = derfix(q, s3);

    *q++ = asn::sequence; // subjectPublicKeyInfo sequence
    *q++ = asn::twobytes;
    *q++ = 0;
    *q++ = 0;
    s3 = q;

    *q++ = asn::sequence; // subject AlgorithmIdentifier sequence
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

    *q++ = asn::bitstring; // identifier bitstring
    *q++ = asn::twobytes;
    *q++ = 0;
    *q++ = 0;
    uint8_t* s4 = q;
    *q++ = 0; // unused bits

    k0 = q;

    *q++ = asn::sequence; // RSAPublicKey sequence
    *q++ = asn::twobytes;
    *q++ = 0;
    *q++ = 0;
    uint8_t* s5 = q;

    *q++ = asn::integer; // modulus integer
    *q++ = asn::twobytes;
    *q++ = 0;
    *q++ = 0;
    uint8_t* s6 = q;

    size_t n = _pubKey.N.bits();
    if (!(n & 3))
        *q++ = 0;
    n = ((n - 1) >> 3) + 1;
    q = _pubKey.N.bin(q, n);
    q = derfix(q, s6);

    *q++ = asn::integer; // exponent integer
    *q++ = asn::twobytes;
    *q++ = 0;
    *q++ = 0;
    s6 = q;

    n = _pubKey.E.bits();
    if (!(n & 3))
        *q++ = 0;
    n = ((n - 1) >> 3) + 1;
    q = _pubKey.E.bin(q, n);
    q = derfix(q, s6);
    q = derfix(q, s5);

    k1 = q;
    sha1.HashBuf(k0, k1 - k0);
    sha1.GetDigest(subjKey);
    q = derfix(q, s4);
    q = derfix(q, s3);

    *q++ = asn::part3; // extensions part
    *q++ = asn::twobytes;
    *q++ = 0;
    *q++ = 0;
    s3 = q;

    *q++ = asn::sequence; // extensions sequence
    *q++ = asn::twobytes;
    *q++ = 0;
    *q++ = 0;
    s4 = q;

    if (_flags & x509::flags::cacert) {
        *q++ = asn::sequence; // basic-constraints (critical; ca-only)
        *q++ = asn::twobytes;
        *q++ = 0;
        *q++ = 0;
        s5 = q;

        *q++ = asn::oid;
        *q++ = 3;
        *q++ = OID_BYTE1(oid::ccitt, oid::ccittds);
        *q++ = oid::ccittdsce;
        *q++ = oid::ccittdsce_basiccon;

        q = asnPutBoolTrue(q);

        *q++ = asn::octetstring;
        *q++ = asn::twobytes;
        *q++ = 0;
        *q++ = 0;
        s6 = q;

        *q++ = asn::sequence;
        *q++ = asn::twobytes;
        *q++ = 0;
        *q++ = 0;
        uint8_t* s7 = q;

        q = asnPutBoolTrue(q);

        if (_pathLen > 0) {
            *q++ = asn::integer; // pathLenConstraint integer
            *q++ = asn::twobytes;
            *q++ = 0;
            *q++ = 0;
            uint8_t* s8 = q;

            Num T;
            T.putLong(_pathLen);
            n = T.bits();
            if (!(n & 3))
                *q++ = 0;
            n = ((n - 1) >> 3) + 1;
            q = T.bin(q, n);
            q = derfix(q, s8);
        }
        q = derfix(q, s7);
        q = derfix(q, s6);
        q = derfix(q, s5);
    }

    *q++ = asn::sequence; // key-usage (critical)
    *q++ = asn::twobytes;
    *q++ = 0;
    *q++ = 0;
    s5 = q;

    *q++ = asn::oid;
    *q++ = 3;
    *q++ = OID_BYTE1(oid::ccitt, oid::ccittds);
    *q++ = oid::ccittdsce;
    *q++ = oid::ccittdsce_keyusage;

    q = asnPutBoolTrue(q);

    *q++ = asn::octetstring;
    *q++ = 4;
    *q++ = asn::bitstring;
    *q++ = 2;
    *q++ = 2; // unused bits
    *q++ = 0xe4;
    q = derfix(q, s5);

    *q++ = asn::sequence; // subject key identifier
    *q++ = asn::twobytes;
    *q++ = 0;
    *q++ = 0;
    s5 = q;

    *q++ = asn::oid;
    *q++ = 3;
    *q++ = OID_BYTE1(oid::ccitt, oid::ccittds);
    *q++ = oid::ccittdsce;
    *q++ = oid::ccittdsce_subjkey;

    *q++ = asn::octetstring;
    *q++ = asn::twobytes;
    *q++ = 0;
    *q++ = 0;
    s6 = q;

    *q++ = asn::octetstring;
    *q++ = asn::twobytes;
    *q++ = 0;
    *q++ = 0;
    uint8_t* s7 = q;

    catmem(&q, subjKey, sizeof subjKey);

    q = derfix(q, s7);
    q = derfix(q, s6);
    q = derfix(q, s5);

    *q++ = asn::sequence; // authority key identifier (not critical)
    *q++ = asn::twobytes;
    *q++ = 0;
    *q++ = 0;
    s5 = q;

    *q++ = asn::oid;
    *q++ = 3;
    *q++ = OID_BYTE1(oid::ccitt, oid::ccittds);
    *q++ = oid::ccittdsce;
    *q++ = oid::ccittdsce_authkey;

    *q++ = asn::octetstring;
    *q++ = asn::twobytes;
    *q++ = 0;
    *q++ = 0;
    s6 = q;

    *q++ = asn::sequence;
    *q++ = asn::twobytes;
    *q++ = 0;
    *q++ = 0;
    s7 = q;

    *q++ = asn::part0;
    *q++ = asn::twobytes;
    *q++ = 0;
    *q++ = 0;
    uint8_t* s8 = q;

    *q++ = asn::octetstring;
    *q++ = asn::twobytes;
    *q++ = 0;
    *q++ = 0;
    uint8_t* s9 = q;

    catmem(&q, authKey, sizeof authKey);

    q = derfix(q, s9);
    q = derfix(q, s8);
    q = derfix(q, s7);
    q = derfix(q, s6);
    q = derfix(q, s5);

    q = derfix(q, s4);
    q = derfix(q, s3);
    q = derfix(q, s2);

    sha1.HashBuf(s1, q - s1);

    *q++ = asn::sequence; // signatureAlgorithm AlgorithmIdentifier sequence
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
    *q++ = oid::isombrus_rsadsi_pkcs1_sha1;
    *q++ = asn::null;
    *q++ = 0;

    *q++ = asn::bitstring;
    *q++ = asn::twobytes;
    *q++ = 0;
    *q++ = 0;
    s2 = q;
    *q++ = 0; //  unused bits

    k0 = sha1.PutDigestInfo(digestInfo);
    _prvKey.Sign(q, digestInfo, k0 - digestInfo);
    n = ((_prvKey.N.bits() - 1) >> 3) + 1;
    q += n;

    q = derfix(q, s2);
    q = derfix(q, s1);
    *len = q - out;
}

void X509::ExportCert(uint8_t* buf, size_t* len)
{
    size_t h = 0;
    uint8_t* q = buf;
    catstr(&q, X509_CERTPREFIX, &h);
    *q++ = '\r';
    *q++ = '\n';
    uint8_t* p = new uint8_t[4096];
    Export(p, &h);
    base64enc(q, p, &h, 64);
    delete[] p;
    q += h;
    catstr(&q, X509_CERTPOSTFIX, &h);
    *q++ = '\r';
    *q++ = '\n';
    *len = q - buf;
}
