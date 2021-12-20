#include "channel.h"
#include "log.h"

const char* cond_channel_message_readable = "Socket is readable";
const char* http_response_message_badrequest = "Bad Request\r\n";
const char* http_response_message_badversion = "Version Not Supported\r\n";
const char* DayName[] = { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };
const char* MonthName[] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };
const char* ok_0 = \
"HTTP/%01u.%01u 200 OK\r\nDate: %s\r\nServer: Redstone/0.X\r\n" \
"Content-type: text/html\r\nContent-Length: %zd\r\n\r\n";
const char* ok_1 = \
"<!DOCTYPE html><html><head>" \
"<meta name=\"viewport\" content=\"width=device-width,initial-scale=1.0\">" \
"<style type=\"text/css\">" \
"body{background-color:#fffffa;color:#2b2c30;margin:0;}" \
"div{padding:3px;font-family:Arial,sans-serif;font-size:1em;}" \
".titl{position:fixed;top:0;}" \
".copy{background-color:#2b2c30;color:#fffafa;position:fixed;bottom:0;width:50%;}" \
".rlbl{right:0;text-align:right;}" \
"</style><title>Redstone 0.X</title></head><body>" \
"<div class=\"titl\">Redstone 0.X Experimental</div>" \
"<div class=\"copy\">&copy; 2021 Proserio</div>" \
"<div class=\"copy rlbl\">";
const char* ok_2 = \
"</div></body></html>";

Channel::Channel()
{
    Init();
}

Channel::~Channel()
{
    Reset();
}

void Channel::Init()
{
    _shutdown = false;
    _haveClientHello = false;
    _haveClientKeyExchange = false;
    _haveChangeCipherSpec = false;

    _id = 0;
    _state = 0;

    _expires = 0;
    _certLen = 0;
    _remain = 0;

    _remoteAddr = 0;
    _handShakeSize = 0;

    _remotePort = 0;
    _plainTextVersion = 0;
    _plainTextSize = 0;
    _clientHelloVersion = 0;
    _cipherSuitesLen = 0;
    _extensionsLen = 0;
    _response = 0;

    _recType = 0;
    _handShakeRecType = 0;
    _sessionIdLen = 0;
    _compressionMethodsLen = 0;
    _clientKeyExchangeLen = 0;
    _httpMethod = 0;
    _httpMajorVersion = 0;
    _httpMinorVersion = 0;

    _cert = nullptr;
    _cipherSuites = nullptr;
    _compressionMethods = nullptr;
    _extensions = nullptr;
    _clientKeyExchange = nullptr;

    _prev = nullptr;
    _next = nullptr;

    memset(_clientRandom, 0, sizeof _clientRandom);
    memset(_sessionId, 0, sizeof _sessionId);
    memset(_serverRandom, 0, sizeof _serverRandom);
    memset(_preMasterSecret, 0, sizeof _preMasterSecret);
    memset(_masterSecret, 0, sizeof _masterSecret);

    memset(_clientWriteMAC, 0, sizeof _clientWriteMAC);
    memset(_serverWriteMAC, 0, sizeof _serverWriteMAC);
    memset(_clientWriteKey, 0, sizeof _clientWriteKey);
    memset(_serverWriteKey, 0, sizeof _serverWriteKey);
    memset(_clientWriteIV, 0, sizeof _clientWriteIV);
    memset(_serverWriteIV, 0, sizeof _serverWriteIV);
}

void Channel::Reset()
{
    freeptr(&_cert);
    freeptr(&_cipherSuites);
    freeptr(&_compressionMethods);
    freeptr(&_extensions);
    freeptr(&_clientKeyExchange);
    Init();
}

void Channel::Connected()
{
    if (_socket.Readable()) {
        _hmac.SetDigestAlg(hmac::alg::sha256);
        _sha256.Begin();
        _read.Reset();
        _httpMajorVersion = 1;
        _httpMinorVersion = 0;
        _state = channel::state::needfirstbytes;
        NeedFirstBytes();
    }
}

void Channel::NeedFirstBytes()
{
    if (_read._len < 3)
        Read();
    if (_read._len >= 3) {
        uint8_t* p = &_read._buf[_read._head];
        if (tls_rec_type_handshake == *p) {
            _remain = 5;
            _state = channel::state::needplaintext;
        } else if (('P' == *p && (('O' == *(p + 1) && 'S' == *(p + 2)) || ('U' == *(p + 1) && 'T' == *(p + 2))))
            || ('E' == *(p + 1) && (('G' == *p && 'T' == *(p + 2)) || ('H' == *p && 'A' == *(p + 2)) || ('D' == *p && 'L' == *(p + 2))))
            || ('O' == *p && 'P' == *(p + 1) && 'T' == *(p + 2))
            || ('C' == *p && 'O' == *(p + 1) && 'N' == *(p + 2))
            || ('T' == *p && 'R' == *(p + 1) && 'A' == *(p + 2))) {
            _state = channel::state::needrequest;
            needRequest();
        }
        // to-do: add support for additional protocols
        else {
            _state = channel::state::done;
            Done();
        }
    }
}

void Channel::Read()
{
    _read.Front();
    size_t len = _read.Avail();
    if (_socket.Read(&_read._buf[_read._len], &len))
        _read._len += len;
    else {
        _state = channel::state::done;
        Done();
    }
}

void Channel::Write()
{
    size_t len = _write._len;
    if (_socket.Write(_write._buf, &len))
        _write.Discard(len);
    else {
        _state = channel::state::done;
        Done();
    }
}

void Channel::Done()
{
    if (_write._len)
        Write();
    if (!_write._len)
        Clear();
}

void Channel::Clear()
{
    _haveClientHello = false;
    _haveClientKeyExchange = false;
    _haveChangeCipherSpec = false;
    _state = channel::state::ready;
    _expires = 0;
    _remain = 0;

    _remoteAddr = 0;
    _handShakeSize = 0;

    _remotePort = 0;
    _plainTextVersion = 0;
    _plainTextSize = 0;
    _clientHelloVersion = 0;
    _cipherSuitesLen = 0;
    _extensionsLen = 0;
    _response = 0;

    _recType = 0;
    _handShakeRecType = 0;
    _sessionIdLen = 0;
    _compressionMethodsLen = 0;
    _httpMethod = 0;
    _httpMajorVersion = 0;
    _httpMinorVersion = 0;

    freeptr(&_cipherSuites);
    freeptr(&_compressionMethods);
    freeptr(&_extensions);
    freeptr(&_clientKeyExchange);

    memset(_clientRandom, 0, sizeof _clientRandom);
    memset(_sessionId, 0, sizeof _sessionId);
    memset(_serverRandom, 0, sizeof _serverRandom);

    _uri.Reset();
    _socket.Close();
    _socket.Reset();
    _read.Reset();
    _write.Reset();
}

void Channel::needPlainText()
{
    uint8_t* p = prefetch(5);
    if (!p) return;
    _recType = *p;
    _plainTextVersion = (uint16_t) * (p + 1) << 8 | *(p + 2);
    if (_plainTextVersion < 0x0301 || _plainTextVersion > 0x0303) {
        sendAlert(tls_alert_level_fatal, tls_alert_desc_version);
        _state = channel::state::done;
        return;
    }
    _plainTextSize = (uint16_t) * (p + 3) << 8 | *(p + 4);
    if (_plainTextSize > 16384) {
        sendAlert(tls_alert_level_fatal, tls_alert_desc_param);
        _state = channel::state::done;
        return;
    }
    _read.Discard(5);
    switch (_recType) {
    case tls_rec_type_change:
        _remain = _plainTextSize;
        _state = channel::state::needrectypechange;
        break;
    case tls_rec_type_alert:
        break;
    case tls_rec_type_handshake:
        if (!_haveChangeCipherSpec) {
            _remain = 4;
            _state = channel::state::needhandshake;
        } else {
            _remain = _plainTextSize;
            _state = channel::state::needdecryptedhandshake;
        }
        break;
    case tls_rec_type_data:
        break;
    default:
        sendAlert(tls_alert_level_fatal, tls_alert_desc_unexpected);
        _state = channel::state::done;
    }
}

uint8_t* Channel::prefetch(size_t remain)
{
    if (_write._len) {
        Write();
        return nullptr;
    }
    if (_remain < remain) {
        // send alert: decode error handshake length too short
        return nullptr;
    }
    if (_read._len < remain)
        Read();
    if (_read._len < remain && _read._len < sizeof _read._buf)
        return nullptr;
    _remain -= remain;
    return &_read._buf[_read._head];
}

void Channel::sendAlert(const uint8_t level, const uint8_t desc)
{
    //  to-do: add encrypted alerts
    size_t len;
    uint8_t buf[512] = { 0 };
    uint8_t* p = buf;
    *p++ = tls_rec_type_alert;
    *p++ = 3;
    *p++ = 0;
    *p++ = 0;
    *p++ = 2;
    *p++ = level;
    *p++ = desc;
    len = p - buf;
    _write.Reset();
    _write.Append(buf, len);
}

void Channel::needHandShake()
{
    uint8_t* p = prefetch(4);
    if (!p) return;
    _sha256.Update(p, 4);
    _handShakeRecType = *p;
    _handShakeSize = (uint32_t) * (p + 1) << 16 | *(p + 2) << 8 | *(p + 3);
    _read.Discard(4);
    switch (_handShakeRecType) {
    case tls_handshake_type_clienthello:
        if (_haveClientHello) {
            sendAlert(tls_alert_level_fatal, tls_alert_desc_unexpected);
            _state = channel::state::done;
        } else {
            _remain = _handShakeSize;
            _state = channel::state::needclienthelloversion;
        }
        break;
    case tls_handshake_type_clientkeyexchange:
        if (_haveClientKeyExchange) {
            sendAlert(tls_alert_level_fatal, tls_alert_desc_unexpected);
            _state = channel::state::done;
        } else {
            _remain = _handShakeSize;
            _state = channel::state::needclientkeyexchangelen;
        }
        break;
    default:
        sendAlert(tls_alert_level_fatal, tls_alert_desc_unexpected);
        _state = channel::state::done;
    }
}

void Channel::needClientHelloVersion()
{
    uint8_t* p = prefetch(2);
    if (!p) return;
    _sha256.Update(p, 2);
    _clientHelloVersion = (uint16_t)*p << 8 | *(p + 1);
    _read.Discard(2);
    _state = channel::state::needclienthellorandom;
}

void Channel::needClientHelloRandom()
{
    uint8_t* p = prefetch(32);
    if (!p) return;
    _sha256.Update(p, 32);
    _read.Emit(_clientRandom, 32);
    _state = channel::state::needclienthellosessionidlen;
}

void Channel::needClientHelloSessionIdLen()
{
    uint8_t* p = prefetch(1);
    if (!p) return;
    _sha256.Update(p, 1);
    _sessionIdLen = *p;
    _read.Discard(1);
    if (_sessionIdLen) {
        _state = channel::state::needclienthellosessionid;
    } else {
        _state = channel::state::needclienthellociphersuiteslen;
    }
}

void Channel::needClientHelloSessionId()
{
    uint8_t* p = prefetch(_sessionIdLen);
    if (!p) return;
    _sha256.Update(p, _sessionIdLen);
    _read.Emit(_sessionId, _sessionIdLen);
    _state = channel::state::needclienthellociphersuiteslen;
}

void Channel::needClientHelloCipherSuitesLen()
{
    uint8_t* p = prefetch(2);
    if (!p) return;
    _sha256.Update(p, 2);
    _cipherSuitesLen = (uint16_t)*p << 8 | *(p + 1);
    _read.Discard(2);
    if (_cipherSuitesLen) {
        _state = channel::state::needclienthellociphersuites;
    } else {
        //  send alert: no cipher suites
        _state = channel::state::done;
    }
}

void Channel::needClientHelloCipherSuites()
{
    uint8_t* p = prefetch(_cipherSuitesLen);
    if (!p) return;
    _sha256.Update(p, _cipherSuitesLen);
    setptr(&_cipherSuites, p, _cipherSuitesLen);
    _read.Discard(_cipherSuitesLen);
    _state = channel::state::needclienthellocompressionmethodslen;
}

void Channel::needClientHelloCompressionMethodsLen()
{
    uint8_t* p = prefetch(1);
    if (!p) return;
    _sha256.Update(p, 1);
    _compressionMethodsLen = *p;
    _read.Discard(1);
    if (_compressionMethodsLen) {
        _state = channel::state::needclienthellocompressionmethods;
    } else {
        //  send alert: required compression method missing
        _state = channel::state::done;
    }
}

void Channel::needClientHelloCompressionMethods()
{
    uint8_t* p = prefetch(_compressionMethodsLen);
    if (!p) return;
    _sha256.Update(p, _compressionMethodsLen);
    setptr(&_compressionMethods, p, _compressionMethodsLen);
    _read.Discard(_compressionMethodsLen);
    if (_remain) {
        _state = channel::state::needclienthelloextensionslen;
    } else {
        putServerHello();
    }
}

void Channel::needClientHelloExtensionsLen()
{
    uint8_t* p = prefetch(2);
    if (!p) return;
    _sha256.Update(p, 2);
    _extensionsLen = (uint16_t)*p << 8 | *(p + 1);
    _read.Discard(2);
    if (_extensionsLen) {
        if (_remain != _extensionsLen) {
            // decode error: handshake length incorrect
        } else {
            _state = channel::state::needclienthelloextensions;
        }
    } else {
        putServerHello();
    }
}

void Channel::needClientHelloExtensions()
{
    uint8_t* p = prefetch(_extensionsLen);
    if (!p) return;
    _sha256.Update(p, _extensionsLen);
    setptr(&_extensions, p, _extensionsLen);
    _read.Discard(_extensionsLen);
    if (_remain) {
        // decode error: handshake length incorrect
        _state = channel::state::done;
    } else {
        putServerHello();
    }
}

void Channel::putServerHello()
{
    time_t t = time(nullptr);
    HILO32(t);
    *((uint32_t*)_serverRandom) = (uint32_t)t;
    _random.Fill(&_serverRandom[4], sizeof _serverRandom - 4);

    _write.Reset();
    uint8_t* q = _write._buf;

    *q++ = tls_rec_type_handshake;
    *q++ = 3;
    *q++ = 3; // tls 1.2
    *q++ = 0;
    *q++ = 42;

    uint8_t* r = q;
    *q++ = tls_handshake_type_serverhello;
    *q++ = 0;
    *q++ = 0;
    *q++ = 38;

    *q++ = 3;
    *q++ = 3;
    catmem(&q, _serverRandom, sizeof _serverRandom);
    *q++ = 0;
    *q++ = 0;
    *q++ = 10;
    *q++ = 0;
    _sha256.Update(r, q - r);

    *q++ = tls_rec_type_handshake;
    *q++ = 3;
    *q++ = 3;
    *q++ = ((_certLen + 10) >> 8) & 255;
    *q++ = (_certLen + 10) & 255;

    r = q;
    *q++ = tls_handshake_type_certificate;
    *q++ = 0;
    *q++ = ((_certLen + 6) >> 8) & 255;
    *q++ = (_certLen + 6) & 255;

    *q++ = 0; // certificates
    *q++ = ((_certLen + 3) >> 8) & 255;
    *q++ = (_certLen + 3) & 255;
    *q++ = 0; // certificate
    *q++ = (_certLen >> 8) & 255;
    *q++ = _certLen & 255;
    catmem(&q, _cert, _certLen);
    _sha256.Update(r, q - r);

    *q++ = tls_rec_type_handshake;
    *q++ = 3;
    *q++ = 3;
    *q++ = 0;
    *q++ = 4;

    r = q;
    *q++ = tls_handshake_type_serverhellodone;
    *q++ = 0;
    *q++ = 0;
    *q++ = 0;
    _sha256.Update(r, q - r);

    _write._len = q - _write._buf;
    _state = channel::state::needplaintext;
    _remain = 5;
}

void Channel::needClientKeyExchangeLen()
{
    uint8_t* p = prefetch(2);
    if (!p) return;
    _sha256.Update(p, 2);
    _clientKeyExchangeLen = (uint16_t)*p << 8 | *(p + 1);
    _read.Discard(2);
    if (!_clientKeyExchangeLen) {
        sendAlert(tls_alert_level_fatal, tls_alert_desc_param);
        _state = channel::state::done;
    } else {
        _state = channel::state::needclientkeyexchange;
    }
}

void Channel::needClientKeyExchange()
{
    uint8_t dec[128] = { 0 };
    uint8_t a1[sha256::hashbytes] = { 0 };
    uint8_t a2[sha256::hashbytes] = { 0 };
    uint8_t a3[sha256::hashbytes] = { 0 };
    uint8_t a4[sha256::hashbytes] = { 0 };

    uint8_t p1[sha256::hashbytes] = { 0 };
    uint8_t p2[sha256::hashbytes] = { 0 };

    uint8_t p[128] = { 0 };

    size_t len = _clientKeyExchangeLen;
    uint8_t* pp = prefetch(len);
    if (!pp) return;
    _sha256.Update(pp, len);
    setptr(&_clientKeyExchange, pp, len);
    _read.Discard(len);
    if (_remain) {
        sendAlert(tls_alert_level_fatal, tls_alert_desc_decode);
        _state = channel::state::done;
    } else if (len != _prvKey.N.bytes()) {
        sendAlert(tls_alert_level_fatal, tls_alert_desc_param);
        _state = channel::state::done;
    } else {
        //uint8_t* dec = (uint8_t*)calloc(len, 1);
        if (!_prvKey.Decrypt(dec, _clientKeyExchange, &len)) {
            sendAlert(tls_alert_level_fatal, tls_alert_desc_decrypt);
            _state = channel::state::done;
        } else if (len != 48) {
            sendAlert(tls_alert_level_fatal, tls_alert_desc_decrypt);
            _state = channel::state::done;
        } else if (dec[0] != 0x03 || dec[1] != 0x03) {
            sendAlert(tls_alert_level_fatal, tls_alert_desc_decrypt);
            _state = channel::state::done;
        } else {
            _hmac.SetDigestAlg(hmac::alg::sha256);
            _hmac.SetKey(dec, len);

            /*
            //------- BEGIN TEST CODE---------------------------
            // test key from tlsulfheim.net
            memcpy(_clientRandom,
                "\x00\x01\x02\x03\x04\x05\x06\x07"
                "\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
                "\x10\x11\x12\x13\x14\x15\x16\x17"
                "\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f", 32);
            memcpy(_serverRandom,
                "\x70\x71\x72\x73\x74\x75\x76\x77"
                "\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f"
                "\x80\x81\x82\x83\x84\x85\x86\x87"
                "\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f", 32);
            _hmac.setKey((uint8_t*)
                "\xdf\x4a\x29\x1b\xaa\x1e\xb7\xcf"
                "\xa6\x93\x4b\x29\xb4\x74\xba\xad"
                "\x26\x97\xe2\x9f\x1f\x92\x0d\xcc"
                "\x77\xc8\xa0\xa0\x88\x44\x76\x24", 32);
            //-------- END TEST CODE ---------------------------
            */

            //  A(1) <-- HMAC_256(secret, "master secret" + ClientHello.random + Serverhello.random)
            _hmac.Begin();
            _hmac.Update((uint8_t*)"master secret", 13);
            _hmac.Update(_clientRandom, 32);
            _hmac.Update(_serverRandom, 32);
            _hmac.End();
            _hmac.GetMAC(a1, sha256::hashbytes);

            //  A(2) <-- HMAC_256(secret, (A1))
            _hmac.Begin();
            _hmac.Update(a1, sha256::hashbytes);
            _hmac.End();
            _hmac.GetMAC(a2, sha256::hashbytes);

            //  P(1) <-- HMAC_256(secret, a1 + seed)
            _hmac.Begin();
            _hmac.Update(a1, sha256::hashbytes);
            _hmac.Update((uint8_t*)"master secret", 13);
            _hmac.Update(_clientRandom, 32);
            _hmac.Update(_serverRandom, 32);
            _hmac.End();
            _hmac.GetMAC(p1, sha256::hashbytes);

            //  P(2) <-- HMAC_256(secret, a2 + seed)
            _hmac.Begin();
            _hmac.Update(a2, sha256::hashbytes);
            _hmac.Update((uint8_t*)"master secret", 13);
            _hmac.Update(_clientRandom, 32);
            _hmac.Update(_serverRandom, 32);
            _hmac.End();
            _hmac.GetMAC(p2, sha256::hashbytes);

            memcpy(_masterSecret, p1, sha256::hashbytes);
            memcpy(&_masterSecret[sha256::hashbytes], p2, sizeof _masterSecret - sha256::hashbytes);

            //  A(1) <-- HMAC_256(master-secret, "key expansion" + ServerHello.random + ClientHello.random)
            _hmac.SetKey(_masterSecret, sizeof _masterSecret);
            _hmac.Begin();
            _hmac.Update((uint8_t*)"key expansion", 13);
            _hmac.Update(_serverRandom, 32);
            _hmac.Update(_clientRandom, 32);
            _hmac.End();
            _hmac.GetMAC(a1, sha256::hashbytes); // bytes 0-31

            //  A(2) <-- HMAC_256(master-secret, A(1))
            _hmac.Begin();
            _hmac.Update(a1, sha256::hashbytes);
            _hmac.End();
            _hmac.GetMAC(a2, sha256::hashbytes); // bytes 32-63

            //  A(3) <-- HMAC_256(master-secret, A(2))
            _hmac.Begin();
            _hmac.Update(a2, sha256::hashbytes);
            _hmac.End();
            _hmac.GetMAC(a3, sha256::hashbytes); // bytes 64-95

            //  A(4) <-- HMA_256(master-secret, A(3))
            _hmac.Begin();
            _hmac.Update(a3, sha256::hashbytes);
            _hmac.End();
            _hmac.GetMAC(a4, sha256::hashbytes); // bytes 96-127

            //  P(1) <-- HMAC_256(maseter-secret, a1 + seed)
            _hmac.Begin();
            _hmac.Update(a1, sha256::hashbytes);
            _hmac.Update((uint8_t*)"key expansion", 13);
            _hmac.Update(_serverRandom, 32);
            _hmac.Update(_clientRandom, 32);
            _hmac.End();
            _hmac.GetMAC(&p[0], sha256::hashbytes);

            //  P(2) <-- HMAC_256(master-secret, a2 + seed)
            _hmac.Begin();
            _hmac.Update(a2, sha256::hashbytes);
            _hmac.Update((uint8_t*)"key expansion", 13);
            _hmac.Update(_serverRandom, 32);
            _hmac.Update(_clientRandom, 32);
            _hmac.End();
            _hmac.GetMAC(&p[32], sha256::hashbytes);

            //  P(3) <-- HMAC_256(master-secret, a3 + seed)
            _hmac.Begin();
            _hmac.Update(a3, sha256::hashbytes);
            _hmac.Update((uint8_t*)"key expansion", 13);
            _hmac.Update(_serverRandom, 32);
            _hmac.Update(_clientRandom, 32);
            _hmac.End();
            _hmac.GetMAC(&p[64], sha256::hashbytes);

            //  P(4) <-- HMAC_256(master-secret, a4 + seed)
            _hmac.Begin();
            _hmac.Update(a4, sha256::hashbytes);
            _hmac.Update((uint8_t*)"key expansion", 13);
            _hmac.Update(_serverRandom, 32);
            _hmac.Update(_clientRandom, 32);
            _hmac.End();
            _hmac.GetMAC(&p[96], sha256::hashbytes);

            memcpy(_clientWriteMAC, &p[0], 20);
            memcpy(_serverWriteMAC, &p[20], 20);
            memcpy(_clientWriteKey, &p[40], 24);
            memcpy(_serverWriteKey, &p[64], 24);
            memcpy(_clientWriteIV, &p[88], 8);
            memcpy(_serverWriteIV, &p[96], 8);

            _haveClientKeyExchange = true;
            _remain = 5;
            _state = channel::state::needplaintext;
        }
    }
}

void Channel::needRecTypeChange()
{
    size_t len = _plainTextSize;
    uint8_t* p = prefetch(len);
    if (!p) return;
    //setptr(&_recTypeChange, p, len);
    _read.Discard(len);
    _haveChangeCipherSpec = true;
    _remain = 5;
    _state = channel::state::needplaintext;
}

void Channel::needDecryptedHandShake()
{
    uint8_t dec[128] = { 0 };
    size_t len = _plainTextSize;
    if (len % 8) {
        _state = channel::state::done;
        return;
    }
    uint8_t* p = prefetch(len);
    if (!p) return;

    // set des3cbc IV, Key
    _des3cbc.SetIV(_clientWriteIV);
    _des3cbc.SetKey(_clientWriteKey);

    uint8_t* q = dec;
    size_t k = len;
    for (; k; q += 8, p += 8, k -= 8)
        _des3cbc.Decrypt(p, q);

    uint8_t m0[sha256::hashbytes] = { 0 };
    uint8_t a1[sha256::hashbytes] = { 0 };
    uint8_t p1[sha256::hashbytes] = { 0 };
    _sha256.End();
    _sha256.GetDigest(m0);

    _hmac.SetKey(_masterSecret, sizeof _masterSecret);
    _hmac.Begin();
    _hmac.Update((uint8_t*)"client finished", 15);
    _hmac.Update(m0, sizeof m0);
    _hmac.End();
    _hmac.GetMAC(a1, sha256::hashbytes);
    _hmac.Begin();
    _hmac.Update(a1, sha256::hashbytes);
    _hmac.Update((uint8_t*)"client finished", 15);
    _hmac.Update(m0, sizeof m0);
    _hmac.End();
    _hmac.GetMAC(p1, sha256::hashbytes);
    // verify first 12 bytes of p1 match validation info

    HMAC sha1mac;
    uint8_t m1[sha1::hashbytes] = { 0 };
    sha1mac.SetDigestAlg(hmac::alg::sha1);
    sha1mac.SetKey(_clientWriteMAC, sizeof _clientWriteMAC);
    sha1mac.Begin();
    sha1mac.Update((uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00", 8); // use incrementing sequence nbr
    sha1mac.Update((uint8_t*)"\x16\x03\x03\x00\x10", 5);
    sha1mac.Update(&dec[8], 16);
    sha1mac.End();
    sha1mac.GetMAC(m1, sizeof m1);
    // verify m1 matches decrypted MAC

    // verify no _remain or alert

    putServerFinished();
}

void Channel::putServerFinished()
{
    _write.Reset();
    uint8_t* q = _write._buf;

    // change cipher spec
    *q++ = tls_rec_type_change;
    *q++ = 3;
    *q++ = 3; // tls 1.2
    *q++ = 0;
    *q++ = 1; // length
    *q++ = 1; // cipher spec changed

    // finished
    _random.Fill(q, 8); // random nonce
    q += 8;
    *q++ = tls_rec_type_change;
    *q++ = 0;
    *q++ = 0;
    *q++ = 12; // validation data length

    //uint8_t* r = q;
}

void Channel::needRequest()
{
    if (_write._len) {
        Write();
        if (_write._len)
            return;
    }
    if (_read._len) {
        char* p = (char*)&_read._buf[_read._head];
        char* q = (char*)&_read._buf[_read._head + _read._len];
        for (; p < q && '\n' != *p; p++);
        if ('\n' == *p) {
            _state = channel::state::haverequest;
            HaveRequest();
        } else
            Read();
    } else
        Read();
}

void Channel::HaveRequest()
{
    char req[256] = { 0 };
    char* p = (char*)&_read._buf[_read._head];
    size_t len = strcspn(p, "\r");
    memcpy(req, p, len < 255 ? len : 255);

    char* q = p;
    for (; *q && ' ' != *q; q++);
    if (q == p || ' ' != *q) {
        badRequest();
        return;
    }
    *q++ = 0;
    if (!checkHttpMethod(p)) {
        badRequest();
        return;
    }
    _read.Discard(q - p);
    for (p = q; *q && ' ' != *q; q++);
    if (q == p || ' ' != *q) {
        badRequest();
        return;
    }
    *q++ = 0;
    if (!_uri.Put(p)) {
        badRequest();
        return;
    }
    _read.Discard(q - p);
    for (p = q; *q && '\r' != *q; q++);
    if (q == p || '\r' != *q) {
        badRequest();
        return;
    }
    *q++ = 0;
    if ('\n' != *q++) {
        badRequest();
        return;
    }
    if (!checkHttpVersion(p)) {
        badRequest();
        return;
    }
    if (!checkHttpSupportedVersion(p)) {
        badRequest();
        return;
    }
    _read.Discard(q - p);
    _state = channel::state::needheader;
    NeedHTTPHeader();
}

void Channel::badRequest()
{
    _response = http_response_badrequest;
    putHttpResponseString(http_response_message_badrequest);
}

void Channel::putHttpResponseString(const char* buf)
{
    char ver[24] = { 0 };
    sprintf(ver, "%03u HTTP/%01u.%01u ", _response, _httpMajorVersion, _httpMinorVersion);
    _write.Reset();
    _write.Append(ver);
    _write.Append(buf);
    putHttpResponse();
}

void Channel::putHttpResponse()
{
    _read.Reset();
    _state = channel::state::done;
}

bool Channel::checkHttpMethod(char* p)
{
    if ('G' == *p && 'E' == *(p + 1) && 'T' == *(p + 2) && !*(p + 3)) {
        _httpMethod = http_method_get;
    } else if ('P' == *p && 'O' == *(p + 1) && 'S' == *(p + 2) && 'T' == *(p + 3) && !*(p + 4)) {
        _httpMethod = http_method_post;
    } else if ('P' == *p && 'U' == *(p + 1) && 'T' == *(p + 2) && !*(p + 3)) {
        _httpMethod = http_method_put;
    } else if ('H' == *p && 'E' == *(p + 1) && 'A' == *(p + 2) && 'D' == *(p + 3) && !*(p + 4)) {
        _httpMethod = http_method_head;
    } else if ('O' == *p && 'P' == *(p + 1) && 'T' == *(p + 2) && 'I' == *(p + 3) && 'O' == *(p + 4) && 'N' == *(p + 5) && 'S' == *(p + 6) && !*(p + 7)) {
        _httpMethod = http_method_options;
    } else if ('C' == *p && 'O' == *(p + 1) && 'N' == *(p + 2) && 'N' == *(p + 3) && 'E' == *(p + 4) && 'C' == *(p + 5) && 'T' == *(p + 6) && !*(p + 7)) {
        _httpMethod = http_method_connect;
    } else if ('T' == *p && 'R' == *(p + 1) && 'A' == *(p + 2) && 'C' == *(p + 3) && 'E' == *(p + 4) && !*(p + 5)) {
        _httpMethod = http_method_trace;
    } else
        return false;
    return true;
}

bool Channel::checkHttpVersion(char* p)
{
    if (('H' != *p || 'T' != *(p + 1) || 'T' != *(p + 2) || 'P' != *(p + 3) || '/' != *(p + 4))
        || ('0' != *(p + 5) && '1' != *(p + 5)) || ('.' != *(p + 6))
        || ('9' != *(p + 7) && '0' != *(p + 7) && '1' != *(p + 7)) || *(p + 8))
        return false;
    return true;
}

bool Channel::checkHttpSupportedVersion(char* p)
{
    if ('0' == *(p + 5) && '9' == *(p + 7)) {
        _httpMajorVersion = 0;
        _httpMinorVersion = 9;
    } else if ('1' == *(p + 5) && '0' == *(p + 7)) {
        _httpMajorVersion = 1;
        _httpMinorVersion = 0;
    } else if ('1' == *(p + 5) && '1' == *(p + 7)) {
        _httpMajorVersion = 1;
        _httpMinorVersion = 1;
    } else
        return false;
    return true;
}

void Channel::badVersion()
{
    _response = http_response_badversion;
    putHttpResponseString(http_response_message_badversion);
}

void Channel::NeedHTTPHeader()
{
    if (_write._len) {
        Write();
        if (_write._len)
            return;
    }
    if (_read._len) {
        char* p = (char*)&_read._buf[_read._head];
        char* q = (char*)&_read._buf[_read._head + _read._len];
        for (; p < q && '\n' != *p; p++);
        if ('\n' == *p) {
            _state = channel::state::haveheader;
            HaveHTTPHeader();
        } else
            Read();
    } else
        Read();
}

void Channel::HaveHTTPHeader()
{
    char* p = (char*)&_read._buf[_read._head];
    if ('\r' == *p && '\n' == *(p + 1)) {
        _state = channel::state::needbody;
        NeedHTTPBody();
    } else {
        SaveHTTPHeader(p);
        _state = channel::state::needheader;
        NeedHTTPHeader();
    }
}

void Channel::SaveHTTPHeader(char* p)
{
    char* q = p;
    for (; *q && '\n' != *q; q++);
    _read.Discard(++q - p);
}

void Channel::NeedHTTPBody()
{
    if (_socket.Readable()) {
        _read.Discard(_read._len);
        Read();
    } else {
        _state = channel::state::havebody;
        HaveHTTPBody();
    }
}

void Channel::HaveHTTPBody()
{
    _write.Reset();
    time_t t = 0;
    time(&t);
    struct tm m = { 0 };
    memcpy(&m, gmtime(&t), sizeof(m));
    char date[30] = { 0 };
    sprintf(date, "%s, %u %s %u %02u:%02u:%02u GMT",
        DayName[m.tm_wday], m.tm_mday, MonthName[m.tm_mon], m.tm_year + 1900,
        m.tm_hour, m.tm_min, m.tm_sec);
    char ip[16] = { 0 };
    sprintf(ip, "%lu.%lu.%lu.%lu",
        (_remoteAddr >> 24) & 255, (_remoteAddr >> 16) & 255,
        (_remoteAddr >> 8) & 255, _remoteAddr & 255);
    char body[768] = { 0 };
    sprintf(body, "%s%s%s",
        ok_1, ip, ok_2);
    char hdr[256] = { 0 };
    sprintf(hdr, ok_0, _httpMajorVersion, _httpMinorVersion, date, strlen(body));
    _write.Append(hdr);
    _write.Append(body);
    _state = channel::state::done;
    Done();
}

void Channel::Service()
{
    if (time(0) > _expires) {
        _state = channel::state::done;
    }
    switch (_state) {
    case channel::state::connected:
        Connected();
        break;
    case channel::state::needfirstbytes:
        NeedFirstBytes();
        break;
    case channel::state::needplaintext:
        needPlainText();
        break;
    case channel::state::needhandshake:
        needHandShake();
        break;
    case channel::state::needclienthelloversion:
        needClientHelloVersion();
        break;
    case channel::state::needclienthellorandom:
        needClientHelloRandom();
        break;
    case channel::state::needclienthellosessionidlen:
        needClientHelloSessionIdLen();
        break;
    case channel::state::needclienthellosessionid:
        needClientHelloSessionId();
        break;
    case channel::state::needclienthellociphersuiteslen:
        needClientHelloCipherSuitesLen();
        break;
    case channel::state::needclienthellociphersuites:
        needClientHelloCipherSuites();
        break;
    case channel::state::needclienthellocompressionmethodslen:
        needClientHelloCompressionMethodsLen();
        break;
    case channel::state::needclienthellocompressionmethods:
        needClientHelloCompressionMethods();
        break;
    case channel::state::needclienthelloextensionslen:
        needClientHelloExtensionsLen();
        break;
    case channel::state::needclienthelloextensions:
        needClientHelloExtensions();
        break;
    case channel::state::needclientkeyexchangelen:
        needClientKeyExchangeLen();
        break;
    case channel::state::needclientkeyexchange:
        needClientKeyExchange();
        break;
    case channel::state::needrectypechange:
        needRecTypeChange();
        break;
    case channel::state::needdecryptedhandshake:
        needDecryptedHandShake();
        break;
    case channel::state::needrequest:
        needRequest();
        break;
    case channel::state::haverequest:
        HaveRequest();
        break;
    case channel::state::needheader:
        NeedHTTPHeader();
        break;
    case channel::state::haveheader:
        HaveHTTPHeader();
        break;
    case channel::state::needbody:
        NeedHTTPBody();
        break;
    case channel::state::havebody:
        HaveHTTPBody();
        break;
    default:
        Done();
    }
}
