#pragma once

#include "api.h"
#include "buffer.h"
#include "des.h"
#include "hmac.h"
#include "random.h"
#include "rsa.h"
#include "sha.h"
#include "socket.h"
#include "uri.h"

enum {
    http_method_unspecified = 0,
    http_method_connect,
    http_method_get,
    http_method_head,
    http_method_options,
    http_method_post,
    http_method_put,
    http_method_trace
};

enum {
    http_response_unspecified = 0,
    http_response_ok = 200,
    http_response_badrequest = 400,
    http_response_badversion = 505
};

enum {
    tls_alert_level_warning = 1,
    tls_alert_level_fatal = 2
};

enum {
    tls_alert_desc_unexpected = 10,
    tls_alert_desc_param = 47,
    tls_alert_desc_decode = 50,
    tls_alert_desc_decrypt = 51,
    tls_alert_desc_version = 70
};

enum {
    tls_rec_type_change = 20,
    tls_rec_type_alert = 21,
    tls_rec_type_handshake = 22,
    tls_rec_type_data = 23
};

enum {
    tls_handshake_type_helloreq = 0,
    tls_handshake_type_clienthello = 1,
    tls_handshake_type_serverhello = 2,
    tls_handshake_type_certificate = 11,
    tls_handshake_type_serverkeyexchange = 12,
    tls_handshake_type_certificaterequest = 13,
    tls_handshake_type_serverhellodone = 14,
    tls_handshake_type_certificateverify = 15,
    tls_handshake_type_clientkeyexchange = 16,
    tls_handshake_type_finished = 20,
    tls_handshake_type_unspecified = 255
};

namespace cond {
    namespace channel {
        enum {
            state = cond_base_channel,
            request,
            timeout
        };
    }
}

namespace channel {
    namespace state {
        enum {
            ready = 0,
            connected,
            needfirstbytes,
            needplaintext,
            needhandshake,
            needclienthelloversion,
            needclienthellorandom,
            needclienthellosessionidlen,
            needclienthellosessionid,
            needclienthellociphersuiteslen,
            needclienthellociphersuites,
            needclienthellocompressionmethodslen,
            needclienthellocompressionmethods,
            needclienthelloextensionslen,
            needclienthelloextensions,
            needclientkeyexchangelen,
            needclientkeyexchange,
            needrectypechange,
            needdecryptedhandshake,
            needrequest,
            haverequest,
            needheader,
            haveheader,
            needbody,
            havebody,
            done
        };
    }
}



class Channel {
public:

    bool _shutdown;
    bool _haveClientHello;
    bool _haveClientKeyExchange;
    bool _haveChangeCipherSpec;

    int _id;
    int _state;

    time_t _expires;
    size_t _certLen;
    size_t _remain;

    uint32_t _remoteAddr;
    uint32_t _handShakeSize;

    uint16_t _remotePort;
    uint16_t _plainTextVersion;
    uint16_t _plainTextSize;
    uint16_t _clientHelloVersion;
    uint16_t _cipherSuitesLen;
    uint16_t _extensionsLen;
    uint16_t _clientKeyExchangeLen;
    uint16_t _response;

    uint8_t _recType;
    uint8_t _handShakeRecType;
    uint8_t _sessionIdLen;
    uint8_t _compressionMethodsLen;
    uint8_t _httpMethod;
    uint8_t _httpMajorVersion;
    uint8_t _httpMinorVersion;

    uint8_t* _cert;
    uint8_t* _cipherSuites;
    uint8_t* _compressionMethods;
    uint8_t* _extensions;
    uint8_t* _clientKeyExchange;

    Channel* _prev;
    Channel* _next;

    uint8_t _clientRandom[32];
    uint8_t _sessionId[32];
    uint8_t _serverRandom[32];
    uint8_t _preMasterSecret[32];
    uint8_t _masterSecret[48];

    uint8_t _clientWriteMAC[20];
    uint8_t _serverWriteMAC[20];
    uint8_t _clientWriteKey[24];
    uint8_t _serverWriteKey[24];
    uint8_t _clientWriteIV[8];
    uint8_t _serverWriteIV[8];

    Random _random;
    HMAC _hmac;
    URI _uri;
    Socket _socket;
    Buffer _read;
    Buffer _message;
    Buffer _write;
    RSA _pubKey;
    RSA _prvKey;
    DES3CBC _des3cbc;
    SHA256 _sha256;

    Channel();
    ~Channel();
    void Init();
    void Reset();
    void Read();
    void Write();
    void HaveRequest();
    void Service();

    void Connected();
    void NeedFirstBytes();
    void Done();
    void Clear();

    //  TLS
    void needPlainText();
    uint8_t* prefetch(size_t n);
    void sendAlert(const uint8_t level, const uint8_t desc);
    void needHandShake();
    void needClientHelloVersion();
    void needClientHelloRandom();
    void needClientHelloSessionIdLen();
    void needClientHelloSessionId();
    void needClientHelloCipherSuitesLen();
    void needClientHelloCipherSuites();
    void needClientHelloCompressionMethodsLen();
    void needClientHelloCompressionMethods();
    void needClientHelloExtensionsLen();
    void needClientHelloExtensions();
    void putServerHello();
    void needClientKeyExchangeLen();
    void needClientKeyExchange();
    void needRecTypeChange();
    void needDecryptedHandShake();
    void putServerFinished();

    //  http
    void needRequest();
    void badRequest();
    void putHttpResponseString(const char* buf);
    void putHttpResponse();
    bool checkHttpMethod(char* p);
    bool checkHttpVersion(char* p);
    bool checkHttpSupportedVersion(char* p);
    void badVersion();
    void NeedHTTPHeader();
    void HaveHTTPHeader();
    void SaveHTTPHeader(char* p);
    void NeedHTTPBody();
    void HaveHTTPBody();
};
