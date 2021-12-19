#pragma once

#include "api.h"

namespace cond {
    namespace socket {
        enum {
            start = cond_base_socket,
            socket,
            datagram,
            block,
            reuse,
            bind,
            listen,
            select,
            accept,
            getpeername,
            keepalive,
            recv,
            send,
            recvfrom,
            sendto,
            shutdown,
            close
        };
        namespace message {
            const char* const socket = "socket error:";
            const char* const datagram = "datagram error:";
            const char* const block = "nonblock error:";
            const char* const reuse = "reuseaddr error:";
            const char* const bind = "bind error:";
            const char* const listen = "listen error:";
            const char* const select = "select error:";
            const char* const accept = "accept error:";
            const char* const getpeername = "getpeername error:";
            const char* const keepalive = "keepalive error:";
            const char* const recv = "recv error:";
            const char* const send = "send error:";
            const char* const recvfrom = "recvfrom error:";
            const char* const sendto = "sendto error:";
            const char* const shutdown = "shutdown error:";
            const char* const close = "close error:";
        }
    }
}

class Socket {
public:
    SOCKET _socket;
    uint32_t _addr;
    uint32_t _remoteAddr;
    uint16_t _port;
    uint16_t _remotePort;

    Socket();
    ~Socket();
    void Init();
    void Reset();
    bool Readable();
    bool Writable();
    bool Stream();
    bool Datagram();
    bool Bind();
    bool Listen();
    SOCKET Accept();
    bool Read(uint8_t *buf, size_t *ret);
    bool Write(uint8_t *buf, size_t *ret);
    bool Get(uint8_t *buf, size_t *ret);
    bool Put(uint8_t *buf, size_t *ret);
    bool Shutdown();
    bool Close();
};
