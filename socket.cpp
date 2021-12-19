#include "socket.h"
#include "log.h"

Socket::Socket()
{
    Init();
}

Socket::~Socket()
{
    Reset();
}

void Socket::Init()
{
    _socket = 0;
    _addr = 0;
    _remoteAddr = 0;
    _port = 1143;
    _remotePort = 0;
}

void Socket::Reset()
{
    Init();
}

bool Socket::Readable()
{
    if (_socket) {
        fd_set rfds = { 0 };
        FD_SET(_socket, &rfds);
        struct timeval tv = { 0, 10 };
        if (select((int)_socket + 1, &rfds, 0, 0, &tv) > 0)
            return true;
    }
    return false;
}

bool Socket::Writable()
{
    if (_socket) {
        fd_set wfds = { 0 };
        FD_SET(_socket, &wfds);
        struct timeval tv = { 0, 10 };
        if (select((int)_socket + 1, 0, &wfds, 0, &tv) > 0)
            return true;
    }
    return false;
}

bool Socket::Stream()
{
    _socket = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    if (INVALID_SOCKET == _socket) {
        osErr(WSAGetLastError());
        appErr(cond::socket::socket);
        return false;
    }
#if defined(_WIN32)
    unsigned long nonblock = 1;
    if (ioctlsocket(_socket, FIONBIO, &nonblock)) {
#else
    if (SOCKET_ERROR == fcntl(_socket, F_SETFL, O_NONBLOCK)) {
#endif
        osErr(WSAGetLastError());
        appErr(cond::socket::block);
        closesocket(_socket);
        _socket = 0;
        return false;
    }
    return true;
}

bool Socket::Datagram()
{
    _socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (INVALID_SOCKET == _socket) {
        osErr(WSAGetLastError());
        appErr(cond::socket::datagram);
        return false;
    }
#if defined(_WIN32)
    unsigned long nonblock = 1;
    if (ioctlsocket(_socket, FIONBIO, &nonblock)) {
#else
    if (SOCKET_ERROR == fcntl(_socket, F_SETFL, O_NONBLOCK)) {
#endif
        osErr(WSAGetLastError());
        appErr(cond::socket::block);
        closesocket(_socket);
        _socket = 0;
        return false;
    }
    return true;
}

bool Socket::Bind()
{
    int on = 1;
    if (setsockopt(_socket, SOL_SOCKET, SO_REUSEADDR, (char*)&on, sizeof on)) {
        osErr(WSAGetLastError());
        appErr(cond::socket::reuse);
        return false;
    }
    struct sockaddr_in sa = { 0 };
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(_addr);
    sa.sin_port = htons(_port);
    if (bind(_socket, (struct sockaddr*)(&sa), sizeof(sa))) {
        osErr(WSAGetLastError());
        appErr(cond::socket::bind);
        return false;
    }
    return true;
}

bool Socket::Listen()
{
    if (::listen(_socket, SOMAXCONN)) {
        osErr(WSAGetLastError());
        appErr(cond::socket::listen);
        return false;
    }
    return true;
}

SOCKET Socket::Accept()
{
    fd_set rfds = { 0 };
    FD_SET(_socket, &rfds);
    struct timeval tv = { 0, 10 };
    int n = select((int)_socket + 1, &rfds, 0, 0, &tv);
    if (!n)
        return 0;
    if (n < 0) {
        osErr(WSAGetLastError());
        if (EINTR != osErr()) {
            appErr(cond::socket::select);
        }
        return 0;
    }
    socklen_t addrlen = sizeof(struct sockaddr);
    struct sockaddr addr = { 0 };
    SOCKET client = accept(_socket, &addr, &addrlen);
    if (INVALID_SOCKET == client) {
        osErr(WSAGetLastError());
        appErr(cond::socket::accept);
        return 0;
    }
    struct sockaddr sa = { 0 };
    socklen_t len = sizeof(struct sockaddr);
    if (getpeername(client, &sa, &len)) {
        osErr(WSAGetLastError());
        appErr(cond::socket::getpeername);
        closesocket(client);
        return 0;
    }
    _remoteAddr = ((struct sockaddr_in*)(&sa))->sin_addr.s_addr;
    _remoteAddr = htonl(_remoteAddr);
    _remotePort = ((struct sockaddr_in*)(&sa))->sin_port;
    _remotePort = htons(_remotePort);
    int ka = 1;
    int rc = setsockopt(client, SOL_SOCKET, SO_KEEPALIVE, (char*)&ka, sizeof(ka));
    if (rc) {
        osErr(WSAGetLastError());
        appErr(cond::socket::keepalive);
        closesocket(client);
        return 0;
    }
    return client;
}

bool Socket::Read(uint8_t* buf, size_t* ret)
{
    size_t len = *ret;
    *ret = 0;
    int count = recv(_socket, (char*)buf, (int)len, 0);
    if (!count)
        return false;
    if (count < 0) {
        int err = WSAGetLastError();
        if (WSAEWOULDBLOCK == err)
            return true;
        osErr(err);
        appErr(cond::socket::recv);
        return false;
    }
    *ret = count;
    return true;
}

bool Socket::Write(uint8_t* buf, size_t* ret)
{
    size_t len = *ret;
    *ret = 0;
    int count = send(_socket, (char*)buf, (int)len, 0);
    if (count < 0) {
        int err = WSAGetLastError();
        if ((WSAEWOULDBLOCK != err) && (WSAENOBUFS != err)) {
            osErr(err);
            appErr(cond::socket::send);
            return false;
        }
    }
    *ret = count;
    return true;
}

bool Socket::Get(uint8_t* buf, size_t* ret)
{
    size_t len = *ret;
    *ret = 0;
    struct sockaddr_in addr = { 0 };
    socklen_t addrLen = sizeof addr;
    int count = recvfrom(_socket, (char*)buf, (int)len, 0, (struct sockaddr*)&addr, &addrLen);
    if (!count)
        return false;
    if (count < 0) {
        int err = WSAGetLastError();
        if (WSAEWOULDBLOCK == err)
            return true;
        osErr(err);
        appErr(cond::socket::recvfrom);
        return false;
    }
    _remoteAddr = htonl(addr.sin_addr.s_addr);
    _remotePort = htons(addr.sin_port);
    *ret = count;
    return true;
}

bool Socket::Put(uint8_t* buf, size_t* ret)
{
    size_t len = *ret;
    *ret = 0;
    struct sockaddr_in addr = { 0 };
    int addrlen = sizeof addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(_remotePort);
    addr.sin_addr.s_addr = htonl(_remoteAddr);
    int count = sendto(_socket, (char*)buf, (int)len, 0, (const sockaddr*)&addr, addrlen);
    if (!count)
        return false;
    if (count < 0) {
        int err = WSAGetLastError();
        if (WSAEWOULDBLOCK == err)
            return true;
        osErr(err);
        appErr(cond::socket::sendto);
        return false;
    }
    *ret = count;
    return true;
}

bool Socket::Shutdown()
{
    if (_socket) {
        if (shutdown(_socket, 2)) {
            int rc = WSAGetLastError();
            if (WSAENOTCONN != rc) {
                osErr(rc);
                appErr(cond::socket::shutdown);
                return false;
            }
        }
    }
    return true;
}

bool Socket::Close()
{
    if (_socket) {
        if (closesocket(_socket)) {
            osErr(WSAGetLastError());
            appErr(cond::socket::close);
            return false;
        }
        _socket = 0;
    }
    return true;
}
