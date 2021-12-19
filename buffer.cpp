#include "buffer.h"

Buffer::Buffer()
{
    Init();
}

Buffer::~Buffer()
{
    Reset();
}

void Buffer::Init()
{
    _len = 0;
    _head = 0;
    memset(_buf, 0, sizeof _buf);
}

void Buffer::Reset()
{
    Init();
}

size_t Buffer::Avail()
{
    return (sizeof _buf) - _len;
}

void Buffer::Front()
{
    if (_head && _len) {
        memcpy(_buf, &_buf[_head], _len);
        _head = 0;
    }
}

uint8_t* Buffer::Discard(size_t len)
{
    if (len > _len)
        len = _len;
    _head += len;
    _len -= len;
    if (!_len)
        _head = 0;
    return &_buf[_head];
}

void Buffer::Append(char *buf)
{
    size_t len = strlen(buf);
    Append((const uint8_t*)buf, len);
}

void Buffer::Append(const char* buf)
{
    size_t len = strlen(buf);
    Append((const uint8_t*)buf, len);
}

void Buffer::Append(const uint8_t* buf, size_t len)
{
    if (len) {
        if (_head) {
            memcpy(_buf, &_buf[_head], _len);
            _head = 0;
        }
        size_t fit = (sizeof _buf) - _len;
        if (fit > len)
            fit = len;
        memcpy(&_buf[_len], buf, fit);
        _len += fit;
    }
}

uint8_t* Buffer::Emit(uint8_t* buf, size_t len)
{
    if (len > _len)
        len = _len;
    if (len && buf)
        memcpy(buf, &_buf[_head], len);
    return Discard(len);
}
