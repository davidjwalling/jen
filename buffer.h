#pragma once

#include "api.h"

class Buffer {
public:
    size_t _len;
    size_t _head;
    uint8_t _buf[2048];

    Buffer();
    ~Buffer();
    void Init();
    void Reset();
    size_t Avail();
    void Front();
    uint8_t* Discard(size_t len);
    void Append(char* buf);
    void Append(const char* buf);
    void Append(const uint8_t* buf, size_t len);
    uint8_t* Emit(uint8_t* buf, size_t len);
};
