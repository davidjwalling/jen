#pragma once

#include "api.h"

namespace cond {
    namespace file {
        enum {
            stat = cond_base_file,
            open,
            read,
            write,
            close
        };
    }
}

class File {
public:
    int _attrs;
    size_t _size;
    char* _name;
    FILE* _fd;

    File();
    ~File();
    void Init();
    void Reset();
    bool Exists();
    bool Open();
    bool Read(void* buf, size_t* len);
    bool Write(void* buf, size_t* len);
    void ReadLine(char* buf, size_t* len);
    bool Close();
};
