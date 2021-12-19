#include "file.h"
#include "log.h"

File::File()
{
    Init();
}

File::~File()
{
    Reset();
}

void File::Init()
{
    _attrs = 0;
    _size = 0;
    _name = nullptr;
    _fd = nullptr;
}

void File::Reset()
{
    freestr(&_name);

    Init();
}

bool File::Exists()
{
    struct _stat64 sb = { 0 };
    if (_name) {
        long lresult = _stat64(_name, &sb);
        if (lresult) {
            osErr(errno);
            appErr(cond::file::stat);
            return false;
        }
        if (((S_ISREG(sb.st_mode)) && (sb.st_mode & S_IRUSR)) || ((S_ISDIR(sb.st_mode)))) {
            _attrs = sb.st_mode;
            _size = (size_t)sb.st_size;
            return true;
        }
    }
    return false;
}

bool File::Open()
{
    _fd = fopen(_name, "r+b");
    if (!_fd) {
        osErr(errno);
        appErr(cond::file::open);
        return false;
    }
    return true;
}

bool File::Read(void* buf, size_t* len)
{
    *len = fread(buf, 1, *len, _fd);
    if (ferror(_fd)) {
        appErr(cond::file::read);
        return false;
    }
    return true;
}

bool File::Write(void* buf, size_t* len)
{
    *len = fwrite(buf, 1, *len, _fd);
    if (ferror(_fd)) {
        appErr(cond::file::write);
        return false;
    }
    if (EOF == fflush(_fd))
        return false;
    return true;
}

void File::ReadLine(char* buf, size_t* len)
{
    size_t remain = *len;
    size_t returned = 0;
    char ch = (char)fgetc(_fd);
    while (!feof(_fd)) {
        if (remain) {
            *buf++ = ch;
            returned++;
            remain--;
        }
        if ('\n' == ch)
            break;
        ch = (char)fgetc(_fd);
    }
    *buf = 0;
    *len = returned;
}

bool File::Close()
{
    if (_fd) {
        if (fclose(_fd)) {
            osErr(errno);
            appErr(cond::file::close);
            return false;
        }
        _fd = 0;
    }
    return true;
}
