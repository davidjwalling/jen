#include "api.h"

#if !defined(_WIN32)
void GetSystemTime(SYSTEMTIME* system_time)
{
    time_t t;
    struct timeval tv;
    struct tm* tm;
    gettimeofday(&tv, 0);
    t = tv.tv_sec;
    tm = gmtime(&t);
    system_time->wYear = tm->tm_year + 1900;
    system_time->wMonth = tm->tm_mon + 1;
    system_time->wDay = tm->tm_mday;
    system_time->wHour = tm->tm_hour;
    system_time->wMinute = tm->tm_min;
    system_time->wSecond = tm->tm_sec;
    system_time->wMilliseconds = tv.tv_usec / 1000;
}
#endif

void catmem(uint8_t** d, uint8_t* s, size_t len)
{
    if (d && *d && s && len) {
        memcpy(*d, s, len);
        *d += len;
    }
}

void catstr(uint8_t** d, const char* s, size_t* len)
{
    catstr((char**)d, s, len);
}

void catstr(char** d, const char* s, size_t* len)
{
    if ((d) && (*d) && (s) && (len)) {
        *len = strlen(s);
        memcpy(*d, s, *len);
        *d += *len;
    }
}

int cmpstr(const char* d, char* s)
{
    return strcmp(d, s);
}

bool datetimecheck(uint8_t* s, struct tm* tmOut)
{
    if (!s)
        return false;
    uint8_t* p = s;
    if (*p < '0' || *p > '9')
        return false;
    int n = (int)(*p++ - '0');
    struct tm tmT = { 0 };
    bool mdy = false;
    if ('/' == *p) {
        mdy = true;
        if (n < 1)
            return false;
        tmT.tm_mon = n - 1;
        p++;
    } else {
        if (*p < '0' || *p > '9')
            return false;
        n = n * 10 + (int)(*p++ - '0');
        if ('/' == *p) {
            mdy = true;
            if (n < 1 || n > 12)
                return false;
            tmT.tm_mon = n - 1;
            p++;
        }
    }
    if (mdy) {
        if (*p < '0' || *p > '9')
            return false;
        n = (int)(*p++ - '0');
        if ('/' == *p) {
            if (n < 1)
                return false;
            tmT.tm_mday = n;
        } else {
            if (*p < '0' || *p > '9')
                return false;
            n = n * 10 + (int)(*p++ - '0');
            if ('/' != *p)
                return false;
            if (n < 1 || n > 31)
                return false;
            tmT.tm_mday = n;
        }
        p++;
        if (*p < '0' || *p > '9')
            return false;
        n = (int)(*p++ - '0');
        if (*p < '0' || *p > '9')
            return false;
        n = n * 10 + (int)(*p++ - '0');
        if (!*p || ' ' == *p) {
            if (n < 50)
                n += 100;
            n += 1900;
        } else {
            if (*p < '0' || *p > '9')
                return false;
            n = n * 10 + (int)(*p++ - '0');
            if (*p < '0' || *p > '9')
                return false;
            n = n * 10 + (int)(*p++ - '0');
            if (*p && ' ' != *p)
                return false;
        }
        tmT.tm_year = n - 1900;
        if (*p++) {
            if (*p < '0' || *p > '9')
                return false;
            n = (int)(*p++ - '0');
            if (*p < '0' || *p > '9')
                return false;
            n = n * 10 + (int)(*p++ - '0');
            if (n > 59)
                return false;
            tmT.tm_hour = n;
            if (':' != *p++)
                return false;
            if (*p < '0' || *p > '9')
                return false;
            n = (int)(*p++ - '0');
            if (*p < '0' || *p > '9')
                return false;
            n = n * 10 + (int)(*p++ - '0');
            if (n > 59)
                return false;
            tmT.tm_min = n;
            if (*p) {
                if (':' != *p++)
                    return false;
                if (*p < '0' || *p > '9')
                    return false;
                n = (int)(*p++ - '0');
                if (*p < '0' || *p > '9')
                    return false;
                n = n * 10 + (int)(*p++ - '0');
                if (*p)
                    return false;
                if (n > 59)
                    return false;
                tmT.tm_sec = n;
            }
        }
    } else {
        n = (int)strlen((const char*)s);
        if (17 != n && 14 != n && 12 != n && 8 != n)
            return false;
        for (p = s; *p && (*p >= '0' && *p <= '9'); p++);
        if (*p)
            return false;
        p = s;
        tmT.tm_yday = 0;
        tmT.tm_wday = 0;
        tmT.tm_year = (*p & 15) * 1000 + (*(p + 1) & 15) * 100 + (*(p + 2) & 15) * 10 + (*(p + 3) & 15) - 1900;
        if (tmT.tm_year < 0)
            return false;
        tmT.tm_mon = (*(p + 4) & 15) * 10 + (*(p + 5) & 15) - 1;
        if (tmT.tm_mon < 0 || tmT.tm_mon > 11)
            return false;
        tmT.tm_mday = (*(p + 6) & 15) * 10 + (*(p + 7) & 15);
        if (tmT.tm_mday < 1 || tmT.tm_mday > 31)
            return false;
        if (n >= 12) {
            tmT.tm_hour = (*(p + 8) & 15) * 10 + (*(p + 9) & 15);
            if (tmT.tm_hour < 0 || tmT.tm_hour > 23)
                return false;
            tmT.tm_min = (*(p + 10) & 15) * 10 + (*(p + 11) & 15);
            if (tmT.tm_min < 0 || tmT.tm_hour > 59)
                return false;
            if ((n >= 14)) {
                tmT.tm_sec = (*(p + 12) & 15) * 10 + (*(p + 13) & 15);
                if (tmT.tm_sec < 0 || tmT.tm_sec > 59)
                    return false;
            }
        }
    }
    if (tmOut)
        memcpy(tmOut, &tmT, sizeof tmT);
    return true;
}

void datetimeclock(uint8_t* out)
{
    time_t t = time(nullptr);
    clock_t c = clock();
    uint8_t* q = out;
    *q++ = ((t >> 24) & 255);
    *q++ = ((t >> 16) & 255);
    *q++ = ((t >> 8) & 255);
    *q++ = (t & 255);
    *q++ = ((c >> 24) & 255);
    *q++ = ((c >> 16) & 255);
    *q++ = ((c >> 8) & 255);
    *q++ = (c & 255);
}

uint8_t* derfix(uint8_t* p, uint8_t* s)
{
    size_t h;
    if (p > s) {
        h = p - s;
        if (h < 128) {
            *(s - 3) = (uint8_t)h;
            if (h)
                memcpy(s - 2, s, h);
            p -= 2;
        } else if (h < 256) {
            *(s - 3) = 0x81;
            *(s - 2) = (uint8_t)h;
            memcpy(s - 1, s, h);
            p--;
        } else {
            *(s - 2) = (uint8_t)(h >> 8);
            *(s - 1) = (uint8_t)(h & 255);
        }
    }
    return p;
}

char* dupstr(const char* s)
{
    char* d = 0;
    if (s) {
        size_t len = strlen(s);
        d = (char*)calloc(len + 1, 1);
        if (d) {
            if (len)
                memcpy(d, s, len);
            d[len] = 0;
        }
    }
    return d;
}

void freeptr(uint8_t** ptr)
{
    if (ptr && *ptr) {
        free(*ptr);
        *ptr = 0;
    }
}

void freestr(char** ptr)
{
    if (ptr && *ptr) {
        free(*ptr);
        *ptr = 0;
    }
}

char* ltrim(char* s)
{
    if (s && *s) {
        char* p = s;
        char* q = s;
        for (; ' ' == *p || '\t' == *p; p++);
        if (p <= s)
            return s;
        for (; *p; *q++ = *p++);
        *q++ = '\0';
    }
    return s;
}

char* rtrim(char* s)
{
    if (s) {
        char* p = s;
        char* q = s + strlen(s) - 1;
        for (; q >= p && (' ' == *q || '\t' == *q); *q-- = '\0');
    }
    return s;
}

void setptr(uint8_t** ptr, uint8_t* s, size_t len)
{
    if (!ptr)
        return;
    if ((s) && (s == *ptr))
        return;
    freeptr(ptr);
    if (!len)
        return;
    *ptr = (uint8_t*)calloc(len + 1, 1);
    if (!*ptr)
        return;
    if (s) {
        memcpy(*ptr, s, len);
        (*ptr)[len] = '\0';
    } else {
        memset(*ptr, 0, len + 1);
    }
}

void setstr(char** ptr, const char* s)
{
    if (ptr && *ptr != s) {
        freestr(ptr);
        *ptr = dupstr(s);
    }
}

void setunstr(char** d, char* s)
{
    setstr(d, s);
    unstr(*d, *d);
}

char* tokstrq(char* s, const char* d, const char* x, char** p)
{
    char* t, * f;
    const char* e;
    unsigned int inq = 0;
    if (p) {
        if (!s)
            s = *p;
        *p = 0;
    }
    if (!s || !(*s))
        return 0;
    t = s;
    if (d) {
        for (; *t; t++) {
            if ('\"' == *t)
                inq ^= 1;
            if (!inq) {
                for (e = d; *e && *t != *e; e++);
                if (!(*e))
                    break;
            }
        }
        if (!(*t))
            return 0;
    }
    f = t;
    if (x) {
        for (; *t; t++) {
            if ('\"' == *t)
                inq ^= 1;
            if (!inq) {
                for (e = x; *e && *t != *e; e++);
                if (*e) {
                    *t = 0;
                    if (p)
                        *p = t + 1;
                    break;
                }
            }
        }
    }
    return f;
}

char* tokstrx(char* s, const char* d, const char* x, char** p)
{
    char* t, * f;
    const char* e;
    if (p) {
        if (!s)
            s = *p;
        *p = 0;
    }
    if (!s || !(*s))
        return 0;
    t = s;
    if (d) {
        for (; *t; t++) {
            for (e = d; *e && *e != *t; e++);
            if (!(*e))
                break;
        }
        if (!(*t))
            return 0;
    }
    f = t;
    if (x) {
        for (; *t; t++) {
            for (e = x; *e && *t != *e; e++);
            if (*e) {
                *t = 0;
                if (p)
                    *p = t + 1;
                break;
            }
        }
    }
    return f;
}

char* unstr(char* d, char* s)
{
    char* p, * q;
    int c, t, state;
    if (d && s) {
        state = 0;
        for (t = 0, q = d, p = s; *p; p++) {
            c = *p;
            if (1 == state) {
                if ('%' == c) {
                    *q++ = '%';
                    state = 0;
                } else {
                    if (c >= '0' && c <= '9')
                        t = (c - (int)'0') << 4;
                    else if (c >= 'A' && c <= 'F')
                        t = (c - (int)'A' + 10) << 4;
                    else if (c >= 'a' && c <= 'f')
                        t = (c - (int)'a' + 10) << 4;
                    state = 2;
                }
            } else if (2 == state) {
                if (c >= '0' && c <= '9')
                    t += c - (int)'0';
                else if (c >= 'A' && c <= 'F')
                    t += c - (int)'A' + 10;
                else if (c >= 'a' && c <= 'f')
                    t += c - (int)'a' + 10;
                *q++ = (char)t;
                state = 0;
            } else if ('%' == c)
                state = 1;
            else {
                *q++ = (char)c;
                state = 0;
            }
        }
        *q++ = 0;
    }
    return d;
}
