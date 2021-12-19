#pragma once

#if defined(_WIN32)
#include <WinSock2.h> // WSADATA, SOCKET, BOOL, DWORD
#else
#if defined(__linux__) || defined(__APPLE__)
#include <fcntl.h> // O_RDWR, open
#include <netinet/in.h> // socket, AF_, SOCK_, IPPROTO_
#endif
#include <arpa/inet.h> // inet_addr
#include <errno.h> // errno
#include <netdb.h> // gethostbyname, struct hostent
#include <string.h> // strlen
#include <sys/time.h> // gettimeofday
#include <unistd.h> // close, STDIN_FILENO
#endif
#include <signal.h> // raise, signal
#include <stdint.h> // uint8_t
#include <stdio.h> // FILE, fflush
#include <stdlib.h> // atoi
#include <sys/stat.h> // _stat64
#include <time.h> // time

enum {
    cond_base_file = 100,
    cond_base_socket = 200,
    cond_base_channel = 300,
    cond_base_app = 1000
};

#if defined(_WIN32)
#define S_IRUSR _S_IREAD
#define S_ISDIR(x) ((x) & (_S_IFDIR))
#define S_ISREG(x) ((x) & (_S_IFREG))
#define WINSOCKVERSION 0x0202
#else
#if defined(__linux__) || defined (__APPLE__)
#define closesocket(x) ::close(x)
#else
#define SOMAXCONN 5
#endif
#define __cdecl
#define _stat64 stat
#define INVALID_SOCKET (-1)
#define SOCKET_ERROR (-1)
#define WSAENOBUFS ENOBUFS
#define WSAENOTCONN ENOTCONN
#define WSAEWOULDBLOCK EWOULDBLOCK
#define WSAGetLastError() errno
#endif
#define HILO32(x) ((x << 24) | ((x & 0xFF00) << 8) | ((x & 0xFF0000) >> 8) | (x >> 24))
#define HILO64(x) ((x << 56) | ((x & 0xFF00) << 40) | ((x & 0xFF0000) << 24) | ((x & 0xFF000000) << 8) | ((x >> 8) & 0xFF000000) | ((x >> 24) & 0xFF0000) | ((x >> 40) & 0xFF00) | (x >> 56))

#if defined(_WIN32)
using socklen_t = int;
#else
#if defined(__linux__) || defined(__APPLE__)
using SOCKET = size_t;
#else
using SOCKET = int;
#endif
#endif

#if !defined(_WIN32)
typedef struct service_table_entry {
    char* x;
    int y;
} SERVICE_TABLE_ENTRY;
typedef struct systemtime {
    unsigned short wYear;
    unsigned short wMonth;
    unsigned short wDayOfWeek;
    unsigned short wDay;
    unsigned short wHour;
    unsigned short wMinute;
    unsigned short wSecond;
    unsigned short wMilliseconds;
} SYSTEMTIME;
#endif

#if !defined(_WIN32)
void GetSystemTime(SYSTEMTIME* st);
#endif
void catmem(uint8_t** d, uint8_t* s, size_t len);
void catstr(uint8_t** d, const char* s, size_t* len);
void catstr(char** d, const char* s, size_t* len);
int cmpstr(const char* d, char* s);
bool datetimecheck(uint8_t* s, struct tm* tmOut);
void datetimeclock(uint8_t* buf);
uint8_t* derfix(uint8_t* p, uint8_t* s);
char* dupstr(const char* s);
void freeptr(uint8_t** ptr);
void freestr(char** s);
char* ltrim(char* s);
char* rtrim(char* s);
void setptr(uint8_t** ptr, uint8_t* s, size_t len);
void setstr(char** ptr, const char* s);
void setunstr(char** d, char* s);
char* tokstrq(char* s, const char* d, const char* x, char** p);
char* tokstrx(char* s, const char* d, const char* x, char** p);
char* unstr(char* d, char* s);
