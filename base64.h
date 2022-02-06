#pragma once

#include "api.h"

const uint8_t six2pr[64] = {
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
    'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
    'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
    'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/' };
#define ENC(c) six2pr[c]

EXPORT bool base64dec(uint8_t* out, const char* in, size_t* len);
EXPORT bool base64dec(uint8_t* out, uint8_t* in, size_t* len);
EXPORT bool base64enc(uint8_t* out, uint8_t* in, size_t* len, size_t maxlen = 0);
