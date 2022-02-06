#pragma once

#include "api.h"

class Passphrase {
public:
    EXPORT bool Encode(uint8_t* out, const char* in);
    EXPORT bool Encode(char* out, char* in);
    EXPORT bool Decode(uint8_t* out, char* in);
    EXPORT bool Decode(char* out, char* in);
};