#pragma once

#include "api.h"

class Passphrase {
public:
    bool Encode(uint8_t* out, const char* in);
    bool Encode(char* out, char* in);
    bool Decode(uint8_t* out, char* in);
    bool Decode(char* out, char* in);
};