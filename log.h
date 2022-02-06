#pragma once

#include "api.h"

class Log {
public:
    int _appErr;
    int _osErr;

    Log();
    ~Log();
    void Init();
    void Reset();
};

EXPORT int appErr();
EXPORT int osErr();
EXPORT void appErr(int err);
EXPORT void osErr(int err);
