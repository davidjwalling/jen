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

int appErr();
int osErr();
void appErr(int err);
void osErr(int err);
