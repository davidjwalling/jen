#include "log.h"

Log theLog;

Log::Log()
{
    Init();
}

Log::~Log()
{
    Reset();
}

void Log::Init()
{
    _appErr = 0;
    _osErr = 0;
}

void Log::Reset()
{
    Init();
}

int appErr()
{
    return theLog._appErr;
}

int osErr()
{
    return theLog._osErr;
}

void appErr(int err)
{
    theLog._appErr = err;
}

void osErr(int err)
{
    theLog._osErr = err;
}
