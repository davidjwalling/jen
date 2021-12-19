#include "app.h"
#include "log.h"

#include <iostream>

namespace cond {
    namespace app {
        enum {
            access = cond_base_app,
            opensc,
            lock,
            size,
            module,
            file,
            command,
            exists,
            display,
            create,
            key,
            value,
            closekey,
            close,
            missing,
            name,
            open,
            remove,
            unlock,
            closesc,
            console,
            dispatch,
            pipe1,
            alarm1,
            intr,
            fork,
            setsid,
            emptyset,
            addset,
            procmask,
            term,
            pipe2,
            alarm2,
            hup,
            null,
            stdin_,
            stdout_,
            stderr_,
            wsastartup
        };
    }
}

namespace app {
    namespace arg {
        const char* port = "-p";
    }
    namespace message {
        const char* title = "Jen Protocol Server [0.X].";
        const char* copyright = "Copyright 2021 Proserio, LLC. All rights reserved.";
        const char* access = "Administrative privilege required.";
        const char* opensc = "Unable to open service control manager.";
        const char* lock = "Unable to lock service database.";
        const char* size = "Registry key and name too long.";
        const char* module = "Unable to get module handle.";
        const char* file = "Unable to get module file name.";
        const char* command = "Service path and spec too long.";
        const char* exists = "Service already exists.";
        const char* display = "Dupliate service name.";
        const char* create = "Unable to create service.";
        const char* key = "Unable to create registry key.";
        const char* value = "Unable to set registry key value.";
        const char* closekey = "Unable to close registry key.";
        const char* installed = "Service installed.";
        const char* missing = "Service not found.";
        const char* name = "Invalid service name.";
        const char* open = "Unable to open service.";
        const char* remove = "Unable to remove service.";
        const char* close = "Unable to close service handle.";
        const char* unlock = "Unable to unlock service database.";
        const char* closesc = "Unable to close service manager handle.";
        const char* uninstalled = "Service uninstalled.";
        const char* usage = "Usage: jen [install|uninstall]";
        const char* complete = "Service started.";
        const char* terminate = "Termination detected.";
        const char* finalize = "Exiting program.";
    }
    namespace pattern {
        const char* message = "%s\n";
        const char* error = "%s Error %d\n";
    }
    const char* command = "jen.exe service";
    const char* description = "Jen provides secure multi-protocol communication.";
    const char* display = "Jen Protocol Server";
    const char* install = "install";
    const char* name = "jen";
    const char* registry = "SOFTWARE\\Proserio\\Jen\\";
    const char* service = "service";
    const char* uninstall = "uninstall";
}

App theApp;

App::App()
{
    Init();
    for (int n = 0; n < app::channels; n++)
        _channel[n]._id = n;
}

App::~App()
{
    Reset();
}

void App::Init()
{
    _daemon = false;
    _stop = false;
    _winsock = false;
    _first = nullptr;
    _last = nullptr;
#if defined(_WIN32)
    _hscm = 0;
    _lock = 0;
    _handle = 0;
    memset(&_section, 0, sizeof _section);
    _status = { 0 };
    _dispatch[0] = { 0 };
    _dispatch[1] = { 0 };
#endif
}

void App::Reset()
{
    Init();
}

#if defined(_WIN32)
void App::Handle(DWORD control)
{
    switch (control) {
    case SERVICE_CONTROL_SHUTDOWN:
    case SERVICE_CONTROL_STOP:
        EnterCriticalSection(&_section);
        _status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
        _status.dwCurrentState = SERVICE_STOP_PENDING;
        _status.dwWin32ExitCode = NO_ERROR;
        _status.dwServiceSpecificExitCode = 0;
        _status.dwCheckPoint = 0;
        _status.dwWaitHint = 0;
        SetServiceStatus(_handle, &_status);
        LeaveCriticalSection(&_section);
        _stop = true;
        break;
    default:
        EnterCriticalSection(&_section);
        SetServiceStatus(_handle, &_status);
        LeaveCriticalSection(&_section);
    }
}
#endif

#if defined(_WIN32)
void WINAPI ServiceCtrlHandler(DWORD control)
{
    theApp.Handle(control);
}
#endif

#if defined(_WIN32)
void App::Main(DWORD argc, LPSTR* argv)
{
    _handle = RegisterServiceCtrlHandler((LPCSTR)app::name, ServiceCtrlHandler);
    if (!_handle) {
        ExitProcess((UINT)-1);
        return;
    }
    InitializeCriticalSection(&_section);
    EnterCriticalSection(&_section);
    _status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    _status.dwCurrentState = SERVICE_RUNNING;
    _status.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    _status.dwWin32ExitCode = NO_ERROR;
    _status.dwServiceSpecificExitCode = 0;
    _status.dwCheckPoint = 0;
    _status.dwWaitHint = 0;
    SetServiceStatus(_handle, &_status);
    LeaveCriticalSection(&_section);
    Run(argc, argv);
    EnterCriticalSection(&_section);
    _status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    _status.dwCurrentState = SERVICE_STOPPED;
    _status.dwControlsAccepted = 0;
    _status.dwWin32ExitCode = NO_ERROR;
    _status.dwServiceSpecificExitCode = 0;
    _status.dwCheckPoint = 0;
    _status.dwWaitHint = 0;
    SetServiceStatus(_handle, &_status);
    LeaveCriticalSection(&_section);
    DeleteCriticalSection(&_section);
    ExitProcess(0);
}
#endif

#if defined(_WIN32)
void WINAPI ServiceMain(DWORD argc, LPSTR* argv)
{
    theApp.Main(argc, argv);
}
#endif

#if defined(_WIN32)
bool App::OpenServiceManager()
{
    _hscm = OpenSCManager(NULL, SERVICES_ACTIVE_DATABASE, SC_MANAGER_ALL_ACCESS);
    if (!_hscm) {
        osErr(GetLastError());
        if (ERROR_ACCESS_DENIED == osErr()) {
            appErr(cond::app::access);
            printf(app::pattern::message, app::message::access);
        } else {
            appErr(cond::app::opensc);
            printf(app::pattern::error, app::message::opensc, osErr());
        }
        return false;
    }
    _lock = LockServiceDatabase(_hscm);
    if (!_lock) {
        osErr(GetLastError());
        appErr(cond::app::lock);
        printf(app::pattern::error, app::message::lock, osErr());
        CloseServiceHandle(_hscm);
        return false;
    }
    return true;
}
#endif

#if defined(_WIN32)
bool App::Install()
{
    char* p;
    long result;
    size_t h, pathLen, specLen, pathSpecLen;
    HMODULE module;
    SC_HANDLE hsvc;
    HKEY hkey;
    DWORD disposition;
    SERVICE_DESCRIPTION description;
    char buf[256] = { 0 };
    h = strlen(app::registry) + strlen(app::name) + 1;
    if (h > sizeof(buf)) {
        osErr(0);
        appErr(cond::app::size);
        printf(app::pattern::message, app::message::size);
        return false;
    }
    module = GetModuleHandle(NULL);
    if (!module) {
        osErr(GetLastError());
        appErr(cond::app::module);
        printf(app::pattern::error, app::message::module, osErr());
        return false;
    }
    pathLen = GetModuleFileName(module, buf, sizeof(buf));
    if (!pathLen) {
        osErr(GetLastError());
        appErr(cond::app::file);
        printf(app::pattern::error, app::message::file, osErr());
        return false;
    }
    for (p = &buf[pathLen]; p > buf;) {
        --p;
        if (('\\' == *p) || ('/' == *p) || (':' == *p)) {
            p++;
            break;
        }
    }
    pathLen = (p - buf);
    specLen = strlen(app::command);
    pathSpecLen = pathLen + specLen + 2;
    if (pathSpecLen > sizeof(buf)) {
        osErr(0);
        appErr(cond::app::command);
        printf(app::pattern::message, app::message::command);
        return false;
    }
    catstr(&p, app::command, &h);
    *p++ = '\0';
    hsvc = CreateService(_hscm, app::name, app::display,
        SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
        SERVICE_AUTO_START, SERVICE_ERROR_NORMAL, buf,
        NULL, NULL, NULL, NULL, NULL);
    if (!hsvc) {
        osErr(GetLastError());
        if (ERROR_SERVICE_EXISTS == osErr()) {
            appErr(cond::app::exists);
            printf(app::pattern::message, app::message::exists);
        } else if (ERROR_DUPLICATE_SERVICE_NAME == osErr()) {
            appErr(cond::app::display);
            printf(app::pattern::message, app::message::display);
        } else {
            appErr(cond::app::create);
            printf(app::pattern::error, app::message::create, osErr());
        }
        return false;
    }
    description.lpDescription = (LPSTR)app::description;
    ChangeServiceConfig2(hsvc, SERVICE_CONFIG_DESCRIPTION, &description);
    p = buf;
    catstr(&p, app::registry, &h);
    catstr(&p, app::name, &h);
    *p++ = '\0';
    result = RegCreateKeyEx(HKEY_LOCAL_MACHINE, buf, 0, NULL,
        REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hkey, &disposition);
    if (result != ERROR_SUCCESS) {
        osErr(result);
        appErr(cond::app::key);
        printf(app::pattern::error, app::message::key, osErr());
        RegCloseKey(hkey);
        CloseServiceHandle(hsvc);
        return false;
    }
    result = RegSetValueEx(hkey, "Description", 0, REG_SZ,
        (const BYTE*)app::description, (DWORD)strlen(app::description) + 1);
    if (result != ERROR_SUCCESS) {
        osErr(result);
        appErr(cond::app::value);
        printf(app::pattern::error, app::message::value, osErr());
        RegCloseKey(hkey);
        CloseServiceHandle(hsvc);
        return false;
    }
    result = RegCloseKey(hkey);
    if (result != ERROR_SUCCESS) {
        osErr(result);
        appErr(cond::app::closekey);
        printf(app::pattern::error, app::message::closekey, osErr());
        CloseServiceHandle(hsvc);
        return false;
    }
    if (!CloseServiceHandle(hsvc)) {
        osErr(GetLastError());
        appErr(cond::app::close);
        printf(app::pattern::error, app::message::close, osErr());
        return false;
    }
    printf(app::pattern::message, app::message::installed);
    return true;
}
#endif

#if defined(_WIN32)
bool App::Uninstall()
{
    SC_HANDLE hsvc = (SC_HANDLE)0;
    hsvc = OpenService(_hscm, app::name, SERVICE_ALL_ACCESS);
    if (!hsvc) {
        osErr(GetLastError());
        if (ERROR_SERVICE_DOES_NOT_EXIST == osErr()) {
            appErr(cond::app::missing);
            printf(app::pattern::error, app::message::missing, osErr());
        } else if (ERROR_INVALID_NAME == osErr()) {
            appErr(cond::app::name);
            printf(app::pattern::error, app::message::name, osErr());
        } else {
            appErr(cond::app::open);
            printf(app::pattern::error, app::message::open, osErr());
        }
        return false;
    }
    if (!DeleteService(hsvc)) {
        osErr(GetLastError());
        appErr(cond::app::remove);
        printf(app::pattern::error, app::message::remove, osErr());
        CloseServiceHandle(hsvc);
        return false;
    }
    if (!CloseServiceHandle(hsvc)) {
        osErr(GetLastError());
        appErr(cond::app::close);
        printf(app::pattern::error, app::message::close, osErr());
        return false;
    }
    printf(app::pattern::message, app::message::uninstalled);
    return true;
}
#endif

#if defined(_WIN32)
void App::CloseServiceManager()
{
    if (!UnlockServiceDatabase(_lock)) {
        if (!appErr()) {
            osErr(GetLastError());
            appErr(cond::app::unlock);
            printf(app::pattern::error, app::message::unlock, osErr());
        }
        CloseServiceHandle(_hscm);
    } else if (!CloseServiceHandle(_hscm)) {
        if (!appErr()) {
            osErr(GetLastError());
            appErr(cond::app::closesc);
            printf(app::pattern::error, app::message::closesc, osErr());
        }
    }
}
#endif

#if defined(_WIN32)
void App::Manage(const char* action)
{
    printf(app::pattern::message, app::message::title);
    printf(app::pattern::message, app::message::copyright);
    if (!strcmp(action, app::install)) {
        if (OpenServiceManager()) {
            Install();
            CloseServiceManager();
        }
    } else if (!strcmp(action, app::uninstall)) {
        if (OpenServiceManager()) {
            Uninstall();
            CloseServiceManager();
        }
    } else
        printf(app::pattern::message, app::message::usage);
}
#endif

#if defined(_WIN32)
BOOL WINAPI ServiceHandleTerm(DWORD fdwCtrlType)
{
    switch (fdwCtrlType) {
    case CTRL_C_EVENT:
    case CTRL_BREAK_EVENT:
    case CTRL_CLOSE_EVENT:
    case CTRL_SHUTDOWN_EVENT:
        if (!theApp._daemon)
            printf(app::pattern::message, app::message::terminate);
        theApp._stop = true;
        return TRUE;
    default:
        return FALSE;
    }
}
#else
void ServiceHandleSig(int sig)
{
    signal(sig, ServiceHandleSig);
}

void ServiceHandleTerm(int sig)
{
    if (!theApp._daemon)
        printf(app::pattern::message, app::message::terminate);
    theApp._stop = true;
    signal(sig, ServiceHandleSig);
}
#endif

bool App::Start(int argc, char* argv[])
{
#if defined(_WIN32)
    if (argc > 1 && argv[1]) {
        if (!strcmp(argv[1], app::service)) {
            _dispatch[0].lpServiceName = (char*)app::name;
            _dispatch[0].lpServiceProc = ServiceMain;
            if (!StartServiceCtrlDispatcher(_dispatch)) {
                printf(app::pattern::message, app::message::title);
                printf(app::pattern::message, app::message::copyright);
                osErr(GetLastError());
                if (ERROR_FAILED_SERVICE_CONTROLLER_CONNECT == osErr()) {
                    appErr(cond::app::console);
                } else {
                    appErr(cond::app::dispatch);
                }
            } else {
                _daemon = true;
            }
            return false;
        }
        printf(app::pattern::message, app::message::title);
        printf(app::pattern::message, app::message::copyright);
        if (!strcmp(argv[1], app::install)) {
            if (OpenServiceManager()) {
                Install();
                CloseServiceManager();
            }
            return false;
        } 
        if (!strcmp(argv[1], app::uninstall)) {
            if (OpenServiceManager()) {
                Uninstall();
                CloseServiceManager();
            }
            return false;
        }
    } else {
        printf(app::pattern::message, app::message::title);
        printf(app::pattern::message, app::message::copyright);
    }
    SetConsoleCtrlHandler(ServiceHandleTerm, TRUE);
#else
    int rc = 0;
    int nullFile = 0;
    sigset_t set = { 0 };
    struct sigaction act = { 0 };
    //  Ignore PIPE and ALARM signals.
    memset(&act, 0, sizeof(act));
    act.sa_handler = SIG_IGN;
    act.sa_flags = 0;
    rc = sigaction(SIGPIPE, &act, NULL);
    if (rc) {
        osErr(errno);
        appErr(cond::app::pipe1);
        return false;
    }
    rc = sigaction(SIGALRM, &act, NULL);
    if (rc) {
        osErr(errno);
        appErr(cond::app::alarm1);
        return false;
    }
    //  If foreground program, set Ctrl+c (SIGINT) handler.
    if ((argc < 2) || (strcmp(app::service, argv[1]))) {
        memset(&act, 0, sizeof(act));
        act.sa_handler = ServiceHandleTerm;
        act.sa_flags = 0;
        rc = sigaction(SIGINT, &act, NULL);
        if (rc) {
            osErr(errno);
            appErr(cond::app::intr);
            return false;
        }
        printf(app::pattern::message, app::message::title);
        printf(app::pattern::message, app::message::copyright);
        return true;
    }
    //  Fork and exit if we are the parent.
    _daemon = true;
    rc = fork();
    if (-1 == rc) {
        osErr(errno);
        appErr(cond::app::fork);
        return false;
    }
    if (rc)
        exit(0);
    //  Set SID, enable TERM and set TERM handler.
    rc = setsid();
    if (-1 == rc) {
        osErr(errno);
        appErr(cond::app::setsid);
        return false;
    }
    rc = sigemptyset(&set);
    if (rc) {
        osErr(errno);
        appErr(cond::app::emptyset);
        return false;
    }
    rc = sigaddset(&set, SIGTERM);
    if (rc) {
        osErr(errno);
        appErr(cond::app::addset);
        return false;
    }
    rc = sigprocmask(SIG_UNBLOCK, &set, NULL);
    if (rc) {
        osErr(errno);
        appErr(cond::app::procmask);
        return false;
    }
    memset(&act, 0, sizeof(act));
    act.sa_handler = ServiceHandleTerm;
    act.sa_flags = 0;
    rc = sigaction(SIGTERM, &act, NULL);
    if (rc) {
        osErr(errno);
        appErr(cond::app::term);
        return false;
    }
    //  Ignore PIPE, ARLARM and HUP signals.
    memset(&act, 0, sizeof(act));
    act.sa_handler = SIG_IGN;
    act.sa_flags = 0;
    rc = sigaction(SIGPIPE, &act, NULL);
    if (rc) {
        osErr(errno);
        appErr(cond::app::pipe2);
        return false;
    }
    rc = sigaction(SIGALRM, &act, NULL);
    if (rc) {
        osErr(errno);
        appErr(cond::app::alarm2);
        return false;
    }
    rc = sigaction(SIGHUP, &act, NULL);
    if (rc) {
        osErr(errno);
        appErr(cond::app::hup);
        return false;
    }
    //  Dup standard streams to null
    nullFile = ::open("/dev/null", O_RDWR);
    if (-1 == nullFile) {
        osErr(errno);
        appErr(cond::app::null);
        return false;
    }
    rc = dup2(nullFile, STDIN_FILENO);
    if (-1 == rc) {
        osErr(errno);
        appErr(cond::app::stdin_);
        return false;
    }
    rc = dup2(nullFile, STDOUT_FILENO);
    if (-1 == rc) {
        osErr(errno);
        appErr(cond::app::stdout_);
        return false;
    }
    rc = dup2(nullFile, STDERR_FILENO);
    if (-1 == rc) {
        osErr(errno);
        appErr(cond::app::stderr_);
        return false;
    }
#endif
    return true;
}

void App::GetArgVars(int argc, char* argv[])
{
    if (argc < 2)
        return;
    for (int n = 1; n < argc; n++) {
        if (!strcmp(argv[n], app::arg::port)) {
            if (++n < argc) {
                _port = (uint16_t)atoi(argv[n]);
            }
        }
    }
}

void App::GenerateKey()
{
    _x509._prvKey.Create(1024);
    _x509._pubKey = _x509._prvKey;
    _x509.PutIssuer("E=jen@proserio.com;O=Proserio;CN=Jen");
    _x509.PutSerNo((uint8_t*)"1001");
    _x509.PutSubject("E=jen@proserio.com;O=Proserio;CN=Jen");
    _x509.PutNotBefore((uint8_t*)"20200101000000");
    _x509.PutNotAfter((uint8_t*)"21000101000000");
    _x509._flags |= x509::flags::cacert;
    _x509._pathLen = 3;
    size_t len = 4096;
    uint8_t* cert = new uint8_t[4096];
    memset(cert, 0, 4096);
    _x509.Export(cert, &len);
    _x509.SetCertBuf(cert, len);
    _x509.SetCertLen(len);
    memset(cert, 0, 4096);
    delete[] cert;
}

void App::Configure(int argc, char* argv[])
{
    GetArgVars(argc, argv);
    GenerateKey();
}

bool App::Initialize(int argc, char* argv[])
{
#if defined(_WIN32)
    WSADATA wsadata = { 0 };
    int rc = WSAStartup(WINSOCKVERSION, &wsadata);
    if (rc) {
        osErr(rc);
        appErr(cond::app::wsastartup);
        return false;
    }
    _winsock = true;
#endif
    Configure(argc, argv);
    if (!Stream())
        return false;
    if (!Bind())
        return false;
    if (!Listen())
        return false;
    if (!_daemon)
        printf(app::pattern::message, app::message::complete);
    return true;
}

void App::Queue(Channel* channel)
{
    if (channel) {
        channel->_next = nullptr;
        channel->_prev = _last;
        if (_last)
            _last->_next = channel;
        _last = channel;
        if (!_first)
            _first = channel;
    }
}

void App::GetClient()
{
    for (int n = 0; n < app::channels; n++) {
        if (_channel[n]._state == channel::state::ready) {
            SOCKET client = Accept();
            if (client) {
                _channel[n]._socket._socket = client;
                _channel[n]._state = channel::state::connected;
                _channel[n]._expires = time(0) + 3600;
                _channel[n]._remoteAddr = _remoteAddr;
                _channel[n]._remotePort = _remotePort;
                Queue(&_channel[n]);
            }
            break;
        }
    }
}

Channel* App::Dequeue()
{
    Channel* channel = _first;
    if (channel) {
        if (channel->_prev)
            channel->_prev->_next = channel->_next;
        if (channel->_next)
            channel->_next->_prev = channel->_prev;
        _first = channel->_next;
        if (channel == _last)
            _last = channel->_prev;
    }
    return channel;
}

void App::ServiceChannel()
{
    Channel* channel = Dequeue();
    if (channel) {
        channel->Service();
        _random.Rand();
        if (channel->_state != channel::state::ready)
            Queue(channel);
    }
}

void App::Mainline()
{
    while (!_stop) {
        GetClient();
        ServiceChannel();
    }
}

void App::Finalize()
{
    Shutdown();
    Close();
#if defined(_WIN32)
    if (_winsock) {
        WSACleanup();
        _winsock = false;
    }
#endif
    if (!_daemon)
        printf(app::pattern::message, app::message::finalize);
}

void App::Run(int argc, char* argv[])
{
    if (Initialize(argc, argv))
        Mainline();
    Finalize();
}

int App::Exec(int argc, char* argv[])
{
    if (Start(argc, argv))
        Run(argc, argv);
    return appErr();
}

int __cdecl main(int argc, char* argv[])
{
    return theApp.Exec(argc, argv);
}
