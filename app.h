#pragma once

#include "channel.h"
#include "random.h"
#include "socket.h"
#include "x509.h"

namespace app {
    enum {
        channels = 16
    };
}

class App : public Socket {
public:
    bool _daemon;
    bool _stop;
    bool _winsock;

    Channel* _first;
    Channel* _last;

#if defined(_WIN32)
    SC_HANDLE _hscm;
    SC_LOCK _lock;
    SERVICE_STATUS_HANDLE _handle;
    CRITICAL_SECTION _section;
    SERVICE_STATUS _status;
    SERVICE_TABLE_ENTRY _dispatch[2];
#endif

    Channel _channel[app::channels];
    Random _random;
    X509 _x509;

    App();
    ~App();
    void Init();
    void Reset();
#if defined(_WIN32)
    void Handle(DWORD control);
    void Main(DWORD argc, LPSTR* argv);
    bool OpenServiceManager();
    bool Install();
    bool Uninstall();
    void CloseServiceManager();
    void Manage(const char* const action);
#endif
    bool Start(int argc, char* argv[]);
    void GetArgVars(int argc, char* argv[]);
    void GenerateKey();
    void Configure(int argc, char* argv[]);
    bool Initialize(int argc, char* argv[]);
    void Queue(Channel* c);
    void GetClient();
    Channel* Dequeue();
    void ServiceChannel();
    void Mainline();
    void Finalize();
    void Run(int argc, char* argv[]);
    int Exec(int argc, char* argv[]);
};
