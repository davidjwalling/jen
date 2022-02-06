### Jen
```
Jen Protocol Server
Copyright 2021 Proserio, LLC. All rights reserved.
```
##### Prerequisites
###### Linux (Debian, Ubuntu)
```
$ sudo apt update
$ sudo apt upgrade
$ sudo apt install build-essential
```
###### Linux (Fedora)
```
$ sudo dnf update
$ sudo dnf install @development-tools
```
###### Linux (Oracle)
```
$ sudo yum update
$ sudo yum upgrade
$ sudo yum groupinstall "Development Tools"
```
###### Windows 10
Install Visual Studio 2019 Community Edition
##### Build
###### Linux
By default, "make install" copies to /usr/local/lib and /usr/local/bin.
Edit the Makefile if your local paths differ.
Note, however, that when run as a daemon, Jen loads from /usr/bin.
This allows local testing from /usr/local/bin.
```
$ cd ~
$ git clone https://github.com/davidjwalling/jen
$ cd jen
$ make
$ sudo make install
```
###### Windows 10 (Visual Studio 2019 Community)
The make.bat script runs the vcvars.bat to set up the local compiler resources.
Debug and release builds for both 32 and 64-bit targets are built.
```
C:\> git clone https://github.com/davidjwalling/jen
C:\> cd jen
C:\jen> make.bat
```
##### Foreground Operation
###### Linux
Use Ctrl-C to terminate the foreground program after the service has started.
```
$ cd ~/jen
$ ./jen.sh
Jen Protocol Server [0.X]
Copyright 2021 Proserio, LLC. All rights reserved.
Service started.
Termination detected.
Exiting program.
Result Code 0
```
###### Windows 10
Use Ctrl-C to terminate the program.
When prompted by Windows whether to terminate the batch job, answer no (n) so that the result code from the program will be displayed.
```
C:\jen> jen.bat
Jen Protocol Server [0.X]
Copyright 2021 Proserio, LLC. All rights reserved.
Service started.
Termination detected.
Exiting program.
Terminate batch job (Y/N)? n
Result Code 0
```
##### Service Installation
###### Linux (systemd)
```
$ sudo mkdir /var/opt/jen
$ sudo cp libjen.so /usr/lib
$ sudo cp jen /usr/bin
$ sudo cp jen.service /lib/systemd/system/
$ sudo cp jen.conf /etc/modules-load.d/
$ sudo systemctl daemon-reload
$ sudo systemctl enable jen
```
###### Windows 10 (as Administrator)
```
C:\jen> x64\Release\jen install
Jen Protocol Sever [0.X]
Copyright 2021 Proserio, LLC. All rights reserved.
Service installed.
```
##### Service Operation
###### Linux (systemd)
```
$ sudo systemctl start jen
$ sudo systemctl status jen
$ netstat -an | grep 1143
$ sudo systemctl stop jen
```
###### Windows 10 (as Administrator)
```
C:\> net start jen
C:\> sc query jen
C:\> netstat -an | findstr 1143
C:\> net stop jen
```
##### Service Removal
###### Linux (systemd)
```
$ sudo systemctl stop jen
$ sudo systemctl disable jen
$ sudo rm /etc/modules-load.d/jen.conf
$ sudo rm /lib/systemd/system/jen.service
$ sudo systemctl daemon-reload
$ sudo rm /usr/bin/jen
$ sudo rm /usr/lib/libjen.so
$ sudo rm -rf /var/opt/jen
```
###### Windows 10 (as Administrator)
```
C:\Windows\System32> jen uninstall
Jen Protocol Sever [0.X]
Copyright 2021 Proserio, LLC. All rights reserved.
Service uninstalled.
```
##### Debug
###### Linux (Visual Studio Code + gdb)
```
$ cd ~/jen
$ cp .gdbinit ~
$ code .
```
###### launch.json (Linux)
```
{
    "version": "0.2.0",
    "configurations": [
        {
            "name": "(gdb) Launch",
            "type": "cppdbg",
            "request": "launch",
            "program": "${workspaceFolder}/jen",
            "args": [],
            "stopAtEntry": true,
            "cwd": "${workspaceFolder}",
            "environment": [],
            "externalConsole": false,
            "MIMode": "gdb"
        }
    ]
}
```
###### Windows 10 (Visual Studio 2019 Community)
```
C:\> "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\Tools\VsDevCmd.bat"
C:\> cd jen
C:\jen> devenv /DebugExe x64\Debug\jen.exe
```
###### Windows 10 (Visual Studio Code)
```
C:\jen> code .
```
###### c_cpp_properties.json
When built using Visual Studio, Jen uses the "__MBCS" (multi-byte character set) preprocessor setting.
To enable this in Visual Studio Code, edit c_cpp_properties.json to include the "__MBCS" define.
```
{
    "configurations": [
        {
            "name": "Win32",
            "includePath": [
                "${workspaceFolder}/**"
            ],
            "defines": [
                "_DEBUG",
                "_MBCS"
            ],
            "windowsSdkVersion": "10.0.18362.0",
            "compilerPath": "C:\\Program Files (x86)\\Microsoft Visual Studio\\2017\\Professional\\VC\\Tools\\MSVC\\14.16.27023\\bin\\Hostx64\\x64\\cl.exe",
            "cStandard": "c17",
            "cppStandard": "c++17",
            "intelliSenseMode": "windows-msvc-x64"
        }
    ],
    "version": 4
}
```
###### launch.json (for Windows 10)
```
{
    "version": "0.2.0",
    "configuration": [
        {
            "name": "(Windows) Launch",
            "type": "cppvsdbg",
            "request": "launch",
            "program": "${workspaceFolder}/x64/Debug/jen.exe",
            "args": [],
            "stopAtEntry": true,
            "cwd": "${workspaceFolder}",
            "environment": [],
            "console": "externalTerminal"
        }
    ]
}
```
