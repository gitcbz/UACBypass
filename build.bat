@echo off
rem build.bat - 编译 allbypass.exe
rem 注意:必须用 g++ 而不是 gcc 驱动,否则 C++ 运行时链接失败。
setlocal

set "GXX=E:\other\msys64\ucrt64\bin\g++.exe"
if not exist "%GXX%" (
    echo [ERROR] 找不到编译器: %GXX%
    echo         请修改本脚本里的 GXX 变量。
    exit /b 1
)

"%GXX%" -O2 -Wall -Wextra -std=c++17 -o allbypass.exe allbypass.cpp ^
    -ladvapi32 -lshell32 -luser32

if errorlevel 1 (
    echo [ERROR] 编译失败
    exit /b 1
)

echo [OK] 已生成 allbypass.exe
allbypass.exe --help
endlocal
