@echo off
rem Build the hmm.dll override-hook proxy with MSVC (32-bit, matches the
rem game's non-relocatable 32-bit imagebase requirement).
setlocal
set VCVARS="C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars32.bat"
if not exist %VCVARS% (
    echo Could not find vcvars32.bat at %VCVARS%
    exit /b 1
)
call %VCVARS% >nul
if %ERRORLEVEL% NEQ 0 (
    echo Failed to initialize MSVC x86 environment
    exit /b 1
)

cl /nologo /O2 /W3 /MT /LD hook.c /link /DEF:hmm.def /OUT:hmm.dll /MACHINE:X86
if %ERRORLEVEL% NEQ 0 (
    echo Build FAILED
    exit /b 1
)
del /q hook.obj hook.exp hook.lib >nul 2>&1
echo Build OK: dpm_override\hmm.dll
