@echo off
setlocal
rem Builds gtmapper.exe with MSVC (any Visual Studio 2019+ with the C++ workload).
rem vswhere is called from a subroutine on purpose: "%ProgramFiles(x86)%" contains ')'
rem which breaks parenthesised blocks, and for/f mangles the quoting.
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
set "VSDIR="
if exist "%VSWHERE%" call :findvs
if defined VSDIR set "VCVARS=%VSDIR%\VC\Auxiliary\Build\vcvars64.bat"
if not defined VSDIR set "VCVARS=C:\Program Files\Microsoft Visual Studio\18\Professional\VC\Auxiliary\Build\vcvars64.bat"
if exist "%VCVARS%" goto :build
echo vcvars64.bat not found - install the Visual Studio C++ tools or edit build.bat
exit /b 1

:build
call "%VCVARS%" >nul 2>&1
cd /d "%~dp0"
cl /nologo /std:c++17 /O2 /EHsc /W3 gtmapper.cpp /Fe:gtmapper.exe
if errorlevel 1 exit /b 1
if exist gtmapper.obj erase gtmapper.obj
echo built gtmapper.exe
exit /b 0

:findvs
"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath > "%TEMP%\gtmapper_vsdir.txt"
set /p VSDIR=<"%TEMP%\gtmapper_vsdir.txt"
if exist "%TEMP%\gtmapper_vsdir.txt" erase "%TEMP%\gtmapper_vsdir.txt"
exit /b 0
