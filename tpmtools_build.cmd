@echo off
REM #####################################################################
REM This script build the tpmtools on windows platform
REM #####################################################################
setlocal enabledelayedexpansion

set me=%~n0
set pwd=%~dp0

set VsDevCmd="C:\Program Files (x86)\Microsoft Visual Studio 12.0\Common7\Tools\VsDevCmd.bat"
set tpmtools_home=%pwd%

IF "%~1"=="" (
  call:print_help
) ELSE IF "%~2"=="" (
  call:print_help
) ELSE (
  call:tpmtools_build %2 %1
)
GOTO:EOF

:tpmtools_build
  echo. Building tpmtools.... %1 %2
  cd %tpmtools_home%
  cd
  call %VsDevCmd%
  IF NOT %ERRORLEVEL% EQU 0 (
    echo. %me%: Visual Studio Dev Env could not be set
	call:ExitBatch
	REM EXIT /b %ERRORLEVEL%
  )
  call:tpmtools_build_util %1 %2
GOTO:EOF

:tpmtools_build_util
  setlocal
  echo. inside tpmtools_build_util %1 %2
  cd
  IF "%2"=="x86" (
    echo. calling with Win32 option
    msbuild Tpmtool.sln /property:Configuration=%1;Platform=Win32;ForceImportBeforeCppTargets=%tpmtools_home%\compiler_flags_x86.props
	IF NOT %ERRORLEVEL% EQU 0 (
	  echo. %me%: Build Failed
	  call:ExitBatch
	  REM EXIT /b %ERRORLEVEL%
	)
  ) ELSE (
    echo. calling with x64 option
    msbuild Tpmtool.sln /property:Configuration=%1;Platform=%2;ForceImportBeforeCppTargets=%tpmtools_home%\compiler_flags_x64.props
    IF NOT %ERRORLEVEL% EQU 0 (
	  echo. %me%: Build Failed
	  call:ExitBatch
	  REM EXIT /b %ERRORLEVEL%
	)
  )
  endlocal
GOTO:EOF

:print_help
  echo. "Usage: $0 Platform Configuration"
GOTO:EOF

:ExitBatch - Cleanly exit batch processing, regardless how many CALLs
if not exist "%temp%\ExitBatchYes.txt" call :buildYes
call :CtrlC <"%temp%\ExitBatchYes.txt" 1>nul 2>&1
:CtrlC
cmd /c exit -1073741510

:buildYes - Establish a Yes file for the language used by the OS
pushd "%temp%"
set "yes="
copy nul ExitBatchYes.txt >nul
for /f "delims=(/ tokens=2" %%Y in (
  '"copy /-y nul ExitBatchYes.txt <nul"'
) do if not defined yes set "yes=%%Y"
echo %yes%>ExitBatchYes.txt
popd
exit /b

endlocal