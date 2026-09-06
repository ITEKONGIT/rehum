@echo off
setlocal
set "PROJECT_DIRECTORY=%~dp0"
pushd "%PROJECT_DIRECTORY%"
where python >nul 2>nul
if errorlevel 1 goto use_py
python rehum.py %*
goto finished
:use_py
where py >nul 2>nul
if errorlevel 1 goto no_python
py -3 rehum.py %*
goto finished
:no_python
echo error: Python 3 was not found. Install Python 3.11 or newer. 1>&2
set "EXIT_CODE=1"
goto cleanup
:finished
set "EXIT_CODE=%ERRORLEVEL%"
:cleanup
popd
exit /b %EXIT_CODE%
