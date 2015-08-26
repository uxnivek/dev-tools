@echo off

echo irxcopy.cmd > excludedfileslist.txt
echo. >> excludedfileslist.txt
echo excludedfileslist.txt >> excludedfileslist.txt

xcopy %1 %2 %3 /y/i/e/f /exclude:excludethesefileslist.txt

rem clean
rem del excludedfileslist.txt

goto exit

:help
echo Microsoft Release Management Deployer Copy Tool v12.0
echo Copyright (c) 2013 Microsoft.  All rights reserved.
echo.
echo IRXCOPY.CMD source destination [other_params]
echo.
echo   [other_params]    Any other valid XCOPY parameters accept for source or destination
echo.

:exit
exit @ERRORLEVEL%
