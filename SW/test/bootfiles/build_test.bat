@echo off
:: Bad UPDATE.HEX files for the bootloader device tests BOOT-06 and BOOT-17,
:: and a host check that pass 1 of the bootloader answers each as expected.
:: Writes out\*.hex (copy one to the SD card as UPDATE.HEX).
python gen_bad_hex.py
if errorlevel 1 exit /b 1
gcc -std=c99 -Wall -Wextra -O1 -DHEXFLASH_HOST_TEST -I..\..\..\bootloader\src check_pass1.c ..\..\..\bootloader\src\hex_flash.c -o check_pass1.exe
if errorlevel 1 exit /b 1
set FAILED=0
for /f "tokens=1,2" %%a in (out\expected.txt) do (
    .\check_pass1.exe %%a out/%%b || set FAILED=1
)
if %FAILED%==1 (echo SOME FILES FAILED & exit /b 1)
echo ALL FILES AS EXPECTED
