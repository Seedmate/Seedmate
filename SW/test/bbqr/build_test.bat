@echo off
:: BBQr decoder (src/bbqr.c with the vendored tinf): frames of gen_bbqr.py,
:: an independent encoder, and of tools/ur_psbt_animator.html (needs Node).
python gen_bbqr.py
if errorlevel 1 exit /b 1
node anim_frames.js
if errorlevel 1 exit /b 1
gcc -std=c99 -O1 -Wall -Wextra -I..\..\src -o test_bbqr.exe test_bbqr.c ..\..\src\bbqr.c
if errorlevel 1 exit /b 1
.\test_bbqr.exe
