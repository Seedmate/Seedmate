@echo off
:: Host-side tests for kdf.c (HMAC-SHA512, BIP39 PBKDF2).
:: Regenerate kdf_vectors.h (only needed after editing gen_kdf_vectors.py):
::   python gen_kdf_vectors.py
gcc -std=c99 -Wall -Wextra -O1 -I..\..\src test_kdf.c ..\..\src\kdf.c ..\..\src\sha512.c ..\..\src\SSS\memzero.c -o test_kdf.exe
if errorlevel 1 exit /b 1
.\test_kdf.exe
