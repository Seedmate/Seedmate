@echo off
:: Host-side tests for psbt.c, psbt_sign.c, fountain_assemble_message(), ur_encode.c and descriptor.c.
:: Regenerate test_vectors.h (only needed after editing gen_vectors.py):
::   python gen_vectors.py test_vectors.h
:: Regenerate the signed test PSBT and key (ur_test_psbt.h):
::   python sign_abandon.py
:: Regenerate the multisig descriptor data (descriptor_vectors.h, MS*.TXT, MS*.PSB):
::   python gen_descriptor.py
gcc -std=c99 -Wall -Wextra -O1 -I..\..\src test_psbt.c ..\..\src\psbt.c ..\..\src\crypto\segwit_addr.c ..\..\src\fountain.c ..\..\src\sampler.c ..\..\src\prng.c ..\..\src\sha256.c -o test_psbt.exe
if errorlevel 1 exit /b 1
.\test_psbt.exe
if errorlevel 1 exit /b 1
gcc -std=c99 -Wall -Wextra -O1 -I..\..\src test_ur.c ..\..\src\ur_encode.c ..\..\src\bytewords.c ..\..\src\psbt.c ..\..\src\crypto\segwit_addr.c ..\..\src\fountain.c ..\..\src\sampler.c ..\..\src\prng.c ..\..\src\sha256.c -o test_ur.exe
if errorlevel 1 exit /b 1
.\test_ur.exe
if errorlevel 1 exit /b 1
gcc -std=c99 -Wall -Wextra -Wno-unused-parameter -O1 -I..\..\src test_sign.c ..\..\src\psbt_sign.c ..\..\src\psbt.c ..\..\src\sha256.c ..\..\src\sha512.c ..\..\src\kdf.c ..\..\src\crypto\bignum.c ..\..\src\crypto\ecdsa.c ..\..\src\crypto\secp256k1.c ..\..\src\crypto\segwit_addr.c ..\..\src\SSS\memzero.c -o test_sign.exe
if errorlevel 1 exit /b 1
.\test_sign.exe
if errorlevel 1 exit /b 1
gcc -std=c99 -Wall -Wextra -Wno-unused-parameter -O1 -I..\..\src test_descriptor.c ..\..\src\descriptor.c ..\..\src\psbt_sign.c ..\..\src\psbt.c ..\..\src\sha256.c ..\..\src\sha512.c ..\..\src\kdf.c ..\..\src\crypto\bignum.c ..\..\src\crypto\ecdsa.c ..\..\src\crypto\secp256k1.c ..\..\src\crypto\segwit_addr.c ..\..\src\SSS\memzero.c -o test_descriptor.exe
if errorlevel 1 exit /b 1
.\test_descriptor.exe
