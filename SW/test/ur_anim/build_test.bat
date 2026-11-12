@echo off
:: Checks tools/ur_psbt_animator.html against the firmware's UR encoder, fountain
:: decoder and QR library. gen_frames.js runs the page's own script (needs Node).
node gen_frames.js
if errorlevel 1 exit /b 1
gcc -std=c99 -Wall -Wextra -O1 -I..\..\src -I..\..\src\QRCode-master\src test_ur_anim.c ..\..\src\ur_encode.c ..\..\src\bytewords.c ..\..\src\fountain.c ..\..\src\sampler.c ..\..\src\prng.c ..\..\src\sha256.c ..\..\src\QRCode-master\src\qrcode.c -o test_ur_anim.exe
if errorlevel 1 exit /b 1
.\test_ur_anim.exe
