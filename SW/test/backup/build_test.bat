@echo off
:: Checks the backup HTML page (Seedmate_HTML_backup) against the firmware.
:: extract_backup.py copies the firmware's obfuscation, card and Shamir code out
:: of src/main.c, gen_backup_vectors.exe writes what it computes, and
:: check_page.js runs the page's core script (needs Node) on the same inputs.
:: The page defaults to C:\Seedmate\HTMLbackup\index.html; give another path as
:: the first argument, and a text file of shares from the page as the second.
:: Then the vectors of the "Build your own" tab must be the current ones (after
:: a change, node gen_user_vectors.js writes them into the page and build-your-own/),
:: and check_spec.py, written only from the specification, must pass them.
cd /d %~dp0
python extract_backup.py
if errorlevel 1 exit /b 1
gcc -std=c99 -Wall -Wextra -Wno-unused-function -O1 -I..\..\src gen_backup_vectors.c ..\..\src\sha256.c ..\..\src\SSS\shamir.c ..\..\src\SSS\memzero.c -o gen_backup_vectors.exe
if errorlevel 1 exit /b 1
.\gen_backup_vectors.exe backup_vectors.json
if errorlevel 1 exit /b 1
node check_page.js %1 %2
if errorlevel 1 exit /b 1
node gen_user_vectors.js --check
if errorlevel 1 exit /b 1
python check_spec.py
if errorlevel 1 exit /b 1
