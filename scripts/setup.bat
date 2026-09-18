@echo off
:: =============================================================================
:: setup.bat — Windows Lab Automation Helper
:: CVE-2021-41773 / CVE-2021-42013 Validation Lab
::
:: USAGE:
::   setup.bat build        Build Docker images
::   setup.bat start        Start both containers (vulnerable + patched)
::   setup.bat stop         Stop and remove containers
::   setup.bat status       Show running containers and port bindings
::   setup.bat logs         Tail logs from both containers
::   setup.bat run-all      Full automated run: start + all validation scripts + stop
::   setup.bat evidence     Run all scripts and save output to evidence/
::   setup.bat clean        Remove images and all containers
:: =============================================================================
setlocal enabledelayedexpansion

set COMPOSE=docker compose
set SCRIPT_DIR=%~dp0
set ROOT_DIR=%SCRIPT_DIR%..

:: Ensure we run from project root
cd /d "%ROOT_DIR%"

if "%1"=="" goto :usage
if "%1"=="build"    goto :build
if "%1"=="start"    goto :start
if "%1"=="stop"     goto :stop
if "%1"=="status"   goto :status
if "%1"=="logs"     goto :logs
if "%1"=="run-all"  goto :run_all
if "%1"=="evidence" goto :evidence
if "%1"=="clean"    goto :clean
goto :usage

:: ---------------------------------------------------------------------------
:build
echo [*] Building Docker images ...
%COMPOSE% build --no-cache
echo [OK] Build complete.
goto :eof

:: ---------------------------------------------------------------------------
:start
echo [*] Starting lab containers ...
%COMPOSE% up -d
echo.
echo [*] Waiting 5 seconds for Apache to initialise ...
timeout /t 5 /nobreak >nul
echo.
echo [*] Container status:
%COMPOSE% ps
echo.
echo [OK] Vulnerable:  http://127.0.0.1:8080
echo [OK] Patched:     http://127.0.0.1:8081
goto :eof

:: ---------------------------------------------------------------------------
:stop
echo [*] Stopping containers ...
%COMPOSE% down
echo [OK] Containers stopped.
goto :eof

:: ---------------------------------------------------------------------------
:status
echo [*] Container status:
%COMPOSE% ps
echo.
echo [*] Port bindings:
docker ps --format "table {{.Names}}\t{{.Ports}}\t{{.Status}}"
goto :eof

:: ---------------------------------------------------------------------------
:logs
echo [*] Tailing container logs (Ctrl+C to stop) ...
%COMPOSE% logs -f
goto :eof

:: ---------------------------------------------------------------------------
:run_all
echo [*] Starting containers ...
call :start
echo.
echo [*] Running detection scanner against VULNERABLE container ...
python scripts\detect_cve.py --url http://127.0.0.1:8080
echo.
echo [*] Running path traversal validator against VULNERABLE container ...
python scripts\validate_traversal.py --url http://127.0.0.1:8080
echo.
echo [*] Running CGI handler validator against VULNERABLE container ...
python scripts\validate_cgi_handling.py --url http://127.0.0.1:8080 --cmd "id; uname -a"
echo.
echo [*] Running detection scanner against PATCHED container ...
python scripts\detect_cve.py --url http://127.0.0.1:8081
echo.
echo [*] Running path traversal validator against PATCHED container ...
python scripts\validate_traversal.py --url http://127.0.0.1:8081
echo.
echo [*] Running CGI handler validator against PATCHED container ...
python scripts\validate_cgi_handling.py --url http://127.0.0.1:8081 --cmd "id"
echo.
echo [OK] All validation runs complete.
goto :eof

:: ---------------------------------------------------------------------------
:evidence
echo [*] Creating evidence directory if not present ...
if not exist evidence mkdir evidence

echo [*] Starting containers ...
%COMPOSE% up -d
timeout /t 5 /nobreak >nul

echo [*] Capturing vulnerable container boot log ...
%COMPOSE% logs apache-vulnerable > evidence\vulnerable_server_boot.txt 2>&1
echo [OK] evidence\vulnerable_server_boot.txt

echo [*] Running traversal validator (vulnerable) ...
python scripts\validate_traversal.py --url http://127.0.0.1:8080 --file /etc/passwd > evidence\validate_traversal_output.txt 2>&1
python scripts\validate_traversal.py --url http://127.0.0.1:8080 --file /var/secret/confidential_token.txt >> evidence\validate_traversal_output.txt 2>&1
echo [OK] evidence\validate_traversal_output.txt

echo [*] Running CGI handler validator (vulnerable) ...
python scripts\validate_cgi_handling.py --url http://127.0.0.1:8080 --cmd "id; uname -a; whoami" > evidence\validate_cgi_output.txt 2>&1
python scripts\validate_cgi_handling.py --url http://127.0.0.1:8080 --cmd "cat /var/secret/confidential_token.txt" >> evidence\validate_cgi_output.txt 2>&1
echo [OK] evidence\validate_cgi_output.txt

echo [*] Running detection scanner (pre-patch / vulnerable) ...
python scripts\detect_cve.py --url http://127.0.0.1:8080 --output evidence\detection_pre_patch.json > evidence\detection_pre_patch.txt 2>&1
echo [OK] evidence\detection_pre_patch.txt

echo [*] Capturing patched container boot log ...
%COMPOSE% logs apache-patched > evidence\patched_server_boot.txt 2>&1
echo [OK] evidence\patched_server_boot.txt

echo [*] Running traversal validator (patched) ...
python scripts\validate_traversal.py --url http://127.0.0.1:8081 --file /etc/passwd > evidence\validate_post_patch.txt 2>&1
python scripts\validate_traversal.py --url http://127.0.0.1:8081 --file /var/secret/confidential_token.txt >> evidence\validate_post_patch.txt 2>&1
python scripts\validate_cgi_handling.py --url http://127.0.0.1:8081 --cmd "id" >> evidence\validate_post_patch.txt 2>&1
echo [OK] evidence\validate_post_patch.txt

echo [*] Running detection scanner (post-patch / patched) ...
python scripts\detect_cve.py --url http://127.0.0.1:8081 --output evidence\detection_post_patch.json > evidence\detection_post_patch.txt 2>&1
echo [OK] evidence\detection_post_patch.txt

echo.
echo [OK] All evidence files captured to evidence\
dir /b evidence\
goto :eof

:: ---------------------------------------------------------------------------
:clean
echo [!] This will remove all lab Docker images and containers.
set /p CONFIRM="Type YES to confirm: "
if /I "!CONFIRM!"=="YES" (
    %COMPOSE% down --rmi all --volumes
    echo [OK] Cleanup complete.
) else (
    echo [CANCELLED] No changes made.
)
goto :eof

:: ---------------------------------------------------------------------------
:usage
echo.
echo  CVE Lab Setup Script (Windows)
echo  ================================
echo  Usage: setup.bat [command]
echo.
echo  Commands:
echo    build      Build Docker images (run once, or after config changes)
echo    start      Start both vulnerable and patched containers
echo    stop       Stop and remove containers
echo    status     Show running containers and port bindings
echo    logs       Tail container logs
echo    run-all    Start containers, run all validators, show results
echo    evidence   Generate all evidence files to evidence\ directory
echo    clean      Remove all containers and images
echo.
goto :eof
