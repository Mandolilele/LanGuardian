@echo off
chcp 65001 >nul
title 启动 LanGuardian 局域网实时监控服务

net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [*] 正在请求管理员权限以启动后台监控服务...
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

echo [*] 正在启动 LanGuardian 后台监控服务...
schtasks /query /tn "LanGuardian" >nul 2>&1
if %errorLevel% equ 0 (
    schtasks /run /tn "LanGuardian"
    timeout /t 2 >nul
    start http://127.0.0.1:8088
    echo [+] 后台监控服务已启动，并已打开监控网页 http://127.0.0.1:8088
    timeout /t 3
    exit /b
)

cd /d "%~dp0"
if exist "C:\LanGuardian\LanGuardian.exe" (
    start "" "C:\LanGuardian\LanGuardian.exe"
) else (
    start "" "%~dp0LanGuardian.exe"
)
