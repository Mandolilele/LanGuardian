@echo off
chcp 65001 >nul
title LanGuardian 局域网实时检测与故障诊断中心

:: 自动检查并提权为管理员运行（启用原生 RawSocket 混杂抓包与 ARP 探测所需）
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [*] 正在请求管理员权限以开启网卡底层混杂抓包引擎...
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

cd /d "%~dp0"
echo [*] 正在启动 LanGuardian.exe ...
"%~dp0LanGuardian.exe"
pause
