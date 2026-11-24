@echo off
chcp 65001 >nul
title 停止 LanGuardian 局域网实时监控服务

net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [*] 正在请求管理员权限以停止后台监控服务...
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

echo [*] 正在停止 LanGuardian 计划任务与后台进程...
schtasks /end /tn "LanGuardian" >nul 2>&1
taskkill /F /IM LanGuardian.exe >nul 2>&1
echo [+] LanGuardian 局域网监控服务已完全停止！
echo     (如需重新启动，请双击桌面上的【启动局域网检测(管理员).bat】)
timeout /t 4
