@echo off
for /f "tokens=5" %%a in ('netstat -aon ^| findstr :3006 ^| findstr LISTENING') do (
    echo Finalizando processo na porta 3006 com PID %%a...
    taskkill /PID %%a /F
)
echo Iniciando servidor...
node server.js
pause
