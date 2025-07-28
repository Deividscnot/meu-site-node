@echo off
echo Finalizando processo que estiver usando a porta 3006...
for /f "tokens=5" %%a in ('netstat -aon ^| findstr :3006 ^| findstr LISTENING') do (
    echo Finalizando PID %%a...
    taskkill /PID %%a /F >nul 2>&1
)

echo Iniciando servidor Node.js...
node server.js
pause
