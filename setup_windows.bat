@echo off
REM setup_windows.bat - Cài đặt trên Windows
echo.
echo ========================================
echo  CyberSec Multi-Agent - Windows Setup
echo ========================================

REM Kiểm tra Python
python --version >nul 2>&1
if errorlevel 1 (
    echo [LOI] Python chua duoc cai. Tai tai: https://python.org
    pause
    exit /b 1
)
echo [OK] Python da co

REM Kiểm tra Ollama
ollama --version >nul 2>&1
if errorlevel 1 (
    echo [CHU Y] Ollama chua co. Tai tai: https://ollama.com/download/windows
    echo         Sau do chay lai file nay.
    pause
    exit /b 1
)
echo [OK] Ollama da co

REM Pull model
echo.
echo Chon model:
echo   1) qwen2.5:7b   - Khuyen nghi (tieng Viet tot)
echo   2) llama3.2:3b  - Nhe nhat
echo   3) mistral:7b   - Nhanh
set /p choice="Chon (1-3): "

if "%choice%"=="1" set MODEL=qwen2.5:7b
if "%choice%"=="2" set MODEL=llama3.2:3b
if "%choice%"=="3" set MODEL=mistral:7b
if not defined MODEL set MODEL=qwen2.5:7b

echo Dang pull %MODEL%...
ollama pull %MODEL%

REM Cài packages
echo.
echo Cai Python packages...
pip install -r requirements.txt -q
echo [OK] Da cai xong

REM Tạo .env
if not exist .env (
    copy .env.example .env
    echo [OK] Da tao .env
    REM Cập nhật model
    powershell -Command "(Get-Content .env) -replace 'OLLAMA_MODEL=.*', 'OLLAMA_MODEL=%MODEL%' | Set-Content .env"
) else (
    echo [OK] .env da ton tai
)

mkdir reports 2>nul
mkdir docs    2>nul

echo.
echo ========================================
echo  Cai dat hoan tat!
echo.
echo  Khoi dong Ollama: ollama serve
echo  Chay he thong:    python main.py
echo  Kiem tra:         python main.py --check
echo ========================================
pause
