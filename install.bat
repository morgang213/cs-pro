@echo off
REM CyberSec Terminal - Windows Installation Script
REM Professional Cybersecurity Analysis Platform

echo.
echo 🛡️  CyberSec Terminal - Windows Installation
echo ==============================================

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python is not installed or not in PATH
    echo Please install Python 3.7+ from https://www.python.org/downloads/
    echo Make sure to check "Add Python to PATH" during installation
    pause
    exit /b 1
)

echo [INFO] Python found
for /f "tokens=2" %%i in ('python --version') do set PYTHON_VERSION=%%i
echo [SUCCESS] Python %PYTHON_VERSION% detected

REM Check if pip is available
python -m pip --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] pip is not available
    echo Please reinstall Python with pip included
    pause
    exit /b 1
)

echo [SUCCESS] pip is available

REM Create virtual environment
if not exist "venv" (
    echo [INFO] Creating virtual environment...
    python -m venv venv
    echo [SUCCESS] Virtual environment created
) else (
    echo [WARNING] Virtual environment already exists
)

REM Activate virtual environment
echo [INFO] Activating virtual environment...
call venv\Scripts\activate.bat

REM Upgrade pip
echo [INFO] Upgrading pip...
python -m pip install --upgrade pip

REM Install requirements
if exist "requirements.txt" (
    echo [INFO] Installing requirements from requirements.txt...
    pip install -r requirements.txt
) else (
    echo [INFO] Installing basic packages...
    pip install flask colorama requests python-whois dnspython cryptography
)

if errorlevel 1 (
    echo [ERROR] Failed to install requirements
    pause
    exit /b 1
)

echo [SUCCESS] Requirements installed successfully

REM Install package in development mode
if exist "setup.py" (
    echo [INFO] Installing CyberSec Terminal package...
    pip install -e .
    if errorlevel 1 (
        echo [WARNING] Package installation failed, but core files are available
    ) else (
        echo [SUCCESS] Package installed successfully
    )
)

REM Create batch files for easy access
echo [INFO] Creating launch scripts...

echo @echo off > cybersec.bat
echo cd /d "%%~dp0" >> cybersec.bat
echo call venv\Scripts\activate.bat >> cybersec.bat
echo python launch_terminal.py >> cybersec.bat
echo pause >> cybersec.bat

echo @echo off > cybersec-web.bat
echo cd /d "%%~dp0" >> cybersec-web.bat
echo call venv\Scripts\activate.bat >> cybersec-web.bat
echo python terminal_web.py >> cybersec-web.bat
echo pause >> cybersec-web.bat

echo @echo off > cybersec-cli.bat
echo cd /d "%%~dp0" >> cybersec-cli.bat
echo call venv\Scripts\activate.bat >> cybersec-cli.bat
echo python app.py >> cybersec-cli.bat
echo pause >> cybersec-cli.bat

echo [SUCCESS] Launch scripts created

echo.
echo ✅ Installation Complete!
echo.
echo 🚀 Quick Start:
echo   cybersec.bat          - Launch terminal selector
echo   cybersec-web.bat      - Start web terminal
echo   cybersec-cli.bat      - Start CLI terminal
echo.
echo 🌐 Web Terminal:
echo   Run cybersec-web.bat and open http://127.0.0.1:5000
echo.
echo ⚠️  Important:
echo   - Use only on systems you own or have permission to test
echo   - Follow responsible disclosure practices
echo   - Keep Windows Defender/antivirus updated
echo.
echo Happy Security Testing! 🛡️
echo.
pause
