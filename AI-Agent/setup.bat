@echo off
echo Checking for Python installation...

:: Check if Python is installed
python --version >nul 2>&1
if %errorlevel% equ 0 (
    echo Python is already installed.
) else (
    echo Python is not installed. Installing Python...
    :: Download and install Python (replace the URL with the latest Python installer)
    curl -o python_installer.exe https://www.python.org/ftp/python/3.11.5/python-3.11.5-amd64.exe
    start /wait python_installer.exe /quiet InstallAllUsers=1 PrependPath=1
    del python_installer.exe
    echo Python installed successfully.
)

:: Install required Python packages
echo Installing required Python packages...
pip install requests beautifulsoup4 tqdm pyfiglet

echo Setup completed successfully!
pause