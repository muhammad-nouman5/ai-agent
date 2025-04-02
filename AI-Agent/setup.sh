#!/bin/bash
echo "Checking for Python installation..."

# Check if Python is installed
if command -v python3 &>/dev/null; then
    echo "Python is already installed."
else
    echo "Python is not installed. Installing Python..."
    # Install Python using the package manager
    if command -v apt-get &>/dev/null; then
        sudo apt-get update
        sudo apt-get install -y python3 python3-pip
    elif command -v yum &>/dev/null; then
        sudo yum install -y python3 python3-pip
    elif command -v brew &>/dev/null; then
        brew install python3
    else
        echo "Unsupported package manager. Please install Python manually."
        exit 1
    fi
    echo "Python installed successfully."
fi

# Install required Python packages
echo "Installing required Python packages..."
pip3 install requests beautifulsoup4 tqdm pyfiglet

echo "Setup completed successfully!"