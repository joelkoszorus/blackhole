#!/bin/bash

# Navigate to the script's directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
cd "$SCRIPT_DIR"

VENV_DIR=".venv"

# Create virtual environment if it doesn't exist
if [ ! -d "$VENV_DIR" ]; then
    echo "Creating virtual environment..."
    python3 -m venv "$VENV_DIR"
fi

# Activate virtual environment
source "$VENV_DIR/bin/activate"

# Install dependencies
echo "Installing/updating dependencies..."
pip install -r requirements.txt

# Run the DNS Sinkhole application with sudo
echo "Starting DNS Sinkhole application (requires sudo for port 53 binding)..."
# Pass the remaining arguments to the python script if any
sudo "$VENV_DIR/bin/python" "$SCRIPT_DIR/main.py" "$@"
