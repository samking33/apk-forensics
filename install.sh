#!/bin/bash

# fSOC APK Forensics - Automated Installation Script
# This script installs all dependencies and sets up the tool

set -e

echo "=================================="
echo "fSOC APK Forensics - Installation"
echo "=================================="
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if running on macOS or Linux
if [[ "$OSTYPE" != "darwin"* ]] && [[ "$OSTYPE" != "linux-gnu"* ]]; then
    echo -e "${RED}Error: This script only supports macOS and Linux${NC}"
    exit 1
fi

echo -e "${GREEN}[*] Checking system requirements...${NC}"

# Check Python 3
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}Error: Python 3 is not installed${NC}"
    echo "Please install Python 3.8 or higher"
    exit 1
fi

PYTHON_VERSION=$(python3 --version | cut -d' ' -f2 | cut -d'.' -f1,2)
echo -e "${GREEN}[+] Python ${PYTHON_VERSION} found${NC}"

# Check Claude CLI
echo -e "${GREEN}[*] Checking for Claude CLI...${NC}"
if ! command -v claude &> /dev/null; then
    echo -e "${YELLOW}Warning: Claude CLI not found${NC}"
    echo "Please install Claude CLI from: https://docs.anthropic.com/claude/docs/cli"
    read -p "Continue anyway? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
else
    CLAUDE_VERSION=$(claude --version 2>&1 | head -n 1)
    echo -e "${GREEN}[+] Claude CLI found: ${CLAUDE_VERSION}${NC}"
fi

# Check/Install forensic tools
echo -e "${GREEN}[*] Checking forensic tools...${NC}"

if command -v brew &> /dev/null; then
    # macOS with Homebrew
    if ! command -v apktool &> /dev/null; then
        echo -e "${YELLOW}[*] Installing apktool...${NC}"
        brew install apktool
    else
        echo -e "${GREEN}[+] apktool found${NC}"
    fi
    
    if ! command -v jadx &> /dev/null; then
        echo -e "${YELLOW}[*] Installing jadx...${NC}"
        brew install jadx
    else
        echo -e "${GREEN}[+] jadx found${NC}"
    fi
else
    # Linux or no Homebrew
    echo -e "${YELLOW}Warning: Homebrew not found. Please install apktool and jadx manually${NC}"
fi

# Create virtual environment
echo -e "${GREEN}[*] Creating virtual environment...${NC}"
if [ -d "venv" ]; then
    echo -e "${YELLOW}Virtual environment already exists${NC}"
else
    python3 -m venv venv
    echo -e "${GREEN}[+] Virtual environment created${NC}"
fi

# Activate virtual environment
echo -e "${GREEN}[*] Installing Python dependencies...${NC}"
source venv/bin/activate

# Upgrade pip
pip install --upgrade pip > /dev/null 2>&1

# Install requirements
pip install -r requirements.txt

echo -e "${GREEN}[+] Python dependencies installed${NC}"

# Create necessary directories
echo -e "${GREEN}[*] Creating directories...${NC}"
mkdir -p logs
mkdir -p apk_analysis

# Make script executable
chmod +x apk_forensics.py

# Create config if it doesn't exist
if [ ! -f "config.yaml" ]; then
    echo -e "${GREEN}[*] Creating default configuration...${NC}"
    cat > config.yaml << 'EOF'
claude:
  model: claude-3-5-sonnet-20241022
  timeout: 600
  auto_approve: true

output:
  directory: apk_analysis
  format: text
  save_logs: true

logging:
  level: INFO
  directory: logs
  max_size_mb: 100
  backup_count: 5

forensic_tools:
  apktool: apktool
  jadx: jadx
EOF
    echo -e "${GREEN}[+] Configuration file created${NC}"
fi

echo ""
echo -e "${GREEN}=================================="
echo "Installation Complete!"
echo "==================================${NC}"
echo ""
echo "To use the tool:"
echo "  1. Activate virtual environment: source venv/bin/activate"
echo "  2. Run the tool: python apk_forensics.py"
echo ""
echo "For help: python apk_forensics.py --help"
echo ""
