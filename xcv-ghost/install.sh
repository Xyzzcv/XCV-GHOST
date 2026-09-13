#!/bin/bash
# XCV-GHOST Installer
# by xcv | @fatih_onee

RED='\033[1;31m'
NC='\033[0m'

echo -e "${RED}"
echo "  ██╗  ██╗ ██████╗██╗   ██╗       ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗"
echo "  ╚██╗██╔╝██╔════╝██║   ██║      ██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝"
echo "   ╚███╔╝ ██║     ██║   ██║█████╗██║  ███╗███████║██║   ██║███████╗   ██║   "
echo "   ██╔██╗ ██║     ╚██╗ ██╔╝╚════╝██║   ██║██╔══██║██║   ██║╚════██║   ██║   "
echo "  ██╔╝ ██╗╚██████╗ ╚████╔╝       ╚██████╔╝██║  ██║╚██████╔╝███████║   ██║   "
echo "  ╚═╝  ╚═╝ ╚═════╝  ╚═══╝         ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝  "
echo -e "${NC}"
echo -e "${RED}[INSTALLER] XCV-GHOST CTF Tool by xcv | @fatih_onee${NC}"
echo ""

# Check Python
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}[!] Python3 not found. Installing...${NC}"
    if command -v apt &> /dev/null; then
        apt install python3 python3-pip -y
    elif command -v pkg &> /dev/null; then
        pkg install python -y
    elif command -v brew &> /dev/null; then
        brew install python3
    fi
fi

echo -e "${RED}[*] Python: $(python3 --version)${NC}"

# Install deps
echo -e "${RED}[*] Installing dependencies...${NC}"
pip3 install -q google-genai 2>/dev/null || pip install -q google-genai 2>/dev/null

# Create launcher
echo -e "${RED}[*] Creating ghost launcher...${NC}"
cat > /usr/local/bin/ghost << 'LAUNCHER'
#!/bin/bash
python3 "$(dirname "$(readlink -f "$0")")"/../xcv-ghost/ghost.py "$@"
LAUNCHER

# Copy to /usr/local if possible
if [ -w /usr/local/bin ]; then
    cp ghost.py /usr/local/bin/xcv-ghost.py 2>/dev/null
    chmod +x /usr/local/bin/ghost 2>/dev/null
    echo -e "${RED}[+] Installed! Run with: ghost${NC}"
fi

echo ""
echo -e "${RED}[+] Installation complete!${NC}"
echo -e "${RED}[*] Run: python3 ghost.py${NC}"
echo -e "${RED}[*] Set API key: export GEMINI_API_KEY=your_key_here${NC}"
echo ""

