# XCV-GHOST — AI-Powered CTF Tool
```
██╗  ██╗ ██████╗██╗   ██╗       ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗
╚██╗██╔╝██╔════╝██║   ██║      ██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝
 ╚███╔╝ ██║     ██║   ██║█████╗██║  ███╗███████║██║   ██║███████╗   ██║   
 ██╔██╗ ██║     ╚██╗ ██╔╝╚════╝██║   ██║██╔══██║██║   ██║╚════██║   ██║   
██╔╝ ██╗╚██████╗ ╚████╔╝       ╚██████╔╝██║  ██║╚██████╔╝███████║   ██║   
╚═╝  ╚═╝ ╚═════╝  ╚═══╝         ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝   
```
> **by xcv and yogarmdn | @fatih_onee**  
> AI-Powered CTF Assistant — Forensics • PWN • Crypto • Reverse

---

## ⚡ Quick Start

### 1. Get Free Gemini API Key
→ https://aistudio.google.com/apikey

### 2. Install & Run

**Linux / macOS:**
```bash
git clone https://github.com/xcv/xcv-ghost
cd xcv-ghost
pip3 install -r requirements.txt
python3 ghost.py
```

**Termux (Android):**
```bash
pkg install python git -y
pip install google-genai
python ghost.py
```

**Windows (PowerShell / CMD):**
```powershell
pip install google-genai
python ghost.py
```

### 3. Set API Key (optional, faster)
```bash
export GEMINI_API_KEY="your_key_here"   # Linux/Termux/macOS
set GEMINI_API_KEY=your_key_here        # Windows CMD
$env:GEMINI_API_KEY="your_key_here"     # PowerShell
```

---

## 🗂 Modules

| Module | Features |
|--------|----------|
| 🔍 **Forensics** | File analysis, steganography, metadata, decoder (base64/hex/rot/bin/url), network PCAP |
| 💀 **PWN** | Buffer overflow, ROP chain, format string, shellcode, pwntools generator |
| 🔐 **Crypto** | Caesar brute-force, XOR solver, RSA solver, hash ID, Vigenere |
| ⚙️ **Reverse** | Binary info, disassembly help, anti-debug bypass, strings, .pyc/.class decompile |
| 🤖 **AI** | Auto-solve CTF with Gemini (flag finder), file analysis, concept explainer, chat |

---

## 📋 Requirements

- Python 3.7+
- `google-genai` (auto-installed)
- Gemini API Key (free)

Optional tools: `exiftool`, `strings`, `file`, `checksec`

---

## 🤖 AI Module Usage

```bash
python ghost.py
use ai
run key <your_gemini_api_key>      # Save & validate API key
run solve challenge.txt            # Solve CTF from file, auto-extract flag
run solve "some CTF question"      # Solve from text input
run analyze binary.exe             # Deep AI analysis of a file
run all challenge.txt              # Comprehensive solving suite
run multi part1.txt part2.txt      # Solve using MULTIPLE files together
run explain rsa                    # Explain a CTF concept
run chat "how to do buffer overflow?"
run key                            # Check current API key status
```

The `multi` command reads multiple files, combines them into a single prompt, and asks Gemini to correlate the files, reconstruct split/encoded data, and extract the final flag.

---

## 👤 Author

- **Name Credit Tool:** YogaRmdn
- **Name Edit Tool:** xcv  
- **Instagram:** [@fatih_onee](https://instagram.com/fatih_onee)  
- **Tool:** XCV-GHOST v1.0.0

---

> *"In darkness, the ghost sees all."* — xcv

