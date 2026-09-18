import os
import sys
import io
import warnings
import logging
from pathlib import Path

warnings.filterwarnings("ignore")
logging.disable(logging.CRITICAL)

def _ensure(package, import_as=None):
    mod = import_as or package
    try:
        __import__(mod)
    except ImportError:
        import subprocess
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", package, "-q"],
            stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL
        )

_ensure("google-genai", "google.genai")

_real_stderr = sys.stderr
sys.stderr   = io.StringIO()
from google import genai as _genai
sys.stderr   = _real_stderr

class _SilentStderr:
    _SKIP = (
        "Direct use of automatic function calling",
        "AFC", "not recommended", "generate_content_stream",
        "Chat.send_message", "Models.generate_content",
    )
    def __init__(self, real): self._r = real
    def write(self, m):
        if any(p in m for p in self._SKIP): return
        self._r.write(m)
    def flush(self):  self._r.flush()
    def fileno(self): return self._r.fileno()

sys.stderr = _SilentStderr(sys.stderr)

class Engine:
    _instance = None

    def __new__(cls, key=None):
        if cls._instance is None:
            cls._instance = super(Engine, cls).__new__(cls)
            cls._instance._init_engine(key)
        return cls._instance

    def _init_engine(self, key=None):
        self.key = key or self._get_key()
        if self.key:
            try:
                self.client = _genai.Client(api_key=self.key)
            except Exception:
                self.client = None
        else:
            self.client = None
        self.model = "gemini-3.6-flash"

    def _get_key(self):
        cfg = Path.home() / ".xcv_ghost_key"
        k = os.environ.get("GEMINI_API_KEY", "").strip()
        if k: return k
        if cfg.exists():
            return cfg.read_text().strip()
        return None
        
  default_key = "AQ.Ab8RN6INuS0CLgDvrDV6bNc4g1iJHTvC49QjWA3TSUx0dhcuNQ"
    if default_key:
        return default_key
    return None      

    def run(self, prompt: str, category: str = "CTF") -> str:
        if not self.client:
            self._init_engine()
        if not self.client:
            return "[!] AI Engine not configured. API Key missing in ~/.xcv_ghost_key or GEMINI_API_KEY."

        sys_prompt = (
            "You are XCV-GHOST, an elite automated CTF solver engine. "
            "You specialize in solving Capture The Flag challenges across Forensics, Crypto, PWN, and Reverse Engineering. "
            "Your task: Solve the challenge step-by-step, decode/decipher all hidden secrets, "
            "explain the attack or analysis clearly, and if you find or derive the flag, highlight it clearly as: flag{...} or CTF{...}. "
            "Keep your output technical, direct, and focused on solving the CTF."
        )

        full = f"{sys_prompt}\n\n[Category: {category}]\n[Challenge Input / Question]:\n{prompt}"
        try:
            _s, sys.stderr = sys.stderr, io.StringIO()
            resp = self.client.models.generate_content(
                model=self.model, contents=full
            )
            sys.stderr = _s
            return resp.text
        except Exception as e:
            sys.stderr = _s if '_s' in dir() else sys.stderr
            return f"[ERROR] {e}"

