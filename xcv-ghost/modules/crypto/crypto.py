import base64
import binascii
import hashlib
import string
import math
from pathlib import Path
from collections import Counter
from core.base import BaseModule
from core.logger import Logger
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box
from rich.text import Text
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import itertools

console = Console()
logger = Logger()


class CryptoModule(BaseModule):
    def __init__(self):
        super().__init__()
        self.name = "crypto"

    def get_commands(self):
        return {
            "_description": "Cryptography tools",
            "base64": {
                "help": "Base64 encode/decode",
                "usage": "base64 [-e/-d] <data>",
                "handler": self.cmd_base64,
                "args": [
                    {"flags": ["data"], "help": "Data to process", "type": str},
                    {"flags": ["-e", "--encode"], "help": "Encode mode", "action": "store_true"},
                    {"flags": ["-d", "--decode"], "help": "Decode mode", "action": "store_true"}
                ]
            },
            "hex": {
                "help": "Hex encode/decode",
                "usage": "hex [-e/-d] <data>",
                "handler": self.cmd_hex,
                "args": [
                    {"flags": ["data"], "help": "Data to process", "type": str},
                    {"flags": ["-e", "--encode"], "help": "Encode mode", "action": "store_true"},
                    {"flags": ["-d", "--decode"], "help": "Decode mode", "action": "store_true"}
                ]
            },
            "rot13": {
                "help": "ROT13 cipher",
                "usage": "rot13 <text>",
                "handler": self.cmd_rot13,
                "args": [
                    {"flags": ["text"], "help": "Text to transform", "type": str}
                ]
            },
            "caesar": {
                "help": "Caesar cipher encrypt/decrypt",
                "usage": "caesar <text> <shift>",
                "handler": self.cmd_caesar,
                "args": [
                    {"flags": ["text"], "help": "Text to process", "type": str},
                    {"flags": ["shift"], "help": "Shift value (0-25)", "type": int, "default": 3}
                ]
            },
            "xor": {
                "help": "XOR encrypt/decrypt",
                "usage": "xor <data> <key>",
                "handler": self.cmd_xor,
                "args": [
                    {"flags": ["data"], "help": "Data to XOR", "type": str},
                    {"flags": ["key"], "help": "XOR key", "type": str, "default": ""}
                ]
            },
            "aes": {
                "help": "AES encrypt/decrypt",
                "usage": "aes [-e/-d] <data> <key> [iv]",
                "handler": self.cmd_aes,
                "args": [
                    {"flags": ["data"], "help": "Data to process", "type": str},
                    {"flags": ["key"], "help": "AES key (16/24/32 bytes)", "type": str},
                    {"flags": ["-e", "--encode"], "help": "Encrypt mode", "action": "store_true"},
                    {"flags": ["-d", "--decode"], "help": "Decrypt mode", "action": "store_true"},
                    {"flags": ["-i", "--iv"], "help": "Initialization vector", "type": str, "default": ""}
                ]
            },
            "hash": {
                "help": "Generate hash of input",
                "usage": "hash <data> [algorithm]",
                "handler": self.cmd_hash,
                "args": [
                    {"flags": ["data"], "help": "Data to hash", "type": str},
                    {"flags": ["-a", "--algorithm"], "help": "Hash algorithm", "type": str, "default": "sha256"}
                ]
            },
            "hashid": {
                "help": "Identify hash type",
                "usage": "hashid <hash>",
                "handler": self.cmd_hashid,
                "args": [
                    {"flags": ["hash"], "help": "Hash to identify", "type": str}
                ]
            },
            "crack": {
                "help": "Dictionary hash cracker",
                "usage": "crack <hash> <wordlist> [algorithm]",
                "handler": self.cmd_crack,
                "args": [
                    {"flags": ["hash"], "help": "Hash to crack", "type": str},
                    {"flags": ["wordlist"], "help": "Path to wordlist", "type": str},
                    {"flags": ["-a", "--algorithm"], "help": "Hash algorithm", "type": str, "default": "sha256"}
                ]
            },
            "freq": {
                "help": "Frequency analysis",
                "usage": "freq <text>",
                "handler": self.cmd_freq,
                "args": [
                    {"flags": ["text"], "help": "Text to analyze", "type": str}
                ]
            },
            "all": {
                "help": "Run ALL cryptography tools on input data",
                "usage": "all <data>",
                "handler": self.cmd_all,
                "args": [
                    {"flags": ["data"], "help": "Data to process", "type": str}
                ]
            }
        }

    def cmd_base64(self, args):
        data = args.data
        if args.decode:
            try:
                padding = 4 - len(data) % 4
                if padding != 4:
                    data += '=' * padding
                decoded = base64.b64decode(data).decode('utf-8', errors='replace')
                console.print(f"\n[green]Decoded:[/green] {decoded}")
                return {"decoded": decoded}
            except Exception as e:
                logger.error(f"Base64 decode failed: {e}")
                return None
        else:
            encoded = base64.b64encode(data.encode() if isinstance(data, str) else data).decode()
            console.print(f"\n[green]Encoded:[/green] {encoded}")
            return {"encoded": encoded}

    def cmd_hex(self, args):
        data = args.data
        if args.decode:
            try:
                decoded = bytes.fromhex(data).decode('utf-8', errors='replace')
                console.print(f"\n[green]Decoded:[/green] {decoded}")
                return {"decoded": decoded}
            except Exception as e:
                logger.error(f"Hex decode failed: {e}")
                return None
        else:
            encoded = data.encode().hex() if isinstance(data, str) else binascii.hexlify(data).decode()
            console.print(f"\n[green]Encoded:[/green] {encoded}")
            return {"encoded": encoded}

    def cmd_rot13(self, args):
        result = self._rot13(args.text)
        console.print(f"\n[green]ROT13:[/green] {result}")
        return {"rot13": result}

    def cmd_caesar(self, args):
        shift = args.shift % 26
        result = self._caesar(args.text, shift)

        table = Table(title="Caesar Cipher", box=box.ROUNDED, border_style="cyan")
        table.add_column("Shift", style="bold yellow")
        table.add_column("Result", style="white")
        table.add_row(str(shift), result)
        console.print(table)

        if shift == 0 or not args.text:
            return {"caesar": result}

        console.print("\n[bold cyan]All shifts:[/bold cyan]")
        for s in range(26):
            shifted = self._caesar(args.text, s)
            console.print(f"  [{s:>2}] {shifted}")

        return {"caesar": result, "all_shifts": {s: self._caesar(args.text, s) for s in range(26)}}

    def cmd_xor(self, args):
        data = args.data.encode() if isinstance(args.data, str) else args.data
        key = args.key.encode() if isinstance(args.key, str) else args.key

        if not key:
            logger.error("XOR key is required")
            return

        result = bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])

        hex_result = result.hex()
        ascii_result = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in result)

        table = Table(title="XOR Result", box=box.ROUNDED, border_style="cyan")
        table.add_column("Format", style="bold yellow")
        table.add_column("Value", style="white")
        table.add_row("Hex", hex_result)
        table.add_row("ASCII", ascii_result)

        console.print(table)
        return {"hex": hex_result, "ascii": ascii_result}

    def cmd_aes(self, args):
        key = args.key.encode() if isinstance(args.key, str) else args.key
        data = args.data

        # Adjust key size
        if len(key) not in [16, 24, 32]:
            if len(key) < 16:
                key = key.ljust(16, b'\0')
            elif len(key) < 24:
                key = key.ljust(24, b'\0')
            else:
                key = key[:32]

        try:
            if args.decode:
                iv = bytes.fromhex(args.iv) if args.iv else b'\0' * 16
                cipher = AES.new(key, AES.MODE_CBC, iv)
                data_bytes = bytes.fromhex(data) if all(c in '0123456789abcdef' for c in data.lower()) else base64.b64decode(data)
                decrypted = unpad(cipher.decrypt(data_bytes), AES.block_size)
                result = decrypted.decode('utf-8', errors='replace')
                console.print(f"\n[green]Decrypted:[/green] {result}")
                return {"decrypted": result}
            else:
                iv = bytes.fromhex(args.iv) if args.iv else b'\0' * 16
                cipher = AES.new(key, AES.MODE_CBC, iv)
                data_bytes = data.encode() if isinstance(data, str) else data
                encrypted = cipher.encrypt(pad(data_bytes, AES.block_size))
                encoded = base64.b64encode(encrypted).decode()
                console.print(f"\n[green]Encrypted (Base64):[/green] {encoded}")
                console.print(f"[green]Encrypted (Hex):[/green] {encrypted.hex()}")
                return {"base64": encoded, "hex": encrypted.hex()}
        except Exception as e:
            logger.error(f"AES operation failed: {e}")
            return None

    def cmd_hash(self, args):
        data = args.data.encode() if isinstance(args.data, str) else args.data
        algorithm = args.algorithm.lower()

        hash_map = {
            'md5': hashlib.md5,
            'sha1': hashlib.sha1,
            'sha224': hashlib.sha224,
            'sha256': hashlib.sha256,
            'sha384': hashlib.sha384,
            'sha512': hashlib.sha512,
            'blake2b': hashlib.blake2b,
            'blake2s': hashlib.blake2s,
            'sha3_256': hashlib.sha3_256,
            'sha3_512': hashlib.sha3_512,
        }

        if algorithm not in hash_map:
            logger.error(f"Unknown hash algorithm: {algorithm}")
            console.print(f"[yellow]Available: {', '.join(hash_map.keys())}[/yellow]")
            return

        hash_obj = hash_map[algorithm](data)
        result = hash_obj.hexdigest()

        table = Table(title="Hash Result", box=box.ROUNDED, border_style="cyan")
        table.add_column("Algorithm", style="bold yellow")
        table.add_column("Hash", style="white")
        table.add_row(algorithm.upper(), result)

        console.print(table)
        return {"algorithm": algorithm, "hash": result}

    def cmd_hashid(self, args):
        hash_str = args.hash.strip()
        length = len(hash_str)
        table = Table(title=f"Hash Identification", box=box.ROUNDED, border_style="cyan")
        table.add_column("Type", style="bold yellow")
        table.add_column("Length", style="white")
        table.add_column("Confidence", style="green")

        identifications = self._identify_hash(hash_str, length)
        if identifications:
            for ident in identifications:
                table.add_row(ident["type"], str(ident["length"]), ident["confidence"])
        else:
            table.add_row("Unknown", str(length), "-")

        console.print(table)
        console.print(f"\n[dim]Hash: {hash_str}[/dim]")
        return identifications

    def cmd_crack(self, args):
        target_hash = args.hash.strip().lower()
        wordlist_path = Path(args.wordlist)
        algorithm = args.algorithm.lower()

        if not wordlist_path.exists():
            logger.error(f"Wordlist not found: {wordlist_path}")
            return

        hash_map = {
            'md5': hashlib.md5,
            'sha1': hashlib.sha1,
            'sha224': hashlib.sha224,
            'sha256': hashlib.sha256,
            'sha384': hashlib.sha384,
            'sha512': hashlib.sha512,
        }

        if algorithm not in hash_map:
            logger.error(f"Unknown algorithm: {algorithm}")
            return

        total = sum(1 for _ in open(wordlist_path, 'r', errors='ignore'))
        hash_func = hash_map[algorithm]

        console.print(f"[cyan]Cracking {algorithm}:{target_hash}")
        console.print(f"[cyan]Wordlist: {wordlist_path} ({total:,} words)[/cyan]\n")

        found = None
        with logger.progress() as progress:
            task = progress.add_task("[cyan]Cracking...", total=total)
            with open(wordlist_path, 'r', errors='ignore') as f:
                for i, line in enumerate(f):
                    word = line.strip()
                    if hash_func(word.encode()).hexdigest() == target_hash:
                        found = word
                        break
                    if i % 1000 == 0:
                        progress.update(task, completed=i)

        if found:
            console.print(f"\n[bold green]✓ Password found: {found}[/bold green]")
        else:
            console.print(f"\n[red]✗ Password not found in wordlist[/red]")

        return {"found": found}

    def cmd_freq(self, args):
        text = args.text
        counter = Counter(text.lower())
        total = len([c for c in text if c.isalpha()])

        if total == 0:
            logger.error("No alphabetic characters to analyze")
            return

        english_freq = {
            'a': 8.167, 'b': 1.492, 'c': 2.782, 'd': 4.253, 'e': 12.702,
            'f': 2.228, 'g': 2.015, 'h': 6.094, 'i': 6.966, 'j': 0.153,
            'k': 0.772, 'l': 4.025, 'm': 2.406, 'n': 6.749, 'o': 7.507,
            'p': 1.929, 'q': 0.095, 'r': 5.987, 's': 6.327, 't': 9.056,
            'u': 2.758, 'v': 0.978, 'w': 2.360, 'x': 0.150, 'y': 1.974,
            'z': 0.074
        }

        table = Table(title="Frequency Analysis", box=box.ROUNDED, border_style="cyan")
        table.add_column("Char", style="bold yellow")
        table.add_column("Count", style="white")
        table.add_column("Frequency", style="cyan")
        table.add_column("Bar", style="white")
        table.add_column("English", style="green")

        sorted_chars = sorted(counter.items(), key=lambda x: x[1], reverse=True)
        for char, count in sorted_chars:
            if char in english_freq:
                freq = count / total * 100
                bar = "█" * int(freq / 2) + "░" * (20 - int(freq / 2))
                table.add_row(
                    f"'{char}'",
                    str(count),
                    f"{freq:.2f}%",
                    bar,
                    f"{english_freq[char]:.2f}%"
                )

        console.print(table)
        console.print(f"\n[cyan]Total alphabetic characters: {total}[/cyan]")

        ic = self._index_of_coincidence(text)
        console.print(f"[cyan]Index of Coincidence: {ic:.4f} (expected English: ~0.0667)[/cyan]")

        if ic < 0.05:
            console.print("[yellow]Low IoC - likely polyalphabetic cipher (e.g., Vigenere)[/yellow]")
        elif ic > 0.06:
            console.print("[green]High IoC - likely monoalphabetic substitution or plaintext[/green]")

        return {
            "frequencies": {c: count / total * 100 for c, count in sorted_chars if c in english_freq},
            "index_of_coincidence": round(ic, 4),
            "total": total
        }

    def _rot13(self, text):
        result = []
        for c in text:
            if 'a' <= c <= 'z':
                result.append(chr((ord(c) - ord('a') + 13) % 26 + ord('a')))
            elif 'A' <= c <= 'Z':
                result.append(chr((ord(c) - ord('A') + 13) % 26 + ord('A')))
            else:
                result.append(c)
        return ''.join(result)

    def _caesar(self, text, shift):
        result = []
        for c in text:
            if 'a' <= c <= 'z':
                result.append(chr((ord(c) - ord('a') + shift) % 26 + ord('a')))
            elif 'A' <= c <= 'Z':
                result.append(chr((ord(c) - ord('A') + shift) % 26 + ord('A')))
            else:
                result.append(c)
        return ''.join(result)

    def _index_of_coincidence(self, text):
        letters = [c.lower() for c in text if c.isalpha()]
        n = len(letters)
        if n <= 1:
            return 0
        freq = Counter(letters)
        ic = sum(f * (f - 1) for f in freq.values()) / (n * (n - 1))
        return ic

    def _identify_hash(self, hash_str, length):
        patterns = [
            (32, ('MD5', 'MD4', 'MD2', 'RIPEMD-128'), 'High'),
            (40, ('SHA-1', 'RIPEMD-160', 'HAS-160'), 'High'),
            (56, ('SHA-224', 'SHA3-224', 'BLAKE2s-224'), 'High'),
            (64, ('SHA-256', 'SHA3-256', 'BLAKE2s-256', 'RIPEMD-256', 'GOST'), 'High'),
            (96, ('SHA-384', 'SHA3-384', 'BLAKE2b-384'), 'High'),
            (128, ('SHA-512', 'SHA3-512', 'BLAKE2b-512'), 'High'),
        ]

        results = []
        if all(c in '0123456789abcdef' for c in hash_str.lower()):
            for l, types, conf in patterns:
                if length == l:
                    for t in types:
                        results.append({"type": t, "length": l, "confidence": conf})
                    break
        elif all(c in '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ' for c in hash_str):
            for l, types, conf in patterns:
                if length == l:
                    for t in types:
                        results.append({"type": t + " (Base64)", "length": l, "confidence": "Medium"})
                    break
            if length == 16:
                results.append({"type": "MySQL 3.x", "length": 16, "confidence": "Medium"})
            elif length == 34:
                results.append({"type": "MySQL 4.x/5.x", "length": 34, "confidence": "Medium"})

        if length == 60:
            results.append({"type": "BLAKE2b-480", "length": 60, "confidence": "Low"})

        if not results:
            patterns_other = [
                (13, 'DES (Unix)'),
                (16, 'MySQL 3.x, DES (Oracle)'),
                (20, 'SHA-1 (Base64)'),
                (24, 'LM, Axel'),
                (29, 'Windows LM'),
                (32, 'NTLM, MD4, MD5'),
                (34, 'MySQL 5.x'),
                (37, 'MD5 (Base64)'),
                (40, 'SHA-1, RIPEMD-160'),
                (41, 'SHA-1 (Base64)'),
                (43, 'SHA-1 (Base64)'),
                (44, 'SHA-256 (Base64)'),
                (56, 'SHA-224, SHA3-224'),
                (64, 'SHA-256, SHA3-256, BLAKE2-256'),
                (86, 'SHA-384 (Base64)'),
                (88, 'SHA-384 (Base64)'),
                (96, 'SHA-384, SHA3-384'),
                (128, 'SHA-512, SHA3-512, BLAKE2-512'),
            ]
            for l, t in patterns_other:
                if length == l:
                    results.append({"type": t, "length": l, "confidence": "Low"})

        return results

    def cmd_all(self, args):
        from core.base import extract_flags, print_final_flag_summary
        data = args.data.strip()
        console.print(f"\n[bold cyan]=== RUNNING ALL CRYPTO ANALYSIS TOOLS ===[/bold cyan]")
        console.print(f"[yellow]Input Data:[/yellow] {data[:100]}{'...' if len(data)>100 else ''}\n")

        collected_flags = set()
        collected_flags.update(extract_flags(data))

        class FakeArgs: pass
        fa = FakeArgs()

        # 1. Base64
        console.print("[bold red][1] BASE64 DECODE/ENCODE[/bold red]")
        fa.data = data
        fa.decode = True
        r1 = self.cmd_base64(fa)
        if r1: collected_flags.update(extract_flags(str(r1)))
        fa.decode = False
        r2 = self.cmd_base64(fa)
        if r2: collected_flags.update(extract_flags(str(r2)))
        console.print()

        # 2. Hex
        console.print("[bold red][2] HEX DECODE/ENCODE[/bold red]")
        fa.data = data
        fa.decode = True
        r3 = self.cmd_hex(fa)
        if r3: collected_flags.update(extract_flags(str(r3)))
        fa.decode = False
        r4 = self.cmd_hex(fa)
        if r4: collected_flags.update(extract_flags(str(r4)))
        console.print()

        # 3. ROT13
        console.print("[bold red][3] ROT13[/bold red]")
        fa.text = data
        r5 = self.cmd_rot13(fa)
        if r5: collected_flags.update(extract_flags(str(r5)))
        console.print()

        # 4. Caesar Shifts
        console.print("[bold red][4] CAESAR SHIFTS (0-25)[/bold red]")
        fa.text = data
        fa.shift = 3
        r6 = self.cmd_caesar(fa)
        if r6: collected_flags.update(extract_flags(str(r6)))
        console.print()

        # 5. Hash Identification & Hashes Generation
        console.print("[bold red][5] HASH IDENTIFICATION & GENERATION[/bold red]")
        fa.hash = data
        self.cmd_hashid(fa)
        fa.data = data
        fa.algorithm = "md5"
        self.cmd_hash(fa)
        fa.algorithm = "sha1"
        self.cmd_hash(fa)
        fa.algorithm = "sha256"
        self.cmd_hash(fa)
        console.print()

        # 6. Frequency Analysis
        console.print("[bold red][6] FREQUENCY ANALYSIS[/bold red]")
        fa.text = data
        self.cmd_freq(fa)
        console.print()

        console.print("[bold green]✓ All crypto tools executed successfully![/bold green]")

        # --- FINAL FLAG SUMMARY AT THE VERY END ---
        print_final_flag_summary(list(collected_flags))


