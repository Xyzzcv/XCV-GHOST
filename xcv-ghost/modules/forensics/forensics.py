import os
import struct
import zipfile
import math
from pathlib import Path
from core.base import BaseModule
from core.logger import Logger
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box
from rich.text import Text
from datetime import datetime

console = Console()
logger = Logger()

try:
    from PIL import ExifTags, Image
except ImportError:
    Image = None

try:
    import yara
except ImportError:
    yara = None

try:
    from scapy.all import rdpcap, Ether, IP, TCP, UDP
except ImportError:
    rdpcap = None

try:
    import binwalk
except ImportError:
    binwalk = None


class ForensicsModule(BaseModule):
    def __init__(self):
        super().__init__()
        self.name = "forensics"

    def get_commands(self):
        return {
            "_description": "Forensics analysis tools",
            "metadata": {
                "help": "Extract file metadata",
                "usage": "metadata <filepath>",
                "handler": self.cmd_metadata,
                "args": [
                    {"flags": ["filepath"], "help": "Path to file", "type": str}
                ]
            },
            "exif": {
                "help": "Extract EXIF data from images",
                "usage": "exif <image_file>",
                "handler": self.cmd_exif,
                "args": [
                    {"flags": ["filepath"], "help": "Path to image file", "type": str}
                ]
            },
            "strings": {
                "help": "Extract strings from file",
                "usage": "strings <filepath> [min_length]",
                "handler": self.cmd_strings,
                "args": [
                    {"flags": ["filepath"], "help": "Path to file", "type": str},
                    {"flags": ["-n", "--min"], "help": "Minimum string length", "type": int, "default": 4}
                ]
            },
            "hidden": {
                "help": "Detect hidden files in archive or image",
                "usage": "hidden <filepath>",
                "handler": self.cmd_hidden,
                "args": [
                    {"flags": ["filepath"], "help": "Path to file", "type": str}
                ]
            },
            "entropy": {
                "help": "Calculate file entropy",
                "usage": "entropy <filepath>",
                "handler": self.cmd_entropy,
                "args": [
                    {"flags": ["filepath"], "help": "Path to file", "type": str}
                ]
            },
            "signature": {
                "help": "Check file signature (magic bytes)",
                "usage": "signature <filepath>",
                "handler": self.cmd_signature,
                "args": [
                    {"flags": ["filepath"], "help": "Path to file", "type": str}
                ]
            },
            "yara": {
                "help": "Scan file with YARA rules",
                "usage": "yara <filepath> [rules_file]",
                "handler": self.cmd_yara,
                "args": [
                    {"flags": ["filepath"], "help": "Path to file", "type": str},
                    {"flags": ["-r", "--rules"], "help": "YARA rules file", "type": str, "default": ""}
                ]
            },
            "zip": {
                "help": "Analyze ZIP file structure",
                "usage": "zip <filepath>",
                "handler": self.cmd_zip,
                "args": [
                    {"flags": ["filepath"], "help": "Path to ZIP file", "type": str}
                ]
            },
            "pcap": {
                "help": "Basic PCAP analysis",
                "usage": "pcap <filepath>",
                "handler": self.cmd_pcap,
                "args": [
                    {"flags": ["filepath"], "help": "Path to PCAP file", "type": str}
                ]
            },
            "binwalk": {
                "help": "Scan for embedded files (binwalk)",
                "usage": "binwalk <filepath>",
                "handler": self.cmd_binwalk,
                "args": [
                    {"flags": ["filepath"], "help": "Path to file", "type": str}
                ]
            },
            "all": {
                "help": "Run all forensics analysis on a file",
                "usage": "all <filepath>",
                "handler": self.cmd_all,
                "args": [
                    {"flags": ["filepath"], "help": "Path to file", "type": str}
                ]
            }
        }

    def cmd_metadata(self, args):
        filepath = Path(args.filepath)
        if not filepath.exists():
            logger.error(f"File not found: {filepath}")
            return

        stat = filepath.stat()
        table = Table(title=f"Metadata: {filepath.name}", box=box.ROUNDED, border_style="cyan")
        table.add_column("Property", style="bold yellow")
        table.add_column("Value", style="white")

        table.add_row("File Name", filepath.name)
        table.add_row("File Size", f"{stat.st_size:,} bytes ({self._human_size(stat.st_size)})")
        table.add_row("Created", datetime.fromtimestamp(stat.st_ctime).strftime('%Y-%m-%d %H:%M:%S'))
        table.add_row("Modified", datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S'))
        table.add_row("Accessed", datetime.fromtimestamp(stat.st_atime).strftime('%Y-%m-%d %H:%M:%S'))
        table.add_row("Permissions", oct(stat.st_mode)[-3:])
        table.add_row("Extension", filepath.suffix)
        table.add_row("Absolute Path", str(filepath.absolute()))

        console.print(table)
        return {
            "name": filepath.name,
            "size": stat.st_size,
            "created": datetime.fromtimestamp(stat.st_ctime).isoformat(),
            "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
            "accessed": datetime.fromtimestamp(stat.st_atime).isoformat(),
            "permissions": oct(stat.st_mode)[-3:],
            "extension": filepath.suffix
        }

    def cmd_exif(self, args):
        if not Image:
            logger.error("PIL/Pillow not installed. Install with: pip install Pillow")
            return

        filepath = Path(args.filepath)
        if not filepath.exists():
            logger.error(f"File not found: {filepath}")
            return

        try:
            img = Image.open(filepath)
            exif_data = img._getexif()
            if not exif_data:
                console.print("[yellow]No EXIF data found.[/yellow]")
                return {"exif": "No EXIF data found"}

            table = Table(title=f"EXIF Data: {filepath.name}", box=box.ROUNDED, border_style="green")
            table.add_column("Tag", style="bold yellow")
            table.add_column("Value", style="white")

            for tag_id, value in exif_data.items():
                tag_name = ExifTags.TAGS.get(tag_id, f"Unknown ({tag_id})")
                table.add_row(str(tag_name), str(value)[:100])

            console.print(table)
            return {ExifTags.TAGS.get(tag_id, str(tag_id)): str(value) for tag_id, value in exif_data.items()}
        except Exception as e:
            logger.error(f"EXIF read failed: {e}")
            return None

    def cmd_strings(self, args):
        filepath = Path(args.filepath)
        if not filepath.exists():
            logger.error(f"File not found: {filepath}")
            return

        min_len = getattr(args, 'min', 4)
        data = self.read_file(filepath)

        result = []
        current = []
        for byte in data:
            if 32 <= byte <= 126:
                current.append(chr(byte))
            else:
                if len(current) >= min_len:
                    result.append(''.join(current))
                current = []

        if len(current) >= min_len:
            result.append(''.join(current))

        console.print(f"[green]Found {len(result)} strings (min length: {min_len})[/green]")
        for i, s in enumerate(result, 1):
            console.print(f"  [dim]{i:>5}[/dim] {s[:200]}")

        return result

    def cmd_hidden(self, args):
        filepath = Path(args.filepath)
        if not filepath.exists():
            logger.error(f"File not found: {filepath}")
            return

        results = []
        console.print(f"[cyan]Scanning for hidden files in: {filepath.name}[/cyan]")

        data = self.read_file(filepath)

        # Check for ZIP appended data
        if data[:2] == b'PK':
            try:
                with zipfile.ZipFile(filepath) as zf:
                    for info in zf.infolist():
                        results.append({
                            "type": "zip_entry",
                            "name": info.filename,
                            "size": info.file_size,
                            "compressed": info.compress_size
                        })
                    console.print(f"[green]ZIP contains {len(results)} entries[/green]")
            except:
                pass

        # Check for appended data after ZIP
        if b'PK\x05\x06' in data:
            eocd_pos = data.rfind(b'PK\x05\x06')
            if eocd_pos + 22 < len(data):
                extra = data[eocd_pos + 22:]
                if extra.strip():
                    results.append({
                        "type": "appended_data",
                        "offset": eocd_pos + 22,
                        "size": len(extra),
                        "description": "Data appended after ZIP central directory"
                    })
                    console.print(f"[red]⚠ Appended data found at offset {eocd_pos + 22} ({len(extra)} bytes)[/red]")

        file_sigs = {
            b'\x89PNG': 'PNG Image',
            b'\xff\xd8\xff': 'JPEG Image',
            b'GIF8': 'GIF Image',
            b'%PDF': 'PDF Document',
            b'PK\x03\x04': 'ZIP Archive',
            b'\x7fELF': 'ELF Binary',
            b'MZ': 'PE Binary',
        }

        for sig, desc in file_sigs.items():
            pos = data.find(sig, 1)
            if pos != -1:
                results.append({
                    "type": "embedded_file",
                    "offset": pos,
                    "signature": desc,
                    "description": f"Embedded {desc} at offset {pos}"
                })
                console.print(f"[yellow]Embedded {desc} at offset {pos}[/yellow]")

        if not results:
            console.print("[green]No hidden files detected.[/green]")

        return results

    def cmd_entropy(self, args):
        filepath = Path(args.filepath)
        if not filepath.exists():
            logger.error(f"File not found: {filepath}")
            return

        data = self.read_file(filepath)
        entropy = self._calculate_entropy(data)

        bar_len = 40
        filled = int(entropy / 8.0 * bar_len)
        bar = "█" * filled + "░" * (bar_len - filled)

        console.print()
        console.print(Panel(
            f"[bold]File:[/bold] {filepath.name}\n"
            f"[bold]Size:[/bold] {len(data):,} bytes\n"
            f"[bold]Entropy:[/bold] {entropy:.4f} / 8.0\n\n"
            f"[cyan]{bar}[/cyan] {entropy:.1f}/8.0\n\n"
            + self._entropy_analysis(entropy),
            box=box.ROUNDED,
            border_style="cyan",
            title="[bold]Entropy Analysis[/bold]"
        ))

        return {"file": filepath.name, "size": len(data), "entropy": round(entropy, 4)}

    def cmd_signature(self, args):
        filepath = Path(args.filepath)
        if not filepath.exists():
            logger.error(f"File not found: {filepath}")
            return

        data = self.read_file(filepath)

        signatures = self._get_signatures()
        detected = []

        for sig_name, sig_bytes, offset, desc in signatures:
            sig_data = sig_bytes if isinstance(sig_bytes, bytes) else bytes.fromhex(sig_bytes)
            if len(data) >= offset + len(sig_data):
                if data[offset:offset + len(sig_data)] == sig_data:
                    detected.append((sig_name, desc))

        table = Table(title=f"File Signature: {filepath.name}", box=box.ROUNDED, border_style="cyan")
        table.add_column("Property", style="bold yellow")
        table.add_column("Value", style="white")

        hex_bytes = ' '.join(f'{b:02x}' for b in data[:16])
        table.add_row("Magic Bytes (hex)", hex_bytes)
        table.add_row("Magic Bytes (ascii)", ''.join(chr(b) if 32 <= b <= 126 else '.' for b in data[:16]))
        table.add_row("Detected Signatures", ", ".join([f"{s[0]} ({s[1]})" for s in detected]) if detected else "None")

        if detected:
            console.print(f"\n[green]✓ Detected: {detected[0][0]} - {detected[0][1]}[/green]")

        console.print(table)
        return {"magic_hex": hex_bytes, "detected": [s[0] for s in detected]}

    def cmd_yara(self, args):
        if not yara:
            logger.error("yara-python not installed. Install with: pip install yara-python")
            return

        filepath = Path(args.filepath)
        if not filepath.exists():
            logger.error(f"File not found: {filepath}")
            return

        rules_path = args.rules
        if not rules_path:
            rules_path = Path(__file__).parent / "rules.yar"
            if not rules_path.exists():
                console.print("[yellow]No YARA rules file specified and no default found.[/yellow]")
                console.print("[yellow]Usage: yara <file> -r <rules.yar>[/yellow]")
                return

        try:
            rules = yara.compile(filepath=str(rules_path))
            matches = rules.match(filepath=str(filepath))

            if not matches:
                console.print("[green]No YARA matches found.[/green]")
                return {"matches": []}

            table = Table(title=f"YARA Matches: {filepath.name}", box=box.ROUNDED, border_style="red")
            table.add_column("Rule", style="bold yellow")
            table.add_column("Tags", style="green")
            table.add_column("Meta", style="white")

            for match in matches:
                tags = ", ".join(match.tags) if match.tags else "-"
                meta_str = "; ".join(f"{k}={v}" for k, v in match.meta.items()) if match.meta else "-"
                table.add_row(match.rule, tags, meta_str)

            console.print(table)
            return {"matches": [{"rule": m.rule, "tags": list(m.tags), "meta": dict(m.meta)} for m in matches]}

        except yara.Error as e:
            logger.error(f"YARA error: {e}")
            return None

    def cmd_zip(self, args):
        filepath = Path(args.filepath)
        if not filepath.exists():
            logger.error(f"File not found: {filepath}")
            return

        try:
            with zipfile.ZipFile(filepath) as zf:
                info_list = zf.infolist()
                table = Table(title=f"ZIP Analysis: {filepath.name}", box=box.ROUNDED, border_style="cyan")
                table.add_column("File", style="bold yellow")
                table.add_column("Size", style="white")
                table.add_column("Compressed", style="white")
                table.add_column("Ratio", style="white")
                table.add_column("Date", style="green")

                total_size = 0
                total_compressed = 0

                for info in info_list:
                    ratio = (1 - info.compress_size / info.file_size) * 100 if info.file_size > 0 else 0
                    date_str = f"{info.date_time[0]:04d}-{info.date_time[1]:02d}-{info.date_time[2]:02d}"
                    table.add_row(
                        info.filename,
                        self._human_size(info.file_size),
                        self._human_size(info.compress_size),
                        f"{ratio:.1f}%",
                        date_str
                    )
                    total_size += info.file_size
                    total_compressed += info.compress_size

                console.print(table)
                console.print(f"\n[cyan]Total files: {len(info_list)}[/cyan]")
                console.print(f"[cyan]Total size: {self._human_size(total_size)} -> {self._human_size(total_compressed)}[/cyan]")

                # Check for encrypted entries
                encrypted = [info.filename for info in info_list if info.flag_bits & 0x1]
                if encrypted:
                    console.print(f"[red]⚠ Encrypted files detected: {', '.join(encrypted)}[/red]")

                return {
                    "files": len(info_list),
                    "total_size": total_size,
                    "total_compressed": total_compressed,
                    "entries": [{"name": info.filename, "size": info.file_size, "compressed": info.compress_size} for info in info_list]
                }

        except zipfile.BadZipFile:
            logger.error("Not a valid ZIP file")
            return None

    def cmd_pcap(self, args):
        if not rdpcap:
            logger.error("scapy not installed. Install with: pip install scapy")
            return

        filepath = Path(args.filepath)
        if not filepath.exists():
            logger.error(f"File not found: {filepath}")
            return

        try:
            packets = rdpcap(str(filepath))
            total = len(packets)

            console.print(f"\n[cyan]Analyzing {total} packets...[/cyan]")

            protocols = {"TCP": 0, "UDP": 0, "ICMP": 0, "ARP": 0, "DNS": 0, "HTTP": 0, "HTTPS": 0, "Other": 0}
            ip_src = {}
            ip_dst = {}
            ports = set()
            total_size = 0

            for pkt in packets:
                total_size += len(pkt)
                if pkt.haslayer(IP):
                    src = pkt[IP].src
                    dst = pkt[IP].dst
                    ip_src[src] = ip_src.get(src, 0) + 1
                    ip_dst[dst] = ip_dst.get(dst, 0) + 1

                    if pkt.haslayer(TCP):
                        protocols["TCP"] += 1
                        ports.add(pkt[TCP].sport)
                        ports.add(pkt[TCP].dport)
                        if pkt[TCP].dport == 80 or pkt[TCP].sport == 80:
                            protocols["HTTP"] += 1
                        elif pkt[TCP].dport == 443 or pkt[TCP].sport == 443:
                            protocols["HTTPS"] += 1
                    elif pkt.haslayer(UDP):
                        protocols["UDP"] += 1
                        ports.add(pkt[UDP].sport)
                        ports.add(pkt[UDP].dport)
                        if pkt[UDP].dport == 53 or pkt[UDP].sport == 53:
                            protocols["DNS"] += 1
                elif pkt.haslayer("ARP"):
                    protocols["ARP"] += 1
                else:
                    protocols["Other"] += 1

            table = Table(title=f"PCAP Analysis: {filepath.name}", box=box.ROUNDED, border_style="blue")
            table.add_column("Metric", style="bold yellow")
            table.add_column("Value", style="white")

            table.add_row("Total Packets", str(total))
            table.add_row("Total Size", self._human_size(total_size))
            table.add_row("Unique Source IPs", str(len(ip_src)))
            table.add_row("Unique Dest IPs", str(len(ip_dst)))
            table.add_row("Unique Ports", str(len(ports)))

            console.print(table)

            proto_table = Table(title="Protocol Distribution", box=box.SIMPLE, border_style="green")
            proto_table.add_column("Protocol", style="bold yellow")
            proto_table.add_column("Count", style="white")
            proto_table.add_column("%", style="cyan")

            for proto, count in sorted(protocols.items(), key=lambda x: x[1], reverse=True):
                if count > 0:
                    pct = count / total * 100
                    proto_table.add_row(proto, str(count), f"{pct:.1f}%")

            console.print(proto_table)

            top_src = sorted(ip_src.items(), key=lambda x: x[1], reverse=True)[:5]
            if top_src:
                ip_table = Table(title="Top Source IPs", box=box.SIMPLE, border_style="yellow")
                ip_table.add_column("IP", style="bold yellow")
                ip_table.add_column("Packets", style="white")
                for ip, count in top_src:
                    ip_table.add_row(ip, str(count))
                console.print(ip_table)

            return {
                "total_packets": total,
                "total_size": total_size,
                "protocols": protocols,
                "sources": len(ip_src),
                "destinations": len(ip_dst),
                "ports": len(ports)
            }

        except Exception as e:
            logger.error(f"PCAP analysis failed: {e}")
            return None

    def cmd_binwalk(self, args):
        if not binwalk:
            logger.error("binwalk not installed. Install with: pip install binwalk")
            return

        filepath = Path(args.filepath)
        if not filepath.exists():
            logger.error(f"File not found: {filepath}")
            return

        try:
            console.print(f"[cyan]Running binwalk on: {filepath.name}[/cyan]")
            results = list(binwalk.scan(str(filepath), signature=True, quiet=True))

            if not results:
                console.print("[yellow]No embedded files detected.[/yellow]")
                return

            table = Table(title=f"Binwalk Results: {filepath.name}", box=box.ROUNDED, border_style="cyan")
            table.add_column("Offset", style="bold yellow")
            table.add_column("Size", style="white")
            table.add_column("Description", style="green")

            for scan_result in results:
                for result in scan_result.results:
                    table.add_row(
                        hex(result.offset),
                        self._human_size(result.size) if result.size > 0 else "-",
                        result.description
                    )

            console.print(table)
            return [{"offset": r.offset, "size": r.size, "desc": r.description} for sr in results for r in sr.results]

        except Exception as e:
            logger.error(f"Binwalk failed: {e}")
            return None

    def cmd_all(self, args):
        filepath = Path(args.filepath)
        if not filepath.exists():
            logger.error(f"File not found: {filepath}")
            return

        console.print(Panel(f"[bold cyan]Full Forensics Analysis: {filepath.name}[/bold cyan]", box=box.ROUNDED))

        results = {}

        with logger.progress() as progress:
            task = progress.add_task("[cyan]Running all analyses...", total=8)

            progress.update(task, description="[cyan]Metadata...")
            results["metadata"] = self.cmd_metadata(args)
            progress.advance(task)

            progress.update(task, description="[cyan]Signatures...")
            results["signature"] = self.cmd_signature(args)
            progress.advance(task)

            progress.update(task, description="[cyan]Entropy...")
            results["entropy"] = self.cmd_entropy(args)
            progress.advance(task)

            progress.update(task, description="[cyan]Strings...")
            results["strings"] = self.cmd_strings(args)
            progress.advance(task)

            progress.update(task, description="[cyan]Hidden files...")
            results["hidden"] = self.cmd_hidden(args)
            progress.advance(task)

            if filepath.suffix.lower() in ['.zip', '.jar', '.apk']:
                progress.update(task, description="[cyan]ZIP analysis...")
                results["zip"] = self.cmd_zip(args)
                progress.advance(task)

            if filepath.suffix.lower() in ['.pcap', '.pcapng']:
                progress.update(task, description="[cyan]PCAP analysis...")
                results["pcap"] = self.cmd_pcap(args)
                progress.advance(task)

            if binwalk:
                progress.update(task, description="[cyan]Binwalk...")
                results["binwalk"] = self.cmd_binwalk(args)
                progress.advance(task)

            if Image and filepath.suffix.lower() in ['.jpg', '.jpeg', '.png', '.tiff', '.webp']:
                progress.update(task, description="[cyan]EXIF...")
                results["exif"] = self.cmd_exif(args)
                progress.advance(task)

        console.print(f"\n[bold green]✓ Analysis complete![/bold green]")
        
        # --- FINAL FLAG SUMMARY AT THE VERY END ---
        from core.base import extract_flags, print_final_flag_summary
        collected_flags = set()
        for k, v in results.items():
            if v:
                collected_flags.update(extract_flags(str(v)))
        print_final_flag_summary(list(collected_flags))
        return results

    def _calculate_entropy(self, data):
        if not data:
            return 0.0
        entropy = 0.0
        for x in range(256):
            p_x = data.count(x) / len(data)
            if p_x > 0:
                entropy += - p_x * math.log2(p_x)
        return entropy

    def _entropy_analysis(self, entropy):
        if entropy < 1.0:
            return "[green]Very low entropy - likely plain text or sparse data[/green]"
        elif entropy < 3.0:
            return "[green]Low entropy - structured data or compressed[/green]"
        elif entropy < 5.0:
            return "[yellow]Medium entropy - possibly encrypted or compressed[/yellow]"
        elif entropy < 7.0:
            return "[red]High entropy - likely encrypted or compressed binary[/red]"
        else:
            return "[bold red]Very high entropy - almost certainly encrypted or random data[/bold red]"

    def _human_size(self, size):
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024:
                return f"{size:.2f} {unit}"
            size /= 1024
        return f"{size:.2f} PB"

    def _get_signatures(self):
        return [
            ("JPG", "FFD8FF", 0, "JPEG image"),
            ("PNG", "89504E47", 0, "PNG image"),
            ("GIF", "47494638", 0, "GIF image"),
            ("BMP", "424D", 0, "BMP image"),
            ("PDF", "25504446", 0, "PDF document"),
            ("ZIP", "504B0304", 0, "ZIP archive"),
            ("ZIP (empty)", "504B0506", 0, "ZIP archive (empty)"),
            ("RAR", "52617221", 0, "RAR archive"),
            ("GZIP", "1F8B", 0, "Gzip compressed"),
            ("BZ2", "425A68", 0, "Bzip2 compressed"),
            ("ELF", "7F454C46", 0, "ELF binary"),
            ("PE", "4D5A", 0, "PE binary (DOS header)"),
            ("Mach-O", "FEEDFACE", 0, "Mach-O binary"),
            ("Mach-O 64", "FEEDFACF", 0, "Mach-O 64-bit binary"),
            ("RIFF/AVI", "52494646", 0, "RIFF/AVI container"),
            ("MP3", "494433", 0, "MP3 audio"),
            ("WAV", "52494646", 0, "WAV audio"),
            ("Java class", "CAFEBABE", 0, "Java class file"),
            ("SQLite", "53514C69", 0, "SQLite database"),
            ("TIFF (LE)", "49492A00", 0, "TIFF image (little-endian)"),
            ("TIFF (BE)", "4D4D002A", 0, "TIFF image (big-endian)"),
            ("7z", "377ABCAF271C", 0, "7z archive"),
            ("OLE2/PPT", "D0CF11E0", 0, "OLE2 compound document"),
            ("PGP", "85", 0, "PGP-encrypted data"),
            ("RTF", "7B5C727466", 0, "RTF document"),
            ("WebP", "52494646", 0, "WebP image"),
        ]
