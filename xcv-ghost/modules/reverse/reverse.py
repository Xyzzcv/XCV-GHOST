import os
import struct
from pathlib import Path
from core.base import BaseModule
from core.logger import Logger
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box
from rich.syntax import Syntax
from rich.text import Text

console = Console()
logger = Logger()

try:
    import pefile
    PEFILE = True
except ImportError:
    PEFILE = False

try:
    from capstone import *
    CAPSTONE = True
except ImportError:
    CAPSTONE = False

try:
    from elftools.elf.elffile import ELFFile
    PYELFFL = True
except ImportError:
    PYELFFL = False


class ReverseModule(BaseModule):
    def __init__(self):
        super().__init__()
        self.name = "reverse"

    def get_commands(self):
        return {
            "_description": "Reverse engineering tools",
            "pe": {
                "help": "Analyze PE (Portable Executable) file",
                "usage": "pe <filepath>",
                "handler": self.cmd_pe,
                "args": [
                    {"flags": ["filepath"], "help": "Path to PE file", "type": str}
                ]
            },
            "elf": {
                "help": "Analyze ELF binary",
                "usage": "elf <filepath>",
                "handler": self.cmd_elf,
                "args": [
                    {"flags": ["filepath"], "help": "Path to ELF file", "type": str}
                ]
            },
            "strings": {
                "help": "Extract and analyze strings from binary",
                "usage": "strings <filepath> [min_length]",
                "handler": self.cmd_strings,
                "args": [
                    {"flags": ["filepath"], "help": "Path to binary", "type": str},
                    {"flags": ["-n", "--min"], "help": "Minimum string length", "type": int, "default": 5}
                ]
            },
            "disasm": {
                "help": "Disassemble binary",
                "usage": "disasm <filepath> [section/offset]",
                "handler": self.cmd_disasm,
                "args": [
                    {"flags": ["filepath"], "help": "Path to binary", "type": str},
                    {"flags": ["-s", "--section"], "help": "Section to disassemble", "type": str, "default": ".text"},
                    {"flags": ["-c", "--count"], "help": "Number of instructions", "type": int, "default": 100}
                ]
            },
            "opcode": {
                "help": "View opcode statistics",
                "usage": "opcode <filepath>",
                "handler": self.cmd_opcode,
                "args": [
                    {"flags": ["filepath"], "help": "Path to binary", "type": str}
                ]
            },
            "sections": {
                "help": "Analyze binary sections",
                "usage": "sections <filepath>",
                "handler": self.cmd_sections,
                "args": [
                    {"flags": ["filepath"], "help": "Path to binary", "type": str}
                ]
            },
            "imports": {
                "help": "View imported functions/symbols",
                "usage": "imports <filepath>",
                "handler": self.cmd_imports,
                "args": [
                    {"flags": ["filepath"], "help": "Path to binary", "type": str}
                ]
            },
            "exports": {
                "help": "View exported functions/symbols",
                "usage": "exports <filepath>",
                "handler": self.cmd_exports,
                "args": [
                    {"flags": ["filepath"], "help": "Path to binary", "type": str}
                ]
            },
            "packer": {
                "help": "Detect packers/obfuscators",
                "usage": "packer <filepath>",
                "handler": self.cmd_packer,
                "args": [
                    {"flags": ["filepath"], "help": "Path to binary", "type": str}
                ]
            },
            "all": {
                "help": "Run all reverse engineering analysis",
                "usage": "all <filepath>",
                "handler": self.cmd_all,
                "args": [
                    {"flags": ["filepath"], "help": "Path to binary", "type": str}
                ]
            }
        }

    def cmd_pe(self, args):
        filepath = Path(args.filepath)
        if not filepath.exists():
            logger.error(f"File not found: {filepath}")
            return

        if not PEFILE:
            logger.error("pefile not installed. Install with: pip install pefile")
            return

        data = self.read_file(filepath)
        if data[:2] != b'MZ':
            logger.error("Not a PE file (missing MZ header)")
            return

        try:
            pe = pefile.PE(filepath)

            table = Table(title=f"PE Analysis: {filepath.name}", box=box.ROUNDED, border_style="cyan")
            table.add_column("Property", style="bold yellow")
            table.add_column("Value", style="white")

            # DOS Header
            table.add_row("DOS Header", f"MZ Signature valid (e_lfanew: {hex(pe.DOS_HEADER.e_lfanew)})")

            # NT Headers
            sig = pe.NT_HEADERS.Signature
            table.add_row("NT Signature", hex(sig))

            # File Header
            fh = pe.FILE_HEADER
            machine_map = {
                0x14c: "i386", 0x8664: "AMD64", 0x1c0: "ARM",
                0x1c4: "ARM Thumb", 0xaa64: "ARM64", 0x200: "Itanium"
            }
            machine = machine_map.get(fh.Machine, hex(fh.Machine))
            table.add_row("Machine", machine)
            table.add_row("Sections", str(fh.NumberOfSections))
            table.add_row("Timestamp", str(pe.get_datetime()) if hasattr(pe, 'get_datetime') else str(fh.TimeDateStamp))
            table.add_row("Characteristics", hex(fh.Characteristics))

            # Optional Header
            oh = pe.OPTIONAL_HEADER
            table.add_row("Entry Point", hex(oh.AddressOfEntryPoint))
            table.add_row("Image Base", hex(oh.ImageBase))
            table.add_row("Subsystem", str(oh.Subsystem))
            table.add_row("File Size", f"{len(data):,} bytes")

            console.print(table)

            # Sections
            sec_table = Table(title="PE Sections", box=box.SIMPLE, border_style="green")
            sec_table.add_column("Name", style="bold yellow")
            sec_table.add_column("Virtual Address", style="cyan")
            sec_table.add_column("Virtual Size", style="white")
            sec_table.add_column("Raw Size", style="white")
            sec_table.add_column("Characteristics", style="white")

            for section in pe.sections:
                sec_table.add_row(
                    section.Name.decode('utf-8', errors='replace').strip('\x00'),
                    hex(section.VirtualAddress),
                    hex(section.Misc_VirtualSize),
                    str(section.SizeOfRawData),
                    hex(section.Characteristics)
                )

            console.print(sec_table)

            return {
                "machine": machine,
                "sections": len(pe.sections),
                "entry": hex(oh.AddressOfEntryPoint),
                "image_base": hex(oh.ImageBase),
                "subsystem": str(oh.Subsystem)
            }

        except Exception as e:
            logger.error(f"PE analysis failed: {e}")
            return None

    def cmd_elf(self, args):
        filepath = Path(args.filepath)
        if not filepath.exists():
            logger.error(f"File not found: {filepath}")
            return

        if not PYELFFL:
            logger.error("pyelftools not installed. Install with: pip install pyelftools")
            return

        data = self.read_file(filepath)
        if data[:4] != b'\x7fELF':
            logger.error("Not a valid ELF file")
            return

        try:
            with open(filepath, 'rb') as f:
                elf = ELFFile(f)

            table = Table(title=f"ELF Analysis: {filepath.name}", box=box.ROUNDED, border_style="cyan")
            table.add_column("Property", style="bold yellow")
            table.add_column("Value", style="white")

            ei_class = "ELF32" if elf.elf_class == 1 else "ELF64"
            ei_data = "Little Endian" if elf.little_endian else "Big Endian"

            e_type_map = {0: "NONE", 1: "REL", 2: "EXEC", 3: "DYN", 4: "CORE"}
            e_type = e_type_map.get(elf.header.e_type, str(elf.header.e_type))

            machine_map = {
                3: "i386", 8: "MIPS", 20: "PowerPC",
                40: "ARM", 62: "AMD64", 183: "AArch64"
            }
            machine = machine_map.get(elf.header.e_machine, str(elf.header.e_machine))

            table.add_row("Class", ei_class)
            table.add_row("Endianness", ei_data)
            table.add_row("Type", e_type)
            table.add_row("Machine", machine)
            table.add_row("Entry Point", hex(elf.header.e_entry))
            table.add_row("Program Headers", str(elf.header.e_phnum))
            table.add_row("Section Headers", str(elf.header.e_shnum))
            table.add_row("Flags", hex(elf.header.e_flags))

            console.print(table)

            # Sections
            sec_table = Table(title="ELF Sections", box=box.SIMPLE, border_style="green")
            sec_table.add_column("Name", style="bold yellow")
            sec_table.add_column("Type", style="white")
            sec_table.add_column("Address", style="cyan")
            sec_table.add_column("Offset", style="white")
            sec_table.add_column("Size", style="white")
            sec_table.add_column("Flags", style="yellow")

            for sec in elf.iter_sections():
                sec_table.add_row(
                    sec.name or "(null)",
                    str(sec['sh_type']),
                    hex(sec['sh_addr']),
                    hex(sec['sh_offset']),
                    str(sec['sh_size']),
                    hex(sec['sh_flags'])
                )

            console.print(sec_table)

            return {
                "class": ei_class, "endian": ei_data, "type": e_type,
                "machine": machine, "entry": hex(elf.header.e_entry),
                "sections": elf.header.e_shnum, "segments": elf.header.e_phnum
            }

        except Exception as e:
            logger.error(f"ELF analysis failed: {e}")
            return None

    def cmd_strings(self, args):
        filepath = Path(args.filepath)
        if not filepath.exists():
            logger.error(f"File not found: {filepath}")
            return

        min_len = args.min
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

        # Categorize strings
        categories = {
            "URLs": [],
            "File Paths": [],
            "IP Addresses": [],
            "Functions": [],
            "Other": []
        }

        import re
        for s in result:
            if re.match(r'https?://', s):
                categories["URLs"].append(s)
            elif re.match(r'[\w/\\:]*\.\w+', s):
                categories["File Paths"].append(s)
            elif re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', s):
                categories["IP Addresses"].append(s)
            elif re.match(r'[\w_]+\(\)', s) or re.match(r'^[a-z_][a-z0-9_]*$', s, re.I):
                categories["Functions"].append(s)
            else:
                categories["Other"].append(s)

        console.print(f"[green]Found {len(result)} strings (min length: {min_len})[/green]")

        for cat_name, cat_strings in categories.items():
            if cat_strings:
                console.print(f"\n[bold yellow]{cat_name}: {len(cat_strings)}[/bold yellow]")
                for s in cat_strings[:15]:
                    console.print(f"  [white]{s[:150]}[/white]")
                if len(cat_strings) > 15:
                    console.print(f"  [dim]... and {len(cat_strings) - 15} more[/dim]")

        return {"strings": result, "count": len(result), "categories": {k: len(v) for k, v in categories.items()}}

    def cmd_disasm(self, args):
        if not CAPSTONE:
            logger.error("capstone not installed. Install with: pip install capstone")
            return

        filepath = Path(args.filepath)
        if not filepath.exists():
            logger.error(f"File not found: {filepath}")
            return

        section_name = args.section
        count = args.count
        data = self.read_file(filepath)

        if data[:4] == b'\x7fELF':
            arch, mode = self._detect_elf_arch(data)
        elif data[:2] == b'MZ':
            arch, mode = CS_ARCH_X86, CS_MODE_32
            if PEFILE:
                try:
                    pe = pefile.PE(filepath)
                    if pe.FILE_HEADER.Machine == 0x8664:
                        mode = CS_MODE_64
                except:
                    pass
        else:
            arch, mode = CS_ARCH_X86, CS_MODE_64

        # Find section data
        section_data = None
        section_addr = 0

        if PYELFFL and data[:4] == b'\x7fELF':
            try:
                with open(filepath, 'rb') as f:
                    elf = ELFFile(f)
                    for sec in elf.iter_sections():
                        if sec.name == section_name:
                            section_data = sec.data()
                            section_addr = sec['sh_addr']
                            break
            except:
                pass

        if section_data is None and data[:2] == b'MZ' and PEFILE:
            try:
                pe = pefile.PE(filepath)
                for sec in pe.sections:
                    name = sec.Name.decode('utf-8', errors='replace').strip('\x00')
                    if name == section_name or name == f".{section_name}":
                        section_data = sec.get_data()
                        section_addr = sec.VirtualAddress + pe.OPTIONAL_HEADER.ImageBase
                        break
            except:
                pass

        if section_data is None:
            console.print(f"[yellow]Section '{section_name}' not found, using full binary[/yellow]")
            section_data = data
            section_addr = 0

        try:
            md = Cs(arch, mode)
            md.detail = True

            insn_count = 0
            console.print(f"\n[bold cyan]Disassembly of {filepath.name}:{section_name}[/bold cyan]")
            console.print(f"[dim]Showing first {count} instructions[/dim]\n")

            disasm_table = Table(box=box.SIMPLE, border_style="blue")
            disasm_table.add_column("Address", style="bold yellow")
            disasm_table.add_column("Bytes", style="cyan")
            disasm_table.add_column("Instruction", style="white")

            for insn in md.disasm(section_data, section_addr):
                if insn_count >= count:
                    break
                bytes_str = ' '.join(f'{b:02x}' for b in insn.bytes)
                disasm_table.add_row(
                    hex(insn.address),
                    bytes_str,
                    f"{insn.mnemonic} {insn.op_str}"
                )
                insn_count += 1

            console.print(disasm_table)
            console.print(f"\n[cyan]Total instructions shown: {insn_count}[/cyan]")

            return {"instructions": insn_count, "section": section_name}

        except Exception as e:
            logger.error(f"Disassembly failed: {e}")
            return None

    def cmd_opcode(self, args):
        if not CAPSTONE:
            logger.error("capstone not installed")
            return

        filepath = Path(args.filepath)
        if not filepath.exists():
            logger.error(f"File not found: {filepath}")
            return

        data = self.read_file(filepath)

        if data[:4] == b'\x7fELF':
            arch, mode = self._detect_elf_arch(data)
        elif data[:2] == b'MZ':
            arch, mode = CS_ARCH_X86, CS_MODE_32
        else:
            arch, mode = CS_ARCH_X86, CS_MODE_64

        text_data = self._find_text_section(filepath, data)
        if not text_data:
            text_data = data

        try:
            md = Cs(arch, mode)
            opcodes = {}

            for insn in md.disasm(text_data, 0):
                mnem = insn.mnemonic
                if mnem not in opcodes:
                    opcodes[mnem] = 0
                opcodes[mnem] += 1

            sorted_ops = sorted(opcodes.items(), key=lambda x: x[1], reverse=True)

            table = Table(title=f"Opcode Statistics", box=box.ROUNDED, border_style="cyan")
            table.add_column("Opcode", style="bold yellow")
            table.add_column("Count", style="white")
            table.add_column("Frequency", style="green")
            table.add_column("Bar", style="white")

            total = sum(o[1] for o in sorted_ops)
            max_count = sorted_ops[0][1] if sorted_ops else 1

            for op, count in sorted_ops[:30]:
                pct = count / total * 100
                bar_len = int(count / max_count * 25)
                bar = "█" * bar_len + "░" * (25 - bar_len)
                table.add_row(op, str(count), f"{pct:.1f}%", bar)

            console.print(table)
            console.print(f"[cyan]Total unique opcodes: {len(opcodes)}[/cyan]")
            console.print(f"[cyan]Total instructions: {total}[/cyan]")

            return {"opcodes": dict(sorted_ops[:30]), "total": total, "unique": len(opcodes)}

        except Exception as e:
            logger.error(f"Opcode analysis failed: {e}")
            return None

    def cmd_sections(self, args):
        filepath = Path(args.filepath)
        if not filepath.exists():
            logger.error(f"File not found: {filepath}")
            return

        data = self.read_file(filepath)

        if data[:4] == b'\x7fELF':
            if PYELFFL:
                return self._analyze_elf_sections(filepath)
            else:
                logger.error("pyelftools required")
                return
        elif data[:2] == b'MZ':
            if PEFILE:
                return self._analyze_pe_sections(filepath)
            else:
                logger.error("pefile required")
                return
        else:
            logger.error("Unknown binary format")
            return None

    def cmd_imports(self, args):
        filepath = Path(args.filepath)
        if not filepath.exists():
            logger.error(f"File not found: {filepath}")
            return

        data = self.read_file(filepath)

        if data[:2] == b'MZ' and PEFILE:
            try:
                pe = pefile.PE(filepath)
                table = Table(title=f"Imports: {filepath.name}", box=box.ROUNDED, border_style="cyan")
                table.add_column("DLL", style="bold yellow")
                table.add_column("Functions", style="white")

                if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                    for entry in pe.DIRECTORY_ENTRY_IMPORT:
                        dll_name = entry.dll.decode('utf-8', errors='replace')
                        funcs = []
                        for imp in entry.imports:
                            if imp.name:
                                funcs.append(imp.name.decode('utf-8', errors='replace'))
                            else:
                                funcs.append(f"ord({hex(imp.ordinal)})" if imp.ordinal else "?")
                        table.add_row(dll_name, ", ".join(funcs[:20]) + ("..." if len(funcs) > 20 else ""))

                console.print(table)
                return {"imports": {entry.dll.decode('utf-8', errors='replace'): [imp.name.decode('utf-8', errors='replace') if imp.name else f"ord({imp.ordinal})" for imp in entry.imports] for entry in pe.DIRECTORY_ENTRY_IMPORT}} if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT') else {}

            except Exception as e:
                logger.error(f"Import analysis failed: {e}")
                return None

        elif data[:4] == b'\x7fELF':
            try:
                if not PYELFFL:
                    logger.error("pyelftools required")
                    return None
                with open(filepath, 'rb') as f:
                    elf = ELFFile(f)
                    table = Table(title=f"Dynamic Symbols: {filepath.name}", box=box.ROUNDED, border_style="cyan")
                    table.add_column("Name", style="bold yellow")
                    table.add_column("Type", style="white")
                    table.add_column("Value", style="cyan")
                    table.add_column("Size", style="white")

                    imports = []
                    for sec in elf.iter_sections():
                        if hasattr(sec, 'iter_symbols'):
                            for sym in sec.iter_symbols():
                                if sym.entry.st_info['bind'] == 'STB_GLOBAL' and sym.name:
                                    table.add_row(
                                        sym.name,
                                        sym.entry.st_info['type'],
                                        hex(sym.entry.st_value),
                                        str(sym.entry.st_size)
                                    )
                                    imports.append({"name": sym.name, "type": sym.entry.st_info['type']})

                    console.print(table)
                    return {"symbols": imports}

            except Exception as e:
                logger.error(f"ELF symbol analysis failed: {e}")
                return None

        else:
            logger.error("Unsupported format")
            return None

    def cmd_exports(self, args):
        filepath = Path(args.filepath)
        if not filepath.exists():
            logger.error(f"File not found: {filepath}")
            return

        data = self.read_file(filepath)

        if data[:2] == b'MZ' and PEFILE:
            try:
                pe = pefile.PE(filepath)
                table = Table(title=f"Exports: {filepath.name}", box=box.ROUNDED, border_style="cyan")
                table.add_column("Name", style="bold yellow")
                table.add_column("Address", style="cyan")
                table.add_column("Ordinal", style="white")

                exports = []
                if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                        table.add_row(
                            exp.name.decode('utf-8', errors='replace') if exp.name else "(unnamed)",
                            hex(exp.address),
                            str(exp.ordinal)
                        )
                        exports.append({
                            "name": exp.name.decode('utf-8', errors='replace') if exp.name else None,
                            "address": exp.address,
                            "ordinal": exp.ordinal
                        })

                console.print(table)
                return {"exports": exports}

            except Exception as e:
                logger.error(f"Export analysis failed: {e}")
                return None

        logger.error("Exports only supported for PE files")
        return None

    def cmd_packer(self, args):
        filepath = Path(args.filepath)
        if not filepath.exists():
            logger.error(f"File not found: {filepath}")
            return

        data = self.read_file(filepath)
        results = []

        console.print(f"[cyan]Checking for packers in: {filepath.name}[/cyan]")

        # Check entropy
        entropy = self._calc_entropy(data)
        console.print(f"[cyan]Overall entropy: {entropy:.4f}/8.0[/cyan]")

        if entropy > 7.0:
            results.append({"check": "Entropy", "status": "ALERT", "detail": f"Very high entropy ({entropy:.2f}) - likely packed/encrypted"})
            console.print(f"[red]⚠ Very high entropy ({entropy:.2f}) - likely packed/encrypted[/red]")
        elif entropy > 6.0:
            results.append({"check": "Entropy", "status": "SUSPICIOUS", "detail": f"High entropy ({entropy:.2f}) - may be packed"})
            console.print(f"[yellow]⚠ High entropy ({entropy:.2f}) - may be packed[/yellow]")
        else:
            results.append({"check": "Entropy", "status": "OK", "detail": f"Normal entropy ({entropy:.2f})"})

        # Check for section anomalies
        if data[:2] == b'MZ' and PEFILE:
            try:
                pe = pefile.PE(filepath)
                section_names = []
                for sec in pe.sections:
                    name = sec.Name.decode('utf-8', errors='replace').strip('\x00')
                    section_names.append(name)

                # Packer signatures
                packer_sigs = {
                    'UPX0': ('UPX', 'UPX packer detected'),
                    'UPX1': ('UPX', 'UPX packer detected'),
                    'UPX2': ('UPX', 'UPX packer detected'),
                    '.packed': ('Generic', 'Packed section detected'),
                    '.pdata': ('Generic', 'Packed section detected'),
                    'ASPack': ('ASPack', 'ASPack packer detected'),
                    'PEPACK!!': ('PEPack', 'PEPack detected'),
                    '.MPR1': ('MPR', 'MPR packer detected'),
                    'PEC2TO': ('PEC2', 'PEC2 packer detected'),
                    'neolite': ('NeoLite', 'NeoLite packer detected'),
                    'sforce': ('Safeguard', 'Safeguard packer detected'),
                }

                for name in section_names:
                    if name in packer_sigs:
                        packer_name, desc = packer_sigs[name]
                        results.append({"check": "Section", "status": "ALERT", "detail": desc})
                        console.print(f"[red]⚠ {desc}[/red]")

                # Check for suspicious section characteristics
                for sec in pe.sections:
                    name = sec.Name.decode('utf-8', errors='replace').strip('\x00')
                    if sec.SizeOfRawData == 0 and sec.Misc_VirtualSize > 0:
                        results.append({"check": "Section", "status": "SUSPICIOUS", "detail": f"Section '{name}' has virtual size but no raw data"})
                        console.print(f"[yellow]⚠ Section '{name}' has virtual size but no raw data[/yellow]")

                # Check for raw data size vs virtual size ratio
                for sec in pe.sections:
                    name = sec.Name.decode('utf-8', errors='replace').strip('\x00')
                    if sec.SizeOfRawData > 0 and sec.Misc_VirtualSize > 0:
                        ratio = sec.Misc_VirtualSize / sec.SizeOfRawData
                        if ratio > 5:
                            results.append({"check": "Section", "status": "SUSPICIOUS", "detail": f"Section '{name}' virtual/raw ratio: {ratio:.2f}"})
                            console.print(f"[yellow]⚠ Section '{name}' virtual/raw ratio: {ratio:.2f}[/yellow]")

            except Exception as e:
                pass

        # Check for unusual section count
        if data[:4] == b'\x7fELF' and PYELFFL:
            try:
                with open(filepath, 'rb') as f:
                    elf = ELFFile(f)
                    text_section = None
                    for sec in elf.iter_sections():
                        if sec.name == '.text':
                            text_section = sec
                            break

                    if text_section:
                        text_entropy = self._calc_entropy(text_section.data())
                        if text_entropy > 6.5:
                            results.append({"check": "Text Entropy", "status": "ALERT", "detail": f".text section entropy: {text_entropy:.2f} - likely packed"})
                            console.print(f"[red]⚠ .text section entropy: {text_entropy:.2f} - likely packed[/red]")
            except:
                pass

        # Summary
        status_counts = {"OK": 0, "SUSPICIOUS": 0, "ALERT": 0}
        for r in results:
            status_counts[r["status"]] = status_counts.get(r["status"], 0) + 1

        console.print(f"\n[bold]Summary:[/bold] "
                    f"[green]{status_counts.get('OK', 0)} OK[/green] | "
                    f"[yellow]{status_counts.get('SUSPICIOUS', 0)} Suspicious[/yellow] | "
                    f"[red]{status_counts.get('ALERT', 0)} Alerts[/red]")

        return results

    def cmd_all(self, args):
        filepath = Path(args.filepath)
        if not filepath.exists():
            logger.error(f"File not found: {filepath}")
            return

        console.print(Panel(f"[bold cyan]Full Reverse Engineering Analysis: {filepath.name}[/bold cyan]", box=box.ROUNDED))
        results = {}

        with logger.progress() as progress:
            task = progress.add_task("[cyan]Running all analyses...", total=7)

            progress.update(task, description="[cyan]Sections...")
            results["sections"] = self.cmd_sections(args)
            progress.advance(task)

            progress.update(task, description="[cyan]Strings...")
            results["strings"] = self.cmd_strings(args)
            progress.advance(task)

            progress.update(task, description="[cyan]Packer detection...")
            results["packer"] = self.cmd_packer(args)
            progress.advance(task)

            progress.update(task, description="[cyan]Imports/Symbols...")
            results["imports"] = self.cmd_imports(args)
            progress.advance(task)

            progress.update(task, description="[cyan]Disassembly...")
            results["disasm"] = self.cmd_disasm(args)
            progress.advance(task)

            progress.update(task, description="[cyan]Opcode stats...")
            results["opcode"] = self.cmd_opcode(args)
            progress.advance(task)

            progress.update(task, description="[cyan]Header analysis...")
            data = self.read_file(filepath)
            if data[:2] == b'MZ':
                results["pe_header"] = self.cmd_pe(args)
            elif data[:4] == b'\x7fELF':
                results["elf_header"] = self.cmd_elf(args)
            progress.advance(task)

        console.print(f"\n[bold green]✓ Reverse engineering analysis complete![/bold green]")
        
        # --- FINAL FLAG SUMMARY AT THE VERY END ---
        from core.base import extract_flags, print_final_flag_summary
        collected_flags = set()
        for k, v in results.items():
            if v:
                collected_flags.update(extract_flags(str(v)))
        print_final_flag_summary(list(collected_flags))
        return results

    def _analyze_elf_sections(self, filepath):
        with open(filepath, 'rb') as f:
            elf = ELFFile(f)

        table = Table(title=f"ELF Sections: {filepath.name}", box=box.ROUNDED, border_style="cyan")
        table.add_column("Name", style="bold yellow")
        table.add_column("Type", style="white")
        table.add_column("Address", style="cyan")
        table.add_column("Offset", style="white")
        table.add_column("Size", style="white")
        table.add_column("Flags", style="yellow")
        table.add_column("Entropy", style="green")

        sections_data = []
        for sec in elf.iter_sections():
            sec_data = sec.data() if hasattr(sec, 'data') else b''
            entropy = self._calc_entropy(sec_data)

            table.add_row(
                sec.name or "(null)",
                str(sec['sh_type']),
                hex(sec['sh_addr']),
                hex(sec['sh_offset']),
                str(sec['sh_size']),
                hex(sec['sh_flags']),
                f"{entropy:.2f}"
            )
            sections_data.append({
                "name": sec.name or "",
                "type": sec['sh_type'],
                "address": sec['sh_addr'],
                "size": sec['sh_size'],
                "entropy": entropy
            })

        console.print(table)
        return sections_data

    def _analyze_pe_sections(self, filepath):
        pe = pefile.PE(filepath)

        table = Table(title=f"PE Sections: {filepath.name}", box=box.ROUNDED, border_style="cyan")
        table.add_column("Name", style="bold yellow")
        table.add_column("VA", style="cyan")
        table.add_column("VSize", style="white")
        table.add_column("Raw Size", style="white")
        table.add_column("Entropy", style="green")
        table.add_column("Char", style="yellow")

        sections_data = []
        for sec in pe.sections:
            entropy = self._calc_entropy(sec.get_data())
            table.add_row(
                sec.Name.decode('utf-8', errors='replace').strip('\x00'),
                hex(sec.VirtualAddress),
                hex(sec.Misc_VirtualSize),
                str(sec.SizeOfRawData),
                f"{entropy:.2f}",
                hex(sec.Characteristics)
            )
            sections_data.append({
                "name": sec.Name.decode('utf-8', errors='replace').strip('\x00'),
                "va": sec.VirtualAddress,
                "vsize": sec.Misc_VirtualSize,
                "raw_size": sec.SizeOfRawData,
                "entropy": entropy
            })

        console.print(table)
        return sections_data

    def _find_text_section(self, filepath, data):
        if PYELFFL and data[:4] == b'\x7fELF':
            try:
                with open(filepath, 'rb') as f:
                    elf = ELFFile(f)
                    for sec in elf.iter_sections():
                        if sec.name == '.text':
                            return sec.data()
            except:
                pass

        if PEFILE and data[:2] == b'MZ':
            try:
                pe = pefile.PE(filepath)
                for sec in pe.sections:
                    name = sec.Name.decode('utf-8', errors='replace').strip('\x00')
                    if name == '.text':
                        return sec.get_data()
            except:
                pass

        return None

    def _detect_elf_arch(self, data):
        if data[4] == 2:  # 64-bit
            return CS_ARCH_X86, CS_MODE_64
        else:
            return CS_ARCH_X86, CS_MODE_32

    def _calc_entropy(self, data):
        import math
        if not data:
            return 0.0
        entropy = 0.0
        for x in range(256):
            p_x = data.count(x) / len(data)
            if p_x > 0:
                entropy += -p_x * math.log2(p_x)
        return entropy
