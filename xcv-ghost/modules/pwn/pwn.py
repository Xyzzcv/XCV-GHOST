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

console = Console()
logger = Logger()

try:
    from pwn import *
    PWND = True
except ImportError:
    PWND = False
    from pwnlib.elf.corefile import CoredumpFilter

try:
    from capstone import *
    CAPSTONE = True
except ImportError:
    CAPSTONE = False

try:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.constants import SH_TYPE, PT_TYPE
    PYELFFL = True
except ImportError:
    PYELFFL = False


class PWNModule(BaseModule):
    def __init__(self):
        super().__init__()
        self.name = "pwn"

    def get_commands(self):
        return {
            "_description": "Binary exploitation tools",
            "pattern": {
                "help": "Generate cyclic pattern",
                "usage": "pattern <length>",
                "handler": self.cmd_pattern,
                "args": [
                    {"flags": ["length"], "help": "Pattern length", "type": int}
                ]
            },
            "offset": {
                "help": "Find cyclic pattern offset",
                "usage": "offset <value> [pattern_length]",
                "handler": self.cmd_offset,
                "args": [
                    {"flags": ["value"], "help": "Value to search for (hex or string)", "type": str},
                    {"flags": ["-l", "--length"], "help": "Pattern length for generation", "type": int, "default": 10000}
                ]
            },
            "elf": {
                "help": "Parse ELF binary for analysis",
                "usage": "elf <filepath>",
                "handler": self.cmd_elf,
                "args": [
                    {"flags": ["filepath"], "help": "Path to ELF file", "type": str}
                ]
            },
            "rop": {
                "help": "Find ROP gadgets in binary",
                "usage": "rop <filepath> [gadget]",
                "handler": self.cmd_rop,
                "args": [
                    {"flags": ["filepath"], "help": "Path to binary", "type": str},
                    {"flags": ["-g", "--gadget"], "help": "Gadget to search (e.g., 'pop rdi; ret')", "type": str, "default": ""}
                ]
            },
            "shellcode": {
                "help": "Generate shellcode",
                "usage": "shellcode <type> [arch]",
                "handler": self.cmd_shellcode,
                "args": [
                    {"flags": ["type"], "help": "Shellcode type (execve, reverse, bind)", "type": str},
                    {"flags": ["-a", "--arch"], "help": "Architecture (i386, amd64)", "type": str, "default": "amd64"},
                    {"flags": ["-p", "--port"], "help": "Port for reverse/bind shell", "type": int, "default": 4444},
                    {"flags": ["-H", "--host"], "help": "Host for reverse shell", "type": str, "default": "127.0.0.1"}
                ]
            },
            "template": {
                "help": "Generate exploit template",
                "usage": "template <binary>",
                "handler": self.cmd_template,
                "args": [
                    {"flags": ["binary"], "help": "Target binary path", "type": str}
                ]
            },
            "checksec": {
                "help": "Check binary security features",
                "usage": "checksec <filepath>",
                "handler": self.cmd_checksec,
                "args": [
                    {"flags": ["filepath"], "help": "Path to binary", "type": str}
                ]
            },
            "asm": {
                "help": "Assemble instructions to bytes",
                "usage": "asm <instructions> [arch]",
                "handler": self.cmd_asm,
                "args": [
                    {"flags": ["instructions"], "help": "Instructions to assemble", "type": str},
                    {"flags": ["-a", "--arch"], "help": "Architecture", "type": str, "default": "amd64"}
                ]
            },
            "all": {
                "help": "Run ALL PWN exploitation & analysis tools on a binary",
                "usage": "all <filepath>",
                "handler": self.cmd_all,
                "args": [
                    {"flags": ["filepath"], "help": "Path to target binary", "type": str}
                ]
            }
        }

    def cmd_pattern(self, args):
        length = args.length
        if PWND:
            pattern_str = cyclic(length).decode()
        else:
            pattern_str = self._cyclic_gen(length)

        console.print(f"\n[green]Cyclic pattern ({length} bytes):[/green]\n")
        # Show first line nicely
        chunk_size = 64
        for i in range(0, len(pattern_str), chunk_size):
            chunk = pattern_str[i:i + chunk_size]
            offset_str = f"+{i:04d}" if i > 0 else "     "
            console.print(f"  [dim]{offset_str}[/dim] [white]{chunk}[/white]")

        console.print(f"\n[cyan]Pattern saved to clipboard context. Use 'offset <value>' to find offset.[/cyan]")
        self._last_pattern = pattern_str
        return {"pattern": pattern_str, "length": length}

    def cmd_offset(self, args):
        value = args.value
        pattern_length = args.length

        if PWND:
            try:
                if value.startswith('0x'):
                    val = int(value, 16)
                    val = struct.pack('<Q', val)
                    offset = cyclic_find(val)
                else:
                    offset = cyclic_find(value.encode())
                if offset is not None:
                    console.print(f"\n[bold green]✓ Offset found: {offset}[/bold green]")
                else:
                    console.print(f"\n[red]✗ Value not found in cyclic pattern[/red]")
                return {"offset": offset}
            except:
                pass

        pattern_str = getattr(self, '_last_pattern', None) or self._cyclic_gen(pattern_length)
        if value.startswith('0x'):
            try:
                val = int(value, 16)
                needle = struct.pack('<Q', val)
            except:
                needle = value.encode()
        else:
            needle = value.encode()

        pos = pattern_str.find(needle.decode() if isinstance(needle, bytes) else needle)
        if pos != -1:
            console.print(f"\n[bold green]✓ Offset found: {pos}[/bold green]")
        else:
            console.print(f"\n[red]✗ Value not found at offset {pattern_length}[/red]")

        return {"offset": pos if pos != -1 else None}

    def cmd_elf(self, args):
        filepath = Path(args.filepath)
        if not filepath.exists():
            logger.error(f"File not found: {filepath}")
            return

        data = self.read_file(filepath)

        if data[:4] != b'\x7fELF':
            logger.error("Not a valid ELF file")
            return

        table = Table(title=f"ELF Analysis: {filepath.name}", box=box.ROUNDED, border_style="cyan")
        table.add_column("Property", style="bold yellow")
        table.add_column("Value", style="white")

        ei_class = "32-bit" if data[4] == 1 else "64-bit" if data[4] == 2 else "Unknown"
        ei_data = "Little Endian" if data[5] == 1 else "Big Endian" if data[5] == 2 else "Unknown"
        ei_osabi_map = {0: "UNIX System V", 3: "Linux", 9: "FreeBSD"}
        osabi = ei_osabi_map.get(data[7], f"Unknown ({data[7]})")

        e_type_map = {0: "NONE", 1: "REL (Relocatable)", 2: "EXEC (Executable)", 3: "DYN (Shared)", 4: "CORE"}
        e_type = e_type_map.get(struct.unpack('<H', data[16:18])[0], "Unknown")

        e_machine_map = {
            0x03: "i386", 0x08: "MIPS", 0x14: "PowerPC",
            0x28: "ARM", 0x3E: "AMD64", 0xB7: "AArch64"
        }
        machine = e_machine_map.get(struct.unpack('<H', data[18:20])[0], "Unknown")

        entry = struct.unpack('<Q' if data[4] == 2 else '<I', data[24:32] if data[4] == 2 else data[24:28])[0]

        phoff = struct.unpack('<Q' if data[4] == 2 else '<I', data[32:40] if data[4] == 2 else data[28:32])[0]
        shoff = struct.unpack('<Q' if data[4] == 2 else '<I', data[40:48] if data[4] == 2 else data[32:36])[0]
        phnum = struct.unpack('<H', data[56:58] if data[4] == 2 else data[44:46])[0]
        shnum = struct.unpack('<H', data[60:62] if data[4] == 2 else data[48:50])[0]

        table.add_row("Architecture", f"{ei_class} {machine}")
        table.add_row("Endianness", ei_data)
        table.add_row("OS/ABI", osabi)
        table.add_row("Type", e_type)
        table.add_row("Entry Point", hex(entry))
        table.add_row("Program Headers", f"{phnum} (offset: {hex(phoff)})")
        table.add_row("Section Headers", f"{shnum} (offset: {hex(shoff)})")
        table.add_row("File Size", f"{len(data):,} bytes")

        console.print(table)

        # Sections
        if PYELFFL:
            try:
                with open(filepath, 'rb') as f:
                    elf = ELFFile(f)
                    sec_table = Table(title="Sections", box=box.SIMPLE, border_style="green")
                    sec_table.add_column("Name", style="bold yellow")
                    sec_table.add_column("Type", style="white")
                    sec_table.add_column("Address", style="cyan")
                    sec_table.add_column("Offset", style="white")
                    sec_table.add_column("Size", style="white")

                    for sec in elf.iter_sections():
                        sec_type = hex(sec['sh_type']) if hasattr(sec, 'sh_type') else str(sec.header.sh_type)
                        sec_table.add_row(
                            sec.name or "(null)",
                            sec_type,
                            hex(sec['sh_addr']) if hasattr(sec, 'sh_addr') else hex(sec.header.sh_addr),
                            hex(sec['sh_offset']) if hasattr(sec, 'sh_offset') else hex(sec.header.sh_offset),
                            str(sec['sh_size']) if hasattr(sec, 'sh_size') else str(sec.header.sh_size)
                        )

                    console.print(sec_table)
            except Exception as e:
                console.print(f"[yellow]Detailed ELF parse skipped: {e}[/yellow]")

        return {
            "class": ei_class, "endian": ei_data, "osabi": osabi,
            "type": e_type, "machine": machine, "entry": hex(entry),
            "phnum": phnum, "shnum": shnum
        }

    def cmd_rop(self, args):
        if not CAPSTONE:
            logger.error("capstone not installed. Install with: pip install capstone")
            return

        filepath = Path(args.filepath)
        if not filepath.exists():
            logger.error(f"File not found: {filepath}")
            return

        data = self.read_file(filepath)
        gadget_str = args.gadget

        console.print(f"[cyan]Searching for ROP gadgets in: {filepath.name}[/cyan]")

        if PYELFFL:
            text_section = None
            try:
                with open(filepath, 'rb') as f:
                    elf = ELFFile(f)
                    for sec in elf.iter_sections():
                        if sec.name == '.text':
                            text_section = sec
                            break
            except:
                pass

            if text_section:
                text_data = text_section.data()
                base_addr = text_section['sh_addr']

                # Determine architecture
                md_mode = CS_MODE_64 if data[4] == 2 else CS_MODE_32
                md_arch = CS_ARCH_X86

                try:
                    md = Cs(md_arch, md_mode)
                    md.detail = True

                    gadgets = []
                    seen = set()

                    with logger.progress() as progress:
                        task = progress.add_task("[cyan]Analyzing bytes...", total=len(text_data))

                        for offset in range(len(text_data)):
                            chunk = text_data[offset:offset + 20]
                            if len(chunk) < 2:
                                continue

                            for insn in md.disasm(chunk, base_addr + offset):
                                if insn.mnemonic in ['ret', 'int3', 'syscall']:
                                    break
                                if insn.mnemonic.startswith('pop') or insn.mnemonic.startswith('ret'):
                                    gaddr = insn.address
                                    if gaddr not in seen:
                                        seen.add(gaddr)
                                        gadgets.append((gaddr, f"{insn.mnemonic} {insn.op_str}"))
                                if len(gadgets) >= 50:
                                    break
                            if len(gadgets) >= 50:
                                break
                            if offset % 100 == 0:
                                progress.update(task, completed=offset)

                    if gadget_str:
                        matching = [g for g in gadgets if gadget_str.lower() in g[1].lower()]
                        if matching:
                            gtable = Table(title=f'Gadgets matching "{gadget_str}"', box=box.ROUNDED, border_style="red")
                            gtable.add_column("Address", style="bold yellow")
                            gtable.add_column("Gadget", style="white")
                            for addr, gad in matching[:20]:
                                gtable.add_row(hex(addr), gad)
                            console.print(gtable)
                            return {"gadgets": [{"address": hex(a), "gadget": g} for a, g in matching[:50]]}
                        else:
                            console.print(f"[yellow]No gadgets matching '{gadget_str}'[/yellow]")
                            # Show available types
                            pop_ret = [g for g in gadgets if 'pop' in g[1]]
                            console.print(f"[cyan]Available pop/ret gadgets: {len(pop_ret)}[/cyan]")

                    gtable = Table(title=f"ROP Gadgets (first 50)", box=box.ROUNDED, border_style="cyan")
                    gtable.add_column("Address", style="bold yellow")
                    gtable.add_column("Gadget", style="white")
                    for addr, gad in gadgets[:50]:
                        gtable.add_row(hex(addr), gad)
                    console.print(gtable)

                    return {"gadgets": [{"address": hex(a), "gadget": g} for a, g in gadgets[:50]]}

                except Exception as e:
                    logger.error(f"ROP search failed: {e}")

        console.print("[yellow]Using pwntools for ROP search...[/yellow]")
        if PWND:
            try:
                elf = ELF(filepath)
                rop = ROP(elf)
                if gadget_str:
                    results = rop.find_gadget([gadget_str])
                else:
                    results = list(rop.gadgets.items())[:50]

                gtable = Table(title="ROP Gadgets (pwntools)", box=box.ROUNDED, border_style="cyan")
                gtable.add_column("Address", style="bold yellow")
                gtable.add_column("Gadget", style="white")
                for addr, gad in results[:50]:
                    gtable.add_row(hex(addr), str(gad))
                console.print(gtable)
                return {"gadgets": [{"address": hex(a), "gadget": str(g)} for a, g in results[:50]]}
            except Exception as e:
                logger.error(f"pwntools ROP failed: {e}")

        return None

    def cmd_shellcode(self, args):
        stype = args.type.lower()
        arch = args.arch
        port = args.port
        host = args.host

        if not PWND:
            logger.error("pwntools required for shellcode generation.")
            logger.error("Install: pip install pwntools")
            return

        shellcodes = {
            'execve': lambda: shellcraft.sh(),
            'execve_sh': lambda: shellcraft.sh(),
            'cat_flag': lambda: shellcraft.cat('flag.txt'),
            'read': lambda: shellcraft.read(0, 0x601000),
        }

        if stype in shellcodes:
            try:
                sc = shellcodes[stype]()
                console.print(f"\n[green]Shellcode ({len(sc)} bytes):[/green]")

                # Display as hex
                hex_lines = []
                for i in range(0, len(sc), 16):
                    hex_str = ' '.join(f'{b:02x}' for b in sc[i:i+16])
                    ascii_str = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in sc[i:i+16])
                    hex_lines.append(f"  {hex(i):>8x}: {hex_str:<48s} {ascii_str}")

                console.print("\n".join(hex_lines[:20]))
                if len(sc) > 320:
                    console.print(f"  [dim]... and {len(sc) - 320} more bytes[/dim]")

                # Show as C array
                c_array = ', '.join(f'0x{b:02x}' for b in sc)
                console.print(f"\n[bold yellow]C array ({len(sc)} bytes):[/bold yellow]")
                console.print(f"unsigned char shellcode[] = {{ {c_array} }};")

                return {
                    "shellcode": sc.hex(),
                    "length": len(sc),
                    "type": stype,
                    "c_array": f"unsigned char shellcode[] = {{ {c_array} }};"
                }
            except Exception as e:
                logger.error(f"Shellcode generation failed: {e}")
                return None
        else:
            logger.error(f"Unknown shellcode type: {stype}")
            logger.error(f"Available: {', '.join(shellcodes.keys())}")
            return None

    def cmd_template(self, args):
        binary = args.binary
        binary_path = Path(binary)

        if not binary_path.exists():
            logger.error(f"Binary not found: {binary}")
            return

        template_lines = [
            '#!/usr/bin/env python3',
            'from pwn import *',
            '',
            '# Configuration',
            f'BINARY = "{binary}"',
            '# HOST = "localhost"',
            '# PORT = 1337',
            '',
            'context.binary = BINARY',
            "context.log_level = 'debug'",
            '',
            'elf = ELF(BINARY)',
            '',
            'def exploit(r):',
            '    """Main exploit logic"""',
            '',
            '    # GDB: uncomment to attach',
            "    # gdb.attach(r, gdbscript='')",
            '',
            '    # Write your exploit here',
            '    payload = cyclic(100)',
            '',
            "    r.sendlineafter(b'> ', payload)",
            '    r.interactive()',
            '',
            "if __name__ == '__main__':",
            '    if args.REMOTE:',
            "        r = remote(args.HOST or 'localhost', args.PORT or 1337)",
            '    else:',
            '        r = process(BINARY)',
            "        # r = gdb.debug(BINARY, '''",
            '        # break main',
            '        # continue',
            "        # ''')",
            '',
            '    exploit(r)',
        ]
        template = '\n'.join(template_lines)

        console.print(Syntax(template, "python", theme="monokai", line_numbers=True))
        console.print(f"\n[green]Template generated for {binary}[/green]")

        output_path = Path(f"exploit_{binary_path.stem}.py")
        output_path.write_text(template)
        console.print(f"[green]Saved to: {output_path}[/green]")

        return {"template": template, "saved_to": str(output_path)}

    def cmd_checksec(self, args):
        filepath = Path(args.filepath)
        if not filepath.exists():
            logger.error(f"File not found: {filepath}")
            return

        if not PWND:
            logger.error("pwntools required for checksec")
            return

        try:
            elf = ELF(filepath)

            table = Table(title=f"Security: {filepath.name}", box=box.ROUNDED, border_style="cyan")
            table.add_column("Check", style="bold yellow")
            table.add_column("Status", style="white")
            table.add_column("Description", style="dim")

            checks = [
                ("RELRO", elf.relro, "Read-only relocations"),
                ("Stack Canary", elf.canary, "Stack overflow protection"),
                ("NX", elf.nx, "Non-executable stack"),
                ("PIE", elf.pie, "Position Independent Executable"),
                ("RPATH", elf.rpath, "Run-time search path"),
                ("RUNPATH", elf.runpath, "Run-time search path"),
                ("FORTIFY", elf.fortify, "Fortify source"),
            ]

            color_map = {True: "[green]✓ Enabled[/green]", False: "[red]✗ Disabled[/red]"}
            for name, value, desc in checks:
                status = color_map.get(value, str(value))
                table.add_row(name, status, desc)

            console.print(table)

            return {name: value for name, value, _ in checks}

        except Exception as e:
            logger.error(f"Checksec failed: {e}")
            return None

    def cmd_asm(self, args):
        instructions = args.instructions
        arch = args.arch

        if not PWND:
            logger.error("pwntools required for assembly")
            return

        try:
            if arch == 'amd64' or arch == 'x64':
                result = asm(instructions, arch='amd64')
            elif arch == 'i386' or arch == 'x86':
                result = asm(instructions, arch='i386')
            elif arch == 'arm':
                result = asm(instructions, arch='arm')
            elif arch == 'aarch64' or arch == 'arm64':
                result = asm(instructions, arch='aarch64')
            else:
                result = asm(instructions, arch=arch)

            hex_str = ' '.join(f'{b:02x}' for b in result)
            console.print(f"\n[green]Bytes ({len(result)}):[/green] {hex_str}")
            console.print(f"[green]Raw:[/green] {result.hex()}")

            # Disassemble back
            if CAPSTONE:
                md_map = {
                    'amd64': (CS_ARCH_X86, CS_MODE_64),
                    'i386': (CS_ARCH_X86, CS_MODE_32),
                    'arm': (CS_ARCH_ARM, CS_MODE_ARM),
                    'aarch64': (CS_ARCH_AARCH64, CS_MODE_ARM),
                }
                md_arch, md_mode = md_map.get(arch, (CS_ARCH_X86, CS_MODE_64))
                md = Cs(md_arch, md_mode)
                decoded = list(md.disasm(result, 0))
                for insn in decoded:
                    console.print(f"  [cyan]{insn.mnemonic} {insn.op_str}[/cyan]")

            return {"bytes": result.hex(), "length": len(result)}

        except Exception as e:
            logger.error(f"Assembly failed: {e}")
            return None

    def _cyclic_gen(self, length):
        """Generate cyclic pattern without pwntools"""
        lowercase = 'abcdefghijklmnopqrstuvwxyz'
        uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
        digits = '0123456789'
        charset = lowercase + uppercase + digits

        result = []
        for i in range(length):
            i3 = i % (len(lowercase) * len(uppercase) * len(digits))
            c = lowercase[i3 % len(lowercase)]
            i3 //= len(lowercase)
            c = uppercase[i3 % len(uppercase)] + c
            i3 //= len(uppercase)
            c = digits[i3 % len(digits)] + c
            result.append(c)

        return ''.join(result[:length])

    def cmd_all(self, args):
        from core.base import extract_flags, print_final_flag_summary
        filepath = Path(args.filepath)
        if not filepath.exists():
            logger.error(f"File not found: {filepath}")
            return

        console.print(f"\n[bold cyan]=== RUNNING ALL PWN EXPLOITATION & ANALYSIS TOOLS ===[/bold cyan]")
        console.print(f"[yellow]Target Binary:[/yellow] {filepath}\n")

        collected_flags = set()

        class FakeArgs: pass
        fa = FakeArgs()
        fa.filepath = str(filepath)
        fa.binary = str(filepath)

        # 1. Checksec
        console.print("[bold red][1] CHECKSEC (SECURITY PROTECTIONS)[/bold red]")
        r1 = self.cmd_checksec(fa)
        if r1: collected_flags.update(extract_flags(str(r1)))
        console.print()

        # 2. ELF Parse
        console.print("[bold red][2] ELF BINARY ANALYSIS[/bold red]")
        r2 = self.cmd_elf(fa)
        if r2: collected_flags.update(extract_flags(str(r2)))
        console.print()

        # 3. ROP Gadgets
        console.print("[bold red][3] ROP GADGETS SEARCH[/bold red]")
        fa.gadget = ""
        r3 = self.cmd_rop(fa)
        if r3: collected_flags.update(extract_flags(str(r3)))
        console.print()

        # 4. Exploit Template
        console.print("[bold red][4] EXPLOIT TEMPLATE GENERATOR[/bold red]")
        r4 = self.cmd_template(fa)
        if r4: collected_flags.update(extract_flags(str(r4)))
        console.print()

        console.print("[bold green]✓ All PWN tools executed successfully![/bold green]")

        # --- FINAL FLAG SUMMARY AT THE VERY END ---
        print_final_flag_summary(list(collected_flags))


