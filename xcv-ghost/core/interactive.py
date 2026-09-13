import cmd
import os
import sys
import base64
import string
import shutil
import subprocess
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich import box
from core.banner import Banner
from core.logger import Logger
from core.engine import Engine

console = Console()
logger = Logger()

class InteractiveMode(cmd.Cmd):
    intro = None
    prompt = "\033[36mGHOST> \033[0m"

    def __init__(self, modules):
        super().__init__()
        self.modules = modules
        self.current_module = None
        self.current_handler = None
        self.history = []
        self.verbose = False
        self.engine = Engine()

    def preloop(self):
        console.clear()
        Banner.show()
        console.print()
        self._show_welcome()

    def _show_welcome(self):
        console.print("[bold yellow]Welcome to XCV-GHOST Interactive Mode![/bold yellow]")
        console.print("Type [bold cyan]help[/bold cyan] to see available commands.")
        console.print("Type [bold cyan]modules[/bold cyan] to list all modules.")
        console.print("Type a module name to select it (e.g. [bold cyan]forensic[/bold cyan])")
        console.print("Type [bold cyan]ai <soal/file/teks>[/bold cyan] or [bold cyan]solve <soal/file/teks>[/bold cyan] to auto-solve CTF using AI tools.")
        console.print("Type [bold cyan]exit[/bold cyan] or [bold cyan]quit[/bold cyan] to leave.")
        console.print("[bold cyan]modules[/bold cyan] to list [bold yellow]forensic[/bold yellow], [bold yellow]crypto[/bold yellow], [bold yellow]pwn[/bold yellow], [bold yellow]reverse[/bold yellow], [bold yellow]ai[/bold yellow].\n")

    def postcmd(self, stop, line):
        if self.current_module:
            self.prompt = f"\033[31mGHOST\033[0m:\033[33m{self.current_module}\033[0m> "
        else:
            self.prompt = "\033[36mGHOST> \033[0m"
        return stop

    @staticmethod
    def _get_dest(flags):
        long_flags = [f for f in flags if f.startswith('--')]
        if long_flags:
            return long_flags[0][2:].replace('-', '_')
        return flags[0].lstrip('-').replace('-', '_')

    def do_modules(self, arg):
        table = Table(box=box.ROUNDED, border_style="cyan", header_style="bold cyan")
        table.add_column("Module", style="bold yellow")
        table.add_column("Description", style="white")
        table.add_column("Commands", style="cyan")

        for name, mod in self.modules.items():
            cmds = [c for c in mod.get_commands().keys() if not c.startswith("_")]
            desc = mod.get_commands().get("_description", name.capitalize() + " module")
            table.add_row(name, desc, ", ".join(cmds[:5]) + ("..." if len(cmds) > 5 else ""))

        console.print(table)

    def do_use(self, arg):
        if not arg:
            console.print("[red]Usage: use <module_name>[/red]")
            return
        if arg in self.modules:
            self.current_module = arg
            self.current_handler = self.modules[arg]
            console.print(f"[green]✓ Using module: {arg}[/green]")
            self._show_module_commands()
        else:
            console.print(f"[red]✗ Module '{arg}' not found. Type 'modules' to list.[/red]")

    def _show_module_commands(self):
        if not self.current_handler:
            return
        cmds = self.current_handler.get_commands()
        table = Table(box=box.SIMPLE, border_style="blue", header_style="bold blue")
        table.add_column("Command", style="bold yellow")
        table.add_column("Description", style="white")
        table.add_column("Usage", style="cyan")

        for name, info in cmds.items():
            if name.startswith("_"):
                continue
            usage = info.get("usage", "")
            desc = info.get("help", "")
            table.add_row(name, desc, usage)

        console.print(table)

    def do_run(self, arg):
        if not self.current_module:
            console.print("[red]No module selected. Use 'use <module>' first.[/red]")
            return
        if not arg:
            console.print("[red]Usage: run <command> [args][/red]")
            self._show_module_commands()
            return

        parts = arg.split()
        cmd_name = parts[0]
        cmd_args = parts[1:] if len(parts) > 1 else []

        cmds = self.current_handler.get_commands()
        if cmd_name not in cmds:
            console.print(f"[red]Unknown command '{cmd_name}' for module {self.current_module}[/red]")
            return

        handler = cmds[cmd_name].get("handler")
        if not handler:
            console.print(f"[red]No handler for '{cmd_name}'[/red]")
            return

        console.print(f"[cyan]Running: {self.current_module} {cmd_name} {' '.join(cmd_args)}[/cyan]")

        class FakeArgs:
            pass

        fake_args = FakeArgs()
        fake_args.command = cmd_name

        arg_defs = cmds[cmd_name].get("args", [])
        i = 0
        while i < len(cmd_args):
            token = cmd_args[i]
            matched = False
            for arg_info in arg_defs:
                flags = arg_info.get("flags", [])
                if token in flags:
                    dest = arg_info.get("dest") or self._get_dest(flags)
                    if arg_info.get("action") in ("store_true", "store_false"):
                        setattr(fake_args, dest, arg_info.get("action") == "store_true")
                        matched = True
                        i += 1
                        break
                    else:
                        if i + 1 < len(cmd_args):
                            val = cmd_args[i + 1].strip('"\'')
                            if arg_info.get("type") == int:
                                try: val = int(val)
                                except: pass
                            setattr(fake_args, dest, val)
                            matched = True
                            i += 2
                            break
            if not matched:
                for arg_info in arg_defs:
                    flags = arg_info.get("flags", [])
                    is_positional = not any(f.startswith('-') for f in flags)
                    if is_positional:
                        dest = arg_info.get("dest") or self._get_dest(flags)
                        if not hasattr(fake_args, dest):
                            nargs = arg_info.get("nargs")
                            if nargs in ("+", "*"):
                                values = []
                                while i < len(cmd_args):
                                    t = cmd_args[i]
                                    is_kw = False
                                    for ai2 in arg_defs:
                                        f2 = ai2.get("flags", [])
                                        if t in f2 and (t.startswith('-') or ai2.get("action") in ("store_true", "store_false")):
                                            is_kw = True
                                            break
                                    if is_kw:
                                        break
                                    values.append(t.strip('"\''))
                                    i += 1
                                setattr(fake_args, dest, values or [])
                                matched = True
                                break
                            else:
                                val = token.strip('"\'')
                                if arg_info.get("type") == int:
                                    try: val = int(val)
                                    except: pass
                                setattr(fake_args, dest, val)
                                matched = True
                                i += 1
                                break
            if not matched:
                i += 1

        for arg_info in arg_defs:
            flags = arg_info.get("flags", [])
            dest = arg_info.get("dest") or self._get_dest(flags)
            if not hasattr(fake_args, dest):
                if arg_info.get("action") == "store_true":
                    setattr(fake_args, dest, False)
                elif arg_info.get("action") == "store_false":
                    setattr(fake_args, dest, True)
                else:
                    setattr(fake_args, dest, arg_info.get("default", None))

        try:
            result = handler(fake_args)
            if result and self.verbose:
                console.print(f"\n[dim]Result: {result}[/dim]")
        except Exception as e:
            console.print(f"[red]Error: {str(e)}[/red]")

    def do_show(self, arg):
        if not self.current_module:
            console.print("[red]No module selected.[/red]")
            return
        if arg == "commands":
            self._show_module_commands()
        elif arg == "info":
            console.print(f"[yellow]Current Module:[/yellow] {self.current_module}")
            console.print(f"[yellow]Commands:[/yellow] {len(self.current_handler.get_commands())}")
        else:
            console.print(f"[red]Unknown: show {arg}[/red]")

    def do_info(self, arg):
        Banner.show_about()

    def do_verbose(self, arg):
        self.verbose = not self.verbose
        console.print(f"[green]Verbose mode: {'ON' if self.verbose else 'OFF'}[/green]")

    def do_clear(self, arg):
        console.clear()
        Banner.show()

    def do_EOF(self, arg):
        return True

    def do_exit(self, arg):
        console.print("[yellow]Exiting XCV-GHOST... Goodbye![/yellow]")
        return True

    def do_quit(self, arg):
        return self.do_exit(arg)

    def solve_with_ai(self, query: str):
        from core.base import extract_flags, print_flag_box, print_final_flag_summary
        from rich.panel import Panel

        query = query.strip()
        if not query:
            query = input("[*] Enter CTF challenge / text / file path / question: ").strip()
        if not query:
            console.print("[red]No challenge provided.[/red]")
            return

        prompt = query
        filepath = Path(query)
        if filepath.exists() and filepath.is_file():
            size = filepath.stat().st_size
            ext = filepath.suffix
            try:
                with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read(50000)
            except Exception:
                with open(filepath, "rb") as f:
                    content = f.read(2048).hex()
            prompt = f"File: {filepath.name}\nSize: {size} bytes\nExtension: {ext}\nContent / Data:\n{content}\n\nPlease analyze this CTF challenge, solve it step-by-step, and extract the flag."

        category = self.current_module.capitalize() if self.current_module else "CTF Challenge"
        with console.status(f"[bold cyan]AI Engine analyzing {category} with your Gemini key...[/bold cyan]", spinner="dots"):
            response = self.engine.run(prompt, category)

        console.print()
        console.print(Panel(response, title="[bold red]★ AI CTF SOLVER RESULT ★[/bold red]", border_style="bold cyan"))

        found_flags = extract_flags(response)
        if found_flags:
            print_flag_box(found_flags)
            print_final_flag_summary(found_flags)

    def do_ai(self, arg):
        self.solve_with_ai(arg)

    def do_solve(self, arg):
        self.solve_with_ai(arg)

    def do_ghost(self, arg):
        self.solve_with_ai(arg)

    def do_help(self, arg):
        if arg:
            if self.current_module:
                cmds = self.current_handler.get_commands()
                if arg in cmds:
                    info = cmds[arg]
                    console.print(f"[bold yellow]Command:[/bold yellow] {arg}")
                    console.print(f"[bold yellow]Help:[/bold yellow] {info.get('help', 'N/A')}")
                    console.print(f"[bold yellow]Usage:[/bold yellow] {info.get('usage', 'N/A')}")
                    return
            console.print(f"[red]No help for '{arg}'[/red]")
            return

        Banner.show_help()

    def default(self, line):
        raw = line.strip()
        if not raw: return

        parts = raw.split(maxsplit=1)
        cmd_name = parts[0].lower()
        args_str = parts[1].strip() if len(parts) > 1 else ""

        from core.base import extract_flags, print_flag_box

        # --- AI CTF Solver ---
        if cmd_name in ("ai", "solve", "ghost", "ask"):
            self.solve_with_ai(args_str)
            return

        # --- Inline Quick Utilities ---
        if cmd_name == "rot13":
            target = args_str
            if os.path.exists(args_str):
                with open(args_str, "r", errors="ignore") as f: target = f.read()
            if not target:
                target = input("[*] Enter text or file: ").strip()
            res = target.translate(str.maketrans(
                string.ascii_uppercase + string.ascii_lowercase,
                string.ascii_uppercase[13:] + string.ascii_uppercase[:13] +
                string.ascii_lowercase[13:] + string.ascii_lowercase[:13]
            ))
            console.print(f"[bold green]✓ ROT13 Decoded:[/bold green]\n{res.strip()}")
            print_flag_box(extract_flags(res))
            return

        if cmd_name in ("base64", "b64"):
            target = args_str
            if os.path.exists(args_str):
                with open(args_str, "r", errors="ignore") as f: target = f.read().strip()
            if not target:
                target = input("[*] Enter base64 text or file: ").strip()
            try:
                res = base64.b64decode(target).decode("utf-8", errors="replace")
                console.print(f"[bold green]✓ Base64 Decoded:[/bold green]\n{res}")
                print_flag_box(extract_flags(res))
            except Exception as e:
                console.print(f"[red]Base64 decode error: {e}[/red]")
            return

        if cmd_name == "hex":
            target = args_str or input("[*] Enter hex string: ").strip()
            clean = target.replace(" ", "").replace("0x", "")
            try:
                res = bytes.fromhex(clean).decode("utf-8", errors="replace")
                console.print(f"[bold green]✓ Hex Decoded:[/bold green]\n{res}")
                print_flag_box(extract_flags(res))
            except Exception as e:
                console.print(f"[red]Hex decode error: {e}[/red]")
            return

        if cmd_name == "caesar":
            target = args_str or input("[*] Enter ciphertext: ").strip()
            console.print("\n[bold red][ALL 25 ROT SHIFTS][/bold red]")
            for n in range(1, 26):
                r = target.translate(str.maketrans(
                    string.ascii_uppercase + string.ascii_lowercase,
                    string.ascii_uppercase[n:] + string.ascii_uppercase[:n] +
                    string.ascii_lowercase[n:] + string.ascii_lowercase[:n]
                ))
                console.print(f"[red]ROT{n:2d}:[/red] [white]{r}[/white]")
                print_flag_box(extract_flags(r))
            return

        if cmd_name == "exif":
            filepath = args_str or input("[*] File path: ").strip()
            if "forensic" in self.modules:
                class FakeArgs: pass
                fa = FakeArgs()
                fa.filepath = filepath
                self.modules["forensic"].cmd_exif(fa)
            return

        if cmd_name == "strings":
            filepath = args_str or input("[*] File path: ").strip()
            if "forensic" in self.modules:
                class FakeArgs: pass
                fa = FakeArgs()
                fa.filepath = filepath
                fa.min = 5
                self.modules["forensic"].cmd_strings(fa)
            return

        if cmd_name == "analyze":
            filepath = args_str or input("[*] File path: ").strip()
            if "forensic" in self.modules:
                class FakeArgs: pass
                fa = FakeArgs()
                fa.filepath = filepath
                self.modules["forensic"].cmd_all(fa)
            return

        # --- Module command matching ---
        if cmd_name == "all":
            if self.current_module:
                self.do_run(f"all {args_str}".strip())
                return
            else:
                console.print("[red]Usage: <module> all <data/filepath> or 'use <module>' first.[/red]")
                return

        if self.current_module:
            cmds = self.current_handler.get_commands()
            if cmd_name in cmds:
                self.do_run(line)
                return
            elif cmd_name in self.modules:
                self.do_use(cmd_name)
                if args_str:
                    self.do_run(args_str)
                return
        elif cmd_name in self.modules:
            self.do_use(cmd_name)
            if args_str:
                self.do_run(args_str)
            return

        # --- Shell Command Fallback ---
        try:
            if line.strip().startswith('cd '):
                path = line.strip()[3:].strip()
                target = Path(path).expanduser().resolve()
                os.chdir(target)
                console.print(f"[dim]→ {Path.cwd()}[/dim]")
            else:
                result = subprocess.run(line, shell=True, capture_output=True, text=True, timeout=30)
                if result.stdout:
                    console.print(result.stdout.rstrip())
                if result.stderr:
                    console.print(f"[red]{result.stderr.rstrip()}[/red]")
                if result.returncode != 0 and not result.stdout:
                    console.print(f"[red]Command failed: {line}[/red]")
        except FileNotFoundError:
            console.print(f"[red]Command not found: {line}[/red]")
        except subprocess.TimeoutExpired:
            console.print(f"[red]Command timed out: {line}[/red]")
        except Exception as e:
            console.print(f"[red]Error: {str(e)}[/red]")

    def emptyline(self):
        pass

