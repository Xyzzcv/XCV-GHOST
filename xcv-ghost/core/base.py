import json
import os
from pathlib import Path
from abc import ABC, abstractmethod
from rich.console import Console
from core.logger import Logger

console = Console()
logger = Logger()

import re

_FLAG_PREFIXES = r'(?:flag|ctf|picoctf|htb|xcv|ghost|sec|cyber|root|tjctf|mctf|angstrom|bi0s|redpwn|uiuctf|ductf|flare|asis|defcon|corctf|pbctf|cscg)'
_LATEX_CMDS = ('mathbb', 'mathrm', 'mathbf', 'textbf', 'textit', 'operatorname', 'boxed', 'text')

def extract_flags(data_str):
    if not isinstance(data_str, str):
        data_str = str(data_str)

    patterns = [
        r'(?:' + _FLAG_PREFIXES + r')\{[^{}\s\n]+\}',
        r'[A-Za-z0-9_\-]{3,25}\{[^}\s\n]{1,80}\}',
    ]

    flags = set()
    for p in patterns:
        for match in re.finditer(p, data_str, re.IGNORECASE):
            candidate = match.group(0)
            brace_idx = candidate.index('{')
            prefix_part = candidate[:brace_idx].lower()
            inner = candidate[brace_idx + 1:-1]
            if len(inner) < 2:
                continue
            if prefix_part in _LATEX_CMDS:
                continue
            if 'math' in prefix_part or 'latex' in prefix_part:
                continue
            if re.search(r'\\(mathbb|mathrm|mathbf|textbf|textit|text|frac|sum|int)', inner, re.IGNORECASE):
                continue
            flags.add(candidate)
    return list(flags)

def print_flag_box(flags):
    if not flags: return
    from rich.panel import Panel
    for f in flags:
        console.print(Panel(f"[bold green]🚩 FLAG FOUND: [bold yellow]{f}[/bold yellow][/bold green]", title="[bold red]★ CTF FLAG EXTRACTED ★[/bold red]", border_style="bold green"))

def print_final_flag_summary(flags):
    from rich.panel import Panel
    from rich.table import Table
    from rich import box

    flags = list(set(f for f in flags if f))
    console.print()
    if not flags:
        console.print(Panel("[dim yellow]No standard flag pattern (e.g. flag{...}) auto-extracted from output.[/dim yellow]", title="[bold cyan]★ FINAL CTF FLAG SUMMARY ★[/bold cyan]", border_style="cyan"))
        return

    table = Table(box=box.DOUBLE, border_style="bold green", header_style="bold red")
    table.add_column("No", style="bold yellow", justify="center")
    table.add_column("Discovered CTF Flag", style="bold green")

    for idx, f in enumerate(flags, 1):
        table.add_row(str(idx), f"🚩 {f}")

    console.print(Panel(table, title="[bold red]★ FINAL CTF FLAG SUMMARY ★[/bold red]", subtitle="[bold yellow]Analysis Complete![/bold yellow]", border_style="bold green"))

class BaseModule(ABC):
    def __init__(self):
        self.name = self.__class__.__name__
        self.logger = logger
        self.console = console

    @abstractmethod
    def get_commands(self):
        return {}

    def register_commands(self, parser):
        subparsers = parser.add_subparsers(dest="command", help=f"{self.name} commands")
        for cmd_name, cmd_info in self.get_commands().items():
            if cmd_name.startswith("_"):
                continue
            cmd_parser = subparsers.add_parser(cmd_name, help=cmd_info.get("help", ""))
            for arg in cmd_info.get("args", []):
                flags = arg.get("flags", [])
                kwargs = {k: v for k, v in arg.items() if k != "flags"}
                cmd_parser.add_argument(*flags, **kwargs)

    def handle(self, args):
        commands = self.get_commands()
        if args.command in commands:
            handler = commands[args.command].get("handler")
            if handler:
                try:
                    result = handler(args)
                    found_flags = extract_flags(str(result))
                    print_flag_box(found_flags)
                    self._handle_output(result, args)
                except Exception as e:
                    self.logger.error(f"{self.name} Error: {str(e)}")
                    console.print(f"\n[red]✗ Error: {str(e)}[/red]")
        else:
            console.print(f"[red]✗ Unknown command: {args.command}[/red]")

    def _handle_output(self, data, args):
        if data is None:
            return

        output_file = getattr(args, 'output', None)
        if output_file:
            ext = Path(output_file).suffix.lower()
            try:
                if ext == '.json':
                    with open(output_file, 'w') as f:
                        json.dump(data, f, indent=2, default=str)
                else:
                    with open(output_file, 'w') as f:
                        if isinstance(data, str):
                            f.write(data)
                        else:
                            f.write(json.dumps(data, indent=2, default=str))
                console.print(f"\n[green]✓ Output saved to: {output_file}[/green]")
            except Exception as e:
                console.print(f"[red]✗ Failed to save output: {e}[/red]")

    def save_text(self, filename, content):
        output_dir = Path.cwd() / "outputs"
        output_dir.mkdir(parents=True, exist_ok=True)
        filepath = output_dir / filename
        with open(filepath, 'w') as f:
            f.write(str(content))
        return filepath

    @staticmethod
    def read_file(path):
        with open(path, 'rb') as f:
            return f.read()

    @staticmethod
    def read_text(path):
        with open(path, 'r', errors='ignore') as f:
            return f.read()

