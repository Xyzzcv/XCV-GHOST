import os
import re
from pathlib import Path
from core.base import BaseModule, extract_flags, print_flag_box, print_final_flag_summary
from core.logger import Logger
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box
from rich.text import Text

console = Console()
logger = Logger()


class AIModule(BaseModule):
    def __init__(self):
        super().__init__()
        self.name = "ai"

    def get_commands(self):
        return {
            "_description": "AI-powered CTF solver & analysis (Gemini)",
            "solve": {
                "help": "Auto-solve a CTF challenge and extract the flag",
                "usage": "solve <question/file/text>",
                "handler": self.cmd_solve,
                "args": [
                    {"flags": ["input"], "help": "Challenge question, file path, or text", "type": str}
                ]
            },
            "analyze": {
                "help": "Analyze a file/artifact with AI assistance",
                "usage": "analyze <filepath>",
                "handler": self.cmd_analyze,
                "args": [
                    {"flags": ["filepath"], "help": "Path to file to analyze", "type": str}
                ]
            },
            "explain": {
                "help": "Explain a CTF concept or technique",
                "usage": "explain <topic>",
                "handler": self.cmd_explain,
                "args": [
                    {"flags": ["topic"], "help": "Topic or concept to explain", "type": str}
                ]
            },
            "chat": {
                "help": "Chat with the AI about cybersecurity/CTF",
                "usage": "chat <message>",
                "handler": self.cmd_chat,
                "args": [
                    {"flags": ["message"], "help": "Message to send to AI", "type": str}
                ]
            },
            "key": {
                "help": "Set or check Gemini API key",
                "usage": "key [<api_key>]",
                "handler": self.cmd_key,
                "args": [
                    {"flags": ["api_key"], "help": "Gemini API key (omit to check current)", "type": str, "default": None, "nargs": "?"}
                ]
            },
            "all": {
                "help": "Run comprehensive AI CTF solving suite on a challenge",
                "usage": "all <question/file/text>",
                "handler": self.cmd_all,
                "args": [
                    {"flags": ["input"], "help": "Challenge question, file path, or text", "type": str}
                ]
            },
            "multi": {
                "help": "Solve CTF using AI with multiple files as input",
                "usage": "multi <file1> <file2> <file3> ...",
                "handler": self.cmd_multi,
                "args": [
                    {"flags": ["files"], "help": "Multiple file paths to analyze", "type": str, "nargs": "+"}
                ]
            }
        }

    def _get_engine(self):
        from core.engine import Engine
        return Engine()

    def _read_input(self, query):
        prompt = query.strip()
        filepath = Path(query)
        is_file = filepath.exists() and filepath.is_file()
        if is_file:
            size = filepath.stat().st_size
            ext = filepath.suffix
            try:
                with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read(50000)
            except Exception:
                with open(filepath, "rb") as f:
                    data = f.read(2048)
                content = data.hex()
            prompt = (
                f"File: {filepath.name}\n"
                f"Size: {size} bytes\n"
                f"Extension: {ext}\n"
                f"Content / Data:\n{content}\n\n"
                f"Please analyze this CTF challenge, solve it step-by-step, "
                f"and extract the flag."
            )
        return prompt, is_file

    def _run_ai(self, prompt, category):
        engine = self._get_engine()
        if not engine.client:
            console.print("[red][!] AI Engine not configured. Set your Gemini API key with: ai key <your_key>[/red]")
            return None

        from core.base import extract_flags, print_flag_box
        with console.status(f"[bold cyan]AI analyzing {category} with Gemini...[/bold cyan]", spinner="dots"):
            response = engine.run(prompt, category)

        console.print()
        console.print(Panel(response, title="[bold red]★ AI CTF SOLVER RESULT ★[/bold red]", border_style="bold cyan"))

        found_flags = extract_flags(response)
        if found_flags:
            print_flag_box(found_flags)
            print_final_flag_summary(found_flags)
        else:
            console.print("[yellow]No flag pattern auto-extracted. Review the AI analysis above.[/yellow]")
        return response

    def cmd_solve(self, args):
        query = args.input.strip() if args.input else ""
        if not query:
            query = input("[*] Enter CTF challenge / text / file path / question: ").strip()
        if not query:
            console.print("[red]No challenge provided.[/red]")
            return

        prompt, _ = self._read_input(query)
        category = "CTF Challenge"
        return self._run_ai(prompt, category)

    def cmd_analyze(self, args):
        filepath = Path(args.filepath)
        if not filepath.exists():
            logger.error(f"File not found: {filepath}")
            return

        prompt, is_file = self._read_input(str(filepath))
        if not is_file:
            prompt = (
                f"File: {filepath.name}\n"
                f"Please perform a thorough forensic and structural analysis of this file,"
                f" identify any hidden data, steganography, or embedded content, and"
                f" extract any flags."
            )
        category = "Forensic Analysis"
        return self._run_ai(prompt, category)

    def cmd_explain(self, args):
        topic = args.topic.strip()
        if not topic:
            topic = input("[*] Enter topic to explain: ").strip()
        if not topic:
            console.print("[red]No topic provided.[/red]")
            return

        prompt = (
            f"You are an expert CTF educator. Explain the following concept or "
            f"technique in detail, including how it applies to Capture The Flag "
            f"competitions and any common pitfalls or best practices: {topic}"
        )
        engine = self._get_engine()
        if not engine.client:
            console.print("[red][!] AI Engine not configured. Set your Gemini API key with: ai key <your_key>[/red]")
            return None

        with console.status(f"[bold cyan]AI explaining '{topic}'...[/bold cyan]", spinner="dots"):
            response = engine.run(prompt, "Education")

        console.print()
        console.print(Panel(response, title=f"[bold yellow]★ EXPLANATION: {topic} ★[/bold yellow]", border_style="bold cyan"))
        return response

    def cmd_chat(self, args):
        message = args.message.strip()
        if not message:
            message = input("[*] Enter message: ").strip()
        if not message:
            console.print("[red]No message provided.[/red]")
            return

        engine = self._get_engine()
        if not engine.client:
            console.print("[red][!] AI Engine not configured. Set your Gemini API key with: ai key <your_key>[/red]")
            return None

        with console.status("[bold cyan]AI thinking...[/bold cyan]", spinner="dots"):
            response = engine.run(message, "Chat")

        console.print()
        console.print(Panel(response, title="[bold magenta]★ GEMINI CHAT ★[/bold magenta]", border_style="bold magenta"))
        return response

    def cmd_key(self, args):
        key_value = args.api_key

        if key_value:
            key_value = key_value.strip()
            if len(key_value) < 10:
                console.print("[red]API key appears too short. Please verify and try again.[/red]")
                return

            key_file = Path.home() / ".xcv_ghost_key"
            try:
                key_file.write_text(key_value)
                console.print(f"[bold green]✓ Gemini API key saved to ~/.xcv_ghost_key[/bold green]")
                console.print("[dim](Alternatively set GEMINI_API_KEY environment variable)[/dim]")

                from core.engine import Engine
                engine = Engine()
                if engine.client:
                    console.print("[green]✓ API key validated successfully! AI engine is ready.[/green]")
                else:
                    console.print("[yellow]⚠ Key saved, but could not validate against Gemini. Try running a command.[/yellow]")
            except Exception as e:
                console.print(f"[red]Failed to save API key: {e}[/red]")
            return {"key_configured": (Path.home() / ".xcv_ghost_key").exists()}
        else:
            key = os.environ.get("GEMINI_API_KEY", "").strip()
            if key:
                masked = key[:4] + "•" * (len(key) - 8) + key[-4:] if len(key) > 8 else "•••••"
                console.print(f"[green]✓ Gemini API key found (via GEMINI_API_KEY env): {masked}[/green]")
            else:
                key_file = Path.home() / ".xcv_ghost_key"
                if key_file.exists():
                    stored = key_file.read_text().strip()
                    if stored:
                        masked = stored[:4] + "•" * (len(stored) - 8) + stored[-4:] if len(stored) > 8 else "•••••"
                        console.print(f"[green]✓ Gemini API key found (via ~/.xcv_ghost_key): {masked}[/green]")
                    else:
                        console.print("[yellow]No Gemini API key configured.[/yellow]")
                        console.print("[cyan]Set it with: ai key <your_api_key>  or  export GEMINI_API_KEY='your_key'[/cyan]")
                else:
                    console.print("[yellow]No Gemini API key configured.[/yellow]")
                    console.print("[cyan]Set it with: ai key <your_api_key>  or  export GEMINI_API_KEY='your_key'[/cyan]")

        console.print()
        console.print(Panel(
            "[bold]Gemini API Key Manager[/bold]\n\n"
            "Usage:\n"
            "  ai key <your_api_key>   - Save your Gemini API key\n"
            "  ai key                  - Check current API key status\n\n"
            "Get a free API key at: https://aistudio.google.com/apikey",
            title="[bold cyan]KEY STATUS[/bold cyan]",
            border_style="cyan"
        ))
        return {"key_configured": bool(key or (Path.home() / ".xcv_ghost_key").exists())}

    def cmd_all(self, args):
        query = args.input.strip() if args.input else ""
        if not query:
            query = input("[*] Enter CTF challenge / text / file path / question: ").strip()
        if not query:
            console.print("[red]No challenge provided.[/red]")
            return

        console.print(Panel(
            f"[bold cyan]AI CTF SOLVING SUITE[/bold cyan]\n"
            f"[yellow]Target:[/yellow] {query[:100]}{'...' if len(query) > 100 else ''}",
            box=box.ROUNDED
        ))

        prompt, is_file = self._read_input(query)
        category = "CTF Challenge (Comprehensive)"

        results = {}
        collected_flags = set()

        console.print("\n[bold red][1] COMPREHENSIVE AI ANALYSIS[/bold red]")
        response = self._run_ai(prompt, category)
        if response:
            results["analysis"] = response
            collected_flags.update(extract_flags(response))

        console.print("\n[bold red][2] DEEP FLAG SEARCH[/bold red]")
        deep_prompt = (
            f"{prompt}\n\n"
            f"Now, with maximum effort, search the entire content for any hidden flags."
            f" Consider steganography, encoding (base64, hex, rot13, etc.), cipher layers,"
            f" metadata, and any pattern matching flag{{...}}, CTF{{...}}, or similar."
            f" Clearly state the final flag at the very end."
        )
        deep_response = self._run_ai(deep_prompt, "Flag Extraction")
        if deep_response:
            results["deep_search"] = deep_response
            collected_flags.update(extract_flags(deep_response))

        console.print(f"\n[bold green]✓ AI CTF solving suite complete![/bold green]")
        print_final_flag_summary(list(collected_flags))
        return {"results": results, "flags": list(collected_flags)}

    def cmd_multi(self, args):
        files = args.files
        if not files:
            raw = input("[*] Enter file paths (space-separated): ").strip()
            if not raw:
                console.print("[red]No files provided.[/red]")
                return
            files = raw.split()

        valid_files = []
        file_table = Table(title="Multi-File Input", box=box.ROUNDED, border_style="cyan")
        file_table.add_column("#", style="bold yellow", justify="center")
        file_table.add_column("File", style="white")
        file_table.add_column("Size", style="cyan")
        file_table.add_column("Type", style="green")

        for idx, fpath in enumerate(files, 1):
            fpath = fpath.strip().strip('"')
            fp = Path(fpath)
            if fp.exists() and fp.is_file():
                size = fp.stat().st_size
                file_table.add_row(str(idx), fpath, f"{size:,} bytes", fp.suffix or "(no ext)")
                valid_files.append(fpath)
            else:
                file_table.add_row(str(idx), fpath, "-", "[red]NOT FOUND[/red]")

        console.print(file_table)
        console.print(f"\n[green]Valid files to analyze: {len(valid_files)}[/green]")
        if not valid_files:
            console.print("[red]No valid files provided. Aborting.[/red]")
            return

        sections = []
        for fidx, fpath in enumerate(valid_files, 1):
            filepath = Path(fpath)
            size = filepath.stat().st_size
            ext = filepath.suffix
            try:
                with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read(80000)
            except Exception:
                with open(filepath, "rb") as f:
                    data = f.read(2048)
                content = data.hex()
            sections.append(
                f"=== FILE {fidx}: {filepath.name} ===\n"
                f"Path: {filepath}\n"
                f"Size: {size} bytes\n"
                f"Extension: {ext}\n"
                f"Content / Data:\n{content}\n"
            )

        combined_prompt = (
            f"MULTI-FILE CTF CHALLENGE - {len(valid_files)} FILES PROVIDED\n\n"
            f"Each file below is part of the same CTF challenge. Analyze all of them "
            f"together, correlate any relationships between them, solve step-by-step, "
            f"and extract the final flag.\n\n"
            + "\n".join(sections)
            + "\nPlease analyze all files together, identify any hidden data, encoding layers,"
            " steganography, or cross-file relationships, and extract the flag."
        )

        category = f"Multi-File CTF ({len(valid_files)} files)"
        return self._run_ai(combined_prompt, category)
