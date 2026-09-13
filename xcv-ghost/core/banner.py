from rich.console import Console
from rich.text import Text

console = Console()

class Banner:
    @staticmethod
    def show():
        lines = [
            ("[bold cyan]******************************************************************[/bold cyan]", ""),
            ("[bold cyan]*                                                                *[/bold cyan]", ""),
            ("[bold cyan]*                        [/bold cyan][bold red]*** XCV-GHOST ***[/bold red][bold cyan]                       *[/bold cyan]", ""),
            ("[bold cyan]*      [/bold cyan][bold green]Framework CLI Cybersecurity for CTF & Learning[/bold green][bold cyan]            *[/bold cyan]", ""),
            ("[bold cyan]*      [/bold cyan][bold yellow]Forensics[/bold yellow] - [bold yellow]Crypto[/bold yellow] - [bold yellow]PWN[/bold yellow] - [bold yellow]Reverse[/bold yellow] - [bold yellow]AI (Gemini)[/bold yellow][bold cyan]            *[/bold cyan]", ""),
            ("[bold cyan]*               [/bold cyan][bold blue]instagram.com/fatih_onee  (by xcv)[/bold blue][bold cyan]               *[/bold cyan]", ""),
            ("[bold cyan]*                                                                *[/bold cyan]", ""),
            ("[bold cyan]******************************************************************[/bold cyan]", ""),
        ]
        for line, _ in lines:
            console.print(line)

    @staticmethod
    def show_help():
        help_text = """
[bold cyan]USAGE:[/bold cyan]
    [green]python ghost.py [module] [command] [options][/green]

[bold cyan]DIRECT COMMANDS:[/bold cyan]
    [cyan]ai [text/file/soal][/cyan]   - Auto-solve CTF challenge with AI
    [cyan]solve [challenge][/cyan]    - Alias for AI CTF solver
    [cyan]rot13 [text/file][/cyan]     - Decode ROT13
    [cyan]base64 [text/file][/cyan]    - Decode Base64
    [cyan]hex [data][/cyan]          - Decode Hex
    [cyan]caesar [text][/cyan]         - Caesar brute-force
    [cyan]exif [filepath][/cyan]     - Image EXIF metadata
    [cyan]strings [filepath][/cyan]  - Extract strings from binary

[bold cyan]MODULES:[/bold cyan]
    [bold yellow]forensic[/bold yellow]    - Forensics analysis tools
    [bold yellow]crypto[/bold yellow]      - Cryptography tools
    [bold yellow]pwn[/bold yellow]         - Binary exploitation tools
    [bold yellow]reverse[/bold yellow]     - Reverse engineering tools
    [bold yellow]ai[/bold yellow]          - AI-powered CTF solver & analysis (Gemini)
        Sub-commands: solve, analyze, explain, chat, key, all, multi

[bold cyan]EXAMPLES:[/bold cyan]
    python ghost.py crypto base64 -d SGVsbG8=
    python ghost.py forensic metadata image.jpg
    python ghost.py pwn pattern 500
    python ghost.py reverse pe malware.exe
    python ghost.py ai "solve this CTF: ..."      - Quick AI solve
    python ghost.py                      - Interactive shell mode

[bold cyan]GLOBAL OPTIONS:[/bold cyan]
    -o, --output FILE    Save output to file (TXT/JSON)
    -v, --verbose        Verbose output
    --help               Show this help message
        """
        console.print(help_text)

    @staticmethod
    def show_about():
        about_text = """
[bold red]XCV-GHOST - Framework CLI Cybersecurity for CTF & Learning[/bold red]

Version  : 1.1.0
Author   : xcv
Social   : @fatih_onee
Purpose  : Educational CTF, Automated Analysis & Cybersecurity Learning Platform
    Modules  : Forensics, Crypto, Binary Exploitation (PWN), Reverse Engineering, AI CTF Solver (Gemini)

[bold yellow]DISCLAIMER:[/bold yellow]
This tool is intended for educational purposes, CTF competitions,
and authorized security testing only. Users are responsible for
complying with all applicable laws and regulations.

[bold green]In darkness, the ghost sees all. — xcv[/bold green]
        """
        console.print(about_text)

