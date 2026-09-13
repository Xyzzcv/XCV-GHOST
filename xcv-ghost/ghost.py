#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
XCV-GHOST - Framework CLI Cybersecurity for CTF & Learning
Author  : xcv
Social  : @fatih_onee
Version : 1.1.0
"""

import os
import sys
import warnings
import logging

warnings.filterwarnings("ignore")
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.disable(logging.CRITICAL)

import argparse
from pathlib import Path

# ─── Windows UTF-8 Fix ───────────────────────────────────────────────────────
if sys.platform == "win32":
    import io as _io_win
    os.system("chcp 65001 > nul 2>&1")
    sys.stdout = _io_win.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = _io_win.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

GHOST_HOME = Path(os.environ.get("GHOST_HOME", Path(__file__).resolve().parent))
sys.path.insert(0, str(GHOST_HOME))

from rich.console import Console
console = Console()

def get_install_path(*parts):
    return GHOST_HOME.joinpath(*parts)

def get_output_path(*parts):
    return Path.cwd().joinpath("outputs", *parts)

def setup_environment():
    from core.config import Config
    from core.logger import Logger

    config = Config(config_path=get_install_path("settings.json"))
    log_dir = get_output_path("logs")
    logger = Logger(log_dir=str(log_dir))

    get_output_path().mkdir(parents=True, exist_ok=True)
    get_output_path("logs").mkdir(parents=True, exist_ok=True)
    get_install_path("plugins").mkdir(exist_ok=True)
    get_install_path("wordlists").mkdir(exist_ok=True)

    return config, logger

def load_modules():
    modules = {}
    try:
        from modules.forensics.forensics import ForensicsModule
        modules["forensic"] = ForensicsModule()
    except Exception as e:
        console.print(f"[red]Failed to load Forensics module: {e}[/red]")

    try:
        from modules.crypto.crypto import CryptoModule
        modules["crypto"] = CryptoModule()
    except Exception as e:
        console.print(f"[red]Failed to load Crypto module: {e}[/red]")

    try:
        from modules.pwn.pwn import PWNModule
        modules["pwn"] = PWNModule()
    except Exception as e:
        console.print(f"[red]Failed to load PWN module: {e}[/red]")

    try:
        from modules.reverse.reverse import ReverseModule
        modules["reverse"] = ReverseModule()
    except Exception as e:
        console.print(f"[red]Failed to load Reverse module: {e}[/red]")

    try:
        from modules.ai.ai import AIModule
        modules["ai"] = AIModule()
    except Exception as e:
        console.print(f"[red]Failed to load AI module: {e}[/red]")

    return modules

def load_plugins(config):
    from core.plugin_loader import PluginLoader
    if config.get("plugins", "auto_load", default=True):
        loader = PluginLoader(plugin_dir=str(get_install_path("plugins")))
        loader.discover_plugins()
        return loader
    return None

def run_interactive(modules):
    from core.interactive import InteractiveMode
    try:
        interactive = InteractiveMode(modules)
        interactive.cmdloop()
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted. Goodbye![/yellow]")
    except Exception as e:
        console.print(f"[red]Interactive mode error: {e}[/red]")

def main():
    config, logger = setup_environment()
    from core.banner import Banner

    modules = load_modules()
    plugin_loader = load_plugins(config)

    # Check for direct quick commands like: python ghost.py rot13 text or python ghost.py ai "soal"
    if len(sys.argv) > 1 and sys.argv[1].lower() in ("ai", "solve", "ghost", "rot13", "base64", "b64", "hex", "caesar", "exif", "strings", "analyze", "stego"):
        cmd_name = sys.argv[1].lower()
        args_str = " ".join(sys.argv[2:]) if len(sys.argv) > 2 else ""
        from core.interactive import InteractiveMode
        im = InteractiveMode(modules)
        im.default(f"{cmd_name} {args_str}")
        return

    parser = argparse.ArgumentParser(
        description="XCV-GHOST - Cybersecurity CLI Framework by xcv (@fatih_onee)",
        usage="ghost [module] [command] [options]",
        add_help=False
    )
    parser.add_argument("--help", action="store_true", help="Show help message")
    parser.add_argument("-o", "--output", help="Save output to file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("module", nargs="?", help="Module name (forensic, crypto, pwn, reverse)")
    parser.add_argument("command", nargs="?", help="Command for the module")

    args, remaining = parser.parse_known_args()

    if args.help or (args.module is None):
        if args.module is None and not args.help:
            run_interactive(modules)
        else:
            Banner.show()
            Banner.show_help()
        return

    if args.module in modules:
        module_parser = argparse.ArgumentParser(
            description=f"XCV-GHOST - {args.module} module",
            usage=f"ghost {args.module} <command> [options]",
            add_help=False
        )

        module = modules[args.module]
        module.register_commands(module_parser)

        cmd_line = ([args.command] if args.command else []) + remaining
        cmd_args = module_parser.parse_args(cmd_line)

        cmd_args.output = args.output
        cmd_args.verbose = args.verbose

        module.handle(cmd_args)
    else:
        console.print(f"[red]Unknown module: {args.module}[/red]")
        console.print(f"[yellow]Available modules: {', '.join(modules.keys())}[/yellow]")
        Banner.show_help()
        sys.exit(1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted. Goodbye![/yellow]")
    except Exception as e:
        console.print(f"\n[bold red]Fatal Error: {str(e)}[/bold red]")
        sys.exit(1)
