import logging
import sys
from pathlib import Path
from datetime import datetime
from rich.console import Console
from rich.logging import RichHandler
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn

console = Console()

class Logger:
    _instance = None

    def __new__(cls, log_dir=None):
        if cls._instance is None:
            cls._instance = super(Logger, cls).__new__(cls)
            cls._instance._init_logger(log_dir)
        return cls._instance

    def _init_logger(self, log_dir=None):
        if log_dir is None:
            log_dir = Path.cwd() / "outputs" / "logs"
        else:
            log_dir = Path(log_dir)

        log_dir.mkdir(parents=True, exist_ok=True)
        filename = f"ghost_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        log_file = log_dir / filename

        self.logger = logging.getLogger("XCV-GHOST")
        self.logger.setLevel(logging.INFO)
        self.logger.handlers = []

        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setLevel(logging.DEBUG)
        file_format = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(file_format)
        self.logger.addHandler(file_handler)

        self.log_file = log_file

    def info(self, msg):
        self.logger.info(msg)

    def warning(self, msg):
        self.logger.warning(msg)
        console.print(f"[yellow]⚠ {msg}[/yellow]")

    def error(self, msg):
        self.logger.error(msg)

    def debug(self, msg):
        self.logger.debug(msg)

    def success(self, msg):
        self.logger.info(f"SUCCESS: {msg}")
        console.print(f"[bold green]✓ {msg}[/bold green]")

    def progress(self):
        return Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console
        )

