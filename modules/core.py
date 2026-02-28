import logging
import sys
import random
from dataclasses import dataclass, field
from typing import Optional, List
from rich.logging import RichHandler
from rich.console import Console
from rich.theme import Theme

custom_theme = Theme({
    "info": "cyan",
    "warning": "yellow",
    "error": "bold red",
    "critical": "bold white on red",
    "success": "bold green"
})
console = Console(theme=custom_theme)

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36 Edg/118.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/119.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36",
]

def get_random_ua() -> str:
    """Return a random user-agent string."""
    return random.choice(USER_AGENTS)


@dataclass
class Config:
    url: str = ""
    threads: int = 50
    timeout: int = 15
    user_agent: str = field(default_factory=get_random_ua)
    output_file: Optional[str] = None
    output_format: str = "all" 
    proxy: Optional[str] = None
    verbose: bool = False
    rate_limit: float = 0.0        
    max_retries: int = 2         
    rotate_ua: bool = True        
    profile: str = "standard"     
    webhook_url: Optional[str] = None
    cookie: Optional[str] = None
    custom_header: Optional[str] = None
    wordlist: Optional[str] = None
    exclude_patterns: Optional[str] = None
    include_patterns: Optional[str] = None
    telegram_token: Optional[str] = None
    telegram_chat: Optional[str] = None
    discord_webhook: Optional[str] = None
    target_list: Optional[str] = None
    shodan_key: Optional[str] = None
    vt_key: Optional[str] = None
    github_token: Optional[str] = None 


class Logger:
    @staticmethod
    def setup(verbose=False):
        level = logging.DEBUG if verbose else logging.INFO
        logging.basicConfig(
            level=level,
            format="%(message)s",
            datefmt="[%X]",
            handlers=[RichHandler(rich_tracebacks=True, console=console, show_path=False)]
        )
        return logging.getLogger("snakebite")


def get_timestamp():
    from datetime import datetime
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def format_duration(seconds: float) -> str:
    """Format seconds into human readable duration."""
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        m, s = divmod(int(seconds), 60)
        return f"{m}m {s}s"
    else:
        h, rem = divmod(int(seconds), 3600)
        m, s = divmod(rem, 60)
        return f"{h}h {m}m {s}s"
