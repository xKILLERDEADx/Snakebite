from rich import print as rprint
from rich.panel import Panel
from rich.align import Align
from rich.text import Text
from rich.columns import Columns
import random

VERSION = "v2.0"

THEMES = [
    ("bold green", "green"),
    ("bold cyan", "cyan"),
    ("bold magenta", "magenta"),
    ("bold bright_green", "bright_green"),
]

def show_banner():
    theme_text, theme_border = random.choice(THEMES)

    snake_art = r"""
       ---_ ......._-_--.
      (|\ /      / /| \  \
      /  /     .'  -=-'   `.
     /  /    .'             )
   _/  /   .'        _.)   /
  /   o  o       _.-' /  .'
  \          _.-'    / .'*|
   \______.-'//    .'.' \*|
    \|  \ | //   .'.' _ |*|
     `   \|//  .'.'_ _ _|*|
      .  .// .'.' | _ _ \*|
      \`-|\_/ /    \ _ _ \*\
       `/'\_/      \ _ _ \*\
      /^|            \ _ _ \*
     '  `             \ _ _ \
                       \_
   ____  _   __ ___    __ __ ______ ____  ____ ______ ______
  / __/ / | / //   |  / //_// ____// __ )/  _//_  __// ____/
 _\ \  /  |/ // /| | / ,<  / __/  / __  |/ /   / /  / __/   
/___/ / /|  // ___ |/ /| |/ /___ / /_/ // /   / /  / /___   
\__/ /_/ |_//_/  |_/_/ |_/_____//_____/___/  /_/  /_____/   
"""

    banner_text = Text(snake_art, style=theme_text)
    banner_text.highlight_regex(r"o  o", "bold red blink")
    tagline = Text(f"\n[ SNAKEBITE {VERSION} — Advanced Automated Web Security Scanner ]", style=f"bold white on {theme_border}")

    try:
        import os
        modules_path = os.path.join(os.path.dirname(__file__), "modules")
        module_count = len([f for f in os.listdir(modules_path) if f.endswith('.py') and f != '__init__.py'])
    except Exception:
        module_count = 110

    links = Text()
    links.append(f"\n\n  Modules Loaded: ", style="bold cyan")
    links.append(f"{module_count}+ attack modules", style="bold yellow")
    links.append("  |  Version: ", style="bold cyan")
    links.append(VERSION, style="bold green")
    links.append("\n  Developer: ", style="bold cyan")
    links.append("Muhammad Abid (xKILLERDEADx)", style="bold yellow")
    links.append("\n  GitHub: ", style="bold cyan")
    links.append("https://github.com/xKILLERDEADx", style="underline blue")

    disclaimer = Text(
        "\n\n[!] LEGAL DISCLAIMER: Usage of Snakebite for attacking targets without prior mutual "
        "consent is illegal. It is the end user's responsibility to obey all applicable local, "
        "state and federal laws. Developers assume no liability.",
        style="dim red", justify="center"
    )

    final_content = banner_text + tagline + links + disclaimer
    panel = Panel(
        Align.center(final_content),
        border_style=theme_border,
        padding=(1, 2)
    )

    rprint(panel)