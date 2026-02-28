"""Scan Resume / Checkpoint — save and resume interrupted scans."""

import json
import os
import hashlib
from datetime import datetime
from modules.core import console


CHECKPOINT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'checkpoints')


def _get_checkpoint_path(url):
    """Generate checkpoint file path based on target URL hash."""
    url_hash = hashlib.md5(url.encode()).hexdigest()[:12]
    return os.path.join(CHECKPOINT_DIR, f'checkpoint_{url_hash}.json')


def save_checkpoint(url, completed_modules, results, config_snapshot=None):
    """Save scan progress to checkpoint file."""
    os.makedirs(CHECKPOINT_DIR, exist_ok=True)

    checkpoint = {
        'url': url,
        'timestamp': datetime.now().isoformat(),
        'completed_modules': list(completed_modules),
        'results': {},
        'config': config_snapshot or {},
    }

    for key, value in results.items():
        try:
            json.dumps(value)
            checkpoint['results'][key] = value
        except (TypeError, ValueError):
            checkpoint['results'][key] = str(value)[:200]

    path = _get_checkpoint_path(url)
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(checkpoint, f, indent=2, default=str)

    console.print(f"  [dim]Checkpoint saved: {len(completed_modules)} modules[/dim]")
    return path


def load_checkpoint(url):
    """Load scan checkpoint for a target URL."""
    path = _get_checkpoint_path(url)
    if not os.path.exists(path):
        return None

    try:
        with open(path, 'r', encoding='utf-8') as f:
            checkpoint = json.load(f)

        age_hours = (datetime.now() - datetime.fromisoformat(checkpoint['timestamp'])).total_seconds() / 3600

        console.print(f"\n[bold cyan]--- Scan Checkpoint Found ---[/bold cyan]")
        console.print(f"  [green]Target: {checkpoint['url']}[/green]")
        console.print(f"  [dim]Saved: {checkpoint['timestamp']} ({age_hours:.1f}h ago)[/dim]")
        console.print(f"  [dim]Completed modules: {len(checkpoint['completed_modules'])}[/dim]")

        if age_hours > 24:
            console.print(f"  [yellow]Checkpoint is {age_hours:.0f}h old — may be stale[/yellow]")

        return checkpoint
    except Exception as e:
        console.print(f"  [red]Checkpoint load error: {e}[/red]")
        return None


def get_remaining_modules(checkpoint, all_modules):
    """Get list of modules not yet completed."""
    if not checkpoint:
        return all_modules
    completed = set(checkpoint.get('completed_modules', []))
    return [m for m in all_modules if m not in completed]


def clear_checkpoint(url):
    """Remove checkpoint file after scan completes."""
    path = _get_checkpoint_path(url)
    if os.path.exists(path):
        os.remove(path)
        console.print(f"  [dim]Checkpoint cleared[/dim]")


def list_checkpoints():
    """List all saved checkpoints."""
    console.print(f"\n[bold cyan]--- Saved Checkpoints ---[/bold cyan]")

    if not os.path.exists(CHECKPOINT_DIR):
        console.print(f"  [dim]No checkpoints found[/dim]")
        return []

    checkpoints = []
    for fname in sorted(os.listdir(CHECKPOINT_DIR)):
        if fname.endswith('.json'):
            try:
                path = os.path.join(CHECKPOINT_DIR, fname)
                with open(path, 'r') as f:
                    data = json.load(f)
                checkpoints.append({
                    'file': fname,
                    'url': data.get('url', 'unknown'),
                    'timestamp': data.get('timestamp', ''),
                    'modules': len(data.get('completed_modules', [])),
                })
                console.print(f"  [green]{data['url']}[/green]")
                console.print(f"    [dim]{data['timestamp']} — {len(data.get('completed_modules', []))} modules completed[/dim]")
            except Exception:
                pass

    if not checkpoints:
        console.print(f"  [dim]No checkpoints found[/dim]")

    return checkpoints
