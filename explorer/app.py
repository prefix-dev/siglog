#!/usr/bin/env -S uv run
# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "textual>=0.47.0",
#     "httpx>=0.27.0",
#     "rich>=13.0.0",
#     "cryptography>=42.0.0",
# ]
# ///
"""
Tessera Log Explorer - A TUI for exploring transparency logs
"""

import argparse
import base64
import hashlib
import json
import re
import struct
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urljoin

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from rich.syntax import Syntax
from textual import work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical, ScrollableContainer
from textual.widgets import (
    Button,
    Footer,
    Header,
    Input,
    Label,
    Static,
    TabbedContent,
    TabPane,
)


@dataclass
class NoteSignature:
    """A parsed note signature."""
    name: str
    key_hash: int  # 4-byte key hash
    signature: bytes  # 64-byte Ed25519 signature
    raw: str

    @classmethod
    def parse(cls, line: str) -> Optional["NoteSignature"]:
        """Parse a signature line like: — name hash+sig"""
        if not line.startswith("— "):
            return None
        parts = line[2:].rsplit(" ", 1)
        if len(parts) != 2:
            return None
        name, hash_sig = parts
        try:
            # hash_sig format: {key_hash_base64}+{signature_base64}
            # The key_hash is first 4 bytes, signature is 64 bytes
            decoded = base64.b64decode(hash_sig)
            if len(decoded) != 4 + 64:
                return None
            key_hash = struct.unpack(">I", decoded[:4])[0]
            signature = decoded[4:]
            return cls(name=name, key_hash=key_hash, signature=signature, raw=line)
        except Exception:
            return None


@dataclass
class ParsedCheckpoint:
    """A parsed and optionally verified checkpoint."""
    origin: str
    size: int
    root_hash: bytes
    root_hash_b64: str
    signatures: list[NoteSignature]
    raw: str
    signed_data: bytes  # The data that was signed

    @classmethod
    def parse(cls, raw: str) -> Optional["ParsedCheckpoint"]:
        """Parse a checkpoint note."""
        lines = raw.strip().split("\n")
        if len(lines) < 3:
            return None

        origin = lines[0]
        try:
            size = int(lines[1])
        except ValueError:
            return None

        root_hash_b64 = lines[2]
        try:
            root_hash = base64.b64decode(root_hash_b64)
        except Exception:
            return None

        # Signatures come after an empty line
        signatures = []
        for line in lines[3:]:
            if line.startswith("— "):
                sig = NoteSignature.parse(line)
                if sig:
                    signatures.append(sig)

        # The signed data is everything up to and including the first empty line after content
        # Format: "{origin}\n{size}\n{hash}\n\n"
        signed_data = f"{origin}\n{size}\n{root_hash_b64}\n".encode("utf-8")

        return cls(
            origin=origin,
            size=size,
            root_hash=root_hash,
            root_hash_b64=root_hash_b64,
            signatures=signatures,
            raw=raw,
            signed_data=signed_data,
        )

    def verify_signature(self, public_key_str: str) -> tuple[bool, str]:
        """Verify the checkpoint signature against a public key.

        The public key format is: {name}+{key_hash_hex}+{public_key_b64}
        The base64 key can contain '+', so we need careful parsing.
        Returns (success, message).
        """
        try:
            # Parse the public key string
            # Format: name+hash_hex+key_base64
            # The hash is always 8 hex chars, key_base64 can contain '+'
            parts = public_key_str.split("+")
            if len(parts) < 3:
                return False, f"Invalid public key format (expected name+hash+key)"

            # Find the 8-char hex hash part
            hash_idx = None
            for i, part in enumerate(parts):
                if len(part) == 8 and all(c in '0123456789abcdef' for c in part.lower()):
                    hash_idx = i
                    break

            if hash_idx is None:
                return False, "Could not find 8-char hex hash in public key"

            name = "+".join(parts[:hash_idx])
            key_hash_hex = parts[hash_idx]
            key_b64 = "+".join(parts[hash_idx + 1:])

            # Parse key hash
            key_hash = int(key_hash_hex, 16)

            # Parse public key (base64 encoded)
            # Format: 1-byte algorithm prefix + 32-byte Ed25519 key = 33 bytes
            key_data = base64.b64decode(key_b64)
            if len(key_data) == 33:
                # Has algorithm prefix byte (0x01 = Ed25519)
                algo_byte = key_data[0]
                if algo_byte != 0x01:
                    return False, f"Unsupported algorithm: {algo_byte:#x} (expected 0x01 for Ed25519)"
                public_key_bytes = key_data[1:]
            elif len(key_data) == 32:
                # No prefix, raw key
                public_key_bytes = key_data
            else:
                return False, f"Invalid public key length: {len(key_data)} (expected 32 or 33 bytes)"

            # Find matching signature by key hash
            matching_sig = None
            for sig in self.signatures:
                if sig.key_hash == key_hash:
                    matching_sig = sig
                    break

            if not matching_sig:
                available = ", ".join(f"{s.name}:{s.key_hash:08x}" for s in self.signatures)
                return False, f"No signature for key hash {key_hash:08x}. Available: {available}"

            # Verify using Ed25519
            public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
            public_key.verify(matching_sig.signature, self.signed_data)
            return True, f"Valid signature from {matching_sig.name}"

        except ValueError as e:
            return False, f"Parse error: {e}"
        except Exception as e:
            return False, f"Verification failed: {e}"


class TesseraExplorer(App):
    """Main TUI application for exploring Tessera logs."""

    CSS = """
    Screen {
        background: $surface;
    }

    #checkpoint-container {
        height: 12;
        border: solid green;
        padding: 0 1;
    }

    #entry-container {
        height: 1fr;
        border: solid blue;
    }

    #entry-nav {
        height: 3;
        align: center middle;
        background: $surface-darken-1;
    }

    #entry-nav Button {
        margin: 0 1;
    }

    #entry-scroll {
        height: 1fr;
        padding: 1;
    }

    #entry-display {
        height: auto;
    }

    .nav-label {
        width: auto;
        padding: 0 2;
    }

    #jump-input {
        width: 12;
    }

    #vindex-container {
        padding: 1;
    }

    #vindex-result {
        height: 1fr;
        border: solid $primary;
        padding: 1;
    }

    #stats-display {
        padding: 1;
    }
    """

    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("left", "prev_entry", "Prev", show=True),
        Binding("right", "next_entry", "Next", show=True),
        Binding("r", "refresh", "Refresh"),
        Binding("g", "focus_jump", "Jump"),
    ]

    def __init__(self, base_url: str, public_key: Optional[str] = None, **kwargs):
        super().__init__(**kwargs)
        self.base_url = base_url.rstrip("/") + "/"
        self.public_key = public_key
        self.client = httpx.AsyncClient(timeout=30.0)
        self.checkpoint_size = 0
        self.current_index = 0
        self.entry_cache: dict[int, bytes] = {}

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)

        with TabbedContent():
            with TabPane("Browse", id="browse-tab"):
                with Vertical():
                    with Container(id="checkpoint-container"):
                        yield Static("Loading checkpoint...", id="checkpoint-display")

                    with Container(id="entry-container"):
                        with Horizontal(id="entry-nav"):
                            yield Button("< Prev", id="btn-prev", variant="primary")
                            yield Static("0 / 0", id="entry-label", classes="nav-label")
                            yield Button("Next >", id="btn-next", variant="primary")
                            yield Input(placeholder="Index", id="jump-input", type="integer")
                            yield Button("Go", id="btn-jump", variant="success")

                        with ScrollableContainer(id="entry-scroll"):
                            yield Static("Loading entry...", id="entry-display")

            with TabPane("VIndex", id="vindex-tab"):
                with Vertical(id="vindex-container"):
                    yield Label("Lookup by package name:")
                    yield Input(placeholder="Package name (e.g., numpy)", id="vindex-input")
                    yield Button("Lookup", id="btn-vindex", variant="primary")
                    with ScrollableContainer(id="vindex-result"):
                        yield Static("Enter a package name", id="vindex-output")

            with TabPane("Stats", id="stats-tab"):
                yield Static("Loading stats...", id="stats-display")

        yield Footer()

    def on_mount(self):
        self.title = "Tessera Log Explorer"
        self.sub_title = self.base_url
        self.refresh_checkpoint()
        self.refresh_stats()

    @work(exclusive=True, group="checkpoint")
    async def refresh_checkpoint(self):
        try:
            response = await self.client.get(urljoin(self.base_url, "checkpoint"))
            response.raise_for_status()
            raw = response.text

            # Parse the checkpoint
            checkpoint = ParsedCheckpoint.parse(raw)
            if not checkpoint:
                self.query_one("#checkpoint-display", Static).update(f"[red]Failed to parse checkpoint[/]")
                return

            # Build display text
            display_text = (
                f"[bold cyan]Origin:[/] {checkpoint.origin}\n"
                f"[bold green]Size:[/] {checkpoint.size:,} entries\n"
                f"[bold yellow]Root Hash:[/] {checkpoint.root_hash_b64}\n"
            )

            # Show signature info
            if checkpoint.signatures:
                sig = checkpoint.signatures[0]
                display_text += f"[bold magenta]Signed by:[/] {sig.name}\n"
                display_text += f"[dim]Key ID:[/] {sig.key_hash:08x}\n"

                # Verify if we have a public key
                if self.public_key:
                    valid, msg = checkpoint.verify_signature(self.public_key)
                    if valid:
                        display_text += f"[bold green]✓ Signature Valid[/]\n"
                    else:
                        display_text += f"[bold red]✗ {msg}[/]\n"
                else:
                    display_text += f"[dim]No public key provided for verification[/]\n"
            else:
                display_text += "[yellow]No signatures found[/]\n"

            self.query_one("#checkpoint-display", Static).update(display_text)

            # Update state and load entry
            self.checkpoint_size = checkpoint.size
            self.update_nav_label()
            if self.checkpoint_size > 0:
                self.current_index = self.checkpoint_size - 1
                self.load_current_entry()

        except Exception as e:
            self.query_one("#checkpoint-display", Static).update(f"[red]Error: {e}[/]")

    @work(exclusive=True, group="stats")
    async def refresh_stats(self):
        try:
            response = await self.client.get(urljoin(self.base_url, "vindex/stats"))
            response.raise_for_status()
            stats = response.json()

            text = "[bold underline]VIndex Statistics[/]\n\n"
            for key, value in stats.items():
                text += f"[cyan]{key}:[/] {value}\n"

            self.query_one("#stats-display", Static).update(text)

        except Exception as e:
            self.query_one("#stats-display", Static).update(f"[dim]Stats unavailable: {e}[/]")

    @work(exclusive=True, group="entry")
    async def load_current_entry(self):
        index = self.current_index
        if index < 0 or index >= self.checkpoint_size:
            return

        # Check cache first
        if index in self.entry_cache:
            self.display_entry(index, self.entry_cache[index])
            return

        try:
            bundle_index = index // 256
            path = self.format_entries_path(bundle_index, self.checkpoint_size)
            url = urljoin(self.base_url, path)

            response = await self.client.get(url)
            response.raise_for_status()

            # Parse bundle
            entries = self.parse_entry_bundle(response.content)
            base_index = bundle_index * 256
            for i, entry in enumerate(entries):
                self.entry_cache[base_index + i] = entry

            if index in self.entry_cache:
                self.display_entry(index, self.entry_cache[index])

        except Exception as e:
            self.query_one("#entry-display", Static).update(f"[red]Error loading entry {index}: {e}[/]")

    def display_entry(self, index: int, data: bytes):
        # Compute entry hash (leaf hash for Merkle tree)
        entry_hash = hashlib.sha256(data).hexdigest()

        # Build header with entry metadata
        header = (
            f"[bold cyan]Entry #{index}[/] of {self.checkpoint_size:,}  "
            f"[dim]|[/]  [bold yellow]Hash:[/] {entry_hash[:16]}...  "
            f"[dim]|[/]  [bold green]Size:[/] {len(data):,} bytes\n"
            f"[dim]{'─' * 70}[/]\n"
        )

        try:
            decoded = data.decode("utf-8")
            parsed = json.loads(decoded)

            # Extract key info for quick view
            name = parsed.get("name", "?")
            version = parsed.get("version", "?")
            build = parsed.get("build", "?")
            quick_info = f"[bold magenta]{name}[/] v{version} ({build})\n\n"

            formatted = json.dumps(parsed, indent=2, sort_keys=True)
            content = Syntax(formatted, "json", theme="monokai", line_numbers=False)

            self.query_one("#entry-display", Static).update(header + quick_info)
            # Note: Can't easily combine Text and Syntax, so we show header separately
            # For now, show the formatted JSON below the header
            self.query_one("#entry-display", Static).update(
                header + quick_info + formatted
            )
        except (json.JSONDecodeError, UnicodeDecodeError):
            self.query_one("#entry-display", Static).update(
                header + f"[dim]Raw data:[/]\n{data[:500]}"
            )

        self.update_nav_label()

    def format_entries_path(self, bundle_index: int, log_size: int) -> str:
        """Format the path to an entry bundle."""
        full_bundles = log_size // 256
        partial = log_size % 256 if bundle_index >= full_bundles else 0

        if bundle_index < 1000:
            index_str = f"{bundle_index:03d}"
        else:
            parts = []
            n = bundle_index
            while n > 0 or not parts:
                parts.append(f"{n % 1000:03d}")
                n //= 1000
            parts = parts[::-1]
            index_str = "/".join(f"x{p}" if i < len(parts) - 1 else p for i, p in enumerate(parts))

        if partial > 0:
            return f"tile/entries/{index_str}.p/{partial}"
        return f"tile/entries/{index_str}"

    def parse_entry_bundle(self, data: bytes) -> list[bytes]:
        """Parse entry bundle into individual entries."""
        entries = []
        offset = 0
        while offset < len(data):
            if offset + 2 > len(data):
                break
            size = int.from_bytes(data[offset:offset + 2], "big")
            offset += 2
            if offset + size > len(data):
                break
            entries.append(data[offset:offset + size])
            offset += size
        return entries

    def update_nav_label(self):
        # Show current position and index
        self.query_one("#entry-label", Static).update(
            f"[bold]#{self.current_index}[/] ({self.current_index + 1}/{self.checkpoint_size:,})"
        )

    async def on_button_pressed(self, event: Button.Pressed):
        if event.button.id == "btn-prev":
            self.action_prev_entry()
        elif event.button.id == "btn-next":
            self.action_next_entry()
        elif event.button.id == "btn-jump":
            self.do_jump()
        elif event.button.id == "btn-vindex":
            self.do_vindex_lookup()

    def on_input_submitted(self, event: Input.Submitted):
        if event.input.id == "jump-input":
            self.do_jump()
        elif event.input.id == "vindex-input":
            self.do_vindex_lookup()

    def do_jump(self):
        jump_input = self.query_one("#jump-input", Input)
        try:
            index = int(jump_input.value)
            if 0 <= index < self.checkpoint_size:
                self.current_index = index
                self.load_current_entry()
            else:
                self.notify(f"Index must be 0-{self.checkpoint_size - 1}", severity="warning")
        except ValueError:
            self.notify("Invalid index", severity="warning")
        jump_input.value = ""

    @work(exclusive=True, group="vindex")
    async def do_vindex_lookup(self):
        vindex_input = self.query_one("#vindex-input", Input)
        output = self.query_one("#vindex-output", Static)
        key = vindex_input.value.strip()

        if not key:
            output.update("[dim]Enter a package name[/]")
            return

        try:
            url = urljoin(self.base_url, f"vindex/lookup/key/{key}")
            response = await self.client.get(url)

            if response.status_code == 404:
                output.update(f"[yellow]No entries found for '{key}'[/]")
                return

            response.raise_for_status()
            data = response.json()

            text = f"[bold underline]Results for '{key}'[/]\n\n"
            if isinstance(data, list):
                for i, item in enumerate(data[:20]):
                    text += f"[cyan][{i + 1}][/] Index: {item.get('index', '?')}\n"
                    if "value" in item:
                        try:
                            entry = json.loads(item["value"]) if isinstance(item["value"], str) else item["value"]
                            text += f"    Version: {entry.get('version', '?')}, Build: {entry.get('build', '?')}\n"
                        except:
                            pass
                    text += "\n"
            else:
                text += json.dumps(data, indent=2)

            output.update(text)

        except Exception as e:
            output.update(f"[red]Error: {e}[/]")

    def action_prev_entry(self):
        if self.current_index > 0:
            self.current_index -= 1
            self.load_current_entry()

    def action_next_entry(self):
        if self.current_index < self.checkpoint_size - 1:
            self.current_index += 1
            self.load_current_entry()

    def action_refresh(self):
        self.entry_cache.clear()
        self.refresh_checkpoint()
        self.refresh_stats()
        self.notify("Refreshed")

    def action_focus_jump(self):
        self.query_one("#jump-input", Input).focus()


def main():
    parser = argparse.ArgumentParser(description="Tessera Log Explorer TUI")
    parser.add_argument("--url", default="http://localhost:2025", help="Base URL of the Tessera server")
    parser.add_argument("--public-key", "-k", help="Public key for signature verification (format: name+hash+key)")
    args = parser.parse_args()

    app = TesseraExplorer(base_url=args.url, public_key=args.public_key)
    app.run()


if __name__ == "__main__":
    main()
