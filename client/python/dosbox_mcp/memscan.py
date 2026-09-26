"""Cheat-engine style memory scanning for locating game variables.

Snapshots are raw copies of a linear memory range saved in the instance directory, so they
survive between separate `dbx` invocations. Reads use memory.peek, so the guest keeps running.
"""
from __future__ import annotations

import json
import re
import struct
from dataclasses import dataclass
from pathlib import Path

from dosbox_agent import AgentClient, MemoryAddress

from .instances import HarnessError, Instance

CONVENTIONAL = (0x00000, 0xA0000)  # 640 KB
_CHUNK = 0x40000
_SIZES = {"u8": ("<B", 1), "i8": ("<b", 1), "u16": ("<H", 2), "i16": ("<h", 2),
          "u32": ("<I", 4), "i32": ("<i", 4)}
_NAME = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


@dataclass
class Snapshot:
    name: str
    start: int
    data: bytes


def format_linear(address: int) -> str:
    """Linear address plus a normalised real-mode SEG:OFF for convenience."""
    return f"0x{address:05X} ({address >> 4:04X}:{address & 0xF:04X})"


def read_linear(client: AgentClient, start: int, length: int) -> bytes:
    data = bytearray()
    offset = 0
    while offset < length:
        size = min(_CHUNK, length - offset)
        data += client.peek(MemoryAddress.linear(start + offset), size)
        offset += size
    return bytes(data)


def parse_pattern(pattern: str, kind: str) -> bytes:
    """kind: u8/u16/u32/i8/i16/i32 (decimal or 0x value), hex ("B8 00 4C"), or text."""
    if kind in _SIZES:
        fmt, _ = _SIZES[kind]
        value = int(pattern, 0)
        try:
            return struct.pack(fmt, value)
        except struct.error as error:
            raise HarnessError(f"{pattern} does not fit in {kind}") from error
    if kind == "hex":
        return bytes.fromhex(pattern.replace(",", " "))
    if kind == "text":
        return pattern.encode("cp437")
    raise HarnessError("kind must be u8, u16, u32, i8, i16, i32, hex, or text")


class MemoryScanner:
    def __init__(self, instance: Instance, client: AgentClient) -> None:
        self.instance = instance
        self.client = client
        self.directory = instance.path / "snapshots"

    def _path(self, name: str) -> Path:
        if not _NAME.match(name):
            raise HarnessError("Snapshot names may use letters, digits, '.', '_' and '-'")
        return self.directory / name

    def search(self, pattern: str, kind: str = "u16", start: int = CONVENTIONAL[0],
               length: int = CONVENTIONAL[1] - CONVENTIONAL[0], limit: int = 200) -> list[int]:
        needle = parse_pattern(pattern, kind)
        data = read_linear(self.client, start, length)
        hits = []
        position = data.find(needle)
        while position >= 0 and len(hits) < limit:
            hits.append(start + position)
            position = data.find(needle, position + 1)
        return hits

    def snapshot(self, name: str, start: int = CONVENTIONAL[0],
                 length: int = CONVENTIONAL[1] - CONVENTIONAL[0]) -> Snapshot:
        data = read_linear(self.client, start, length)
        self.directory.mkdir(parents=True, exist_ok=True)
        path = self._path(name)
        path.with_suffix(".bin").write_bytes(data)
        path.with_suffix(".json").write_text(json.dumps({"start": start, "length": length}), encoding="utf-8")
        return Snapshot(name, start, data)

    def load(self, name: str) -> Snapshot:
        path = self._path(name)
        if not path.with_suffix(".bin").is_file():
            raise HarnessError(f"No snapshot named '{name}'")
        meta = json.loads(path.with_suffix(".json").read_text(encoding="utf-8"))
        return Snapshot(name, int(meta["start"]), path.with_suffix(".bin").read_bytes())

    def diff(self, before: str, after: str | None = None, mode: str = "changed", kind: str = "u8",
             value: str | None = None, candidates: str | None = None, limit: int = 200
             ) -> tuple[list[tuple[int, int, int]], int]:
        """Compare two snapshots (after=None: compare against live memory now).

        mode: changed, unchanged, increased, decreased, equals (needs value), or
        delta (after - before == value). candidates: name of a previous result set to narrow.
        Returns (matches as (address, old, new), total match count); the full match set is
        stored as '<before>.<after>.cand' so it can narrow the next scan.
        """
        if kind not in _SIZES:
            raise HarnessError("diff kind must be u8, u16, u32, i8, i16, or i32")
        old = self.load(before)
        new = self.load(after) if after else Snapshot("live", old.start, read_linear(self.client, old.start, len(old.data)))
        if new.start != old.start or len(new.data) != len(old.data):
            raise HarnessError("Snapshots cover different ranges")
        fmt, size = _SIZES[kind]
        target = int(value, 0) if value is not None else None
        if mode in ("equals", "delta") and target is None:
            raise HarnessError(f"mode {mode} needs a value")

        offsets = range(0, len(old.data) - size + 1)
        if candidates:
            offsets = [address - old.start for address in self._load_candidates(candidates)]
        matches: list[tuple[int, int, int]] = []
        for offset in offsets:
            a = struct.unpack_from(fmt, old.data, offset)[0]
            b = struct.unpack_from(fmt, new.data, offset)[0]
            if ((mode == "changed" and a != b) or (mode == "unchanged" and a == b)
                    or (mode == "increased" and b > a) or (mode == "decreased" and b < a)
                    or (mode == "equals" and b == target) or (mode == "delta" and b - a == target)):
                matches.append((old.start + offset, a, b))
        stored = f"{before}.{after or 'live'}"
        self._save_candidates(stored, [address for address, _, _ in matches])
        return matches[:limit], len(matches)

    def _save_candidates(self, name: str, addresses: list[int]) -> None:
        self.directory.mkdir(parents=True, exist_ok=True)
        (self.directory / f"{name}.cand").write_text(json.dumps(addresses), encoding="utf-8")

    def _load_candidates(self, name: str) -> list[int]:
        path = self.directory / f"{name}.cand"
        if not path.is_file():
            raise HarnessError(f"No candidate set '{name}' (they are named '<before>.<after>' after a diff)")
        return json.loads(path.read_text(encoding="utf-8"))
