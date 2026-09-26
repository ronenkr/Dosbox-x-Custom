"""High-level operations an LLM needs: run a DOS command, wait for text, debug."""
from __future__ import annotations

import json
import os
import re
import struct
import time
import zlib
from dataclasses import dataclass
from pathlib import Path

from dosbox_agent import (
    AgentClient,
    AgentError,
    MemoryAddress,
    RawFrame,
    RegisterSnapshot,
    ScreenImage,
    ScreenText,
    SessionNotFoundError,
)

from .instances import HarnessError, Instance, state_root

# "C:\>", "C:\GAMES>", "Z:\>" with nothing typed after it.
PROMPT_RE = re.compile(r"^[A-Z]:\\[^>]*>\s*$")


@dataclass
class CommandResult:
    completed: bool
    screen: ScreenText
    elapsed_s: float


def parse_address(text: str) -> MemoryAddress:
    """'1234:0100' segmented, '0x12345' / '12345h' linear, 'phys:0x...' physical."""
    value = text.strip()
    if value.lower().startswith("phys:"):
        return MemoryAddress.physical(_parse_hex(value[5:]))
    if ":" in value:
        segment, offset = value.split(":", 1)
        return MemoryAddress.segmented(_parse_hex(segment), _parse_hex(offset))
    return MemoryAddress.linear(_parse_hex(value))


def _parse_hex(text: str) -> int:
    value = text.strip().lower()
    if value.endswith("h"):
        value = value[:-1]
    if value.startswith("0x"):
        value = value[2:]
    try:
        return int(value, 16)
    except ValueError as error:
        raise HarnessError(f"'{text}' is not a hexadecimal number") from error


def hex_dump(data: bytes, base: int = 0) -> str:
    lines = []
    for index in range(0, len(data), 16):
        chunk = data[index:index + 16]
        hex_part = " ".join(f"{byte:02X}" for byte in chunk)
        text_part = "".join(chr(byte) if 32 <= byte < 127 else "." for byte in chunk)
        lines.append(f"{base + index:08X}  {hex_part:<47}  {text_part}")
    return "\n".join(lines)


def format_registers(registers: RegisterSnapshot) -> str:
    general = registers.general
    segments = registers.segments
    return (
        f"EAX={general['eax']} EBX={general['ebx']} ECX={general['ecx']} EDX={general['edx']}\n"
        f"ESI={general['esi']} EDI={general['edi']} EBP={general['ebp']} ESP={general['esp']}\n"
        f"CS={segments['cs']} DS={segments['ds']} ES={segments['es']} FS={segments['fs']} "
        f"GS={segments['gs']} SS={segments['ss']}\n"
        f"EIP={registers.instruction_pointer} FLAGS={registers.flags} mode={registers.cpu_mode}"
    )


class Dosbox:
    """One running DOSBox-X instance."""

    def __init__(self, instance: Instance) -> None:
        if not instance.alive():
            raise HarnessError(f"Instance {instance.id} is not running.\n{instance.log_tail()}")
        self.instance = instance
        self.client: AgentClient = instance.client()

    # ---- screen ----

    def screen(self, attributes: bool = False) -> ScreenText:
        return self.client.read_screen(attributes=attributes)

    def screenshot(self) -> ScreenImage:
        return self.client.screenshot()

    def wait_for_text(self, pattern: str, timeout_s: float = 30.0, regex: bool = True,
                      poll_s: float = 0.25) -> tuple[bool, ScreenText]:
        matcher = re.compile(pattern, re.MULTILINE) if regex else None
        deadline = time.monotonic() + timeout_s
        while True:
            screen = self.screen()
            text = screen.text()
            if (matcher.search(text) if matcher else pattern in text):
                return True, screen
            if time.monotonic() >= deadline:
                return False, screen
            time.sleep(poll_s)

    def wait_for_prompt(self, timeout_s: float = 30.0) -> tuple[bool, ScreenText]:
        deadline = time.monotonic() + timeout_s
        while True:
            screen = self.screen()
            if at_prompt(screen):
                return True, screen
            if time.monotonic() >= deadline:
                return False, screen
            time.sleep(0.25)

    # ---- input ----

    def type(self, text: str, pace_ms: int = 40, wait: bool = True) -> None:
        self.client.type_text(text, pace_ms=pace_ms)
        if wait:
            self._drain(len(text) * pace_ms * 3 / 1000 + 10)

    def keys(self, combos: list[str], pace_ms: int = 40, hold_ms: int = 60, wait: bool = True) -> None:
        self.client.keys(combos, pace_ms=pace_ms, hold_ms=hold_ms)
        if wait:
            self._drain(len(combos) * (pace_ms * 4 + hold_ms) / 1000 + 10)

    def _drain(self, timeout_s: float) -> None:
        if not self.client.wait_input_drained(timeout_s):
            status = self.client.machine_status()
            if status.get("debugger_active"):
                raise HarnessError("Keys are queued but the debugger has the CPU stopped; resume first")
            raise HarnessError("Timed out delivering keys to the guest")

    def run_command(self, command: str, timeout_s: float = 30.0) -> CommandResult:
        """Type a command at the DOS prompt, press Enter and wait for the prompt to return."""
        started = time.monotonic()
        ready, screen = self.wait_for_prompt(timeout_s=min(timeout_s, 5.0))
        if not ready:
            raise HarnessError("DOS prompt is not visible; the screen currently shows:\n" + screen.text())
        self.type(command + "\n")
        # Give the command a moment to start so the old prompt is not mistaken for completion.
        time.sleep(0.2)
        remaining = max(0.0, timeout_s - (time.monotonic() - started))
        completed, screen = self.wait_for_prompt(timeout_s=remaining)
        return CommandResult(completed, screen, time.monotonic() - started)

    # ---- debugger ----

    def session(self) -> str:
        """Attach a debugger session on first use and remember it for later calls."""
        if self.instance.session_id:
            try:
                state = self.client.status(self.instance.session_id).state
                if state not in ("exited", "failed"):
                    return self.instance.session_id
            except SessionNotFoundError:
                pass
        self.instance.session_id = self.client.attach().id
        self.instance.last_operation_id = None
        self.instance.save()
        return self.instance.session_id

    def state(self) -> str:
        return self.client.status(self.session()).state

    def pause(self, timeout_s: float = 5.0) -> RegisterSnapshot:
        session_id = self.session()
        if self.client.status(session_id).state != "stopped":
            operation = self.client.pause(session_id)
            result = self.client.wait(session_id, operation.id, int(timeout_s * 1000))
            if result.running:
                raise HarnessError("The CPU did not stop in time")
        return self.client.get_registers(session_id)

    def resume(self, wait_for_break_s: float = 0.0) -> str:
        """Continue execution; optionally wait for a breakpoint. Returns the resulting state."""
        session_id = self.session()
        if self.client.status(session_id).state == "stopped":
            operation = self.client.continue_(session_id)
            self.instance.last_operation_id = operation.id
            self.instance.save()
        if wait_for_break_s > 0:
            return self.wait_for_break(wait_for_break_s)
        return "running"

    def wait_for_break(self, timeout_s: float) -> str:
        session_id = self.session()
        operation_id = self.instance.last_operation_id
        if not operation_id:
            return self.client.status(session_id).state
        result = self.client.wait(session_id, operation_id, int(timeout_s * 1000))
        if result.running:
            return "running"
        stop = result.session.stop_reason
        detail = f" ({stop.kind}{' ' + stop.breakpoint_id if stop and stop.breakpoint_id else ''})" if stop else ""
        return "stopped" + detail

    def step(self, mode: str = "into", count: int = 1) -> RegisterSnapshot:
        session_id = self.session()
        self.pause()
        registers = None
        for _ in range(max(1, count)):
            _, registers = self.client.step(session_id, mode)
        assert registers is not None
        return registers

    def registers(self) -> RegisterSnapshot:
        return self.pause()

    def read_memory(self, address: str, length: int) -> tuple[MemoryAddress, bytes]:
        self.pause()
        parsed = parse_address(address)
        result = self.client.read_memory(self.session(), parsed, length)
        return parsed, result.data

    def write_memory(self, address: str, data: bytes) -> None:
        self.pause()
        self.client.write_memory(self.session(), parse_address(address), data)

    def add_breakpoint(self, address: str, once: bool = False, kind: str = "execution") -> str:
        self.pause()
        return self.client.create_breakpoint(self.session(), kind, parse_address(address), once=once).id

    def breakpoints(self) -> list[str]:
        self.pause()
        return [
            f"{item.id} {item.kind} {_format_address(item.address)}{' once' if item.once else ''}"
            for item in self.client.list_breakpoints(self.session())
        ]

    def delete_breakpoint(self, breakpoint_id: str) -> None:
        self.pause()
        self.client.delete_breakpoint(self.session(), breakpoint_id)

    def debugger_command(self, command: str) -> str:
        self.pause()
        return self.client.execute_command(self.session(), command).raw_output

    def trace(self, count: int = 200, detail: str = "normal", timeout_s: float = 10.0) -> list[str]:
        """Execute `count` instructions under the debugger and return one line per instruction."""
        session_id = self.session()
        self.pause()
        self.client.start_trace(session_id, detail, count)
        operation = self.client.continue_(session_id)
        self.client.wait(session_id, operation.id, int(timeout_s * 1000))
        lines: list[str] = []
        cursor = None
        while True:
            page = self.client.read_trace(session_id, cursor, 1000)
            for event in page.events:
                changes = " ".join(f"{name}={value}" for name, value in event.register_changes.items())
                lines.append(f"{_format_address(event.address)}  {event.instruction}" + (f"  ; {changes}" if changes else ""))
            if not page.next_cursor:
                break
            cursor = page.next_cursor
        return lines

    # ---- memory without stopping the CPU ----

    def peek(self, address: str, length: int) -> tuple[MemoryAddress, bytes]:
        parsed = parse_address(address)
        return parsed, self.client.peek(parsed, length)

    def poke(self, address: str, data: bytes) -> None:
        self.client.poke(parse_address(address), data)

    def watch(self, address: str, length: int, duration_s: float, interval_s: float = 0.05) -> list[tuple[float, bytes]]:
        """Sample memory while the guest runs; returns (seconds, bytes) for the first sample and every change."""
        parsed = parse_address(address)
        started = time.monotonic()
        samples: list[tuple[float, bytes]] = []
        previous = None
        while True:
            elapsed = time.monotonic() - started
            data = self.client.peek(parsed, length)
            if data != previous:
                samples.append((elapsed, data))
                previous = data
            if elapsed >= duration_s:
                return samples
            time.sleep(interval_s)

    # ---- named checkpoints, shared by every instance ----

    def save_checkpoint(self, name: str) -> Path:
        path = checkpoint_path(name)
        self.client.save_state(path=path)
        return path

    def load_checkpoint(self, name: str) -> Path:
        path = checkpoint_path(name)
        if not path.is_file():
            raise HarnessError(f"No checkpoint named '{name}' (have: {', '.join(list_checkpoints()) or 'none'})")
        self.client.load_state(path=path)
        return path

    def hold_key(self, key: str, hold_ms: int) -> None:
        """Keep one key down for hold_ms emulated milliseconds (e.g. for games that poll the keyboard)."""
        self.client.key(key, "press", hold_ms=hold_ms)
        self._drain(hold_ms / 1000 + 10)

    # ---- reverse engineering ----

    def video_info(self) -> dict:
        return self.client.video_info()

    def disassemble(self, address: str | None = None, count: int = 20) -> list[str]:
        if address is None:
            address = self.client.video_info()["cs_ip"]
        parsed = parse_address(address)
        if parsed.space != "segmented":
            raise HarnessError("disassemble needs a SEG:OFF address")
        lines = self.client.disassemble(parsed, count)
        return [f"{line['address']}  {line['bytes']:<20} {line['text']}" for line in lines]

    def stack(self, count: int = 32) -> str:
        self.pause()
        return self.client.stack(count)["text"]

    def set_registers(self, registers: dict[str, int]) -> RegisterSnapshot:
        self.pause()
        self.client.set_registers(registers)
        return self.client.get_registers(self.session())

    def call_function(self, address: str, registers: dict[str, int] | None = None,
                      stack_args: list[int] | None = None, far: bool = True,
                      timeout_s: float = 5.0) -> tuple[bool, RegisterSnapshot, str]:
        """Call a guest function (real/V86 mode) and come back to where the CPU was paused.

        Pushes stack_args (C order: stack_args[0] ends up nearest the return address) and a return
        address, sets registers and CS:IP, runs until the function returns there, captures the
        registers, then restores every register (memory changes made by the function remain).
        Returns (returned, registers_at_return, note).
        """
        target = parse_address(address)
        if target.space != "segmented":
            raise HarnessError("call_function needs a SEG:OFF address")
        original = self.pause()
        if original.cpu_mode not in ("real", "v86"):
            raise HarnessError(f"call_function supports real/V86 mode only (CPU is in {original.cpu_mode} mode)")
        session_id = self.session()
        target_seg, target_off = int(target.segment, 16), int(target.offset, 16)
        orig_cs = int(original.segments["cs"], 16)
        orig_ip = int(original.instruction_pointer, 16) & 0xFFFF
        orig_ss = int(original.segments["ss"], 16)
        orig_sp = int(original.general["esp"], 16) & 0xFFFF
        # A near return lands in the callee's segment, so the return breakpoint goes there.
        ret_cs = orig_cs if far else target_seg
        args = [int(value) & 0xFFFF for value in (stack_args or [])]
        frame = struct.pack("<H", orig_ip) + (struct.pack("<H", ret_cs) if far else b"")
        frame += b"".join(struct.pack("<H", value) for value in args)
        new_sp = (orig_sp - len(frame)) & 0xFFFF
        self.client.write_memory(session_id, MemoryAddress.segmented(orig_ss, new_sp), frame)
        values = dict(registers or {})
        values.update({"esp": new_sp, "cs": target_seg, "eip": target_off})
        self.client.set_registers(values)
        breakpoint_id = self.client.create_breakpoint(
            session_id, "execution", MemoryAddress.segmented(ret_cs, orig_ip)).id
        returned, note = False, ""
        result = original
        deadline = time.monotonic() + timeout_s
        try:
            while time.monotonic() < deadline:
                operation = self.client.continue_(session_id)
                waited = self.client.wait(session_id, operation.id, int(max(0.05, deadline - time.monotonic()) * 1000))
                if waited.running:
                    note = f"did not return within {timeout_s:g}s"
                    self.pause()
                    break
                result = self.client.get_registers(session_id)
                at_return = (int(result.segments["cs"], 16) == ret_cs and
                             int(result.instruction_pointer, 16) & 0xFFFF == orig_ip)
                sp = int(result.general["esp"], 16) & 0xFFFF
                if at_return and sp in ((new_sp + len(frame) - 2 * len(args)) & 0xFFFF, orig_sp):
                    returned = True
                    break
                if not at_return:
                    stop = waited.session.stop_reason
                    note = f"stopped elsewhere ({stop.kind if stop else 'unknown'}) at {result.segments['cs']}:{result.instruction_pointer}"
                    break
                # Same address reached at a different stack depth (recursion): keep going.
        finally:
            try:
                self.client.delete_breakpoint(session_id, breakpoint_id)
            except AgentError:
                pass
            restore = {name: int(value, 16) for name, value in original.general.items()}
            restore.update({name: int(value, 16) for name, value in original.segments.items()})
            restore["eip"] = int(original.instruction_pointer, 16)
            restore["eflags"] = int(original.flags, 16)
            self.client.set_registers(restore)
        return returned, result, note

    def scratch(self) -> dict:
        return self.client.call("memory.scratch", {})

    def inject_code(self, code: bytes, call: bool = True, registers: dict[str, int] | None = None,
                    append_retf: bool = True, timeout_s: float = 5.0):
        """Write machine code into the scratch area and (optionally) far-call it."""
        area = self.scratch()
        if append_retf and not code.endswith(b"\xCB"):
            code += b"\xCB"
        if len(code) > int(area["size"]):
            raise HarnessError(f"Code is {len(code)} bytes; the scratch area holds {area['size']}")
        self.client.poke(MemoryAddress.physical(int(area["physical"], 16)), code)
        if not call:
            return area["address"], None
        return area["address"], self.call_function(area["address"], registers=registers, far=True, timeout_s=timeout_s)

    def calltrace_start(self, trigger: str | None = None, **options) -> dict:
        address = parse_address(trigger) if trigger else None
        return self.client.calltrace_start(trigger=address, **options)

    def detach(self) -> None:
        if self.instance.session_id:
            try:
                self.client.stop(self.instance.session_id)
            except AgentError:
                pass
        self.instance.session_id = None
        self.instance.last_operation_id = None
        self.instance.save()


def _png(width: int, height: int, rgb_rows: list[bytes]) -> bytes:
    def chunk(kind: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)
    raw = b"".join(b"\x00" + row for row in rgb_rows)
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw, 6)) + chunk(b"IEND", b""))


def palette_png(info: dict, cell: int = 24) -> bytes:
    """16x16 swatch grid of the 256 DAC colours (index = row*16 + column). The entries used by
    the 16 attribute colours are framed in white; a strip above shows those 16 colours in order."""
    palette = [int(color, 16) for color in info["palette"]]
    used = set(info["attribute_to_dac"])
    strip = cell + 8
    width, height = 16 * cell, strip + 16 * cell
    rows = []
    for y in range(height):
        row = bytearray()
        for x in range(width):
            if y < strip:
                color = palette[info["attribute_to_dac"][x // cell]] if y < cell else 0x202020
            else:
                gy = y - strip
                index = (gy // cell) * 16 + x // cell
                border = x % cell in (0, cell - 1) or gy % cell in (0, cell - 1)
                color = 0xFFFFFF if border and index in used else (0x202020 if border else palette[index])
            row += bytes(((color >> 16) & 0xFF, (color >> 8) & 0xFF, color & 0xFF))
        rows.append(bytes(row))
    return _png(width, height, rows)


def format_video_info(info: dict) -> str:
    frame = info["frame"]
    lines = [
        f"BIOS mode {info['bios_mode']} ({info['vga_mode']}, {info['machine']}), {info['width']}x{info['height']}"
        + (f", text {info['text_columns']}x{info['text_rows']} char height {info['char_height']}" if info["is_text"] else ""),
        f"frame {frame['width']}x{frame['height']} {frame['bpp']}bpp double_w={frame['double_width']} "
        f"double_h={frame['double_height']} {float(frame['fps']):.2f} Hz",
        f"DAC {info['dac_bits']}-bit, PEL mask {info['pel_mask']}; display start {info['display_start']}, "
        f"line offset {info['scan_len']}, pel panning {info['pel_panning']}, chained={info['chained']}",
        "16 colours -> DAC: " + " ".join(f"{index:X}:{dac:02X}" for index, dac in enumerate(info["attribute_to_dac"])),
        f"attribute registers: {' '.join(f'{value:02X}' for value in info['attribute_palette'])} "
        f"overscan {info['overscan']:02X} color_select {info['color_select']:02X} mode_control {info['mode_control']:02X}",
        "DAC palette (index: RRGGBB):",
    ]
    for base in range(0, 256, 8):
        lines.append("  " + "  ".join(f"{index:02X}:{info['palette'][index]}" for index in range(base, base + 8)))
    return "\n".join(lines)


def write_raw_frame(frame: RawFrame, path: str | os.PathLike[str]) -> tuple[Path, Path]:
    """Write <path>.bin (packed source pixels), <path>.idx (one palette index per pixel, when the
    mode is palettised) and <path>.json (geometry, palette, file names)."""
    base = Path(path)
    base.parent.mkdir(parents=True, exist_ok=True)
    pixels = base.with_suffix(".bin")
    meta = base.with_suffix(".json")
    pixels.write_bytes(frame.pixels)
    index_file = None
    if frame.indices is not None:
        index_file = base.with_suffix(".idx")
        index_file.write_bytes(frame.indices)
    elif frame.bpp == 8:
        index_file = pixels
    meta.write_text(json.dumps({
        "width": frame.width, "height": frame.height, "bpp": frame.bpp,
        "double_width": frame.double_width, "double_height": frame.double_height,
        "video_mode": frame.video_mode, "pixels_file": pixels.name,
        "indices_file": index_file.name if index_file else None,
        "unmatched_pixels": frame.unmatched_pixels,
        "palette": [f"{color:06X}" for color in frame.palette] if frame.palette else None,
    }, indent=1), encoding="utf-8")
    return pixels, meta


def region_indices(frame: RawFrame, x: int, y: int, width: int, height: int) -> str:
    """Grid of pixel values (palette indices in 8 bpp modes) for a source-frame rectangle."""
    if x < 0 or y < 0 or width <= 0 or height <= 0 or x + width > frame.width or y + height > frame.height:
        raise HarnessError(f"Region outside the {frame.width}x{frame.height} frame")
    digits = 2 if frame.indexed else 4 if frame.bpp in (15, 16) else 6
    rows = []
    for row in range(y, y + height):
        values = (frame.index_at(column, row) for column in range(x, x + width))
        rows.append(f"{row:4d}: " + " ".join(f"{value:0{digits}X}" for value in values))
    return "\n".join(rows)


_CHECKPOINT_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


def checkpoint_dir() -> Path:
    configured = os.environ.get("DOSBOX_LLM_CHECKPOINTS")
    directory = Path(configured) if configured else state_root() / "checkpoints"
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def checkpoint_path(name: str) -> Path:
    if not _CHECKPOINT_NAME.match(name):
        raise HarnessError("Checkpoint names may use letters, digits, '.', '_' and '-' (max 64 characters)")
    return checkpoint_dir() / f"{name}.sav"


def list_checkpoints() -> list[str]:
    return sorted(path.stem for path in checkpoint_dir().glob("*.sav"))


def at_prompt(screen: ScreenText) -> bool:
    if not screen.is_text or not screen.lines:
        return False
    row = min(screen.cursor_row, len(screen.lines) - 1)
    return bool(PROMPT_RE.match(screen.lines[row].rstrip()))


def _format_address(address: MemoryAddress) -> str:
    if address.space == "segmented":
        return f"{address.segment}:{address.offset}"
    return f"{address.space}:{address.offset}"
