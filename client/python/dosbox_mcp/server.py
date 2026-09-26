"""MCP server that lets Claude drive headless DOSBox-X instances.

Run with `python -m dosbox_mcp` (stdio transport). Every tool takes an optional
instance_id; without it the most recently launched instance is used.
"""
from __future__ import annotations

import atexit
import os
from typing import Any

from mcp.server.mcpserver import Image, MCPServer

from dosbox_agent import AgentError

from . import instances
from .harness import (Dosbox, format_registers, format_video_info, hex_dump, list_checkpoints, palette_png,
                      region_indices, write_raw_frame)
from .instances import HarnessError
from .memscan import MemoryScanner, format_linear

INSTRUCTIONS = """\
Controls DOSBox-X (a DOS PC emulator) running headless in the background.
Typical loop: dosbox_launch (optionally mounting a host folder as C:) -> run_dos_command /
type_text / press_keys -> read_screen (text modes, cheap) or screenshot (graphics, games) ->
repeat. Everything goes to the emulated machine directly; no window focus is needed.
Debugging: debug_pause stops the CPU and shows registers; then debug_step, debug_read_memory,
debug_breakpoint_add, debug_command (raw DOSBox-X debugger commands), and debug_resume.
Keyboard and mouse input only reach the guest while it runs (not while paused).
Use checkpoint_save/checkpoint_load before risky actions.
Reverse engineering: doslog_* (file reads with offsets/buffers), calltrace_* (call tree and
function discovery from any point), debug_stack (call chain), disassemble, video_info/palette,
memory_search/snapshot/diff (locate variables), memory_watch, call_function/inject_code (run the
program's own routines or your code with chosen inputs). See docs/llm-harness.md.
"""

server = MCPServer("dosbox-x", instructions=INSTRUCTIONS)
_launched: list[instances.Instance] = []


def _box(instance_id: str | None) -> Dosbox:
    return Dosbox(instances.get_instance(instance_id))


def _screen_text(box: Dosbox) -> str:
    screen = box.screen()
    if not screen.is_text:
        return f"(graphics mode {screen.video_mode}; use screenshot to see it)"
    cursor = f"cursor at row {screen.cursor_row}, column {screen.cursor_column}"
    return f"[text mode {screen.video_mode}, {screen.columns}x{screen.rows}, {cursor}]\n{screen.text()}"


def _guard(action):
    try:
        return action()
    except (HarnessError, AgentError, ValueError) as error:
        return f"ERROR: {error}"


@server.tool()
def dosbox_launch(mount_dir: str | None = None, program: str | None = None, conf: str | None = None,
                  show: bool = False, cycles: str | None = None, checkpoint: str | None = None,
                  inspector: bool = False) -> str:
    """Start a new DOSBox-X instance (headless unless show=True).

    mount_dir: host folder mounted as C: (and made current). program: DOS command run at startup.
    conf: optional dosbox-x.conf. cycles: e.g. "max", "auto", "20000".
    checkpoint: restore this named checkpoint right after boot (use the same mount/conf as when saved).
    inspector: with show=True, also open the live palette / video-mode window for the human watching.
    Returns the instance id and the first screen.
    """
    def run() -> str:
        instance = instances.launch(mount_dir=mount_dir, program=program, conf=conf, show=show, cycles=cycles,
                                    inspector=inspector)
        _launched.append(instance)
        box = Dosbox(instance)
        if program is None:
            box.wait_for_prompt(timeout_s=20)
        if checkpoint:
            box.load_checkpoint(checkpoint)
        return f"instance_id={instance.id}\n{_screen_text(box)}"
    return _guard(run)


@server.tool()
def dosbox_list() -> str:
    """List running DOSBox-X instances."""
    live = instances.list_instances()
    if not live:
        return "No instances are running."
    return "\n".join(
        f"{item.id} pid={item.pid} mount={item.mount_dir or '-'} show={item.show}"
        f"{' session=' + item.session_id if item.session_id else ''}" for item in live
    )


@server.tool()
def dosbox_shutdown(instance_id: str | None = None) -> str:
    """Quit a DOSBox-X instance."""
    def run() -> str:
        instance = instances.get_instance(instance_id)
        instances.stop(instance)
        return f"Stopped {instance.id}."
    return _guard(run)


@server.tool()
def read_screen(instance_id: str | None = None, force_graphics: bool = False) -> str:
    """Read the DOS text screen as text (80x25 etc). Cheap; prefer it over screenshot in text modes.

    force_graphics=True tries to recognise BIOS-font characters even in graphics modes.
    """
    def run() -> str:
        box = _box(instance_id)
        if force_graphics:
            screen = box.client.read_screen(force=True)
            return f"[mode {screen.video_mode}, recognised text]\n{screen.text()}"
        return _screen_text(box)
    return _guard(run)


@server.tool(structured_output=False)
def screenshot(instance_id: str | None = None) -> Any:
    """Capture the emulated display as a PNG image (works in any video mode, also while paused)."""
    def run() -> Any:
        image = _box(instance_id).screenshot()
        return [Image(data=image.png, format="png"), f"{image.width}x{image.height}, video mode {image.video_mode}"]
    return _guard(run)


@server.tool()
def type_text(text: str, instance_id: str | None = None, press_enter: bool = False, pace_ms: int = 40) -> str:
    """Type text on the emulated US keyboard ("\\n" = Enter). Waits until it has been delivered."""
    def run() -> str:
        box = _box(instance_id)
        box.type(text + ("\n" if press_enter else ""), pace_ms=pace_ms)
        return "Typed."
    return _guard(run)


@server.tool()
def press_keys(keys: list[str], instance_id: str | None = None, hold_ms: int = 60, pace_ms: int = 40) -> str:
    """Press keys or combos in order, e.g. ["esc"], ["alt+x"], ["up","up","enter"], ["ctrl+alt+del"].

    Names: a-z 0-9 f1-f12 enter esc tab space backspace up down left right home end pageup pagedown
    insert delete shift ctrl alt lshift rshift lctrl rctrl lalt ralt kp_0..kp_9 kp_enter minus equals
    lbracket rbracket semicolon quote comma period slash backslash grave capslock numlock.
    """
    def run() -> str:
        _box(instance_id).keys(keys, pace_ms=pace_ms, hold_ms=hold_ms)
        return f"Pressed {', '.join(keys)}."
    return _guard(run)


@server.tool()
def run_dos_command(command: str, instance_id: str | None = None, timeout_s: float = 30.0) -> str:
    """Type a command at the DOS prompt, press Enter and wait for the prompt to come back.

    Returns the resulting screen. If the program is interactive or full-screen, completed=false
    and you should continue with read_screen/screenshot and keys.
    """
    def run() -> str:
        box = _box(instance_id)
        result = box.run_command(command, timeout_s=timeout_s)
        return f"completed={str(result.completed).lower()} ({result.elapsed_s:.1f}s)\n{_screen_text(box)}"
    return _guard(run)


@server.tool()
def wait_for_text(pattern: str, instance_id: str | None = None, timeout_s: float = 30.0, regex: bool = True) -> str:
    """Wait until the text screen matches pattern (regex by default). Returns found=true/false and the screen."""
    def run() -> str:
        box = _box(instance_id)
        found, _ = box.wait_for_text(pattern, timeout_s=timeout_s, regex=regex)
        return f"found={str(found).lower()}\n{_screen_text(box)}"
    return _guard(run)


@server.tool()
def mouse(instance_id: str | None = None, x: float | None = None, y: float | None = None,
          dx: float | None = None, dy: float | None = None, button: str | None = None,
          action: str = "click", wheel: int = 0) -> str:
    """Mouse input. x,y are 0..1 fractions of the screen (absolute move); dx,dy relative pixels.
    button: left/right/middle with action click/press/release; wheel: scroll steps."""
    def run() -> str:
        _box(instance_id).client.mouse(x=x, y=y, dx=dx, dy=dy, button=button, action=action, wheel=wheel)
        return "Mouse input sent."
    return _guard(run)


@server.tool()
def status(instance_id: str | None = None) -> str:
    """Machine status: video mode, emulated time, cycles, whether the debugger has the CPU stopped."""
    def run() -> str:
        values = _box(instance_id).client.machine_status()
        return "\n".join(f"{key}: {value}" for key, value in sorted(values.items()))
    return _guard(run)


@server.tool()
def set_speed(cycles: str | None = None, turbo: bool | None = None, instance_id: str | None = None) -> str:
    """Change CPU speed: cycles "max", "auto", or a number like "20000"; turbo fast-forwards."""
    def run() -> str:
        _box(instance_id).client.set_speed(cycles=cycles, turbo=turbo)
        return "Speed updated."
    return _guard(run)


@server.tool()
def checkpoint_save(name: str, instance_id: str | None = None) -> str:
    """Save the whole machine state as a named checkpoint (shared by all instances; overwrites)."""
    return _guard(lambda: f"Saved checkpoint '{name}' to {_box(instance_id).save_checkpoint(name)}.")


@server.tool()
def checkpoint_load(name: str, instance_id: str | None = None) -> str:
    """Restore a named checkpoint. Instances must use the same machine config as when it was saved."""
    def run() -> str:
        box = _box(instance_id)
        box.load_checkpoint(name)
        return f"Loaded checkpoint '{name}'.\n{_screen_text(box)}"
    return _guard(run)


@server.tool()
def checkpoint_list() -> str:
    """List saved checkpoints."""
    return ", ".join(list_checkpoints()) or "No checkpoints yet."


@server.tool()
def hold_key(key: str, hold_ms: int = 500, instance_id: str | None = None) -> str:
    """Hold one key down for hold_ms emulated milliseconds, then release it (for games that poll keys)."""
    return _guard(lambda: (_box(instance_id).hold_key(key, hold_ms), f"Held {key} for {hold_ms} ms.")[1])


@server.tool()
def memory_peek(address: str, length: int = 64, instance_id: str | None = None) -> str:
    """Read guest memory WITHOUT pausing (the game keeps running). address: "SEG:OFF", linear "0x...",
    or "phys:0x..."."""
    def run() -> str:
        parsed, data = _box(instance_id).peek(address, length)
        return hex_dump(data, int(parsed.offset, 16))
    return _guard(run)


@server.tool()
def memory_poke(address: str, hex_bytes: str, instance_id: str | None = None) -> str:
    """Write bytes (hex like "01 FF") to guest memory WITHOUT pausing."""
    def run() -> str:
        data = bytes.fromhex(hex_bytes.replace(",", " "))
        _box(instance_id).poke(address, data)
        return f"Wrote {len(data)} bytes at {address}."
    return _guard(run)


@server.tool()
def memory_watch(address: str, length: int = 16, duration_s: float = 5.0, interval_s: float = 0.05,
                 instance_id: str | None = None) -> str:
    """Sample memory while the guest runs and report every change (time offset + hex)."""
    def run() -> str:
        samples = _box(instance_id).watch(address, length, duration_s, interval_s)
        lines = [f"+{elapsed:6.2f}s  {data.hex(' ').upper()}" for elapsed, data in samples]
        return f"{len(samples) - 1} change(s) in {duration_s:.1f}s\n" + "\n".join(lines)
    return _guard(run)


@server.tool()
def screen_pixels(x: int, y: int, width: int = 16, height: int = 8, instance_id: str | None = None) -> str:
    """Exact pixel values of a rectangle of the unscaled frame (palette indices in 256/16-colour
    modes, plus the RGB of each index used). Coordinates are in source-frame pixels."""
    def run() -> str:
        frame = _box(instance_id).client.screenshot_raw()
        if width * height > 4096:
            raise HarnessError("Region too large (max 4096 pixels); use screenshot_raw to dump the frame")
        grid = region_indices(frame, x, y, width, height)
        header = f"frame {frame.width}x{frame.height} {frame.bpp}bpp mode {frame.video_mode}"
        if frame.indices is not None:
            header += f" (palette indices recovered from the VGA DAC; {frame.unmatched_pixels} unmatched pixels)"
        if frame.palette and frame.indexed:
            used = sorted({frame.index_at(cx, cy) for cy in range(y, y + height) for cx in range(x, x + width)})
            header += "\npalette: " + " ".join(f"{index:02X}=#{frame.palette[index]:06X}" for index in used)
        return f"{header}\n{grid}"
    return _guard(run)


@server.tool()
def screenshot_raw(path: str, instance_id: str | None = None) -> str:
    """Dump the unscaled frame to <path>.bin (packed pixels / palette indices) and <path>.json
    (width, height, bpp, doubling flags, 256-entry palette). For precise measurement."""
    def run() -> str:
        frame = _box(instance_id).client.screenshot_raw()
        pixels, meta = write_raw_frame(frame, path)
        return f"Wrote {pixels} and {meta} ({frame.width}x{frame.height}, {frame.bpp} bpp, mode {frame.video_mode})."
    return _guard(run)


def _scanner(instance_id: str | None) -> MemoryScanner:
    box = _box(instance_id)
    return MemoryScanner(box.instance, box.client)


def _parse_int(value: str | int) -> int:
    return value if isinstance(value, int) else int(value.lower().rstrip("h"), 16 if value.lower().endswith("h") else 0)


@server.tool()
def memory_search(pattern: str, kind: str = "u16", start: str = "0x0", length: str = "0xA0000",
                  instance_id: str | None = None) -> str:
    """Find a value or byte pattern in guest memory (default: all 640 KB conventional memory).
    kind: u8/u16/u32/i8/i16/i32 (pattern is a number like "1234" or "0x4D2"), hex ("B8 00 4C"),
    or text (CP437 string). Returns linear addresses with their real-mode SEG:OFF."""
    def run() -> str:
        hits = _scanner(instance_id).search(pattern, kind, _parse_int(start), _parse_int(length))
        return f"{len(hits)} hit(s)\n" + "\n".join(format_linear(address) for address in hits)
    return _guard(run)


@server.tool()
def memory_snapshot(name: str, start: str = "0x0", length: str = "0xA0000", instance_id: str | None = None) -> str:
    """Save a copy of a memory range (default: 640 KB conventional) for later memory_diff."""
    def run() -> str:
        snapshot = _scanner(instance_id).snapshot(name, _parse_int(start), _parse_int(length))
        return f"Snapshot '{name}': {len(snapshot.data)} bytes from {format_linear(snapshot.start)}."
    return _guard(run)


@server.tool()
def memory_diff(before: str, after: str | None = None, mode: str = "changed", kind: str = "u8",
                value: str | None = None, candidates: str | None = None, instance_id: str | None = None) -> str:
    """Compare snapshot `before` with snapshot `after` (or live memory if omitted) to locate variables.
    mode: changed, unchanged, increased, decreased, equals (value), delta (after-before == value).
    candidates: narrow to the matches of a previous diff, named '<before>.<after>' (or '<before>.live').
    Typical loop: snapshot a -> change the value in game -> diff a (mode=changed) -> repeat with
    candidates=... until one address remains."""
    def run() -> str:
        matches, total = _scanner(instance_id).diff(before, after, mode, kind, value, candidates)
        stored = f"{before}.{after or 'live'}"
        lines = [f"{format_linear(address)}  {old:#x} -> {new:#x}" for address, old, new in matches]
        more = f" (showing {len(matches)})" if total > len(matches) else ""
        return f"{total} match(es){more}; candidate set '{stored}'\n" + "\n".join(lines)
    return _guard(run)


@server.tool()
def video_info(instance_id: str | None = None) -> str:
    """Current video mode (BIOS mode, drawing mode, resolution, frame format), VGA registers that
    matter for rendering (display start, line offset, panning), the 16-colour attribute -> DAC
    mapping and all 256 DAC palette entries."""
    return _guard(lambda: format_video_info(_box(instance_id).video_info()))


@server.tool(structured_output=False)
def palette(instance_id: str | None = None) -> Any:
    """Image of the current palette: top strip = the 16 attribute colours in order, grid = the 256
    DAC entries (index = row*16 + column, entries used by the 16 colours framed in white)."""
    def run() -> Any:
        info = _box(instance_id).video_info()
        return [Image(data=palette_png(info), format="png"), format_video_info(info)]
    return _guard(run)


@server.tool()
def disassemble(address: str | None = None, count: int = 20, instance_id: str | None = None) -> str:
    """Disassemble `count` instructions at "SEG:OFF" (default: current CS:IP). Does not pause."""
    return _guard(lambda: "\n".join(_box(instance_id).disassemble(address, count)))


@server.tool()
def debug_stack(count: int = 32, instance_id: str | None = None) -> str:
    """Pause and show the full stack: SS:SP words plus the reconstructed call chain (return
    addresses verified against the CALL instruction before them, with call targets)."""
    return _guard(lambda: _box(instance_id).stack(count))


@server.tool()
def debug_set_registers(registers: dict[str, str], instance_id: str | None = None) -> str:
    """Set CPU registers while paused, e.g. {"eax": "0x1234", "eip": "0x100", "cs": "0x1814"}
    (segment registers only in real/V86 mode)."""
    def run() -> str:
        values = {name: int(str(value), 0) for name, value in registers.items()}
        return format_registers(_box(instance_id).set_registers(values))
    return _guard(run)


@server.tool()
def call_function(address: str, registers: dict[str, str] | None = None, stack_args: list[str] | None = None,
                  far: bool = True, timeout_s: float = 5.0, instance_id: str | None = None) -> str:
    """Call a guest function (real/V86 mode) as if the program did it, and return its registers.
    address: "SEG:OFF". registers: inputs like {"ax": "0x10"}. stack_args: words pushed C-style
    (first argument nearest the return address). far: RETF function (False for near/RET).
    Everything is restored afterwards except memory the function changed - use it to probe a
    game's own routines (RNG, formulas, decoders) with chosen inputs."""
    def run() -> str:
        values = {name: int(str(value), 0) for name, value in (registers or {}).items()}
        args = [int(str(value), 0) for value in (stack_args or [])]
        returned, result, note = _box(instance_id).call_function(address, values, args, far, timeout_s)
        status = "returned" if returned else f"did NOT return: {note}"
        return f"{status}\nregisters at return:\n{format_registers(result)}\n(CPU state restored; still paused)"
    return _guard(run)


@server.tool()
def inject_code(hex_bytes: str, call: bool = True, registers: dict[str, str] | None = None,
                append_retf: bool = True, timeout_s: float = 5.0, instance_id: str | None = None) -> str:
    """Write 16-bit machine code (hex, e.g. "B8 34 12 CD 21") into a private scratch area and
    far-call it (a RETF is appended unless present). Returns the result registers; CPU state is
    restored afterwards. The scratch area lives in ROM space: the code can't write into itself."""
    def run() -> str:
        code = bytes.fromhex(hex_bytes.replace(",", " "))
        values = {name: int(str(value), 0) for name, value in (registers or {}).items()}
        address, outcome = _box(instance_id).inject_code(code, call, values, append_retf, timeout_s)
        if outcome is None:
            return f"Code written at {address} ({len(code)} bytes)."
        returned, result, note = outcome
        status = "returned" if returned else f"did NOT return: {note}"
        return f"code at {address}: {status}\n{format_registers(result)}"
    return _guard(run)


@server.tool()
def calltrace_start(trigger: str | None = None, max_events: int = 100000, include_interrupts: bool = True,
                    include_irq: bool = False, stop_on_return: bool | None = None, break_on_end: bool = False,
                    instance_id: str | None = None) -> str:
    """Record every CALL/RET (and INT) from now, or from when execution reaches `trigger`
    ("SEG:OFF", e.g. a function entry). stop_on_return (default: True with a trigger) ends the
    trace when that function returns; break_on_end then stops in the debugger. Hardware interrupt
    handlers are excluded unless include_irq. Read with calltrace_read / calltrace_stop."""
    def run() -> str:
        options = {"max_events": max_events, "include_interrupts": include_interrupts, "include_irq": include_irq,
                   "stop_on_return": trigger is not None if stop_on_return is None else stop_on_return,
                   "break_on_end": break_on_end}
        status = _box(instance_id).calltrace_start(trigger, **options)
        return f"call trace {status['state']}" + (f" (waiting for {trigger})" if status["state"] == "armed" else "")
    return _guard(run)


def _calltrace_text(result: dict, show_functions: bool) -> str:
    lines = [f"state={result['state']} {result['end_reason']} events={result['events']} "
             f"functions={result['function_count']} next_cursor={result['next_cursor']}"]
    lines += [event["text"] for event in result["event_list"]]
    if show_functions and result.get("functions"):
        lines.append("functions (address calls callers min_depth):")
        for item in sorted(result["functions"], key=lambda f: f["first_seq"]):
            lines.append(f"  {item['address']}  {item['calls']}  {item['callers']}  {item['min_depth']}")
    return "\n".join(lines)


@server.tool()
def calltrace_read(cursor: int = 0, limit: int = 300, instance_id: str | None = None) -> str:
    """Read call-trace events after `cursor` as an indented call tree (depth = indentation)."""
    return _guard(lambda: _calltrace_text(_box(instance_id).client.calltrace_read(cursor, limit), False))


@server.tool()
def calltrace_stop(limit: int = 300, instance_id: str | None = None) -> str:
    """Stop tracing; returns the first events plus every function discovered (entry address,
    call count, distinct callers, shallowest depth)."""
    def run() -> str:
        client = _box(instance_id).client
        client.calltrace_stop()
        return _calltrace_text(client.call("calltrace.read", {"cursor": 0, "limit": limit, "functions": True}), True)
    return _guard(run)


@server.tool()
def doslog_start(instance_id: str | None = None) -> str:
    """Start logging INT 21h (DOS API) calls: file opens, reads with file position + destination
    buffer, seeks, memory allocation, vectors, exec... Great for finding how data files are used."""
    return _guard(lambda: (_box(instance_id).client.doslog_start(), "DOS log recording.")[1])


@server.tool()
def doslog_read(cursor: int = 0, limit: int = 300, instance_id: str | None = None) -> str:
    """Read DOS log entries after `cursor` (caller CS:IP, function, details)."""
    def run() -> str:
        result = _box(instance_id).client.doslog_read(cursor, limit)
        lines = [f"recording={result['recording']} next_cursor={result['next_cursor']}"]
        return "\n".join(lines + [event["text"] for event in result["event_list"]])
    return _guard(run)


@server.tool()
def doslog_stop(instance_id: str | None = None) -> str:
    """Stop the DOS log (entries stay readable)."""
    return _guard(lambda: (_box(instance_id).client.doslog_stop(), "DOS log stopped.")[1])


@server.tool()
def cpu_trace(count: int = 200, detail: str = "normal", instance_id: str | None = None) -> str:
    """Execute `count` instructions under the debugger and list them (detail: short, normal, long,
    csip). Output grows fast; keep count small. Leaves the CPU paused afterwards."""
    return _guard(lambda: "\n".join(_box(instance_id).trace(count=count, detail=detail)) or "(no events)")


@server.tool()
def mapper_event(event: str, instance_id: str | None = None) -> str:
    """Trigger a DOSBox-X mapper action by name, e.g. hand_swapimg (next disk), hand_capture, hand_shutdown."""
    return _guard(lambda: (_box(instance_id).client.trigger_mapper(event), f"Triggered {event}.")[1])


# ---- debugger ----

@server.tool()
def debug_pause(instance_id: str | None = None) -> str:
    """Stop the emulated CPU in the debugger and show the registers."""
    return _guard(lambda: format_registers(_box(instance_id).pause()))


@server.tool()
def debug_resume(instance_id: str | None = None, wait_for_break_s: float = 0.0) -> str:
    """Resume execution. With wait_for_break_s > 0, wait that long for a breakpoint to hit."""
    return _guard(lambda: _box(instance_id).resume(wait_for_break_s=wait_for_break_s))


@server.tool()
def debug_step(instance_id: str | None = None, mode: str = "into", count: int = 1) -> str:
    """Single-step instructions (mode "into" or "over") and show the registers."""
    return _guard(lambda: format_registers(_box(instance_id).step(mode=mode, count=count)))


@server.tool()
def debug_registers(instance_id: str | None = None) -> str:
    """Show CPU registers (pauses the CPU if it is running)."""
    return _guard(lambda: format_registers(_box(instance_id).registers()))


@server.tool()
def debug_read_memory(address: str, length: int = 128, instance_id: str | None = None) -> str:
    """Hex dump of guest memory. address: "SEG:OFF" (e.g. "B800:0000"), linear "0x12345", or "phys:0x...".
    Pauses the CPU."""
    def run() -> str:
        parsed, data = _box(instance_id).read_memory(address, length)
        return f"{address} ({len(data)} bytes)\n{hex_dump(data, int(parsed.offset, 16))}"
    return _guard(run)


@server.tool()
def debug_write_memory(address: str, hex_bytes: str, instance_id: str | None = None) -> str:
    """Write bytes (hex string like "90 90 EB FE") to guest memory. Pauses the CPU."""
    def run() -> str:
        data = bytes.fromhex(hex_bytes.replace(",", " "))
        _box(instance_id).write_memory(address, data)
        return f"Wrote {len(data)} bytes at {address}."
    return _guard(run)


@server.tool()
def debug_breakpoint_add(address: str, instance_id: str | None = None, once: bool = False,
                         kind: str = "execution") -> str:
    """Add a breakpoint at "SEG:OFF" or a linear address. kind: execution or memory_change."""
    return _guard(lambda: f"Added {_box(instance_id).add_breakpoint(address, once=once, kind=kind)}.")


@server.tool()
def debug_breakpoint_list(instance_id: str | None = None) -> str:
    """List breakpoints of the debug session."""
    return _guard(lambda: "\n".join(_box(instance_id).breakpoints()) or "No breakpoints.")


@server.tool()
def debug_breakpoint_delete(breakpoint_id: str, instance_id: str | None = None) -> str:
    """Delete a breakpoint by id (e.g. bp-1)."""
    return _guard(lambda: (_box(instance_id).delete_breakpoint(breakpoint_id), f"Deleted {breakpoint_id}.")[1])


@server.tool()
def debug_command(command: str, instance_id: str | None = None) -> str:
    """Run a raw DOSBox-X debugger command and return its message output (e.g. "CPU", "BPLIST",
    "INTVEC", "DOS MCBS", "SR EAX 1234", "EV AX"). Pauses the CPU."""
    return _guard(lambda: _box(instance_id).debugger_command(command) or "(no output)")


@server.tool()
def debug_detach(instance_id: str | None = None) -> str:
    """End the debug session: removes its breakpoints and lets the program keep running."""
    return _guard(lambda: (_box(instance_id).detach(), "Detached.")[1])


def _shutdown_launched() -> None:
    if os.environ.get("DOSBOX_MCP_KEEP_INSTANCES"):
        return
    for instance in _launched:
        try:
            instances.stop(instance, graceful=False)
        except Exception:
            pass


def main() -> None:
    atexit.register(_shutdown_launched)
    server.run("stdio")


if __name__ == "__main__":
    main()
