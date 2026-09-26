# DOSBox-X LLM harness

DOSBox-X built so an LLM agent (Claude Code: Opus, Fable, Sonnet) can run DOS software in the
background and control all of it programmatically. Nothing needs window focus or a physical
keyboard: keys, mouse, screen, debugger and save states all go through a local named pipe.

Three layers, use whichever fits:

| Layer | Use it for | Entry point |
|---|---|---|
| MCP server `dosbox` | Claude Code tools (screenshots come back as images) | `.mcp.json` → `python -m dosbox_mcp` |
| CLI `dbx` | Bash / scripts / experiments run N times | `.venv\Scripts\dbx.exe` |
| Python `dosbox_mcp.Dosbox` / `dosbox_agent.AgentClient` | your own tooling | `client/python` |

All three share the instance registry in `%LOCALAPPDATA%\dosbox-llm` (override with
`DOSBOX_LLM_HOME`), so an instance launched with `dbx` can be driven from MCP and vice versa.

## Build and install

```powershell
.\build.ps1                                   # VS 2022 Build Tools, "Agent Release SDL2|x64"
python -m venv .venv
.venv\Scripts\pip install -e client\python    # dosbox_agent + dosbox_mcp, provides dbx
```

Output: `bin\x64\Agent Release SDL2\dosbox-x.exe` (optimised, debugger + heavy debug + agent).
The harness finds it automatically; set `DOSBOX_X_EXE` to use another build. For Claude Code, copy
`.mcp.json.example` to `.mcp.json` in the repo root and put in your paths (the file is
machine-specific and git-ignored); Claude Code then picks up the `dosbox` server (check with `/mcp`).

## How an agent should work with it

1. `dosbox_launch(mount_dir="D:\\path\\to\\game")`: boots headless in about a second. The folder
   becomes `C:` and the current drive.
2. At the prompt: `run_dos_command("DIR")` types the command, waits for the prompt to come back,
   and returns the screen as text.
3. Inside programs: `press_keys([...])`, `type_text(...)`, `hold_key(...)`, `mouse(...)`, then
   look with `read_screen` (text modes, cheap) or `screenshot` (graphics, returned as a PNG image).
4. Checkpoint before anything risky or slow to reach: `checkpoint_save("at-title")`, and later
   `checkpoint_load` or `dosbox_launch(..., checkpoint="at-title")`. Checkpoints are files shared by
   all instances. Load them with the same mount/config they were saved with.
5. `dosbox_shutdown()` when done. The MCP server also kills its instances when it exits (set
   `DOSBOX_MCP_KEEP_INSTANCES=1` to keep them).

Speed: the default config runs 3000 cycles (a slow 286). Use `set_speed(cycles="max")` or
`dosbox_launch(cycles="max")` for speed, `set_speed(turbo=True)` to fast-forward, and fixed
cycles (e.g. `"20000"`) for reproducible timing.

## Tool reference (MCP)

Every tool takes an optional `instance_id`; the default is the most recently launched instance.

| Tool | What it does |
|---|---|
| `dosbox_launch(mount_dir?, program?, conf?, show?, cycles?, checkpoint?)` | start an instance (headless unless `show=true`) |
| `dosbox_list()` / `dosbox_shutdown()` | list / quit instances |
| `run_dos_command(command, timeout_s)` | type at the prompt, wait for the prompt, return the screen; `completed=false` if a program took over |
| `read_screen(force_graphics?)` | text screen with mode and cursor; `force_graphics` recognises BIOS-font text in graphics modes |
| `screenshot()` | PNG of the emulated display (any mode; also works while paused) |
| `screen_pixels(x, y, width, height)` | exact pixel values of a region, with palette RGB in 8 bpp modes |
| `screenshot_raw(path)` | `<path>.bin` pixels, `<path>.idx` palette indices, `<path>.json` palette + geometry |
| `wait_for_text(pattern, timeout_s, regex?)` | poll the text screen until the pattern appears |
| `type_text(text, press_enter?, pace_ms?)` | US-keyboard typing; `\n` = Enter |
| `press_keys(keys, hold_ms?, pace_ms?)` | `["esc"]`, `["alt+x"]`, `["up","up","enter"]`, `["ctrl+alt+del"]` |
| `hold_key(key, hold_ms)` | hold one key down for an exact (emulated) duration |
| `mouse(x?, y?, dx?, dy?, button?, action?, wheel?)` | x,y in 0..1 of the screen; dx,dy relative |
| `status()` / `set_speed(cycles?, turbo?)` | video mode, emulated ms, cycles, debugger state / speed |
| `checkpoint_save(name)` / `checkpoint_load(name)` / `checkpoint_list()` | whole-machine save states |
| `memory_peek(address, length)` / `memory_poke(address, hex_bytes)` | read/write memory while the program keeps running |
| `memory_watch(address, length, duration_s, interval_s)` | log every change of a memory range over time |
| `debug_pause()` / `debug_resume(wait_for_break_s?)` | stop the CPU (shows registers) / continue |
| `debug_step(mode, count)` / `debug_registers()` | single-step into/over / registers |
| `debug_read_memory` / `debug_write_memory` | memory access with the CPU stopped |
| `debug_breakpoint_add(address, once?, kind?)` / `_list` / `_delete` | execution or memory-change breakpoints |
| `debug_command(command)` | raw DOSBox-X debugger command, e.g. `BPLIST`, `INTVEC`, `DOS MCBS`, `SR EAX 1234` |
| `cpu_trace(count, detail)` | run `count` instructions and list them with register changes |
| `debug_detach()` | remove breakpoints and let the program run free |
| `mapper_event(event)` | any mapper action, e.g. `hand_swapimg` (next disk image) |

### Reverse-engineering tools (MCP)

| Tool | What it does |
|---|---|
| `video_info()` | BIOS mode, drawing mode, resolution, frame format, display start / line offset / panning, the 16-colour attribute → DAC map and all 256 DAC entries |
| `palette()` | image of the palette (top strip: the 16 attribute colours; grid: 256 DAC entries, in-use ones framed) plus the text listing |
| `disassemble(address?, count)` | disassembly at `SEG:OFF` (default current CS:IP), without pausing |
| `debug_stack(count)` | pause, dump SS:SP, and reconstruct the call chain; every return address is checked against the CALL before it, and direct call targets are shown |
| `calltrace_start(trigger?, max_events, include_interrupts, include_irq, stop_on_return, break_on_end)` | record every CALL/RET/INT from now, or from when execution reaches `trigger` (a function entry), optionally until that function returns |
| `calltrace_read(cursor, limit)` / `calltrace_stop()` | the call tree (indented by depth, registers at each call/return) / every function discovered, with call counts and distinct callers |
| `doslog_start()` / `doslog_read()` / `doslog_stop()` | INT 21h log: opens, reads with file offset + destination buffer, seeks, exec, memory, vectors, date/time, each with the caller's CS:IP |
| `memory_search(pattern, kind)` | find a u8/u16/u32/i8/i16/i32 value, a hex byte string or text anywhere in 640 KB |
| `memory_snapshot(name)` / `memory_diff(before, after?, mode, kind, value?, candidates?)` | cheat-engine style: snapshot, change something in the game, diff (changed/unchanged/increased/decreased/equals/delta), narrow with `candidates` |
| `debug_set_registers(registers)` | write registers while paused |
| `call_function(address, registers?, stack_args?, far?)` | call one of the program's own functions with chosen inputs and get its result registers; CPU state is restored afterwards |
| `inject_code(hex_bytes, call?, registers?)` | write machine code into a private scratch area (in ROM space, 4 KB) and far-call it |

The same features in the curses debugger (for a human using `show=true`):

| Debugger command | |
|---|---|
| `STACK [n]` | stack dump plus reconstructed call chain |
| `CALLTRACE ON [seg:off]` | trace calls from here (or from `seg:off`) until that function returns, then stop in the debugger |
| `CALLTRACE ALL [seg:off]` / `OFF` / `SHOW [n]` / `FUNCS` / `STATUS` | trace everything / stop / last n events / discovered functions |
| `DOSLOG ON` / `OFF` / `SHOW [n]` | the INT 21h log |

**Inspector window**: `dosbox_launch(show=true, inspector=true)`, `dbx launch --show --inspector`
(CLI flag `-inspector`), or Debug menu → "Video/palette inspector window". It opens a second
window beside the emulator that shows the video mode, frame format, CS:IP, the 16 attribute
colours with their DAC indices and the full 256-colour DAC grid, all updated live. Hover over a
colour for its exact value. Headless instances have no window; `video_info`/`palette` give the
same data.

Addresses: `"SEG:OFF"` (e.g. `"B800:0000"`, `"0040:004A"`), linear `"0x12345"` or `"12345h"`,
physical `"phys:0x..."`.

Key names: `a`–`z`, `0`–`9`, `f1`–`f12`, `enter`, `esc`, `tab`, `space`, `backspace`, `up`/`down`/`left`/`right`,
`home`, `end`, `pageup`, `pagedown`, `insert`, `delete`, `shift`/`ctrl`/`alt` (left) and
`lshift rshift lctrl rctrl lalt ralt`, `kp_0`–`kp_9`, `kp_enter`, `kp_plus`, `kp_minus`, `minus`,
`equals`, `lbracket`, `rbracket`, `semicolon`, `quote`, `comma`, `period`, `slash`, `backslash`,
`grave`, `capslock`, `numlock`, `scrolllock`, `printscreen`, `pause`.

## CLI (`dbx`)

```text
dbx launch --mount D:\games\pirates [--cycles max] [--checkpoint NAME] [--show]
dbx run "DIR /W"            dbx type "PIRATES\n"        dbx keys enter space alt+x
dbx hold up 400             dbx screen [--force]        dbx shot out.png
dbx raw --region 0,0,16,8   dbx raw --path frames\title dbx wait "Press any key"
dbx save NAME               dbx load NAME               dbx checkpoints
dbx peek 0040:004A 2        dbx watch 1234:0010 4 --seconds 10
dbx pause | regs | step --count 5 [--over] | resume [--wait 5] | detach
dbx mem B800:0000 64        dbx poke 0000:04F0 4C 4C 4D
dbx bp 1234:0100 [--once] [--memory]   dbx bp            dbx bp --delete bp-1
dbx dbg "DOS MCBS"          dbx trace --count 100       dbx status
dbx speed --cycles max      dbx list                    dbx kill [--all]

dbx video [--png pal.png]   dbx disasm 1814:0895 20     dbx stack 40
dbx ctrace start --trigger 1814:0895 [--break-on-end]   dbx ctrace read | stop | funcs
dbx doslog start | read | stop
dbx find 1234 --kind u16    dbx find "SAVE" --kind text
dbx snap before             dbx diff before --mode decreased --kind u16 [--candidates before.live]
dbx setreg ax=0x10 bx=5     dbx call 1814:10F9 --near --reg ax=3 --arg 7
dbx inject B4 2A CD 21      (far-called; RETF appended)
```

`--id <prefix>` picks an instance. Exit code 2 means a wait or command timed out.

## Using it as a behavioural oracle

- **Prefer memory over pixels** once a variable is located: `memory_watch` shows exactly when and
  how a value changes while you play, without disturbing timing. Confirm by `memory_poke`-ing a
  value and watching the game react.
- **Find a variable**: checkpoint, `memory_peek` a candidate region, change the value in-game (for
  example spend gold), peek again and diff. Memory-change breakpoints (`kind="memory_change"`)
  then stop the CPU on the code that writes it; `debug_registers` and `cpu_trace` show that code.
- **Reproducible experiments**: always start from `checkpoint_load`, set fixed cycles, and drive
  input with explicit `hold_ms`/`pace_ms`. Key timing is measured in emulated milliseconds, so it
  doesn't depend on host load.
- **Measuring graphics**: `screenshot_raw` / `screen_pixels` return the frame before scaling,
  with a palette index per pixel for every palettised mode (CGA, EGA, VGA 256, text). DOSBox-X
  renders those through the VGA DAC at 32 bpp; the harness inverts the DAC table to recover the
  indices (`<path>.idx`, one byte per pixel). Where several DAC entries hold the same colour the
  lowest index is reported. `unmatched_pixels` counts anything that isn't a DAC colour, such as a
  palette change mid-frame. True-colour (15/16/24/32-bit) modes give raw pixel values.

## Reverse-engineering a program

A workflow that works well for re-implementing a DOS game:

1. **Data files first.** `doslog_start`, run the program to the screen you care about, then
   `doslog_read`. Every read shows the file, the offset, the size and the buffer (`DS:DX`). You get
   the file layout and the address where each chunk lands in memory.
2. **Find the code that uses the data.** Set a memory-change breakpoint on that buffer, or
   `debug_stack` when stopped there. The call chain names the functions and their callers.
3. **Map a routine.** `calltrace_start(trigger="SEG:OFF", break_on_end=true)` on its entry, make
   the game run it, then `calltrace_stop`. You get the complete call tree under it, the DOS/BIOS
   interrupts it uses (INT 10h video, 16h keyboard, 21h DOS) and a list of every sub-function.
   `disassemble` each one.
4. **Probe a routine as a black box.** Stop in the debugger (`debug_pause`), then
   `call_function("SEG:OFF", registers=..., stack_args=...)` with chosen inputs. Everything is
   restored afterwards, so you can sweep inputs (random-number generators, damage formulas,
   decompressors) and tabulate the results. `inject_code` runs your own snippet in the program's
   context, for example to read a far pointer, or to call INT 21h/10h to see a service's answer.
5. **Variables.** `memory_snapshot` → change it in the game → `memory_diff(mode="decreased")`
   → repeat with `candidates` until one address remains. Then `memory_watch` it.
6. **Graphics.** `palette` and `video_info` for the colour setup; `screenshot_raw` for per-pixel
   palette indices; `display start` / `pel panning` in `video_info` for scrolling.

Call tracing needs the debugger's per-instruction hook: the harness build has it (heavy debug),
and tracing temporarily switches the CPU core to `normal` (restored when the trace ends).
Near-call tracking follows the stack pointer, so `longjmp`-style unwinds and stack switches are
handled, and hardware interrupt handlers (timer, keyboard) are left out unless `include_irq`.

## Things to know

- Keyboard and mouse input only reach the guest while it runs. If the debugger has the CPU
  stopped, keys stay queued (`status()` shows `pending_input_actions`) and mouse calls return an
  error. `debug_resume` or `debug_detach` first.
- `screenshot` works in every mode, including while paused (it returns the last rendered frame).
  It returns an error if a complex scaler (xBRZ/HQ) replaces the render cache; the harness
  launches with the default scaler.
- `run_dos_command` detects completion by the prompt (`C:\>` etc.) returning on the cursor line.
  Programs that clear the screen or never return give `completed=false`; continue with
  screen/keys.
- Modal dialogs never block a headless instance: message boxes are logged and answered with
  their default button.
- Logs: `%LOCALAPPDATA%\dosbox-llm\instances\<id>\dosbox-x.log`. `dbx kill --all` also prunes
  the directories of dead instances.

## Protocol additions (JSON-RPC over the agent pipe)

These extend the upstream agent protocol (`docs/rpc.md`). None of them needs a debugger session.

| Method | Params | Result |
|---|---|---|
| `session.attach` | – | debugger session on the running machine (no target launch); `session.stop` detaches |
| `input.key` | `key`, `action` press/down/up, `hold_ms` | `queued_actions`, `pending_actions`, `estimated_emulated_ms` |
| `input.keys` | `keys[]` combos, `pace_ms`, `hold_ms` | same |
| `input.type_text` | `text`, `pace_ms` | same |
| `input.status` / `input.clear` | – | `pending_actions` (clear also releases held keys) |
| `input.mouse` | `x`,`y` (0..1) and/or `dx`,`dy`, `button`, `action`, `wheel` | `accepted` |
| `screen.capture` | `format` png (default) or raw | png: `width`, `height`, `video_mode`, `data_base64`; raw adds `bpp`, doubling flags, `palette[]`, `indices_base64` + `unmatched_pixels` for palettised modes rendered at 32 bpp |
| `screen.read_text` | `attributes`, `force` | `is_text`, `video_mode`, `columns`, `rows`, `cursor`, `lines[]`, `attributes[]` |
| `machine.status` | – | `debugger_active`, `emulated_ms`, `cycles`, `video_mode`, `pending_input_actions`, … |
| `machine.set_speed` | `cycles`, `turbo` | `accepted` |
| `state.save` / `state.load` | `slot` or absolute `path` | `slot` / `path` |
| `memory.peek` / `memory.poke` | `address` (as `memory.read`), `length` / `data_base64` | bytes, without stopping the CPU |
| `mapper.trigger` | `event` | `accepted` |
| `video.info` | – | mode, resolution, frame, DAC/attribute palettes, CRTC start/offset/panning, `cs_ip` |
| `debug.disassemble` | `address` (segmented), `count` | `lines[]`: `address`, `linear`, `bytes`, `text` |
| `debug.stack` | `count` | `ss_sp`, `bp`, `words[]`, `frames[]` (`return`, `call_site`, `call_text`, `target`, `source`), `text` |
| `state.set_registers` | `registers` {name: value} | `accepted` (CPU must be stopped) |
| `memory.scratch` | – | `address`, `physical`, `size` of the injected-code area |
| `calltrace.start` | `trigger?`, `max_events`, `include_interrupts`, `include_irq`, `stop_on_return`, `break_on_end` | trace status |
| `calltrace.read` / `calltrace.stop` | `cursor`, `limit`, `functions` | status, `event_list[]`, `next_cursor`, `functions[]` |
| `doslog.start` / `doslog.read` / `doslog.stop` | `cursor`, `limit` | `recording`, `event_list[]`, `next_cursor` |

Agent config (`--agent-config`) gains `raw_debugger_commands=allowlist|all`. With `all`,
`debugger.execute_command` runs any debugger command; the harness enables it. The command-line
flag `-headless` runs with no window, no audio device and no console. Emulated hardware (sound
cards included) stays active. `-inspector` opens the inspector window at startup.
