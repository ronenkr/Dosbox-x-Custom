"""dbx: drive headless DOSBox-X instances from the shell (same engine as the MCP server).

  dbx launch --mount D:\\games\\pirates            # prints the instance id
  dbx run "DIR /W"                                # run a DOS command, print the screen
  dbx type "PIRATES\\n" ; dbx keys enter space     # raw input
  dbx screen ; dbx shot out.png                   # look at it
  dbx pause ; dbx regs ; dbx mem B800:0000 64 ; dbx step --count 5 ; dbx resume
  dbx kill
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from dosbox_agent import AgentError

from . import instances
from .harness import (Dosbox, format_registers, format_video_info, hex_dump, list_checkpoints, palette_png,
                      region_indices, write_raw_frame)
from .memscan import MemoryScanner, format_linear
from .instances import HarnessError


def _box(args: argparse.Namespace) -> Dosbox:
    return Dosbox(instances.get_instance(args.id))


def _print_screen(box: Dosbox) -> None:
    screen = box.screen()
    if screen.is_text:
        print(screen.text())
    else:
        print(f"(graphics mode {screen.video_mode}; use `dbx shot file.png`)")


def cmd_launch(args: argparse.Namespace) -> None:
    instance = instances.launch(mount_dir=args.mount, program=args.program, conf=args.conf, show=args.show,
                                cycles=args.cycles, inspector=args.inspector)
    print(instance.id)
    box = Dosbox(instance)
    if args.program is None:
        box.wait_for_prompt(20)
    if args.checkpoint:
        box.load_checkpoint(args.checkpoint)


def cmd_list(args: argparse.Namespace) -> None:
    for item in instances.list_instances():
        print(f"{item.id} pid={item.pid} mount={item.mount_dir or '-'} show={item.show}")


def cmd_kill(args: argparse.Namespace) -> None:
    targets = instances.list_instances() if args.all else [instances.get_instance(args.id)]
    for instance in targets:
        instances.stop(instance)
        print(f"stopped {instance.id}")
    instances.prune()


def cmd_run(args: argparse.Namespace) -> None:
    box = _box(args)
    result = box.run_command(args.command, timeout_s=args.timeout)
    _print_screen(box)
    if not result.completed:
        print("(prompt did not return within the timeout)", file=sys.stderr)
        sys.exit(2)


def cmd_type(args: argparse.Namespace) -> None:
    text = args.text.encode("utf-8").decode("unicode_escape") if args.escapes else args.text
    _box(args).type(text, pace_ms=args.pace)


def cmd_keys(args: argparse.Namespace) -> None:
    _box(args).keys(args.keys, pace_ms=args.pace, hold_ms=args.hold)


def cmd_screen(args: argparse.Namespace) -> None:
    box = _box(args)
    if args.force:
        print(box.client.read_screen(force=True).text())
    else:
        _print_screen(box)


def cmd_shot(args: argparse.Namespace) -> None:
    image = _box(args).screenshot()
    Path(args.file).write_bytes(image.png)
    print(f"{args.file}: {image.width}x{image.height} mode {image.video_mode}")


def cmd_wait(args: argparse.Namespace) -> None:
    found, screen = _box(args).wait_for_text(args.pattern, timeout_s=args.timeout)
    print(screen.text())
    if not found:
        sys.exit(2)


def cmd_mouse(args: argparse.Namespace) -> None:
    _box(args).client.mouse(x=args.x, y=args.y, dx=args.dx, dy=args.dy, button=args.button,
                            action=args.action, wheel=args.wheel)


def cmd_status(args: argparse.Namespace) -> None:
    for key, value in sorted(_box(args).client.machine_status().items()):
        print(f"{key}: {value}")


def cmd_speed(args: argparse.Namespace) -> None:
    turbo = None if args.turbo is None else args.turbo == "on"
    _box(args).client.set_speed(cycles=args.cycles, turbo=turbo)


def cmd_save(args: argparse.Namespace) -> None:
    print(_box(args).save_checkpoint(args.name))


def cmd_load(args: argparse.Namespace) -> None:
    _box(args).load_checkpoint(args.name)


def cmd_checkpoints(args: argparse.Namespace) -> None:
    print("\n".join(list_checkpoints()))


def cmd_hold(args: argparse.Namespace) -> None:
    _box(args).hold_key(args.key, args.ms)


def cmd_peek(args: argparse.Namespace) -> None:
    parsed, data = _box(args).peek(args.address, args.length)
    print(hex_dump(data, int(parsed.offset, 16)))


def cmd_watch(args: argparse.Namespace) -> None:
    for elapsed, data in _box(args).watch(args.address, args.length, args.seconds, args.interval):
        print(f"+{elapsed:6.2f}s  {data.hex(' ').upper()}")


def cmd_raw(args: argparse.Namespace) -> None:
    frame = _box(args).client.screenshot_raw()
    if args.region:
        x, y, w, h = (int(value) for value in args.region.split(","))
        print(region_indices(frame, x, y, w, h))
    if args.path:
        pixels, meta = write_raw_frame(frame, args.path)
        print(f"{pixels}\n{meta}")


def cmd_trace(args: argparse.Namespace) -> None:
    print("\n".join(_box(args).trace(count=args.count, detail=args.detail)))


def _int(text: str) -> int:
    value = text.strip().lower()
    return int(value[:-1], 16) if value.endswith("h") else int(value, 0)


def _register_args(pairs: list[str]) -> dict[str, int]:
    registers = {}
    for pair in pairs:
        name, _, value = pair.partition("=")
        if not value:
            raise ValueError(f"register assignments look like ax=0x10, got '{pair}'")
        registers[name] = _int(value)
    return registers


def cmd_video(args: argparse.Namespace) -> None:
    info = _box(args).video_info()
    print(format_video_info(info))
    if args.png:
        Path(args.png).write_bytes(palette_png(info))
        print(f"palette image: {args.png}")


def cmd_disasm(args: argparse.Namespace) -> None:
    print("\n".join(_box(args).disassemble(args.address, args.count)))


def cmd_stack(args: argparse.Namespace) -> None:
    print(_box(args).stack(args.count))


def cmd_setreg(args: argparse.Namespace) -> None:
    print(format_registers(_box(args).set_registers(_register_args(args.assignments))))


def cmd_call(args: argparse.Namespace) -> None:
    returned, result, note = _box(args).call_function(
        args.address, _register_args(args.reg or []), [_int(value) for value in args.arg or []],
        far=not args.near, timeout_s=args.timeout)
    print("returned" if returned else f"did NOT return: {note}")
    print(format_registers(result))


def cmd_inject(args: argparse.Namespace) -> None:
    address, outcome = _box(args).inject_code(bytes.fromhex(" ".join(args.bytes)), call=not args.no_call,
                                              registers=_register_args(args.reg or []), timeout_s=args.timeout)
    print(f"code at {address}")
    if outcome is not None:
        returned, result, note = outcome
        print("returned" if returned else f"did NOT return: {note}")
        print(format_registers(result))


def cmd_ctrace(args: argparse.Namespace) -> None:
    box = _box(args)
    if args.action == "start":
        status = box.calltrace_start(args.trigger, max_events=args.max_events, include_irq=args.irq,
                                     stop_on_return=args.trigger is not None if args.until_return is None else args.until_return,
                                     break_on_end=args.break_on_end)
        print(f"call trace {status['state']}")
        return
    if args.action == "stop":
        box.client.calltrace_stop()
    result = box.client.call("calltrace.read", {"cursor": args.cursor, "limit": args.limit,
                                               "functions": args.action in ("stop", "funcs")})
    print(f"state={result['state']} {result['end_reason']} events={result['events']} "
          f"functions={result['function_count']} next_cursor={result['next_cursor']}")
    if args.action != "funcs":
        for event in result["event_list"]:
            print(event["text"])
    for item in sorted(result.get("functions", []), key=lambda f: f["first_seq"]):
        print(f"  {item['address']}  calls={item['calls']} callers={item['callers']} depth={item['min_depth']}")


def cmd_doslog(args: argparse.Namespace) -> None:
    client = _box(args).client
    if args.action == "start":
        client.doslog_start()
    elif args.action == "stop":
        client.doslog_stop()
    else:
        result = client.doslog_read(args.cursor, args.limit)
        print(f"recording={result['recording']} next_cursor={result['next_cursor']}")
        for event in result["event_list"]:
            print(event["text"])


def _scanner(args: argparse.Namespace) -> MemoryScanner:
    box = _box(args)
    return MemoryScanner(box.instance, box.client)


def cmd_find(args: argparse.Namespace) -> None:
    for address in _scanner(args).search(args.pattern, args.kind, _int(args.start), _int(args.length)):
        print(format_linear(address))


def cmd_snap(args: argparse.Namespace) -> None:
    snapshot = _scanner(args).snapshot(args.name, _int(args.start), _int(args.length))
    print(f"{args.name}: {len(snapshot.data)} bytes from {format_linear(snapshot.start)}")


def cmd_diff(args: argparse.Namespace) -> None:
    matches, total = _scanner(args).diff(args.before, args.after, args.mode, args.kind, args.value, args.candidates)
    print(f"{total} match(es); candidate set '{args.before}.{args.after or 'live'}'")
    for address, old, new in matches:
        print(f"{format_linear(address)}  {old:#x} -> {new:#x}")


def cmd_pause(args: argparse.Namespace) -> None:
    print(format_registers(_box(args).pause()))


def cmd_resume(args: argparse.Namespace) -> None:
    print(_box(args).resume(wait_for_break_s=args.wait))


def cmd_step(args: argparse.Namespace) -> None:
    print(format_registers(_box(args).step(mode="over" if args.over else "into", count=args.count)))


def cmd_regs(args: argparse.Namespace) -> None:
    print(format_registers(_box(args).registers()))


def cmd_mem(args: argparse.Namespace) -> None:
    parsed, data = _box(args).read_memory(args.address, args.length)
    print(hex_dump(data, int(parsed.offset, 16)))


def cmd_poke(args: argparse.Namespace) -> None:
    _box(args).poke(args.address, bytes.fromhex(" ".join(args.bytes)))


def cmd_bp(args: argparse.Namespace) -> None:
    box = _box(args)
    if args.delete:
        box.delete_breakpoint(args.delete)
    elif args.address:
        print(box.add_breakpoint(args.address, once=args.once, kind="memory_change" if args.memory else "execution"))
    else:
        print("\n".join(box.breakpoints()) or "no breakpoints")


def cmd_dbg(args: argparse.Namespace) -> None:
    print(_box(args).debugger_command(" ".join(args.command)))


def cmd_detach(args: argparse.Namespace) -> None:
    _box(args).detach()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="dbx", description="Drive headless DOSBox-X instances.")
    parser.add_argument("--id", help="instance id (default: most recently launched)")
    sub = parser.add_subparsers(dest="command_name", required=True)

    p = sub.add_parser("launch", help="start an instance")
    p.add_argument("--mount", help="host folder to mount as C:")
    p.add_argument("--program", help="DOS command to run at startup")
    p.add_argument("--conf", help="dosbox-x.conf to use")
    p.add_argument("--cycles", help="max, auto, or a number")
    p.add_argument("--show", action="store_true", help="show the emulator window")
    p.add_argument("--inspector", action="store_true", help="with --show: open the palette/video inspector window")
    p.add_argument("--checkpoint", help="named checkpoint to restore after boot")
    p.set_defaults(func=cmd_launch)

    sub.add_parser("list", help="list running instances").set_defaults(func=cmd_list)
    p = sub.add_parser("kill", help="stop an instance")
    p.add_argument("--all", action="store_true")
    p.set_defaults(func=cmd_kill)

    p = sub.add_parser("run", help="run a DOS command and print the screen")
    p.add_argument("command")
    p.add_argument("--timeout", type=float, default=30.0)
    p.set_defaults(func=cmd_run)

    p = sub.add_parser("type", help="type text (\\n = Enter)")
    p.add_argument("text")
    p.add_argument("--pace", type=int, default=40)
    p.add_argument("--no-escapes", dest="escapes", action="store_false", help="type backslashes literally")
    p.set_defaults(func=cmd_type)

    p = sub.add_parser("keys", help="press keys/combos, e.g. enter esc ctrl+c")
    p.add_argument("keys", nargs="+")
    p.add_argument("--pace", type=int, default=40)
    p.add_argument("--hold", type=int, default=60)
    p.set_defaults(func=cmd_keys)

    p = sub.add_parser("screen", help="print the text screen")
    p.add_argument("--force", action="store_true", help="try to read text in graphics modes")
    p.set_defaults(func=cmd_screen)

    p = sub.add_parser("shot", help="save a PNG screenshot")
    p.add_argument("file")
    p.set_defaults(func=cmd_shot)

    p = sub.add_parser("wait", help="wait for a regex on the text screen")
    p.add_argument("pattern")
    p.add_argument("--timeout", type=float, default=30.0)
    p.set_defaults(func=cmd_wait)

    p = sub.add_parser("mouse", help="mouse input")
    p.add_argument("--x", type=float)
    p.add_argument("--y", type=float)
    p.add_argument("--dx", type=float)
    p.add_argument("--dy", type=float)
    p.add_argument("--button", choices=["left", "right", "middle"])
    p.add_argument("--action", choices=["click", "press", "release"], default="click")
    p.add_argument("--wheel", type=int, default=0)
    p.set_defaults(func=cmd_mouse)

    sub.add_parser("status", help="machine status").set_defaults(func=cmd_status)
    p = sub.add_parser("speed", help="set cycles / turbo")
    p.add_argument("--cycles")
    p.add_argument("--turbo", choices=["on", "off"])
    p.set_defaults(func=cmd_speed)
    for name, func in (("save", cmd_save), ("load", cmd_load)):
        p = sub.add_parser(name, help=f"{name} a named checkpoint (shared by all instances)")
        p.add_argument("name")
        p.set_defaults(func=func)
    sub.add_parser("checkpoints", help="list named checkpoints").set_defaults(func=cmd_checkpoints)
    p = sub.add_parser("hold", help="hold a key down for N emulated ms")
    p.add_argument("key")
    p.add_argument("ms", type=int)
    p.set_defaults(func=cmd_hold)
    p = sub.add_parser("peek", help="hex dump memory without pausing")
    p.add_argument("address")
    p.add_argument("length", type=int, nargs="?", default=64)
    p.set_defaults(func=cmd_peek)
    p = sub.add_parser("watch", help="print memory changes while the guest runs")
    p.add_argument("address")
    p.add_argument("length", type=int, nargs="?", default=16)
    p.add_argument("--seconds", type=float, default=5.0)
    p.add_argument("--interval", type=float, default=0.05)
    p.set_defaults(func=cmd_watch)
    p = sub.add_parser("raw", help="raw frame: region of palette indices and/or dump to files")
    p.add_argument("--region", help="x,y,w,h in source-frame pixels")
    p.add_argument("--path", help="write <path>.bin and <path>.json")
    p.set_defaults(func=cmd_raw)
    p = sub.add_parser("trace", help="trace N instructions (pauses the CPU)")
    p.add_argument("--count", type=int, default=100)
    p.add_argument("--detail", choices=["short", "normal", "long", "csip"], default="normal")
    p.set_defaults(func=cmd_trace)

    sub.add_parser("pause", help="stop the CPU in the debugger").set_defaults(func=cmd_pause)
    p = sub.add_parser("resume", help="continue execution")
    p.add_argument("--wait", type=float, default=0.0, help="seconds to wait for a breakpoint")
    p.set_defaults(func=cmd_resume)
    p = sub.add_parser("step", help="single-step")
    p.add_argument("--over", action="store_true")
    p.add_argument("--count", type=int, default=1)
    p.set_defaults(func=cmd_step)
    sub.add_parser("regs", help="show registers").set_defaults(func=cmd_regs)
    p = sub.add_parser("mem", help="hex dump memory")
    p.add_argument("address")
    p.add_argument("length", type=int, nargs="?", default=128)
    p.set_defaults(func=cmd_mem)
    p = sub.add_parser("poke", help="write hex bytes to memory without pausing")
    p.add_argument("address")
    p.add_argument("bytes", nargs="+")
    p.set_defaults(func=cmd_poke)
    p = sub.add_parser("bp", help="list/add/delete breakpoints")
    p.add_argument("address", nargs="?")
    p.add_argument("--once", action="store_true")
    p.add_argument("--memory", action="store_true", help="memory-change breakpoint")
    p.add_argument("--delete", metavar="BP_ID")
    p.set_defaults(func=cmd_bp)
    p = sub.add_parser("dbg", help="raw DOSBox-X debugger command")
    p.add_argument("command", nargs="+")
    p.set_defaults(func=cmd_dbg)
    sub.add_parser("detach", help="end the debug session").set_defaults(func=cmd_detach)

    p = sub.add_parser("video", help="video mode, VGA registers and palette")
    p.add_argument("--png", help="also save the palette as an image")
    p.set_defaults(func=cmd_video)
    p = sub.add_parser("disasm", help="disassemble (default: at CS:IP)")
    p.add_argument("address", nargs="?")
    p.add_argument("count", type=int, nargs="?", default=20)
    p.set_defaults(func=cmd_disasm)
    p = sub.add_parser("stack", help="stack dump + reconstructed call chain (pauses)")
    p.add_argument("count", type=int, nargs="?", default=32)
    p.set_defaults(func=cmd_stack)
    p = sub.add_parser("setreg", help="set registers while paused: dbx setreg ax=0x10 ip=0x100")
    p.add_argument("assignments", nargs="+")
    p.set_defaults(func=cmd_setreg)
    p = sub.add_parser("call", help="call a guest function and restore the CPU afterwards")
    p.add_argument("address")
    p.add_argument("--reg", action="append", help="input register, e.g. --reg ax=0x10 (repeatable)")
    p.add_argument("--arg", action="append", help="stack argument word, C order (repeatable)")
    p.add_argument("--near", action="store_true", help="near function (RET), default far (RETF)")
    p.add_argument("--timeout", type=float, default=5.0)
    p.set_defaults(func=cmd_call)
    p = sub.add_parser("inject", help="write machine code to the scratch area and far-call it")
    p.add_argument("bytes", nargs="+", help="hex bytes, e.g. B4 2A CD 21")
    p.add_argument("--reg", action="append")
    p.add_argument("--no-call", action="store_true")
    p.add_argument("--timeout", type=float, default=5.0)
    p.set_defaults(func=cmd_inject)
    p = sub.add_parser("ctrace", help="function-call trace: start | read | stop | funcs")
    p.add_argument("action", choices=["start", "read", "stop", "funcs"])
    p.add_argument("--trigger", help="start recording when execution reaches SEG:OFF")
    p.add_argument("--max-events", type=int, default=100000)
    p.add_argument("--irq", action="store_true", help="include calls inside hardware interrupt handlers")
    p.add_argument("--until-return", dest="until_return", action="store_true", default=None)
    p.add_argument("--no-until-return", dest="until_return", action="store_false")
    p.add_argument("--break-on-end", action="store_true")
    p.add_argument("--cursor", type=int, default=0)
    p.add_argument("--limit", type=int, default=500)
    p.set_defaults(func=cmd_ctrace)
    p = sub.add_parser("doslog", help="INT 21h log: start | read | stop")
    p.add_argument("action", choices=["start", "read", "stop"])
    p.add_argument("--cursor", type=int, default=0)
    p.add_argument("--limit", type=int, default=500)
    p.set_defaults(func=cmd_doslog)
    p = sub.add_parser("find", help="search memory for a value/pattern")
    p.add_argument("pattern")
    p.add_argument("--kind", default="u16", help="u8 u16 u32 i8 i16 i32 hex text")
    p.add_argument("--start", default="0")
    p.add_argument("--length", default="0xA0000")
    p.set_defaults(func=cmd_find)
    p = sub.add_parser("snap", help="save a memory snapshot for diffing")
    p.add_argument("name")
    p.add_argument("--start", default="0")
    p.add_argument("--length", default="0xA0000")
    p.set_defaults(func=cmd_snap)
    p = sub.add_parser("diff", help="compare snapshots (or a snapshot with live memory)")
    p.add_argument("before")
    p.add_argument("after", nargs="?")
    p.add_argument("--mode", default="changed", help="changed unchanged increased decreased equals delta")
    p.add_argument("--kind", default="u8")
    p.add_argument("--value")
    p.add_argument("--candidates", help="narrow to a previous result set '<before>.<after>'")
    p.set_defaults(func=cmd_diff)
    return parser


def main(argv: list[str] | None = None) -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    args = build_parser().parse_args(argv)
    try:
        args.func(args)
    except (HarnessError, AgentError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
