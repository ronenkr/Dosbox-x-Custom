"""Drive the MCP server over real stdio, the way Claude Code talks to it."""
from __future__ import annotations

import asyncio
import os
import sys
import tempfile
import unittest

from mcp import ClientSession, StdioServerParameters, stdio_client

from dosbox_mcp import instances

EXE = instances.default_executable()


def _text(result) -> str:
    return "\n".join(getattr(block, "text", "") for block in result.content)


@unittest.skipUnless(os.name == "nt" and EXE.is_file(), f"DOSBox-X build not found at {EXE}")
class McpStdioTest(unittest.TestCase):
    def test_tools_over_stdio(self) -> None:
        asyncio.run(self._scenario())

    async def _scenario(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as home:
            env = dict(os.environ, DOSBOX_LLM_HOME=home)
            params = StdioServerParameters(command=sys.executable, args=["-m", "dosbox_mcp"], env=env)
            async with stdio_client(params) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    names = {tool.name for tool in (await session.list_tools()).tools}
                    for expected in ("dosbox_launch", "run_dos_command", "screenshot", "press_keys",
                                     "debug_pause", "memory_peek", "checkpoint_save", "cpu_trace",
                                     "video_info", "palette", "disassemble", "debug_stack", "call_function",
                                     "inject_code", "calltrace_start", "doslog_start", "memory_diff"):
                        self.assertIn(expected, names)

                    launched = _text(await session.call_tool("dosbox_launch", {}))
                    self.assertIn("instance_id=", launched, launched)

                    ran = _text(await session.call_tool("run_dos_command", {"command": "VER"}))
                    self.assertIn("completed=true", ran)
                    self.assertIn("DOSBox-X version", ran)

                    shot = await session.call_tool("screenshot", {})
                    images = [block for block in shot.content if getattr(block, "type", "") == "image"]
                    self.assertEqual(len(images), 1)
                    self.assertEqual(images[0].mime_type, "image/png")

                    registers = _text(await session.call_tool("debug_pause", {}))
                    self.assertIn("EIP=", registers)
                    self.assertIn("running", _text(await session.call_tool("debug_resume", {})))
                    self.assertIn("Detached", _text(await session.call_tool("debug_detach", {})))

                    peek = _text(await session.call_tool("memory_peek", {"address": "0040:004A", "length": 2}))
                    self.assertIn("50 00", peek)

                    palette = await session.call_tool("palette", {})
                    self.assertTrue(any(getattr(block, "type", "") == "image" for block in palette.content))
                    injected = _text(await session.call_tool("inject_code", {"hex_bytes": "B8 34 12"}))
                    self.assertIn("EAX=0x00001234", injected)
                    await session.call_tool("debug_detach", {})

                    bad = _text(await session.call_tool("press_keys", {"keys": ["ctrl+nokey"]}))
                    self.assertTrue(bad.startswith("ERROR"), bad)

                    self.assertIn("Stopped", _text(await session.call_tool("dosbox_shutdown", {})))


if __name__ == "__main__":
    unittest.main()
