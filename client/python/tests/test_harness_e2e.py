"""End-to-end tests of the headless harness against a real DOSBox-X build.

Skipped unless the Agent Release build exists (or DOSBOX_X_EXE points at one).
"""
from __future__ import annotations

import os
import struct
import tempfile
import time
import unittest
import uuid
from pathlib import Path

from dosbox_agent import MemoryAddress
from dosbox_mcp import instances
from dosbox_mcp.harness import Dosbox, at_prompt, checkpoint_path, region_indices, write_raw_frame

EXE = instances.default_executable()


@unittest.skipUnless(os.name == "nt" and EXE.is_file(), f"DOSBox-X build not found at {EXE}")
class HeadlessHarnessTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.home = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        os.environ["DOSBOX_LLM_HOME"] = cls.home.name
        cls.instance = instances.launch()
        cls.box = Dosbox(cls.instance)
        ready, _ = cls.box.wait_for_prompt(30)
        assert ready, "DOS prompt never appeared"

    @classmethod
    def tearDownClass(cls) -> None:
        instances.stop(cls.instance)
        del os.environ["DOSBOX_LLM_HOME"]
        cls.home.cleanup()

    def setUp(self) -> None:
        # Every test starts from a running machine at the prompt.
        self.box.detach()

    def test_runs_commands_and_reads_the_text_screen(self) -> None:
        result = self.box.run_command("VER", timeout_s=20)
        self.assertTrue(result.completed)
        self.assertIn("DOSBox-X version", result.screen.text())
        self.assertTrue(at_prompt(result.screen))

    def test_typed_text_and_key_combos_reach_the_guest(self) -> None:
        self.box.type("ECHO Mixed Case & Symbols!?")
        self.assertIn("ECHO Mixed Case & Symbols!?", self.box.screen().text())
        self.box.keys(["esc"])  # clears the typed line in COMMAND.COM
        self.box.keys(["enter"])
        self.assertTrue(self.box.wait_for_prompt(10)[0])

    def test_screenshot_is_a_png_of_the_text_mode(self) -> None:
        image = self.box.screenshot()
        self.assertEqual(image.png[:8], b"\x89PNG\r\n\x1a\n")
        width, height = struct.unpack(">II", image.png[16:24])
        self.assertEqual((width, height), (image.width, image.height))
        self.assertEqual(image.video_mode, "0x0003")

    def test_raw_frame_has_indices_and_palette(self) -> None:
        frame = self.box.client.screenshot_raw()
        # VGA renders text mode at 32 bpp; indices are recovered from the DAC.
        self.assertIn(frame.bpp, (8, 32))
        self.assertEqual(len(frame.pixels), frame.width * frame.height * (1 if frame.bpp == 8 else 4))
        self.assertTrue(frame.indexed)
        self.assertEqual(len(frame.palette or ()), 256)
        if frame.indices is not None:
            self.assertEqual(len(frame.indices), frame.width * frame.height)
            self.assertEqual(frame.unmatched_pixels, 0)
        self.assertEqual(len(region_indices(frame, 0, 0, 8, 2).splitlines()), 2)
        with tempfile.TemporaryDirectory() as directory:
            pixels, meta = write_raw_frame(frame, Path(directory) / "frame")
            self.assertEqual(pixels.stat().st_size, len(frame.pixels))
            self.assertIn('"palette"', meta.read_text(encoding="utf-8"))

    def test_memory_peek_and_poke_without_pausing(self) -> None:
        # 0000:04F0 is the BIOS inter-application communication area: free to scribble on.
        address = MemoryAddress.segmented(0x0000, 0x04F0)
        self.box.client.poke(address, b"LLM!")
        self.assertEqual(self.box.client.peek(address, 4), b"LLM!")
        self.assertFalse(self.box.client.machine_status()["debugger_active"])
        _, columns = self.box.peek("0040:004A", 2)
        self.assertEqual(int.from_bytes(columns, "little"), 80)

    def test_debugger_pause_step_breakpoint_trace_and_detach(self) -> None:
        registers = self.box.pause()
        self.assertEqual(registers.cpu_mode, "real")
        self.assertTrue(self.box.client.machine_status()["debugger_active"])
        self.box.step("into", 2)
        _, data = self.box.read_memory("0040:0000", 16)
        self.assertEqual(len(data), 16)
        breakpoint_id = self.box.add_breakpoint(
            f"{registers.segments['cs'][2:]}:{registers.instruction_pointer[2:]}", once=True)
        self.assertTrue(any(line.startswith(breakpoint_id) for line in self.box.breakpoints()))
        self.box.resume()
        self.assertTrue(self.box.wait_for_break(5).startswith("stopped"))
        self.assertIn("cr0", self.box.debugger_command("CPU"))
        trace = self.box.trace(count=5)
        self.assertGreaterEqual(len(trace), 1)
        self.box.detach()
        self.assertFalse(self.box.client.machine_status()["debugger_active"])
        self.assertTrue(self.box.run_command("VER", 20).completed)

    def test_mouse_input_is_accepted(self) -> None:
        self.box.client.mouse(x=0.5, y=0.5)
        self.box.client.mouse(button="left", action="click")
        self.box.client.mouse(dx=5, dy=-3)

    def test_named_checkpoints_are_shared_between_instances(self) -> None:
        marker = f"CHECKPOINT-{uuid.uuid4().hex[:6].upper()}"
        self.box.run_command(f"ECHO {marker}", 20)
        name = f"e2e-{marker.lower()}"
        path = self.box.save_checkpoint(name)
        self.assertEqual(path, checkpoint_path(name))
        self.box.run_command("CLS", 20)
        self.assertNotIn(marker, self.box.screen().text())

        other = instances.launch()
        try:
            second = Dosbox(other)
            second.wait_for_prompt(30)
            second.load_checkpoint(name)
            deadline = time.monotonic() + 5
            while marker not in second.screen().text() and time.monotonic() < deadline:
                time.sleep(0.1)
            self.assertIn(marker, second.screen().text())
        finally:
            instances.stop(other)

    def test_invalid_input_is_rejected_with_a_clear_error(self) -> None:
        with self.assertRaisesRegex(Exception, "Unknown key name"):
            self.box.client.keys(["ctrl+nokey"])
        with self.assertRaisesRegex(Exception, "US-keyboard"):
            self.box.client.type_text("café")


if __name__ == "__main__":
    unittest.main()
