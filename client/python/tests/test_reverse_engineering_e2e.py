"""End-to-end tests of the reverse-engineering features against a real DOSBox-X build."""
from __future__ import annotations

import os
import tempfile
import time
import unittest

from dosbox_agent import MemoryAddress
from dosbox_mcp import instances
from dosbox_mcp.harness import Dosbox, format_video_info, palette_png
from dosbox_mcp.memscan import MemoryScanner

EXE = instances.default_executable()


@unittest.skipUnless(os.name == "nt" and EXE.is_file(), f"DOSBox-X build not found at {EXE}")
class ReverseEngineeringTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.home = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        os.environ["DOSBOX_LLM_HOME"] = cls.home.name
        cls.instance = instances.launch()
        cls.box = Dosbox(cls.instance)
        assert cls.box.wait_for_prompt(30)[0]

    @classmethod
    def tearDownClass(cls) -> None:
        instances.stop(cls.instance)
        del os.environ["DOSBOX_LLM_HOME"]
        cls.home.cleanup()

    def setUp(self) -> None:
        self.box.detach()

    def test_video_info_and_palette_image(self) -> None:
        info = self.box.video_info()
        self.assertEqual(info["bios_mode"], "0x0003")
        self.assertTrue(info["is_text"])
        self.assertEqual(len(info["palette"]), 256)
        self.assertEqual(len(info["attribute_to_dac"]), 16)
        self.assertIn("16 colours -> DAC", format_video_info(info))
        self.assertEqual(palette_png(info)[:8], b"\x89PNG\r\n\x1a\n")

    def test_disassembly_and_stack(self) -> None:
        registers = self.box.pause()
        address = f"{registers.segments['cs'][2:]}:{registers.instruction_pointer[-4:]}"
        lines = self.box.disassemble(address, 4)
        self.assertEqual(len(lines), 4)
        self.assertTrue(lines[0].startswith(address.upper()))
        self.assertIn("SS:SP=", self.box.stack(16))

    def test_inject_code_and_call_function_restore_the_cpu(self) -> None:
        before = self.box.pause()
        _, (returned, result, _) = self.box.inject_code(bytes.fromhex("B8 34 12"))
        self.assertTrue(returned)
        self.assertEqual(int(result.general["eax"], 16) & 0xFFFF, 0x1234)
        area = self.box.scratch()["address"]
        self.box.inject_code(bytes.fromhex("89 E5 8B 46 04 03 46 06"), call=False)  # ax = arg0 + arg1
        returned, result, _ = self.box.call_function(area, stack_args=[40, 2])
        self.assertTrue(returned)
        self.assertEqual(int(result.general["eax"], 16) & 0xFFFF, 42)
        after = self.box.client.get_registers(self.box.session())
        self.assertEqual(after.general, before.general)
        self.assertEqual(after.segments, before.segments)
        self.assertEqual(after.instruction_pointer, before.instruction_pointer)
        self.box.detach()
        self.assertTrue(self.box.run_command("VER", 20).completed)

    def test_call_trace_records_calls_and_functions(self) -> None:
        self.box.client.calltrace_start(max_events=400, stop_on_return=False)
        time.sleep(1.0)
        result = self.box.client.calltrace_stop()
        self.assertEqual(result["state"], "finished")
        self.assertGreater(result["events"], 0)
        kinds = {event["kind"] for event in self.box.client.calltrace_read(0, 400)["event_list"]}
        self.assertTrue(kinds & {"call", "int"}, kinds)

    def test_dos_log_captures_int21_calls(self) -> None:
        self.box.client.doslog_start()
        self.box.inject_code(bytes.fromhex("B4 2A CD 21"))  # INT 21h AH=2Ah get date
        self.box.detach()
        events = self.box.client.doslog_read(0, 100)["event_list"]
        self.box.client.doslog_stop()
        self.assertTrue(any(event["function"] == "get date" for event in events), [e["text"] for e in events])

    def test_memory_scanner_finds_a_changed_value(self) -> None:
        scanner = MemoryScanner(self.instance, self.box.client)
        address = MemoryAddress.segmented(0x0000, 0x04F4)
        self.box.client.poke(address, (0x1111).to_bytes(2, "little"))
        scanner.snapshot("before", 0, 0x1000)
        self.box.client.poke(address, (0x2222).to_bytes(2, "little"))
        matches, _ = scanner.diff("before", None, mode="equals", kind="u16", value="0x2222")
        self.assertIn(0x4F4, [match[0] for match in matches])
        self.assertIn(0x4F4, scanner.search("0x2222", "u16", 0, 0x1000))


if __name__ == "__main__":
    unittest.main()
