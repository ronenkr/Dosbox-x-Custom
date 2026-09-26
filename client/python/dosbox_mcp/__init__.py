"""Headless DOSBox-X harness for LLM agents: instance launcher, high-level helpers, MCP server and CLI."""
from .harness import CommandResult, Dosbox, at_prompt, format_registers, hex_dump, parse_address
from .instances import HarnessError, Instance, get_instance, launch, list_instances, stop

__all__ = [
    "CommandResult", "Dosbox", "HarnessError", "Instance", "at_prompt", "format_registers", "get_instance",
    "hex_dump", "launch", "list_instances", "parse_address", "stop",
]
