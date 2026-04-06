# backend/modules/reversing.py
"""Reverse Engineering module for CTF challenges.

Provides:
- CATEGORY: "reversing"
- TOOLS: list of allowed command-line tools for reverse engineering
- system_prompt(): returns a system prompt tailored for reversing tasks
- suggest_commands(challenge_text: str, filename: Optional[str]) -> List[str]
"""

from typing import List, Optional

CATEGORY = "reversing"
TOOLS = [
    "objdump",
    "strings",
    "ltrace",
    "strace",
    "gdb",
    "radare2",
    "file",
    "readelf",
    "python3",
]

def system_prompt() -> str:
    return """You are a reverse engineering specialist. Analyse the binary or challenge description to understand the program logic, identify the flag format, and propose disassembly/debugging commands. Use only the allowed tools."""

def suggest_commands(challenge_text: str, filename: Optional[str] = None) -> List[str]:
    cmds: List[str] = []
    if filename:
        cmds.append(f"file {filename}")
        cmds.append(f"strings {filename} | grep -iE 'flag|ctf|key'")
        cmds.append(f"objdump -d {filename} | head -100")
        cmds.append(f"readelf -h {filename}")
    else:
        cmds.append("echo 'A binary file is required for reverse engineering.'")
    return cmds
