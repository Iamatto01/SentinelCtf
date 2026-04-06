# backend/modules/pwn.py
"""Binary Exploitation (Pwn) module for CTF challenges.

Provides:
- CATEGORY: "pwn"
- TOOLS: list of allowed command-line tools for binary exploitation
- system_prompt(): returns a system prompt tailored for pwn tasks
- suggest_commands(challenge_text: str, filename: Optional[str]) -> List[str]
"""

from typing import List, Optional

CATEGORY = "pwn"
TOOLS = [
    "checksec",
    "gdb",
    "python3",
    "file",
    "strings",
    "readelf",
    "objdump",
    "ropper",
    "one_gadget",
]

def system_prompt() -> str:
    return """You are a binary exploitation (pwn) specialist. Analyse the binary for vulnerabilities such as buffer overflows, format string bugs, use-after-free, and ROP chains. Propose an exploitation strategy and the commands needed. Use only the allowed tools."""

def suggest_commands(challenge_text: str, filename: Optional[str] = None) -> List[str]:
    cmds: List[str] = []
    if filename:
        cmds.append(f"file {filename}")
        cmds.append(f"checksec --file={filename}")
        cmds.append(f"readelf -h {filename}")
        cmds.append(f"strings {filename} | grep -iE 'flag|ctf|key'")
    else:
        cmds.append("echo 'A binary file is required for pwn analysis.'")
    return cmds
