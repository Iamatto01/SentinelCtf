# backend/modules/forensics.py
"""Forensics module for CTF challenges.

Provides:
- CATEGORY: "forensics"
- TOOLS: list of allowed command-line tools for forensic analysis
- system_prompt(): returns a system prompt tailored for forensics tasks
- suggest_commands(challenge_text: str, filename: Optional[str]) -> List[str]
"""

from typing import List, Optional

CATEGORY = "forensics"
TOOLS = [
    "binwalk",
    "foremost",
    "steghide",
    "exiftool",
    "strings",
    "file",
    "xxd",
    "volatility",
]

def system_prompt() -> str:
    return """You are a forensic analyst. Analyze the provided file and description, and propose commands to extract hidden data, identify file types, and locate flags. Use only the allowed tools."""

def suggest_commands(challenge_text: str, filename: Optional[str] = None) -> List[str]:
    cmds = []
    if filename:
        cmds.append(f"file {filename}")
        cmds.append(f"strings {filename} | grep -i flag")
        cmds.append(f"binwalk -e {filename}")
    else:
        cmds.append("echo 'No file provided for forensic analysis.'")
    return cmds
