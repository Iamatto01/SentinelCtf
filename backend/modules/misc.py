# backend/modules/misc.py
"""Miscellaneous / Steganography module for CTF challenges.

Provides:
- CATEGORY: "misc"
- TOOLS: list of allowed command-line tools for miscellaneous challenges
- system_prompt(): returns a system prompt tailored for misc tasks
- suggest_commands(challenge_text: str, filename: Optional[str]) -> List[str]
"""

from typing import List, Optional

CATEGORY = "misc"
TOOLS = [
    "python3",
    "file",
    "strings",
    "steghide",
    "zsteg",
    "stegseek",
    "exiftool",
    "xxd",
    "base64",
    "unzip",
    "tar",
]

def system_prompt() -> str:
    return """You are a CTF miscellaneous / steganography specialist. The challenge may involve hidden data in images, audio, encoded text, or unusual formats. Propose commands to investigate the file and uncover the flag. Use only the allowed tools."""

def suggest_commands(challenge_text: str, filename: Optional[str] = None) -> List[str]:
    cmds: List[str] = []
    text = challenge_text.lower()
    if filename:
        cmds.append(f"file {filename}")
        cmds.append(f"exiftool {filename}")
        cmds.append(f"strings {filename} | grep -iE 'flag|ctf|key'")
        if any(kw in text for kw in ["image", "png", "jpg", "jpeg", "steg"]):
            cmds.append(f"steghide extract -sf {filename} -p ''")
            cmds.append(f"zsteg {filename}")
    if "base64" in text:
        cmds.append("python3 -c \"import base64,sys;print(base64.b64decode(sys.stdin.read().strip()))\"")
    if not cmds:
        cmds.append("echo 'Provide more context or a file for miscellaneous analysis.'")
    return cmds
