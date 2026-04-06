# backend/modules/crypto.py
"""Crypto module for CTF challenges.

Provides:
- CATEGORY: "crypto"
- TOOLS: list of allowed command-line tools for cryptographic analysis
- system_prompt(): returns a system prompt tailored for crypto tasks
- suggest_commands(challenge_text: str, filename: Optional[str]) -> List[str]
"""

from typing import List, Optional

CATEGORY = "crypto"
TOOLS = [
    "openssl",
    "hashcat",
    "john",
    "python3",
    "gpg",
]

def system_prompt() -> str:
    return """You are a cryptography analyst. Analyze the challenge description and any provided file, and propose commands to decode, decrypt, or brute-force the secret. Use only the allowed tools."""

def suggest_commands(challenge_text: str, filename: Optional[str] = None) -> List[str]:
    cmds = []
    # Simple heuristic: look for common encodings
    if "base64" in challenge_text.lower():
        cmds.append("python3 -c 'import base64,sys;print(base64.b64decode(sys.stdin.read()))' < " + (filename or ""))
    if filename:
        cmds.append(f"file {filename}")
    return cmds
