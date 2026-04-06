# backend/modules/osint.py
"""OSINT module for CTF challenges.

Provides:
- CATEGORY: "osint"
- TOOLS: list of allowed command-line tools for OSINT analysis
- system_prompt(): returns a system prompt tailored for OSINT tasks
- suggest_commands(challenge_text: str, filename: Optional[str]) -> List[str]
"""

from typing import List, Optional

CATEGORY = "osint"
TOOLS = [
    "whois",
    "dig",
    "nslookup",
    "curl",
    "wget",
    "exiftool",
    "python3",
    "nmap",
]

def system_prompt() -> str:
    return """You are an OSINT (Open Source Intelligence) specialist. Analyse the challenge description for hostnames, IP addresses, usernames, domains, or metadata clues. Propose reconnaissance commands to enumerate information and locate the flag. Use only the allowed tools."""

def suggest_commands(challenge_text: str, filename: Optional[str] = None) -> List[str]:
    cmds: List[str] = []
    text = challenge_text.lower()
    # Domain / URL patterns
    if any(kw in text for kw in ["domain", "dns", "http", "url", "website"]):
        cmds.append("dig example.com ANY")
        cmds.append("whois example.com")
    if any(kw in text for kw in ["ip", "host", "server", "port"]):
        cmds.append("nmap -sV -T4 <target>")
    if filename:
        cmds.append(f"exiftool {filename}")
    if not cmds:
        cmds.append("echo 'Provide a domain/IP/URL for OSINT recon.'")
    return cmds
