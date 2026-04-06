# backend/modules/web.py
"""Web Exploitation module for CTF challenges.

Provides:
- CATEGORY: "web"
- TOOLS: list of allowed command-line tools for web exploitation
- system_prompt(): returns a system prompt tailored for web tasks
- suggest_commands(challenge_text: str, filename: Optional[str]) -> List[str]
"""

from typing import List, Optional

CATEGORY = "web"
TOOLS = [
    "curl",
    "wget",
    "nikto",
    "sqlmap",
    "dirb",
    "gobuster",
    "python3",
]

def system_prompt() -> str:
    return """You are a web exploitation specialist. Analyse the challenge description for URLs, injection points, authentication bypasses, and server-side vulnerabilities. Propose commands to enumerate and exploit the target. Use only the allowed tools."""

def suggest_commands(challenge_text: str, filename: Optional[str] = None) -> List[str]:
    cmds: List[str] = []
    text = challenge_text.lower()
    if any(kw in text for kw in ["sql", "injection", "login", "database"]):
        cmds.append("sqlmap -u '<target_url>' --batch --dbs")
    if any(kw in text for kw in ["directory", "hidden", "path", "robots"]):
        cmds.append("gobuster dir -u <target_url> -w /usr/share/wordlists/dirb/common.txt")
    if any(kw in text for kw in ["http", "url", "web", "site"]):
        cmds.append("curl -v <target_url>")
        cmds.append("nikto -h <target_url>")
    if not cmds:
        cmds.append("echo 'Provide a URL for web exploitation.'")
    return cmds
