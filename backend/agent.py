"""SentinelCTF – AI Agent Orchestrator

Wraps Claude Opus (via LangChain) with module-aware system prompts and
structured output parsing to separate reasoning from executable commands.
Falls back to a rich mock when ANTHROPIC_API_KEY is not set.
"""

import os
import re
import json
from typing import Optional, List, Dict, Any

from modules import get_module_by_category, get_all_allowed_tools, list_categories

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_FLAG_RE = re.compile(r"(flag\{[^}]+\})", re.IGNORECASE)
_CMD_RE = re.compile(r"```(?:bash|sh)?\s*\n(.*?)```", re.DOTALL)


def _extract_commands(text: str) -> List[str]:
    """Pull fenced-bash blocks out of the agent response."""
    return [cmd.strip() for block in _CMD_RE.findall(text) for cmd in block.splitlines() if cmd.strip()]


def _extract_flags(text: str) -> List[str]:
    return _FLAG_RE.findall(text)


# ---------------------------------------------------------------------------
# Category classifier (simple keyword heuristic, or delegate to LLM)
# ---------------------------------------------------------------------------

CATEGORY_KEYWORDS: Dict[str, List[str]] = {
    "forensics": ["forensic", "binwalk", "steghide", "memory dump", "volatility", "pcap", "wireshark"],
    "crypto":    ["cipher", "encrypt", "decrypt", "aes", "rsa", "base64", "xor", "hash", "openssl"],
    "osint":     ["osint", "whois", "domain", "recon", "ip address", "dns"],
    "web":       ["sql", "injection", "xss", "web", "http", "url", "cookie", "session"],
    "reversing": ["reverse", "disassem", "objdump", "elf", "binary", "decompil"],
    "pwn":       ["overflow", "pwn", "buffer", "exploit", "rop", "shellcode"],
    "misc":      ["steg", "misc", "hidden", "image"],
}


def classify_category(challenge_text: str) -> str:
    text = challenge_text.lower()
    scores = {cat: sum(1 for kw in kws if kw in text) for cat, kws in CATEGORY_KEYWORDS.items()}
    best = max(scores, key=scores.get)
    return best if scores[best] > 0 else "misc"


# ---------------------------------------------------------------------------
# Core agent invocation
# ---------------------------------------------------------------------------

def run_agent(
    challenge_text: str,
    category: Optional[str] = None,
    filename: Optional[str] = None,
    history: Optional[List[Dict[str, str]]] = None,
) -> Dict[str, Any]:
    """Run the AI agent on a challenge.

    Returns a dict with keys:
      - category: str
      - reasoning: str
      - commands: list[str]        – proposed shell commands
      - flags: list[str]           – any flags detected in the response
      - needs_human: bool          – True when commands require approval
      - raw: str                   – full LLM output (or mock text)
    """
    if history is None:
        history = []

    # ----- Auto-classify if not provided -----
    if not category:
        category = classify_category(challenge_text)

    mod = get_module_by_category(category)
    module_prompt = mod.system_prompt() if mod else ""
    allowed_tools = mod.TOOLS if mod else get_all_allowed_tools()
    suggested = mod.suggest_commands(challenge_text, filename) if mod else []

    # ----- Try real LLM -----
    api_key = os.getenv("ANTHROPIC_API_KEY")
    if api_key:
        return _invoke_llm(api_key, challenge_text, category, module_prompt, allowed_tools, suggested, filename, history)

    # ----- Mock path -----
    return _mock_response(challenge_text, category, suggested)


def _invoke_llm(
    api_key: str,
    challenge_text: str,
    category: str,
    module_prompt: str,
    allowed_tools: list,
    suggested: list,
    filename: Optional[str],
    history: list,
) -> Dict[str, Any]:
    from langchain_anthropic import ChatAnthropic
    from langchain.schema import HumanMessage, SystemMessage, AIMessage

    llm = ChatAnthropic(
        model="claude-sonnet-4-20250514",
        temperature=0,
        api_key=api_key,
        max_tokens=4096,
    )

    system_text = f"""You are Sentinel-AI, the elite orchestrator for a multi-module CTF (Capture The Flag) platform.

[MODULE] Category: {category}
{module_prompt}

[ALLOWED TOOLS] {', '.join(allowed_tools)}

[WORKFLOW RULES]
1. UNDERSTAND: Analyse the challenge text (and file if given) to determine the best approach.
2. PLAN: Formulate a multi-step attack plan.
3. PROPOSE COMMANDS: Wrap every command you want executed inside ```bash ... ``` fences. Each fenced block should contain exactly ONE command per line.
4. PAUSE FOR HUMAN REVIEW: Always wait after proposing commands.
5. ANALYSE OUTPUT: When you receive tool output, look for flag formats like flag{{...}}.
6. REPORT: Once you find the flag, state it clearly.

[SUGGESTED STARTING COMMANDS]
{chr(10).join(f'  - {c}' for c in suggested)}
"""

    messages = [SystemMessage(content=system_text)]
    for h in history:
        if h.get("role") == "user":
            messages.append(HumanMessage(content=h["content"]))
        else:
            messages.append(AIMessage(content=h["content"]))

    user_text = f"Challenge: {challenge_text}"
    if filename:
        user_text += f"\nUploaded file: {filename}"
    messages.append(HumanMessage(content=user_text))

    response = llm.invoke(messages)
    raw = response.content

    commands = _extract_commands(raw)
    flags = _extract_flags(raw)

    return {
        "category": category,
        "reasoning": raw,
        "commands": commands,
        "flags": flags,
        "needs_human": len(commands) > 0,
        "raw": raw,
    }


def _mock_response(challenge_text: str, category: str, suggested: list) -> Dict[str, Any]:
    """Rich mock response for demo / when no API key is set."""
    reasoning = (
        f"[MOCK] Sentinel-AI classified this as **{category}**.\n\n"
        f"Based on the challenge description, I recommend the following approach:\n"
    )
    for i, cmd in enumerate(suggested, 1):
        reasoning += f"\n{i}. `{cmd}`"

    reasoning += "\n\nI need human approval before executing these commands."

    return {
        "category": category,
        "reasoning": reasoning,
        "commands": suggested,
        "flags": [],
        "needs_human": len(suggested) > 0,
        "raw": reasoning,
    }
