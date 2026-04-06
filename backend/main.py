"""SentinelCTF — FastAPI Backend

Provides:
  /api/health               – health check
  /api/categories            – list available CTF modules
  /api/challenge             – submit a new challenge (multipart form)
  /api/challenge/{id}        – get challenge status + logs
  /api/challenge/{id}/approve – human approves proposed commands
  /api/challenge/{id}/reject  – human rejects proposed commands
  /api/execute               – run a single whitelisted command
  /ws/logs/{id}              – WebSocket stream of real-time logs
"""

import os
import json
import time
import sqlite3
import asyncio
import subprocess
import shutil
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, List

from fastapi import (
    FastAPI, HTTPException, BackgroundTasks,
    UploadFile, File, Form, WebSocket, WebSocketDisconnect,
)
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from dotenv import load_dotenv

load_dotenv()

# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------
app = FastAPI(title="SentinelCTF API", description="Backend for multi-layer CTF Solver")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
UPLOAD_DIR = Path("uploads")
UPLOAD_DIR.mkdir(exist_ok=True)

# ---------------------------------------------------------------------------
# Database (SQLite — compatible with Turso/libSQL for production)
# ---------------------------------------------------------------------------
DB_PATH = os.getenv("DB_PATH", "sentinel.db")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db():
    conn = get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS challenges (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            question   TEXT    NOT NULL,
            category   TEXT,
            filename   TEXT,
            status     TEXT    DEFAULT 'pending',
            flag       TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS logs (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            challenge_id INTEGER NOT NULL,
            role         TEXT    NOT NULL,
            message      TEXT    NOT NULL,
            timestamp    DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (challenge_id) REFERENCES challenges(id)
        );

        CREATE TABLE IF NOT EXISTS pending_commands (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            challenge_id INTEGER NOT NULL,
            commands     TEXT    NOT NULL,
            status       TEXT    DEFAULT 'pending',
            FOREIGN KEY (challenge_id) REFERENCES challenges(id)
        );
    """)
    conn.commit()
    conn.close()


@app.on_event("startup")
def startup():
    init_db()


# ---------------------------------------------------------------------------
# WebSocket connection manager
# ---------------------------------------------------------------------------
class ConnectionManager:
    def __init__(self):
        self.connections: Dict[int, List[WebSocket]] = {}

    async def connect(self, ws: WebSocket, challenge_id: int):
        await ws.accept()
        self.connections.setdefault(challenge_id, []).append(ws)

    def disconnect(self, ws: WebSocket, challenge_id: int):
        if challenge_id in self.connections:
            self.connections[challenge_id] = [
                c for c in self.connections[challenge_id] if c is not ws
            ]

    async def broadcast(self, challenge_id: int, data: dict):
        for ws in self.connections.get(challenge_id, []):
            try:
                await ws.send_json(data)
            except Exception:
                pass


manager = ConnectionManager()


# Helper — add log to DB *and* broadcast over WS
async def _add_log(challenge_id: int, role: str, message: str):
    conn = get_db()
    conn.execute(
        "INSERT INTO logs (challenge_id, role, message) VALUES (?, ?, ?)",
        (challenge_id, role, message),
    )
    conn.commit()
    conn.close()
    await manager.broadcast(challenge_id, {
        "role": role,
        "message": message,
        "time": datetime.utcnow().isoformat(),
    })


def _add_log_sync(challenge_id: int, role: str, message: str):
    """Synchronous version for use inside background tasks."""
    conn = get_db()
    conn.execute(
        "INSERT INTO logs (challenge_id, role, message) VALUES (?, ?, ?)",
        (challenge_id, role, message),
    )
    conn.commit()
    conn.close()


async def _broadcast_log(challenge_id: int, role: str, message: str):
    """Broadcast-only (log already written)."""
    await manager.broadcast(challenge_id, {
        "role": role,
        "message": message,
        "time": datetime.utcnow().isoformat(),
    })


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------
class ActionCommand(BaseModel):
    command: str


# ---------------------------------------------------------------------------
# Allowed tools whitelist (union of all module tools)
# ---------------------------------------------------------------------------
from modules import get_all_allowed_tools, list_categories as _list_cats


def _is_command_allowed(cmd: str) -> bool:
    """Check that the base binary is in the global tool whitelist."""
    allowed = set(get_all_allowed_tools())
    # Always allow safe baseline commands
    allowed |= {"echo", "pwd", "ls", "cat", "head", "tail", "wc", "grep", "find", "base64", "xxd", "unzip", "tar"}
    parts = cmd.strip().split()
    return bool(parts) and parts[0] in allowed


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/api/health")
def health():
    return {"status": "operational", "modules": _list_cats()}


@app.get("/api/categories")
def categories():
    return {"categories": _list_cats()}


@app.post("/api/challenge")
async def submit_challenge(
    question: str = Form(...),
    file: Optional[UploadFile] = File(None),
    background_tasks: BackgroundTasks = BackgroundTasks(),
):
    filename: Optional[str] = None

    # Save uploaded file
    if file and file.filename:
        safe_name = file.filename.replace("/", "_").replace("\\", "_")
        dest = UPLOAD_DIR / safe_name
        with open(dest, "wb") as f:
            shutil.copyfileobj(file.file, f)
        filename = str(dest)

    # Insert challenge
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO challenges (question, filename, status) VALUES (?, ?, ?)",
        (question, filename, "processing"),
    )
    challenge_id = cur.lastrowid
    conn.commit()
    conn.close()

    # Kick off agent in background
    background_tasks.add_task(_run_agent_flow, challenge_id, question, filename)

    return {"id": challenge_id, "status": "processing"}


async def _run_agent_flow(challenge_id: int, question: str, filename: Optional[str]):
    """Background task that orchestrates the agent."""
    from agent import run_agent

    await _add_log(challenge_id, "system", "Challenge uploaded. Initiating Orchestrator Agent…")
    await asyncio.sleep(0.3)
    await _add_log(challenge_id, "agent", "Analysing challenge prompt for category routing…")
    await asyncio.sleep(0.5)

    result = run_agent(challenge_text=question, filename=filename)
    category = result["category"]

    conn = get_db()
    conn.execute("UPDATE challenges SET category = ? WHERE id = ?", (category, challenge_id))
    conn.commit()
    conn.close()

    await _add_log(
        challenge_id, "agent",
        f"Categorised as **{category.upper()}**. Initialising {category} module…"
    )
    await asyncio.sleep(0.3)

    # Send reasoning
    await _add_log(challenge_id, "agent", result["reasoning"])

    # If flags already found without commands
    if result["flags"]:
        flag_str = result["flags"][0]
        conn = get_db()
        conn.execute("UPDATE challenges SET flag = ?, status = 'solved' WHERE id = ?", (flag_str, challenge_id))
        conn.commit()
        conn.close()
        await _add_log(challenge_id, "agent_success", f"Flag identified: {flag_str}")
        return

    # If commands proposed → store them and wait for human
    if result["commands"]:
        cmds_json = json.dumps(result["commands"])
        conn = get_db()
        conn.execute(
            "INSERT INTO pending_commands (challenge_id, commands, status) VALUES (?, ?, 'pending')",
            (challenge_id, cmds_json),
        )
        conn.execute("UPDATE challenges SET status = 'needs_human' WHERE id = ?", (challenge_id,))
        conn.commit()
        conn.close()

        plan_text = "Plan created:\n" + "\n".join(f"  {i+1}. `{c}`" for i, c in enumerate(result["commands"]))
        await _add_log(challenge_id, "agent_plan", plan_text)
        await _add_log(challenge_id, "system", "⚠️ Human approval required before command execution.")
        return

    # No commands and no flags — needs more input
    conn = get_db()
    conn.execute("UPDATE challenges SET status = 'idle' WHERE id = ?", (challenge_id,))
    conn.commit()
    conn.close()
    await _add_log(challenge_id, "agent", "I need more information to proceed. Please provide additional details.")


@app.get("/api/challenge/{challenge_id}")
def get_challenge(challenge_id: int):
    conn = get_db()
    challenge = conn.execute("SELECT * FROM challenges WHERE id = ?", (challenge_id,)).fetchone()
    logs = conn.execute(
        "SELECT * FROM logs WHERE challenge_id = ? ORDER BY id ASC", (challenge_id,)
    ).fetchall()
    pending = conn.execute(
        "SELECT * FROM pending_commands WHERE challenge_id = ? AND status = 'pending' ORDER BY id DESC LIMIT 1",
        (challenge_id,),
    ).fetchone()
    conn.close()

    if not challenge:
        raise HTTPException(status_code=404, detail="Challenge not found")

    return {
        "challenge": dict(challenge),
        "logs": [dict(l) for l in logs],
        "pending_commands": json.loads(pending["commands"]) if pending else [],
    }


@app.post("/api/challenge/{challenge_id}/approve")
async def approve_commands(challenge_id: int, background_tasks: BackgroundTasks):
    conn = get_db()
    pending = conn.execute(
        "SELECT * FROM pending_commands WHERE challenge_id = ? AND status = 'pending' ORDER BY id DESC LIMIT 1",
        (challenge_id,),
    ).fetchone()

    if not pending:
        conn.close()
        raise HTTPException(status_code=404, detail="No pending commands")

    commands = json.loads(pending["commands"])
    conn.execute("UPDATE pending_commands SET status = 'approved' WHERE id = ?", (pending["id"],))
    conn.execute("UPDATE challenges SET status = 'processing' WHERE id = ?", (challenge_id,))
    conn.commit()
    conn.close()

    background_tasks.add_task(_execute_approved_commands, challenge_id, commands)
    return {"status": "approved", "commands": commands}


@app.post("/api/challenge/{challenge_id}/reject")
async def reject_commands(challenge_id: int):
    conn = get_db()
    conn.execute(
        "UPDATE pending_commands SET status = 'rejected' WHERE challenge_id = ? AND status = 'pending'",
        (challenge_id,),
    )
    conn.execute("UPDATE challenges SET status = 'idle' WHERE id = ?", (challenge_id,))
    conn.commit()
    conn.close()

    await _add_log(challenge_id, "system", "Action rejected by human override. Awaiting new instructions.")
    return {"status": "rejected"}


async def _execute_approved_commands(challenge_id: int, commands: List[str]):
    """Execute approved commands and feed output back to the agent."""
    from agent import run_agent, _extract_flags

    await _add_log(challenge_id, "system", "Action approved by Human Override.")

    all_output = ""
    for cmd in commands:
        if not _is_command_allowed(cmd):
            await _add_log(challenge_id, "system", f"⛔ Blocked: `{cmd}` — not in allowed tool list.")
            continue

        await _add_log(challenge_id, "system", f"Executing: `{cmd}`")
        try:
            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True, timeout=30,
                cwd=str(UPLOAD_DIR),
            )
            output = (result.stdout + result.stderr).strip() or "(no output)"
        except subprocess.TimeoutExpired:
            output = "Error: Command timed out after 30s."
        except Exception as e:
            output = f"Error: {e}"

        await _add_log(challenge_id, "terminal", output)
        all_output += f"\n--- Output of `{cmd}` ---\n{output}\n"

        # Check for flags in output
        flags = _extract_flags(output)
        if flags:
            flag = flags[0]
            conn = get_db()
            conn.execute("UPDATE challenges SET flag = ?, status = 'solved' WHERE id = ?", (flag, challenge_id))
            conn.commit()
            conn.close()
            await _add_log(challenge_id, "agent_success", f"🎉 Flag captured: {flag}")
            return

    # Feed output back to the agent for next round
    await _add_log(challenge_id, "agent", "Analysing command output…")
    await asyncio.sleep(0.5)

    conn = get_db()
    challenge = conn.execute("SELECT * FROM challenges WHERE id = ?", (challenge_id,)).fetchone()
    conn.close()

    history = [
        {"role": "user", "content": challenge["question"]},
        {"role": "assistant", "content": "Previous commands executed."},
        {"role": "user", "content": f"Tool output:\n{all_output}\n\nAnalyse the output. If you found the flag, state it. Otherwise, propose the next commands."},
    ]

    result = run_agent(
        challenge_text=challenge["question"],
        category=challenge["category"],
        filename=challenge["filename"],
        history=history,
    )

    await _add_log(challenge_id, "agent", result["reasoning"])

    if result["flags"]:
        flag = result["flags"][0]
        conn = get_db()
        conn.execute("UPDATE challenges SET flag = ?, status = 'solved' WHERE id = ?", (flag, challenge_id))
        conn.commit()
        conn.close()
        await _add_log(challenge_id, "agent_success", f"🎉 Flag captured: {flag}")
        return

    if result["commands"]:
        cmds_json = json.dumps(result["commands"])
        conn = get_db()
        conn.execute(
            "INSERT INTO pending_commands (challenge_id, commands, status) VALUES (?, ?, 'pending')",
            (challenge_id, cmds_json),
        )
        conn.execute("UPDATE challenges SET status = 'needs_human' WHERE id = ?", (challenge_id,))
        conn.commit()
        conn.close()
        plan_text = "Next steps:\n" + "\n".join(f"  {i+1}. `{c}`" for i, c in enumerate(result["commands"]))
        await _add_log(challenge_id, "agent_plan", plan_text)
        await _add_log(challenge_id, "system", "⚠️ Human approval required for next commands.")
    else:
        conn = get_db()
        conn.execute("UPDATE challenges SET status = 'idle' WHERE id = ?", (challenge_id,))
        conn.commit()
        conn.close()
        await _add_log(challenge_id, "agent", "Analysis complete. No further automated actions available.")


@app.post("/api/execute")
def execute_command(action: ActionCommand):
    """Ad-hoc command execution — sandbox-safe."""
    if not _is_command_allowed(action.command):
        return {"output": f"Error: `{action.command.split()[0]}` is not in the allowed tool list."}
    try:
        result = subprocess.run(
            action.command, shell=True, capture_output=True, text=True,
            timeout=30, cwd=str(UPLOAD_DIR),
        )
        return {"output": (result.stdout + result.stderr).strip() or "(no output)"}
    except subprocess.TimeoutExpired:
        return {"output": "Error: Command timed out after 30s."}
    except Exception as e:
        return {"output": f"Execution Error: {e}"}


# ---------------------------------------------------------------------------
# WebSocket
# ---------------------------------------------------------------------------
@app.websocket("/ws/logs/{challenge_id}")
async def ws_logs(ws: WebSocket, challenge_id: int):
    await manager.connect(ws, challenge_id)

    # Send existing logs as catchup
    conn = get_db()
    logs = conn.execute(
        "SELECT role, message, timestamp FROM logs WHERE challenge_id = ? ORDER BY id ASC",
        (challenge_id,),
    ).fetchall()
    conn.close()

    for log in logs:
        await ws.send_json({
            "role": log["role"],
            "message": log["message"],
            "time": log["timestamp"],
        })

    # Keep alive
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(ws, challenge_id)
