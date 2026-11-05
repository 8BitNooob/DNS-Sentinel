"""Dashboard data access and Windows collector process controls."""

import json
import os
import subprocess
import sys
import ctypes
from pathlib import Path

import pandas as pd

from storage.database import initialize_database


def load_events(path: str | Path, limit: int = 5000) -> pd.DataFrame:
    initialize_database(path)
    return pd.read_sql_query(
        """SELECT observed_at, source_ip, destination_ip, qname, qtype,
                  is_response, response_code, ttl, correlation_status
           FROM dns_events ORDER BY observed_at DESC LIMIT ?""",
        f"sqlite:///{Path(path).resolve()}",
        params=(limit,),
    )


def load_table(path: str | Path, table: str, limit: int = 500) -> pd.DataFrame:
    allowed = {"alerts", "incidents", "client_baselines", "allowlist"}
    if table not in allowed:
        raise ValueError(f"Unsupported dashboard table: {table}")
    initialize_database(path)
    return pd.read_sql_query(
        f"SELECT * FROM {table} ORDER BY rowid DESC LIMIT ?",
        f"sqlite:///{Path(path).resolve()}",
        params=(limit,),
    )


def load_health(path: str | Path) -> dict[str, object]:
    try:
        with Path(path).open(encoding="utf-8") as file:
            return json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        return {"status": "not_started", "error": None}


def collector_running(health: dict[str, object]) -> bool:
    pid = health.get("pid")
    if not isinstance(pid, int):
        return False
    if sys.platform == "win32":
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        handle = kernel32.OpenProcess(0x1000, False, pid)
        if not handle:
            return False
        exit_code = ctypes.c_ulong()
        try:
            alive = bool(kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code)))
        finally:
            kernel32.CloseHandle(handle)
        if not alive or exit_code.value != 259:
            return False
    else:
        try:
            os.kill(pid, 0)
        except (OSError, ProcessLookupError):
            return False
    return health.get("status") == "running"


def start_collector(config_path: str | Path) -> subprocess.Popen:
    stop_path = Path(config_path).resolve().parent.parent / "outputs" / "collector.stop"
    stop_path.unlink(missing_ok=True)
    flags = (
        getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        | getattr(subprocess, "DETACHED_PROCESS", 0)
        | getattr(subprocess, "CREATE_NO_WINDOW", 0)
    )
    return subprocess.Popen(
        [sys.executable, "-m", "collector.service", "--config", str(config_path)],
        creationflags=flags,
        cwd=Path(config_path).resolve().parent.parent,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def stop_collector(process: subprocess.Popen | None, stop_path: str | Path) -> None:
    Path(stop_path).parent.mkdir(parents=True, exist_ok=True)
    Path(stop_path).touch()
    if process is not None and process.poll() is None:
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.terminate()
            process.wait(timeout=5)
