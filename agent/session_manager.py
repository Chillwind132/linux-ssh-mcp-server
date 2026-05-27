"""SSH session manager — thread-safe connection pool for Linux hosts."""

import contextvars
import logging
import re
import shlex
import threading
import time
from dataclasses import dataclass
from typing import Any

import paramiko


@dataclass(frozen=True)
class UserIdentity:
    username: str


current_user: contextvars.ContextVar[UserIdentity | None] = contextvars.ContextVar(
    "current_user", default=None
)

logger = logging.getLogger("linux-ssh-mcp.sessions")
audit = logging.getLogger("linux-ssh-mcp.audit")

MAX_OUTPUT_CHARS = 60_000
CMD_TIMEOUT = 60
SEPARATOR = "═" * 80


@dataclass
class _CachedPassword:
    value: str
    last_used: float


def _truncate(text: str, limit: int = MAX_OUTPUT_CHARS) -> str:
    if len(text) <= limit:
        return text
    return (
        text[:limit]
        + f"\n\n--- truncated ({len(text):,} chars total, showing first {limit:,}) ---"
    )


def _ts() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


def _audit_block(header: str, fields: dict[str, str], body: str = "") -> None:
    lines = [f"\n{SEPARATOR}", f"{_ts()}  {header}", "─" * 80]
    for k, v in fields.items():
        lines.append(f"  {k:<14}: {v}")
    if body:
        lines.append("")
        lines.append(body)
    lines.append(SEPARATOR)
    audit.info("\n".join(lines))


def _indent(text: str, prefix: str = "  ") -> str:
    if not text.strip():
        return prefix + "(empty)"
    return "\n".join(prefix + line for line in text.splitlines())


class _Session:
    __slots__ = (
        "host", "port", "client", "connected_at",
        "last_used", "command_count", "cmd_lock", "_sftp",
        "_sudo_password",
    )

    def __init__(self, host: str, port: int, client: paramiko.SSHClient) -> None:
        self.host = host
        self.port = port
        self.client = client
        self.connected_at = time.time()
        self.last_used = self.connected_at
        self.command_count = 0
        self.cmd_lock = threading.Lock()
        self._sftp: paramiko.SFTPClient | None = None
        self._sudo_password: str | None = None

    @property
    def sftp(self) -> paramiko.SFTPClient:
        if self._sftp is None or self._sftp.get_channel().closed:
            self._sftp = self.client.open_sftp()
        return self._sftp

    def close(self) -> None:
        try:
            if self._sftp is not None:
                self._sftp.close()
        except Exception:
            pass
        try:
            self.client.close()
        except Exception:
            pass


class SessionManager:
    def __init__(
        self,
        username: str,
        password: str,
        default_port: int = 22,
    ) -> None:
        self._username = username
        self._password = password
        self._default_port = default_port
        self._sessions: dict[str, _Session] = {}
        self._lock = threading.Lock()

    def connect(self, host: str, port: int | None = None) -> dict[str, Any]:
        port = port or self._default_port
        session_id = host if port == self._default_port else f"{host}:{port}"

        with self._lock:
            if session_id in self._sessions:
                logger.info("Already connected to %s", session_id)
                return {
                    "session_id": session_id,
                    "status": "already_connected",
                    "host": host,
                    "port": port,
                }

        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(
                hostname=host,
                port=port,
                username=self._username,
                password=self._password,
                timeout=15,
                banner_timeout=15,
                auth_timeout=15,
                allow_agent=False,
                look_for_keys=False,
            )

            probe = (
                'echo "$(hostname)|'
                '$(cat /etc/os-release 2>/dev/null | grep ^PRETTY_NAME= | cut -d= -f2- | tr -d \'\"\')|'
                '$(uname -r)|'
                '$(uptime -s 2>/dev/null || who -b | awk \'{print $3,$4}\')"'
            )
            _, stdout_ch, stderr_ch = client.exec_command(probe, timeout=15)
            raw = stdout_ch.read().decode("utf-8", errors="replace").strip()
            err = stderr_ch.read().decode("utf-8", errors="replace").strip()
            parts = raw.split("|")

            with self._lock:
                self._sessions[session_id] = _Session(host, port, client)

            info: dict[str, Any] = {
                "session_id": session_id,
                "status": "connected",
                "host": host,
                "port": port,
                "hostname": parts[0] if parts else raw,
            }
            if len(parts) >= 4:
                info["os"] = parts[1]
                info["kernel"] = parts[2]
                info["last_boot"] = parts[3]

            logger.info("Connected to %s (%s)", session_id, info.get("os", ""))
            _audit_block("CONNECT", {
                "user": self._username,
                "session": session_id,
                "host": host,
                "port": str(port),
                "hostname": info.get("hostname", ""),
                "os": info.get("os", ""),
                "kernel": info.get("kernel", ""),
                "last_boot": info.get("last_boot", ""),
            })
            return info
        except Exception as e:
            logger.warning("Connect failed for %s: %s", host, e)
            _audit_block("CONNECT ERROR", {
                "user": self._username,
                "host": host,
                "port": str(port),
                "error": str(e)[:300],
            })
            return {"error": str(e), "host": host, "port": port}

    def disconnect(self, session_id: str) -> dict[str, Any]:
        with self._lock:
            s = self._sessions.pop(session_id, None)
        if s:
            cmd_count = s.command_count
            s.close()
            logger.info("Disconnected %s (ran %d commands)", session_id, cmd_count)
            _audit_block("DISCONNECT", {
                "user": self._username,
                "session": session_id,
                "commands_run": str(cmd_count),
            })
            return {"session_id": session_id, "status": "disconnected"}
        return {"error": f"Session not found: {session_id}"}

    def disconnect_all(self) -> dict[str, Any]:
        with self._lock:
            sessions = list(self._sessions.values())
            self._sessions.clear()
        for s in sessions:
            s.close()
        logger.info("Disconnected all (%d sessions)", len(sessions))
        _audit_block("DISCONNECT ALL", {
            "user": self._username,
            "sessions_closed": str(len(sessions)),
        })
        return {"status": "disconnected_all", "count": len(sessions)}

    def list_sessions(self) -> dict[str, Any]:
        with self._lock:
            items = []
            for sid, s in self._sessions.items():
                items.append({
                    "session_id": sid,
                    "host": s.host,
                    "port": s.port,
                    "connected_at": time.strftime(
                        "%Y-%m-%d %H:%M:%S", time.localtime(s.connected_at)
                    ),
                    "last_used": time.strftime(
                        "%Y-%m-%d %H:%M:%S", time.localtime(s.last_used)
                    ),
                    "command_count": s.command_count,
                })
            return {"sessions": items, "count": len(items)}

    def _get_session(self, session_id: str) -> _Session | None:
        with self._lock:
            return self._sessions.get(session_id)

    def run_cmd(
        self, session_id: str, command: str, tool_name: str = "",
        timeout: int = CMD_TIMEOUT,
        audit_command: str | None = None,
    ) -> dict[str, Any]:
        s = self._get_session(session_id)
        if not s:
            return {"error": f"Session not found: {session_id}. Use connect first."}

        with self._lock:
            s.last_used = time.time()
            s.command_count += 1
            cmd_num = s.command_count

        label = f" [{tool_name}]" if tool_name else ""
        command_for_audit = audit_command or command

        with s.cmd_lock:
            try:
                start = time.perf_counter()
                _, stdout_ch, stderr_ch = s.client.exec_command(
                    command, timeout=timeout
                )
                stdout = stdout_ch.read().decode("utf-8", errors="replace")
                stderr = stderr_ch.read().decode("utf-8", errors="replace")
                exit_code = stdout_ch.channel.recv_exit_status()
                elapsed_ms = int((time.perf_counter() - start) * 1000)

                truncated_stdout = _truncate(stdout)

                _audit_block(
                    f"COMMAND #{cmd_num}{label}",
                    {
                        "user": self._username,
                        "session": session_id,
                        "tool": tool_name or "(direct)",
                        "elapsed_ms": str(elapsed_ms),
                        "exit_code": str(exit_code),
                        "stdout_bytes": str(len(stdout)),
                        "stderr_bytes": str(len(stderr)),
                    },
                    body=(
                        "  $ " + command_for_audit + "\n"
                        "\n"
                        "  ── stdout ──\n"
                        + _indent(truncated_stdout)
                        + (
                            "\n\n  ── stderr ──\n" + _indent(stderr)
                            if stderr.strip()
                            else ""
                        )
                    ),
                )

                return {
                    "exit_code": exit_code,
                    "stdout": truncated_stdout,
                    "stderr": stderr.strip(),
                    "elapsed_ms": elapsed_ms,
                }
            except Exception as e:
                logger.error("run_cmd failed on %s: %s", session_id, e)
                _audit_block(f"COMMAND ERROR{label}", {
                    "user": self._username,
                    "session": session_id,
                    "tool": tool_name or "(direct)",
                    "error": str(e)[:300],
                }, body="  $ " + command_for_audit)
                return {"error": str(e), "session_id": session_id}

    def set_sudo_password(self, session_id: str, password: str | None) -> bool:
        s = self._get_session(session_id)
        if not s:
            return False
        s._sudo_password = password
        return True

    def has_sudo_password(self, session_id: str) -> bool:
        s = self._get_session(session_id)
        return s is not None and s._sudo_password is not None

    def run_sudo(
        self, session_id: str, command: str, tool_name: str = "",
        timeout: int = CMD_TIMEOUT,
    ) -> dict[str, Any]:
        """Run a command with sudo. Uses cached sudo password via stdin pipe."""
        s = self._get_session(session_id)
        if not s:
            return {"error": f"Session not found: {session_id}. Use connect first."}
        if s._sudo_password is None:
            return {"error": "sudo_not_configured", "message": "Sudo password not set. Call elevate_sudo first."}

        wrapped = (
            f"printf '%s\\n' {shlex.quote(s._sudo_password)} "
            f"| sudo -S -p '' bash -c {shlex.quote(command)}"
        )
        audit_command = f"sudo -S -p '' bash -c {shlex.quote(command)}"
        return self.run_cmd(
            session_id,
            wrapped,
            tool_name,
            timeout,
            audit_command=audit_command,
        )

    def sftp_stat(self, session_id: str, path: str) -> paramiko.SFTPAttributes | None:
        s = self._get_session(session_id)
        if not s:
            return None
        with s.cmd_lock:
            try:
                return s.sftp.stat(path)
            except Exception:
                return None

    def sftp_read_lines(
        self, session_id: str, path: str,
        start_line: int = 1, end_line: int = 200,
        tail: bool = False,
    ) -> dict[str, Any]:
        """Read file lines via SFTP with chunked streaming — never loads full file."""
        s = self._get_session(session_id)
        if not s:
            return {"error": f"Session not found: {session_id}. Use connect first."}

        with s.cmd_lock:
            try:
                start = time.perf_counter()
                st = s.sftp.stat(path)
                file_size = st.st_size or 0

                if tail:
                    count = max(1, min(end_line, 500))
                    chunk_size = count * 200
                    offset = max(0, file_size - chunk_size)
                    with s.sftp.open(path, "rb") as f:
                        f.seek(offset)
                        raw = f.read()
                    data = raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else raw
                    all_lines = data.splitlines()
                    lines = all_lines[-count:]
                    numbered = []
                    for i, line in enumerate(lines, 1):
                        numbered.append(f"{i:6}|{line}")
                    numbered.append(f"--- tail: last {len(lines)} lines ---")
                    elapsed_ms = int((time.perf_counter() - start) * 1000)
                    return {
                        "exit_code": 0,
                        "stdout": "\n".join(numbered),
                        "stderr": "",
                        "elapsed_ms": elapsed_ms,
                    }
                else:
                    if start_line < 1:
                        start_line = 1
                    if end_line < start_line:
                        return {"error": "end_line must be >= start_line"}
                    if end_line - start_line + 1 > 500:
                        end_line = start_line + 499

                    numbered = []
                    line_num = 0
                    with s.sftp.open(path, "rb") as f:
                        for raw_line in f:
                            line_num += 1
                            if line_num > end_line:
                                break
                            if line_num >= start_line:
                                text = raw_line.decode("utf-8", errors="replace") if isinstance(raw_line, bytes) else raw_line
                                numbered.append(f"{line_num:6}|{text.rstrip(chr(10) + chr(13))}")

                    numbered.append(
                        f"--- lines {start_line} to {end_line}, read {line_num} lines ---"
                    )
                    elapsed_ms = int((time.perf_counter() - start) * 1000)
                    return {
                        "exit_code": 0,
                        "stdout": "\n".join(numbered),
                        "stderr": "",
                        "elapsed_ms": elapsed_ms,
                    }
            except Exception as e:
                return {"error": str(e)}


class SessionRegistry:
    """Per-user SessionManager pool.

    Reads the calling user's identity from the ``current_user`` context-var
    (set by the auth middleware). AD passwords are collected through MCP
    elicitation by the connect tool, cached in memory with an idle TTL, and
    never accepted through HTTP headers.
    """

    def __init__(
        self,
        default_port: int = 22,
        password_idle_ttl_seconds: int = 3600,
    ) -> None:
        self._managers: dict[str, SessionManager] = {}
        self._passwords: dict[str, _CachedPassword] = {}
        self._lock = threading.Lock()
        self._default_port = default_port
        self._password_idle_ttl_seconds = password_idle_ttl_seconds

    def current_username(self) -> str:
        user = current_user.get()
        if not user:
            raise RuntimeError("No user identity in request context")
        return user.username

    def _is_expired(self, cached: _CachedPassword, now: float) -> bool:
        ttl = self._password_idle_ttl_seconds
        return ttl > 0 and now - cached.last_used > ttl

    def has_cached_password(self) -> bool:
        username = self.current_username()
        expired_mgr: SessionManager | None = None
        now = time.monotonic()

        with self._lock:
            cached = self._passwords.get(username)
            if cached is None:
                return False
            if self._is_expired(cached, now):
                self._passwords.pop(username, None)
                expired_mgr = self._managers.pop(username, None)
                cached = None
            else:
                cached.last_used = now

        if expired_mgr is not None:
            expired_mgr.disconnect_all()

        return cached is not None

    def cache_password(self, password: str) -> None:
        username = self.current_username()
        now = time.monotonic()
        old_mgr: SessionManager | None = None

        with self._lock:
            existing = self._passwords.get(username)
            if existing is not None and existing.value != password:
                old_mgr = self._managers.pop(username, None)
            self._passwords[username] = _CachedPassword(
                value=password,
                last_used=now,
            )

        if old_mgr is not None:
            old_mgr.disconnect_all()

    def _get(self) -> SessionManager:
        user = current_user.get()
        if not user:
            raise RuntimeError("No user identity in request context")

        username = user.username
        now = time.monotonic()
        expired_mgr: SessionManager | None = None
        mgr: SessionManager | None = None
        missing_password = False

        with self._lock:
            cached = self._passwords.get(username)
            if cached is None or self._is_expired(cached, now):
                self._passwords.pop(username, None)
                expired_mgr = self._managers.pop(username, None)
                cached = None
            else:
                cached.last_used = now
                mgr = self._managers.get(username)

            if mgr is None:
                if cached is None:
                    missing_password = True
                else:
                    mgr = SessionManager(
                        username=username,
                        password=cached.value,
                        default_port=self._default_port,
                    )
                    self._managers[username] = mgr

        if expired_mgr is not None:
            expired_mgr.disconnect_all()

        if missing_password or mgr is None:
            raise RuntimeError(
                "AD password is not cached or has expired. Call connect to enter it again."
            )

        return mgr

    def connect(self, host: str, port: int | None = None) -> dict[str, Any]:
        return self._get().connect(host, port)

    def disconnect(self, session_id: str) -> dict[str, Any]:
        return self._get().disconnect(session_id)

    def disconnect_all(self) -> dict[str, Any]:
        return self._get().disconnect_all()

    def list_sessions(self) -> dict[str, Any]:
        return self._get().list_sessions()

    def run_cmd(
        self, session_id: str, command: str, tool_name: str = "",
        timeout: int = CMD_TIMEOUT,
        audit_command: str | None = None,
    ) -> dict[str, Any]:
        return self._get().run_cmd(
            session_id,
            command,
            tool_name,
            timeout,
            audit_command=audit_command,
        )

    def set_sudo_password(self, session_id: str, password: str | None) -> bool:
        return self._get().set_sudo_password(session_id, password)

    def has_sudo_password(self, session_id: str) -> bool:
        return self._get().has_sudo_password(session_id)

    def run_sudo(
        self, session_id: str, command: str, tool_name: str = "",
        timeout: int = CMD_TIMEOUT,
    ) -> dict[str, Any]:
        return self._get().run_sudo(session_id, command, tool_name, timeout)

    def sftp_stat(self, session_id: str, path: str) -> paramiko.SFTPAttributes | None:
        return self._get().sftp_stat(session_id, path)

    def sftp_read_lines(
        self, session_id: str, path: str,
        start_line: int = 1, end_line: int = 200,
        tail: bool = False,
    ) -> dict[str, Any]:
        return self._get().sftp_read_lines(
            session_id, path, start_line, end_line, tail
        )
