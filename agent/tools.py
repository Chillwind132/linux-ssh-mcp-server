"""MCP tool definitions — Linux remote operations via SSH."""

import logging
from typing import Any

from fastmcp import Context, FastMCP

from agent.session_manager import SessionRegistry

logger = logging.getLogger("linux-ssh-mcp.tools")


def _sh_escape(value: str) -> str:
    """Escape a value for embedding in a bash single-quoted string."""
    return value.replace("'", "'\\''")


def register_tools(mcp: FastMCP, sm: SessionRegistry) -> None:
    async def _ensure_ad_password(ctx: Context) -> dict[str, Any] | None:
        if sm.has_cached_password():
            return None

        username = sm.current_username()
        try:
            result = await ctx.elicit(
                message=(
                    f"Enter your AD password for {username}.\n"
                    "It is cached only in MCP server memory with an idle TTL and is never logged."
                ),
                response_type=str,
            )
            if result.action != "accept":
                return {"status": "cancelled", "message": "AD password entry cancelled"}
        except Exception:
            return {"error": "Elicitation unavailable - cannot prompt for AD password"}

        password = result.data if hasattr(result, "data") and result.data else ""
        if not password:
            return {"error": "No AD password provided"}

        sm.cache_password(str(password))
        return None

    # ==================================================================
    # Session lifecycle
    # ==================================================================

    @mcp.tool()
    async def connect(host: str, ctx: Context, port: int = 22) -> dict[str, Any]:
        """REQUIRED FIRST STEP — connect before calling any other tool. Authenticates via SSH after eliciting your AD password once per cached session; the password is stored only in server memory with an idle TTL and never appears in tool responses or logs. Returns a session_id you must pass to every subsequent tool call, plus hostname, OS, kernel version, and last boot time for immediate triage context.

        Args:
            host: Hostname or IP address (e.g. 'web-server-01.example.com').
            port: SSH port (default 22).
        """
        auth_error = await _ensure_ad_password(ctx)
        if auth_error is not None:
            return auth_error
        return sm.connect(host, port)

    @mcp.tool()
    def disconnect(session_id: str) -> dict[str, Any]:
        """Close an SSH session when you are done. Always disconnect when finished — sessions are not automatically cleaned up. Call list_sessions first if you need to find the session_id.

        Args:
            session_id: Session ID returned by connect.
        """
        return sm.disconnect(session_id)

    @mcp.tool()
    def list_sessions() -> dict[str, Any]:
        """List all active SSH sessions with host, connection time, last used time, and command count. Use this to find session IDs or check if you are already connected to a host."""
        return sm.list_sessions()

    # ==================================================================
    # Sudo elevation
    # ==================================================================

    @mcp.tool()
    async def elevate_sudo(session_id: str, ctx: Context) -> dict[str, Any]:
        """Elevate the session to run privileged commands via sudo. Prompts the user for their sudo password once — it is cached for the session lifetime and cleared on disconnect. The password never appears in tool responses or LLM context. Required before using tools that need root access (journalctl, service management, kill_process, etc.).

        Args:
            session_id: Session ID from connect.
        """
        if sm.has_sudo_password(session_id):
            test = sm.run_sudo(session_id, "whoami", tool_name="elevate_sudo")
            if test.get("stdout", "").strip() == "root":
                return {"status": "already_elevated", "message": "Sudo is already configured and working for this session."}

        try:
            result = await ctx.elicit(
                message="Enter your sudo password to enable privileged commands.\nThe password is cached in memory for this session only and never logged.",
                response_type=str,
            )
            if result.action != "accept":
                return {"status": "cancelled", "message": "Sudo elevation cancelled by user"}
        except Exception:
            return {"error": "Elicitation unavailable — cannot prompt for sudo password"}

        password = result.data if hasattr(result, "data") and result.data else ""
        if not password:
            return {"error": "No password provided"}

        sm.set_sudo_password(session_id, str(password))

        test = sm.run_sudo(session_id, "whoami", tool_name="elevate_sudo")
        if test.get("stdout", "").strip() == "root":
            return {"status": "elevated", "message": "Sudo configured successfully. Privileged commands are now available."}
        else:
            sm.set_sudo_password(session_id, None)
            return {"error": "Sudo authentication failed. Check your password.", "details": test.get("stderr", "") or test.get("stdout", "")}

    def _run(
        session_id: str, command: str, tool_name: str = "",
        timeout: int = 60,
    ) -> dict[str, Any]:
        """Single routing point for all command execution.

        - Not elevated: runs as the connected SSH user (commands that need
          root will fail with permission errors — this is expected).
        - Elevated (after elevate_sudo): runs everything through sudo.
        """
        if sm.has_sudo_password(session_id):
            return sm.run_sudo(session_id, command, tool_name, timeout)
        return sm.run_cmd(session_id, command, tool_name, timeout)

    # ==================================================================
    # Filesystem — read-only
    # ==================================================================

    @mcp.tool()
    def list_directory(session_id: str, path: str) -> dict[str, Any]:
        """List files and directories at the given path, showing permissions, owner, size, modification time, and name (max 200 entries). Use this to explore directory structure; use find_files to search recursively by pattern instead.

        Args:
            session_id: Session ID from connect.
            path: Absolute directory path (e.g. '/var/log', '/opt/app').
        """
        safe = _sh_escape(path)
        cmd = f"ls -lhA '{safe}' 2>&1 | head -201"
        return _run(session_id, cmd, tool_name="list_directory")

    @mcp.tool()
    def find_files(
        session_id: str,
        path: str,
        pattern: str,
        max_depth: int = 5,
        file_type: str = "f",
    ) -> dict[str, Any]:
        """Recursively search for files matching a name pattern, returning path, size, and modification time (max 100 results). Use list_directory to browse folders instead.

        Args:
            session_id: Session ID from connect.
            path: Root directory to search from.
            pattern: Name pattern (e.g. '*.log', '*.conf', 'server.xml').
            max_depth: Recursion depth limit (default 5, max 10).
            file_type: 'f' for files only (default), 'd' for directories, empty for both.
        """
        safe_path = _sh_escape(path)
        safe_pattern = _sh_escape(pattern)
        depth = max(1, min(max_depth, 10))
        ft = file_type.strip()
        type_arg = f"-type {ft} " if ft in ("f", "d", "l") else ""
        cmd = (
            f"find '{safe_path}' -maxdepth {depth} {type_arg}"
            f"-name '{safe_pattern}' "
            f"-printf '%T+ %s %p\\n' 2>/dev/null "
            f"| sort -r | head -100"
        )
        return _run(session_id, cmd, tool_name="find_files")

    @mcp.tool()
    def read_file(
        session_id: str,
        path: str,
        start_line: int = 1,
        end_line: int = 200,
        tail: bool = False,
    ) -> dict[str, Any]:
        """Read file contents with numbered lines (max 500 lines per call). Uses SFTP streaming so it handles huge files efficiently without loading them into memory. Two modes: (1) Range mode (default): reads lines start_line through end_line. (2) Tail mode (tail=True): reads the last N lines where N=end_line — fast even on huge files, ideal for recent log entries.

        Args:
            session_id: Session ID from connect.
            path: Absolute file path.
            start_line: First line to return (1-based, default 1). Ignored when tail=True.
            end_line: Range mode: last line number to return (default 200). Tail mode: number of lines from the end to return.
            tail: When true, read last N lines instead of a range from start. Use for logs.
        """
        result = sm.sftp_read_lines(session_id, path, start_line, end_line, tail)
        if "error" in result and "Permission denied" in str(result["error"]):
            safe = _sh_escape(path)
            if tail:
                count = max(1, min(end_line, 500))
                cmd = (
                    f"tail -n {count} '{safe}' 2>&1 "
                    f"| awk '{{printf \"%6d|%s\\n\", NR, $0}}'; "
                    f"echo '--- tail: last {count} lines ---'"
                )
            else:
                if start_line < 1:
                    start_line = 1
                if end_line < start_line:
                    return {"error": "end_line must be >= start_line"}
                if end_line - start_line + 1 > 500:
                    end_line = start_line + 499
                cmd = (
                    f"sed -n '{start_line},{end_line}p' '{safe}' 2>&1 "
                    f"| awk -v s={start_line} '{{printf \"%6d|%s\\n\", NR+s-1, $0}}'; "
                    f"echo '--- lines {start_line} to {end_line} ---'"
                )
            return _run(session_id, cmd, tool_name="read_file")
        return result

    @mcp.tool()
    def search_file_content(
        session_id: str,
        path: str,
        pattern: str,
        file_filter: str = "*",
        max_results: int = 50,
        context_lines: int = 0,
        modified_after_hours: int = 0,
    ) -> dict[str, Any]:
        """Search for text inside files using grep. Pass a single file path to search that file, or a directory path to search recursively across files matching file_filter. Pattern is treated as a fixed string (literal match, no regex).

        EFFICIENCY GUIDANCE:
        1. SCOPE THE PATH as tightly as possible.
        2. ALWAYS set modified_after_hours when searching directories for recent activity.
        3. USE a precise file_filter to exclude irrelevant files.
        4. PICK a discriminating pattern — distinctive strings return useful results.
        5. KEEP max_results modest (default 50).
        6. FOR A KNOWN SINGLE FILE, pass the file path directly.

        Args:
            session_id: Session ID from connect.
            path: File path, or directory to search recursively.
            pattern: Exact text to search for (literal match, no regex).
            file_filter: Glob filter when path is a directory (e.g. '*.log', '*.conf'). Default '*'.
            max_results: Max matching lines to return (default 50, max 100).
            context_lines: Lines before and after each match, like grep -C (default 0, max 10).
            modified_after_hours: Only search files changed within this many hours (0 = all files).
        """
        safe_path = _sh_escape(path)
        safe_pattern = _sh_escape(pattern)
        safe_filter = _sh_escape(file_filter)
        cap = max(1, min(max_results, 100))
        ctx = max(0, min(context_lines, 10))
        ctx_arg = f"-C {ctx} " if ctx > 0 else ""

        time_filter = ""
        if modified_after_hours > 0:
            time_filter = f"-mmin -{modified_after_hours * 60} "

        cmd = (
            f"if [ -f '{safe_path}' ]; then "
            f"grep -nF {ctx_arg}-m {cap} '{safe_pattern}' '{safe_path}' 2>/dev/null; "
            f"else "
            f"find '{safe_path}' -type f -name '{safe_filter}' {time_filter}"
            f"-exec grep -lF '{safe_pattern}' {{}} + 2>/dev/null "
            f"| head -50 "
            f"| xargs -r grep -nF {ctx_arg}'{safe_pattern}' 2>/dev/null "
            f"| head -{cap}; "
            f"fi"
        )
        return _run(session_id, cmd, tool_name="search_file_content")

    @mcp.tool()
    def file_info(session_id: str, path: str) -> dict[str, Any]:
        """Get metadata for a single file or directory: size, permissions, owner, timestamps, and type. Use this to check file size before reading, or to verify a path exists.

        Args:
            session_id: Session ID from connect.
            path: Absolute path to file or directory.
        """
        safe = _sh_escape(path)
        cmd = (
            f"stat -c '"
            f'{{ "path": "%n", "type": "%F", "size_bytes": %s, '
            f'"size_human": "%s", "permissions": "%A", "octal": "%a", '
            f'"owner": "%U", "group": "%G", '
            f'"modified": "%y", "accessed": "%x", "created": "%w" }}'
            f"' '{safe}' 2>&1"
        )
        return _run(session_id, cmd, tool_name="file_info")

    @mcp.tool()
    def compare_files(
        session_id: str,
        path_a: str,
        path_b: str,
        max_diffs: int = 50,
    ) -> dict[str, Any]:
        """Compare two files and show differences (like diff). Shows line numbers and which file each differing line belongs to. Use to compare configs between environments.

        Args:
            session_id: Session ID from connect.
            path_a: Absolute path to the first file.
            path_b: Absolute path to the second file.
            max_diffs: Maximum number of differing lines to show (default 50).
        """
        safe_a = _sh_escape(path_a)
        safe_b = _sh_escape(path_b)
        cap = max(1, min(max_diffs, 200))
        cmd = (
            f"echo \"File A: {safe_a} ($(wc -l < '{safe_a}') lines)\"; "
            f"echo \"File B: {safe_b} ($(wc -l < '{safe_b}') lines)\"; "
            f"echo; "
            f"diff -u '{safe_a}' '{safe_b}' 2>&1 | head -{cap + 10}"
        )
        return _run(session_id, cmd, tool_name="compare_files")

    # ==================================================================
    # System diagnostics — read-only
    # ==================================================================

    @mcp.tool()
    def get_system_info(session_id: str) -> dict[str, Any]:
        """Get full system overview — hostname, OS, kernel, uptime, last boot, total/free RAM, CPU count, disk summary, and timezone. Call this first after connect for triage context.

        Args:
            session_id: Session ID from connect.
        """
        cmd = (
            "echo '{';"
            'printf \'"hostname": "%s",\\n\' "$(hostname -f 2>/dev/null || hostname)";'
            'printf \'"os": "%s",\\n\' "$(cat /etc/os-release 2>/dev/null | grep ^PRETTY_NAME= | cut -d= -f2- | tr -d \'\\"\')";'
            'printf \'"kernel": "%s",\\n\' "$(uname -r)";'
            'printf \'"arch": "%s",\\n\' "$(uname -m)";'
            'printf \'"uptime": "%s",\\n\' "$(uptime -p 2>/dev/null || uptime)";'
            'printf \'"last_boot": "%s",\\n\' "$(uptime -s 2>/dev/null || who -b | awk \'{print $3,$4}\')";'
            'printf \'"cpu_count": %d,\\n\' "$(nproc 2>/dev/null || grep -c ^processor /proc/cpuinfo)";'
            'printf \'"total_ram_gb": %.1f,\\n\' "$(awk \'/MemTotal/{printf "%.1f", $2/1048576}\' /proc/meminfo)";'
            'printf \'"free_ram_gb": %.1f,\\n\' "$(awk \'/MemAvailable/{printf "%.1f", $2/1048576}\' /proc/meminfo)";'
            'printf \'"timezone": "%s"\\n\' "$(timedatectl show -p Timezone --value 2>/dev/null || cat /etc/timezone 2>/dev/null || date +%Z)";'
            "echo '}'"
        )
        return _run(session_id, cmd, tool_name="get_system_info")

    @mcp.tool()
    def get_disk_space(session_id: str) -> dict[str, Any]:
        """Get disk space for all mounted filesystems — filesystem, size, used, available, use%, and mount point. Disk full is a top-5 cause of production incidents.

        Args:
            session_id: Session ID from connect.
        """
        cmd = "df -hT -x tmpfs -x devtmpfs -x squashfs 2>/dev/null || df -h"
        return _run(session_id, cmd, tool_name="get_disk_space")

    @mcp.tool()
    def list_processes(
        session_id: str,
        name_filter: str = "",
        sort_by: str = "memory",
        top: int = 30,
    ) -> dict[str, Any]:
        """List running processes showing PID, user, CPU%, memory%, VSZ, RSS, start time, elapsed time, and command. Use to identify resource hogs, confirm an application is running, or check for hung processes.

        Args:
            session_id: Session ID from connect.
            name_filter: Filter on command name (e.g. 'java', 'nginx', 'postgres').
            sort_by: Sort by 'cpu' or 'memory' (default memory).
            top: Number of processes to show (default 30, max 100).
        """
        cap = max(1, min(top, 100))
        sort_key = "-%cpu" if sort_by.strip().lower() == "cpu" else "-%mem"

        grep_filter = ""
        if name_filter.strip():
            safe_nf = _sh_escape(name_filter.strip())
            grep_filter = f"| grep -i '{safe_nf}' "

        cmd = (
            f"ps aux --sort={sort_key} "
            f"{grep_filter}"
            f"| head -{cap + 1}"
        )
        return _run(session_id, cmd, tool_name="list_processes")

    @mcp.tool()
    def get_perf_snapshot(session_id: str) -> dict[str, Any]:
        """Capture a performance snapshot — CPU load averages, memory breakdown, swap usage, and top 10 processes by memory and CPU. Use to answer "is the server healthy?" or "is it CPU/memory bound?".

        Args:
            session_id: Session ID from connect.
        """
        cmd = (
            "echo '=== LOAD AVERAGES ==='; "
            "cat /proc/loadavg; "
            "echo; "
            "echo '=== MEMORY ==='; "
            "free -h; "
            "echo; "
            "echo '=== TOP 10 BY MEMORY ==='; "
            "ps aux --sort=-%mem | head -11; "
            "echo; "
            "echo '=== TOP 10 BY CPU ==='; "
            "ps aux --sort=-%cpu | head -11; "
            "echo; "
            "echo '=== DISK I/O ==='; "
            "iostat -x 1 1 2>/dev/null || echo 'iostat not available'; "
        )
        return _run(session_id, cmd, tool_name="get_perf_snapshot")

    @mcp.tool()
    def get_services(
        session_id: str,
        name_filter: str = "",
        status_filter: str = "all",
        detail: bool = False,
    ) -> dict[str, Any]:
        """List systemd services. Summary mode (default) shows unit, load state, active state, sub state, and description. Detail mode shows full service properties for a specific service. Use summary to find services, then detail to inspect.

        Args:
            session_id: Session ID from connect.
            name_filter: Filter on unit name (e.g. 'nginx', 'docker', 'sshd').
            status_filter: 'running', 'failed', 'inactive', or 'all' (default).
            detail: Show full systemctl status output for matched services.
        """
        if detail and name_filter.strip():
            safe_nf = _sh_escape(name_filter.strip())
            cmd = f"systemctl status '{safe_nf}' --no-pager -l 2>&1"
        else:
            state_arg = ""
            sf = status_filter.strip().lower()
            if sf == "running":
                state_arg = "--state=running "
            elif sf == "failed":
                state_arg = "--state=failed "
            elif sf == "inactive":
                state_arg = "--state=inactive "

            grep_filter = ""
            if name_filter.strip():
                safe_nf = _sh_escape(name_filter.strip())
                grep_filter = f"| grep -i '{safe_nf}' "

            cmd = (
                f"systemctl list-units --type=service {state_arg}"
                f"--no-pager --no-legend 2>/dev/null "
                f"{grep_filter}"
                f"| head -100"
            )
        return _run(session_id, cmd, tool_name="get_services")

    @mcp.tool()
    def get_journal_logs(
        session_id: str,
        unit: str = "",
        level: str = "",
        hours_back: int = 24,
        count: int = 50,
        grep_pattern: str = "",
    ) -> dict[str, Any]:
        """Read systemd journal logs — the primary diagnostic source for service failures, crashes, and system events. Equivalent to Windows Event Log. Filter by unit, severity, time range, or grep pattern.

        Args:
            session_id: Session ID from connect.
            unit: Systemd unit name (e.g. 'nginx.service', 'docker.service'). Empty = all units.
            level: Minimum severity: emerg, alert, crit, err, warning, notice, info, debug. Empty = all.
            hours_back: How far back to search in hours (default 24, max 720).
            count: Max log entries to return (default 50, max 200).
            grep_pattern: Filter log messages containing this text (literal match).
        """
        hrs = max(1, min(hours_back, 720))
        cap = max(1, min(count, 200))

        parts = [f"journalctl --no-pager -q --since='{hrs} hours ago'"]
        if unit.strip():
            safe_unit = _sh_escape(unit.strip())
            parts.append(f"-u '{safe_unit}'")
        if level.strip():
            safe_level = _sh_escape(level.strip().lower())
            parts.append(f"-p '{safe_level}'")
        parts.append(f"-n {cap}")

        if grep_pattern.strip():
            safe_grep = _sh_escape(grep_pattern.strip())
            parts.append(f"--grep='{safe_grep}'")

        cmd = " ".join(parts) + " 2>&1"
        return _run(session_id, cmd, tool_name="get_journal_logs")

    @mcp.tool()
    def get_tcp_connections(
        session_id: str,
        state_filter: str = "established",
        port_filter: int = 0,
    ) -> dict[str, Any]:
        """List active TCP connections showing local/remote addresses, ports, state, and owning process. Like 'ss -tnp'. Use to check database connections, find connection leaks, or see what is talking to what.

        Args:
            session_id: Session ID from connect.
            state_filter: Filter by state: established (default), listen, time-wait, close-wait, all.
            port_filter: Only show connections involving this port (0 = all ports).
        """
        sf = state_filter.strip().lower()

        port_grep = ""
        if port_filter > 0:
            port_grep = f"| grep -E ':{port_filter}\\b' "

        state_grep = ""
        if sf == "listen":
            state_grep = "| grep -i LISTEN "
        elif sf == "established":
            state_grep = "| grep -i ESTAB "
        elif sf == "time-wait":
            state_grep = "| grep -i TIME.WAIT "
        elif sf == "close-wait":
            state_grep = "| grep -i CLOSE.WAIT "

        cmd = (
            f"/usr/sbin/ss -tnp 2>/dev/null || ss -tnp 2>/dev/null || "
            f"netstat -tnp 2>/dev/null | "
            f"head -200 {state_grep}{port_grep}| head -100"
        )
        return _run(session_id, cmd, tool_name="get_tcp_connections")

    @mcp.tool()
    def get_network_config(session_id: str) -> dict[str, Any]:
        """Get network configuration — interfaces, IP addresses, routes, and DNS servers. Essential for network triage.

        Args:
            session_id: Session ID from connect.
        """
        cmd = (
            "echo '=== INTERFACES ==='; "
            "/usr/sbin/ip -br addr 2>/dev/null || ip -br addr 2>/dev/null || ifconfig 2>/dev/null; "
            "echo; "
            "echo '=== ROUTES ==='; "
            "/usr/sbin/ip route 2>/dev/null || ip route 2>/dev/null || route -n 2>/dev/null; "
            "echo; "
            "echo '=== DNS ==='; "
            "cat /etc/resolv.conf 2>/dev/null"
        )
        return _run(session_id, cmd, tool_name="get_network_config")

    @mcp.tool()
    def test_network(
        session_id: str,
        target: str,
        port: int = 0,
    ) -> dict[str, Any]:
        """Test network connectivity FROM the remote Linux host. With port=0 sends 3 ICMP pings. With port>0 tests TCP connectivity using nc/ncat. Common ports: 5432 Postgres, 3306 MySQL, 443 HTTPS, 22 SSH, 8080 HTTP.

        Args:
            session_id: Session ID from connect.
            target: Hostname or IP to test connectivity to.
            port: TCP port to test. Set 0 for ICMP ping (default), or a port number for TCP test.
        """
        safe_target = _sh_escape(target)
        if port > 0:
            cmd = (
                f"timeout 10 bash -c '"
                f"echo > /dev/tcp/{safe_target}/{port} && "
                f"echo \"TCP connection to {safe_target}:{port} SUCCEEDED\" || "
                f"echo \"TCP connection to {safe_target}:{port} FAILED\"' 2>&1 || "
                f"nc -zv -w5 '{safe_target}' {port} 2>&1 || "
                f"echo 'Neither /dev/tcp nor nc available'"
            )
        else:
            cmd = f"ping -c 3 -W 5 '{safe_target}' 2>&1"
        return _run(session_id, cmd, tool_name="test_network")

    @mcp.tool()
    def resolve_dns(
        session_id: str,
        name: str,
        record_type: str = "A",
    ) -> dict[str, Any]:
        """Resolve a DNS name from the remote server's perspective. Use to verify DNS propagation or check what IP a hostname resolves to.

        Args:
            session_id: Session ID from connect.
            name: Hostname or FQDN to resolve.
            record_type: DNS record type: A (default), AAAA, CNAME, MX, NS, PTR, SOA, SRV, TXT.
        """
        safe_name = _sh_escape(name)
        safe_type = _sh_escape(record_type.strip().upper())
        cmd = (
            f"dig +short '{safe_name}' {safe_type} 2>/dev/null || "
            f"nslookup '{safe_name}' 2>/dev/null || "
            f"getent hosts '{safe_name}' 2>/dev/null"
        )
        return _run(session_id, cmd, tool_name="resolve_dns")

    @mcp.tool()
    def get_environment_variables(
        session_id: str,
        name_filter: str = "",
    ) -> dict[str, Any]:
        """Get environment variables. Shows name and value, optionally filtered by name pattern.

        Args:
            session_id: Session ID from connect.
            name_filter: Grep filter on variable name (e.g. 'JAVA', 'PATH', 'HOME'). Empty = all.
        """
        grep_filter = ""
        if name_filter.strip():
            safe_nf = _sh_escape(name_filter.strip())
            grep_filter = f"| grep -i '{safe_nf}' "
        cmd = f"env {grep_filter}| sort"
        return _run(session_id, cmd, tool_name="get_environment_variables")

    @mcp.tool()
    def get_cron_jobs(
        session_id: str,
        user: str = "",
    ) -> dict[str, Any]:
        """List cron jobs. Shows user crontab and system cron directories. Use to understand automated jobs on this server.

        Args:
            session_id: Session ID from connect.
            user: Specific user's crontab to check. Empty = current user + system cron.
        """
        if user.strip():
            safe_user = _sh_escape(user.strip())
            cmd = f"crontab -u '{safe_user}' -l 2>&1"
        else:
            cmd = (
                "echo '=== USER CRONTAB ==='; "
                "crontab -l 2>&1; "
                "echo; "
                "echo '=== /etc/crontab ==='; "
                "cat /etc/crontab 2>/dev/null; "
                "echo; "
                "echo '=== /etc/cron.d/ ==='; "
                "ls -la /etc/cron.d/ 2>/dev/null; "
                "echo; "
                "for f in /etc/cron.d/*; do "
                "[ -f \"$f\" ] && echo \"--- $f ---\" && cat \"$f\" 2>/dev/null && echo; "
                "done"
            )
        return _run(session_id, cmd, tool_name="get_cron_jobs")

    @mcp.tool()
    def get_users(session_id: str, system_users: bool = False) -> dict[str, Any]:
        """List user accounts on the server. By default shows only human/service accounts (UID >= 1000). Shows username, UID, GID, home directory, shell, and last login.

        Args:
            session_id: Session ID from connect.
            system_users: Include system accounts with UID < 1000 (default False).
        """
        uid_filter = "" if system_users else "| awk -F: '$3 >= 1000'"
        cmd = (
            f"echo '=== USERS ==='; "
            f"cat /etc/passwd {uid_filter}; "
            f"echo; "
            f"echo '=== LAST LOGINS ==='; "
            f"last -n 20 2>/dev/null | head -25"
        )
        return _run(session_id, cmd, tool_name="get_users")

    @mcp.tool()
    def get_permissions(session_id: str, path: str) -> dict[str, Any]:
        """Get file/directory permissions, ownership, and ACLs. Essential for troubleshooting "permission denied" errors.

        Args:
            session_id: Session ID from connect.
            path: Absolute path to the file or folder to check.
        """
        safe = _sh_escape(path)
        cmd = (
            f"echo '=== STAT ==='; "
            f"stat '{safe}' 2>&1; "
            f"echo; "
            f"echo '=== ACL ==='; "
            f"getfacl '{safe}' 2>/dev/null || echo 'getfacl not available'"
        )
        return _run(session_id, cmd, tool_name="get_permissions")

    # ==================================================================
    # Docker — read-only
    # ==================================================================

    @mcp.tool()
    def get_docker(
        session_id: str,
        subcommand: str = "ps",
        target: str = "",
        tail: int = 100,
    ) -> dict[str, Any]:
        """Inspect Docker containers. Subcommands:
        - 'ps': List all containers with status, ports, and image (default).
        - 'logs': Show last N lines of a container's logs (requires target=container name or ID).
        - 'inspect': Full container config, mounts, networking (requires target).
        - 'stats': Live CPU/memory/network per container (single snapshot).
        - 'images': List Docker images on the host.

        Args:
            session_id: Session ID from connect.
            subcommand: One of 'ps', 'logs', 'inspect', 'stats', 'images'.
            target: Container name or ID — required for 'logs' and 'inspect'.
            tail: Number of log lines for 'logs' subcommand (default 100, max 500).
        """
        sub = subcommand.strip().lower()
        if sub == "ps":
            cmd = "docker ps -a --format 'table {{.Names}}\t{{.Status}}\t{{.Image}}\t{{.Ports}}\t{{.RunningFor}}' 2>&1"
        elif sub == "logs":
            if not target.strip():
                return {"error": "target (container name or ID) is required for 'logs'"}
            safe_t = _sh_escape(target.strip())
            cap = max(1, min(tail, 500))
            cmd = f"docker logs --tail {cap} --timestamps '{safe_t}' 2>&1"
        elif sub == "inspect":
            if not target.strip():
                return {"error": "target (container name or ID) is required for 'inspect'"}
            safe_t = _sh_escape(target.strip())
            cmd = f"docker inspect '{safe_t}' 2>&1 | head -300"
        elif sub == "stats":
            cmd = "docker stats --no-stream --format 'table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.MemPerc}}\t{{.NetIO}}\t{{.BlockIO}}\t{{.PIDs}}' 2>&1"
        elif sub == "images":
            cmd = "docker images --format 'table {{.Repository}}\t{{.Tag}}\t{{.Size}}\t{{.CreatedSince}}\t{{.ID}}' 2>&1"
        else:
            return {"error": f"Unknown subcommand '{subcommand}'. Valid: ps, logs, inspect, stats, images"}
        return _run(session_id, cmd, tool_name="get_docker")

    # ==================================================================
    # Disk, kernel, file descriptors, certs, firewall — read-only
    # ==================================================================

    @mcp.tool()
    def get_disk_usage(
        session_id: str,
        path: str = "/",
        depth: int = 1,
        top: int = 20,
    ) -> dict[str, Any]:
        """Show disk usage by directory — answers "what is eating the disk?" Sorted largest-first. Use after get_disk_space identifies a full filesystem to drill into the specific directory consuming space.

        Args:
            session_id: Session ID from connect.
            path: Directory to analyze (e.g. '/var', '/opt', '/').
            depth: How many levels deep to report (default 1, max 3).
            top: Number of largest entries to show (default 20, max 50).
        """
        safe = _sh_escape(path)
        d = max(1, min(depth, 3))
        cap = max(1, min(top, 50))
        cmd = (
            f"du -xh --max-depth={d} '{safe}' 2>/dev/null "
            f"| sort -rh | head -{cap}"
        )
        return _run(session_id, cmd, tool_name="get_disk_usage")

    @mcp.tool()
    def get_dmesg(
        session_id: str,
        count: int = 50,
        level: str = "",
        grep_pattern: str = "",
    ) -> dict[str, Any]:
        """Read kernel ring buffer (dmesg) — catches OOM kills, disk I/O errors, hardware failures, NIC flaps, and other low-level events that don't appear in journalctl or application logs. Check this when a process was killed unexpectedly or hardware is suspected.

        Args:
            session_id: Session ID from connect.
            count: Number of most recent messages to show (default 50, max 200).
            grep_pattern: Filter messages containing this text (e.g. 'oom', 'error', 'sda', 'eth0').
            level: Kernel log level filter: emerg, alert, crit, err, warn, notice, info, debug. Empty = all.
        """
        cap = max(1, min(count, 200))
        level_arg = ""
        if level.strip():
            safe_level = _sh_escape(level.strip().lower())
            level_arg = f"--level={safe_level} "
        grep_pipe = ""
        if grep_pattern.strip():
            safe_grep = _sh_escape(grep_pattern.strip())
            grep_pipe = f"| grep -i '{safe_grep}' "
        cmd = (
            f"dmesg -T {level_arg}2>/dev/null "
            f"| tail -{cap * 2} {grep_pipe}| tail -{cap}"
        )
        return _run(session_id, cmd, tool_name="get_dmesg")

    @mcp.tool()
    def get_open_files(
        session_id: str,
        pid: int = 0,
    ) -> dict[str, Any]:
        """Check file descriptor usage — diagnoses "too many open files" errors. With pid=0 shows system-wide fd stats and per-process top consumers. With a specific PID shows that process's fd count, limits, and open file types.

        Args:
            session_id: Session ID from connect.
            pid: Process ID to inspect. 0 = system-wide overview (default).
        """
        if pid > 0:
            cmd = (
                f"echo '=== FD COUNT ==='; "
                f"ls /proc/{pid}/fd 2>/dev/null | wc -l; "
                f"echo; "
                f"echo '=== FD LIMITS ==='; "
                f"grep -E 'open files' /proc/{pid}/limits 2>/dev/null; "
                f"echo; "
                f"echo '=== FD TYPES ==='; "
                f"ls -la /proc/{pid}/fd 2>/dev/null | awk '{{print $NF}}' "
                f"| sed 's|.*socket.*|socket|; s|.*pipe.*|pipe|; s|/.*|file|' "
                f"| sort | uniq -c | sort -rn; "
                f"echo; "
                f"echo '=== PROCESS ==='; "
                f"ps -p {pid} -o pid,user,%mem,etime,comm --no-headers 2>&1"
            )
        else:
            cmd = (
                "echo '=== SYSTEM FD USAGE ==='; "
                "cat /proc/sys/fs/file-nr; "
                "echo '(allocated  free  max)'; "
                "echo; "
                "echo '=== TOP 15 FD CONSUMERS ==='; "
                "for p in /proc/[0-9]*/fd; do "
                "pid=$(echo $p | cut -d/ -f3); "
                "count=$(ls $p 2>/dev/null | wc -l); "
                "comm=$(cat /proc/$pid/comm 2>/dev/null); "
                "echo \"$count $pid $comm\"; "
                "done 2>/dev/null | sort -rn | head -15 | "
                "awk '{printf \"%6d fds  PID %-8s %s\\n\", $1, $2, $3}'"
            )
        return _run(session_id, cmd, tool_name="get_open_files")

    @mcp.tool()
    def get_certificates(
        session_id: str,
        path: str = "",
        host: str = "",
        port: int = 443,
    ) -> dict[str, Any]:
        """Check TLS certificate expiry and details. Two modes:
        - File mode (path set): reads a PEM/CRT file and shows subject, issuer, dates, and days until expiry.
        - Network mode (host set): probes a remote TLS endpoint and shows the served certificate.
        Cert expiry is a top cause of silent outages.

        Args:
            session_id: Session ID from connect.
            path: Path to a PEM or CRT certificate file. Mutually exclusive with host.
            host: Hostname to probe via TLS (e.g. 'localhost', 'api.example.com'). Mutually exclusive with path.
            port: Port for TLS probe (default 443). Common: 443 HTTPS, 8443 alt-HTTPS, 636 LDAPS.
        """
        if path.strip() and host.strip():
            return {"error": "Provide either path or host, not both"}
        if not path.strip() and not host.strip():
            return {"error": "Provide either path (cert file) or host (TLS endpoint)"}

        if path.strip():
            safe = _sh_escape(path.strip())
            cmd = (
                f"openssl x509 -in '{safe}' -noout "
                f"-subject -issuer -dates -serial -fingerprint 2>&1; "
                f"echo; "
                f"echo '=== DAYS UNTIL EXPIRY ==='; "
                f"EXP=$(openssl x509 -in '{safe}' -noout -enddate 2>/dev/null "
                f"| cut -d= -f2); "
                f"echo $(( ($(date -d \"$EXP\" +%s) - $(date +%s)) / 86400 )) days"
            )
        else:
            safe_host = _sh_escape(host.strip())
            cmd = (
                f"echo | openssl s_client -connect '{safe_host}:{port}' "
                f"-servername '{safe_host}' 2>/dev/null "
                f"| openssl x509 -noout -subject -issuer -dates -serial 2>&1; "
                f"echo; "
                f"echo '=== DAYS UNTIL EXPIRY ==='; "
                f"EXP=$(echo | openssl s_client -connect '{safe_host}:{port}' "
                f"-servername '{safe_host}' 2>/dev/null "
                f"| openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2); "
                f"echo $(( ($(date -d \"$EXP\" +%s) - $(date +%s)) / 86400 )) days"
            )
        return _run(session_id, cmd, tool_name="get_certificates")

    @mcp.tool()
    def get_firewall_rules(
        session_id: str,
        zone: str = "",
    ) -> dict[str, Any]:
        """Show firewall rules. Tries firewalld first (RHEL/CentOS), then falls back to iptables. Use when network connectivity tests fail to determine if a firewall rule is blocking traffic.

        Args:
            session_id: Session ID from connect.
            zone: Firewalld zone to inspect (e.g. 'public', 'internal'). Empty = default zone + all zones summary.
        """
        if zone.strip():
            safe_zone = _sh_escape(zone.strip())
            cmd = f"firewall-cmd --zone='{safe_zone}' --list-all 2>&1"
        else:
            cmd = (
                "echo '=== FIREWALLD ==='; "
                "firewall-cmd --state 2>/dev/null && "
                "firewall-cmd --list-all 2>/dev/null && "
                "echo && echo '=== ALL ZONES ===' && "
                "firewall-cmd --get-active-zones 2>/dev/null || "
                "echo '(firewalld not active)'; "
                "echo; "
                "echo '=== IPTABLES ==='; "
                "iptables -L -n --line-numbers 2>/dev/null | head -80 || "
                "echo '(iptables not available)'"
            )
        return _run(session_id, cmd, tool_name="get_firewall_rules")

    # ==================================================================
    # JBoss EAP / WildFly diagnostics
    # ==================================================================

    def _jboss_discovery_functions(instance: str = "") -> str:
        safe_instance = _sh_escape(instance.strip())
        return f"""
JBOSS_INSTANCE_MATCH='{safe_instance}'

_jboss_rows() {{
  for pid in $(pgrep -f 'jboss.home.dir|jboss-modules.jar|org.jboss|wildfly' 2>/dev/null | sort -n); do
    [ -r "/proc/$pid/cmdline" ] || continue
    comm=$(ps -p "$pid" -o comm= 2>/dev/null | awk '{{print $1}}')
    case "$comm" in
      java|java*) ;;
      *) continue ;;
    esac
    cmdline=$(tr '\\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null)
    case "$cmdline" in
      *jboss.home.dir*|*jboss-modules.jar*|*wildfly*) printf '%s|%s\\n' "$pid" "$cmdline" ;;
    esac
  done
}}

_jboss_prop() {{
  printf '%s\\n' "$JBOSS_CMDLINE" | sed -n "s/.*-D$1=\\([^ ]*\\).*/\\1/p" | head -1
}}

_select_jboss() {{
  JBOSS_ROWS="$(_jboss_rows)"
  if [ -z "$JBOSS_ROWS" ]; then
    echo 'ERROR: no JBoss/WildFly Java process found' >&2
    return 1
  fi

  if [ -n "$JBOSS_INSTANCE_MATCH" ]; then
    JBOSS_ROW=$(printf '%s\\n' "$JBOSS_ROWS" | awk -F'|' -v m="$JBOSS_INSTANCE_MATCH" '$1 == m || index($0, m) > 0 {{ print; exit }}')
    if [ -z "$JBOSS_ROW" ]; then
      echo "ERROR: JBoss instance '$JBOSS_INSTANCE_MATCH' not found. Run discover_jboss first." >&2
      return 1
    fi
  else
    row_count=$(printf '%s\\n' "$JBOSS_ROWS" | sed '/^$/d' | wc -l | tr -d ' ')
    if [ "$row_count" -gt 1 ]; then
      echo 'ERROR: multiple JBoss/WildFly processes found. Run discover_jboss and pass instance=<pid>.' >&2
      printf '%s\\n' "$JBOSS_ROWS" | cut -d'|' -f1 | sed 's/^/  PID /' >&2
      return 1
    fi
    JBOSS_ROW="$JBOSS_ROWS"
  fi

  JBOSS_PID=${{JBOSS_ROW%%|*}}
  JBOSS_CMDLINE=${{JBOSS_ROW#*|}}
  JBOSS_USER=$(ps -p "$JBOSS_PID" -o user= 2>/dev/null | awk '{{print $1}}')
  JBOSS_HOME=$(_jboss_prop 'jboss.home.dir')
  JBOSS_BASE=$(_jboss_prop 'jboss.server.base.dir')
  JBOSS_CONFIG=$(_jboss_prop 'jboss.server.config.file')
  [ -z "$JBOSS_BASE" ] && [ -n "$JBOSS_HOME" ] && JBOSS_BASE="$JBOSS_HOME/standalone"

  JBOSS_CLI=''
  for candidate in \
    "$JBOSS_HOME/bin/jboss-cli.sh" \
    "$JBOSS_BASE/../bin/jboss-cli.sh" \
    /opt/rh/eap*/root/usr/share/wildfly/bin/jboss-cli.sh \
    /opt/wildfly/bin/jboss-cli.sh \
    /opt/jboss*/bin/jboss-cli.sh \
    /usr/share/wildfly/bin/jboss-cli.sh; do
    if [ -x "$candidate" ]; then
      JBOSS_CLI="$candidate"
      break
    fi
  done

  JAVA_EXE=$(readlink -f "/proc/$JBOSS_PID/exe" 2>/dev/null || true)
  JAVA_BIN_DIR=$(dirname "$JAVA_EXE" 2>/dev/null || true)
  JSTACK="$JAVA_BIN_DIR/jstack"
  JCMD="$JAVA_BIN_DIR/jcmd"
  JSTAT="$JAVA_BIN_DIR/jstat"
  [ -x "$JSTACK" ] || JSTACK=$(command -v jstack 2>/dev/null || true)
  [ -x "$JCMD" ] || JCMD=$(command -v jcmd 2>/dev/null || true)
  [ -x "$JSTAT" ] || JSTAT=$(command -v jstat 2>/dev/null || true)

  APP_LOG_DIR=''
  for candidate in "$JBOSS_BASE/log" "$JBOSS_HOME/standalone/log"; do
    if [ -d "$candidate" ]; then
      APP_LOG_DIR="$candidate"
      break
    fi
  done
}}

_jboss_cli() {{
  if [ -z "$JBOSS_CLI" ]; then
    echo "ERROR: jboss-cli.sh not found for PID $JBOSS_PID. Run discover_jboss for detected paths." >&2
    return 1
  fi
  run_cli=''
  if [ -n "$JBOSS_USER" ] && [ "$(id -un 2>/dev/null)" != "$JBOSS_USER" ] && command -v sudo >/dev/null 2>&1; then
    run_cli="sudo -n -u $JBOSS_USER"
  fi
  if command -v timeout >/dev/null 2>&1; then
    if [ -n "$run_cli" ]; then
      timeout 25s $run_cli "$JBOSS_CLI" -c --command="$1" 2>/dev/null || timeout 25s "$JBOSS_CLI" -c --command="$1"
    else
      timeout 25s "$JBOSS_CLI" -c --command="$1"
    fi
  else
    if [ -n "$run_cli" ]; then
      $run_cli "$JBOSS_CLI" -c --command="$1" 2>/dev/null || "$JBOSS_CLI" -c --command="$1"
    else
      "$JBOSS_CLI" -c --command="$1"
    fi
  fi
}}

_run_as_jboss_user() {{
  if [ -n "$JBOSS_USER" ] && [ "$(id -un 2>/dev/null)" != "$JBOSS_USER" ] && command -v sudo >/dev/null 2>&1; then
    sudo -n -u "$JBOSS_USER" "$@" 2>/dev/null || "$@"
  else
    "$@"
  fi
}}
"""

    def _jboss_select_cmd(instance: str = "") -> str:
        return _jboss_discovery_functions(instance) + "\n_select_jboss || exit 1\n"

    @mcp.tool()
    def discover_jboss(session_id: str) -> dict[str, Any]:
        """Discover running JBoss EAP/WildFly JVMs and their useful paths. Call this first when troubleshooting JBoss, especially if the host may have multiple instances.

        Returns PID, OS user, jboss.home.dir, server base dir, config file, CLI path,
        Java tools path, and likely log directories. Use the PID as instance=... for
        other JBoss tools when more than one JVM is found.

        Args:
            session_id: Session ID from connect.
        """
        cmd = (
            _jboss_discovery_functions()
            + """
rows="$(_jboss_rows)"
if [ -z "$rows" ]; then
  echo 'ERROR: no JBoss/WildFly Java process found'
  exit 1
fi

idx=0
printf '%s\\n' "$rows" | while IFS='|' read -r pid cmdline; do
  [ -n "$pid" ] || continue
  idx=$((idx + 1))
  JBOSS_PID="$pid"
  JBOSS_CMDLINE="$cmdline"
  JBOSS_USER=$(ps -p "$JBOSS_PID" -o user= 2>/dev/null | awk '{print $1}')
  JBOSS_HOME=$(_jboss_prop 'jboss.home.dir')
  JBOSS_BASE=$(_jboss_prop 'jboss.server.base.dir')
  JBOSS_CONFIG=$(_jboss_prop 'jboss.server.config.file')
  [ -z "$JBOSS_BASE" ] && [ -n "$JBOSS_HOME" ] && JBOSS_BASE="$JBOSS_HOME/standalone"
  OLD_JBOSS_INSTANCE_MATCH="$JBOSS_INSTANCE_MATCH"
  JBOSS_INSTANCE_MATCH="$JBOSS_PID"
  _select_jboss >/dev/null 2>&1 || true
  JBOSS_INSTANCE_MATCH="$OLD_JBOSS_INSTANCE_MATCH"

  echo "=== JBOSS INSTANCE $idx ==="
  echo "instance_pid=$JBOSS_PID"
  echo "user=$JBOSS_USER"
  echo "home=${JBOSS_HOME:-unknown}"
  echo "base=${JBOSS_BASE:-unknown}"
  echo "config=${JBOSS_CONFIG:-standalone.xml}"
  echo "cli=${JBOSS_CLI:-not-found}"
  echo "java=${JAVA_EXE:-unknown}"
  echo "jstack=${JSTACK:-not-found}"
  echo "jcmd=${JCMD:-not-found}"
  echo "jstat=${JSTAT:-not-found}"
  echo "preferred_log_dir=${APP_LOG_DIR:-not-found}"
  echo "cmdline=$(printf '%s' "$JBOSS_CMDLINE" | cut -c1-400)"
  echo
done
"""
        )
        return _run(session_id, cmd, tool_name="discover_jboss")

    @mcp.tool()
    def get_jboss_server_log(
        session_id: str,
        pattern: str = "",
        hours_back: int = 1,
        log_type: str = "server",
        count: int = 50,
        instance: str = "",
        log_dir: str = "",
    ) -> dict[str, Any]:
        """Search JBoss/WildFly logs for errors while preserving filename context.

        Defaults to searching for ERROR/FATAL/Exception entries. Use a specific pattern for targeted searches.

        High-value error patterns to search for:
        - 'OutOfMemoryError' — JVM heap exhaustion, requires restart
        - 'ConnectionNotFoundException' — DB connection pool exhausted
        - 'RESTEASY004655' — REST client failure
        - 'No buffer space available' — socket/fd exhaustion
        - 'Connection refused' — downstream service unreachable
        - 'StackOverflowError' — infinite recursion
        - 'pool' — connection pool messages

        Args:
            session_id: Session ID from connect.
            pattern: Text to search for (case-insensitive). Empty = search for ERROR, FATAL, OutOfMemoryError, Exception.
            log_type: 'server' (default), 'batch', 'gc', or 'all'.
            hours_back: Only search files modified within this many hours (default 1, max 72). Set higher for historical analysis.
            count: Max matching lines to return (default 50, max 200).
            instance: Optional PID from discover_jboss when multiple JBoss JVMs are present.
            log_dir: Optional explicit log directory. Empty = discovered JBoss log directory.
        """
        hrs = max(1, min(hours_back, 72))
        cap = max(1, min(count, 200))
        safe_dir = _sh_escape(log_dir.strip())
        safe_type = _sh_escape(log_type.strip().lower())
        search_pattern = pattern.strip() if pattern.strip() else "ERROR\\|FATAL\\|OutOfMemoryError\\|Exception"
        safe_pattern = _sh_escape(search_pattern)
        cmd = (
            _jboss_select_cmd(instance)
            + f"REQUESTED_LOG_DIR='{safe_dir}'; "
            + f"LOG_TYPE='{safe_type}'; "
            + f"SEARCH_PATTERN='{safe_pattern}'; "
            + f"HOURS_BACK={hrs}; "
            + f"CAP={cap}; "
            + "SEARCH_DIR=\"$REQUESTED_LOG_DIR\"; "
            + "[ -z \"$SEARCH_DIR\" ] && SEARCH_DIR=\"$APP_LOG_DIR\"; "
            + "[ -z \"$SEARCH_DIR\" ] && SEARCH_DIR=\"$JBOSS_BASE/log\"; "
            + "if [ -z \"$SEARCH_DIR\" ] || [ ! -d \"$SEARCH_DIR\" ]; then echo 'ERROR: no readable log directory discovered'; exit 1; fi; "
            + "echo \"=== LOG SEARCH ===\"; "
            + "echo \"dir=$SEARCH_DIR type=$LOG_TYPE hours_back=$HOURS_BACK pattern=$SEARCH_PATTERN\"; "
            + "case \"$LOG_TYPE\" in "
            + "gc) NAME_EXPR=\"-iname '*gc*.log'\" ;; "
            + "batch) NAME_EXPR=\"-iname 'batch-trace-*.log' -o -iname '*batch*.log'\" ;; "
            + "all) NAME_EXPR=\"-iname '*.log'\" ;; "
            + "*) NAME_EXPR=\"-iname 'server-*.log' -o -iname 'server.log'\" ;; "
            + "esac; "
            + "eval \"find \\\"$SEARCH_DIR\\\" -type f \\( $NAME_EXPR \\) -mmin -$((HOURS_BACK * 60)) -printf '%T@ %p\\n'\" 2>/dev/null "
            + "| sort -nr | head -10 | cut -d' ' -f2- "
            + f"| xargs -r grep -EinH '{safe_pattern}' 2>/dev/null "
            + "| tail -$CAP"
        )
        return _run(session_id, cmd, tool_name="get_jboss_server_log")

    # ==================================================================
    # Write operations (all require user confirmation via elicitation)
    # ==================================================================

    async def _confirm(ctx: Context, action: str, details: str) -> bool:
        """Prompt the user to confirm a destructive/modifying action."""
        try:
            result = await ctx.elicit(
                message=f"Confirm {action}?\n\n{details}",
                response_type=None,
            )
            return result.action == "accept"
        except Exception:
            logger.error("Elicitation unavailable — rejecting modification")
            return False

    @mcp.tool()
    async def restart_service(
        session_id: str,
        name: str,
        ctx: Context,
    ) -> dict[str, Any]:
        """Restart a systemd service. Captures service state before and after the restart and prompts the user for confirmation.

        Args:
            session_id: Session ID from connect.
            name: Systemd unit name (e.g. 'nginx.service', 'docker.service').
        """
        safe = _sh_escape(name)
        pre = _run(session_id, f"systemctl status '{safe}' --no-pager -l 2>&1 | head -20", tool_name="restart_service")
        if "error" in pre:
            return pre
        pre_stdout = pre.get("stdout", "").strip()

        confirmed = await _confirm(
            ctx, "RESTART SERVICE",
            f"Service: {name}\nCurrent state:\n{pre_stdout}\n\nThis will briefly stop and restart the service.",
        )
        if not confirmed:
            return {"status": "cancelled", "message": "Restart cancelled by user"}

        cmd = (
            f"systemctl restart '{safe}' 2>&1 && sleep 2 && "
            f"systemctl status '{safe}' --no-pager -l 2>&1 | head -20"
        )
        post = _run(session_id, cmd, tool_name="restart_service")
        return {
            "pre_state": pre_stdout,
            "post_state": post.get("stdout", "").strip(),
            "exit_code": post.get("exit_code"),
            "stderr": post.get("stderr", ""),
            "elapsed_ms": post.get("elapsed_ms"),
        }

    @mcp.tool()
    async def stop_service(
        session_id: str,
        name: str,
        ctx: Context,
    ) -> dict[str, Any]:
        """Stop a running systemd service. Captures state before and after, prompts the user for confirmation.

        Args:
            session_id: Session ID from connect.
            name: Systemd unit name (e.g. 'nginx.service').
        """
        safe = _sh_escape(name)
        pre = _run(session_id, f"systemctl status '{safe}' --no-pager -l 2>&1 | head -20", tool_name="stop_service")
        if "error" in pre:
            return pre
        pre_stdout = pre.get("stdout", "").strip()

        confirmed = await _confirm(
            ctx, "STOP SERVICE",
            f"Service: {name}\nCurrent state:\n{pre_stdout}\n\nThis will stop the service. It will NOT restart automatically.",
        )
        if not confirmed:
            return {"status": "cancelled", "message": "Stop cancelled by user"}

        cmd = (
            f"systemctl stop '{safe}' 2>&1 && sleep 2 && "
            f"systemctl status '{safe}' --no-pager -l 2>&1 | head -20"
        )
        post = _run(session_id, cmd, tool_name="stop_service")
        return {
            "pre_state": pre_stdout,
            "post_state": post.get("stdout", "").strip(),
            "exit_code": post.get("exit_code"),
            "stderr": post.get("stderr", ""),
            "elapsed_ms": post.get("elapsed_ms"),
        }

    @mcp.tool()
    async def start_service(
        session_id: str,
        name: str,
        ctx: Context,
    ) -> dict[str, Any]:
        """Start a stopped systemd service. Captures state before and after, prompts the user for confirmation.

        Args:
            session_id: Session ID from connect.
            name: Systemd unit name (e.g. 'nginx.service').
        """
        safe = _sh_escape(name)
        pre = _run(session_id, f"systemctl status '{safe}' --no-pager -l 2>&1 | head -20", tool_name="start_service")
        if "error" in pre:
            return pre
        pre_stdout = pre.get("stdout", "").strip()

        confirmed = await _confirm(
            ctx, "START SERVICE",
            f"Service: {name}\nCurrent state:\n{pre_stdout}",
        )
        if not confirmed:
            return {"status": "cancelled", "message": "Start cancelled by user"}

        cmd = (
            f"systemctl start '{safe}' 2>&1 && sleep 2 && "
            f"systemctl status '{safe}' --no-pager -l 2>&1 | head -20"
        )
        post = _run(session_id, cmd, tool_name="start_service")
        return {
            "pre_state": pre_stdout,
            "post_state": post.get("stdout", "").strip(),
            "exit_code": post.get("exit_code"),
            "stderr": post.get("stderr", ""),
            "elapsed_ms": post.get("elapsed_ms"),
        }

    @mcp.tool()
    async def kill_process(
        session_id: str,
        pid: int,
        ctx: Context,
    ) -> dict[str, Any]:
        """Kill a process by PID. Captures process details before killing and shows them in the confirmation prompt.

        Args:
            session_id: Session ID from connect.
            pid: Process ID to kill. Use list_processes to find the correct PID.
        """
        pre = _run(
            session_id,
            f"ps -p {pid} -o pid,user,%cpu,%mem,etime,comm --no-headers 2>&1",
            tool_name="kill_process",
        )
        if "error" in pre:
            return pre
        pre_stdout = pre.get("stdout", "").strip()

        confirmed = await _confirm(
            ctx, "KILL PROCESS",
            f"PID: {pid}\nProcess details: {pre_stdout}\n\nThis will FORCE TERMINATE the process immediately.",
        )
        if not confirmed:
            return {"status": "cancelled", "message": "Kill cancelled by user"}

        cmd = (
            f"kill -9 {pid} 2>&1; sleep 0.5; "
            f"if ps -p {pid} > /dev/null 2>&1; then "
            f"echo 'WARNING: process still running'; "
            f"else echo 'Confirmed: process {pid} terminated'; fi"
        )
        post = _run(session_id, cmd, tool_name="kill_process")
        return {
            "killed_process": pre_stdout,
            "result": post.get("stdout", "").strip(),
            "exit_code": post.get("exit_code"),
            "stderr": post.get("stderr", ""),
            "elapsed_ms": post.get("elapsed_ms"),
        }

    @mcp.tool()
    async def copy_file(
        session_id: str,
        source: str,
        destination: str,
        ctx: Context,
        overwrite: bool = False,
    ) -> dict[str, Any]:
        """Copy a file to a new location. Prompts the user for confirmation. Does NOT overwrite by default.

        Args:
            session_id: Session ID from connect.
            source: Absolute path of the file to copy.
            destination: Absolute path for the copy.
            overwrite: Allow overwriting the destination if it exists (default False).
        """
        confirmed = await _confirm(
            ctx, "COPY FILE",
            f"From: {source}\nTo:   {destination}\nOverwrite: {overwrite}",
        )
        if not confirmed:
            return {"status": "cancelled", "message": "Copy cancelled by user"}

        safe_src = _sh_escape(source)
        safe_dst = _sh_escape(destination)
        no_clobber = "" if overwrite else "-n "
        cmd = (
            f"cp -p {no_clobber}'{safe_src}' '{safe_dst}' 2>&1 && "
            f"stat -c 'Copied: %n (%s bytes)' '{safe_dst}'"
        )
        return _run(session_id, cmd, tool_name="copy_file")

    @mcp.tool()
    async def rename_file(
        session_id: str,
        path: str,
        new_name: str,
        ctx: Context,
    ) -> dict[str, Any]:
        """Rename a file or directory (stays in the same folder). Prompts the user for confirmation.

        Args:
            session_id: Session ID from connect.
            path: Absolute path of the file or directory to rename.
            new_name: New filename only (not a full path).
        """
        if "/" in new_name:
            return {"error": "new_name must be a filename only, not a path. Use move_file to move across directories."}

        confirmed = await _confirm(
            ctx, "RENAME FILE",
            f"Path: {path}\nNew name: {new_name}",
        )
        if not confirmed:
            return {"status": "cancelled", "message": "Rename cancelled by user"}

        safe_path = _sh_escape(path)
        safe_name = _sh_escape(new_name)
        cmd = (
            f"DIR=$(dirname '{safe_path}') && "
            f"mv '{safe_path}' \"$DIR/{safe_name}\" 2>&1 && "
            f"stat -c 'Renamed to: %n (%s bytes)' \"$DIR/{safe_name}\""
        )
        return _run(session_id, cmd, tool_name="rename_file")

    @mcp.tool()
    async def move_file(
        session_id: str,
        source: str,
        destination: str,
        ctx: Context,
        overwrite: bool = False,
    ) -> dict[str, Any]:
        """Move a file to a different location. Prompts the user for confirmation.

        Args:
            session_id: Session ID from connect.
            source: Absolute path of the file to move.
            destination: Absolute destination path (full path including filename).
            overwrite: Allow overwriting the destination if it exists (default False).
        """
        confirmed = await _confirm(
            ctx, "MOVE FILE",
            f"From: {source}\nTo:   {destination}\nOverwrite: {overwrite}",
        )
        if not confirmed:
            return {"status": "cancelled", "message": "Move cancelled by user"}

        safe_src = _sh_escape(source)
        safe_dst = _sh_escape(destination)
        no_clobber = "" if overwrite else "-n "
        cmd = (
            f"mv {no_clobber}'{safe_src}' '{safe_dst}' 2>&1 && "
            f"stat -c 'Moved to: %n (%s bytes)' '{safe_dst}'"
        )
        return _run(session_id, cmd, tool_name="move_file")

    @mcp.tool()
    async def create_directory(
        session_id: str,
        path: str,
        ctx: Context,
    ) -> dict[str, Any]:
        """Create a directory (and any missing parent directories via mkdir -p). If the directory already exists, returns its info without error. Prompts for confirmation. Use this before write_file when the target folder might not exist.

        Args:
            session_id: Session ID from connect.
            path: Absolute path of the directory to create (e.g. '/tmp/backup/2026-04-26').
        """
        safe = _sh_escape(path)

        exists_cmd = (
            f"if [ -e '{safe}' ]; then "
            f"if [ -d '{safe}' ]; then echo 'EXISTS_AS_DIR'; "
            f"else echo 'EXISTS_AS_FILE'; fi; "
            f"else echo 'NOT_EXISTS'; fi"
        )
        check = _run(session_id, exists_cmd, tool_name="create_directory")
        state = check.get("stdout", "").strip()

        if state == "EXISTS_AS_FILE":
            return {"error": f"Path already exists as a file, not a directory: {path}"}
        if state == "EXISTS_AS_DIR":
            info = _run(
                session_id,
                f"stat -c '%n  created=%w  modified=%y  perms=%A  owner=%U:%G' '{safe}' 2>&1",
                tool_name="create_directory",
            )
            return {
                "status": "already_exists",
                "message": f"Directory already exists: {path}",
                "info": info.get("stdout", "").strip(),
            }

        confirmed = await _confirm(
            ctx, "CREATE DIRECTORY",
            f"Path: {path}\n\nThis will create the directory and any missing parent directories (mkdir -p).",
        )
        if not confirmed:
            return {"status": "cancelled", "message": "Create directory cancelled by user"}

        cmd = (
            f"mkdir -p '{safe}' 2>&1 && "
            f"stat -c '%n  created=%w  modified=%y  perms=%A  owner=%U:%G' '{safe}'"
        )
        return _run(session_id, cmd, tool_name="create_directory")

    @mcp.tool()
    async def delete_file(
        session_id: str,
        path: str,
        ctx: Context,
    ) -> dict[str, Any]:
        """Delete a single file. Shows file metadata (name, size, modified time, owner) in the confirmation prompt so you can verify the correct file. Refuses to delete directories — use delete_directory for that.

        Args:
            session_id: Session ID from connect.
            path: Absolute path to the file to delete.
        """
        safe = _sh_escape(path)

        pre_cmd = (
            f"if [ ! -e '{safe}' ]; then echo 'ERROR: path does not exist' >&2; exit 1; fi; "
            f"if [ -d '{safe}' ]; then echo 'ERROR: path is a directory - use delete_directory instead' >&2; exit 1; fi; "
            f"ls -lh '{safe}' 2>&1; "
            f"stat -c 'modified=%y  owner=%U:%G  perms=%A' '{safe}' 2>&1"
        )
        pre = _run(session_id, pre_cmd, tool_name="delete_file")
        pre_stdout = pre.get("stdout", "").strip()
        pre_stderr = pre.get("stderr", "").strip()
        exit_code = pre.get("exit_code", pre.get("status_code", 0))

        if "error" in pre or exit_code != 0 or pre_stderr:
            return {"error": pre_stderr or pre.get("error") or "Pre-check failed"}

        confirmed = await _confirm(
            ctx, "DELETE FILE",
            f"File details:\n{pre_stdout}\n\nThis will permanently delete the file. This cannot be undone.",
        )
        if not confirmed:
            return {"status": "cancelled", "message": "Delete file cancelled by user"}

        del_cmd = (
            f"rm -f '{safe}' 2>&1; "
            f"if [ -e '{safe}' ]; then echo 'WARNING: file still exists after deletion attempt'; "
            f"else echo 'File deleted successfully'; fi"
        )
        post = _run(session_id, del_cmd, tool_name="delete_file")
        return {
            "deleted_file": pre_stdout,
            "result": post.get("stdout", "").strip(),
            "exit_code": post.get("exit_code", post.get("status_code")),
            "stderr": post.get("stderr", ""),
        }

    @mcp.tool()
    async def delete_directory(
        session_id: str,
        path: str,
        ctx: Context,
        max_items: int = 5000,
    ) -> dict[str, Any]:
        """Delete a directory and all its contents recursively. Before confirming, scans the directory to show total file count, directory count, and total size. Refuses to delete if the item count exceeds max_items (default 5000) as a safety brake — raise the cap explicitly if you are sure. Will NOT delete well-known system directories.

        Args:
            session_id: Session ID from connect.
            path: Absolute path to the directory to delete.
            max_items: Safety cap — refuse deletion if more than this many items exist (default 5000, max 50000). Set higher only after reviewing the scan output.
        """
        safe = _sh_escape(path)
        cap = max(1, min(max_items, 50000))

        protected = [
            "/", "/bin", "/boot", "/dev", "/etc", "/home", "/lib", "/lib64",
            "/opt", "/proc", "/root", "/run", "/sbin", "/srv", "/sys",
            "/tmp", "/usr", "/var",
        ]
        path_clean = path.rstrip("/")
        if not path_clean:
            path_clean = "/"
        if path_clean in protected:
            return {"error": f"Refusing to delete protected path: {path}"}

        pre_cmd = (
            f"if [ ! -e '{safe}' ]; then echo 'ERROR: path does not exist' >&2; exit 1; fi; "
            f"if [ ! -d '{safe}' ]; then echo 'ERROR: path is a file - use delete_file instead' >&2; exit 1; fi; "
            f"FILE_COUNT=$(find '{safe}' -type f 2>/dev/null | head -{cap + 1} | wc -l); "
            f"DIR_COUNT=$(find '{safe}' -type d 2>/dev/null | head -{cap + 1} | wc -l); "
            f"TOTAL_SIZE=$(du -sh '{safe}' 2>/dev/null | cut -f1); "
            f"echo \"path={safe}\"; "
            f"echo \"file_count=$FILE_COUNT\"; "
            f"echo \"dir_count=$DIR_COUNT\"; "
            f"echo \"total_items=$((FILE_COUNT + DIR_COUNT))\"; "
            f"echo \"total_size=$TOTAL_SIZE\"; "
            f"stat -c 'created=%w  modified=%y' '{safe}' 2>/dev/null"
        )
        pre = _run(session_id, pre_cmd, tool_name="delete_directory", timeout=30)
        pre_stdout = pre.get("stdout", "").strip()
        pre_stderr = pre.get("stderr", "").strip()
        exit_code = pre.get("exit_code", pre.get("status_code", 0))

        if "error" in pre or exit_code != 0 or pre_stderr:
            return {"error": pre_stderr or pre.get("error") or "Pre-check failed"}

        total_items = 0
        for line in pre_stdout.splitlines():
            if line.startswith("total_items="):
                try:
                    total_items = int(line.split("=", 1)[1])
                except ValueError:
                    pass

        if total_items > cap:
            return {
                "error": f"Directory contains {total_items}+ items — exceeds safety cap of {cap}. "
                f"Review the scan and set max_items higher if you are sure.",
                "scan": pre_stdout,
            }

        confirmed = await _confirm(
            ctx, "DELETE DIRECTORY (recursive)",
            f"Directory scan:\n{pre_stdout}\n\nThis will permanently delete the directory and ALL "
            f"its contents. This cannot be undone.",
        )
        if not confirmed:
            return {"status": "cancelled", "message": "Delete directory cancelled by user"}

        del_cmd = (
            f"rm -rf '{safe}' 2>&1; "
            f"if [ -e '{safe}' ]; then echo 'WARNING: directory still exists after deletion attempt'; "
            f"else echo 'Directory deleted successfully'; fi"
        )
        post = _run(session_id, del_cmd, tool_name="delete_directory")
        return {
            "deleted_directory": pre_stdout,
            "result": post.get("stdout", "").strip(),
            "exit_code": post.get("exit_code", post.get("status_code")),
            "stderr": post.get("stderr", ""),
        }

    @mcp.tool()
    async def compress_archive(
        session_id: str,
        source_path: str,
        destination_archive: str,
        ctx: Context,
        overwrite: bool = False,
    ) -> dict[str, Any]:
        """Compress a file or directory into a .tar.gz archive. Prompts for confirmation. Use to archive logs, back up configs, or bundle files.

        Args:
            session_id: Session ID from connect.
            source_path: File or directory to compress.
            destination_archive: Path for the output archive (e.g. '/tmp/backup.tar.gz').
            overwrite: Allow overwriting an existing archive (default False).
        """
        safe_src = _sh_escape(source_path)
        safe_dst = _sh_escape(destination_archive)

        src_info = _run(
            session_id,
            f"if [ -d '{safe_src}' ]; then "
            f"echo \"Directory: {safe_src} ($(find '{safe_src}' -type f | wc -l) files)\"; "
            f"else stat -c 'File: %n (%s bytes)' '{safe_src}'; fi",
            tool_name="compress_archive",
        )
        if "error" in src_info:
            return src_info
        src_desc = src_info.get("stdout", "").strip()

        confirmed = await _confirm(
            ctx, "COMPRESS to tar.gz",
            f"Source: {src_desc}\nDestination: {destination_archive}\nOverwrite: {overwrite}",
        )
        if not confirmed:
            return {"status": "cancelled", "message": "Compress cancelled by user"}

        overwrite_check = ""
        if not overwrite:
            overwrite_check = f"[ -f '{safe_dst}' ] && echo 'Destination already exists. Set overwrite=True.' && exit 1; "

        cmd = (
            f"{overwrite_check}"
            f"tar -czf '{safe_dst}' -C $(dirname '{safe_src}') $(basename '{safe_src}') 2>&1 && "
            f"stat -c 'Archive created: %n (%s bytes)' '{safe_dst}'"
        )
        return _run(session_id, cmd, tool_name="compress_archive")

    @mcp.tool()
    async def extract_archive(
        session_id: str,
        archive_path: str,
        destination_dir: str,
        ctx: Context,
    ) -> dict[str, Any]:
        """Extract a .tar.gz, .tar, or .zip archive to a directory. Prompts for confirmation.

        Args:
            session_id: Session ID from connect.
            archive_path: Path to the archive file.
            destination_dir: Directory to extract into (created if it doesn't exist).
        """
        safe_arc = _sh_escape(archive_path)
        safe_dst = _sh_escape(destination_dir)

        confirmed = await _confirm(
            ctx, "EXTRACT ARCHIVE",
            f"Archive: {archive_path}\nExtract to: {destination_dir}",
        )
        if not confirmed:
            return {"status": "cancelled", "message": "Extract cancelled by user"}

        cmd = (
            f"mkdir -p '{safe_dst}' && "
            f"if echo '{safe_arc}' | grep -qE '\\.(tar\\.gz|tgz)$'; then "
            f"tar -xzf '{safe_arc}' -C '{safe_dst}' 2>&1; "
            f"elif echo '{safe_arc}' | grep -qE '\\.tar$'; then "
            f"tar -xf '{safe_arc}' -C '{safe_dst}' 2>&1; "
            f"elif echo '{safe_arc}' | grep -qE '\\.zip$'; then "
            f"unzip -o '{safe_arc}' -d '{safe_dst}' 2>&1; "
            f"else echo 'Unsupported archive format'; exit 1; fi && "
            f"echo \"Extracted to {safe_dst}: $(find '{safe_dst}' -type f | wc -l) files\""
        )
        return _run(session_id, cmd, tool_name="extract_archive")

    @mcp.tool()
    async def invoke_http_request(
        session_id: str,
        url: str,
        ctx: Context,
        method: str = "GET",
        timeout_sec: int = 15,
    ) -> dict[str, Any]:
        """Make an HTTP request FROM the remote Linux server. Tests connectivity and API health from the server's network perspective. Prompts for confirmation.

        Args:
            session_id: Session ID from connect.
            url: Full URL to request (e.g. 'http://localhost:8080/health').
            method: HTTP method: GET (default), HEAD, POST, PUT, DELETE.
            timeout_sec: Request timeout in seconds (default 15, max 60).
        """
        valid_methods = {"GET", "HEAD", "POST", "PUT", "DELETE"}
        m = method.strip().upper()
        if m not in valid_methods:
            return {"error": f"Invalid method '{method}'. Valid: {', '.join(sorted(valid_methods))}"}
        timeout = max(1, min(timeout_sec, 60))

        confirmed = await _confirm(
            ctx, "HTTP REQUEST (from remote server)",
            f"Method: {m}\nURL: {url}\nTimeout: {timeout}s",
        )
        if not confirmed:
            return {"status": "cancelled", "message": "HTTP request cancelled by user"}

        safe_url = _sh_escape(url)
        cmd = (
            f"curl -s -S -X {m} --max-time {timeout} "
            f"-w '\\n---HTTP_STATUS:%{{http_code}}---\\nTime: %{{time_total}}s' "
            f"'{safe_url}' 2>&1 | tail -c 8000"
        )
        return _run(session_id, cmd, tool_name="invoke_http_request")
