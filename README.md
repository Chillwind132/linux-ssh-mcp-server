# linux-ssh-mcp-server

[![License: MIT](https://img.shields.io/github/license/Chillwind132/linux-ssh-mcp-server)](LICENSE)
[![Python 3.11](https://img.shields.io/badge/python-3.11-blue?logo=python&logoColor=white)](https://www.python.org/)
[![Docker](https://img.shields.io/badge/docker-ready-2496ED?logo=docker&logoColor=white)](Dockerfile)

**A Linux MCP server for remote administration over SSH.** Diagnose, inspect, and manage any Linux host from Cursor, Claude Code, Codex, or any MCP (Model Context Protocol) client. Connects using per-user AD credentials elicited at runtime. Passwords live only in server memory with an idle TTL and are never logged.

- **45+ tools**: filesystem, systemd services, Docker, JBoss/WildFly discovery and log search, network, certificates, firewall, and more
- **Per-user AD identity**: each request carries an `X-AD-User` header; the password is either supplied via the optional `X-AD-Password` header (no prompt) or elicited once and cached in-memory
- **Optional sudo elevation**: privileged commands require an explicit `elevate_sudo` call; the sudo password is prompted, or reuses `X-AD-Password` when supplied
- **Zero secrets on disk**: no credentials in config files, env vars, or logs

## Example prompts

- "Why is the disk almost full on `host1`? What's eating the space?"
- "The `myapp` service keeps crashing, check the journal logs and tell me why."
- "Grep the JBoss server log for OutOfMemory errors from today."
- "Which process is listening on port 8443?"
- "Is the TLS certificate on `host1:443` close to expiry?"
- "Tail the logs of the `nginx` Docker container."
- "Restart the `httpd` service and confirm it came back up."

## Tools

### Session

| Tool | Description |
|------|-------------|
| `connect` | Open an SSH session to a Linux host and return a `session_id` |
| `disconnect` | Close an active SSH session |
| `list_sessions` | List active SSH sessions with usage details |
| `elevate_sudo` | Enable sudo for the session (password prompted once, cached in memory) |

### Filesystem (read-only)

| Tool | Description |
|------|-------------|
| `list_directory` | List files with permissions, owner, size, and mtime |
| `find_files` | Recursively find files by name pattern |
| `read_file` | Read file contents as numbered lines via SFTP streaming |
| `search_file_content` | Grep for text in a file or recursively across a directory |
| `file_info` | JSON metadata for a file or directory |
| `compare_files` | Unified-style diff of two files |

### System diagnostics (read-only)

| Tool | Description |
|------|-------------|
| `get_system_info` | OS, kernel, uptime, RAM, CPU count, timezone |
| `get_disk_space` | Disk space for all mounted filesystems |
| `get_disk_usage` | Disk usage by directory, largest first |
| `list_processes` | Processes sorted by CPU or memory |
| `get_perf_snapshot` | CPU load, memory, swap, disk I/O, top processes |
| `get_services` | systemd services summary or full status detail |
| `get_journal_logs` | systemd journal: service failures, crashes, system events |
| `get_dmesg` | Kernel ring buffer: OOM kills, I/O errors, hardware faults |
| `get_open_files` | File-descriptor usage ("too many open files" diagnosis) |
| `get_tcp_connections` | Active TCP connections with owning process |
| `get_network_config` | Interfaces, routing table, DNS servers |
| `test_network` | ICMP ping or TCP port test from the remote host |
| `resolve_dns` | DNS resolution from the remote server's perspective |
| `get_environment_variables` | Environment variables, optionally filtered |
| `get_cron_jobs` | User crontab and system cron directories |
| `get_users` | User accounts with recent logins |
| `get_permissions` | Permissions, ownership, and POSIX ACLs |
| `get_certificates` | TLS certificate details and days until expiry (file or endpoint) |
| `get_firewall_rules` | firewalld or iptables rules |

### Docker & JBoss (read-only)

| Tool | Description |
|------|-------------|
| `get_docker` | Containers, logs, inspect, stats, and images |
| `discover_jboss` | Discover running JBoss EAP/WildFly JVMs and their paths |
| `get_jboss_server_log` | Search JBoss/WildFly logs for errors with filename context |

### Write operations (all require user confirmation)

| Tool | Description |
|------|-------------|
| `restart_service` / `stop_service` / `start_service` | Manage systemd services with before/after state |
| `kill_process` | Force-kill a process by PID |
| `copy_file` / `rename_file` / `move_file` | File operations (no overwrite unless requested) |
| `create_directory` | `mkdir -p` with confirmation |
| `delete_file` / `delete_directory` | Delete with metadata/size shown in the prompt |
| `compress_archive` / `extract_archive` | Create or extract `.tar.gz` / `.zip` archives |
| `invoke_http_request` | HTTP request from the remote server via curl |

## Quick Start

```bash
docker compose -f docker-compose.yml -p linux-ssh-mcp up -d --build --force-recreate
```

## Client setup

`X-AD-User` is required. `X-AD-Password` is optional: omit it and the server prompts for the password once via MCP elicitation, caching it in memory.

### Cursor (`mcp.json`)

```json
{
  "mcpServers": {
    "linux-ssh-mcp": {
      "type": "http",
      "url": "http://localhost:8006/mcp",
      "headers": {
        "X-AD-User": "<your-ad-username>",
        "X-AD-Password": "<your-ad-password>"
      }
    }
  }
}
```

### Claude Code

```bash
claude mcp add --transport http linux-ssh-mcp http://localhost:8006/mcp \
  --header "X-AD-User: <your-ad-username>" \
  --header "X-AD-Password: <your-ad-password>"
```

### Codex (`~/.codex/config.toml`)

```toml
[mcp_servers.linux-ssh-mcp]
url = "http://localhost:8006/mcp"
http_headers = { "X-AD-User" = "<your-ad-username>", "X-AD-Password" = "<your-ad-password>" }
```

Any other MCP client works the same way: point it at the streamable HTTP endpoint and pass the headers.
