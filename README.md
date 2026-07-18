# linux-ssh-mcp-server

[![License: MIT](https://img.shields.io/github/license/Chillwind132/linux-ssh-mcp-server)](LICENSE)
[![Python 3.11](https://img.shields.io/badge/python-3.11-blue?logo=python&logoColor=white)](https://www.python.org/)
[![Docker](https://img.shields.io/badge/docker-ready-2496ED?logo=docker&logoColor=white)](Dockerfile)

Remote Linux operations via SSH, exposed as an MCP (Model Context Protocol) server. Connects to any Linux host using per-user AD credentials elicited at runtime — passwords live only in server memory with an idle TTL and are never logged.

- **45+ tools** — filesystem, systemd services, Docker, JBoss/WildFly discovery and log search, network, certificates, firewall, and more
- **Per-user AD identity** — each request carries an `X-AD-User` header; the password is either supplied via the optional `X-AD-Password` header (no prompt) or elicited once and cached in-memory
- **Optional sudo elevation** — privileged commands require an explicit `elevate_sudo` call; the sudo password is prompted, or reuses `X-AD-Password` when supplied
- **Zero secrets on disk** — no credentials in config files, env vars, or logs

## Quick Start

```bash
docker compose -f docker-compose.yml -p linux-ssh-mcp up -d --build --force-recreate
```

## Cursor `mcp.json`

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
