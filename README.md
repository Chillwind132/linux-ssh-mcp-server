# linux-ssh-mcp-server

Remote Linux operations via SSH, exposed as an MCP (Model Context Protocol) server. Connects to any Linux host using per-user AD credentials elicited at runtime — passwords live only in server memory with an idle TTL and are never logged.

- **45+ tools** — filesystem, systemd services, Docker, JBoss/WildFly discovery and log search, network, certificates, firewall, and more
- **Per-user AD identity** — each request carries an `X-AD-User` header; passwords are prompted once and cached in-memory
- **Optional sudo elevation** — privileged commands require an explicit `elevate_sudo` call with a separate password prompt
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
        "X-AD-User": "<your-ad-username>"
      }
    }
  }
}
```
