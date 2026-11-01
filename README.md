# samma MCP server

A read-only [Model Context Protocol](https://modelcontextprotocol.io) server for
[samma.io](https://samma.io). Connect your own AI agent and ask it about your
scan targets and their latest results, e.g. *"Which of my hosts have critical
findings?"* or *"What did the TLS scan find on api.example.com?"*.

- Endpoint: `https://mcp.samma.io/mcp` (Streamable HTTP)
- Auth: your samma API token as `Authorization: Bearer <token>`.
  Create one in the dashboard under **API tokens**. A **read-only** token is
  recommended. The server only ever reads, but a read-only token also can't
  change targets if it leaks.
- Scope: everything is limited to the organisation that owns the token.

## Tools

| Tool | What it returns |
|------|-----------------|
| `whoami` | The organisation the token belongs to |
| `list_targets` | Scan targets (host/IP, profile, scanner and reachability status). Filters: `profile_id`, `query`, `type`. Paginated with `cursor` |
| `get_target` | One target plus the latest run of each scanner: outcome, time, finding counts by severity |
| `get_latest_results` | Findings from the most recent run of each scanner on a target. Filters: `scanner`, `min_severity` |
| `list_findings` | The newest findings across all targets. Defaults to `HIGH` and above; `since` takes `24h`, `7d` or an RFC 3339 timestamp |

Resource template: `samma://targets/{id}` returns a target with its latest
results as JSON.

Severities: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`.

## Connecting a client

Claude Code:

```sh
claude mcp add --transport http samma https://mcp.samma.io/mcp \
  --header "Authorization: Bearer $SAMMA_API_TOKEN"
```

Generic JSON config (Claude Desktop, Cursor, and others that support remote
HTTP servers):

```json
{
  "mcpServers": {
    "samma": {
      "type": "http",
      "url": "https://mcp.samma.io/mcp",
      "headers": { "Authorization": "Bearer <your samma API token>" }
    }
  }
}
```

MCP Inspector: `npx @modelcontextprotocol/inspector`, choose *Streamable
HTTP*, set the URL to `https://mcp.samma.io/mcp`, and add the `Authorization`
header.

## How it works

```
agent ──MCP/HTTP──▶ samma-mcp ──GET /api/v1/*──▶ samma app ──▶ Postgres (targets) + TimescaleDB (scan_results)
          Bearer token        forwards same token          org scoping + read-only checks
```

The server is a thin, stateless layer. It holds no database credentials. Every
request is checked against the app's `GET /api/v1/me`, and the caller's own
token is forwarded on each API call, so the app enforces tenant isolation.
Verified tokens are cached in memory by their SHA-256 hash for
`TOKEN_CACHE_TTL` (60s by default), which means a revoked token keeps working
for up to that long.

It needs these app endpoints (samma-io/app): `GET /api/v1/me`,
`GET /api/v1/targets`, `GET /api/v1/targets/{id}`,
`GET /api/v1/targets/{id}/results` and `GET /api/v1/findings`.

## Running and developing

| Env | Default | |
|-----|---------|-|
| `SAMMA_API_URL` | `http://localhost:3000` | Base URL of the samma app |
| `LISTEN_ADDR` | `:8080` | MCP is served at `/mcp`, health at `/healthz` |
| `TOKEN_CACHE_TTL` | `60s` | How long a verified token is cached |
| `LOG_LEVEL` | `info` | |

```sh
go test ./...
SAMMA_API_URL=http://localhost:3000 go run ./cmd/samma-mcp
```

Deploy: on a push to `main`, *Docker Publish* builds `ghcr.io/samma-io/mcp:<sha>`.
*Deploy To Production* then renders `chart/` into `samma-io/deploy` at
`mcp/deploy.yaml`, which Argo CD syncs.
