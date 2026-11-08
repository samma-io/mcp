# Operating the samma MCP server

This page is for people who run `mcp.samma.io`. If you only want to connect an
agent, see the [README](../README.md).

## Architecture

```
AI agent ──MCP over HTTPS──▶ Ingress (mcp.samma.io, Traefik + cert-manager)
                                │
                                ▼
                        samma-mcp (2 replicas, stateless, :8080)
                                │  GET /api/v1/*  with the caller's own token
                                ▼
                        samma-app (http://samma-app, same namespace)
                                │
                  ┌─────────────┴──────────────┐
                  ▼                            ▼
          Postgres: orgs, profiles,    TimescaleDB: scan_results
          targets, API tokens          (written by the scanners)
```

- **No credentials of its own.** samma-mcp has no database access and no
  service token. It can only see what the caller's token lets the app return.
  The app looks the token up and limits every query to that token's
  organisation, so tenant isolation lives in one place (samma-io/app,
  `src/lib/api-auth.ts`).
- **Read-only by construction.** It only calls `GET` endpoints, and every tool
  is annotated `readOnlyHint`. A write-capable token still works, but the
  server never uses it to write.
- **Stateless.** It uses Streamable HTTP in stateless mode with JSON
  responses. Any replica can serve any request, so no sticky sessions are
  needed.
- **Auth on every request.** A bearer token is checked with
  `GET /api/v1/me`. A valid result is cached in memory per replica, keyed by
  the token's SHA-256, for `TOKEN_CACHE_TTL` (default 60s). A revoked token
  therefore keeps working for up to 60s. Failed checks aren't cached.

### Request flow

1. The client sends `POST /mcp` with `Authorization: Bearer <token>`.
2. Without a token the server replies `401 no bearer token`. With an unknown
   token it replies `401 invalid token`, because the app rejected it. If the
   app can't be reached, it replies `500`.
3. The tool handler calls the app, for example `GET /api/v1/targets?limit=50`,
   forwarding the same token.
4. The app's JSON is returned as the tool's `structuredContent`. App errors
   become short messages the agent can act on, such as "target not found",
   "the samma API token was rejected (it may have been revoked)" or "scan
   results are temporarily unavailable".

### App endpoints used

| MCP | App endpoint |
|-----|--------------|
| auth, `whoami` | `GET /api/v1/me` |
| `list_targets` | `GET /api/v1/targets?profileId&q&type&limit&cursor` |
| `get_target` | `GET /api/v1/targets/{id}` |
| `get_latest_results` | `GET /api/v1/targets/{id}/results?scanner&severity&limit` |
| `list_findings` | `GET /api/v1/findings?severity&since&limit` |
| `samma://targets/{id}` | `GET /api/v1/targets/{id}` + `/results?limit=200` |

The app returns `503` from the results endpoints when `SCANNER_DATABASE_URL` is
not set or TimescaleDB is unreachable. Agents then see "scan results are
temporarily unavailable".

## Release and deploy

Everything after the merge is automatic:

1. A merge to `main` runs **Test** (`go vet`, `go test`) and **Docker Publish**,
   which builds `ghcr.io/samma-io/mcp:<commit sha>`.
2. When Docker Publish succeeds for a push to `main`, **Deploy To Production**
   runs `helm template samma-mcp chart/ --set image.tag=<sha>` and commits the
   result to `samma-io/deploy` as `mcp/deploy.yaml`.
3. The Argo CD application `samma-mcp` (namespace `samma`, automated sync)
   applies it.

To roll back, revert the commit on `main`. That rebuilds and redeploys the
previous code. For a quicker fix, revert the CI commit in `samma-io/deploy`.
The next merge to `main` will overwrite it.

Settings live in `chart/values.yaml`:

| Value | Default | Notes |
|-------|---------|-------|
| `replicaCount` | 2 | `autoscaling.enabled` switches to an HPA (2–5) |
| `sammaApiUrl` | `http://samma-app` | Must be in the same namespace as the app |
| `tokenCacheTTL` | `60s` | Upper bound on how long a revoked token still works |
| `ingress.hosts` | `mcp.samma.io` | TLS via cert-manager `cluster-issuer: http` (HTTP-01) |

## First-time setup of the public endpoint

1. **DNS:** add `mcp.samma.io` as an `A` record pointing at the same ingress IP
   as `samma.io`, or a `CNAME` to `samma.io.`. Check it with
   `dig +short mcp.samma.io`.
2. **TLS:** nothing to do. cert-manager's HTTP-01 challenge retries until DNS
   resolves, then issues `mcp-samma-io-tls`.
3. While the challenge is pending, Argo CD shows `samma-mcp` as **OutOfSync**,
   because cert-manager edits the Ingress in place (`http01-edit-in-place`).
   That clears once the certificate is issued.

## Checking that it works

```sh
curl -s https://mcp.samma.io/healthz          # → ok
curl -s -X POST https://mcp.samma.io/mcp      # → 401 no bearer token
```

End to end with a real token: create a **read-only** token under
**Dashboard → API Tokens**, then run

```sh
SAMMA_TOKEN=<token> scripts/smoke-test.sh
```

The script runs `initialize`, `tools/list`, every tool, the resource template,
and a negative case. It should print `[http 200]` throughout, and end with
`TOOL ERROR: target not found`. Revoke the token afterwards.

Before DNS exists, pin the host to the ingress IP. This also skips TLS
verification:

```sh
SAMMA_TOKEN=<token> MCP_RESOLVE=<ingress ip> scripts/smoke-test.sh
```

For an interactive check, run `npx @modelcontextprotocol/inspector`.

## Troubleshooting

| Symptom | Likely cause |
|---------|--------------|
| `curl https://mcp.samma.io/...` can't connect, or the certificate is untrusted | DNS is missing, or the certificate isn't issued yet. Check `kubectl -n samma get certificate,challenge` |
| `401 invalid token` | The app rejected the token: it is mistyped or was revoked. Check it with `curl -H "Authorization: Bearer …" https://samma.io/api/v1/me` |
| `500 verify token: samma api: …` on every request | samma-mcp can't reach `http://samma-app` to check tokens. Check the app pods, and that both are in namespace `samma` |
| Tool calls fail with "samma API request failed" | The app returned an unexpected error, or became unreachable after the token was cached. Check the app logs |
| "scan results are temporarily unavailable" | The app has no `SCANNER_DATABASE_URL`, or TimescaleDB is down |
| A revoked token still works | Expected for up to `tokenCacheTTL` (60s) |
| Argo CD `samma-mcp` OutOfSync but Healthy | A cert-manager HTTP-01 challenge is in progress (see above) |

Logs are JSON on stdout, one line per server event:
`kubectl -n samma logs deploy/samma-mcp`. The startup line includes the
deployed commit (`"version"`).
