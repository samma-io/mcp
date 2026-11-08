#!/usr/bin/env bash
# Smoke-test a running samma MCP server end to end with a real API token.
#
#   SAMMA_TOKEN=<token> scripts/smoke-test.sh
#
# Env:
#   SAMMA_TOKEN   samma API token (required). Use a read-only one, and revoke it
#                 afterwards if it ended up in a log or transcript.
#   MCP_URL       default https://mcp.samma.io/mcp
#   MCP_RESOLVE   optional IP to pin the MCP_URL host to (curl --resolve), for
#                 testing before DNS exists. Implies -k, since the TLS cert
#                 can't be issued until DNS resolves.
#
# Every step prints the HTTP status and a short summary. A healthy server
# returns 200 for each call, and the last call ("does-not-exist") must come
# back as a tool error saying "target not found".
set -uo pipefail
: "${SAMMA_TOKEN:?set SAMMA_TOKEN to a samma API token}"
command -v python3 >/dev/null || { echo "python3 is required" >&2; exit 1; }

URL=${MCP_URL:-https://mcp.samma.io/mcp}
CURL=(curl -s --max-time 30 "$URL"
  -H "Authorization: Bearer $SAMMA_TOKEN"
  -H "Content-Type: application/json"
  -H "Accept: application/json, text/event-stream"
  -H "MCP-Protocol-Version: 2025-06-18")
if [ -n "${MCP_RESOLVE:-}" ]; then
  host=$(python3 -c 'import sys,urllib.parse as u; p=u.urlsplit(sys.argv[1]); print(f"{p.hostname}:{p.port or 443}")' "$URL")
  CURL+=(-k --resolve "$host:$MCP_RESOLVE")
fi

rpc() { # label, json-rpc body
  echo "=== $1"
  "${CURL[@]}" -w '\n[http %{http_code}]\n' -d "$2" | python3 -c '
import sys, json
raw = sys.stdin.read()
body, _, status = raw.rpartition("\n[http ")
print("[http " + status.strip())
try:
    d = json.loads(body)
except Exception:
    print(body[:500]); sys.exit()
r = d.get("result", d)
if isinstance(r, dict) and "tools" in r:
    print("tools:", ", ".join(t["name"] for t in r["tools"]))
elif isinstance(r, dict) and r.get("isError"):
    print("TOOL ERROR:", r["content"][0]["text"])
else:
    out = r.get("structuredContent", r) if isinstance(r, dict) else r
    print(json.dumps(out, indent=1)[:1500])
'
}

call() { rpc "$1 $2" "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"$1\",\"arguments\":$2}}"; }

rpc initialize '{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"smoke","version":"0"}}}'
rpc tools/list '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
call whoami '{}'
call list_targets '{"limit":5}'

# Use the first target for the per-target tools.
TID=$("${CURL[@]}" -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"list_targets","arguments":{"limit":1}}}' \
  | python3 -c 'import sys,json
try:
    t = json.load(sys.stdin)["result"]["structuredContent"]["targets"]
    print(t[0]["id"] if t else "")
except Exception:
    print("")')
if [ -n "$TID" ]; then
  call get_target "{\"target_id\":\"$TID\"}"
  call get_latest_results "{\"target_id\":\"$TID\",\"limit\":5}"
  rpc "resources/read samma://targets/$TID" "{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"resources/read\",\"params\":{\"uri\":\"samma://targets/$TID\"}}"
else
  echo "=== no targets in this org; skipping per-target tools"
fi
call list_findings '{"min_severity":"INFO","limit":5}'
call get_target '{"target_id":"does-not-exist"}'
