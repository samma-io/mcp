// Package server wires the samma read-only MCP tools onto an HTTP handler.
package server

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/samma-io/mcp/internal/sammaapi"
)

const instructions = `Read-only access to samma.io external attack-surface scanning for the organisation that owns the API token.

Typical flow:
- list_targets to find hosts/IPs being scanned (each has an id).
- get_target for a target's status and the latest run of every scanner.
- get_latest_results for the findings from the most recent run of each scanner on one target.
- list_findings for the newest findings across all targets (defaults to HIGH and above).

Severities are CRITICAL, HIGH, MEDIUM, LOW, INFO. Results reflect the latest completed scans; this server cannot start scans or change targets.`

// NewMCPServer builds the MCP server with all read-only tools registered.
func NewMCPServer(api *sammaapi.Client, version string) *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{Name: "samma", Title: "samma.io", Version: version},
		&mcp.ServerOptions{Instructions: instructions})
	t := &tools{api: api}

	mcp.AddTool(s, &mcp.Tool{
		Name:        "whoami",
		Description: "Show which samma organisation the API token belongs to.",
		Annotations: readOnly("Who am I"),
	}, t.whoami)
	mcp.AddTool(s, &mcp.Tool{
		Name:        "list_targets",
		Description: "List the scan targets (hostnames and IPs) of the organisation, with scanner and reachability status. Paginated.",
		Annotations: readOnly("List scan targets"),
	}, t.listTargets)
	mcp.AddTool(s, &mcp.Tool{
		Name:        "get_target",
		Description: "Get one scan target and a summary of the latest run of each scanner against it (outcome, time, finding counts by severity).",
		Annotations: readOnly("Get scan target"),
	}, t.getTarget)
	mcp.AddTool(s, &mcp.Tool{
		Name:        "get_latest_results",
		Description: "Get the findings from the most recent run of each scanner on a target, optionally filtered by scanner and minimum severity.",
		Annotations: readOnly("Latest scan results"),
	}, t.latestResults)
	mcp.AddTool(s, &mcp.Tool{
		Name:        "list_findings",
		Description: "List the newest findings across all of the organisation's targets, by default HIGH and CRITICAL only.",
		Annotations: readOnly("List findings"),
	}, t.listFindings)

	s.AddResourceTemplate(&mcp.ResourceTemplate{
		Name:        "target",
		Title:       "Scan target with latest results",
		URITemplate: targetURIPrefix + "{id}",
		MIMEType:    "application/json",
		Description: "A scan target, its latest scanner runs and latest findings.",
	}, t.readTarget)
	return s
}

// Options configure the HTTP handler.
type Options struct {
	API      *sammaapi.Client
	Version  string
	CacheTTL time.Duration
	Logger   *slog.Logger
}

// NewHandler returns an http.Handler serving MCP (Streamable HTTP, stateless)
// at "/", protected by bearer-token auth against the samma app.
func NewHandler(o Options) http.Handler {
	if o.CacheTTL <= 0 {
		o.CacheTTL = time.Minute
	}
	srv := NewMCPServer(o.API, o.Version)
	h := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return srv }, &mcp.StreamableHTTPOptions{
		// Stateless: every request is self-contained, so replicas need no
		// sticky sessions and auth is checked on every call.
		Stateless:    true,
		JSONResponse: true,
		Logger:       o.Logger,
	})
	v := NewVerifier(o.API, o.CacheTTL)
	return auth.RequireBearerToken(v.Verify, nil)(h)
}
