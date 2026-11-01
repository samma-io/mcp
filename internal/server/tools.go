package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/samma-io/mcp/internal/sammaapi"
)

var severities = []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}

// atLeast returns the severities at or above min, or nil (no filter) if min is empty.
func atLeast(min string) ([]string, error) {
	min = strings.ToUpper(strings.TrimSpace(min))
	if min == "" {
		return nil, nil
	}
	for i, s := range severities {
		if s == min {
			return append([]string(nil), severities[:i+1]...), nil
		}
	}
	return nil, fmt.Errorf("min_severity must be one of %s", strings.Join(severities, ", "))
}

func clampLimit(n, def, max int) int {
	if n <= 0 {
		return def
	}
	if n > max {
		return max
	}
	return n
}

// apiErr maps app API errors to messages that make sense to an agent.
func apiErr(err error, what string) error {
	var ae *sammaapi.APIError
	if errors.As(err, &ae) {
		switch ae.Status {
		case http.StatusUnauthorized, http.StatusForbidden:
			return fmt.Errorf("the samma API token was rejected (it may have been revoked)")
		case http.StatusNotFound:
			return fmt.Errorf("%s not found", what)
		case http.StatusServiceUnavailable:
			return fmt.Errorf("scan results are temporarily unavailable")
		case http.StatusBadRequest:
			return fmt.Errorf("invalid request: %s", ae.Message)
		}
	}
	return fmt.Errorf("samma API request failed")
}

type tools struct {
	api *sammaapi.Client
}

func readOnly(title string) *mcp.ToolAnnotations {
	f := false
	return &mcp.ToolAnnotations{Title: title, ReadOnlyHint: true, IdempotentHint: true, OpenWorldHint: &f}
}

// ---- whoami

type WhoamiIn struct{}

type WhoamiOut struct {
	Organisation sammaapi.Organisation `json:"organisation"`
	TokenName    string                `json:"tokenName"`
	ReadOnly     bool                  `json:"readOnlyToken"`
}

func (t *tools) whoami(_ context.Context, req *mcp.CallToolRequest, _ WhoamiIn) (*mcp.CallToolResult, WhoamiOut, error) {
	_, me, err := callerFrom(req.Extra.TokenInfo)
	if err != nil {
		return nil, WhoamiOut{}, err
	}
	return nil, WhoamiOut{Organisation: me.Organisation, TokenName: me.Token.Name, ReadOnly: me.Token.ReadOnly}, nil
}

// ---- list_targets

type ListTargetsIn struct {
	ProfileID string `json:"profile_id,omitempty" jsonschema:"only targets in this scan profile"`
	Query     string `json:"query,omitempty" jsonschema:"case-insensitive substring match on target value (hostname/IP) or label"`
	Type      string `json:"type,omitempty" jsonschema:"filter by target type: ip or dns"`
	Limit     int    `json:"limit,omitempty" jsonschema:"page size, 1-100 (default 50)"`
	Cursor    string `json:"cursor,omitempty" jsonschema:"nextCursor from a previous call, to get the next page"`
}

type ListTargetsOut struct {
	Targets    []sammaapi.Target `json:"targets"`
	NextCursor string            `json:"nextCursor,omitempty"`
}

func (t *tools) listTargets(ctx context.Context, req *mcp.CallToolRequest, in ListTargetsIn) (*mcp.CallToolResult, ListTargetsOut, error) {
	tok, _, err := callerFrom(req.Extra.TokenInfo)
	if err != nil {
		return nil, ListTargetsOut{}, err
	}
	if in.Type != "" && in.Type != "ip" && in.Type != "dns" {
		return nil, ListTargetsOut{}, fmt.Errorf("type must be ip or dns")
	}
	res, err := t.api.ListTargets(ctx, tok, sammaapi.ListTargetsParams{
		ProfileID: in.ProfileID, Query: in.Query, Type: in.Type,
		Limit: clampLimit(in.Limit, 50, 100), Cursor: in.Cursor,
	})
	if err != nil {
		return nil, ListTargetsOut{}, apiErr(err, "profile")
	}
	if res.Targets == nil {
		res.Targets = []sammaapi.Target{}
	}
	return nil, ListTargetsOut{Targets: res.Targets, NextCursor: res.NextCursor}, nil
}

// ---- get_target

type GetTargetIn struct {
	TargetID string `json:"target_id" jsonschema:"the target id (from list_targets)"`
}

func (t *tools) getTarget(ctx context.Context, req *mcp.CallToolRequest, in GetTargetIn) (*mcp.CallToolResult, sammaapi.TargetDetail, error) {
	tok, _, err := callerFrom(req.Extra.TokenInfo)
	if err != nil {
		return nil, sammaapi.TargetDetail{}, err
	}
	if strings.TrimSpace(in.TargetID) == "" {
		return nil, sammaapi.TargetDetail{}, fmt.Errorf("target_id is required")
	}
	res, err := t.api.GetTarget(ctx, tok, in.TargetID)
	if err != nil {
		return nil, sammaapi.TargetDetail{}, apiErr(err, "target")
	}
	if res.Scanners == nil {
		res.Scanners = []sammaapi.ScannerRun{}
	}
	return nil, *res, nil
}

// ---- get_latest_results

type LatestResultsIn struct {
	TargetID    string `json:"target_id" jsonschema:"the target id (from list_targets)"`
	Scanner     string `json:"scanner,omitempty" jsonschema:"only this scanner, e.g. tls, http-headers, port, nmap, nikto"`
	MinSeverity string `json:"min_severity,omitempty" jsonschema:"only findings at or above this severity: CRITICAL, HIGH, MEDIUM, LOW, INFO"`
	Limit       int    `json:"limit,omitempty" jsonschema:"max findings, 1-500 (default 200)"`
}

func (t *tools) latestResults(ctx context.Context, req *mcp.CallToolRequest, in LatestResultsIn) (*mcp.CallToolResult, sammaapi.Results, error) {
	tok, _, err := callerFrom(req.Extra.TokenInfo)
	if err != nil {
		return nil, sammaapi.Results{}, err
	}
	if strings.TrimSpace(in.TargetID) == "" {
		return nil, sammaapi.Results{}, fmt.Errorf("target_id is required")
	}
	sev, err := atLeast(in.MinSeverity)
	if err != nil {
		return nil, sammaapi.Results{}, err
	}
	res, err := t.api.TargetResults(ctx, tok, in.TargetID, sammaapi.ResultsParams{
		Scanner: in.Scanner, Severity: sev, Limit: clampLimit(in.Limit, 200, 500),
	})
	if err != nil {
		return nil, sammaapi.Results{}, apiErr(err, "target")
	}
	if res.Runs == nil {
		res.Runs = []sammaapi.ScannerRun{}
	}
	if res.Results == nil {
		res.Results = []sammaapi.Finding{}
	}
	return nil, *res, nil
}

// ---- list_findings

type ListFindingsIn struct {
	MinSeverity string `json:"min_severity,omitempty" jsonschema:"only findings at or above this severity (default HIGH): CRITICAL, HIGH, MEDIUM, LOW, INFO"`
	Since       string `json:"since,omitempty" jsonschema:"only findings seen at or after this time: RFC 3339 timestamp or a duration like 24h or 7d"`
	Limit       int    `json:"limit,omitempty" jsonschema:"max findings, 1-500 (default 100)"`
}

// normaliseSince turns "24h"/"7d" into an RFC 3339 timestamp; RFC 3339 passes through.
func normaliseSince(s string, now time.Time) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", nil
	}
	if ts, err := time.Parse(time.RFC3339, s); err == nil {
		return ts.UTC().Format(time.RFC3339), nil
	}
	if strings.HasSuffix(s, "d") {
		var days int
		if _, err := fmt.Sscanf(s, "%dd", &days); err == nil && days > 0 {
			return now.Add(-time.Duration(days) * 24 * time.Hour).UTC().Format(time.RFC3339), nil
		}
	}
	if d, err := time.ParseDuration(s); err == nil && d > 0 {
		return now.Add(-d).UTC().Format(time.RFC3339), nil
	}
	return "", fmt.Errorf("since must be an RFC 3339 timestamp or a duration like 24h or 7d")
}

func (t *tools) listFindings(ctx context.Context, req *mcp.CallToolRequest, in ListFindingsIn) (*mcp.CallToolResult, sammaapi.FindingList, error) {
	tok, _, err := callerFrom(req.Extra.TokenInfo)
	if err != nil {
		return nil, sammaapi.FindingList{}, err
	}
	min := in.MinSeverity
	if min == "" {
		min = "HIGH"
	}
	sev, err := atLeast(min)
	if err != nil {
		return nil, sammaapi.FindingList{}, err
	}
	since, err := normaliseSince(in.Since, time.Now())
	if err != nil {
		return nil, sammaapi.FindingList{}, err
	}
	res, err := t.api.Findings(ctx, tok, sammaapi.FindingsParams{
		Severity: sev, Since: since, Limit: clampLimit(in.Limit, 100, 500),
	})
	if err != nil {
		return nil, sammaapi.FindingList{}, apiErr(err, "findings")
	}
	if res.Findings == nil {
		res.Findings = []sammaapi.Finding{}
	}
	return nil, *res, nil
}

// ---- resource: samma://targets/{id}

const targetURIPrefix = "samma://targets/"

func (t *tools) readTarget(ctx context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
	uri := req.Params.URI
	id := strings.TrimPrefix(uri, targetURIPrefix)
	if id == uri || id == "" || strings.Contains(id, "/") {
		return nil, mcp.ResourceNotFoundError(uri)
	}
	tok, _, err := callerFrom(req.Extra.TokenInfo)
	if err != nil {
		return nil, err
	}
	detail, err := t.api.GetTarget(ctx, tok, id)
	if err != nil {
		if sammaapi.IsStatus(err, http.StatusNotFound) {
			return nil, mcp.ResourceNotFoundError(uri)
		}
		return nil, apiErr(err, "target")
	}
	results, err := t.api.TargetResults(ctx, tok, id, sammaapi.ResultsParams{Limit: 200})
	if err != nil {
		return nil, apiErr(err, "target")
	}
	body, err := json.MarshalIndent(struct {
		*sammaapi.TargetDetail
		Results []sammaapi.Finding `json:"results"`
	}{detail, results.Results}, "", "  ")
	if err != nil {
		return nil, err
	}
	// Tenant data: only the requesting client may cache it.
	return &mcp.ReadResourceResult{Cacheable: mcp.Cacheable{CacheScope: "private"}, Contents: []*mcp.ResourceContents{{URI: uri, MIMEType: "application/json", Text: string(body)}}}, nil
}
