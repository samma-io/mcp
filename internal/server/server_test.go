package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/samma-io/mcp/internal/sammaapi"
)

const goodToken = "tok-org-a"

// fakeApp is a stand-in for the samma app read API.
type fakeApp struct {
	meCalls  atomic.Int32
	lastPath atomic.Value // string: path?query of the last data request
}

func (f *fakeApp) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer "+goodToken {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"Unauthorized"}`))
		return
	}
	if r.URL.Path != "/api/v1/me" {
		f.lastPath.Store(r.URL.Path + "?" + r.URL.RawQuery)
	}
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.URL.Path == "/api/v1/me":
		f.meCalls.Add(1)
		_, _ = w.Write([]byte(`{"organisation":{"id":"org_a","name":"Acme"},"token":{"name":"agent","readOnly":true}}`))
	case r.URL.Path == "/api/v1/targets":
		_, _ = w.Write([]byte(`{"targets":[{"id":"t1","value":"acme.com","type":"dns","profile":{"id":"p1","name":"Default","type":"SMALL"},"scannerStatus":"DEPLOYED","reachabilityStatus":"UP","createdAt":"2026-10-01T00:00:00Z"}],"nextCursor":"t1"}`))
	case r.URL.Path == "/api/v1/targets/t1":
		_, _ = w.Write([]byte(`{"target":{"id":"t1","value":"acme.com","type":"dns","profile":{"id":"p1","name":"Default","type":"SMALL"},"scannerStatus":"DEPLOYED","reachabilityStatus":"UP","createdAt":"2026-10-01T00:00:00Z"},"scanners":[{"scanner":"tls","runId":"r1","outcome":"succeeded","findingCount":1,"severity":{"HIGH":1}}]}`))
	case r.URL.Path == "/api/v1/targets/t1/results":
		_, _ = w.Write([]byte(`{"targetId":"t1","runs":[{"scanner":"tls","runId":"r1","outcome":"succeeded","findingCount":1}],"results":[{"time":"2026-10-31T10:00:00Z","targetId":"t1","scanner":"tls","runId":"r1","checkId":"SAMMA-TLS-WEAK-PROTOCOL","severity":"HIGH","title":"TLS 1.0 enabled"}]}`))
	case r.URL.Path == "/api/v1/findings":
		_, _ = w.Write([]byte(`{"findings":[{"time":"2026-10-31T10:00:00Z","targetId":"t1","target":"acme.com","scanner":"tls","severity":"HIGH","title":"TLS 1.0 enabled"}]}`))
	default:
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"Not found"}`))
	}
}

type bearerRT struct{ token string }

func (b bearerRT) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	if b.token != "" {
		r.Header.Set("Authorization", "Bearer "+b.token)
	}
	return http.DefaultTransport.RoundTrip(r)
}

func setup(t *testing.T) (*fakeApp, *httptest.Server) {
	t.Helper()
	fake := &fakeApp{}
	app := httptest.NewServer(fake)
	t.Cleanup(app.Close)
	api, err := sammaapi.New(app.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	mcpSrv := httptest.NewServer(NewHandler(Options{API: api, Version: "test"}))
	t.Cleanup(mcpSrv.Close)
	return fake, mcpSrv
}

func connect(t *testing.T, url, token string) (*mcp.ClientSession, error) {
	t.Helper()
	c := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "0"}, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return c.Connect(ctx, &mcp.StreamableClientTransport{
		Endpoint:   url,
		HTTPClient: &http.Client{Transport: bearerRT{token}},
		MaxRetries: -1,
	}, nil)
}

func TestAuthRejected(t *testing.T) {
	_, srv := setup(t)
	for _, tok := range []string{"", "wrong"} {
		resp, err := (&http.Client{Transport: bearerRT{tok}}).Post(srv.URL, "application/json",
			strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("token %q: status %d, want 401", tok, resp.StatusCode)
		}
		if _, err := connect(t, srv.URL, tok); err == nil {
			t.Errorf("token %q: connect succeeded, want error", tok)
		}
	}
}

func callJSON(t *testing.T, cs *mcp.ClientSession, name string, args map[string]any) (map[string]any, bool) {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	if res.IsError {
		return nil, true
	}
	b, _ := json.Marshal(res.StructuredContent)
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("%s: decode structured content: %v", name, err)
	}
	return out, false
}

func TestTools(t *testing.T) {
	fake, srv := setup(t)
	cs, err := connect(t, srv.URL, goodToken)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()

	lt, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(lt.Tools) != 5 {
		t.Fatalf("got %d tools, want 5", len(lt.Tools))
	}
	for _, tool := range lt.Tools {
		if tool.Annotations == nil || !tool.Annotations.ReadOnlyHint {
			t.Errorf("tool %s is not marked read-only", tool.Name)
		}
	}

	cases := []struct {
		tool     string
		args     map[string]any
		wantErr  bool
		wantKey  string
		wantPath string
	}{
		{tool: "whoami", wantKey: "organisation"},
		{tool: "list_targets", args: map[string]any{"query": "acme", "limit": 500}, wantKey: "targets", wantPath: "/api/v1/targets?limit=100&q=acme"},
		{tool: "list_targets", args: map[string]any{"type": "bogus"}, wantErr: true},
		{tool: "get_target", args: map[string]any{"target_id": "t1"}, wantKey: "scanners", wantPath: "/api/v1/targets/t1?"},
		{tool: "get_target", args: map[string]any{"target_id": "nope"}, wantErr: true},
		{tool: "get_target", args: map[string]any{"target_id": ""}, wantErr: true},
		{tool: "get_latest_results", args: map[string]any{"target_id": "t1", "min_severity": "high"}, wantKey: "results", wantPath: "/api/v1/targets/t1/results?limit=200&severity=CRITICAL%2CHIGH"},
		{tool: "get_latest_results", args: map[string]any{"target_id": "t1", "min_severity": "urgent"}, wantErr: true},
		{tool: "list_findings", wantKey: "findings", wantPath: "/api/v1/findings?limit=100&severity=CRITICAL%2CHIGH"},
		{tool: "list_findings", args: map[string]any{"since": "yesterday"}, wantErr: true},
	}
	for _, c := range cases {
		fake.lastPath.Store("")
		out, isErr := callJSON(t, cs, c.tool, c.args)
		if isErr != c.wantErr {
			t.Errorf("%s %v: isError=%v, want %v", c.tool, c.args, isErr, c.wantErr)
			continue
		}
		if c.wantKey != "" {
			if _, ok := out[c.wantKey]; !ok {
				t.Errorf("%s: output missing %q: %v", c.tool, c.wantKey, out)
			}
		}
		if c.wantPath != "" {
			if got := fake.lastPath.Load(); got != c.wantPath {
				t.Errorf("%s: app request %q, want %q", c.tool, got, c.wantPath)
			}
		}
	}

	// Token verification is cached: one /me call for the whole session.
	if n := fake.meCalls.Load(); n != 1 {
		t.Errorf("/api/v1/me called %d times, want 1 (cached)", n)
	}

	rr, err := cs.ReadResource(context.Background(), &mcp.ReadResourceParams{URI: "samma://targets/t1"})
	if err != nil {
		t.Fatalf("read resource: %v", err)
	}
	if len(rr.Contents) != 1 || !strings.Contains(rr.Contents[0].Text, "SAMMA-TLS-WEAK-PROTOCOL") {
		t.Errorf("resource contents unexpected: %+v", rr.Contents)
	}
	if rr.CacheScope != "private" {
		t.Errorf("resource cacheScope = %q, want private", rr.CacheScope)
	}
}

func TestAtLeast(t *testing.T) {
	got, _ := atLeast("medium")
	if strings.Join(got, ",") != "CRITICAL,HIGH,MEDIUM" {
		t.Errorf("atLeast(medium) = %v", got)
	}
	if got, _ := atLeast(""); got != nil {
		t.Errorf("atLeast(\"\") = %v, want nil", got)
	}
}

func TestNormaliseSince(t *testing.T) {
	now := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	for in, want := range map[string]string{
		"":                     "",
		"24h":                  "2026-10-31T12:00:00Z",
		"7d":                   "2026-10-25T12:00:00Z",
		"2026-10-01T00:00:00Z": "2026-10-01T00:00:00Z",
	} {
		got, err := normaliseSince(in, now)
		if err != nil || got != want {
			t.Errorf("normaliseSince(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
}
