// Package sammaapi is a small read-only client for the samma app REST API.
// Every call forwards the caller's own API token, so org scoping is enforced
// by the app, never by this service.
package sammaapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// APIError is a non-2xx response from the app.
type APIError struct {
	Status  int
	Message string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("samma api: %d %s", e.Status, e.Message)
}

// IsStatus reports whether err is an APIError with the given status.
func IsStatus(err error, status int) bool {
	var ae *APIError
	return errors.As(err, &ae) && ae.Status == status
}

type Client struct {
	base *url.URL
	http *http.Client
}

func New(baseURL string, hc *http.Client) (*Client, error) {
	u, err := url.Parse(strings.TrimRight(baseURL, "/"))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("invalid SAMMA_API_URL %q", baseURL)
	}
	if hc == nil {
		hc = &http.Client{Timeout: 15 * time.Second}
	}
	return &Client{base: u, http: hc}, nil
}

func (c *Client) get(ctx context.Context, token, path string, q url.Values, out any) error {
	u := *c.base
	u.Path = u.Path + path
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("samma api: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return fmt.Errorf("samma api: read body: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		msg := http.StatusText(resp.StatusCode)
		var e struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(body, &e) == nil && e.Error != "" {
			msg = e.Error
		}
		return &APIError{Status: resp.StatusCode, Message: msg}
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("samma api: decode %s: %w", path, err)
	}
	return nil
}

func setIf(q url.Values, k, v string) {
	if v != "" {
		q.Set(k, v)
	}
}

func setInt(q url.Values, k string, v int) {
	if v > 0 {
		q.Set(k, fmt.Sprint(v))
	}
}

func (c *Client) Me(ctx context.Context, token string) (*Me, error) {
	var out Me
	return &out, c.get(ctx, token, "/api/v1/me", nil, &out)
}

type ListTargetsParams struct {
	ProfileID string
	Query     string
	Type      string
	Limit     int
	Cursor    string
}

func (c *Client) ListTargets(ctx context.Context, token string, p ListTargetsParams) (*TargetList, error) {
	q := url.Values{}
	setIf(q, "profileId", p.ProfileID)
	setIf(q, "q", p.Query)
	setIf(q, "type", p.Type)
	setIf(q, "cursor", p.Cursor)
	setInt(q, "limit", p.Limit)
	var out TargetList
	return &out, c.get(ctx, token, "/api/v1/targets", q, &out)
}

func (c *Client) GetTarget(ctx context.Context, token, id string) (*TargetDetail, error) {
	var out TargetDetail
	return &out, c.get(ctx, token, "/api/v1/targets/"+url.PathEscape(id), nil, &out)
}

type ResultsParams struct {
	Scanner  string
	Severity []string
	Limit    int
}

func (c *Client) TargetResults(ctx context.Context, token, id string, p ResultsParams) (*Results, error) {
	q := url.Values{}
	setIf(q, "scanner", p.Scanner)
	setIf(q, "severity", strings.Join(p.Severity, ","))
	setInt(q, "limit", p.Limit)
	var out Results
	return &out, c.get(ctx, token, "/api/v1/targets/"+url.PathEscape(id)+"/results", q, &out)
}

type FindingsParams struct {
	Severity []string
	Since    string
	Limit    int
}

func (c *Client) Findings(ctx context.Context, token string, p FindingsParams) (*FindingList, error) {
	q := url.Values{}
	setIf(q, "severity", strings.Join(p.Severity, ","))
	setIf(q, "since", p.Since)
	setInt(q, "limit", p.Limit)
	var out FindingList
	return &out, c.get(ctx, token, "/api/v1/findings", q, &out)
}
